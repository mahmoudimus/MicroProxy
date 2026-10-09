package io.github.mahmoudimus.http3;

import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Encodes field sections with QPACK (RFC 9204). One encoder per connection, for the field sections
 * this endpoint sends. Not thread-safe: callers serialize access, and must send each section's
 * encoder-stream instructions (see {@link #encoderStreamBytes()}) no later than the section.
 *
 * <p>Two modes:
 *
 * <ul>
 *   <li><b>Static only</b> ({@link #QpackEncoder()}, or until the peer allows a dynamic table):
 *       fields are indexed in the static table or sent as literals. Sections never depend on the
 *       encoder stream (Required Insert Count 0), so they can never block. Always safe.
 *   <li><b>Dynamic</b> ({@link #QpackEncoder(long)} with a non-zero limit, once
 *       {@link #applyPeerSettings} gives a non-zero SETTINGS_QPACK_MAX_TABLE_CAPACITY): the encoder
 *       sets the table capacity to the smaller of its limit and the peer's, inserts fields into the
 *       dynamic table with encoder-stream instructions (Set Dynamic Table Capacity, Insert With
 *       Name Reference, Insert With Literal Name, Duplicate) and references them. A section may
 *       reference entries the peer has not acknowledged yet, and so block, only while fewer than
 *       the peer's SETTINGS_QPACK_BLOCKED_STREAMS streams are blocked (or the stream already is);
 *       otherwise it uses only acknowledged entries and literals.
 * </ul>
 *
 * <pre>{@code
 * QpackEncoder qpack = new QpackEncoder(4096);
 * qpack.applyPeerSettings(peerSettings);
 * byte[] section = qpack.encode(streamId, fields);
 * encoderStream.write(qpack.encoderStreamBytes());   // first, or together with the section
 * requestStream.writeHeaders(section);
 * // Bytes from the peer's QPACK decoder stream:
 * qpack.onDecoderStream(bytes, 0, n);
 * }</pre>
 *
 * <p>The peer's decoder-stream instructions (Section Acknowledgment, Stream Cancellation, Insert
 * Count Increment) release references and advance the Known Received Count. An entry is evicted
 * only once its insertion has been acknowledged and no unacknowledged section references it
 * (§2.1.1); when that does not leave room, the field is sent as a literal instead.
 *
 * <p>A field marked {@link HeaderField#sensitive()}, or (unless turned off) one named in
 * {@link #SENSITIVE_NAMES}, is sent as a literal with the 'N' bit set and never enters the dynamic
 * table. Strings are Huffman-coded unless that would make them longer or {@link #setHuffman}
 * turns it off. Names are sent as given: lower-case them first.
 */
public final class QpackEncoder {

    /** Names whose fields are sent never-indexed by default: they carry credentials. */
    public static final Set<String> SENSITIVE_NAMES = Set.of("authorization", "cookie", "proxy-authorization", "set-cookie");

    private static final Http3ErrorCode DECODER_STREAM_ERROR = Http3ErrorCode.QPACK_DECODER_STREAM_ERROR;

    private final long tableCapacityLimit;
    private final QpackDynamicTable table = new QpackDynamicTable();
    private boolean huffman = true;
    private boolean neverIndexSensitiveNames = true;

    private long peerMaxTableCapacity;
    private long peerMaxBlockedStreams;
    private long peerMaxFieldSectionSize = Http3Settings.UNLIMITED;
    private long maxEntries;
    private boolean capacityChosen;

    private long knownReceivedCount;
    // Outstanding references per absolute index, from unacknowledged sections (and the one being encoded).
    private final Map<Long, Integer> references = new HashMap<>();
    // Unacknowledged sections that reference the dynamic table, oldest first, per stream.
    private final Map<Long, ArrayDeque<Section>> outstanding = new HashMap<>();

    private final ByteArrayOutputStream encoderStream = new ByteArrayOutputStream();
    private byte[] pending = new byte[16];
    private int pendingLength;

    private record Section(long requiredInsertCount, long[] references) {}

    /** A static-table-only encoder: it never uses the dynamic table, whatever the peer allows. */
    public QpackEncoder() {
        this(0);
    }

    /**
     * An encoder that will use a dynamic table of up to {@code maxTableCapacity} octets (memory it
     * is willing to spend), and no more than the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY. Until
     * {@link #applyPeerSettings} it works in static-only mode, which is valid with any peer.
     */
    public QpackEncoder(long maxTableCapacity) {
        if (maxTableCapacity < 0 || maxTableCapacity > QuicVarInt.MAX_VALUE) {
            throw new IllegalArgumentException("table capacity out of range: " + maxTableCapacity);
        }
        this.tableCapacityLimit = maxTableCapacity;
    }

    /** Whether to Huffman-code strings that do not get longer for it (default true). */
    public QpackEncoder setHuffman(boolean huffman) {
        this.huffman = huffman;
        return this;
    }

    /** Whether to send fields named in {@link #SENSITIVE_NAMES} never-indexed (default true). */
    public QpackEncoder setNeverIndexSensitiveNames(boolean neverIndexSensitiveNames) {
        this.neverIndexSensitiveNames = neverIndexSensitiveNames;
        return this;
    }

    /** Applies the QPACK settings and MAX_FIELD_SECTION_SIZE from the peer's SETTINGS. */
    public void applyPeerSettings(Http3Settings peer) {
        setPeerSettings(peer.qpackMaxTableCapacity(), peer.qpackBlockedStreams());
        peerMaxFieldSectionSize = peer.maxFieldSectionSize();
    }

    /**
     * Applies the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS. HTTP/3
     * sends SETTINGS once, so call this once.
     */
    public void setPeerSettings(long maxTableCapacity, long maxBlockedStreams) {
        if (maxTableCapacity < 0 || maxBlockedStreams < 0) throw new IllegalArgumentException("negative setting");
        this.peerMaxTableCapacity = maxTableCapacity;
        this.peerMaxBlockedStreams = maxBlockedStreams;
        this.maxEntries = maxTableCapacity / HeaderField.ENTRY_OVERHEAD;
    }

    /** The largest capacity the dynamic table may have: the smaller of our limit and the peer's. */
    public long maxDynamicTableCapacity() {
        return Math.min(tableCapacityLimit, peerMaxTableCapacity);
    }

    public long insertCount() {
        return table.insertCount();
    }

    /** How many inserts the peer's decoder has acknowledged (§2.1.4). */
    public long knownReceivedCount() {
        return knownReceivedCount;
    }

    public long dynamicTableSize() {
        return table.size();
    }

    public long dynamicTableCapacity() {
        return table.capacity();
    }

    public int dynamicTableLength() {
        return table.length();
    }

    /** The dynamic table entry with this absolute index, or null if absent. */
    public HeaderField dynamicTableEntry(long absoluteIndex) {
        return table.contains(absoluteIndex) ? table.get(absoluteIndex) : null;
    }

    /** The number of unacknowledged field sections that reference this entry. */
    public int referenceCount(long absoluteIndex) {
        return references.getOrDefault(absoluteIndex, 0);
    }

    /** The number of streams with a section that the peer cannot decode until it receives more inserts. */
    public int blockedStreams() {
        int n = 0;
        for (ArrayDeque<Section> sections : outstanding.values()) {
            if (blocking(sections)) n++;
        }
        return n;
    }

    /**
     * Takes the encoder-stream instructions produced so far; send them on the QPACK encoder stream
     * before, or together with, the sections that depend on them.
     *
     * @return the bytes, possibly none
     */
    public byte[] encoderStreamBytes() {
        byte[] b = encoderStream.toByteArray();
        encoderStream.reset();
        return b;
    }

    /**
     * Sets the dynamic table capacity, emitting a Set Dynamic Table Capacity instruction (§4.3.1).
     * Without this call, the first section or insert sets it to {@link #maxDynamicTableCapacity()}.
     *
     * @throws IllegalArgumentException above {@link #maxDynamicTableCapacity()}
     * @throws IllegalStateException if shrinking would evict an entry that is not evictable
     */
    public void setCapacity(long capacity) {
        if (capacity < 0 || capacity > maxDynamicTableCapacity()) {
            throw new IllegalArgumentException("capacity must be 0 to " + maxDynamicTableCapacity() + ", got " + capacity);
        }
        int evictions = evictionsFor(table.size() - capacity);
        if (evictions < 0) throw new IllegalStateException("cannot shrink the table: entries in use");
        capacityChosen = true;
        QpackWire.writeInt(encoderStream, 0x20, 5, capacity);
        table.setCapacity(capacity);
    }

    /**
     * Inserts a field into the dynamic table without referencing it, for later sections (a
     * speculative insert), choosing a name reference where one exists.
     *
     * @return the new entry's absolute index, or -1 if it did not fit
     */
    public long insert(String name, String value) {
        checkOctets(name);
        checkOctets(value);
        chooseCapacity();
        return insertEntry(new HeaderField(name, value));
    }

    /**
     * Re-inserts an existing entry with a Duplicate instruction (§4.3.4), so that sections can
     * reference a fresh copy while the old one becomes evictable.
     *
     * @return the new entry's absolute index, or -1 if there was no room
     * @throws IllegalArgumentException if the entry is not in the table
     */
    public long duplicate(long absoluteIndex) {
        if (!table.contains(absoluteIndex)) throw new IllegalArgumentException("no dynamic table entry " + absoluteIndex);
        HeaderField f = table.get(absoluteIndex);
        if (!makeRoom(f.size())) return -1;
        QpackWire.writeInt(encoderStream, 0x00, 5, table.insertCount() - 1 - absoluteIndex);
        table.add(f);
        return table.insertCount() - 1;
    }

    /**
     * Encodes one field section for a HEADERS or PUSH_PROMISE frame on the given stream, queuing
     * any encoder-stream instructions it needs.
     *
     * @throws IllegalArgumentException if a name or value has a char above U+00FF (not an octet),
     *     or the section is larger than the peer's SETTINGS_MAX_FIELD_SECTION_SIZE; nothing has
     *     changed then
     */
    public byte[] encode(long streamId, List<HeaderField> fields) {
        if (streamId < 0 || streamId > QuicVarInt.MAX_VALUE) throw new IllegalArgumentException("bad stream ID " + streamId);
        long sectionSize = 0;
        for (HeaderField f : fields) {
            checkOctets(f.name());
            checkOctets(f.value());
            sectionSize += f.size();
        }
        if (sectionSize > peerMaxFieldSectionSize) {
            throw new IllegalArgumentException("field section of " + sectionSize
                    + " octets exceeds the peer's SETTINGS_MAX_FIELD_SECTION_SIZE " + peerMaxFieldSectionSize);
        }
        chooseCapacity();
        boolean dynamic = table.capacity() > 0;
        long base = table.insertCount();
        ArrayDeque<Section> streamSections = outstanding.get(streamId);
        boolean mayBlock = (streamSections != null && blocking(streamSections)) || blockedStreams() < peerMaxBlockedStreams;
        long[] refs = new long[8];
        int refCount = 0;
        long maxReference = -1;

        ByteArrayOutputStream lines = new ByteArrayOutputStream();
        for (HeaderField f : fields) {
            String name = f.name();
            String value = f.value();
            boolean never = f.sensitive() || (neverIndexSensitiveNames && SENSITIVE_NAMES.contains(name));
            long reference = -1; // the dynamic entry this line references, if any
            if (!never) {
                int index = QpackStaticTable.indexOf(name, value);
                if (index >= 0) {
                    QpackWire.writeInt(lines, 0xc0, 6, index); // Indexed Field Line, static
                    continue;
                }
                if (dynamic) {
                    long found = findEntry(name, value, mayBlock);
                    if (found >= 0) {
                        reference = found;
                    } else if (f.size() <= table.capacity()) {
                        long inserted = insertEntry(new HeaderField(name, value));
                        if (inserted >= 0 && mayBlock) reference = inserted;
                    }
                }
            }
            if (reference >= 0) {
                if (reference < base) {
                    QpackWire.writeInt(lines, 0x80, 6, base - 1 - reference); // Indexed Field Line, dynamic
                } else {
                    QpackWire.writeInt(lines, 0x10, 4, reference - base); // Indexed Field Line with Post-Base Index
                }
            } else {
                int nameIndex = QpackStaticTable.indexOfName(name);
                long dynamicName = nameIndex < 0 && dynamic && !never ? findName(name, mayBlock) : -1;
                int nBit = never ? 1 : 0;
                if (nameIndex >= 0) {
                    QpackWire.writeInt(lines, 0x50 | nBit << 5, 4, nameIndex); // Literal, static name reference
                } else if (dynamicName >= 0) {
                    reference = dynamicName;
                    if (dynamicName < base) {
                        QpackWire.writeInt(lines, 0x40 | nBit << 5, 4, base - 1 - dynamicName); // Literal, dynamic name reference
                    } else {
                        QpackWire.writeInt(lines, nBit << 3, 3, dynamicName - base); // Literal, post-base name reference
                    }
                } else {
                    QpackWire.writeString(lines, 0x20 | nBit << 4, 3, name, huffman); // Literal with literal name
                }
                QpackWire.writeString(lines, 0x00, 7, value, huffman);
            }
            if (reference >= 0) {
                // Count the reference now, so that inserts later in this section cannot evict it.
                references.merge(reference, 1, Integer::sum);
                if (refCount == refs.length) refs = Arrays.copyOf(refs, refCount * 2);
                refs[refCount++] = reference;
                maxReference = Math.max(maxReference, reference);
            }
        }

        long requiredInsertCount = maxReference + 1;
        ByteArrayOutputStream out = new ByteArrayOutputStream(lines.size() + 4);
        if (requiredInsertCount == 0) {
            out.write(0);
            out.write(0);
        } else {
            QpackWire.writeInt(out, 0x00, 8, requiredInsertCount % (2 * maxEntries) + 1);
            if (base >= requiredInsertCount) {
                QpackWire.writeInt(out, 0x00, 7, base - requiredInsertCount);
            } else {
                QpackWire.writeInt(out, 0x80, 7, requiredInsertCount - base - 1);
            }
            outstanding.computeIfAbsent(streamId, k -> new ArrayDeque<>())
                    .add(new Section(requiredInsertCount, Arrays.copyOf(refs, refCount)));
        }
        out.writeBytes(lines.toByteArray());
        return out.toByteArray();
    }

    public void onDecoderStream(byte[] data) throws Http3Exception {
        onDecoderStream(data, 0, data.length);
    }

    /**
     * Processes bytes from the peer's QPACK decoder stream (§4.4), in any pieces: an instruction
     * split between calls is completed by the next.
     *
     * @throws Http3Exception a connection error QPACK_DECODER_STREAM_ERROR for an acknowledgment of
     *     a section that was not sent, an Insert Count Increment of 0 or past the inserts sent, or
     *     an integer overflow
     */
    public void onDecoderStream(byte[] data, int offset, int length) throws Http3Exception {
        Objects.checkFromIndexSize(offset, length, data.length);
        if (pendingLength + length > pending.length) {
            pending = Arrays.copyOf(pending, Math.max(pendingLength + length, pending.length * 2));
        }
        System.arraycopy(data, offset, pending, pendingLength, length);
        pendingLength += length;
        QpackWire.Input in = new QpackWire.Input(pending, 0, pendingLength, DECODER_STREAM_ERROR, true);
        int done = 0;
        try {
            while (in.hasRemaining()) {
                decoderInstruction(in);
                done = in.pos;
            }
        } catch (QpackWire.Incomplete e) {
            // Wait for the rest of the instruction.
        }
        System.arraycopy(pending, done, pending, 0, pendingLength - done);
        pendingLength -= done;
        if (pending.length > 256 && pendingLength < 16) pending = Arrays.copyOf(pending, 16);
    }

    private void decoderInstruction(QpackWire.Input in) throws Http3Exception, QpackWire.Incomplete {
        int b = in.peek();
        if ((b & 0x80) != 0) { // 1xxxxxxx: Section Acknowledgment (§4.4.1)
            long streamId = in.readInt(7);
            ArrayDeque<Section> sections = outstanding.get(streamId);
            if (sections == null) {
                throw in.fail("Section Acknowledgment for stream " + streamId + ", which has no unacknowledged field section");
            }
            Section s = sections.poll();
            if (sections.isEmpty()) outstanding.remove(streamId);
            release(s);
            knownReceivedCount = Math.max(knownReceivedCount, s.requiredInsertCount());
        } else if ((b & 0x40) != 0) { // 01xxxxxx: Stream Cancellation (§4.4.2)
            long streamId = in.readInt(6);
            ArrayDeque<Section> sections = outstanding.remove(streamId);
            if (sections != null) {
                for (Section s : sections) release(s);
            }
        } else { // 00xxxxxx: Insert Count Increment (§4.4.3)
            long increment = in.readInt(6);
            if (increment == 0) throw in.fail("Insert Count Increment of 0");
            if (increment > table.insertCount() - knownReceivedCount) {
                throw in.fail("Insert Count Increment of " + increment + " beyond the " + table.insertCount() + " inserts sent");
            }
            knownReceivedCount += increment;
        }
    }

    private void release(Section s) {
        for (long ref : s.references()) {
            references.computeIfPresent(ref, (k, n) -> n == 1 ? null : n - 1);
        }
    }

    private boolean blocking(ArrayDeque<Section> sections) {
        for (Section s : sections) {
            if (s.requiredInsertCount() > knownReceivedCount) return true;
        }
        return false;
    }

    /** Sets the table capacity on first use of the dynamic table, if the caller did not. */
    private void chooseCapacity() {
        if (!capacityChosen && maxDynamicTableCapacity() > 0) setCapacity(maxDynamicTableCapacity());
    }

    /**
     * Inserts an entry with an encoder instruction, evicting what is necessary and allowed.
     *
     * @return its absolute index, or -1 if there was no room
     */
    private long insertEntry(HeaderField f) {
        if (!makeRoom(f.size())) return -1;
        int staticName = QpackStaticTable.indexOfName(f.name());
        long dynamicName = staticName < 0 ? findName(f.name(), true) : -1;
        if (staticName >= 0) {
            QpackWire.writeInt(encoderStream, 0xc0, 6, staticName); // Insert with Name Reference, static
        } else if (dynamicName >= 0) {
            QpackWire.writeInt(encoderStream, 0x80, 6, table.insertCount() - 1 - dynamicName); // dynamic
        } else {
            QpackWire.writeString(encoderStream, 0x40, 5, f.name(), huffman); // Insert with Literal Name
        }
        QpackWire.writeString(encoderStream, 0x00, 7, f.value(), huffman);
        table.add(f);
        return table.insertCount() - 1;
    }

    /** Evicts the oldest entries until {@code entrySize} more octets fit; false (evicting nothing) if they cannot. */
    private boolean makeRoom(long entrySize) {
        if (entrySize > table.capacity()) return false;
        int evictions = evictionsFor(table.size() + entrySize - table.capacity());
        if (evictions < 0) return false;
        for (int i = 0; i < evictions; i++) table.evictOldest();
        return true;
    }

    /**
     * How many of the oldest entries must go to free {@code octets}, or -1 if one of them is not
     * evictable: unacknowledged, or referenced by an unacknowledged section (§2.1.1).
     */
    private int evictionsFor(long octets) {
        int n = 0;
        for (long abs = table.firstIndex(); octets > 0; abs++, n++) {
            if (abs >= table.insertCount() || abs >= knownReceivedCount || references.containsKey(abs)) return -1;
            octets -= table.get(abs).size();
        }
        return n;
    }

    /** The newest entry with this name and value, acknowledged unless {@code unacknowledged}; or -1. */
    private long findEntry(String name, String value, boolean unacknowledged) {
        long newest = unacknowledged ? table.insertCount() - 1 : Math.min(table.insertCount(), knownReceivedCount) - 1;
        for (long abs = newest; abs >= table.firstIndex(); abs--) {
            HeaderField e = table.get(abs);
            if (e.name().equals(name) && e.value().equals(value)) return abs;
        }
        return -1;
    }

    /** The newest entry with this name, acknowledged unless {@code unacknowledged}; or -1. */
    private long findName(String name, boolean unacknowledged) {
        long newest = unacknowledged ? table.insertCount() - 1 : Math.min(table.insertCount(), knownReceivedCount) - 1;
        for (long abs = newest; abs >= table.firstIndex(); abs--) {
            if (table.get(abs).name().equals(name)) return abs;
        }
        return -1;
    }

    private static void checkOctets(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 0xff) {
                throw new IllegalArgumentException("field contains a char that is not an octet: U+" + Integer.toHexString(s.charAt(i)));
            }
        }
    }
}
