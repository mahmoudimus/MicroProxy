package io.github.mahmoudimus.http3;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Decodes QPACK field sections (RFC 9204) and keeps the dynamic table in step with the peer's
 * encoder. One decoder per connection, for the field sections the peer sends. Not thread-safe:
 * field sections from many streams and the encoder stream all go through it, so callers serialize
 * access (with a {@link java.util.concurrent.locks.ReentrantLock}, say, or one thread).
 *
 * <pre>{@code
 * QpackDecoder qpack = new QpackDecoder(4096, 16);   // what our SETTINGS advertise
 * // HEADERS on a request stream:
 * List<HeaderField> fields = qpack.decode(streamId, headers.fieldSection());
 * if (fields == null) { ... blocked: wait for the encoder stream ... }
 * // Bytes from the peer's QPACK encoder stream:
 * for (long ready : qpack.onEncoderStream(bytes)) resumeStream(ready, qpack.resume(ready));
 * // Then send what the peer's encoder needs to hear on our QPACK decoder stream:
 * decoderStream.write(qpack.decoderStreamBytes());
 * }</pre>
 *
 * <p>The decoder handles every field line representation (§4.5): indexed (static, dynamic
 * relative and post-base), literal with a name reference (static, dynamic and post-base) and
 * literal with a literal name. A literal's 'N' bit comes back as {@link HeaderField#sensitive()}.
 *
 * <p>A field section whose Required Insert Count is above the number of entries received so far is
 * <em>blocked</em>: {@link #decode} keeps it and returns null, and {@link #onEncoderStream} reports
 * its stream once enough entries have arrived, after which {@link #resume} decodes it. At most
 * {@code maxBlockedStreams} streams may be blocked (our SETTINGS_QPACK_BLOCKED_STREAMS); one more
 * is a connection error QPACK_DECOMPRESSION_FAILED (§2.2.1).
 *
 * <p>The decoder queues the decoder-stream instructions the encoder needs (§4.4): a Section
 * Acknowledgment for each decoded section that used the dynamic table, a Stream Cancellation for
 * each {@link #cancelStream}, and an Insert Count Increment for entries not otherwise
 * acknowledged, all returned by {@link #decoderStreamBytes()}.
 *
 * <p>Limits: {@link #setMaxFieldSectionSize(long)} (our SETTINGS_MAX_FIELD_SECTION_SIZE, default 64
 * KiB) bounds a decoded section, counting name + value + 32 per field; a larger one raises
 * {@link FieldSectionSizeException}, a stream error, after the section has been processed and
 * acknowledged, keeping only the fields within the limit. The table capacity bounds the encoder
 * stream's instructions: an entry that cannot fit is an error as soon as its length is read.
 * Any other malformed field section is a connection error QPACK_DECOMPRESSION_FAILED, and any
 * malformed encoder instruction a connection error QPACK_ENCODER_STREAM_ERROR; the decoder must not
 * be used after a connection error.
 */
public final class QpackDecoder {

    /**
     * The default limit on a decoded field section, 64 KiB.
     */
    public static final long DEFAULT_MAX_FIELD_SECTION_SIZE = 64 * 1024;

    private static final Http3ErrorCode SECTION_ERROR = Http3ErrorCode.QPACK_DECOMPRESSION_FAILED;
    private static final Http3ErrorCode ENCODER_STREAM_ERROR = Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR;

    private final long maxTableCapacity;
    private final int maxBlockedStreams;
    private final long maxEntries;
    private final QpackDynamicTable table = new QpackDynamicTable();
    private long maxFieldSectionSize = DEFAULT_MAX_FIELD_SECTION_SIZE;

    // The insert count the encoder knows we have, from our acknowledgments and increments.
    private long acknowledgedInsertCount;
    private final ByteArrayOutputStream decoderStream = new ByteArrayOutputStream();

    // Encoder-stream bytes holding an incomplete instruction.
    private byte[] pending = new byte[0];
    private int pendingLength;

    private final Map<Long, BlockedSection> blocked = new LinkedHashMap<>();

    private static final class BlockedSection {
        final byte[] section;
        final long requiredInsertCount;
        boolean reported;

        BlockedSection(byte[] section, long requiredInsertCount) {
            this.section = section;
            this.requiredInsertCount = requiredInsertCount;
        }
    }

    /** A static-table-only decoder: SETTINGS_QPACK_MAX_TABLE_CAPACITY and BLOCKED_STREAMS of 0. */
    public QpackDecoder() {
        this(0, 0);
    }

    /**
     * A decoder for the given settings, which this endpoint must advertise in its SETTINGS.
     *
     * @param maxTableCapacity SETTINGS_QPACK_MAX_TABLE_CAPACITY: the largest dynamic table the
     *     peer's encoder may use
     * @param maxBlockedStreams SETTINGS_QPACK_BLOCKED_STREAMS: how many streams may wait for
     *     encoder-stream updates at once
     */
    public QpackDecoder(long maxTableCapacity, int maxBlockedStreams) {
        if (maxTableCapacity < 0 || maxTableCapacity > QuicVarInt.MAX_VALUE) {
            throw new IllegalArgumentException("table capacity out of range: " + maxTableCapacity);
        }
        if (maxBlockedStreams < 0) throw new IllegalArgumentException("negative blocked streams");
        this.maxTableCapacity = maxTableCapacity;
        this.maxBlockedStreams = maxBlockedStreams;
        this.maxEntries = maxTableCapacity / HeaderField.ENTRY_OVERHEAD;
    }

    /**
     * SETTINGS_MAX_FIELD_SECTION_SIZE: the largest decoded field section accepted.
     *
     * @param maxFieldSectionSize the limit in octets
     */
    public void setMaxFieldSectionSize(long maxFieldSectionSize) {
        if (maxFieldSectionSize < 0) throw new IllegalArgumentException("negative limit");
        this.maxFieldSectionSize = maxFieldSectionSize;
    }

    /**
     * The largest decoded field section accepted.
     *
     * @return the limit in octets
     */
    public long maxFieldSectionSize() {
        return maxFieldSectionSize;
    }

    /**
     * The largest dynamic table the encoder may use: our SETTINGS_QPACK_MAX_TABLE_CAPACITY.
     *
     * @return the capacity in octets
     */
    public long maxTableCapacity() {
        return maxTableCapacity;
    }

    /**
     * How many streams may wait for the encoder stream: our SETTINGS_QPACK_BLOCKED_STREAMS.
     *
     * @return the number of streams
     */
    public int maxBlockedStreams() {
        return maxBlockedStreams;
    }

    /**
     * The number of entries inserted so far (the Insert Count).
     *
     * @return the Insert Count
     */
    public long insertCount() {
        return table.insertCount();
    }

    /**
     * The current size of the dynamic table in octets (entries plus 32 each).
     *
     * @return the size in octets
     */
    public long dynamicTableSize() {
        return table.size();
    }

    /**
     * The current capacity of the dynamic table, as last set by the peer's encoder.
     *
     * @return the capacity in octets
     */
    public long dynamicTableCapacity() {
        return table.capacity();
    }

    /**
     * The number of entries in the dynamic table.
     *
     * @return the number of entries
     */
    public int dynamicTableLength() {
        return table.length();
    }

    /**
     * The dynamic table entry with this absolute index (0 is the first ever inserted), or null if absent.
     *
     * @param absoluteIndex the absolute index
     * @return the entry, or null
     */
    public HeaderField dynamicTableEntry(long absoluteIndex) {
        return table.contains(absoluteIndex) ? table.get(absoluteIndex) : null;
    }

    /**
     * Whether a field section of this stream is waiting for encoder-stream updates.
     *
     * @param streamId the stream
     * @return whether it is blocked
     */
    public boolean isBlocked(long streamId) {
        return blocked.containsKey(streamId);
    }

    /**
     * The number of streams with a blocked field section.
     *
     * @return the number of blocked streams
     */
    public int blockedStreams() {
        return blocked.size();
    }

    /**
     * Decodes one encoded field section (the payload of a HEADERS or PUSH_PROMISE frame).
     *
     * @param streamId the stream the section came on
     * @param section the encoded field section
     * @return the fields in order, with never-indexed literals marked {@link HeaderField#sensitive()};
     *     or null if the section is blocked, in which case the decoder keeps a copy of it
     * @throws FieldSectionSizeException if the section is larger than the limit (a stream error)
     * @throws Http3Exception a connection error QPACK_DECOMPRESSION_FAILED if the section is
     *     malformed or one stream too many would be blocked
     * @throws IllegalStateException if a section of this stream is already blocked
     */
    public List<HeaderField> decode(long streamId, byte[] section) throws Http3Exception {
        Objects.requireNonNull(section, "section");
        if (blocked.containsKey(streamId)) throw new IllegalStateException("stream " + streamId + " is blocked");
        long requiredInsertCount = requiredInsertCount(section);
        if (requiredInsertCount > table.insertCount()) {
            if (blocked.size() >= maxBlockedStreams) {
                throw Http3Exception.connectionError(SECTION_ERROR,
                        "stream " + streamId + " would be blocked beyond SETTINGS_QPACK_BLOCKED_STREAMS " + maxBlockedStreams);
            }
            blocked.put(streamId, new BlockedSection(section.clone(), requiredInsertCount));
            return null;
        }
        return decodeSection(streamId, section, requiredInsertCount);
    }

    /**
     * Decodes the blocked field section of a stream that {@link #onEncoderStream} reported as
     * ready.
     *
     * @param streamId the stream
     * @throws IllegalStateException if the stream has no blocked section, or it is still blocked
     * @return the decoded fields
     * @throws Http3Exception as {@link #decode}
     */
    public List<HeaderField> resume(long streamId) throws Http3Exception {
        BlockedSection b = blocked.get(streamId);
        if (b == null) throw new IllegalStateException("stream " + streamId + " is not blocked");
        if (b.requiredInsertCount > table.insertCount()) throw new IllegalStateException("stream " + streamId + " is still blocked");
        blocked.remove(streamId);
        return decodeSection(streamId, b.section, b.requiredInsertCount);
    }

    /**
     * Reports that a stream was reset, or that its reading was abandoned, before all its field
     * sections were decoded. Drops any blocked section and queues a Stream Cancellation (§4.4.2),
     * unless the table capacity is 0 and the encoder cannot have referenced the table.
     *
     * @param streamId the stream
     */
    public void cancelStream(long streamId) {
        if (streamId < 0 || streamId > QuicVarInt.MAX_VALUE) throw new IllegalArgumentException("bad stream ID " + streamId);
        blocked.remove(streamId);
        if (maxTableCapacity > 0) QpackWire.writeInt(decoderStream, 0x40, 6, streamId);
    }

    /**
     * Takes the decoder-stream instructions queued so far, ending with an Insert Count Increment
     * for any entries received but not yet acknowledged; send them on the QPACK decoder stream.
     *
     * @return the bytes, possibly none
     */
    public byte[] decoderStreamBytes() {
        long unacknowledged = table.insertCount() - acknowledgedInsertCount;
        if (unacknowledged > 0) {
            QpackWire.writeInt(decoderStream, 0x00, 6, unacknowledged);
            acknowledgedInsertCount = table.insertCount();
        }
        byte[] b = decoderStream.toByteArray();
        decoderStream.reset();
        return b;
    }

    /**
     * Processes bytes from the peer's QPACK encoder stream; see {@link #onEncoderStream(byte[], int, int)}.
     *
     * @param data the bytes
     * @return the streams that can now be resumed
     * @throws Http3Exception a connection error QPACK_ENCODER_STREAM_ERROR for an invalid instruction
     */
    public List<Long> onEncoderStream(byte[] data) throws Http3Exception {
        return onEncoderStream(data, 0, data.length);
    }

    /**
     * Processes bytes from the peer's QPACK encoder stream (§4.3), in any pieces: an instruction
     * split between calls is completed by the next.
     *
     * @param data the bytes
     * @param offset where they start in {@code data}
     * @param length how many
     * @return the streams whose blocked field sections can now be decoded with {@link #resume},
     *     each reported once, in the order they blocked
     * @throws Http3Exception a connection error QPACK_ENCODER_STREAM_ERROR for an invalid instruction
     */
    public List<Long> onEncoderStream(byte[] data, int offset, int length) throws Http3Exception {
        Objects.checkFromIndexSize(offset, length, data.length);
        if (pendingLength + length > pending.length) {
            pending = Arrays.copyOf(pending, Math.max(pendingLength + length, pending.length * 2));
        }
        System.arraycopy(data, offset, pending, pendingLength, length);
        pendingLength += length;
        QpackWire.Input in = new QpackWire.Input(pending, 0, pendingLength, ENCODER_STREAM_ERROR, true);
        int done = 0;
        try {
            while (in.hasRemaining()) {
                encoderInstruction(in);
                done = in.pos;
            }
        } catch (QpackWire.Incomplete e) {
            // Wait for the rest of the instruction.
        }
        System.arraycopy(pending, done, pending, 0, pendingLength - done);
        pendingLength -= done;
        if (pending.length > 4096 && pendingLength < pending.length / 4) pending = Arrays.copyOf(pending, pendingLength);

        List<Long> ready = new ArrayList<>();
        for (Map.Entry<Long, BlockedSection> e : blocked.entrySet()) {
            BlockedSection b = e.getValue();
            if (!b.reported && b.requiredInsertCount <= table.insertCount()) {
                b.reported = true;
                ready.add(e.getKey());
            }
        }
        return ready;
    }

    private void encoderInstruction(QpackWire.Input in) throws Http3Exception, QpackWire.Incomplete {
        int b = in.peek();
        long room = table.capacity() - HeaderField.ENTRY_OVERHEAD;
        if ((b & 0x80) != 0) { // 1Txxxxxx: Insert with Name Reference (§4.3.2)
            boolean isStatic = (b & 0x40) != 0;
            long index = in.readInt(6);
            String name;
            if (isStatic) {
                if (index >= QpackStaticTable.LENGTH) throw in.fail("static table index " + index + " out of range");
                name = QpackStaticTable.ENTRIES[(int) index].name();
            } else {
                name = relative(in, index).name();
            }
            String value = in.readString(7, room - name.length());
            insert(in, new HeaderField(name, value));
        } else if ((b & 0x40) != 0) { // 01Hxxxxx: Insert with Literal Name (§4.3.3)
            String name = in.readString(5, room);
            String value = in.readString(7, room - name.length());
            insert(in, new HeaderField(name, value));
        } else if ((b & 0x20) != 0) { // 001xxxxx: Set Dynamic Table Capacity (§4.3.1)
            long capacity = in.readInt(5);
            if (capacity > maxTableCapacity) {
                throw in.fail("dynamic table capacity " + capacity + " exceeds SETTINGS_QPACK_MAX_TABLE_CAPACITY " + maxTableCapacity);
            }
            table.setCapacity(capacity);
        } else { // 000xxxxx: Duplicate (§4.3.4)
            long index = in.readInt(5);
            insert(in, relative(in, index));
        }
    }

    /** The entry a relative index on the encoder stream names (§3.2.5). */
    private HeaderField relative(QpackWire.Input in, long index) throws Http3Exception {
        long absolute = table.insertCount() - 1 - index;
        if (absolute < table.firstIndex()) {
            throw in.fail("relative index " + index + " names no dynamic table entry (insert count " + table.insertCount() + ")");
        }
        return table.get(absolute);
    }

    private void insert(QpackWire.Input in, HeaderField field) throws Http3Exception {
        if (field.size() > table.capacity()) {
            throw in.fail("entry of " + field.size() + " octets exceeds the dynamic table capacity " + table.capacity());
        }
        table.add(field);
    }

    /** The Required Insert Count of a section (§4.5.1.1). */
    private long requiredInsertCount(byte[] section) throws Http3Exception {
        QpackWire.Input in = new QpackWire.Input(section, 0, section.length, SECTION_ERROR, false);
        try {
            return requiredInsertCount(in);
        } catch (QpackWire.Incomplete e) {
            throw new AssertionError(e);
        }
    }

    private long requiredInsertCount(QpackWire.Input in) throws Http3Exception, QpackWire.Incomplete {
        long encoded = in.readInt(8);
        if (encoded == 0) return 0;
        long fullRange = 2 * maxEntries;
        if (encoded > fullRange) throw in.fail("encoded Required Insert Count " + encoded + " exceeds " + fullRange);
        long maxValue = table.insertCount() + maxEntries;
        long maxWrapped = (maxValue / fullRange) * fullRange;
        long required = maxWrapped + encoded - 1;
        if (required > maxValue) {
            if (required <= fullRange) throw in.fail("invalid encoded Required Insert Count " + encoded);
            required -= fullRange;
        }
        if (required == 0) throw in.fail("invalid encoded Required Insert Count " + encoded);
        return required;
    }

    private List<HeaderField> decodeSection(long streamId, byte[] section, long requiredInsertCount) throws Http3Exception {
        QpackWire.Input in = new QpackWire.Input(section, 0, section.length, SECTION_ERROR, false);
        try {
            in.readInt(8); // Required Insert Count, already known
            boolean negative = (in.peek() & 0x80) != 0;
            long delta = in.readInt(7);
            long base;
            if (negative) {
                if (delta >= requiredInsertCount) {
                    throw in.fail("negative Base: Required Insert Count " + requiredInsertCount + ", Delta Base -" + (delta + 1));
                }
                base = requiredInsertCount - delta - 1;
            } else {
                base = requiredInsertCount + delta;
            }
            List<HeaderField> fields = new ArrayList<>();
            long sectionSize = 0;
            while (in.hasRemaining()) {
                HeaderField field = fieldLine(in, base, requiredInsertCount);
                sectionSize += field.size();
                if (sectionSize <= maxFieldSectionSize) fields.add(field);
            }
            if (requiredInsertCount > 0) {
                QpackWire.writeInt(decoderStream, 0x80, 7, streamId);
                acknowledgedInsertCount = Math.max(acknowledgedInsertCount, requiredInsertCount);
            }
            if (sectionSize > maxFieldSectionSize) throw new FieldSectionSizeException(streamId, sectionSize, maxFieldSectionSize);
            return fields;
        } catch (QpackWire.Incomplete e) {
            throw new AssertionError(e);
        }
    }

    private HeaderField fieldLine(QpackWire.Input in, long base, long requiredInsertCount)
            throws Http3Exception, QpackWire.Incomplete {
        int b = in.peek();
        if ((b & 0x80) != 0) { // 1Txxxxxx: Indexed Field Line (§4.5.2)
            boolean isStatic = (b & 0x40) != 0;
            long index = in.readInt(6);
            if (isStatic) return staticEntry(in, index);
            return dynamicEntry(in, base - 1 - index, requiredInsertCount);
        }
        if ((b & 0x40) != 0) { // 01NTxxxx: Literal Field Line with Name Reference (§4.5.4)
            boolean never = (b & 0x20) != 0;
            boolean isStatic = (b & 0x10) != 0;
            long index = in.readInt(4);
            String name = isStatic ? staticEntry(in, index).name() : dynamicEntry(in, base - 1 - index, requiredInsertCount).name();
            return new HeaderField(name, in.readString(7, Long.MAX_VALUE), never);
        }
        if ((b & 0x20) != 0) { // 001NHxxx: Literal Field Line with Literal Name (§4.5.6)
            boolean never = (b & 0x10) != 0;
            String name = in.readString(3, Long.MAX_VALUE);
            return new HeaderField(name, in.readString(7, Long.MAX_VALUE), never);
        }
        if ((b & 0x10) != 0) { // 0001xxxx: Indexed Field Line with Post-Base Index (§4.5.3)
            long index = in.readInt(4);
            return dynamicEntry(in, base + index, requiredInsertCount);
        }
        // 0000Nxxx: Literal Field Line with Post-Base Name Reference (§4.5.5)
        boolean never = (b & 0x08) != 0;
        long index = in.readInt(3);
        String name = dynamicEntry(in, base + index, requiredInsertCount).name();
        return new HeaderField(name, in.readString(7, Long.MAX_VALUE), never);
    }

    private static HeaderField staticEntry(QpackWire.Input in, long index) throws Http3Exception {
        if (index >= QpackStaticTable.LENGTH) throw in.fail("static table index " + index + " out of range");
        return QpackStaticTable.ENTRIES[(int) index];
    }

    private HeaderField dynamicEntry(QpackWire.Input in, long absolute, long requiredInsertCount) throws Http3Exception {
        if (absolute < 0 || absolute >= requiredInsertCount) {
            throw in.fail("dynamic table reference " + absolute + " outside the Required Insert Count " + requiredInsertCount);
        }
        if (absolute < table.firstIndex()) throw in.fail("dynamic table entry " + absolute + " was evicted");
        return table.get(absolute);
    }
}
