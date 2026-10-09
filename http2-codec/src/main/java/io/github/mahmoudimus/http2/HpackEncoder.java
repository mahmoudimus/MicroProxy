package io.github.mahmoudimus.http2;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Set;

/**
 * Encodes field sections into HPACK field blocks (RFC 7541). One encoder per connection direction;
 * blocks must be sent in the order they were encoded. Not thread-safe.
 *
 * <pre>{@code
 * HpackEncoder hpack = new HpackEncoder();
 * writer.writeHeaders(streamId, hpack.encode(fields), endStream);
 * }</pre>
 *
 * <p>Fields go out as an index when the static or dynamic table holds them, and otherwise as
 * literals added to the dynamic table, except:
 *
 * <ul>
 *   <li>a field marked {@link HeaderField#sensitive()}, or (unless turned off) one named in
 *       {@link #SENSITIVE_NAMES}, is sent as a never-indexed literal, so it never enters either
 *       side's compression context and intermediaries must forward it the same way;
 *   <li>a field larger than the whole table is sent without indexing.
 * </ul>
 *
 * <p>Strings are Huffman-coded unless that would make them longer or {@link #setHuffman(boolean)} turns it
 * off. Names are sent as given: lower-case them first ({@link Http2Headers} does).
 */
public final class HpackEncoder {

    /** Names whose fields are sent never-indexed by default: they carry credentials. */
    public static final Set<String> SENSITIVE_NAMES = Set.of("authorization", "cookie", "proxy-authorization", "set-cookie");

    private final DynamicTable table;
    private final int tableSizeLimit;
    private boolean huffman = true;
    private boolean neverIndexSensitiveNames = true;
    // Size updates owed to the peer's decoder, emitted at the start of the next block (§4.2).
    private int pendingMinCapacity = -1;
    private boolean sizeUpdatePending;

    /** An encoder with the protocol's initial table size, 4096, which it will not exceed. */
    public HpackEncoder() {
        this(Http2Settings.DEFAULT_HEADER_TABLE_SIZE);
    }

    /**
     * An encoder whose dynamic table starts at {@code maxHeaderTableSize}, which both sides must
     * already agree on (in HTTP/2, 4096). The table never grows beyond this, however large a
     * SETTINGS_HEADER_TABLE_SIZE the peer allows.
     */
    public HpackEncoder(int maxHeaderTableSize) {
        if (maxHeaderTableSize < 0) throw new IllegalArgumentException("negative table size");
        this.tableSizeLimit = maxHeaderTableSize;
        this.table = new DynamicTable(maxHeaderTableSize);
    }

    /** Whether to Huffman-code strings that do not get longer for it (default true). */
    public HpackEncoder setHuffman(boolean huffman) {
        this.huffman = huffman;
        return this;
    }

    /** Whether to send fields named in {@link #SENSITIVE_NAMES} never-indexed (default true). */
    public HpackEncoder setNeverIndexSensitiveNames(boolean neverIndexSensitiveNames) {
        this.neverIndexSensitiveNames = neverIndexSensitiveNames;
        return this;
    }

    /**
     * Applies the peer's SETTINGS_HEADER_TABLE_SIZE. The table is resized to the smaller of that and
     * this encoder's own limit, and the change is signalled at the start of the next block (both
     * the smallest size and the final one, if it shrank and grew again in between).
     */
    public void setMaxHeaderTableSize(long peerMaxHeaderTableSize) {
        if (peerMaxHeaderTableSize < 0) throw new IllegalArgumentException("negative table size");
        int capacity = (int) Math.min(peerMaxHeaderTableSize, tableSizeLimit);
        if (capacity == table.capacity() && !sizeUpdatePending) return;
        pendingMinCapacity = pendingMinCapacity < 0 ? capacity : Math.min(pendingMinCapacity, capacity);
        sizeUpdatePending = true;
        table.setCapacity(capacity);
    }

    /** The current size of the dynamic table in octets. */
    public int dynamicTableSize() {
        return table.size();
    }

    public int dynamicTableCapacity() {
        return table.capacity();
    }

    public int dynamicTableLength() {
        return table.length();
    }

    /** A dynamic table entry, 1 being the newest. */
    public HeaderField dynamicTableEntry(int index) {
        return table.get(index);
    }

    /** Encodes one field section into a field block. */
    public byte[] encode(List<HeaderField> fields) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encode(fields, out);
        return out.toByteArray();
    }

    /**
     * Encodes one field section, appending the field block to {@code out}.
     *
     * @throws IllegalArgumentException if a name or value has a char above U+00FF (not an octet)
     */
    public void encode(List<HeaderField> fields, ByteArrayOutputStream out) {
        for (HeaderField f : fields) {
            checkOctets(f.name());
            checkOctets(f.value());
        }
        if (sizeUpdatePending) {
            if (pendingMinCapacity < table.capacity()) writeInt(out, 0x20, 5, pendingMinCapacity);
            writeInt(out, 0x20, 5, table.capacity());
            sizeUpdatePending = false;
            pendingMinCapacity = -1;
        }
        for (HeaderField f : fields) {
            encodeField(f, out);
        }
    }

    private void encodeField(HeaderField f, ByteArrayOutputStream out) {
        String name = f.name();
        String value = f.value();
        if (f.sensitive() || (neverIndexSensitiveNames && SENSITIVE_NAMES.contains(name))) {
            literal(out, 0x10, 4, nameIndex(name), f);
            return;
        }
        int index = StaticTable.indexOf(name, value);
        if (index == 0) index = dynamicIndexOf(name, value);
        if (index != 0) {
            writeInt(out, 0x80, 7, index);
            return;
        }
        if (f.size() > table.capacity()) {
            literal(out, 0x00, 4, nameIndex(name), f);
        } else {
            literal(out, 0x40, 6, nameIndex(name), f);
            table.add(new HeaderField(name, value));
        }
    }

    private void literal(ByteArrayOutputStream out, int pattern, int prefixBits, int nameIndex, HeaderField f) {
        writeInt(out, pattern, prefixBits, nameIndex);
        if (nameIndex == 0) writeString(out, f.name());
        writeString(out, f.value());
    }

    private int nameIndex(String name) {
        int index = StaticTable.indexOfName(name);
        if (index != 0) return index;
        for (int i = 1; i <= table.length(); i++) {
            if (table.get(i).name().equals(name)) return StaticTable.LENGTH + i;
        }
        return 0;
    }

    private int dynamicIndexOf(String name, String value) {
        for (int i = 1; i <= table.length(); i++) {
            HeaderField e = table.get(i);
            if (e.name().equals(name) && e.value().equals(value)) return StaticTable.LENGTH + i;
        }
        return 0;
    }

    private void writeString(ByteArrayOutputStream out, String s) {
        if (huffman && !s.isEmpty()) {
            long encoded = Huffman.encodedLength(s);
            if (encoded <= s.length()) { // ties go to Huffman, as in RFC 7541 Appendix C
                writeInt(out, 0x80, 7, (int) encoded);
                Huffman.encode(s, out);
                return;
            }
        }
        writeInt(out, 0x00, 7, s.length());
        for (int i = 0; i < s.length(); i++) out.write(s.charAt(i));
    }

    /** An integer with an N-bit prefix (§5.1), the other bits of the first octet set to {@code pattern}. */
    static void writeInt(ByteArrayOutputStream out, int pattern, int prefixBits, int value) {
        int max = (1 << prefixBits) - 1;
        if (value < max) {
            out.write(pattern | value);
            return;
        }
        out.write(pattern | max);
        value -= max;
        while (value >= 0x80) {
            out.write((value & 0x7f) | 0x80);
            value >>>= 7;
        }
        out.write(value);
    }

    private static void checkOctets(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 0xff) {
                throw new IllegalArgumentException("field contains a char that is not an octet: U+" + Integer.toHexString(s.charAt(i)));
            }
        }
    }
}
