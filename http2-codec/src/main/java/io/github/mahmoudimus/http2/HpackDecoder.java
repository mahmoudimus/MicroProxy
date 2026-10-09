package io.github.mahmoudimus.http2;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Decodes HPACK field blocks (RFC 7541). One decoder per connection direction, fed every field
 * block the peer sends, in order: each block can change the dynamic table the next one refers to.
 * Not thread-safe.
 *
 * <pre>{@code
 * HpackDecoder hpack = new HpackDecoder();
 * List<HeaderField> fields = hpack.decode(headers.streamId(), headers.fieldBlock());
 * }</pre>
 *
 * <p>Limits, so a peer cannot make it use much memory or time (the "HPACK bomb"):
 *
 * <ul>
 *   <li>{@link #setMaxHeaderTableSize(int)}: the SETTINGS_HEADER_TABLE_SIZE this endpoint advertised
 *       (default 4096). A dynamic table size update above it is a COMPRESSION_ERROR.
 *   <li>{@link #setMaxHeaderListSize(long)}: SETTINGS_MAX_HEADER_LIST_SIZE, the decoded size of a
 *       field section, counting 32 octets per field (default 64 KiB). Exceeding it raises
 *       {@link HeaderListSizeException}, a stream error, after the whole block has been processed
 *       so the dynamic table stays in step; fields past the limit are not kept.
 *   <li>{@link #setMaxStringLength(int)}: the longest name or value, before or after Huffman
 *       decoding (default 64 KiB); a longer one is a connection error ENHANCE_YOUR_CALM.
 * </ul>
 *
 * <p>Any other malformed input is a connection error COMPRESSION_ERROR (RFC 9113 §4.3): an index
 * outside the tables, an integer over 2^31-1, a string running past the block, bad Huffman
 * padding or EOS, a size update after the first field or missing when one is required.
 * After a connection error the decoder's state is undefined and the connection must be closed.
 */
public final class HpackDecoder {

    public static final long DEFAULT_MAX_HEADER_LIST_SIZE = 64 * 1024;
    public static final int DEFAULT_MAX_STRING_LENGTH = 64 * 1024;

    private final DynamicTable table;
    private int maxTableSize;
    private boolean sizeUpdateRequired;
    private long maxHeaderListSize = DEFAULT_MAX_HEADER_LIST_SIZE;
    private int maxStringLength = DEFAULT_MAX_STRING_LENGTH;

    // The block being decoded.
    private byte[] buf;
    private int pos;
    private int end;

    /** A decoder with the protocol's initial table size, 4096. */
    public HpackDecoder() {
        this(Http2Settings.DEFAULT_HEADER_TABLE_SIZE);
    }

    /**
     * A decoder whose dynamic table starts with the given maximum size, which both sides must
     * already agree on: in HTTP/2, 4096 (the initial SETTINGS_HEADER_TABLE_SIZE).
     */
    public HpackDecoder(int maxHeaderTableSize) {
        if (maxHeaderTableSize < 0) throw new IllegalArgumentException("negative table size");
        this.maxTableSize = maxHeaderTableSize;
        this.table = new DynamicTable(maxHeaderTableSize);
    }

    /**
     * Sets the largest dynamic table the peer's encoder may use: call this when the peer
     * acknowledges a SETTINGS frame that carried SETTINGS_HEADER_TABLE_SIZE. If the table is now
     * larger than allowed, the next field block must start with a size update that shrinks it.
     */
    public void setMaxHeaderTableSize(int maxHeaderTableSize) {
        if (maxHeaderTableSize < 0) throw new IllegalArgumentException("negative table size");
        this.maxTableSize = maxHeaderTableSize;
        if (maxHeaderTableSize < table.capacity()) sizeUpdateRequired = true;
    }

    public int maxHeaderTableSize() {
        return maxTableSize;
    }

    /** SETTINGS_MAX_HEADER_LIST_SIZE: the largest decoded field section accepted. */
    public void setMaxHeaderListSize(long maxHeaderListSize) {
        if (maxHeaderListSize < 0) throw new IllegalArgumentException("negative limit");
        this.maxHeaderListSize = maxHeaderListSize;
    }

    public long maxHeaderListSize() {
        return maxHeaderListSize;
    }

    /** The longest name or value accepted, in octets. */
    public void setMaxStringLength(int maxStringLength) {
        if (maxStringLength < 0) throw new IllegalArgumentException("negative limit");
        this.maxStringLength = maxStringLength;
    }

    /** The current size of the dynamic table in octets (entries plus 32 each). */
    public int dynamicTableSize() {
        return table.size();
    }

    /** The current maximum size of the dynamic table, as last set by the peer's encoder. */
    public int dynamicTableCapacity() {
        return table.capacity();
    }

    /** The number of entries in the dynamic table. */
    public int dynamicTableLength() {
        return table.length();
    }

    /** A dynamic table entry, 1 being the newest (HPACK index 62). */
    public HeaderField dynamicTableEntry(int index) {
        return table.get(index);
    }

    public List<HeaderField> decode(int streamId, byte[] block) throws Http2Exception {
        return decode(streamId, block, 0, block.length);
    }

    /**
     * Decodes one complete field block.
     *
     * @param streamId the stream the block belongs to, for {@link HeaderListSizeException}
     * @return the fields in order; never-indexed literals come back with
     *     {@link HeaderField#sensitive()} set
     */
    public List<HeaderField> decode(int streamId, byte[] block, int offset, int length) throws Http2Exception {
        Objects.checkFromIndexSize(offset, length, block.length);
        buf = block;
        pos = offset;
        end = offset + length;
        try {
            List<HeaderField> fields = new ArrayList<>();
            long listSize = 0;
            boolean fieldSeen = false;
            while (pos < end) {
                int b = buf[pos] & 0xff;
                if ((b & 0xe0) == 0x20) { // 001xxxxx: dynamic table size update (§6.3)
                    if (fieldSeen) throw compressionError("dynamic table size update after a field");
                    int size = readInt(5);
                    if (size > maxTableSize) {
                        throw compressionError("dynamic table size update to " + size + " exceeds the limit " + maxTableSize);
                    }
                    table.setCapacity(size);
                    sizeUpdateRequired = false;
                    continue;
                }
                if (sizeUpdateRequired) throw compressionError("field block must start with a dynamic table size update");
                fieldSeen = true;
                HeaderField field;
                if ((b & 0x80) != 0) { // 1xxxxxxx: indexed field (§6.1)
                    field = lookup(readInt(7));
                } else if ((b & 0x40) != 0) { // 01xxxxxx: literal with incremental indexing (§6.2.1)
                    field = literal(6, false);
                    table.add(field);
                } else { // 0000xxxx without indexing, 0001xxxx never indexed (§6.2.2, §6.2.3)
                    field = literal(4, (b & 0x10) != 0);
                }
                listSize += field.size();
                if (listSize <= maxHeaderListSize) fields.add(field);
            }
            if (sizeUpdateRequired) throw compressionError("field block must start with a dynamic table size update");
            if (listSize > maxHeaderListSize) throw new HeaderListSizeException(streamId, listSize, maxHeaderListSize);
            return fields;
        } finally {
            buf = null;
        }
    }

    private HeaderField literal(int prefixBits, boolean neverIndexed) throws Http2Exception {
        int nameIndex = readInt(prefixBits);
        String name = nameIndex == 0 ? readString() : lookup(nameIndex).name();
        String value = readString();
        return new HeaderField(name, value, neverIndexed);
    }

    private HeaderField lookup(int index) throws Http2Exception {
        if (index == 0) throw compressionError("index 0");
        if (index <= StaticTable.LENGTH) return StaticTable.ENTRIES[index];
        int dynamic = index - StaticTable.LENGTH;
        if (dynamic > table.length()) {
            throw compressionError("index " + index + " beyond the dynamic table of " + table.length() + " entries");
        }
        return table.get(dynamic);
    }

    /** An integer with an N-bit prefix (§5.1); values above 2^31-1 are rejected. */
    private int readInt(int prefixBits) throws Http2Exception {
        int max = (1 << prefixBits) - 1;
        int value = buf[pos++] & max;
        if (value < max) return value;
        long v = max;
        for (int shift = 0; ; shift += 7) {
            if (pos >= end) throw compressionError("truncated integer");
            if (shift > 28) throw compressionError("integer overflow");
            int b = buf[pos++] & 0xff;
            v += (long) (b & 0x7f) << shift;
            if (v > Integer.MAX_VALUE) throw compressionError("integer overflow");
            if ((b & 0x80) == 0) return (int) v;
        }
    }

    /** A string literal (§5.2), as one char per octet. */
    private String readString() throws Http2Exception {
        if (pos >= end) throw compressionError("truncated field");
        boolean huffman = (buf[pos] & 0x80) != 0;
        int length = readInt(7);
        if (length > end - pos) throw compressionError("string of " + length + " octets runs past the field block");
        String s;
        if (huffman) {
            s = Huffman.decode(buf, pos, length, maxStringLength);
        } else {
            if (length > maxStringLength) {
                throw Http2Exception.connectionError(ErrorCode.ENHANCE_YOUR_CALM,
                        "string of " + length + " octets exceeds the limit " + maxStringLength);
            }
            s = new String(buf, pos, length, StandardCharsets.ISO_8859_1);
        }
        pos += length;
        return s;
    }

    private static Http2Exception compressionError(String message) {
        return Http2Exception.connectionError(ErrorCode.COMPRESSION_ERROR, message);
    }
}
