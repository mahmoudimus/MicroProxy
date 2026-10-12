/*
 * Ported from quinn-proto src/frame.rs (StreamMeta) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.VarInt;
import java.nio.ByteBuffer;

/**
 * What a sent STREAM frame carried, without its data, which stays in the stream's {@link
 * SendBuffer}: kept with the sent packet to acknowledge or retransmit the range.
 *
 * @param id the stream
 * @param start the first stream offset carried
 * @param end one past the last stream offset carried
 * @param fin whether the frame carried the FIN bit
 */
public record StreamMeta(StreamId id, long start, long end, boolean fin) {

    /** The largest STREAM frame header: type, stream ID, offset and length. */
    public static final int SIZE_BOUND = 1 + 8 + 8 + 8;

    /**
     * Writes the STREAM frame header (RFC 9000 section 19.8); the data follows.
     *
     * @param length whether to include the Length field
     * @param out the buffer, written at its position
     */
    public void encodeHeader(boolean length, ByteBuffer out) {
        int type = 0x08;
        if (start != 0) {
            type |= 0x04;
        }
        if (length) {
            type |= 0x02;
        }
        if (fin) {
            type |= 0x01;
        }
        out.put((byte) type);
        VarInt.write(out, id.value());
        if (start != 0) {
            VarInt.write(out, start);
        }
        if (length) {
            VarInt.write(out, end - start);
        }
    }
}
