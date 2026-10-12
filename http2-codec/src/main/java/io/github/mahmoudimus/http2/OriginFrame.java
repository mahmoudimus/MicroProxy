package io.github.mahmoudimus.http2;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The ORIGIN frame (RFC 8336): a server names the origins it is authoritative for on the
 * connection, such as {@code https://b.example.com} or {@code https://b.example.com:8443}, so a
 * client may send requests for them there without consulting DNS.
 *
 * <p>It is an extension frame, not one of RFC 9113's types, so it travels as a {@link
 * Frame.Unknown} of type {@link FrameType#ORIGIN}: {@link FrameReader} returns it when asked to
 * ({@link FrameReader#setDeliverOriginFrames(boolean)}), and {@link FrameWriter#writeFrame(Frame)}
 * writes the one {@link #frame} builds. Its payload is a sequence of Origin-Entry fields, each a
 * 16-bit length and that many octets of an origin's ASCII serialization. It defines no flags, and
 * one received on a stream other than 0 must be ignored (RFC 8336 section 2.1), as must one sent
 * to a server.
 *
 * <pre>{@code
 * case Frame.Unknown u when OriginFrame.isOrigin(u) -> {
 *     try {
 *         originSet.addAll(OriginFrame.origins(u));
 *     } catch (IllegalArgumentException malformed) {
 *         // ignored, as any extension frame may be
 *     }
 * }
 * }</pre>
 */
public final class OriginFrame {

    /** The longest origin an Origin-Entry can carry: its length is 16 bits. */
    public static final int MAX_ORIGIN_LENGTH = 0xffff;

    private OriginFrame() {}

    /**
     * Whether {@code frame} is an ORIGIN frame a client acts on: of type {@link FrameType#ORIGIN}
     * and on stream 0 (one on any other stream is ignored).
     *
     * @param frame any frame
     * @return true for an ORIGIN frame on stream 0
     */
    public static boolean isOrigin(Frame frame) {
        return frame instanceof Frame.Unknown u && u.type() == FrameType.ORIGIN && u.streamId() == 0;
    }

    /**
     * The origins an ORIGIN frame names, in the order it names them.
     *
     * @param frame an ORIGIN frame
     * @return the origins' ASCII serializations, as sent (an empty one stays empty)
     * @throws IllegalArgumentException if the frame is not of type ORIGIN, or is malformed: an
     *     entry runs past the end of the payload, or holds non-ASCII octets
     */
    public static List<String> origins(Frame.Unknown frame) {
        if (frame.type() != FrameType.ORIGIN) {
            throw new IllegalArgumentException("not an ORIGIN frame: " + FrameType.name(frame.type()));
        }
        return decode(frame.payload());
    }

    /**
     * Reads an ORIGIN frame's payload.
     *
     * @param payload the frame's payload
     * @return the origins' ASCII serializations, in order
     * @throws IllegalArgumentException if an entry runs past the end of the payload, or holds
     *     non-ASCII octets
     */
    public static List<String> decode(byte[] payload) {
        List<String> origins = new ArrayList<>();
        int pos = 0;
        while (pos < payload.length) {
            if (payload.length - pos < 2) {
                throw new IllegalArgumentException("ORIGIN entry truncated in its length at offset " + pos);
            }
            int length = (payload[pos] & 0xff) << 8 | (payload[pos + 1] & 0xff);
            pos += 2;
            if (length > payload.length - pos) {
                throw new IllegalArgumentException("ORIGIN entry of " + length + " octets runs past the payload");
            }
            for (int i = pos; i < pos + length; i++) {
                if (payload[i] < 0) throw new IllegalArgumentException("non-ASCII octet in an ORIGIN entry");
            }
            origins.add(new String(payload, pos, length, StandardCharsets.US_ASCII));
            pos += length;
        }
        return origins;
    }

    /**
     * Builds an ORIGIN frame's payload.
     *
     * @param origins the origins' ASCII serializations, such as {@code https://example.com}
     * @return the payload: each origin preceded by its 16-bit length
     * @throws IllegalArgumentException if an origin is not ASCII or longer than {@link
     *     #MAX_ORIGIN_LENGTH} octets
     */
    public static byte[] encode(List<String> origins) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String origin : origins) {
            Objects.requireNonNull(origin, "origin");
            for (int i = 0; i < origin.length(); i++) {
                if (origin.charAt(i) > 0x7f) throw new IllegalArgumentException("origin is not ASCII: " + origin);
            }
            if (origin.length() > MAX_ORIGIN_LENGTH) {
                throw new IllegalArgumentException(
                        "origin of " + origin.length() + " octets exceeds " + MAX_ORIGIN_LENGTH);
            }
            out.write(origin.length() >>> 8);
            out.write(origin.length());
            out.writeBytes(origin.getBytes(StandardCharsets.US_ASCII));
        }
        return out.toByteArray();
    }

    /**
     * An ORIGIN frame naming {@code origins}, on stream 0 and without flags, for {@link
     * FrameWriter#writeFrame(Frame)}.
     *
     * @param origins the origins' ASCII serializations
     * @return the frame
     * @throws IllegalArgumentException as {@link #encode} does
     */
    public static Frame.Unknown frame(List<String> origins) {
        return new Frame.Unknown(FrameType.ORIGIN, 0, 0, encode(origins));
    }
}
