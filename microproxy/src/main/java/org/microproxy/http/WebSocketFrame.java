package org.microproxy.http;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.microproxy.simd.Simd;

/**
 * A WebSocket frame (RFC 6455 section 5.2). Frames the proxy relays after an upgrade are shown to
 * {@link org.microproxy.HttpFilters#webSocketFrameReceived(WebSocketFrame, boolean)} and {@link
 * org.microproxy.HttpFilters#filterWebSocketFrame(WebSocketFrame, boolean)}; the latter may return
 * a frame built with {@link #text(String)}, {@link #binary(byte[])}, {@link #withPayload(byte[])}
 * and the like to send instead. Frames are immutable.
 *
 * <p>Built frames carry an unmasked payload. The proxy masks a frame when it sends it towards the
 * server and leaves it unmasked towards the client, as RFC 6455 requires ({@link #toWire(boolean)}).
 */
public final class WebSocketFrame {

    public static final int OPCODE_CONTINUATION = 0x0;
    public static final int OPCODE_TEXT = 0x1;
    public static final int OPCODE_BINARY = 0x2;
    public static final int OPCODE_CLOSE = 0x8;
    public static final int OPCODE_PING = 0x9;
    public static final int OPCODE_PONG = 0xA;

    private static final SecureRandom MASKS = new SecureRandom();

    private final byte[] header;
    private final byte[] maskedPayload;
    private final long payloadLength;
    private byte[] unmasked;

    /**
     * @param header the frame header as on the wire (2-14 bytes)
     * @param wirePayload the payload as on the wire (still masked), or {@code null} if the frame was
     *     too large to buffer
     * @param payloadLength the payload length declared in the header
     */
    public WebSocketFrame(byte[] header, byte[] wirePayload, long payloadLength) {
        this.header = header;
        this.maskedPayload = wirePayload;
        this.payloadLength = payloadLength;
    }

    /**
     * A frame with the given fields and an unmasked payload.
     *
     * @param rsv the RSV1-3 bits (0 unless an extension defines them)
     */
    public static WebSocketFrame of(boolean fin, int rsv, int opcode, byte[] payload) {
        if ((opcode & ~0x0f) != 0) throw new IllegalArgumentException("opcode " + opcode);
        if ((rsv & ~0x7) != 0) throw new IllegalArgumentException("rsv " + rsv);
        byte[] body = payload.clone();
        if (opcode >= OPCODE_CLOSE && body.length > 125) {
            throw new IllegalArgumentException("control frame payload over 125 bytes");
        }
        return new WebSocketFrame(header(fin, rsv, opcode, body.length, false), body, body.length);
    }

    /** A final text frame. */
    public static WebSocketFrame text(String text) {
        return of(true, 0, OPCODE_TEXT, text.getBytes(StandardCharsets.UTF_8));
    }

    /** A final binary frame. */
    public static WebSocketFrame binary(byte[] data) {
        return of(true, 0, OPCODE_BINARY, data);
    }

    /** A close frame with a status code (RFC 6455 section 7.4) and a reason. */
    public static WebSocketFrame close(int code, String reason) {
        byte[] text = reason.getBytes(StandardCharsets.UTF_8);
        byte[] body = new byte[2 + text.length];
        body[0] = (byte) (code >> 8);
        body[1] = (byte) code;
        System.arraycopy(text, 0, body, 2, text.length);
        return of(true, 0, OPCODE_CLOSE, body);
    }

    /** This frame's FIN bit, RSV bits and opcode with a new payload. */
    public WebSocketFrame withPayload(byte[] payload) {
        return of(isFinal(), rsv(), opcode(), payload);
    }

    /** This frame's FIN bit, RSV bits and opcode with a new payload, encoded as UTF-8. */
    public WebSocketFrame withText(String text) {
        return withPayload(text.getBytes(StandardCharsets.UTF_8));
    }

    public boolean isFinal() {
        return (header[0] & 0x80) != 0;
    }

    /** The RSV1-3 bits (bit 2 = RSV1, used by permessage-deflate). */
    public int rsv() {
        return (header[0] >> 4) & 0x7;
    }

    public int opcode() {
        return header[0] & 0x0f;
    }

    public boolean isText() {
        return opcode() == OPCODE_TEXT;
    }

    public boolean isBinary() {
        return opcode() == OPCODE_BINARY;
    }

    public boolean isContinuation() {
        return opcode() == OPCODE_CONTINUATION;
    }

    public boolean isClose() {
        return opcode() == OPCODE_CLOSE;
    }

    public boolean isPing() {
        return opcode() == OPCODE_PING;
    }

    public boolean isPong() {
        return opcode() == OPCODE_PONG;
    }

    /** Whether the payload is masked (always true for client-to-server frames). */
    public boolean isMasked() {
        return (header[1] & 0x80) != 0;
    }

    public long payloadLength() {
        return payloadLength;
    }

    /** Whether the payload was too large to buffer, in which case {@link #payload()} is null. */
    public boolean isTruncated() {
        return maskedPayload == null;
    }

    /** The unmasked application payload, or {@code null} if {@link #isTruncated()}. */
    public byte[] payload() {
        if (maskedPayload == null) return null;
        if (unmasked == null) {
            byte[] out = maskedPayload.clone();
            if (isMasked()) {
                int k = header.length - 4;
                int key = (header[k] & 0xff) << 24 | (header[k + 1] & 0xff) << 16
                        | (header[k + 2] & 0xff) << 8 | (header[k + 3] & 0xff);
                Simd.xorMask(out, 0, out.length, key);
            }
            unmasked = out;
        }
        return unmasked.clone();
    }

    /** The payload decoded as UTF-8 (meaningful for text frames), or null if truncated. */
    public String payloadAsText() {
        byte[] p = payload();
        return p == null ? null : new String(p, StandardCharsets.UTF_8);
    }

    /**
     * The frame encoded for sending: masked with a fresh random key when {@code masked} (frames
     * towards a server), unmasked otherwise.
     *
     * @throws IllegalStateException if the frame is {@linkplain #isTruncated() truncated}
     */
    public byte[] toWire(boolean masked) {
        byte[] body = payload();
        if (body == null) throw new IllegalStateException("truncated frames cannot be re-encoded");
        byte[] head = header(isFinal(), rsv(), opcode(), body.length, masked);
        if (masked) {
            int key = MASKS.nextInt();
            int k = head.length - 4;
            head[k] = (byte) (key >> 24);
            head[k + 1] = (byte) (key >> 16);
            head[k + 2] = (byte) (key >> 8);
            head[k + 3] = (byte) key;
            Simd.xorMask(body, 0, body.length, key);
        }
        byte[] out = new byte[head.length + body.length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(body, 0, out, head.length, body.length);
        return out;
    }

    private static byte[] header(boolean fin, int rsv, int opcode, int length, boolean masked) {
        int lengthBytes = length < 126 ? 0 : length <= 0xffff ? 2 : 8;
        byte[] head = new byte[2 + lengthBytes + (masked ? 4 : 0)];
        head[0] = (byte) ((fin ? 0x80 : 0) | rsv << 4 | opcode);
        int mask = masked ? 0x80 : 0;
        if (lengthBytes == 0) {
            head[1] = (byte) (mask | length);
        } else if (lengthBytes == 2) {
            head[1] = (byte) (mask | 126);
            head[2] = (byte) (length >> 8);
            head[3] = (byte) length;
        } else {
            head[1] = (byte) (mask | 127);
            for (int i = 0; i < 8; i++) {
                head[2 + i] = (byte) ((long) length >> (56 - 8 * i));
            }
        }
        return head;
    }

    /** The frame exactly as on the wire: header plus (masked) payload, or just the header if truncated. */
    public byte[] rawBytes() {
        int payloadBytes = maskedPayload == null ? 0 : maskedPayload.length;
        byte[] out = new byte[header.length + payloadBytes];
        System.arraycopy(header, 0, out, 0, header.length);
        if (maskedPayload != null) {
            System.arraycopy(maskedPayload, 0, out, header.length, payloadBytes);
        }
        return out;
    }

    @Override
    public String toString() {
        return "WebSocketFrame[opcode=" + opcode() + ", fin=" + isFinal() + ", length=" + payloadLength
                + (isTruncated() ? ", truncated" : "") + "]";
    }
}
