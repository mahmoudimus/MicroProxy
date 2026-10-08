package org.microproxy.http;

import java.nio.charset.StandardCharsets;

/**
 * A WebSocket frame (RFC 6455 section 5.2) observed by the proxy after an upgrade. The proxy
 * relays frames unchanged; this is a read-only view for {@link
 * org.microproxy.HttpFilters#webSocketFrameReceived(WebSocketFrame, boolean)}.
 */
public final class WebSocketFrame {

    public static final int OPCODE_CONTINUATION = 0x0;
    public static final int OPCODE_TEXT = 0x1;
    public static final int OPCODE_BINARY = 0x2;
    public static final int OPCODE_CLOSE = 0x8;
    public static final int OPCODE_PING = 0x9;
    public static final int OPCODE_PONG = 0xA;

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
                org.microproxy.simd.Simd.xorMask(out, 0, out.length, key);
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
