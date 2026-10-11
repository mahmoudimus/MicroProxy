/*
 * Ported from quinn-proto src/token.rs (ResetToken) and src/constant_time.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * A 16-byte stateless reset token (RFC 9000 section 10.3), as carried in NEW_CONNECTION_ID
 * frames, the {@code stateless_reset_token} transport parameter and the tail of a Stateless Reset.
 *
 * <p>{@link #equals(Object)} and {@link #matches(ByteBuffer)} compare in constant time ({@link
 * MessageDigest#isEqual}), so a peer cannot learn a token byte by byte from timing. Instances are
 * immutable and thread-safe.
 */
public final class StatelessResetToken {

    /** The token length in bytes. */
    public static final int LENGTH = 16;

    /**
     * The smallest datagram that can be a Stateless Reset: 5 bytes that look like a short header
     * plus the token (RFC 9000 section 10.3).
     */
    public static final int MIN_RESET_DATAGRAM = 21;

    private final byte[] bytes;

    private StatelessResetToken(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * A token with a copy of some bytes.
     *
     * @param bytes exactly {@link #LENGTH} bytes
     * @return the token
     * @throws IllegalArgumentException if the length is not 16
     */
    public static StatelessResetToken of(byte[] bytes) {
        if (bytes.length != LENGTH) {
            throw new IllegalArgumentException("stateless reset token length " + bytes.length);
        }
        return new StatelessResetToken(bytes.clone());
    }

    /**
     * Reads a token at the buffer's position.
     *
     * @param in the buffer; its position moves past the token
     * @return the token
     * @throws BufferUnderflowException if fewer than 16 bytes remain
     */
    public static StatelessResetToken read(ByteBuffer in) {
        if (in.remaining() < LENGTH) {
            throw new BufferUnderflowException();
        }
        byte[] b = new byte[LENGTH];
        in.get(b);
        return new StatelessResetToken(b);
    }

    /**
     * Derives the token for a connection ID from a static key, as quinn does: the first 16 bytes
     * of HMAC-SHA256(key, connection ID). An endpoint that keeps the key can then reset
     * connections it has forgotten (RFC 9000 section 10.3.2).
     *
     * @param staticKey a secret key of at least 32 random bytes
     * @param connectionId the connection ID the token belongs to
     * @return the token
     */
    public static StatelessResetToken derive(byte[] staticKey, ConnectionId connectionId) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(staticKey, "HmacSHA256"));
            return new StatelessResetToken(Arrays.copyOf(mac.doFinal(connectionId.toByteArray()), LENGTH));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("JDK lacks HmacSHA256", e);
        }
    }

    /**
     * A copy of the bytes.
     *
     * @return a new 16-byte array
     */
    public byte[] toByteArray() {
        return bytes.clone();
    }

    /**
     * Writes the token.
     *
     * @param out the buffer, written at its position
     */
    public void writeTo(ByteBuffer out) {
        out.put(bytes);
    }

    /**
     * Whether a received datagram ends in this token, which identifies it as a Stateless Reset
     * (RFC 9000 section 10.3.1). Datagrams shorter than {@link #MIN_RESET_DATAGRAM} never match.
     * The comparison takes the same time wherever the bytes differ.
     *
     * @param datagram the datagram between its position and limit; the buffer is not changed
     * @return true if the last 16 bytes equal the token
     */
    public boolean matches(ByteBuffer datagram) {
        int len = datagram.remaining();
        if (len < MIN_RESET_DATAGRAM) {
            return false;
        }
        byte[] tail = new byte[LENGTH];
        datagram.get(datagram.limit() - LENGTH, tail);
        return MessageDigest.isEqual(tail, bytes);
    }

    /** Compares in constant time. */
    @Override
    public boolean equals(Object o) {
        return o instanceof StatelessResetToken other && MessageDigest.isEqual(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    /** The token in lowercase hexadecimal. */
    @Override
    public String toString() {
        return HexFormat.of().formatHex(bytes);
    }
}
