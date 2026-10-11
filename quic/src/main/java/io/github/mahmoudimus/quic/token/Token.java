/*
 * Ported from quinn-proto src/token.rs (Token, TokenType and the address and time codecs)
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.token;

import io.github.mahmoudimus.quic.ConnectionId;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.random.RandomGenerator;

/**
 * An address validation token: a payload and a random nonce. On the wire it is the payload sealed
 * with a one-time key derived from the nonce, followed by the 16-byte nonce in the clear.
 *
 * <pre>
 *   type (1) | address: family (1), 4 or 16 bytes [, port (2) for Retry]
 *            | [original DCID: length (1), bytes, for Retry] | issued, Unix seconds (8)
 * </pre>
 *
 * <p>Immutable.
 */
public final class Token {

    /** The nonce length, in bytes. */
    public static final int NONCE_LENGTH = 16;

    private static final int TYPE_RETRY = 0;
    private static final int TYPE_VALIDATION = 1;

    private final TokenPayload payload;
    private final byte[] nonce;

    /**
     * A token.
     *
     * @param payload what the token says
     * @param nonce a unique random value of {@value #NONCE_LENGTH} bytes
     */
    public Token(TokenPayload payload, byte[] nonce) {
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("token nonce of " + nonce.length + " bytes");
        }
        this.payload = Objects.requireNonNull(payload, "payload");
        this.nonce = nonce.clone();
    }

    /**
     * A token with a fresh random nonce.
     *
     * @param payload what the token says
     * @param random the source of randomness; a {@link java.security.SecureRandom} outside tests
     * @return the token
     */
    public static Token create(TokenPayload payload, RandomGenerator random) {
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        return new Token(payload, nonce);
    }

    /**
     * What the token says.
     *
     * @return the payload
     */
    public TokenPayload payload() {
        return payload;
    }

    /**
     * The token's nonce, visible to the client.
     *
     * @return a copy
     */
    public byte[] nonce() {
        return nonce.clone();
    }

    /**
     * Encodes and seals the token.
     *
     * @param key the server's token key
     * @return the token as sent to the client
     */
    public byte[] encode(TokenKey key) {
        ByteBuffer buf = ByteBuffer.allocate(1 + 1 + 16 + 2 + 1 + ConnectionId.MAX_LENGTH + 8);
        switch (payload) {
            case TokenPayload.Retry r -> {
                buf.put((byte) TYPE_RETRY);
                encodeIp(buf, r.address().getAddress());
                buf.putShort((short) r.address().getPort());
                buf.put((byte) r.originalDestinationId().length());
                r.originalDestinationId().writeTo(buf);
                buf.putLong(Math.max(0, r.issued().getEpochSecond()));
            }
            case TokenPayload.Validation v -> {
                buf.put((byte) TYPE_VALIDATION);
                encodeIp(buf, v.ip());
                buf.putLong(Math.max(0, v.issued().getEpochSecond()));
            }
        }
        byte[] sealed = key.seal(nonce, Arrays.copyOf(buf.array(), buf.position()));
        byte[] out = Arrays.copyOf(sealed, sealed.length + NONCE_LENGTH);
        System.arraycopy(nonce, 0, out, sealed.length, NONCE_LENGTH);
        return out;
    }

    /**
     * Opens and decodes a token.
     *
     * @param key the server's token key
     * @param raw the token from the client
     * @return the token, or null if it does not authenticate or decode, as for a token from another
     *     server or version
     */
    public static Token decode(TokenKey key, byte[] raw) {
        if (raw.length < NONCE_LENGTH) {
            return null;
        }
        byte[] nonce = Arrays.copyOfRange(raw, raw.length - NONCE_LENGTH, raw.length);
        byte[] data = key.open(nonce, Arrays.copyOf(raw, raw.length - NONCE_LENGTH));
        if (data == null) {
            return null;
        }
        ByteBuffer in = ByteBuffer.wrap(data);
        try {
            TokenPayload payload;
            switch (in.get()) {
                case TYPE_RETRY -> {
                    InetAddress ip = decodeIp(in);
                    if (ip == null) {
                        return null;
                    }
                    int port = Short.toUnsignedInt(in.getShort());
                    int cidLength = Byte.toUnsignedInt(in.get());
                    if (cidLength > ConnectionId.MAX_LENGTH) {
                        return null;
                    }
                    ConnectionId cid = ConnectionId.read(in, cidLength);
                    payload = new TokenPayload.Retry(new InetSocketAddress(ip, port), cid, issued(in.getLong()));
                }
                case TYPE_VALIDATION -> {
                    InetAddress ip = decodeIp(in);
                    if (ip == null) {
                        return null;
                    }
                    payload = new TokenPayload.Validation(ip, issued(in.getLong()));
                }
                default -> {
                    return null;
                }
            }
            if (in.hasRemaining()) {
                return null; // extra bytes: perhaps an incompatible endpoint
            }
            return new Token(payload, nonce);
        } catch (BufferUnderflowException | IllegalArgumentException e) {
            return null;
        }
    }

    private static Instant issued(long seconds) {
        return Instant.ofEpochSecond(Math.max(0, seconds));
    }

    private static void encodeIp(ByteBuffer buf, InetAddress ip) {
        if (ip instanceof Inet4Address) {
            buf.put((byte) 0);
        } else {
            buf.put((byte) 1);
        }
        buf.put(ip.getAddress());
    }

    private static InetAddress decodeIp(ByteBuffer in) {
        int family = in.get();
        byte[] bytes;
        if (family == 0) {
            bytes = new byte[4];
        } else if (family == 1) {
            bytes = new byte[16];
        } else {
            return null;
        }
        in.get(bytes);
        try {
            return InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
