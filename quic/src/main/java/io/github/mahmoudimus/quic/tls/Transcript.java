// Ported from rustls src/hash_hs.rs (HandshakeHashBuffer, HandshakeHash and the HelloRetryRequest
// rollup) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The running hash of the handshake messages (RFC 8446 section 4.4.1). Until the cipher suite,
 * and so the hash, is known, messages are buffered; after a HelloRetryRequest the first
 * ClientHello is replaced by the synthetic {@code message_hash} message carrying its hash.
 */
final class Transcript {

    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private MessageDigest digest;

    /** The JCA digest name of a suite's hash. */
    static String digestAlgorithm(CipherSuite suite) {
        return suite.hkdf().hashLength() == 48 ? "SHA-384" : "SHA-256";
    }

    static MessageDigest newDigest(CipherSuite suite) {
        try {
            return MessageDigest.getInstance(digestAlgorithm(suite));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK lacks " + digestAlgorithm(suite), e);
        }
    }

    boolean started() {
        return digest != null;
    }

    /** Fixes the hash, hashing whatever was buffered. Starting again with the same suite does nothing. */
    void start(CipherSuite suite) {
        if (digest != null) {
            if (!digest.getAlgorithm().equals(digestAlgorithm(suite))) {
                throw new IllegalStateException("transcript hash changed");
            }
            return;
        }
        digest = newDigest(suite);
        digest.update(buffer.toByteArray());
        buffer = null;
    }

    void add(byte[] message) {
        if (digest != null) {
            digest.update(message);
        } else {
            buffer.writeBytes(message);
        }
    }

    /**
     * The hash of every message so far followed by {@code extra}, which is not added: for a PSK
     * binder over a truncated ClientHello.
     */
    byte[] hashWith(byte[] extra) {
        if (digest == null) throw new IllegalStateException("transcript hash not started");
        try {
            MessageDigest copy = (MessageDigest) digest.clone();
            copy.update(extra);
            return copy.digest();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("digest cannot be cloned", e);
        }
    }

    /** The hash of every message so far. */
    byte[] hash() {
        if (digest == null) throw new IllegalStateException("transcript hash not started");
        try {
            return ((MessageDigest) digest.clone()).digest();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("digest cannot be cloned", e);
        }
    }

    /**
     * Replaces the transcript so far, the first ClientHello, with {@code message_hash}: type 254,
     * a 24-bit length and {@code Hash(ClientHello1)} (RFC 8446 section 4.4.1).
     */
    void rollupForRetry() {
        byte[] hash = hash();
        digest.reset();
        digest.update(new byte[] {(byte) HandshakeType.MESSAGE_HASH, 0, 0, (byte) hash.length});
        digest.update(hash);
    }
}
