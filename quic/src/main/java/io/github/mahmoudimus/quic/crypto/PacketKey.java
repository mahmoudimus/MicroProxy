/*
 * Ported from rustls src/quic.rs (KeyBuilder::packet_key) and rustls-ring src/quic.rs (PacketKey)
 * and quinn-proto src/crypto.rs and src/crypto/rustls.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.crypto;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicVersion;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The AEAD key and IV that protect packet payloads in one direction (RFC 9001 section 5.3). The
 * nonce of each packet is the IV XORed with its packet number; the associated data is the packet
 * header up to and including the packet number.
 *
 * <p>Payloads are sealed and opened in place inside the packet buffer, so no payload bytes are
 * copied.
 *
 * <p><b>Thread confinement.</b> A key holds one reusable {@link Cipher}, which is not
 * thread-safe: use a key from one thread at a time (a connection's keys belong to that
 * connection). The JDK also refuses to seal twice with the same packet number in a row, which
 * QUIC never does.
 */
public final class PacketKey {

    /** The authentication tag length of every QUIC AEAD, in bytes. */
    public static final int TAG_LENGTH = 16;

    /** The nonce (and IV) length of every QUIC AEAD, in bytes. */
    public static final int NONCE_LENGTH = 12;

    /** The AES-GCM confidentiality limit: packets sealed under one key (RFC 9001 section 6.6). */
    public static final long AES_GCM_CONFIDENTIALITY_LIMIT = 1L << 23;

    /** The AES-GCM integrity limit: failed openings under one key (RFC 9001 section 6.6). */
    public static final long AES_GCM_INTEGRITY_LIMIT = 1L << 52;

    /**
     * The ChaCha20-Poly1305 confidentiality limit. RFC 9001 section 6.6 sets it above the number
     * of possible packets (2<sup>62</sup>), so it is effectively unlimited.
     */
    public static final long CHACHA20_POLY1305_CONFIDENTIALITY_LIMIT = Long.MAX_VALUE;

    /** The ChaCha20-Poly1305 integrity limit (RFC 9001 section 6.6). */
    public static final long CHACHA20_POLY1305_INTEGRITY_LIMIT = 1L << 36;

    private final CipherSuite suite;
    private final SecretKeySpec key;
    private final byte[] iv;
    private final Cipher cipher;

    private PacketKey(CipherSuite suite, byte[] key, byte[] iv) {
        if (key.length != suite.keyLength()) {
            throw new IllegalArgumentException("key length " + key.length + " for " + suite);
        }
        if (iv.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("IV length " + iv.length);
        }
        this.suite = suite;
        this.key = new SecretKeySpec(key, suite.aes() ? "AES" : "ChaCha20");
        this.iv = iv.clone();
        try {
            this.cipher = Cipher.getInstance(suite.aead());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("JDK lacks " + suite.aead(), e);
        }
    }

    /**
     * A key from its raw parts.
     *
     * @param suite the cipher suite
     * @param key the AEAD key, {@link CipherSuite#keyLength()} bytes
     * @param iv the 12-byte IV
     * @return the key
     * @throws IllegalArgumentException if a length is wrong
     */
    public static PacketKey of(CipherSuite suite, byte[] key, byte[] iv) {
        return new PacketKey(suite, key, iv);
    }

    /**
     * Derives a key from a traffic secret with the version's {@code "quic key"} and {@code "quic
     * iv"} labels (RFC 9001 section 5.1).
     *
     * @param suite the cipher suite the secret belongs to
     * @param secret the traffic secret
     * @param version the QUIC version, which picks the labels
     * @return the key
     */
    public static PacketKey fromSecret(CipherSuite suite, byte[] secret, QuicVersion version) {
        byte[] k = suite.hkdf().expandLabel(secret, version.keyLabel(), new byte[0], suite.keyLength());
        byte[] i = suite.hkdf().expandLabel(secret, version.ivLabel(), new byte[0], NONCE_LENGTH);
        return new PacketKey(suite, k, i);
    }

    /**
     * The cipher suite.
     *
     * @return the suite
     */
    public CipherSuite suite() {
        return suite;
    }

    /**
     * The authentication tag length.
     *
     * @return {@value #TAG_LENGTH}
     */
    public int tagLength() {
        return TAG_LENGTH;
    }

    /**
     * How many packets may be sealed with this key before it must be updated.
     *
     * @return the confidentiality limit of the suite's AEAD
     */
    public long confidentialityLimit() {
        return suite.aes() ? AES_GCM_CONFIDENTIALITY_LIMIT : CHACHA20_POLY1305_CONFIDENTIALITY_LIMIT;
    }

    /**
     * How many packets may fail authentication under this key before the connection must close.
     *
     * @return the integrity limit of the suite's AEAD
     */
    public long integrityLimit() {
        return suite.aes() ? AES_GCM_INTEGRITY_LIMIT : CHACHA20_POLY1305_INTEGRITY_LIMIT;
    }

    /**
     * The nonce for a packet number: the IV XORed with the 62-bit packet number, left-padded.
     *
     * @param packetNumber the full packet number
     * @return a new 12-byte nonce
     */
    public byte[] nonce(long packetNumber) {
        byte[] nonce = iv.clone();
        for (int i = 0; i < 8; i++) {
            nonce[NONCE_LENGTH - 1 - i] ^= (byte) (packetNumber >>> (8 * i));
        }
        return nonce;
    }

    /**
     * Seals a payload in place. The header bytes {@code [headerStart, payloadStart)} are the
     * associated data; the plaintext {@code [payloadStart, payloadEnd)} is replaced by the
     * ciphertext and followed by the tag, so the buffer needs 16 more bytes of capacity after
     * {@code payloadEnd}. Indexes are absolute; the buffer's position and limit are not changed.
     *
     * @param packetNumber the full packet number
     * @param packet the packet buffer
     * @param headerStart the index of the first header byte
     * @param payloadStart the index of the first payload byte, just past the packet number
     * @param payloadEnd the index just past the plaintext
     * @return the index just past the tag, {@code payloadEnd + 16}
     * @throws IllegalStateException if the AEAD fails, as when a packet number is reused
     */
    public int seal(long packetNumber, ByteBuffer packet, int headerStart, int payloadStart, int payloadEnd) {
        int end = payloadEnd + TAG_LENGTH;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, spec(packetNumber));
            cipher.updateAAD(packet.duplicate().limit(payloadStart).position(headerStart));
            ByteBuffer in = packet.duplicate().limit(payloadEnd).position(payloadStart);
            ByteBuffer out = packet.duplicate().limit(end).position(payloadStart);
            cipher.doFinal(in, out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AEAD seal failed for packet " + packetNumber, e);
        }
        return end;
    }

    /**
     * Opens a payload in place: authenticates {@code [headerStart, payloadStart)} and the
     * ciphertext with its tag {@code [payloadStart, end)}, and writes the plaintext over the
     * ciphertext. Indexes are absolute; the buffer's position and limit are not changed.
     *
     * @param packetNumber the full packet number
     * @param packet the packet buffer
     * @param headerStart the index of the first header byte
     * @param payloadStart the index of the first ciphertext byte
     * @param end the index just past the tag
     * @return the index just past the plaintext ({@code end - 16}), or -1 if the packet fails
     *     authentication, in which case the payload bytes are unspecified
     */
    public int open(long packetNumber, ByteBuffer packet, int headerStart, int payloadStart, int end) {
        if (end - payloadStart < TAG_LENGTH) {
            return -1;
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, spec(packetNumber));
            cipher.updateAAD(packet.duplicate().limit(payloadStart).position(headerStart));
            ByteBuffer in = packet.duplicate().limit(end).position(payloadStart);
            ByteBuffer out = packet.duplicate().limit(end).position(payloadStart);
            int n = cipher.doFinal(in, out);
            return payloadStart + n;
        } catch (AEADBadTagException e) {
            return -1;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AEAD open failed", e);
        }
    }

    /**
     * Seals a payload held in an array; see {@link #seal(long, ByteBuffer, int, int, int)}.
     *
     * @param packetNumber the full packet number
     * @param packet the packet bytes
     * @param headerStart the index of the first header byte
     * @param payloadStart the index of the first payload byte
     * @param payloadEnd the index just past the plaintext
     * @return the index just past the tag
     */
    public int seal(long packetNumber, byte[] packet, int headerStart, int payloadStart, int payloadEnd) {
        return seal(packetNumber, ByteBuffer.wrap(packet), headerStart, payloadStart, payloadEnd);
    }

    /**
     * Opens a payload held in an array; see {@link #open(long, ByteBuffer, int, int, int)}.
     *
     * @param packetNumber the full packet number
     * @param packet the packet bytes
     * @param headerStart the index of the first header byte
     * @param payloadStart the index of the first ciphertext byte
     * @param end the index just past the tag
     * @return the index just past the plaintext, or -1 if authentication fails
     */
    public int open(long packetNumber, byte[] packet, int headerStart, int payloadStart, int end) {
        return open(packetNumber, ByteBuffer.wrap(packet), headerStart, payloadStart, end);
    }

    private AlgorithmParameterSpec spec(long packetNumber) {
        byte[] nonce = nonce(packetNumber);
        return suite.aes() ? new GCMParameterSpec(TAG_LENGTH * 8, nonce) : new IvParameterSpec(nonce);
    }
}
