/*
 * Ported from rustls-ring src/quic.rs (HeaderProtectionKey::xor_in_place) and quinn-proto
 * src/crypto/rustls.rs (HeaderKey) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.crypto;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicVersion;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A header protection key (RFC 9001 section 5.4): masks the low bits of the first byte and the
 * packet number with five bytes derived from a 16-byte sample of the ciphertext. AES suites use
 * AES-ECB on the sample; ChaCha20 uses the sample's first four bytes as the little-endian block
 * counter and the remaining twelve as the nonce, through the JDK's {@code "ChaCha20"} cipher.
 *
 * <p>Header keys do not change on a key update.
 *
 * <p><b>Thread confinement.</b> A key holds one reusable {@link Cipher} and scratch buffers, which
 * are not thread-safe: use a key from one thread at a time.
 */
public final class HeaderKey {

    /** The sample length for every QUIC header protection algorithm, in bytes. */
    public static final int SAMPLE_LENGTH = 16;

    /** The mask length in bytes: one for the first byte and up to four for the packet number. */
    public static final int MASK_LENGTH = 5;

    private static final byte LONG_HEADER_FORM = (byte) 0x80;

    private final CipherSuite suite;
    private final SecretKeySpec key;
    private final Cipher cipher;
    private final byte[] sample = new byte[SAMPLE_LENGTH];
    private final byte[] block = new byte[SAMPLE_LENGTH];

    private HeaderKey(CipherSuite suite, byte[] key) {
        if (key.length != suite.keyLength()) {
            throw new IllegalArgumentException("header key length " + key.length + " for " + suite);
        }
        this.suite = suite;
        try {
            if (suite.aes()) {
                this.key = new SecretKeySpec(key, "AES");
                this.cipher = Cipher.getInstance("AES/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, this.key);
            } else {
                this.key = new SecretKeySpec(key, "ChaCha20");
                this.cipher = Cipher.getInstance("ChaCha20");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("JDK lacks header protection for " + suite, e);
        }
    }

    /**
     * A key from its raw bytes.
     *
     * @param suite the cipher suite
     * @param key the key, {@link CipherSuite#keyLength()} bytes
     * @return the key
     */
    public static HeaderKey of(CipherSuite suite, byte[] key) {
        return new HeaderKey(suite, key);
    }

    /**
     * Derives a key from a traffic secret with the version's {@code "quic hp"} label.
     *
     * @param suite the cipher suite the secret belongs to
     * @param secret the traffic secret
     * @param version the QUIC version, which picks the label
     * @return the key
     */
    public static HeaderKey fromSecret(CipherSuite suite, byte[] secret, QuicVersion version) {
        return new HeaderKey(suite, suite.hkdf().expandLabel(
                secret, version.headerProtectionLabel(), new byte[0], suite.keyLength()));
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
     * The mask for a sample.
     *
     * @param sample 16 bytes of ciphertext
     * @return a new 5-byte mask
     */
    public byte[] mask(byte[] sample) {
        if (sample.length != SAMPLE_LENGTH) {
            throw new IllegalArgumentException("sample length " + sample.length);
        }
        System.arraycopy(sample, 0, this.sample, 0, SAMPLE_LENGTH);
        computeMask();
        byte[] mask = new byte[MASK_LENGTH];
        System.arraycopy(block, 0, mask, 0, MASK_LENGTH);
        return mask;
    }

    /**
     * Applies header protection in place to a packet whose payload is already sealed. The packet
     * number length comes from the unprotected first byte. Indexes are absolute; the buffer's
     * position and limit are not changed.
     *
     * @param packet the packet buffer
     * @param start the index of the packet's first byte
     * @param packetNumberOffset the index of the packet number; the sample starts four bytes later
     * @throws IndexOutOfBoundsException if the packet is too short to sample
     */
    public void protect(ByteBuffer packet, int start, int packetNumberOffset) {
        loadSample(packet, packetNumberOffset);
        byte first = packet.get(start);
        int pnLength = (first & 0x03) + 1;
        apply(packet, start, packetNumberOffset, first, pnLength);
    }

    /**
     * Removes header protection in place. Indexes are absolute; the buffer's position and limit
     * are not changed.
     *
     * @param packet the packet buffer
     * @param start the index of the packet's first byte
     * @param packetNumberOffset the index of the packet number; the sample starts four bytes later
     * @return the packet number length read from the unmasked first byte, 1 to 4
     * @throws IndexOutOfBoundsException if the packet is too short to sample
     */
    public int unprotect(ByteBuffer packet, int start, int packetNumberOffset) {
        loadSample(packet, packetNumberOffset);
        byte first = packet.get(start);
        byte bits = (first & LONG_HEADER_FORM) != 0 ? (byte) 0x0f : (byte) 0x1f;
        int pnLength = ((first ^ (block[0] & bits)) & 0x03) + 1;
        apply(packet, start, packetNumberOffset, first, pnLength);
        return pnLength;
    }

    private void loadSample(ByteBuffer packet, int packetNumberOffset) {
        packet.get(packetNumberOffset + 4, sample, 0, SAMPLE_LENGTH);
        computeMask();
    }

    private void apply(ByteBuffer packet, int start, int pnOffset, byte first, int pnLength) {
        byte bits = (first & LONG_HEADER_FORM) != 0 ? (byte) 0x0f : (byte) 0x1f;
        packet.put(start, (byte) (first ^ (block[0] & bits)));
        for (int i = 0; i < pnLength; i++) {
            packet.put(pnOffset + i, (byte) (packet.get(pnOffset + i) ^ block[1 + i]));
        }
    }

    private void computeMask() {
        try {
            if (suite.aes()) {
                cipher.doFinal(sample, 0, SAMPLE_LENGTH, block, 0);
            } else {
                int counter = (sample[0] & 0xff) | (sample[1] & 0xff) << 8 | (sample[2] & 0xff) << 16
                        | (sample[3] & 0xff) << 24;
                byte[] nonce = new byte[12];
                System.arraycopy(sample, 4, nonce, 0, 12);
                // Decrypt mode: ChaCha20 is symmetric, and the JDK only refuses a repeated nonce
                // when encrypting.
                cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                Arrays.fill(block, (byte) 0);
                cipher.doFinal(block, 0, MASK_LENGTH, block, 0);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("header protection failed", e);
        }
    }
}
