/*
 * Ported from quinn-proto src/crypto/ring_like.rs (HandshakeTokenKey for hkdf::Prk, AeadKey for
 * LessSafeKey) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.token;

import io.github.mahmoudimus.quic.Hkdf;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The server's secret for sealing address validation tokens, as quinn does it: an HKDF-SHA256
 * pseudorandom key from a master key, from which each token derives a one-time AES-256-GCM key
 * using its random nonce as the HKDF info. Since every key seals one token, the AEAD nonce is zero.
 *
 * <p>Immutable and thread-safe: each operation uses its own {@link Cipher}.
 */
public final class TokenKey {

    /** The AES-GCM tag length, in bytes. */
    public static final int TAG_LENGTH = 16;

    private final byte[] prk;

    /**
     * A key from a master secret.
     *
     * @param masterKey at least 32 random bytes; endpoints that must accept each other's tokens
     *     share it
     * @throws IllegalArgumentException if the key is shorter than 32 bytes
     */
    public TokenKey(byte[] masterKey) {
        if (masterKey.length < 32) {
            throw new IllegalArgumentException("token master key of " + masterKey.length + " bytes");
        }
        this.prk = Hkdf.SHA256.extract(new byte[0], masterKey);
    }

    /**
     * A key from a fresh random master secret of 64 bytes.
     *
     * @param random the source of randomness
     * @return the key
     */
    public static TokenKey random(SecureRandom random) {
        byte[] master = new byte[64];
        random.nextBytes(master);
        return new TokenKey(master);
    }

    /**
     * Encrypts and authenticates a token body.
     *
     * @param nonce the token's unique random nonce
     * @param plaintext the encoded body
     * @return the ciphertext followed by the tag
     */
    byte[] seal(byte[] nonce, byte[] plaintext) {
        try {
            return cipher(Cipher.ENCRYPT_MODE, nonce).doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM sealing failed", e);
        }
    }

    /**
     * Decrypts a token body.
     *
     * @param nonce the token's nonce
     * @param sealed the ciphertext and tag
     * @return the body, or null if it fails authentication
     */
    byte[] open(byte[] nonce, byte[] sealed) {
        if (sealed.length < TAG_LENGTH) {
            return null;
        }
        try {
            return cipher(Cipher.DECRYPT_MODE, nonce).doFinal(sealed);
        } catch (AEADBadTagException e) {
            return null;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM opening failed", e);
        }
    }

    private Cipher cipher(int mode, byte[] nonce) throws GeneralSecurityException {
        byte[] key = Hkdf.SHA256.expand(prk, nonce, 32);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LENGTH * 8, new byte[12]));
        Arrays.fill(key, (byte) 0);
        return c;
    }
}
