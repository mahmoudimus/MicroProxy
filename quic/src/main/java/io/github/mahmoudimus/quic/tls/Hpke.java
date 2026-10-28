// Ported from Go src/crypto/hpke (hpke.go, kem.go, kdf.go and aead.go: the labeled
// extract/expand, DHKEM's ExtractAndExpand, the key schedule and the context's nonce sequence)
// (BSD-3-Clause, Copyright 2022 The Go Authors), for the base mode and the suites ECH uses.
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.Hkdf;
import io.github.mahmoudimus.quic.QuicException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hybrid Public Key Encryption (RFC 9180) in the base mode, with the KEM
 * DHKEM(X25519, HKDF-SHA256), the KDF HKDF-SHA256 and the AEADs AES-128-GCM, AES-256-GCM and
 * ChaCha20-Poly1305: what Encrypted Client Hello (RFC 9849) encrypts the inner ClientHello with.
 *
 * <p>{@link #setupBaseS} gives the sender its encapsulated key and a {@link Context} to seal
 * with; {@link #setupBaseR} gives the receiver the matching context to open with.
 */
final class Hpke {

    /** DHKEM(X25519, HKDF-SHA256). */
    static final int KEM_X25519_HKDF_SHA256 = 0x0020;
    /** HKDF-SHA256. */
    static final int KDF_HKDF_SHA256 = 0x0001;

    /** The length of an X25519 public key, encapsulated key and private key. */
    static final int X25519_KEY_LENGTH = 32;

    private static final byte[] VERSION_LABEL = ascii("HPKE-v1");
    private static final byte[] KEM_SUITE_ID = concat(ascii("KEM"), u16(KEM_X25519_HKDF_SHA256));
    private static final int MODE_BASE = 0;

    /** The AEADs supported, by their HPKE ids (RFC 9180 section 7.3). */
    enum Aead {
        AES_128_GCM(0x0001, 16, "AES/GCM/NoPadding"),
        AES_256_GCM(0x0002, 32, "AES/GCM/NoPadding"),
        CHACHA20_POLY1305(0x0003, 32, "ChaCha20-Poly1305");

        /** The nonce length, {@code Nn}, of every supported AEAD. */
        static final int NONCE_LENGTH = 12;
        /** The tag length, {@code Nt}, of every supported AEAD. */
        static final int TAG_LENGTH = 16;

        private final int id;
        private final int keyLength;
        private final String transformation;

        Aead(int id, int keyLength, String transformation) {
            this.id = id;
            this.keyLength = keyLength;
            this.transformation = transformation;
        }

        /** {@return the HPKE AEAD id} */
        int id() {
            return id;
        }

        /** {@return the AEAD for {@code id}, or null if it is not supported} */
        static Aead forId(int id) {
            for (Aead a : values()) {
                if (a.id == id) return a;
            }
            return null;
        }

        byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance(transformation);
            String algorithm = this == CHACHA20_POLY1305 ? "ChaCha20" : "AES";
            if (this == CHACHA20_POLY1305) {
                cipher.init(mode, new SecretKeySpec(key, algorithm), new IvParameterSpec(nonce));
            } else {
                cipher.init(mode, new SecretKeySpec(key, algorithm), new GCMParameterSpec(TAG_LENGTH * 8, nonce));
            }
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        }
    }

    /** What {@link #setupBaseS} gives the sender: the encapsulated key to send, and the context. */
    record Sender(byte[] enc, Context context) {}

    private Hpke() {}

    /** Whether {@code kem}, {@code kdf} and {@code aead} are a suite this class implements. */
    static boolean supports(int kem, int kdf, int aead) {
        return kem == KEM_X25519_HKDF_SHA256 && kdf == KDF_HKDF_SHA256 && Aead.forId(aead) != null;
    }

    /**
     * {@code SetupBaseS(pkR, info)} (RFC 9180 section 5.1.1) with a fresh ephemeral key.
     *
     * @param pkR the receiver's X25519 public key
     * @param info the application's context
     * @throws GeneralSecurityException if {@code pkR} is not a usable X25519 key
     */
    static Sender setupBaseS(byte[] pkR, byte[] info, Aead aead, SecureRandom random) throws GeneralSecurityException {
        return setupBaseS(pkR, info, aead, KeyExchange.generate(NamedGroup.X25519, random));
    }

    /**
     * {@code SetupBaseS} with the ephemeral key {@code DeriveKeyPair(ikmE)}, as the test vectors
     * of RFC 9180 appendix A make it.
     */
    static Sender setupBaseS(byte[] pkR, byte[] info, Aead aead, byte[] ikmE) throws GeneralSecurityException {
        return setupBaseS(pkR, info, aead, KeyExchange.x25519(deriveX25519PrivateKey(ikmE)));
    }

    private static Sender setupBaseS(byte[] pkR, byte[] info, Aead aead, KeyExchange ephemeral)
            throws GeneralSecurityException {
        byte[] enc = ephemeral.publicKey();
        byte[] dh = agree(ephemeral, pkR);
        byte[] sharedSecret = extractAndExpand(dh, concat(enc, pkR));
        return new Sender(enc, keySchedule(sharedSecret, info, aead));
    }

    /**
     * {@code SetupBaseR(enc, skR, info)} (RFC 9180 section 5.1.1).
     *
     * @param enc the sender's encapsulated key
     * @param skR the receiver's X25519 private key
     */
    static Context setupBaseR(byte[] enc, byte[] skR, byte[] info, Aead aead) throws GeneralSecurityException {
        KeyExchange receiver = KeyExchange.x25519(skR);
        byte[] dh = agree(receiver, enc);
        byte[] sharedSecret = extractAndExpand(dh, concat(enc, receiver.publicKey()));
        return keySchedule(sharedSecret, info, aead);
    }

    /** The X25519 public key of the private key {@code sk}. */
    static byte[] x25519PublicKey(byte[] sk) throws GeneralSecurityException {
        return KeyExchange.x25519(sk).publicKey();
    }

    /**
     * The private key of {@code DeriveKeyPair(ikm)} for X25519 (RFC 9180 section 7.1.3):
     * {@code LabeledExpand(LabeledExtract("", "dkp_prk", ikm), "sk", "", 32)}.
     */
    static byte[] deriveX25519PrivateKey(byte[] ikm) {
        byte[] prk = labeledExtract(KEM_SUITE_ID, new byte[0], "dkp_prk", ikm);
        return labeledExpand(KEM_SUITE_ID, prk, "sk", new byte[0], X25519_KEY_LENGTH);
    }

    private static byte[] agree(KeyExchange ours, byte[] theirs) throws GeneralSecurityException {
        if (theirs.length != X25519_KEY_LENGTH) throw new GeneralSecurityException("X25519 key of " + theirs.length + " bytes");
        try {
            return ours.agree(theirs); // rejects the all-zero output (RFC 9180 section 7.1.4)
        } catch (QuicException e) {
            throw new GeneralSecurityException("HPKE: " + e.getMessage(), e);
        }
    }

    /** DHKEM's {@code ExtractAndExpand(dh, kem_context)} (RFC 9180 section 4.1). */
    private static byte[] extractAndExpand(byte[] dh, byte[] kemContext) {
        byte[] prk = labeledExtract(KEM_SUITE_ID, new byte[0], "eae_prk", dh);
        return labeledExpand(KEM_SUITE_ID, prk, "shared_secret", kemContext, Hkdf.SHA256.hashLength());
    }

    /** {@code KeySchedule} for the base mode: no PSK (RFC 9180 section 5.1). */
    private static Context keySchedule(byte[] sharedSecret, byte[] info, Aead aead) {
        byte[] suiteId = concat(ascii("HPKE"), u16(KEM_X25519_HKDF_SHA256), u16(KDF_HKDF_SHA256), u16(aead.id()));
        byte[] pskIdHash = labeledExtract(suiteId, new byte[0], "psk_id_hash", new byte[0]);
        byte[] infoHash = labeledExtract(suiteId, new byte[0], "info_hash", info);
        byte[] context = concat(new byte[] {MODE_BASE}, pskIdHash, infoHash);
        byte[] secret = labeledExtract(suiteId, sharedSecret, "secret", new byte[0]);
        byte[] key = labeledExpand(suiteId, secret, "key", context, aead.keyLength);
        byte[] baseNonce = labeledExpand(suiteId, secret, "base_nonce", context, Aead.NONCE_LENGTH);
        byte[] exporterSecret = labeledExpand(suiteId, secret, "exp", context, Hkdf.SHA256.hashLength());
        return new Context(suiteId, aead, key, baseNonce, exporterSecret);
    }

    /** {@code LabeledExtract(salt, label, ikm)}: HKDF-Extract over {@code "HPKE-v1" || suite_id || label || ikm}. */
    private static byte[] labeledExtract(byte[] suiteId, byte[] salt, String label, byte[] ikm) {
        return Hkdf.SHA256.extract(salt, concat(VERSION_LABEL, suiteId, ascii(label), ikm));
    }

    /** {@code LabeledExpand(prk, label, info, L)}: HKDF-Expand with {@code I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info}. */
    private static byte[] labeledExpand(byte[] suiteId, byte[] prk, String label, byte[] info, int length) {
        return Hkdf.SHA256.expand(prk, concat(u16(length), VERSION_LABEL, suiteId, ascii(label), info), length);
    }

    /**
     * An HPKE context (RFC 9180 section 5.2): the AEAD key, the base nonce and the sequence
     * number each seal or open uses and advances.
     */
    static final class Context {
        private final byte[] suiteId;
        private final Aead aead;
        private final byte[] key;
        private final byte[] baseNonce;
        private final byte[] exporterSecret;
        private long sequence;

        private Context(byte[] suiteId, Aead aead, byte[] key, byte[] baseNonce, byte[] exporterSecret) {
            this.suiteId = suiteId;
            this.aead = aead;
            this.key = key;
            this.baseNonce = baseNonce;
            this.exporterSecret = exporterSecret;
        }

        Aead aead() {
            return aead;
        }

        /** {@return the sequence number the next seal or open uses} */
        long sequence() {
            return sequence;
        }

        /** For test vectors that skip sequence numbers. */
        void sequence(long sequence) {
            this.sequence = sequence;
        }

        byte[] seal(byte[] aad, byte[] plaintext) throws GeneralSecurityException {
            byte[] out = aead.crypt(Cipher.ENCRYPT_MODE, key, nonce(), aad, plaintext);
            sequence++;
            return out;
        }

        byte[] open(byte[] aad, byte[] ciphertext) throws GeneralSecurityException {
            byte[] out = aead.crypt(Cipher.DECRYPT_MODE, key, nonce(), aad, ciphertext);
            sequence++;
            return out;
        }

        /** {@code Context.Export(exporter_context, L)} (RFC 9180 section 5.3). */
        byte[] export(byte[] exporterContext, int length) {
            return labeledExpand(suiteId, exporterSecret, "sec", exporterContext, length);
        }

        /** {@code base_nonce XOR I2OSP(seq, Nn)}. */
        byte[] nonce() {
            if (sequence < 0) throw new IllegalStateException("HPKE sequence number overflow");
            byte[] nonce = baseNonce.clone();
            for (int i = 0; i < 8; i++) {
                nonce[nonce.length - 1 - i] ^= (byte) (sequence >>> (8 * i));
            }
            return nonce;
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] u16(int v) {
        return new byte[] {(byte) (v >>> 8), (byte) v};
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }
}
