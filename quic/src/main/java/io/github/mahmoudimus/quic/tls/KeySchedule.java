// Ported from rustls src/tls13/key_schedule.rs (KeySchedule, SecretKind, the Finished
// computation, the exporter and the QUIC key update of quic.rs) and src/tls13/mod.rs (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.Hkdf;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The TLS 1.3 key schedule (RFC 8446 section 7.1) without PSKs: early secret from zeros,
 * handshake secret from the (EC)DHE shared secret, master secret from zeros, with each traffic
 * secret derived from the current secret and a transcript hash.
 */
final class KeySchedule {

    static final String CLIENT_HANDSHAKE_TRAFFIC = "c hs traffic";
    static final String SERVER_HANDSHAKE_TRAFFIC = "s hs traffic";
    static final String CLIENT_APPLICATION_TRAFFIC = "c ap traffic";
    static final String SERVER_APPLICATION_TRAFFIC = "s ap traffic";
    static final String EXPORTER_MASTER = "exp master";
    static final String RESUMPTION_MASTER = "res master";
    /** The QUIC key update label (RFC 9001 section 6.1). */
    static final String QUIC_KEY_UPDATE = "quic ku";

    private final CipherSuite suite;
    private final Hkdf hkdf;
    private final byte[] emptyHash;
    private byte[] current;

    /** Starts at the early secret, {@code HKDF-Extract(0, 0)}, since no PSK is used. */
    KeySchedule(CipherSuite suite) {
        this.suite = suite;
        this.hkdf = suite.hkdf();
        this.emptyHash = Transcript.newDigest(suite).digest();
        this.current = hkdf.extract(new byte[0], new byte[hkdf.hashLength()]);
    }

    CipherSuite suite() {
        return suite;
    }

    /** The current secret: early, then handshake, then master. */
    byte[] secret() {
        return current.clone();
    }

    /** Moves to the next stage: {@code HKDF-Extract(Derive-Secret(current, "derived", ""), ikm)}. */
    void input(byte[] ikm) {
        byte[] salt = deriveSecret("derived", emptyHash);
        current = hkdf.extract(salt, ikm);
    }

    /** Moves from the early secret to the handshake secret with the (EC)DHE shared secret. */
    void inputSharedSecret(byte[] shared) {
        input(shared);
    }

    /** Moves from the handshake secret to the master secret. */
    void inputEmpty() {
        input(new byte[hkdf.hashLength()]);
    }

    /** {@code Derive-Secret(current, label, transcript) = HKDF-Expand-Label(current, label, hash, Hash.length)}. */
    byte[] deriveSecret(String label, byte[] transcriptHash) {
        return hkdf.expandLabel(current, label, transcriptHash, hkdf.hashLength());
    }

    /** {@code HMAC(HKDF-Expand-Label(base, "finished", "", Hash.length), transcript)} (RFC 8446 section 4.4.4). */
    byte[] finishedVerifyData(byte[] baseKey, byte[] transcriptHash) {
        byte[] finishedKey = hkdf.expandLabel(baseKey, "finished", new byte[0], hkdf.hashLength());
        return hmac(finishedKey, transcriptHash);
    }

    private byte[] hmac(byte[] key, byte[] data) {
        String algorithm = hkdf.hashLength() == 48 ? "HmacSHA384" : "HmacSHA256";
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("JDK lacks " + algorithm, e);
        }
    }

    /** The next generation of a 1-RTT traffic secret (RFC 9001 section 6.1). */
    byte[] nextApplicationSecret(byte[] secret) {
        return hkdf.expandLabel(secret, QUIC_KEY_UPDATE, new byte[0], hkdf.hashLength());
    }

    /**
     * TLS-Exporter (RFC 8446 section 7.5): {@code HKDF-Expand-Label(Derive-Secret(exporter_master,
     * label, ""), "exporter", Hash(context), length)}.
     */
    static byte[] export(CipherSuite suite, byte[] exporterMaster, String label, byte[] context, int length) {
        Hkdf hkdf = suite.hkdf();
        byte[] empty = Transcript.newDigest(suite).digest();
        byte[] secret = hkdf.expandLabel(exporterMaster, label, empty, hkdf.hashLength());
        byte[] contextHash = Transcript.newDigest(suite).digest(context);
        return hkdf.expandLabel(secret, "exporter", contextHash, length);
    }
}
