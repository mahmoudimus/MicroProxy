package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge;
import java.util.Objects;

/**
 * HKDF (RFC 5869) over an HMAC, and the {@code HKDF-Expand-Label} of TLS 1.3 (RFC 8446 section 7.1)
 * that QUIC uses for its secrets and keys (RFC 9001 section 5.1).
 *
 * <p>The functional result of every operation is produced by the Dafny-verified kernel compiled to
 * {@code io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf}; this class preserves the
 * historical Java API and exception surface. The verified kernel, the reviewed Java/JCE bridge,
 * the Dafny compiler/runtime, the JDK cryptographic provider and JVM timing remain trusted. The
 * proof establishes functional equations relative to an abstract HMAC; it makes no claim about
 * HMAC security, provider correctness, constant-time execution or secret erasure.
 *
 * <p>Instances are immutable and thread-safe; no provider {@code Mac} is shared between calls.
 */
public final class Hkdf {

    /** HKDF with HMAC-SHA256, for the SHA-256 cipher suites and QUIC's Initial secrets. */
    public static final Hkdf SHA256 = new Hkdf(32);

    /** HKDF with HMAC-SHA384, for {@code TLS_AES_256_GCM_SHA384}. */
    public static final Hkdf SHA384 = new Hkdf(48);

    private static final byte[] EMPTY = new byte[0];

    private final int hashLength;

    private Hkdf(int hashLength) {
        this.hashLength = hashLength;
    }

    /**
     * The length of the hash, which is also the length of {@link #extract} output.
     *
     * @return the hash length in bytes
     */
    public int hashLength() {
        return hashLength;
    }

    /**
     * {@code HKDF-Extract(salt, ikm)}.
     *
     * <p>For compatibility with the previous JCE-backed implementation, a {@code null} IKM is
     * treated as an empty IKM, exactly as {@code Mac.doFinal(null)} was. A null salt remains a
     * {@link NullPointerException}.
     *
     * @param salt the salt; empty means a string of {@link #hashLength()} zeros
     * @param ikm the input keying material
     * @return the pseudorandom key, {@link #hashLength()} bytes
     */
    public byte[] extract(byte[] salt, byte[] ikm) {
        Objects.requireNonNull(salt, "salt");
        return HkdfBridge.extract(hashLength, salt, ikm == null ? EMPTY : ikm);
    }

    /**
     * {@code HKDF-Expand(prk, info, length)}.
     *
     * <p>For compatibility with the previous JCE-backed implementation, a {@code null} info is
     * treated as empty (as {@code Mac.update(null)} was), while a null PRK retains the historical
     * {@link IllegalArgumentException}. Empty PRKs, negative lengths and lengths above
     * {@code 255 * hashLength} remain rejected.
     *
     * @param prk the pseudorandom key, at least {@link #hashLength()} bytes
     * @param info the context
     * @param length the output length, at most 255 times {@link #hashLength()}
     * @return the output keying material
     */
    public byte[] expand(byte[] prk, byte[] info, int length) {
        // Preserve the previous check order: output length first, then the PRK. The generated
        // kernel repeats the length check; this guard avoids converting arguments for a rejected
        // length and keeps the historical null-PRK message for the remaining cases.
        if (length < 0 || length > 255 * hashLength) {
            throw new IllegalArgumentException("HKDF output length " + length);
        }
        if (prk == null) {
            // The previous implementation obtained this exception from SecretKeySpec.
            throw new IllegalArgumentException("Missing argument");
        }
        return HkdfBridge.expand(hashLength, prk, info == null ? EMPTY : info, length);
    }

    /**
     * TLS 1.3's {@code HKDF-Expand-Label(secret, label, context, length)}, with the {@code "tls13 "}
     * prefix added to {@code label}.
     *
     * @param secret the secret to expand
     * @param label the label without its prefix, such as {@code "quic key"}
     * @param context the context, often empty or a transcript hash
     * @param length the output length, at most 65535
     * @return the derived bytes
     * @throws IllegalArgumentException if the label is not ASCII or a length exceeds its encoding
     */
    public byte[] expandLabel(byte[] secret, String label, byte[] context, int length) {
        // Preserve the previous evaluation order: label validation/serialization first, then expand.
        return expand(secret, labelInfo(label, context, length), length);
    }

    /** RFC 8446's length-delimited HKDFLabel; ASCII conversion must never alias distinct labels. */
    static byte[] labelInfo(String label, byte[] context, int length) {
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(context, "context");
        return HkdfBridge.labelInfo(label, context, length);
    }
}
