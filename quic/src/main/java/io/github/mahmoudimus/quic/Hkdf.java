package io.github.mahmoudimus.quic;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF (RFC 5869) over an HMAC, and the {@code HKDF-Expand-Label} of TLS 1.3 (RFC 8446 section 7.1)
 * that QUIC uses for its secrets and keys (RFC 9001 section 5.1).
 *
 * <p>Instances are immutable and thread-safe; each call makes its own {@link Mac}.
 */
public final class Hkdf {

    /** HKDF with HMAC-SHA256, for the SHA-256 cipher suites and QUIC's Initial secrets. */
    public static final Hkdf SHA256 = new Hkdf("HmacSHA256", 32);

    /** HKDF with HMAC-SHA384, for {@code TLS_AES_256_GCM_SHA384}. */
    public static final Hkdf SHA384 = new Hkdf("HmacSHA384", 48);

    private static final byte[] LABEL_PREFIX = "tls13 ".getBytes(StandardCharsets.US_ASCII);

    private final String algorithm;
    private final int hashLength;

    private Hkdf(String algorithm, int hashLength) {
        this.algorithm = algorithm;
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
     * @param salt the salt; empty means a string of {@link #hashLength()} zeros
     * @param ikm the input keying material
     * @return the pseudorandom key, {@link #hashLength()} bytes
     */
    public byte[] extract(byte[] salt, byte[] ikm) {
        Mac mac = mac(salt.length == 0 ? new byte[hashLength] : salt);
        return mac.doFinal(ikm);
    }

    /**
     * {@code HKDF-Expand(prk, info, length)}.
     *
     * @param prk the pseudorandom key, at least {@link #hashLength()} bytes
     * @param info the context
     * @param length the output length, at most 255 times {@link #hashLength()}
     * @return the output keying material
     */
    public byte[] expand(byte[] prk, byte[] info, int length) {
        if (length < 0 || length > 255 * hashLength) {
            throw new IllegalArgumentException("HKDF output length " + length);
        }
        Mac mac = mac(prk);
        byte[] out = new byte[length];
        byte[] block = new byte[0];
        int filled = 0;
        for (int counter = 1; filled < length; counter++) {
            mac.update(block);
            mac.update(info);
            mac.update((byte) counter);
            block = mac.doFinal();
            int n = Math.min(block.length, length - filled);
            System.arraycopy(block, 0, out, filled, n);
            filled += n;
        }
        return out;
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
        return expand(secret, labelInfo(label, context, length), length);
    }

    /** RFC 8446's length-delimited HKDFLabel; ASCII conversion must never alias distinct labels. */
    static byte[] labelInfo(String label, byte[] context, int length) {
        if (length < 0 || length > 0xffff || label.length() > 249 || context.length > 255) {
            throw new IllegalArgumentException("HKDF label length out of range");
        }
        for (int c = 0; c < label.length(); c++) {
            if (label.charAt(c) > 0x7f) throw new IllegalArgumentException("HKDF label must be ASCII");
        }
        byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
        int fullLabel = LABEL_PREFIX.length + labelBytes.length;
        byte[] info = new byte[2 + 1 + fullLabel + 1 + context.length];
        int i = 0;
        info[i++] = (byte) (length >>> 8);
        info[i++] = (byte) length;
        info[i++] = (byte) fullLabel;
        System.arraycopy(LABEL_PREFIX, 0, info, i, LABEL_PREFIX.length);
        i += LABEL_PREFIX.length;
        System.arraycopy(labelBytes, 0, info, i, labelBytes.length);
        i += labelBytes.length;
        info[i++] = (byte) context.length;
        System.arraycopy(context, 0, info, i, context.length);
        return info;
    }

    private Mac mac(byte[] key) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("JDK lacks " + algorithm, e);
        }
    }
}
