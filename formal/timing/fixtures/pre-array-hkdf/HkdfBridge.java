package io.github.mahmoudimus.quic.internal.verifiedhkdf;

import dafny.DafnySequence;
import io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult;
import io.github.mahmoudimus.verifiedcrypto.JdkHmac;
import io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.FailureKind;
import io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Handwritten value/error boundary between {@link io.github.mahmoudimus.quic.Hkdf} and the
 * Dafny-generated RFC 5869/8446 implementation in {@code VerifiedHkdf}.
 *
 * <p>The generated kernel decides every functional result; this class only copies octets,
 * preserves UTF-16 label units for ASCII validation, and maps the kernel's failure data to the
 * historical Java exception types and messages of {@code quic.Hkdf}. Java array/sequence copying,
 * allocation, the Dafny compiler/runtime and JCE remain trusted; this is not a refinement proof
 * of the adapter, and it makes no constant-time claim.
 */
public final class HkdfBridge {
    private static final BigInteger SHA256 = BigInteger.valueOf(32);
    private static final BigInteger SHA384 = BigInteger.valueOf(48);

    private HkdfBridge() {}

    /** {@code HKDF-Extract}; an empty salt is normalized by the generated kernel. */
    public static byte[] extract(int hashLength, byte[] salt, byte[] ikm) {
        BytesResult result = __default.Extract(
                hash(hashLength), sequence(salt, "salt"), sequence(ikm, "ikm"));
        if (result.is_Success()) {
            return bytes(result.dtor_bytes());
        }
        throw failure(result.dtor_reason(), 0, false);
    }

    /** {@code HKDF-Expand}; the generated kernel validates length and key before its loop. */
    public static byte[] expand(int hashLength, byte[] prk, byte[] info, int length) {
        BytesResult result = __default.Expand(hash(hashLength), sequence(prk, "prk"),
                sequence(info, "info"), BigInteger.valueOf(length));
        if (result.is_Success()) {
            return bytes(result.dtor_bytes());
        }
        throw failure(result.dtor_reason(), length, false);
    }

    /** RFC 8446 {@code HkdfLabel} serialization; the generated kernel validates ASCII and bounds. */
    public static byte[] labelInfo(String label, byte[] context, int length) {
        BytesResult result = __default.LabelInfo(labelUnits(label), sequence(context, "context"),
                BigInteger.valueOf(length));
        if (result.is_Success()) {
            return bytes(result.dtor_bytes());
        }
        throw failure(result.dtor_reason(), length, true);
    }

    private static BigInteger hash(int hashLength) {
        return switch (hashLength) {
            case 32 -> SHA256;
            case 48 -> SHA384;
            default -> throw new IllegalStateException("Unsupported HKDF hash length " + hashLength);
        };
    }

    private static DafnySequence<Byte> sequence(byte[] value, String name) {
        // The clone gives the Dafny sequence its own backing storage. Caller-owned arrays are
        // never retained in a generated value, including for concurrent or repeated calls.
        return DafnySequence.of(Objects.requireNonNull(value, name).clone());
    }

    private static DafnySequence<Short> labelUnits(String label) {
        Objects.requireNonNull(label, "label");
        short[] units = new short[label.length()];
        for (int i = 0; i < units.length; i++) {
            // Java short and Dafny bv16 carry the same 16 bits. Preserve lone surrogates and
            // units above 0xFF so the kernel rejects them instead of aliasing a different label.
            units[i] = (short) label.charAt(i);
        }
        return DafnySequence.of(units);
    }

    private static byte[] bytes(DafnySequence<? extends Byte> sequence) {
        // Delegate to the single reviewed primitive bulk-copy boundary; the structural gate
        // rejects select/Byte.valueOf in both production byte-conversion classes.
        return JdkHmac.bytes(sequence);
    }

    /**
     * Reproduces the pre-adoption exception surface. {@code InvalidHash} is unreachable from the
     * public instances, which are constructed with SHA-256 or SHA-384.
     */
    private static RuntimeException failure(FailureKind reason, int length, boolean label) {
        if (reason.is_InvalidLength()) {
            return new IllegalArgumentException(
                    label ? "HKDF label length out of range" : "HKDF output length " + length);
        }
        if (reason.is_InvalidLabel()) {
            return new IllegalArgumentException("HKDF label must be ASCII");
        }
        if (reason.is_InvalidKey()) {
            return new IllegalArgumentException("Empty key");
        }
        if (reason.is_InvalidHash()) {
            return new IllegalStateException("Unsupported HKDF hash length");
        }
        return new IllegalStateException("Unexpected HKDF failure " + reason);
    }
}
