package io.github.mahmoudimus.verifiedcrypto;

import VerifiedHkdf.BytesResult;
import VerifiedHkdf.__default;
import dafny.DafnySequence;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Java boundary for the Dafny-generated implementation of RFC 5869 and RFC 8446 section 7.1.
 *
 * <p>The kernel implements the standard algorithms; this adapter only converts values and failures.
 * Its Java conversions, Dafny's compiler/runtime, and the JCE HMAC provider remain trusted. The
 * Dafny proof does not establish provider correctness, constant-time behavior, or secret erasure.
 * Instances are immutable; each HMAC operation obtains a fresh provider instance.
 */
public final class DafnyHkdf {
    public static final DafnyHkdf SHA256 = new DafnyHkdf(32);
    public static final DafnyHkdf SHA384 = new DafnyHkdf(48);
    public static final DafnyHkdf SHA512 = new DafnyHkdf(64);

    private final BigInteger hashLength;

    private DafnyHkdf(int hashLength) {
        this.hashLength = BigInteger.valueOf(hashLength);
    }

    public int hashLength() {
        return hashLength.intValue();
    }

    /** Extracts with the supplied salt; an empty salt becomes HashLen zero octets. */
    public byte[] extract(byte[] salt, byte[] ikm) {
        return result(__default.Extract(hashLength, sequence(salt, "salt"), sequence(ikm, "ikm")));
    }

    /** Expands any nonempty PRK to 0 through 255 * HashLen octets, inclusive. */
    public byte[] expand(byte[] prk, byte[] info, int length) {
        return result(__default.Expand(hashLength, sequence(prk, "prk"), sequence(info, "info"),
            BigInteger.valueOf(length)));
    }

    /** Expands with the TLS 1.3 label prefix; the unprefixed label must contain only ASCII units. */
    public byte[] expandLabel(byte[] secret, String label, byte[] context, int length) {
        return result(__default.ExpandLabel(hashLength, sequence(secret, "secret"), labelUnits(label),
            sequence(context, "context"), BigInteger.valueOf(length)));
    }

    static byte[] labelInfo(String label, byte[] context, int length) {
        return result(__default.LabelInfo(labelUnits(label), sequence(context, "context"), BigInteger.valueOf(length)));
    }

    private static DafnySequence<Byte> sequence(byte[] value, String name) {
        // The clone gives the Dafny sequence its own backing storage, irrespective of runtime
        // wrapping behavior. Never retain caller-owned mutable arrays in generated values.
        return DafnySequence.of(Objects.requireNonNull(value, name).clone());
    }

    private static DafnySequence<Short> labelUnits(String label) {
        Objects.requireNonNull(label, "label");
        short[] units = new short[label.length()];
        for (int i = 0; i < units.length; i++) {
            // Java short and Dafny bv16 carry the same 16 bits. In particular, preserve lone
            // surrogates and units above 0xFF so the kernel can reject them without aliasing.
            units[i] = (short) label.charAt(i);
        }
        return DafnySequence.of(units);
    }

    private static byte[] result(BytesResult result) {
        if (result.is_Failure()) {
            throw new IllegalArgumentException("HKDF input rejected: " + result.dtor_reason());
        }
        return JdkHmac.bytes(result.dtor_bytes());
    }
}
