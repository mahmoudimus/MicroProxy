package io.github.mahmoudimus.verifiedcrypto;

import dafny.DafnySequence;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reviewed JCE boundary named by the verified HKDF kernel's sole external contract
 * ({@code VerifiedHkdf.Mac}). This class performs no cryptographic construction of its own: it
 * selects the standard {@code HmacSHA256/384/512} provider operation, copies values at the Dafny
 * boundary, and checks the provider's output length.
 *
 * <p>Trust: JCE provider selection, provider correctness, key/input handling inside {@link Mac},
 * its {@code doFinal} reset semantics, and JVM timing are outside the Dafny proof. Each call
 * creates a fresh {@link Mac}, so no provider state is shared. Secret-bearing Dafny sequences and
 * temporary arrays are not guaranteed to be erased.
 */
public final class JdkHmac {
    private JdkHmac() {}

    public static DafnySequence<? extends Byte> compute(BigInteger hashLen,
            DafnySequence<? extends Byte> key, DafnySequence<? extends Byte> input) {
        Objects.requireNonNull(hashLen, "hashLen");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(input, "input");
        String algorithm;
        if (hashLen.equals(BigInteger.valueOf(32))) {
            algorithm = "HmacSHA256";
        } else if (hashLen.equals(BigInteger.valueOf(48))) {
            algorithm = "HmacSHA384";
        } else if (hashLen.equals(BigInteger.valueOf(64))) {
            algorithm = "HmacSHA512";
        } else {
            throw new IllegalArgumentException("Unsupported HMAC hash length");
        }
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(bytes(key), algorithm));
            // A fresh Mac is discarded after this call; doFinal's internal reset is therefore not
            // relied upon by the kernel's feedback loop. Provider state is not modelled in Dafny.
            byte[] output = mac.doFinal(bytes(input));
            if (output.length != hashLen.intValue()) {
                throw new IllegalStateException("HMAC provider returned an unexpected digest length");
            }
            return DafnySequence.of(output);
        } catch (NoSuchAlgorithmException | InvalidKeyException error) {
            throw new IllegalStateException("JCE cannot initialize " + algorithm, error);
        }
    }

    /**
     * Copies a production byte sequence through DafnyRuntime's primitive bulk-copy path.
     *
     * <p>Pinned DafnyRuntime 4.9.1 {@code DafnySequence.toRawArray()} calls
     * {@code toArray().unwrap()}. For an {@code ArrayDafnySequence} backed by a primitive
     * {@code byte[]}, {@code toArray()} clones the primitive array; for a forced
     * {@code ConcatDafnySequence}, the copier uses the {@code ArrayDafnySequence} fast path with
     * {@code System.arraycopy} and then {@code toArray()} clones again. The returned array is a
     * fresh primitive copy and no {@code select}/{@code Byte.valueOf} occurs. Other
     * representations fail closed rather than silently unboxing.
     */
    public static byte[] bytes(DafnySequence<? extends Byte> sequence) {
        Objects.requireNonNull(sequence, "sequence");
        Object raw;
        try {
            raw = sequence.toRawArray();
        } catch (ClassCastException error) {
            throw new IllegalStateException("Unexpected non-primitive Dafny byte sequence", error);
        }
        if (raw instanceof byte[] bytes) {
            return bytes;
        }
        throw new IllegalStateException("Unexpected Dafny byte sequence representation: "
                + raw.getClass().getName());
    }
}
