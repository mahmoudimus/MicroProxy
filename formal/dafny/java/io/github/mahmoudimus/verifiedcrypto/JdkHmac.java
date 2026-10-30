package io.github.mahmoudimus.verifiedcrypto;

import dafny.DafnySequence;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Trusted external HMAC operation used by the Dafny-generated RFC 5869 kernel. This delegates to
 * JCE's standard HmacSHA256/384/512 implementations and does not implement a new primitive.
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
            byte[] output = mac.doFinal(bytes(input));
            if (output.length != hashLen.intValue()) {
                throw new IllegalStateException("HMAC provider returned an unexpected digest length");
            }
            return DafnySequence.of(output);
        } catch (NoSuchAlgorithmException | InvalidKeyException error) {
            throw new IllegalStateException("JCE cannot initialize " + algorithm, error);
        }
    }

    /** Copies every octet without depending on the runtime's raw-array representation. */
    static byte[] bytes(DafnySequence<? extends Byte> sequence) {
        byte[] result = new byte[sequence.length()];
        for (int i = 0; i < result.length; i++) {
            result[i] = sequence.select(i);
        }
        return result;
    }
}
