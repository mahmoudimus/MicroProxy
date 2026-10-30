package io.github.mahmoudimus.verifiedcrypto;

import dafny.DafnySequence;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Test/generation adapter for the explicitly trusted JDK SHA3 boundary.
 * Not a verified provider implementation or a constant-time claim. */
public final class kem_hash {
    private kem_hash() {}
    private static DafnySequence<? extends Byte> digest(String algorithm, DafnySequence<? extends Byte> input) {
        byte[] bytes = new byte[input.length()];
        for (int i = 0; i < bytes.length; i++) bytes[i] = input.select(i);
        try {
            return DafnySequence.of(MessageDigest.getInstance(algorithm).digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Required JDK SHA3 provider is unavailable", e);
        }
    }
    public static DafnySequence<? extends Byte> sha3_256(DafnySequence<? extends Byte> input) {
        return digest("SHA3-256", input);
    }
    public static DafnySequence<? extends Byte> sha3_512(DafnySequence<? extends Byte> input) {
        return digest("SHA3-512", input);
    }
}
