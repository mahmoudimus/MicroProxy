package io.github.mahmoudimus.verifiedcrypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Named native ABI for the two trusted JDK SHA-3 provider operations.
 * Provider correctness, normal availability and internal erasure are external
 * assumptions. The generated owned algorithms do not use sequence adapters.
 */
public final class native_kem_hash {
    private native_kem_hash() {}
    public static byte[] sha3_256(byte[] input) { return digest("SHA3-256", input); }
    public static byte[] sha3_512(byte[] input) { return digest("SHA3-512", input); }
    private static byte[] digest(String name, byte[] input) {
        try { return MessageDigest.getInstance(name).digest(input); }
        catch (NoSuchAlgorithmException failure) { throw new IllegalStateException(name, failure); }
    }
}
