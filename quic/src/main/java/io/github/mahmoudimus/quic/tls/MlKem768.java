package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.SecretKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * ML-KEM-768 (FIPS 203) backed by Java generated from the verified Dafny kernels.
 * The facade retains exclusive ownership of expanded keys and copies exported
 * arrays. JDK SHA3 and compiler/runtime correctness remain explicit assumptions;
 * this does not prove JVM timing or cryptographic hardness.
 */
final class MlKem768 {
    static final int ENCAPSULATION_KEY_SIZE = 1184;
    static final int CIPHERTEXT_SIZE = 1088;
    static final int SHARED_KEY_SIZE = 32;
    static final int SEED_SIZE = 64;

    private MlKem768() {}

    record Encapsulation(byte[] sharedKey, byte[] ciphertext) {}

    static final class DecapsulationKey {
        private final SecretKey key;

        private DecapsulationKey(SecretKey key) {
            this.key = key;
        }

        static DecapsulationKey fromSeed(byte[] seed) {
            Objects.requireNonNull(seed);
            if (seed.length != SEED_SIZE) throw new IllegalArgumentException("ML-KEM seed of " + seed.length + " bytes");
            byte[] owned = seed.clone();
            try {
                // KeyGen proves deep fresh ownership of all retained key data.
                return new DecapsulationKey(success(
                        io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.__default.KeyGen(owned)));
            } finally {
                Arrays.fill(owned, (byte) 0);
            }
        }

        static DecapsulationKey generate(SecureRandom random) {
            byte[] seed = new byte[SEED_SIZE];
            try {
                Objects.requireNonNull(random).nextBytes(seed);
                return fromSeed(seed);
            } finally {
                Arrays.fill(seed, (byte) 0);
            }
        }

        byte[] encapsulationKey() {
            return key.ek().encoded().clone();
        }

        byte[] decapsulate(byte[] ciphertext) {
            Objects.requireNonNull(ciphertext);
            if (ciphertext.length != CIPHERTEXT_SIZE) {
                throw new IllegalArgumentException("ML-KEM-768 ciphertext of " + ciphertext.length + " bytes");
            }
            byte[] owned = ciphertext.clone();
            try {
                return success(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.__default.Decaps(key, owned));
            } finally {
                Arrays.fill(owned, (byte) 0);
            }
        }
    }

    static Encapsulation encapsulate(byte[] encapsulationKey, SecureRandom random) {
        byte[] message = new byte[SHARED_KEY_SIZE];
        try {
            Objects.requireNonNull(random).nextBytes(message);
            return encapsulate(encapsulationKey, message);
        } finally {
            Arrays.fill(message, (byte) 0);
        }
    }

    static Encapsulation encapsulate(byte[] encapsulationKey, byte[] message) {
        byte[] ownedKey = Objects.requireNonNull(encapsulationKey).clone();
        byte[] ownedMessage = null;
        try {
            ownedMessage = Objects.requireNonNull(message).clone();
            var result = success(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.__default.Encaps(ownedKey, ownedMessage));
            return new Encapsulation(result.dtor_key(), result.dtor_ciphertext());
        } finally {
            Arrays.fill(ownedKey, (byte) 0);
            if (ownedMessage != null) Arrays.fill(ownedMessage, (byte) 0);
        }
    }

    private static <T> T success(Result<T> result) {
        if (result.is_Success()) return result.dtor_value();
        if (result.dtor_reason().is_RejectionLimit()) {
            // Uniform failure for the FIPS 203 Appendix B bounded sampler.
            throw new IllegalStateException("ML-KEM sampling limit");
        }
        throw new IllegalArgumentException("ML-KEM input: " + result.dtor_reason());
    }
}
