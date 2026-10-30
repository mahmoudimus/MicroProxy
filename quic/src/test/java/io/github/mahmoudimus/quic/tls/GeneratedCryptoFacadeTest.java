package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** Checks the Java ownership and validation boundary around the generated kernels. */
class GeneratedCryptoFacadeTest {
    @Test
    void invalidSlicesAreAtomicAndCheckedBeforeAbsorption() {
        for (int[] slice : new int[][] {{-1, 1}, {0, -1}, {0, 3}, {2, 1}, {Integer.MAX_VALUE, Integer.MAX_VALUE}}) {
            Shake actual = Shake.shake256().update(new byte[] {9});
            assertThrows(IndexOutOfBoundsException.class, () -> actual.update(new byte[] {1, 2}, slice[0], slice[1]));
            actual.update(new byte[] {7});
            byte[] output = new byte[300];
            actual.read(output);
            byte[] expected = new byte[300];
            Shake.shake256().update(new byte[] {9, 7}).read(expected);
            assertArrayEquals(expected, output);
        }
    }

    @Test
    void failedNullReadDoesNotStartSqueezingButEmptyReadDoes() {
        Shake actual = Shake.shake128().update(new byte[] {1});
        assertThrows(NullPointerException.class, () -> actual.read(null));
        actual.update(new byte[] {2});
        actual.read(new byte[0]);
        assertThrows(IllegalStateException.class, () -> actual.update(null, 0, 0));
        byte[] output = new byte[200];
        actual.read(output);
        byte[] expected = new byte[200];
        Shake.shake128().update(new byte[] {1, 2}).read(expected);
        assertArrayEquals(expected, output);
    }

    @Test
    void keyInputsExportsAndRepeatedDecapsulationRemainIndependent() {
        byte[] seed = new byte[64];
        Arrays.fill(seed, (byte) 7);
        byte[] originalSeed = seed.clone();
        var key = MlKem768.DecapsulationKey.fromSeed(seed);
        assertArrayEquals(originalSeed, seed);
        Arrays.fill(seed, (byte) 0);
        byte[] publicKey = key.encapsulationKey();
        byte[] expectedPublicKey = publicKey.clone();
        Arrays.fill(publicKey, (byte) 0);
        assertArrayEquals(expectedPublicKey, key.encapsulationKey());
        assertArrayEquals(expectedPublicKey, MlKem768.DecapsulationKey.fromSeed(originalSeed).encapsulationKey());
        byte[] message = new byte[32];
        Arrays.fill(message, (byte) 5);
        byte[] messageBefore = message.clone();
        var encapsulated = MlKem768.encapsulate(expectedPublicKey, message);
        assertArrayEquals(messageBefore, message);
        assertArrayEquals(expectedPublicKey, key.encapsulationKey());
        byte[] ciphertextBefore = encapsulated.ciphertext().clone();
        byte[] first = key.decapsulate(encapsulated.ciphertext());
        assertArrayEquals(encapsulated.sharedKey(), first);
        Arrays.fill(first, (byte) 0);
        assertArrayEquals(encapsulated.sharedKey(), key.decapsulate(encapsulated.ciphertext()));
        assertArrayEquals(ciphertextBefore, encapsulated.ciphertext());
        // Returned ciphertext/shared-key arrays are fresh across equal calls.
        var second = MlKem768.encapsulate(expectedPublicKey, message);
        Arrays.fill(encapsulated.ciphertext(), (byte) 0);
        Arrays.fill(encapsulated.sharedKey(), (byte) 0);
        assertArrayEquals(ciphertextBefore, second.ciphertext());
        assertArrayEquals(second.sharedKey(), key.decapsulate(second.ciphertext()));
    }

    @Test
    void invalidMessageLengthsAreRejected() {
        var key = MlKem768.DecapsulationKey.fromSeed(new byte[64]);
        byte[] encoded = key.encapsulationKey();
        for (int length : new int[] {0, 1, 31, 33, 64}) {
            assertThrows(IllegalArgumentException.class, () -> MlKem768.encapsulate(encoded, new byte[length]));
        }
    }

    @Test
    void internallyGeneratedSeedAndMessageBuffersAreWiped() {
        CapturingRandom random = new CapturingRandom();
        var key = MlKem768.DecapsulationKey.generate(random);
        assertTrue(allZero(random.last));
        var encapsulated = MlKem768.encapsulate(key.encapsulationKey(), random);
        assertTrue(allZero(random.last));
        assertArrayEquals(encapsulated.sharedKey(), key.decapsulate(encapsulated.ciphertext()));
    }

    private static boolean allZero(byte[] bytes) {
        for (byte value : bytes) if (value != 0) return false;
        return true;
    }

    private static final class CapturingRandom extends SecureRandom {
        private byte[] last;

        @Override
        public void nextBytes(byte[] bytes) {
            last = bytes;
            Arrays.fill(bytes, (byte) 11);
        }
    }
}
