package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class MlKem768Test {

    /**
     * Go's TestAccumulated (crypto/mlkem, BSD-3-Clause): keys, encapsulations and decapsulations
     * (including implicit rejection of a random ciphertext) driven by one SHAKE128 stream, all
     * outputs absorbed into another, whose first 32 bytes are compared.
     */
    private static String accumulated(int n) {
        Shake s = Shake.shake128();
        Shake o = Shake.shake128();
        byte[] seed = new byte[64];
        byte[] msg = new byte[32];
        byte[] randomCiphertext = new byte[MlKem768.CIPHERTEXT_SIZE];
        for (int i = 0; i < n; i++) {
            s.read(seed);
            MlKem768.DecapsulationKey dk = MlKem768.DecapsulationKey.fromSeed(seed);
            byte[] ek = dk.encapsulationKey();
            o.update(ek);
            s.read(msg);
            MlKem768.Encapsulation e = MlKem768.encapsulate(ek, msg);
            o.update(e.ciphertext());
            o.update(e.sharedKey());
            assertArrayEquals(e.sharedKey(), dk.decapsulate(e.ciphertext()));
            s.read(randomCiphertext);
            o.update(dk.decapsulate(randomCiphertext));
        }
        byte[] out = new byte[32];
        o.read(out);
        return HexFormat.of().formatHex(out);
    }

    @Test
    void accumulated100() {
        assertEquals("1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415", accumulated(100));
    }

    @Test
    void accumulated10000() {
        assertEquals("8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc", accumulated(10000));
    }

    @Test
    void sizesAreFips203s() {
        MlKem768.DecapsulationKey dk = MlKem768.DecapsulationKey.generate(new SecureRandom());
        assertEquals(1184, dk.encapsulationKey().length);
        MlKem768.Encapsulation e = MlKem768.encapsulate(dk.encapsulationKey(), new SecureRandom());
        assertEquals(1088, e.ciphertext().length);
        assertEquals(32, e.sharedKey().length);
        assertArrayEquals(e.sharedKey(), dk.decapsulate(e.ciphertext()));
    }

    @Test
    void malformedInputsAreRejected() {
        MlKem768.DecapsulationKey dk = MlKem768.DecapsulationKey.generate(new SecureRandom());
        byte[] ek = dk.encapsulationKey();
        assertThrows(IllegalArgumentException.class, () -> MlKem768.encapsulate(Arrays.copyOf(ek, 1183), new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> dk.decapsulate(new byte[1087]));
        assertThrows(IllegalArgumentException.class, () -> MlKem768.DecapsulationKey.fromSeed(new byte[63]));
        // FIPS 203 section 7.2: an encapsulation key with a coefficient of q or more fails the modulus check
        byte[] unreduced = ek.clone();
        unreduced[0] = (byte) 0xff;
        unreduced[1] = (byte) 0x0f;
        assertThrows(IllegalArgumentException.class, () -> MlKem768.encapsulate(unreduced, new byte[32]));
    }

    @Test
    void aTamperedCiphertextGivesADifferentKey() {
        MlKem768.DecapsulationKey dk = MlKem768.DecapsulationKey.generate(new SecureRandom());
        MlKem768.Encapsulation e = MlKem768.encapsulate(dk.encapsulationKey(), new SecureRandom());
        byte[] tampered = e.ciphertext().clone();
        tampered[0] ^= 1;
        assertFalse(Arrays.equals(e.sharedKey(), dk.decapsulate(tampered)));
    }
}
