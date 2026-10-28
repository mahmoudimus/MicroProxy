package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

class GreaseTest {

    @Test
    void recognizesTheSixteenValues() {
        for (int n = 0; n < 16; n++) assertTrue(Grease.isGrease(0x0a0a + 0x1010 * n));
        assertFalse(Grease.isGrease(0x1301));
        assertFalse(Grease.isGrease(0x0a1a));
        assertFalse(Grease.isGrease(0x11ec));
    }

    @Test
    void everySlotIsGreaseAndTheTwoExtensionsDiffer() {
        SplittableRandom rng = new SplittableRandom(1);
        Set<Integer> seen = new HashSet<>();
        for (int i = 0; i < 2000; i++) {
            Grease g = Grease.random(rng);
            for (int v : new int[] {g.cipher(), g.group(), g.extension1(), g.extension2(), g.version(), g.signature()}) {
                assertTrue(Grease.isGrease(v), Integer.toHexString(v));
                seen.add(v);
            }
            // BoringSSL: the two GREASE extensions of a hello must not share a type
            assertNotEquals(g.extension1(), g.extension2());
        }
        assertEquals(16, seen.size());
    }
}
