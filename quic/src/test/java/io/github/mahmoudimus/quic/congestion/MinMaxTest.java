/*
 * The first test is ported from quinn-proto src/congestion/bbr/min_max.rs (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class MinMaxTest {

    @Test
    void test() {
        long round = 25;
        MinMax minMax = new MinMax();
        minMax.updateMax(round + 1, 100);
        assertEquals(100, minMax.get());
        minMax.updateMax(round + 3, 120);
        assertEquals(120, minMax.get());
        minMax.updateMax(round + 5, 160);
        assertEquals(160, minMax.get());
        minMax.updateMax(round + 7, 100);
        assertEquals(160, minMax.get());
        minMax.updateMax(round + 10, 100);
        assertEquals(160, minMax.get());
        minMax.updateMax(round + 14, 100);
        assertEquals(160, minMax.get());
        minMax.updateMax(round + 16, 100);
        assertEquals(100, minMax.get());
        minMax.updateMax(round + 18, 130);
        assertEquals(130, minMax.get());
    }

    @Test
    void resetForgetsAndCopiesAreIndependent() {
        MinMax minMax = new MinMax();
        minMax.updateMax(1, 500);
        MinMax copy = new MinMax(minMax);
        minMax.reset();
        assertEquals(0, minMax.get());
        assertEquals(500, copy.get());
        // After a reset any sample is the maximum
        minMax.updateMax(2, 7);
        assertEquals(7, minMax.get());
    }

    @Test
    void aMaximumExpiresOnceTheWindowPasses() {
        MinMax minMax = new MinMax();
        minMax.updateMax(0, 1000);
        for (long round = 1; round <= 10; round++) {
            minMax.updateMax(round, 1000 - round * 10);
            assertEquals(1000, minMax.get(), "round " + round);
        }
        // Eleven rounds after the maximum it has left the window
        minMax.updateMax(11, 500);
        assertTrue(minMax.get() < 1000, "the old maximum expired: " + minMax.get());
    }
}
