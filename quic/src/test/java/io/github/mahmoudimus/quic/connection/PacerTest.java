/*
 * Ported from quinn-proto src/connection/pacing.rs (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PacerTest {

    private static final long MS = 1_000_000L;
    private static final long US = 1_000L;
    private static final long NONE = NanoClock.NONE;

    @Test
    void doesNotFailOnBadInstant() {
        long oldInstant = 1_000 * MS;
        long newInstant = oldInstant + 15 * US;
        long rtt = 400 * US;
        assertEquals(NONE, new Pacer(rtt, 30000, 1500, -1, newInstant).delay(0, 0, 1500, 1, oldInstant));
        assertEquals(NONE, new Pacer(rtt, 30000, 1500, -1, newInstant).delay(0, 1600, 1500, 1, oldInstant));
        assertEquals(NONE, new Pacer(rtt, 30000, 1500, -1, newInstant).delay(0, 1500, 1500, 3000, oldInstant));
    }

    @Test
    void derivesInitialCapacity() {
        long window = 2_000_000;
        int mtu = 1500;
        long rtt = 50 * MS;
        long now = 0;

        Pacer pacer = new Pacer(rtt, window, mtu, -1, now);
        assertEquals(window * Pacer.TARGET_BURST_INTERVAL / rtt, pacer.capacity);
        assertEquals(pacer.capacity, pacer.tokens);

        pacer = new Pacer(0, window, mtu, -1, now);
        assertEquals(Pacer.MAX_BURST_SIZE * mtu, pacer.capacity);
        assertEquals(pacer.capacity, pacer.tokens);

        pacer = new Pacer(rtt, 1, mtu, -1, now);
        assertEquals(mtu, pacer.capacity);
        assertEquals(pacer.capacity, pacer.tokens);
    }

    @Test
    void adjustsCapacity() {
        long window = 2_000_000;
        int mtu = 1500;
        long rtt = 50 * MS;
        long now = 0;

        Pacer pacer = new Pacer(rtt, window, mtu, -1, now);
        assertEquals(window * Pacer.TARGET_BURST_INTERVAL / rtt, pacer.capacity);
        long initialTokens = pacer.tokens;

        pacer.delay(rtt, mtu, mtu, window * 2, now);
        assertEquals(2 * window * Pacer.TARGET_BURST_INTERVAL / rtt, pacer.capacity);
        assertEquals(initialTokens, pacer.tokens);

        pacer.delay(rtt, mtu, mtu, window / 2, now);
        assertEquals(window / 2 * Pacer.TARGET_BURST_INTERVAL / rtt, pacer.capacity);
        assertEquals(initialTokens / 2, pacer.tokens);

        pacer.delay(rtt, mtu, mtu * 2, window, now);
        assertEquals(window * Pacer.TARGET_BURST_INTERVAL / rtt, pacer.capacity);

        pacer.delay(rtt, mtu, 20_000, window, now);
        assertEquals(20_000L * Pacer.MIN_BURST_SIZE, pacer.capacity);
    }

    @Test
    void computesPauseCorrectly() {
        long window = 2_000_000;
        int mtu = 1000;
        long rtt = 50 * MS;
        long oldInstant = 7_000 * MS;

        Pacer pacer = new Pacer(rtt, window, mtu, -1, oldInstant);
        long packetCapacity = pacer.capacity / mtu;
        for (long i = 0; i < packetCapacity; i++) {
            assertEquals(NONE, pacer.delay(rtt, mtu, mtu, window, oldInstant),
                    "when capacity is available packets are sent immediately");
            pacer.onTransmit(mtu);
        }

        long paceDuration = Pacer.TARGET_BURST_INTERVAL * 4 / 5;
        long next = pacer.delay(rtt, mtu, mtu, window, oldInstant);
        assertNotEquals(NONE, next, "send must be delayed");
        long actualDelay = next - oldInstant;
        assertTrue(Math.abs(actualDelay - paceDuration) < 2, "expected about " + paceDuration + ", got " + actualDelay);

        // Refill half of the tokens
        assertEquals(NONE, pacer.delay(rtt, mtu, mtu, window, oldInstant + paceDuration / 2));
        assertEquals(pacer.capacity / 2, pacer.tokens);

        for (long i = 0; i < packetCapacity / 2; i++) {
            assertEquals(NONE, pacer.delay(rtt, mtu, mtu, window, oldInstant));
            pacer.onTransmit(mtu);
        }

        // Refill all capacity by waiting longer than needed
        assertEquals(NONE, pacer.delay(rtt, mtu, mtu, window, oldInstant + paceDuration * 3 / 2));
        assertEquals(pacer.capacity, pacer.tokens);
    }

    @Test
    void computesPauseCorrectlyForRateLimited() {
        long window = 2_000_000;
        int mtu = 1000;
        long rtt = 50 * MS;
        long oldInstant = 7_000 * MS;

        Pacer pacer = new Pacer(rtt, window, mtu, 2_000, oldInstant);
        assertEquals(NONE, pacer.delay(rtt, 1_000, mtu, window, oldInstant));
        pacer.onTransmit(mtu);

        long next = pacer.delay(rtt, 1_000, mtu, window, oldInstant);
        assertNotEquals(NONE, next);
        long expected = 500 * MS;
        assertTrue(Math.abs((next - oldInstant) - expected) < 2, "got " + (next - oldInstant));

        // Can send after a while
        assertEquals(NONE, pacer.delay(rtt, 500, mtu, window, oldInstant + expected / 2));
    }
}
