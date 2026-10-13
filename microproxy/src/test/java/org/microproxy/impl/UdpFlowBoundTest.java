package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The proxy's bound on CONNECT-UDP flows: a full bound refuses at once unless a flow holding a
 * place is ending, and then waits, up to its deadline, for that place to come back.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class UdpFlowBoundTest {

    private static final long LONG_WAIT = TimeUnit.SECONDS.toNanos(30);

    @Test
    void aFullBoundWithNoFlowEndingRefusesAtOnce() throws Exception {
        UdpFlowBound bound = new UdpFlowBound();
        assertNotNull(bound.take(2, 0));
        assertNotNull(bound.take(2, 0));
        long start = System.nanoTime();
        assertNull(bound.take(2, LONG_WAIT));
        assertTrue(System.nanoTime() - start < LONG_WAIT / 3, "refused without waiting");
        assertEquals(2, bound.held());
    }

    @Test
    void aFullBoundWaitsForAnEndingFlowsPlace() throws Exception {
        UdpFlowBound bound = new UdpFlowBound();
        UdpFlowBound.Place ending = bound.take(1, 0);
        ending.ending();
        assertEquals(1, bound.ending());
        CompletableFuture<UdpFlowBound.Place> next = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try {
                next.complete(bound.take(1, LONG_WAIT));
            } catch (Throwable t) {
                next.completeExceptionally(t);
            }
        });
        // The request waits, for as long as its deadline allows, until the place comes back.
        while (!bound.hasWaiters()) Thread.onSpinWait();
        assertFalse(next.isDone());
        ending.release();
        assertNotNull(next.get(30, TimeUnit.SECONDS));
        assertEquals(1, bound.held());
        assertEquals(0, bound.ending());
    }

    @Test
    void aFullBoundGivesUpAtTheDeadline() throws Exception {
        UdpFlowBound bound = new UdpFlowBound();
        UdpFlowBound.Place ending = bound.take(1, 0);
        ending.ending();
        long deadline = TimeUnit.MILLISECONDS.toNanos(50);
        long start = System.nanoTime();
        assertNull(bound.take(1, deadline));
        assertTrue(System.nanoTime() - start >= deadline, "waited for the ending flow");
        ending.release();
        assertNotNull(bound.take(1, 0));
    }

    @Test
    void aPlaceGoesBackOnce() throws Exception {
        UdpFlowBound bound = new UdpFlowBound();
        UdpFlowBound.Place first = bound.take(2, 0);
        UdpFlowBound.Place second = bound.take(2, 0);
        first.ending();
        first.ending();
        assertEquals(1, bound.ending());
        // As a connection's reader and the flow's own end both do.
        first.release();
        first.release();
        first.ending();
        assertEquals(1, bound.held());
        assertEquals(0, bound.ending());
        second.release();
        assertEquals(0, bound.held());
    }
}
