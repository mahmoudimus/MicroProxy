package org.microproxy.impl;

import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The proxy's bound on CONNECT-UDP flows at once ({@link
 * org.microproxy.Http3Options#connectUdpMaxFlows()}). A request takes a {@link Place} before
 * anything is done for it, and gives it back once, before its client can learn that it ended: as it
 * is refused, as its flow ends ({@link UdpFlow#end}), or as soon as its connection's reader sees
 * that the client ended it (a reset, the stream's end, the connection's close), whichever comes
 * first.
 *
 * <p>A request that finds the bound full waits, for at most {@link
 * org.microproxy.Http3Options#connectUdpReleaseWait()}, while flows whose end has been seen still
 * hold places ({@link Place#ending}): a client may have ended a flow on one connection and opened
 * this one on another at once, and nothing orders the two connections' reading. A request on the
 * same connection needs no wait, because the connection's reader gives a flow's place back as it
 * reads the client's end, before it reads what follows. With no flow ending, a full bound refuses
 * at once.
 *
 * <p>One lock, with a condition signalled on every release. It is taken last: under a connection's
 * {@code stateLock}, never the other way round, and nothing is called while it is held.
 */
final class UdpFlowBound {

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition freed = lock.newCondition();
    // Guarded by lock.
    /** Places taken and not given back, those of ending flows among them. */
    private int held;
    /** Places held by flows whose end has been seen. */
    private int ending;

    /**
     * Takes a place, if fewer than {@code max} are held; when the bound is full, waits up to
     * {@code waitNanos} for one, but only while some flow holding a place is ending.
     *
     * @return the place, or null if the bound is full
     */
    Place take(int max, long waitNanos) throws InterruptedException {
        lock.lock();
        try {
            long remaining = waitNanos;
            while (held >= max) {
                if (ending == 0 || remaining <= 0) return null;
                remaining = freed.awaitNanos(remaining);
            }
            held++;
            return new Place();
        } finally {
            lock.unlock();
        }
    }

    /** The places held now. */
    int held() {
        lock.lock();
        try {
            return held;
        } finally {
            lock.unlock();
        }
    }

    /** The places held now by flows whose end has been seen. */
    int ending() {
        lock.lock();
        try {
            return ending;
        } finally {
            lock.unlock();
        }
    }

    /** Whether a request is waiting for a place. */
    boolean hasWaiters() {
        lock.lock();
        try {
            return lock.hasWaiters(freed);
        } finally {
            lock.unlock();
        }
    }

    /** One request's place in the bound, from {@link #take} until {@link #release}. */
    final class Place {
        // Guarded by the bound's lock.
        private boolean ending;
        private boolean released;

        private Place() {}

        /**
         * The flow's end has been seen and it is closing: its place goes back soon, and requests
         * that find the bound full meanwhile wait for it. Does nothing once the place is back.
         */
        void ending() {
            lock.lock();
            try {
                if (released || ending) return;
                ending = true;
                UdpFlowBound.this.ending++;
            } finally {
                lock.unlock();
            }
        }

        /** Gives the place back; does nothing when called again. */
        void release() {
            lock.lock();
            try {
                if (released) return;
                released = true;
                held--;
                if (ending) UdpFlowBound.this.ending--;
                freed.signalAll();
            } finally {
                lock.unlock();
            }
        }
    }
}
