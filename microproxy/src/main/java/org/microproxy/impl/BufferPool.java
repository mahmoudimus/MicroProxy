package org.microproxy.impl;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Lends fixed-size byte arrays so that connections hold buffers only while bytes are moving, not
 * while they sit idle. Arrays not in use are kept for reuse up to a limit; beyond it they are left
 * to the garbage collector, so the pool never grows without bound.
 */
final class BufferPool {

    private final int size;
    private final int maxRetained;
    private final ConcurrentLinkedQueue<byte[]> free = new ConcurrentLinkedQueue<>();
    private final AtomicInteger retained = new AtomicInteger();
    private final AtomicInteger outstanding = new AtomicInteger();

    BufferPool(int size, int maxRetained) {
        this.size = size;
        this.maxRetained = maxRetained;
    }

    int size() {
        return size;
    }

    /** A buffer of {@link #size()} bytes; its contents are unspecified. */
    byte[] take() {
        outstanding.incrementAndGet();
        byte[] b = free.poll();
        if (b == null) return new byte[size];
        retained.decrementAndGet();
        return b;
    }

    /** Returns a buffer from {@link #take()}; the caller must not use it afterwards. */
    void give(byte[] b) {
        if (b == null || b.length != size) return;
        outstanding.decrementAndGet();
        if (retained.incrementAndGet() <= maxRetained) {
            free.offer(b);
        } else {
            retained.decrementAndGet();
        }
    }

    /** Buffers lent out and not yet given back. */
    int outstanding() {
        return outstanding.get();
    }

    /** Buffers currently kept for reuse. */
    int retained() {
        return retained.get();
    }
}
