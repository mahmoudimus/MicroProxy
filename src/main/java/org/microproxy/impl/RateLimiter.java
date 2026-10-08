package org.microproxy.impl;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A global bytes-per-second limiter shared by all connections. Waiting happens with {@link
 * Thread#sleep}, which only parks a virtual thread. A {@link ReentrantLock} (not {@code
 * synchronized}) guards state so carriers are never pinned on JDK 21.
 */
final class RateLimiter {

    private static final long MAX_BURST_NANOS = TimeUnit.MILLISECONDS.toNanos(100);

    private final ReentrantLock lock = new ReentrantLock();
    private volatile long bytesPerSecond;
    private long nextFreeNanos = System.nanoTime();

    RateLimiter(long bytesPerSecond) {
        this.bytesPerSecond = Math.max(0, bytesPerSecond);
    }

    void setRate(long bytesPerSecond) {
        this.bytesPerSecond = Math.max(0, bytesPerSecond);
    }

    long rate() {
        return bytesPerSecond;
    }

    /** Accounts for {@code bytes}, sleeping as needed to keep the average under the rate. */
    void acquire(int bytes) throws InterruptedIOException {
        long rate = bytesPerSecond;
        if (rate <= 0 || bytes <= 0) return;
        long cost = (long) (bytes * 1_000_000_000.0 / rate);
        long wait;
        lock.lock();
        try {
            long now = System.nanoTime();
            long start = Math.max(nextFreeNanos, now - MAX_BURST_NANOS);
            nextFreeNanos = start + cost;
            wait = nextFreeNanos - now - MAX_BURST_NANOS;
        } finally {
            lock.unlock();
        }
        if (wait > 0) {
            try {
                TimeUnit.NANOSECONDS.sleep(wait);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("interrupted while throttling");
            }
        }
    }

    InputStream wrap(InputStream in) {
        return new FilterInputStream(in) {
            @Override
            public int read() throws IOException {
                int b = super.read();
                if (b >= 0) acquire(1);
                return b;
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (rate() > 0) len = Math.min(len, 8192);
                int n = in.read(b, off, len);
                if (n > 0) acquire(n);
                return n;
            }
        };
    }

    OutputStream wrap(OutputStream out) {
        return new FilterOutputStream(out) {
            @Override
            public void write(int b) throws IOException {
                acquire(1);
                out.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                while (len > 0) {
                    int n = rate() > 0 ? Math.min(len, 8192) : len;
                    acquire(n);
                    out.write(b, off, n);
                    off += n;
                    len -= n;
                }
            }
        };
    }
}
