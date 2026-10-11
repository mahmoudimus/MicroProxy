package io.github.mahmoudimus.quic.tls;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * The default {@link EarlyDataPolicy}: RFC 8446 section 8's freshness check plus a single-use
 * record of tickets (a strike register).
 *
 * <ul>
 *   <li><b>Freshness.</b> The ticket age the client reports (de-obfuscated with {@code
 *       ticket_age_add}) must be within the window of the age the server measures. A captured
 *       first flight carries a frozen age, so it fails this check once more than the window has
 *       passed.
 *   <li><b>Single use.</b> Each ticket's early data is accepted once. The record keeps a ticket for
 *       twice the window, which covers every moment its first flight could pass the freshness
 *       check, and then forgets it. It holds at most {@code maxEntries} tickets; when full it
 *       refuses early data rather than forget a ticket early.
 * </ul>
 *
 * <p>Thread-safe: a {@link ReentrantLock} guards the record.
 */
final class AntiReplay implements EarlyDataPolicy {

    static final int DEFAULT_WINDOW_SECONDS = 10;
    static final int DEFAULT_MAX_ENTRIES = 100_000;

    private final long windowMillis;
    private final long retentionNanos;
    private final int maxEntries;
    private final LongSupplier nanoClock;
    private final ReentrantLock lock = new ReentrantLock();
    /** Ticket identifiers in the order recorded, with when each may be forgotten. */
    private final LinkedHashMap<ByteBuffer, Long> seen = new LinkedHashMap<>();

    AntiReplay(Duration window, int maxEntries, LongSupplier nanoClock) {
        if (window.isNegative() || window.isZero()) {
            throw new IllegalArgumentException("window " + window);
        }
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries " + maxEntries);
        }
        this.windowMillis = window.toMillis();
        this.retentionNanos = window.multipliedBy(2).toNanos();
        this.maxEntries = maxEntries;
        this.nanoClock = nanoClock;
    }

    @Override
    public boolean accept(EarlyDataAttempt attempt) {
        if (attempt.ageSkew().toMillis() > windowMillis) {
            return false;
        }
        ByteBuffer id = ByteBuffer.wrap(attempt.ticketId());
        long now = nanoClock.getAsLong();
        lock.lock();
        try {
            for (Iterator<Map.Entry<ByteBuffer, Long>> it = seen.entrySet().iterator(); it.hasNext(); ) {
                if (it.next().getValue() - now > 0) {
                    break; // entries were recorded in order, with one retention
                }
                it.remove();
            }
            if (seen.containsKey(id) || seen.size() >= maxEntries) {
                return false;
            }
            seen.put(id, now + retentionNanos);
            return true;
        } finally {
            lock.unlock();
        }
    }

    /** The number of tickets recorded, for tests. */
    int size() {
        lock.lock();
        try {
            return seen.size();
        } finally {
            lock.unlock();
        }
    }
}
