/*
 * Ported from quinn-proto src/bloom_token_log.rs (Apache-2.0), with a small bloom filter in place
 * of the fastbloom crate.
 */
package io.github.mahmoudimus.quic.token;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * A {@link TokenLog} of bounded memory. Each period keeps a hash set of the tokens used, which
 * turns into a bloom filter once it outgrows its share of the memory budget, so memory grows
 * linearly and then stops. Time is divided into periods of one token lifetime, and two filters
 * cover the two periods in which unexpired tokens can expire; older filters are dropped, so the
 * false positive rate does not climb forever.
 *
 * <p>Tokens are identified by the first 8 bytes of their nonce, which the server chose at random
 * and authenticated, so no secure hash is needed.
 *
 * <p><b>Threads.</b> Not thread-safe and takes no locks. An endpoint shares one log among its
 * connections, so the endpoint layer must serialize calls to it.
 */
public final class BloomTokenLog implements TokenLog {

    /** The default memory budget, 10 MiB. */
    public static final int DEFAULT_MAX_BYTES = 10 << 20;
    /** The default expected token uses per lifetime. */
    public static final long DEFAULT_EXPECTED_HITS = 1_000_000;

    private final int filterMaxBytes;
    private final int kNum;
    /** Filter 1 covers tokens expiring in the lifetime from here; filter 2 the lifetime after. */
    private Instant period1Start = Instant.EPOCH;
    Filter filter1 = new Filter();
    private Filter filter2 = new Filter();

    /**
     * A log with the default budget and expected use.
     */
    public BloomTokenLog() {
        this(DEFAULT_MAX_BYTES, optimalKNum(DEFAULT_MAX_BYTES, DEFAULT_EXPECTED_HITS));
    }

    /**
     * A log with a memory budget and a number of hash functions.
     *
     * @param maxBytes the approximate memory budget, split between the two filters
     * @param kNum the number of bloom filter hash functions
     */
    public BloomTokenLog(int maxBytes, int kNum) {
        this.filterMaxBytes = Math.max(maxBytes, 0) / 2;
        this.kNum = Math.max(kNum, 1);
    }

    /**
     * A log with a memory budget, tuned for an expected number of uses per lifetime.
     *
     * @param maxBytes the approximate memory budget
     * @param expectedHits the expected token uses per lifetime
     * @return the log
     */
    public static BloomTokenLog withExpectedItems(int maxBytes, long expectedHits) {
        return new BloomTokenLog(maxBytes, optimalKNum(maxBytes, expectedHits));
    }

    /**
     * The optimal number of hash functions, {@code m ln 2 / n}, at least 1.
     *
     * @param numBytes the filter size in bytes
     * @param expectedHits the expected number of items
     * @return the number of hash functions
     */
    static int optimalKNum(long numBytes, long expectedHits) {
        double numBits = numBytes > Long.MAX_VALUE / 8 ? Long.MAX_VALUE : numBytes * 8.0;
        long hits = Math.max(expectedHits, 1);
        long k = Math.round(numBits / hits * Math.log(2));
        return Math.clamp(k, 1, Integer.MAX_VALUE);
    }

    @Override
    public boolean checkAndInsert(byte[] nonce, Instant issued, Duration lifetime) {
        if (lifetime.isZero() || lifetime.isNegative()) {
            return false;
        }
        Instant expiresAt = issued.plus(lifetime);
        if (expiresAt.isBefore(period1Start)) {
            return false; // from before the filters' time, or the clock went back
        }
        long periodsForward = Duration.between(period1Start, expiresAt).dividedBy(lifetime);
        Filter filter;
        if (periodsForward == 0) {
            filter = filter1;
        } else if (periodsForward == 1) {
            filter = filter2;
        } else if (periodsForward == 2) {
            // Turn over filter 1
            filter1 = filter2;
            filter2 = new Filter();
            period1Start = period1Start.plus(lifetime);
            filter = filter2;
        } else {
            // Turn over both
            filter1 = new Filter();
            filter2 = new Filter();
            period1Start = expiresAt;
            filter = filter1;
        }
        long fingerprint = ByteBuffer.wrap(nonce, 0, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
        return filter.checkAndInsert(fingerprint);
    }

    /** One period's record: a hash set, then a bloom filter. */
    final class Filter {
        Set<Long> set = new HashSet<>();
        long[] bloom;

        /** Returns false if the fingerprint was (probably) seen. */
        boolean checkAndInsert(long fingerprint) {
            if (set != null) {
                if (!set.add(fingerprint)) {
                    return false;
                }
                if ((long) set.size() * Long.BYTES <= filterMaxBytes) {
                    return true;
                }
                // Convert to a bloom filter
                bloom = new long[(int) ((Math.max(filterMaxBytes, 1) * 8L + 63) / 64)];
                for (long item : set) {
                    bloomInsert(item);
                }
                set = null;
                return true;
            }
            return !bloomInsert(fingerprint);
        }

        /** Adds an item; true if every bit was already set (probably present). */
        private boolean bloomInsert(long item) {
            long numBits = (long) bloom.length * 64;
            long h1 = mix(item);
            long h2 = mix(item ^ 0x9e3779b97f4a7c15L) | 1;
            boolean present = true;
            for (int i = 0; i < kNum; i++) {
                long bit = Long.remainderUnsigned(h1 + i * h2, numBits);
                int word = (int) (bit >>> 6);
                long mask = 1L << bit;
                if ((bloom[word] & mask) == 0) {
                    present = false;
                    bloom[word] |= mask;
                }
            }
            return present;
        }

        boolean isBloom() {
            return set == null;
        }
    }

    /** The splitmix64 finalizer. */
    private static long mix(long z) {
        z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
        z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
        return z ^ (z >>> 31);
    }
}
