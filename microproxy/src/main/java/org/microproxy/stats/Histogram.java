package org.microproxy.stats;

import java.util.Arrays;

/**
 * A distribution of recorded values in fixed buckets, such as {@code downstream_rq_time}: one
 * {@link java.util.concurrent.atomic.LongAdder} per bucket, plus the sum and the count of the
 * values, so recording takes no lock and allocates nothing. Times are recorded in milliseconds.
 *
 * <p>A bucket is named by its upper bound, which it includes (Prometheus's {@code le}); values
 * above the last bound fall in the {@code +Inf} bucket. The default bounds ({@link
 * #defaultBounds()}) are Envoy's: 0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000,
 * 30000, 60000, 300000, 600000, 1800000 and 3600000.
 */
public interface Histogram extends Metric {

    /**
     * Records {@code value}.
     *
     * @param value the value, in the histogram's unit (milliseconds for times)
     */
    void record(double value);

    /**
     * Records a duration measured in nanoseconds, in milliseconds.
     *
     * @param nanos the duration in nanoseconds
     */
    default void recordNanos(long nanos) {
        record(nanos / 1_000_000.0);
    }

    /** {@return the counts so far, read bucket by bucket (not atomically as a whole)} */
    Snapshot snapshot();

    @Override
    default Type type() {
        return Type.HISTOGRAM;
    }

    /** {@return a copy of Envoy's default bucket bounds, in milliseconds} */
    static double[] defaultBounds() {
        return Snapshot.DEFAULT_BOUNDS.clone();
    }

    /**
     * {@return bucket bounds for short durations in microseconds, such as a hook's run: 1, 5, 10,
     * 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000 and
     * 1000000}
     */
    static double[] microsecondBounds() {
        return Snapshot.MICROSECOND_BOUNDS.clone();
    }

    /**
     * The counts of a histogram at one moment.
     *
     * <p>Bucket {@code i} counts the values above bound {@code i - 1} (or any value, for {@code
     * i == 0}) and at most bound {@code i}; bucket {@code bounds().length} counts the values above
     * the last bound.
     */
    final class Snapshot {

        static final double[] MICROSECOND_BOUNDS = {
            1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000
        };

        static final double[] DEFAULT_BOUNDS = {
            0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 300000, 600000, 1800000, 3600000
        };

        private final double[] bounds;
        private final long[] counts;
        private final double sum;
        private final long count;

        /**
         * A snapshot of the given counts.
         *
         * @param bounds the buckets' upper bounds, ascending
         * @param counts each bucket's own count, one more than there are bounds
         * @param sum the sum of the recorded values
         * @param count how many values were recorded
         * @throws IllegalArgumentException if there is not one more count than bounds
         */
        public Snapshot(double[] bounds, long[] counts, double sum, long count) {
            if (counts.length != bounds.length + 1) {
                throw new IllegalArgumentException(counts.length + " counts for " + bounds.length + " bounds");
            }
            this.bounds = bounds.clone();
            this.counts = counts.clone();
            this.sum = sum;
            this.count = count;
        }

        /** {@return a copy of the buckets' upper bounds, ascending, without {@code +Inf}} */
        public double[] bounds() {
            return bounds.clone();
        }

        /** {@return how many buckets there are, the {@code +Inf} one included} */
        public int buckets() {
            return counts.length;
        }

        /**
         * The count of bucket {@code i} alone.
         *
         * @param i the bucket, from 0 to {@code bounds().length}
         * @return the number of values in the bucket
         */
        public long bucketCount(int i) {
            return counts[i];
        }

        /**
         * The count of bucket {@code i} and every bucket below it, as Prometheus's {@code _bucket}
         * lines show it.
         *
         * @param i the bucket, from 0 to {@code bounds().length}
         * @return the number of values at most the bucket's bound
         */
        public long cumulativeCount(int i) {
            long total = 0;
            for (int b = 0; b <= i; b++) total += counts[b];
            return total;
        }

        /** {@return the sum of the recorded values} */
        public double sum() {
            return sum;
        }

        /** {@return how many values were recorded} */
        public long count() {
            return count;
        }

        /**
         * Estimates quantile {@code q} by interpolating linearly inside the bucket it falls in, as
         * Prometheus's {@code histogram_quantile} does; a quantile in the {@code +Inf} bucket is the
         * last bound.
         *
         * @param q the quantile, from 0 to 1
         * @return the estimate, or {@code NaN} when nothing was recorded
         */
        public double quantile(double q) {
            if (q < 0 || q > 1) throw new IllegalArgumentException("quantile out of [0, 1]: " + q);
            long total = 0;
            for (long c : counts) total += c;
            if (total == 0) return Double.NaN;
            double rank = q * total;
            long below = 0;
            for (int i = 0; i < counts.length; i++) {
                long next = below + counts[i];
                if (next >= rank && counts[i] > 0) {
                    if (i == bounds.length) return bounds.length == 0 ? Double.NaN : bounds[bounds.length - 1];
                    double lower = i == 0 ? 0 : bounds[i - 1];
                    double upper = bounds[i];
                    return lower + (upper - lower) * ((rank - below) / counts[i]);
                }
                below = next;
            }
            return bounds.length == 0 ? Double.NaN : bounds[bounds.length - 1];
        }

        @Override
        public String toString() {
            return "Snapshot[bounds=" + Arrays.toString(bounds) + ", counts=" + Arrays.toString(counts) + ", sum=" + sum
                    + ", count=" + count + "]";
        }
    }
}
