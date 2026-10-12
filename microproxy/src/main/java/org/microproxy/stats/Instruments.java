package org.microproxy.stats;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.DoubleAdder;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.LongSupplier;

/** The metrics a registry makes, and those of {@link StatsRegistry#NOOP}. */
final class Instruments {

    private Instruments() {}

    /** The names, tags and help every metric of a registry has. */
    abstract static class Named implements Metric {
        private final String name;
        private final String tagExtractedName;
        private final List<Tag> tags;
        private final String help;

        Named(String name, TagExtractor.Result extracted, String help) {
            this.name = name;
            this.tagExtractedName = extracted.tagExtractedName();
            this.tags = extracted.tags();
            this.help = help == null ? "" : help;
        }

        @Override
        public final String name() {
            return name;
        }

        @Override
        public final String tagExtractedName() {
            return tagExtractedName;
        }

        @Override
        public final List<Tag> tags() {
            return tags;
        }

        @Override
        public final String help() {
            return help;
        }

        @Override
        public String toString() {
            return name + "=" + render();
        }

        abstract String render();
    }

    static final class AdderCounter extends Named implements Counter {
        private final LongAdder count = new LongAdder();

        AdderCounter(String name, TagExtractor.Result extracted, String help) {
            super(name, extracted, help);
        }

        @Override
        public void inc() {
            count.increment();
        }

        @Override
        public void add(long n) {
            count.add(n);
        }

        @Override
        public long value() {
            return count.sum();
        }

        @Override
        String render() {
            return Long.toString(value());
        }
    }

    /** A counter whose count lives elsewhere, such as in {@link org.microproxy.cache.HttpCache#stats()}. */
    static final class SupplierCounter extends Named implements Counter {
        private final LongSupplier value;

        SupplierCounter(String name, TagExtractor.Result extracted, String help, LongSupplier value) {
            super(name, extracted, help);
            this.value = value;
        }

        @Override
        public void inc() {
            throw new UnsupportedOperationException(name() + " reads its count from elsewhere");
        }

        @Override
        public void add(long n) {
            throw new UnsupportedOperationException(name() + " reads its count from elsewhere");
        }

        @Override
        public long value() {
            return value.getAsLong();
        }

        @Override
        String render() {
            return Long.toString(value());
        }
    }

    static final class AtomicGauge extends Named implements Gauge {
        private final AtomicLong value = new AtomicLong();

        AtomicGauge(String name, TagExtractor.Result extracted, String help) {
            super(name, extracted, help);
        }

        @Override
        public void set(long v) {
            value.set(v);
        }

        @Override
        public void add(long delta) {
            value.addAndGet(delta);
        }

        @Override
        public void inc() {
            value.incrementAndGet();
        }

        @Override
        public void dec() {
            value.decrementAndGet();
        }

        @Override
        public long value() {
            return value.get();
        }

        @Override
        String render() {
            return Long.toString(value());
        }
    }

    static final class SupplierGauge extends Named implements Gauge {
        private final LongSupplier value;

        SupplierGauge(String name, TagExtractor.Result extracted, String help, LongSupplier value) {
            super(name, extracted, help);
            this.value = value;
        }

        @Override
        public void set(long v) {
            throw new UnsupportedOperationException(name() + " reads its value from elsewhere");
        }

        @Override
        public void add(long delta) {
            throw new UnsupportedOperationException(name() + " reads its value from elsewhere");
        }

        @Override
        public long value() {
            return value.getAsLong();
        }

        @Override
        String render() {
            return Long.toString(value());
        }
    }

    static final class BucketHistogram extends Named implements Histogram {
        private final double[] bounds;
        /** One adder per bucket, the last for values above every bound. */
        private final LongAdder[] buckets;
        private final DoubleAdder sum = new DoubleAdder();
        private final LongAdder count = new LongAdder();

        BucketHistogram(String name, TagExtractor.Result extracted, String help, double[] bounds) {
            super(name, extracted, help);
            this.bounds = bounds.clone();
            this.buckets = new LongAdder[bounds.length + 1];
            for (int i = 0; i < buckets.length; i++) buckets[i] = new LongAdder();
        }

        @Override
        public void record(double value) {
            buckets[bucket(value)].increment();
            sum.add(value);
            count.increment();
        }

        /** The first bucket whose bound is at least {@code value}: a binary search. */
        private int bucket(double value) {
            int lo = 0;
            int hi = bounds.length;
            while (lo < hi) {
                int mid = (lo + hi) >>> 1;
                if (bounds[mid] < value) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            return lo;
        }

        double[] bounds() {
            return bounds;
        }

        @Override
        public Snapshot snapshot() {
            long[] counts = new long[buckets.length];
            for (int i = 0; i < counts.length; i++) counts[i] = buckets[i].sum();
            return new Snapshot(bounds, counts, sum.sum(), count.sum());
        }

        @Override
        String render() {
            Snapshot s = snapshot();
            return "count=" + s.count() + " sum=" + s.sum();
        }
    }

    /** The metrics of {@link StatsRegistry#NOOP}, which do nothing. */
    static final Counter NOOP_COUNTER = new Counter() {
        @Override
        public void inc() {}

        @Override
        public void add(long n) {}

        @Override
        public long value() {
            return 0;
        }

        @Override
        public String name() {
            return "";
        }

        @Override
        public String tagExtractedName() {
            return "";
        }

        @Override
        public List<Tag> tags() {
            return List.of();
        }

        @Override
        public String help() {
            return "";
        }

        @Override
        public String toString() {
            return "NOOP counter";
        }
    };

    static final Gauge NOOP_GAUGE = new Gauge() {
        @Override
        public void set(long value) {}

        @Override
        public void add(long delta) {}

        @Override
        public void inc() {}

        @Override
        public void dec() {}

        @Override
        public long value() {
            return 0;
        }

        @Override
        public String name() {
            return "";
        }

        @Override
        public String tagExtractedName() {
            return "";
        }

        @Override
        public List<Tag> tags() {
            return List.of();
        }

        @Override
        public String help() {
            return "";
        }

        @Override
        public String toString() {
            return "NOOP gauge";
        }
    };

    static final Histogram NOOP_HISTOGRAM = new Histogram() {
        private final Snapshot empty = new Snapshot(new double[0], new long[1], 0, 0);

        @Override
        public void record(double value) {}

        @Override
        public void recordNanos(long nanos) {}

        @Override
        public Snapshot snapshot() {
            return empty;
        }

        @Override
        public String name() {
            return "";
        }

        @Override
        public String tagExtractedName() {
            return "";
        }

        @Override
        public List<Tag> tags() {
            return List.of();
        }

        @Override
        public String help() {
            return "";
        }

        @Override
        public String toString() {
            return "NOOP histogram";
        }
    };
}
