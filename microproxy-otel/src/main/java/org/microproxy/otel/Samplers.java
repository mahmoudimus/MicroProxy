package org.microproxy.otel;

/** The {@link Sampler} implementations. */
final class Samplers {

    private Samplers() {}

    static final Sampler ALWAYS_ON = new Sampler() {
        @Override
        public boolean shouldSample(SpanContext parent, long traceIdHigh, long traceIdLow) {
            return true;
        }

        @Override
        public String description() {
            return "AlwaysOnSampler";
        }

        @Override
        public String toString() {
            return description();
        }
    };

    static final Sampler ALWAYS_OFF = new Sampler() {
        @Override
        public boolean shouldSample(SpanContext parent, long traceIdHigh, long traceIdLow) {
            return false;
        }

        @Override
        public String description() {
            return "AlwaysOffSampler";
        }

        @Override
        public String toString() {
            return description();
        }
    };

    static final class TraceIdRatio implements Sampler {
        private final double ratio;
        private final long idUpperBound;

        TraceIdRatio(double ratio) {
            if (!(ratio >= 0 && ratio <= 1)) throw new IllegalArgumentException("the ratio must be in [0, 1]: " + ratio);
            this.ratio = ratio;
            // As OpenTelemetry's Java SDK: 0 samples nothing, 1 everything.
            this.idUpperBound = ratio == 0 ? Long.MIN_VALUE : ratio == 1 ? Long.MAX_VALUE : (long) (ratio * Long.MAX_VALUE);
        }

        @Override
        public boolean shouldSample(SpanContext parent, long traceIdHigh, long traceIdLow) {
            return ratio >= 1 || Math.abs(traceIdLow) < idUpperBound;
        }

        @Override
        public String description() {
            return "TraceIdRatioBased{" + ratio + "}";
        }

        @Override
        public String toString() {
            return description();
        }
    }

    static final class ParentBased implements Sampler {
        private final Sampler root;

        ParentBased(Sampler root) {
            this.root = java.util.Objects.requireNonNull(root);
        }

        @Override
        public boolean shouldSample(SpanContext parent, long traceIdHigh, long traceIdLow) {
            return parent != null ? parent.isSampled() : root.shouldSample(null, traceIdHigh, traceIdLow);
        }

        @Override
        public String description() {
            return "ParentBased{root:" + root.description() + "}";
        }

        @Override
        public String toString() {
            return description();
        }
    }
}
