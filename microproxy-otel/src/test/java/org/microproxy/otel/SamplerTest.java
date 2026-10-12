package org.microproxy.otel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

/** Sampling decisions: always on and off, trace-id ratio, parent-based, and the samplers' names. */
class SamplerTest {

    private static final SpanContext SAMPLED_PARENT = new SpanContext(1, 2, 3, SpanContext.SAMPLED, "", true);
    private static final SpanContext UNSAMPLED_PARENT = new SpanContext(1, 2, 3, 0, "", true);

    @Test
    void alwaysOnAndOff() {
        assertTrue(Sampler.alwaysOn().shouldSample(null, 1, 2));
        assertTrue(Sampler.alwaysOn().shouldSample(UNSAMPLED_PARENT, 1, 2));
        assertFalse(Sampler.alwaysOff().shouldSample(null, 1, 2));
        assertFalse(Sampler.alwaysOff().shouldSample(SAMPLED_PARENT, 1, 2));
    }

    @Test
    void theRatioDecidesByTheTraceIdsLastEightBytes() {
        Sampler half = Sampler.traceIdRatio(0.5);
        assertTrue(half.shouldSample(null, 0, 0));
        assertTrue(half.shouldSample(null, 0, Long.MAX_VALUE / 2 - 1));
        assertTrue(half.shouldSample(null, 0, -(Long.MAX_VALUE / 2 - 1)));
        assertFalse(half.shouldSample(null, 0, Long.MAX_VALUE / 2 + 1));
        assertFalse(half.shouldSample(null, 0, Long.MAX_VALUE));
        // The first eight bytes do not matter, so every process of a trace decides the same.
        assertEquals(half.shouldSample(null, 0, 42), half.shouldSample(null, -7, 42));
        assertFalse(Sampler.traceIdRatio(0).shouldSample(null, 0, 0));
        assertTrue(Sampler.traceIdRatio(1).shouldSample(null, 0, Long.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> Sampler.traceIdRatio(1.5));
        assertThrows(IllegalArgumentException.class, () -> Sampler.traceIdRatio(Double.NaN));
    }

    @Test
    void theRatioIsMetOverManyTraces() {
        SplittableRandom random = new SplittableRandom(7);
        for (double ratio : new double[] {0.01, 0.1, 0.25, 0.9}) {
            Sampler s = Sampler.traceIdRatio(ratio);
            int sampled = 0;
            int n = 100_000;
            for (int i = 0; i < n; i++) {
                if (s.shouldSample(null, random.nextLong(), random.nextLong())) sampled++;
            }
            assertEquals(ratio, sampled / (double) n, 0.01, "ratio " + ratio);
        }
    }

    @Test
    void parentBasedFollowsTheParentAndAsksTheRootForNewTraces() {
        Sampler s = Sampler.parentBased(Sampler.alwaysOff());
        assertTrue(s.shouldSample(SAMPLED_PARENT, 1, 2));
        assertFalse(s.shouldSample(UNSAMPLED_PARENT, 1, 2));
        assertFalse(s.shouldSample(null, 1, 2));
        Sampler on = Sampler.parentBased(Sampler.alwaysOn());
        assertFalse(on.shouldSample(UNSAMPLED_PARENT, 1, 2));
        assertTrue(on.shouldSample(null, 1, 2));
        Sampler ratio = Sampler.parentBased(Sampler.traceIdRatio(0.5));
        assertTrue(ratio.shouldSample(SAMPLED_PARENT, 0, Long.MAX_VALUE));
        assertFalse(ratio.shouldSample(null, 0, Long.MAX_VALUE));
        assertTrue(ratio.shouldSample(null, 0, 0));
    }

    @Test
    void samplersAreNamedAsOtelTracesSamplerNamesThem() {
        assertEquals("ParentBased{root:AlwaysOnSampler}", Sampler.of(null, null).description());
        assertEquals("AlwaysOnSampler", Sampler.of("always_on", null).description());
        assertEquals("AlwaysOffSampler", Sampler.of("ALWAYS_OFF", null).description());
        assertEquals("TraceIdRatioBased{0.25}", Sampler.of("traceidratio", "0.25").description());
        assertEquals("TraceIdRatioBased{1.0}", Sampler.of("traceidratio", null).description());
        assertEquals("ParentBased{root:TraceIdRatioBased{0.1}}", Sampler.of("parentbased_traceidratio", "0.1").description());
        assertEquals("ParentBased{root:AlwaysOffSampler}", Sampler.of("parentbased_always_off", null).description());
        assertThrows(IllegalArgumentException.class, () -> Sampler.of("jaeger_remote", null));
        assertThrows(IllegalArgumentException.class, () -> Sampler.of("traceidratio", "lots"));
    }
}
