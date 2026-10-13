package org.microproxy.loadtest.client;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.DataFormatException;
import org.HdrHistogram.Histogram;

/**
 * HdrHistogram helpers. Latencies are recorded in microseconds; summaries are reported in
 * milliseconds; histograms travel between processes compressed and Base64-encoded, so windows can
 * be merged without losing precision.
 */
public final class Histograms {

    private Histograms() {}

    /** A new histogram with three significant digits, resizing as needed. */
    public static Histogram create() {
        Histogram h = new Histogram(3);
        h.setAutoResize(true);
        return h;
    }

    /** Records {@code nanos} as microseconds (at least 1). */
    public static void recordNanos(Histogram h, long nanos) {
        h.recordValue(Math.max(1, nanos / 1000));
    }

    /** p50, p90, p99, p99.9, p99.99, max and mean in milliseconds, and the count. */
    public static Map<String, Object> summary(Histogram h) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("count", h.getTotalCount());
        if (h.getTotalCount() == 0) return m;
        m.put("p50", ms(h.getValueAtPercentile(50)));
        m.put("p90", ms(h.getValueAtPercentile(90)));
        m.put("p99", ms(h.getValueAtPercentile(99)));
        m.put("p999", ms(h.getValueAtPercentile(99.9)));
        m.put("p9999", ms(h.getValueAtPercentile(99.99)));
        m.put("max", ms(h.getMaxValue()));
        m.put("mean", Math.round(h.getMean()) / 1000.0);
        return m;
    }

    private static double ms(long micros) {
        return micros / 1000.0;
    }

    /** The histogram, compressed and Base64-encoded. */
    public static String encode(Histogram h) {
        ByteBuffer buf = ByteBuffer.allocate(h.getNeededByteBufferCapacity());
        int n = h.encodeIntoCompressedByteBuffer(buf);
        byte[] bytes = new byte[n];
        buf.flip();
        buf.get(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /** Decodes {@link #encode}'s output. */
    public static Histogram decode(String s) {
        try {
            Histogram h = Histogram.decodeFromCompressedByteBuffer(ByteBuffer.wrap(Base64.getDecoder().decode(s)), 0);
            h.setAutoResize(true);
            return h;
        } catch (DataFormatException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
