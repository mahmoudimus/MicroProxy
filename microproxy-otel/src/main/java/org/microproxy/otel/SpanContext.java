package org.microproxy.otel;

import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;

/**
 * What a propagator carries between processes: a 128-bit trace id, a 64-bit span id, the trace
 * flags (bit 0: sampled) and the W3C {@code tracestate}, as OpenTelemetry's {@code SpanContext}.
 *
 * @param traceIdHigh the trace id's first 8 bytes
 * @param traceIdLow the trace id's last 8 bytes
 * @param spanId the span id
 * @param flags the trace flags, of which bit 0 says whether the trace is sampled
 * @param traceState the {@code tracestate} list, normalized, or an empty string
 * @param remote whether the context came from another process
 */
public record SpanContext(long traceIdHigh, long traceIdLow, long spanId, int flags, String traceState, boolean remote) {

    /** The {@code sampled} trace flag. */
    public static final int SAMPLED = 0x01;

    private static final HexFormat HEX = HexFormat.of();

    /**
     * Checks the parts.
     *
     * @param traceIdHigh the trace id's first 8 bytes
     * @param traceIdLow the trace id's last 8 bytes
     * @param spanId the span id
     * @param flags the trace flags
     * @param traceState the {@code tracestate} list, or {@code null} for none
     * @param remote whether the context came from another process
     */
    public SpanContext {
        flags &= 0xff;
        if (traceState == null) traceState = "";
    }

    /** {@return whether the ids are valid: neither is all zeros} */
    public boolean isValid() {
        return (traceIdHigh != 0 || traceIdLow != 0) && spanId != 0;
    }

    /** {@return whether the trace is sampled} */
    public boolean isSampled() {
        return (flags & SAMPLED) != 0;
    }

    /** {@return the trace id as 32 lower-case hex digits} */
    public String traceIdHex() {
        return traceIdHex(traceIdHigh, traceIdLow);
    }

    /** {@return the span id as 16 lower-case hex digits} */
    public String spanIdHex() {
        return HEX.toHexDigits(spanId);
    }

    /**
     * {@return this context with another span id and sampled flag, as the proxy's own span}
     *
     * @param spanId the span's id
     * @param sampled whether the trace is sampled
     */
    public SpanContext withSpan(long spanId, boolean sampled) {
        return new SpanContext(traceIdHigh, traceIdLow, spanId, sampled ? flags | SAMPLED : flags & ~SAMPLED, traceState,
                false);
    }

    @Override
    public String toString() {
        return "SpanContext[" + traceIdHex() + "-" + spanIdHex() + "-" + HEX.toHexDigits((byte) flags)
                + (traceState.isEmpty() ? "" : " " + traceState) + (remote ? " remote" : "") + "]";
    }

    static String traceIdHex(long high, long low) {
        return HEX.toHexDigits(high) + HEX.toHexDigits(low);
    }

    static String spanIdHex(long id) {
        return HEX.toHexDigits(id);
    }

    /** A random span id, never zero. */
    static long randomSpanId() {
        long id;
        do {
            id = ThreadLocalRandom.current().nextLong();
        } while (id == 0);
        return id;
    }

    /** Whether {@code length} characters of {@code s} from {@code from} are all lower-case hex digits. */
    static boolean isLowerHex(CharSequence s, int from, int length) {
        if (from < 0 || from + length > s.length()) return false;
        for (int i = from; i < from + length; i++) {
            char c = s.charAt(i);
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) return false;
        }
        return true;
    }

    /** Reads up to 16 lower-case hex digits as a number; the caller checks the digits first. */
    static long hexValue(CharSequence s, int from, int length) {
        long v = 0;
        for (int i = from; i < from + length; i++) {
            char c = s.charAt(i);
            v = (v << 4) | (c <= '9' ? c - '0' : c - 'a' + 10);
        }
        return v;
    }
}
