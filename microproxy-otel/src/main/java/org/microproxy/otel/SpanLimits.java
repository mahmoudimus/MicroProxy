package org.microproxy.otel;

/**
 * Bounds on what one span (or log record) keeps, so that attributes a script or a request supplies
 * cannot grow it without limit: past them, attributes and events are dropped and counted as
 * dropped in the export, and longer string values are cut. The defaults are OpenTelemetry's, but
 * for the value length, which OpenTelemetry leaves unbounded.
 *
 * @param maxAttributes the attributes a span keeps ({@code OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT}, 128)
 * @param maxAttributeValueLength the characters a string value keeps ({@code
 *     OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT}, 4096)
 * @param maxEvents the events a span keeps ({@code OTEL_SPAN_EVENT_COUNT_LIMIT}, 128)
 * @param maxAttributesPerEvent the attributes an event keeps ({@code OTEL_EVENT_ATTRIBUTE_COUNT_LIMIT}, 128)
 */
public record SpanLimits(int maxAttributes, int maxAttributeValueLength, int maxEvents, int maxAttributesPerEvent) {

    /** The defaults: 128 attributes of up to 4096 characters, 128 events of up to 128 attributes. */
    public static final SpanLimits DEFAULT = new SpanLimits(128, 4096, 128, 128);

    /**
     * Checks the limits.
     *
     * @param maxAttributes the attributes a span keeps
     * @param maxAttributeValueLength the characters a string value keeps
     * @param maxEvents the events a span keeps
     * @param maxAttributesPerEvent the attributes an event keeps
     * @throws IllegalArgumentException if one is negative, or the length is zero
     */
    public SpanLimits {
        if (maxAttributes < 0 || maxEvents < 0 || maxAttributesPerEvent < 0 || maxAttributeValueLength <= 0) {
            throw new IllegalArgumentException("bad span limits");
        }
    }
}
