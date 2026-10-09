package io.github.mahmoudimus.http3;

/**
 * A decoded field section is larger than the decoder's SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114
 * §4.2.2). This is a stream error: the section was still decoded to the end and acknowledged, so
 * the QPACK state is intact and the connection can continue. A server would typically answer the
 * request with 431 (Request Header Fields Too Large), or reset the stream with
 * {@link #errorCode()}.
 */
public final class FieldSectionSizeException extends Http3Exception {

    private static final long serialVersionUID = 1L;

    private final long size;
    private final long limit;

    FieldSectionSizeException(long streamId, long size, long limit) {
        super(Http3ErrorCode.H3_EXCESSIVE_LOAD, streamId,
                "field section of at least " + size + " octets exceeds SETTINGS_MAX_FIELD_SECTION_SIZE " + limit);
        this.size = size;
        this.limit = limit;
    }

    /** The size of the field section, counted as SETTINGS_MAX_FIELD_SECTION_SIZE counts it. */
    public long size() {
        return size;
    }

    public long limit() {
        return limit;
    }
}
