package io.github.mahmoudimus.http2;

/**
 * A decoded field section is larger than the decoder's SETTINGS_MAX_HEADER_LIST_SIZE. This is a
 * stream error: the whole field block was still decoded, so the HPACK state is intact and the
 * connection can continue. A server would typically answer the request with 431 (Request Header
 * Fields Too Large) or reset the stream with {@link #errorCode()}.
 */
public final class HeaderListSizeException extends Http2Exception {

    private static final long serialVersionUID = 1L;

    /**
     * The decoded field section size in octets.
     */
    private final long size;
    /**
     * The configured decoded field section limit in octets.
     */
    private final long limit;

    HeaderListSizeException(int streamId, long size, long limit) {
        super(ErrorCode.PROTOCOL_ERROR, streamId, false,
                "header list of at least " + size + " octets exceeds SETTINGS_MAX_HEADER_LIST_SIZE " + limit);
        this.size = size;
        this.limit = limit;
    }

    /**
     * The size of the field section, counted as SETTINGS_MAX_HEADER_LIST_SIZE counts it.
     *
     * @return the decoded field section size in octets
     */
    public long size() {
        return size;
    }

    /**
     * The configured decoded field section limit in octets.
     *
     * @return the configured limit in octets
     */
    public long limit() {
        return limit;
    }
}
