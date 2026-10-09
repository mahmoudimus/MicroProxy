package org.microproxy;

import org.microproxy.http.HttpRequest;

/** Creates the {@link HttpFilters} for each request. */
public interface HttpFiltersSource {

    /**
     * Returns the filters for a request, or {@code null} to proxy it unfiltered.
     *
     * @param originalRequest a copy of the request as received from the client
     * @param flowContext the client connection the request arrived on
     *
     * @return the per-request filters, or {@code null} to leave the request unfiltered
     */
    HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext);

    /**
     * When positive, request bodies are buffered (up to this many bytes) and filters receive a
     * single {@link org.microproxy.http.FullHttpRequest}. Larger requests get {@code 413}.
     *
     * @return the maximum request buffer size in bytes, or zero for streaming
     */
    default int getMaximumRequestBufferSizeInBytes() {
        return 0;
    }

    /**
     * When positive, response bodies are buffered (up to this many bytes) and filters receive a
     * single {@link org.microproxy.http.FullHttpResponse}. Larger responses get {@code 502}.
     *
     * @return the maximum response buffer size in bytes, or zero for streaming
     */
    default int getMaximumResponseBufferSizeInBytes() {
        return 0;
    }
}
