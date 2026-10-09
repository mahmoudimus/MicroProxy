package org.microproxy;

import org.microproxy.http.HttpRequest;

/** Convenience base class for {@link HttpFilters} that keeps the original request and context. */
public class HttpFiltersAdapter implements HttpFilters {

    /** A filter that does nothing. */
    public static final HttpFilters NOOP_FILTER = new HttpFilters() {};

    /** The request head received from the client. */
    protected final HttpRequest originalRequest;
    /** The client connection or exchange context. */
    protected final FlowContext flowContext;

    /**
     * Creates filters retaining the original request and client context.
     *
     * @param originalRequest the request head as received from the client
     * @param flowContext the client connection or exchange context
     */
    public HttpFiltersAdapter(HttpRequest originalRequest, FlowContext flowContext) {
        this.originalRequest = originalRequest;
        this.flowContext = flowContext;
    }

    /**
     * Creates filters retaining the original request without a client context.
     *
     * @param originalRequest the request head as received from the client
     */
    public HttpFiltersAdapter(HttpRequest originalRequest) {
        this(originalRequest, null);
    }
}
