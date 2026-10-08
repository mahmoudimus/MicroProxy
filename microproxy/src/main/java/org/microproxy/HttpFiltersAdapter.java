package org.microproxy;

import org.microproxy.http.HttpRequest;

/** Convenience base class for {@link HttpFilters} that keeps the original request and context. */
public class HttpFiltersAdapter implements HttpFilters {

    /** A filter that does nothing. */
    public static final HttpFilters NOOP_FILTER = new HttpFilters() {};

    protected final HttpRequest originalRequest;
    protected final FlowContext flowContext;

    public HttpFiltersAdapter(HttpRequest originalRequest, FlowContext flowContext) {
        this.originalRequest = originalRequest;
        this.flowContext = flowContext;
    }

    public HttpFiltersAdapter(HttpRequest originalRequest) {
        this(originalRequest, null);
    }
}
