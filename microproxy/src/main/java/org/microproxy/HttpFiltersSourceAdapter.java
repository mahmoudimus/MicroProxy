package org.microproxy;

import org.microproxy.http.HttpRequest;

/** A {@link HttpFiltersSource} that applies no filtering and no buffering unless overridden. */
public class HttpFiltersSourceAdapter implements HttpFiltersSource {

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        return new HttpFiltersAdapter(originalRequest, flowContext);
    }
}
