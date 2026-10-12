/*
 * Ported from mitmproxy's mitmproxy/addons/anticache.py and Request.anticache in
 * mitmproxy/http.py (https://github.com/mitmproxy/mitmproxy), Copyright (c) 2013, Aldo Cortesi.
 * Licensed under the MIT License; see META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.extras;

import java.util.Objects;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Removes the request headers that let a server answer {@code 304 Not Modified} ({@code
 * If-None-Match} and {@code If-Modified-Since}), as mitmproxy's {@code anticache}, so that clients
 * get whole responses, which other addons and recorders can then see. Reads heads only.
 *
 * <pre>{@code
 * bootstrap.plusFiltersSource(AntiCache.create());
 * }</pre>
 */
public final class AntiCache implements HttpFiltersSource {

    private final FlowFilter filter;

    private AntiCache(FlowFilter filter) {
        this.filter = Objects.requireNonNull(filter, "filter");
    }

    /**
     * Strips the conditional headers from every request.
     *
     * @return the addon
     */
    public static AntiCache create() {
        return new AntiCache(FlowFilter.ALL);
    }

    /**
     * Strips the conditional headers from the requests {@code filter} matches (body matchers do
     * not match: the body is never buffered for this).
     *
     * @param filter the requests to change
     * @return the addon
     */
    public static AntiCache matching(FlowFilter filter) {
        return new AntiCache(filter);
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (HttpMethod.CONNECT.equals(originalRequest.method())) return null;
        return new AddonFilters(originalRequest, flowContext) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                if (httpObject instanceof HttpRequest r) {
                    request = r;
                    if (filter == FlowFilter.ALL || filter.matches(flow(null))) {
                        r.headers().remove("If-None-Match");
                        r.headers().remove("If-Modified-Since");
                    }
                }
                return null;
            }
        };
    }
}
