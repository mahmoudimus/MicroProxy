package org.microproxy.extras;

import org.microproxy.FlowContext;
import org.microproxy.HttpFiltersBuilder.Body;
import org.microproxy.SelectiveFilters;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.HttpMessage;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpUtil;

/**
 * The per-exchange filters of an addon. Addons read and edit heads, and buffer a body only when a
 * rule needs it (through {@code requestBufferSizeInBytes} / {@code responseBufferSizeInBytes}), so
 * they never ask for body pieces: every stream keeps the proxy's fast path unless buffered.
 */
abstract class AddonFilters implements SelectiveFilters {

    final FlowContext ctx;
    /** The request as the hooks last saw it (the live object, which filters may have changed). */
    HttpRequest request;

    AddonFilters(HttpRequest originalRequest, FlowContext ctx) {
        this.request = originalRequest;
        this.ctx = ctx;
    }

    @Override
    public boolean sees(Body stream) {
        return false;
    }

    /** The exchange as filter expressions see it, with {@code response} (null before one). */
    FlowFilter.Flow flow(HttpResponse response) {
        return FlowFilter.flow(request, Specs.url(request, ctx), response);
    }

    /** Whether {@code message} carries a body that has not been buffered. */
    static boolean unbufferedBody(HttpMessage message) {
        if (message instanceof FullHttpMessage) return false;
        return HttpUtil.isTransferEncodingChunked(message) || HttpUtil.getContentLength(message, 0) > 0;
    }

    /**
     * How much of the request body to buffer for {@code filter}: {@code max} if the filter looks at
     * the request body and might match, else 0.
     */
    int requestBufferFor(FlowFilter filter, HttpRequest head, int max) {
        if (!filter.usesRequestBody() || !unbufferedBody(head)) return 0;
        request = head;
        return filter.mayMatch(flow(null)) ? max : 0;
    }
}
