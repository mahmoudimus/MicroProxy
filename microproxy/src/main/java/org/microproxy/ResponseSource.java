package org.microproxy;

import org.microproxy.http.HttpResponse;

/**
 * Where a response sent to the client came from; see {@link
 * ActivityTracker#responseSentToClient(FlowContext, HttpResponse, ResponseSource)}. Together with
 * {@link FlowContext#upstreamStatus()} it tells server errors from the proxy's own.
 */
public enum ResponseSource {
    /**
     * The server's response, relayed. Filters may have changed its headers or body in place; one
     * that changes its status, or returns another response object, makes it {@link #FILTER}.
     */
    SERVER,
    /**
     * Made by the proxy: its answers to failures (including a {@link FailureResponder}'s), the
     * {@code 407} authentication challenge and the {@code 200} that opens a {@code CONNECT} tunnel.
     */
    PROXY,
    /**
     * Made by a filter: a short-circuit response, an answer from {@link
     * HttpFilters#proxyToServerFailure}, or a replacement for the server's or the proxy's response
     * (another response object, or the same one with a different status).
     */
    FILTER,
    /**
     * Answered by the {@link org.microproxy.cache.HttpCache}: a stored response (fresh, revalidated
     * or stale while the server is unreachable), or the cache's own {@code 504} for a request it
     * may not forward (offline mode, {@code only-if-cached}).
     */
    CACHE
}
