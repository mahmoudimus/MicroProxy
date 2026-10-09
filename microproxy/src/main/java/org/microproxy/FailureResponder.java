package org.microproxy;

import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Makes the proxy's own answer when a request fails ({@link ProxyFailure}), e.g. to send branded
 * error pages or JSON instead of the default plain-text body. Install it with {@link
 * HttpProxyServerBootstrap#withFailureResponder}.
 *
 * <p>Filters are asked first ({@link HttpFilters#proxyToServerFailure}); the responder is only
 * consulted when none of them answers. Whatever it returns is framed by the proxy as usual: a
 * {@code Content-Length} matching the body, the connection's keep-alive state, and no body for
 * {@code HEAD}. The response then passes {@link HttpFilters#proxyToClientResponse} like the
 * proxy's other responses.
 *
 * <p>The responder runs on the client connection's virtual thread and may be called concurrently
 * for different connections. If it throws, the failure is logged and the default answer is sent.
 */
@FunctionalInterface
public interface FailureResponder {

    /**
     * Returns the response for {@code failure}, or {@code null} for the proxy's default.
     *
     * @param request the request as the proxy was about to forward it (after filters and the
     *     proxy's own header changes); avoid echoing its parts into an HTML body unescaped
     *
     * @param failure the proxy failure to answer
     * @return the response to send, or {@code null} for the proxy default
     */
    HttpResponse respond(HttpRequest request, ProxyFailure failure);
}
