package org.microproxy;

import java.io.IOException;
import java.net.UnknownHostException;
import org.microproxy.http.HttpResponseStatus;

/**
 * Why the proxy has to answer a request itself instead of relaying the server's response. Each
 * failure knows the status of the proxy's default answer; {@link HttpFilters#proxyToServerFailure}
 * and a {@link FailureResponder} can answer differently.
 *
 * <p>The default answers are short plain-text bodies ({@code Bad Gateway}, {@code Gateway
 * Timeout}, ...) that never echo the request. Requests the proxy cannot parse at all (malformed
 * or oversized heads, bad chunk framing) are answered with a plain {@code 4xx} without consulting
 * filters or the responder, since there is no request to hand over.
 */
public sealed interface ProxyFailure {

    /** The status of the proxy's default answer. */
    HttpResponseStatus status();

    /** The server's name did not resolve (direct connections). Default {@code 502}. */
    record UnresolvedHost(String hostAndPort, UnknownHostException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }
    }

    /**
     * No connection could be made to the server or any chained proxy offered for it: refused,
     * unreachable, timed out, or a chained proxy that refused the {@code CONNECT} or SOCKS request.
     * With several chained proxies, {@code cause} is the last one's failure. Default {@code 502}.
     */
    record ConnectFailed(String hostAndPort, IOException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }
    }

    /**
     * The TLS handshake with the server (when intercepting) or with a TLS chained proxy failed or
     * did not finish within {@link HttpProxyServerBootstrap#withTlsHandshakeTimeout}, e.g. because
     * its certificate is not trusted. Default {@code 502}.
     */
    record TlsFailed(String hostAndPort, IOException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }
    }

    /** The server did not answer within the idle timeout. Default {@code 504}. */
    record ServerTimeout(String hostAndPort, IOException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.GATEWAY_TIMEOUT;
        }
    }

    /**
     * The server's response was malformed, or the server closed the connection or failed before
     * the response head (or a body the filters asked to buffer) was complete. Default {@code 502}.
     */
    record BadServerResponse(String hostAndPort, IOException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }
    }

    /**
     * There is nowhere to send the request: it names no host ({@code hostAndPort} is null), or the
     * {@link ChainedProxyManager} offered no route. Default {@code 502}.
     */
    record NoRoute(String hostAndPort) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }
    }

    /**
     * The {@linkplain HttpProxyServerBootstrap#withSharedServerConnectionPool shared connection
     * pool} had no connection to spare within the connect timeout. Default {@code 503}.
     */
    record NoConnectionAvailable(String hostAndPort) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.SERVICE_UNAVAILABLE;
        }
    }

    /**
     * The proxy refuses the request: an origin-form request without {@link
     * HttpProxyServerBootstrap#withAllowRequestToOriginServer}, or a {@code CONNECT} target that is
     * not {@code host:port}. Default {@code 400} with the body {@code "Bad Request: " + reason}.
     */
    record BadRequest(String reason) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_REQUEST;
        }
    }

    /**
     * The request body is larger than the filters asked to buffer ({@code maxBytes}). The client
     * connection is always closed afterwards, since the rest of the body is never read. Default
     * {@code 413}.
     */
    record RequestTooLarge(int maxBytes) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.REQUEST_ENTITY_TOO_LARGE;
        }
    }
}
