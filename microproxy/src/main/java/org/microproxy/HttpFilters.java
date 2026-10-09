package org.microproxy;

import java.net.InetSocketAddress;
import java.util.function.Supplier;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.WebSocketFrame;

/**
 * Hooks into the life of a single request/response exchange. One instance is created per request
 * by {@link HttpFiltersSource#filterRequest}; all methods are invoked on the virtual thread that
 * serves the client connection, so implementations may block.
 *
 * <p>Unless the {@link HttpFiltersSource} asks for buffering, a message flows through the filter
 * as a head ({@link org.microproxy.http.HttpRequest}/{@link org.microproxy.http.HttpResponse})
 * followed by zero or more {@link org.microproxy.http.HttpContent} pieces and a final {@link
 * org.microproxy.http.LastHttpContent}. With buffering it arrives as a single {@link
 * org.microproxy.http.FullHttpRequest}/{@link org.microproxy.http.FullHttpResponse}.
 *
 * <p>Every method has a no-op default, so implement only what you need. Call order for a typical
 * exchange:
 *
 * <ol>
 *   <li>{@link #clientToProxyRequest}
 *   <li>{@link #proxyToServerRequest}, so a filter can answer or redirect before any DNS lookup
 *       or connection
 *   <li>when a new server connection is needed: {@link #proxyToServerResolutionStarted}, {@link
 *       #proxyToServerResolutionSucceeded} / {@link #proxyToServerResolutionFailed} (direct
 *       connections only), then {@link #proxyToServerConnectionStarted}, {@link
 *       #proxyToServerConnectionSSLHandshakeStarted}, {@link #proxyToServerConnectionSucceeded} /
 *       {@link #proxyToServerConnectionFailed}
 *   <li>{@link #proxyToServerRequestSending}, {@link #proxyToServerRequestSent}
 *   <li>{@link #serverToProxyResponseReceiving}, {@link #serverToProxyResponse}, {@link
 *       #serverToProxyResponseReceived} (or {@link #serverToProxyResponseTimedOut})
 *   <li>{@link #proxyToClientResponse}, then {@link #proxyToClientResponseSent} once the response
 *       has been written
 *   <li>{@link #exchangeEnded}, exactly once, however the exchange ended
 * </ol>
 *
 * <p>When the proxy answers a request itself because something failed, {@link
 * #proxyToServerFailure} may supply the answer.
 *
 * <p>With {@link HttpProxyServerBootstrap#withLittleProxyCompatibility()}, the server is resolved
 * before {@link #proxyToServerRequest}, as LittleProxy does (and a name that does not resolve is
 * answered with {@code 502} without calling it); the connection is still made after it.
 */
public interface HttpFilters {

    /** Starts filters made from lambdas, one per hook (see {@link HttpFiltersBuilder}). */
    static HttpFiltersBuilder builder() {
        return new HttpFiltersBuilder();
    }


    /**
     * Asks for this request to be buffered, before {@link #clientToProxyRequest} sees it: return a
     * positive size to receive the head and body as one {@link
     * org.microproxy.http.FullHttpRequest}, or 0 to stream. A body larger than the size is answered
     * with {@code 413}. Not consulted for {@code CONNECT}, or when the source already buffers.
     */
    default int requestBufferSizeInBytes(HttpRequest request) {
        return 0;
    }

    /**
     * Filters requests on their way from the client to the proxy. Return a response to answer the
     * client directly ("short-circuit") without contacting the server; only the return value for
     * the request head is honoured.
     */
    default HttpResponse clientToProxyRequest(HttpObject httpObject) {
        return null;
    }

    /**
     * Filters requests on their way from the proxy to the server, after the proxy has rewritten
     * headers. Return a response to short-circuit; only the return value for the request head is
     * honoured.
     */
    default HttpResponse proxyToServerRequest(HttpObject httpObject) {
        return null;
    }

    /** Called just before the request head is written to the server. */
    default void proxyToServerRequestSending() {}

    /** Called after the complete request, including its body, has been written to the server. */
    default void proxyToServerRequestSent() {}

    /**
     * Filters responses on their way from the server to the proxy. Return the (possibly modified
     * or replaced) object, or {@code null} to abort and disconnect the client.
     */
    default HttpObject serverToProxyResponse(HttpObject httpObject) {
        return httpObject;
    }

    /**
     * Asks for this response to be buffered, after seeing its head: return a positive size to
     * receive the head and body as one {@link org.microproxy.http.FullHttpResponse} in {@link
     * #serverToProxyResponse}, or 0 to stream. Unlike {@link
     * HttpFiltersSource#getMaximumResponseBufferSizeInBytes()}, a body larger than the size is not
     * an error: it is streamed through as usual. Ignored when the source already buffers.
     */
    default int responseBufferSizeInBytes(HttpResponse response) {
        return 0;
    }

    /** Called when the server did not respond within the idle timeout. */
    default void serverToProxyResponseTimedOut() {}

    /**
     * Called when the proxy is about to answer this request itself because of {@code failure}
     * (the server could not be reached, timed out or answered badly, the request was refused, ...).
     * Return a response to send instead of the proxy's default, or {@code null}. It is framed by
     * the proxy and passes {@link #proxyToClientResponse} like any proxy-made response. Filters
     * are asked before the {@link FailureResponder}; the more specific callbacks ({@link
     * #proxyToServerResolutionFailed}, {@link #proxyToServerConnectionFailed}, {@link
     * #serverToProxyResponseTimedOut}) are still called as well, before this one.
     *
     * <p>Not called when the failure happens after the response has started (the client connection
     * is closed instead), or for requests the proxy could not parse.
     */
    default HttpResponse proxyToServerFailure(ProxyFailure failure) {
        return null;
    }

    /** Called when the server begins sending a response. */
    default void serverToProxyResponseReceiving() {}

    /** Called when the server has finished sending a response. */
    default void serverToProxyResponseReceived() {}

    /**
     * Filters responses on their way from the proxy to the client. This also sees responses
     * generated by the proxy itself (errors, short-circuits, the CONNECT 200). Return the (possibly
     * modified) object, or {@code null} to abort and disconnect the client.
     */
    default HttpObject proxyToClientResponse(HttpObject httpObject) {
        return httpObject;
    }

    /**
     * Called once the whole response has been written to the client, whoever made it: the server,
     * the proxy, a filter or the cache. {@link FlowContext#timings()} then covers the whole
     * exchange. Not called when the exchange was aborted or failed half-way through the response,
     * or for the {@code 407} challenge sent before filters are created.
     *
     * @param response the response head as it was sent (after every filter)
     * @param source where it came from, as reported to {@link
     *     ActivityTracker#responseSentToClient(FlowContext, HttpResponse, ResponseSource)}
     */
    default void proxyToClientResponseSent(HttpResponse response, ResponseSource source) {}

    /**
     * Called exactly once when this exchange is over, however it ended, so per-exchange resources
     * (a concurrency permit, a span, a temporary file) can be released:
     *
     * <ul>
     *   <li>after {@link #proxyToClientResponseSent} for a response written in full, whoever made
     *       it (the server, the proxy's failure answer, a filter's short-circuit, the cache);
     *   <li>for a {@code CONNECT} that became a byte tunnel, or a request upgraded with {@code 101}
     *       (WebSocket), when the tunnel closes;
     *   <li>for an intercepted {@code CONNECT}, once interception starts: the requests inside the
     *       session are exchanges of their own;
     *   <li>when the exchange was abandoned: the client disconnected, the server failed half-way
     *       through the response, a filter returned {@code null}, a filter or the proxy threw, or
     *       the proxy was stopped.
     * </ul>
     *
     * <p>It runs on the connection's thread before the next request on the connection is read.
     * Exceptions it throws are logged and ignored.
     *
     * @param completed whether the response was written in full ({@link
     *     #proxyToClientResponseSent} was called)
     */
    default void exchangeEnded(boolean completed) {}

    /**
     * Called before the server's host name is resolved. Return an address to skip resolution and
     * connect there instead.
     */
    default InetSocketAddress proxyToServerResolutionStarted(String resolvingServerHostAndPort) {
        return null;
    }

    default void proxyToServerResolutionFailed(String hostAndPort) {}

    default void proxyToServerResolutionSucceeded(
            String serverHostAndPort, InetSocketAddress resolvedRemoteAddress) {}

    default void proxyToServerConnectionStarted() {}

    default void proxyToServerConnectionSSLHandshakeStarted() {}

    default void proxyToServerConnectionFailed() {}

    /** Called once the connection to the server (or chained proxy) is ready for traffic. */
    default void proxyToServerConnectionSucceeded(FullFlowContext serverContext) {}

    /**
     * Whether this CONNECT request may be intercepted when a {@link MitmManager} is configured.
     * Return false to tunnel the bytes untouched instead.
     */
    default boolean proxyToServerAllowMitm() {
        return true;
    }

    /**
     * For a CONNECT that is being intercepted but whose server cannot be reached: return true to
     * intercept it anyway, with a certificate made from the requested host name alone, so these
     * filters can answer the requests inside the session (from a cache, for example). Those
     * requests fail as usual if they do need the server.
     */
    default boolean proxyToServerAllowOfflineMitm() {
        return false;
    }

    /**
     * Called for every WebSocket frame relayed after this request was upgraded ({@code 101
     * Switching Protocols} with {@code Upgrade: websocket}), including inside intercepted TLS
     * sessions. Frames are observed, not modified: they are forwarded unchanged after this returns.
     * The two directions are relayed on separate virtual threads, so this may be called
     * concurrently for client and server frames.
     *
     * <p>Frames are only parsed when the filters class overrides one of the two {@code
     * webSocketFrameReceived} methods; otherwise upgraded connections are relayed as raw bytes.
     *
     * <p>Frames whose payload exceeds {@link
     * HttpProxyServerBootstrap#withMaxWebSocketFrameBufferSize(int)} are streamed through and
     * reported with {@link WebSocketFrame#isTruncated()} set.
     *
     * <p>The default implementation delegates to the LittleProxy-compatible {@link
     * #webSocketFrameReceived(Supplier, boolean)}.
     *
     * @param fromClient true for client-to-server frames
     */
    default void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
        webSocketFrameReceived(frame::rawBytes, fromClient);
    }

    /**
     * LittleProxy-compatible form of {@link #webSocketFrameReceived(WebSocketFrame, boolean)}:
     * supplies the raw frame bytes as on the wire (header and still-masked payload).
     */
    default void webSocketFrameReceived(Supplier<byte[]> frameBytes, boolean fromClient) {}

    /**
     * Rewrites or drops a WebSocket frame on an upgraded connection, after {@link
     * #webSocketFrameReceived(WebSocketFrame, boolean)} has seen it. Return {@code frame} to
     * forward it unchanged, another frame ({@link WebSocketFrame#withText(String)}, {@link
     * WebSocketFrame#text(String)}, ...) to send instead, or {@code null} to drop it. The proxy
     * masks frames it sends towards the server.
     *
     * <ul>
     *   <li>Frames are rewritten one at a time; a message split across continuation frames is seen
     *       piece by piece.
     *   <li>When a filters class overrides this method, the proxy removes {@code
     *       Sec-WebSocket-Extensions} from the upgrade request so that payloads are not compressed
     *       (permessage-deflate) and can be read and rewritten.
     *   <li>A frame larger than {@link HttpProxyServerBootstrap#withMaxWebSocketFrameBufferSize(int)}
     *       arrives {@linkplain WebSocketFrame#isTruncated() truncated}: returning it streams it
     *       through, {@code null} discards it, and a replacement frame is sent in its place.
     *   <li>Like the observer, this is called concurrently for client and server frames.
     * </ul>
     *
     * @param fromClient true for client-to-server frames
     */
    default WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
        return frame;
    }
}
