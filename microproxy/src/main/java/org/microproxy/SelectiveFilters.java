package org.microproxy;

import org.microproxy.HttpFiltersBuilder.Body;

/**
 * Filters that say which streams they inspect piece by piece.
 *
 * <p>Without this interface the proxy decides from the class: one that overrides {@code
 * clientToProxyRequest} or {@code proxyToServerRequest} gets request bodies piece by piece, one that
 * overrides {@code serverToProxyResponse} or {@code proxyToClientResponse} gets response bodies,
 * and one that overrides a WebSocket frame hook gets parsed frames. A class that overrides those
 * hooks only to read heads would turn off the fast path for bodies it never looks at. Implementing
 * this interface replaces the guess with an answer per instance: the proxy relays every stream
 * {@link #sees} declines as raw bytes, and the hooks then receive only heads.
 *
 * <p>{@link HttpFiltersBuilder.Built} implements it.
 */
public interface SelectiveFilters extends HttpFilters {

    /**
     * Whether these filters inspect {@code stream} piece by piece:
     *
     * <ul>
     *   <li>{@link Body#REQUEST}: request body pieces reach {@code clientToProxyRequest} and {@code
     *       proxyToServerRequest};
     *   <li>{@link Body#RESPONSE}: response body pieces reach {@code serverToProxyResponse} and
     *       {@code proxyToClientResponse};
     *   <li>{@link Body#WEBSOCKET_FRAMES}: frames go through {@link #filterWebSocketFrame}, which
     *       makes the proxy remove {@code Sec-WebSocket-Extensions} from the upgrade request;
     *   <li>{@link Body#OBSERVED_WEBSOCKET_FRAMES}: frames are shown to {@link
     *       #webSocketFrameReceived(org.microproxy.http.WebSocketFrame, boolean)} and forwarded
     *       unchanged.
     * </ul>
     */
    boolean sees(Body stream);
}
