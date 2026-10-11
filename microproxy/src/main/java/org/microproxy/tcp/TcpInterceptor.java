package org.microproxy.tcp;

/**
 * Sees, rewrites, drops and adds the bytes of raw TCP tunnels: mitmproxy's {@code tcp_start},
 * {@code tcp_message}, {@code tcp_end} and {@code tcp_error} hooks. Configure one per proxy with
 * {@link org.microproxy.HttpProxyServerBootstrap#withTcpInterceptor(TcpInterceptor)}.
 *
 * <pre>{@code
 * bootstrap.withTcpInterceptor((message, ctx) -> message.fromClient()
 *         ? message.data()                                              // pass on
 *         : message.text().replace("ESMTP", "ESMTP proxied").getBytes(UTF_8));
 * }</pre>
 *
 * <h2>Which tunnels</h2>
 *
 * <p>Every connection the proxy relays as bytes rather than as HTTP: a {@code CONNECT} tunnel that
 * is not intercepted (no MITM manager, an ignored host, a declined ClientHello, a protocol other
 * than TLS or HTTP, a server that speaks first), on an HTTP/1 connection or as a stream of an
 * HTTP/2 one, and whether the server is reached directly, through a chained proxy, on a stream of
 * an HTTP/2 connection or through an intercepted HTTPS proxy; {@code reverse:tcp://} connections;
 * and intercepted TLS sessions that do not carry HTTP (see {@link
 * org.microproxy.HttpProxyServerBootstrap#withTcpInterceptor}), whose bytes the hooks see
 * decrypted ({@link TcpContext#tlsIntercepted()}). Hosts matched by {@link
 * org.microproxy.HttpProxyServerBootstrap#withTcpHosts} are tunnels even when they speak HTTP.
 * Upgraded WebSocket connections are not: their frames go to the WebSocket frame hooks.
 *
 * <h2>Messages</h2>
 *
 * <p>TCP has no message boundaries: a {@link TcpMessage} is whatever one read returned, so a
 * peer's write may be seen in pieces or joined with the next one (see {@link TcpMessage}).
 *
 * <p>Each direction is read by a thread of its own, so the hooks of one tunnel are called from two
 * threads at once, and those of many tunnels concurrently: the interceptor must be thread-safe.
 * Within a direction, calls come in order, and the direction waits for each one: a slow hook slows
 * that direction down.
 *
 * <p>Every tunnel gets {@link #tcpStart} first, then its messages and half-closes, then either
 * {@link #tcpEnd} or {@link #tcpError}, never both. A hook that throws is logged; a throwing
 * {@link #tcpMessage} passes the message on unchanged.
 *
 * <p>Without an interceptor, tunnels copy bytes through pooled buffers as they always did, and
 * cost nothing extra.
 */
@FunctionalInterface
public interface TcpInterceptor {

    /**
     * A tunnel opened: both sides are connected, nothing has been relayed yet (except the bytes
     * the proxy read to decide what the connection is, which follow as the first message).
     * {@link TcpContext#send} may already add bytes, such as a greeting.
     *
     * @param context the tunnel
     */
    default void tcpStart(TcpContext context) {}

    /**
     * Bytes read from one side, before they are passed on.
     *
     * @param message the bytes, which side sent them and when
     * @param context the tunnel, and {@link TcpContext#send} to add bytes after these
     * @return the bytes to pass on: {@code message.data()} as it is or changed in place, other
     *     bytes, or null or an empty array to drop them
     */
    byte[] tcpMessage(TcpMessage message, TcpContext context);

    /**
     * One side finished sending (end of stream, a TCP half-close): called before the end is passed
     * on to the other side, so {@link TcpContext#send} with the same {@code fromClient} can still
     * add bytes in that direction. The other direction goes on.
     *
     * @param context the tunnel
     * @param fromClient whether the client finished sending, rather than the server
     */
    default void tcpHalfClose(TcpContext context, boolean fromClient) {}

    /**
     * The tunnel ended: both directions finished, or one side closed the connection.
     *
     * @param context the tunnel
     */
    default void tcpEnd(TcpContext context) {}

    /**
     * The tunnel failed: a read or write failed (a reset, a timeout), and the connection was
     * closed. Called instead of {@link #tcpEnd}.
     *
     * @param context the tunnel
     * @param error what failed
     */
    default void tcpError(TcpContext context, Throwable error) {}
}
