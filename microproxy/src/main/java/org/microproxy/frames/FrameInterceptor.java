package org.microproxy.frames;

/**
 * Inspects, edits, drops and adds HTTP/2 frames on live connections, and HTTP/3 frames in an
 * {@link Http3FramePipeline}. Configure one per proxy with {@link
 * org.microproxy.HttpProxyServerBootstrap#withFrameInterceptor(FrameInterceptor)}. It is not an
 * {@link org.microproxy.HttpFilters} hook: SETTINGS, PING and GOAWAY belong to a connection, not to
 * an exchange.
 *
 * <pre>{@code
 * bootstrap.withFrameInterceptor((frame, direction, ctx) -> switch (frame) {
 *     case Http2Frame.Headers h when direction == FrameDirection.TO_CLIENT -> h.withHeader("x-seen-by", "proxy");
 *     case Http2Frame.Priority p -> null;                 // drop
 *     default -> frame;                                   // pass through
 * });
 * }</pre>
 *
 * <h2>What it sees</h2>
 *
 * <p>The proxy terminates HTTP/2 on each side, so it sees each hop's frames: those it receives from
 * the client ({@link FrameDirection#FROM_CLIENT}) after decoding them and before acting on them,
 * those it sends to the client ({@link FrameDirection#TO_CLIENT}) before encoding them, and the
 * same for every connection to a server ({@link FrameDirection#FROM_SERVER}, {@link
 * FrameDirection#TO_SERVER}). That covers HTTP/2 clients on intercepted TLS, {@code h2c} and the
 * TLS listener, HTTP/2 connections to servers with all their multiplexed streams, full-duplex gRPC,
 * and {@code CONNECT} tunnels and WebSockets over HTTP/2, whose bytes are DATA frames. Header
 * blocks arrive decoded, CONTINUATION frames folded in and padding removed; frames of extension
 * types, which the proxy otherwise discards unread, are shown as {@link Http2Frame.Unknown}. DATA
 * the proxy sends is shown in pieces of at most 16 KiB, before flow control. PUSH_PROMISE is never
 * shown: the proxy disables push, and one is a connection error.
 *
 * <p>The interceptor is called from many threads at once (each connection's reading thread, each
 * stream's thread) and must be thread-safe. It may block, but a blocked call stalls what waits on
 * it: a connection's reading of frames, or a stream's writing. The HEADERS that open a stream to a
 * server are intercepted while the connection's writing is held, so that stream ids reach the
 * server in order.
 *
 * <h2>What it may change</h2>
 *
 * <p>The return value replaces the frame: {@code frame} itself to pass it on, an edited copy, or
 * {@code null} to drop it. {@link FrameContext#send} adds frames after it. Whatever the
 * interceptor does, the proxy stays protocol-correct, so it accepts only these results:
 *
 * <table>
 *   <caption>Allowed results per frame type</caption>
 *   <tr><th>Frame</th><th>May be edited</th><th>May be dropped</th><th>May be followed by</th></tr>
 *   <tr><td>DATA</td><td>the payload, to any size</td><td>yes</td>
 *       <td>DATA; HEADERS (trailers), as the last frame, when the frame ends the stream; extension frames</td></tr>
 *   <tr><td>HEADERS</td><td>the fields</td><td>no</td><td>HEADERS; extension frames</td></tr>
 *   <tr><td>PRIORITY</td><td>everything but the stream</td><td>yes</td><td>extension frames</td></tr>
 *   <tr><td>RST_STREAM</td><td>the error code</td><td>no</td><td>extension frames</td></tr>
 *   <tr><td>SETTINGS</td><td>received: values, only to be stricter (below); sent: only extension
 *       settings</td><td>no</td><td>extension frames</td></tr>
 *   <tr><td>GOAWAY</td><td>the error code and debug data</td><td>no</td><td>extension frames</td></tr>
 *   <tr><td>extension frames</td><td>everything</td><td>yes</td><td>extension frames</td></tr>
 *   <tr><td>SETTINGS ACK, PING, WINDOW_UPDATE</td><td>nothing</td><td>no</td><td>nothing</td></tr>
 * </table>
 *
 * <ul>
 *   <li><b>Streams.</b> Stream ids are the proxy's: every frame returned or added is on the
 *       intercepted frame's stream, except extension frames, which may also be on stream 0.
 *   <li><b>END_STREAM</b> is the proxy's too: what the interceptor sets is ignored. When the
 *       intercepted frame ended its stream, the last DATA or HEADERS frame of the result does; when
 *       a DATA frame that ended its stream is dropped, an empty DATA frame with END_STREAM takes its
 *       place. Nothing may follow it on the stream.
 *   <li><b>Header fields</b> must pass {@link Field#validate}. Whether they make a valid request or
 *       response is checked as usual: a malformed request or response the proxy receives resets
 *       its stream, and a peer resets a stream the proxy sends it a malformed message on. When an
 *       edit changes the length of a body whose HEADERS declared {@code content-length}, remove or
 *       fix that field in the HEADERS too (the interceptor sees them first): the proxy checks the
 *       body it receives against it.
 *   <li><b>SETTINGS received</b> may be edited only to make the proxy stricter towards the peer:
 *       a smaller header table, initial window, frame size (not below 16384), concurrent stream
 *       limit or header list size, and not turning on ENABLE_PUSH or ENABLE_CONNECT_PROTOCOL. The
 *       proxy then uses the edited values. Its own SETTINGS keep the values it relies on.
 *   <li><b>Sizes.</b> Extension frame payloads and GOAWAY debug data are at most 16376 bytes.
 *   <li><b>HPACK</b> is never at risk: header blocks are decoded once as they arrive and encoded
 *       once as they are sent, in order.
 *   <li><b>Flow control.</b> Received DATA is counted against the proxy's windows, and credited
 *       back, at its size on the wire, whatever the interceptor makes of it. DATA the proxy sends
 *       waits for window at its size after interception.
 *   <li><b>Rate limits</b> count frames as they arrive, before interception.
 *   <li><b>Added frames</b> coming in are processed as if the peer had sent them; extension frames
 *       coming in are ignored by the proxy after the interceptor has seen them. Frames are never
 *       relayed from one side to the other: add them on the side they should reach.
 * </ul>
 *
 * <p>A result that breaks these rules is rejected as a whole: it is logged as a warning, and the
 * intercepted frame goes on unchanged, without the added frames. So does a frame whose interceptor
 * throws. Without an interceptor, frames cost nothing extra.
 *
 * <p>HTTP/3 follows the same rules in {@link Http3FramePipeline}, which describes the differences.
 */
@FunctionalInterface
public interface FrameInterceptor {

    /**
     * Inspects one frame.
     *
     * @param frame the frame, an {@link Http2Frame} or {@link Http3Frame}
     * @param direction where it is going
     * @param context the connection and stream it belongs to, and {@link FrameContext#send}
     * @return {@code frame} to pass it on, a replacement, or {@code null} to drop it
     */
    HttpFrame intercept(HttpFrame frame, FrameDirection direction, FrameContext context);
}
