package org.microproxy.quic;

import java.util.List;

/**
 * Sees, rewrites, drops and adds the stream data and datagrams of QUIC connections the proxy
 * terminates without speaking their protocol: the QUIC counterpart of {@link
 * org.microproxy.tcp.TcpInterceptor}. Configure one per proxy with {@link
 * org.microproxy.HttpProxyServerBootstrap#withQuicInterceptor(QuicInterceptor)}.
 *
 * <pre>{@code
 * bootstrap.withQuicInterceptor((message, stream) -> message.fromClient()
 *         ? message.data()                                              // pass on
 *         : message.text().replace("secret", "******").getBytes(UTF_8));
 * }</pre>
 *
 * <h2>Which connections</h2>
 *
 * <p>QUIC whose ClientHello offers no HTTP/3 ({@code doq}, {@code hq-interop}, a protocol of its
 * own) that the proxy decides to intercept: redirected to the {@linkplain
 * org.microproxy.HttpProxyServerBootstrap#withTransparentQuicPort transparent QUIC listener}, or
 * inside a CONNECT-UDP flow with {@link org.microproxy.Http3Options.Builder#connectUdpInterceptQuic}.
 * With an interceptor, such clients are intercepted (the host rules, {@code shouldIntercept} and
 * the filters still decide first); without one they are relayed untouched. Hosts matched by
 * {@link org.microproxy.HttpProxyServerBootstrap#withQuicHosts} come here even when they offer
 * HTTP/3, with or without an interceptor.
 *
 * <p>The proxy finishes a handshake with the server first, offering the client's ALPN protocols
 * and server name, then one with the client, presenting a certificate its CA issues for the server
 * name and choosing the protocol the server chose. Each stream one side opens is opened on the other
 * connection, of the same kind (bidirectional or unidirectional), and its bytes, its end (FIN), a
 * reset (RESET_STREAM) and a request to stop sending (STOP_SENDING) are passed on, with their error
 * codes; datagrams (RFC 9221) go across one for one, when both sides take them. When one connection
 * closes, the other is closed with the same application error code and reason.
 *
 * <h2>Stream data</h2>
 *
 * <p>A stream is a byte stream, as TCP is: a {@link QuicStreamMessage} is whatever one read
 * returned (at most 16 KiB), so a peer's write may be seen in pieces or joined with the next one,
 * differently from one run to the next. A hook that looks for a message of the protocol keeps the
 * start of it until its end arrives.
 *
 * <p>Flow control is end to end: each direction of each stream is read only as fast as the other
 * side takes its data, so a slow reader slows its writer down through QUIC's own flow control,
 * and the proxy holds at most one read per direction (with framing, a message's bytes and one
 * read). Stream limits are the peers' too: a stream one side opens waits until the other side's
 * limit allows it.
 *
 * <h2>Messages</h2>
 *
 * <p>An interceptor that overrides {@link #streamMessage} sees whole messages instead, on the
 * connections that {@link QuicFraming} (configured with {@link
 * org.microproxy.HttpProxyServerBootstrap#withQuicFraming}) gives a {@link MessageFramer}: by
 * default DNS over QUIC ({@code doq}), whose messages have a two-byte length prefix. The proxy
 * keeps each direction's bytes until a message is whole, shows its payload to {@code streamMessage},
 * and frames what that returns again, computing a length prefix afresh for an edited payload. On
 * such a stream {@link #streamData} is not called: framing replaces it. A message larger than
 * {@link QuicFraming#maxMessageSize()}, or bytes the framer cannot read, reset the stream in both
 * directions on both connections with {@link QuicFraming#errorCode()}. Bytes left over when a side
 * finishes its stream, not a whole message, are passed on as they are. Streams of connections
 * without a framer, and every stream when the interceptor does not override {@code streamMessage},
 * go through {@code streamData} as before, and nothing is kept.
 *
 * <pre>{@code
 * bootstrap.withQuicInterceptor(new QuicInterceptor() {
 *     public byte[] streamData(QuicStreamMessage message, QuicStreamContext stream) {
 *         return message.data();                                  // other protocols' streams
 *     }
 *
 *     public List<QuicMessage> streamMessage(QuicMessage message, QuicStreamContext stream) {
 *         DnsMessage dns = message.dns();                          // a DNS over QUIC message
 *         log(dns.questions());
 *         return List.of(message);
 *     }
 * });
 * }</pre>
 *
 * <h2>Threads</h2>
 *
 * <p>Each direction of each stream is read by a thread of its own, and so are the datagrams of
 * each direction, so a connection's hooks are called from many threads at once: the interceptor
 * must be thread-safe. Within one direction of one stream, calls come in order, and the
 * direction waits for each one.
 *
 * <p>Every connection gets {@link #quicStart} first, then its streams' and datagrams' hooks (each
 * stream's {@link #streamOpened} before its data), then either {@link #quicEnd} or {@link
 * #quicError}, never both. A hook that throws is logged; a throwing {@link #streamData}, {@link
 * #streamMessage} or {@link #datagram} passes the bytes on unchanged.
 */
@FunctionalInterface
public interface QuicInterceptor {

    /**
     * A connection was intercepted: the handshakes with both sides are complete, nothing has been
     * relayed yet. {@link QuicContext#sendDatagram} may already send datagrams.
     *
     * @param context the connection
     */
    default void quicStart(QuicContext context) {}

    /**
     * A side opened a stream, which the proxy has opened on the other connection: called before
     * any of its data. {@link QuicStreamContext#send} may already add bytes.
     *
     * @param stream the stream
     */
    default void streamOpened(QuicStreamContext stream) {}

    /**
     * Bytes read from one side of a stream, before they are passed on.
     *
     * @param message the bytes, which side sent them and when
     * @param stream the stream, and {@link QuicStreamContext#send} to add bytes after these
     * @return the bytes to pass on: {@code message.data()} as it is or changed in place, other
     *     bytes, or null or an empty array to drop them
     */
    byte[] streamData(QuicStreamMessage message, QuicStreamContext stream);

    /**
     * A whole message from one side of a stream, on a connection that {@link QuicFraming} gives a
     * framer, before it is passed on; on such streams this replaces {@link #streamData}. Only
     * interceptors that override this method see messages: the proxy frames streams for no other.
     *
     * <p>Each message returned is framed again ({@link MessageFramer#frame}) and sent in the
     * direction its {@link QuicMessage#fromClient()} says, on the same stream: those of the same
     * direction follow each other in place of {@code message}, and those of the other direction
     * (made with {@link QuicMessage#withFromClient}) are sent to the side that sent {@code
     * message}, as if the other side had answered. A hook that throws, or returns a payload the
     * framer cannot frame, has the message passed on unchanged.
     *
     * @param message the message's payload, which side sent it, on which stream and when
     * @param stream the stream, and {@link QuicStreamContext#send} to add bytes as they are (not
     *     framed) after these
     * @return the messages to send: {@code List.of(message)} (the default) to pass it on with any
     *     change made in place, others, or null or an empty list to drop it
     */
    default List<QuicMessage> streamMessage(QuicMessage message, QuicStreamContext stream) {
        return List.of(message);
    }

    /**
     * One side finished sending on a stream (its FIN): called before the end is passed on, so
     * {@link QuicStreamContext#send} with the same {@code fromClient} can still add bytes.
     *
     * @param stream the stream
     * @param fromClient whether the client finished sending, rather than the server
     */
    default void streamFinished(QuicStreamContext stream, boolean fromClient) {}

    /**
     * One side reset its sending part of a stream (RESET_STREAM): the proxy resets the other
     * side's with the same code, after this call.
     *
     * @param stream the stream
     * @param fromClient whether the client reset it, rather than the server
     * @param errorCode the application error code
     */
    default void streamReset(QuicStreamContext stream, boolean fromClient, long errorCode) {}

    /**
     * One side asked the other to stop sending on a stream (STOP_SENDING): the proxy asks the
     * other side the same, with the same code, and resets what it sends to the side that asked.
     *
     * @param stream the stream
     * @param fromClient whether the client asked the server to stop, rather than the server the client
     * @param errorCode the application error code
     */
    default void streamStopped(QuicStreamContext stream, boolean fromClient, long errorCode) {}

    /**
     * A datagram (RFC 9221) from one side, before it is passed on. Datagrams are unreliable: the
     * proxy drops one that the other side does not take, or that is too large for it.
     *
     * @param datagram the payload, which side sent it and when
     * @param context the connection, and {@link QuicContext#sendDatagram} to add datagrams
     * @return the payload to send on as one datagram ({@code datagram.data()} as it is or changed
     *     in place, or other bytes), or null to drop it
     */
    default byte[] datagram(QuicDatagram datagram, QuicContext context) {
        return datagram.data();
    }

    /**
     * The connection ended: one side closed its connection (the other was closed the same way)
     * without an error, or the proxy closed both.
     *
     * @param context the connection
     */
    default void quicEnd(QuicContext context) {}

    /**
     * The connection failed: one side's connection timed out, was reset (a stateless reset) or
     * closed with a transport error. Called instead of {@link #quicEnd}.
     *
     * @param context the connection
     * @param error what failed
     */
    default void quicError(QuicContext context, Throwable error) {}
}
