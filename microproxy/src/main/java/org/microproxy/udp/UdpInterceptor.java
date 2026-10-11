package org.microproxy.udp;

/**
 * Sees, rewrites, drops and adds the datagrams of UDP flows the proxy relays: the UDP counterpart
 * of {@link org.microproxy.tcp.TcpInterceptor}, as mitmproxy's {@code udp_message} hooks. Configure
 * one per proxy with {@link org.microproxy.HttpProxyServerBootstrap#withUdpInterceptor(UdpInterceptor)}.
 *
 * <pre>{@code
 * bootstrap.withUdpInterceptor((message, ctx) -> message.fromClient() && message.length() > 1200
 *         ? null                                                        // drop
 *         : message.data());                                            // pass on
 * }</pre>
 *
 * <h2>Which flows</h2>
 *
 * <p>Every CONNECT-UDP flow (MASQUE, RFC 9298) a client of the forward proxy's HTTP/3 listener
 * opens: the client's UDP payloads, which arrive in HTTP Datagrams (QUIC DATAGRAM frames, or
 * DATAGRAM capsules on the request stream), go to the target from a UDP socket of the flow's own,
 * and the target's datagrams come back to the client the same way.
 *
 * <h2>Messages</h2>
 *
 * <p>Unlike TCP, UDP keeps message boundaries: a {@link UdpMessage} is one datagram's payload,
 * and what the hook returns is sent as one datagram. UDP is unreliable: the proxy drops datagrams
 * when a flow's queue is full, as a network would, and so may the hook.
 *
 * <p>Each direction is handled by a thread of its own, so the hooks of one flow are called from
 * two threads at once, and those of many flows concurrently: the interceptor must be thread-safe.
 * Within a direction, calls come in order, and the direction waits for each one.
 *
 * <p>Every flow gets {@link #udpStart} first, then its messages, then {@link #udpEnd}. A hook that
 * throws is logged; a throwing {@link #udpMessage} passes the datagram on unchanged.
 */
@FunctionalInterface
public interface UdpInterceptor {

    /**
     * A flow opened: the client's CONNECT-UDP was accepted and the proxy's socket to the target is
     * ready, nothing has been relayed yet. {@link UdpContext#send} may already send datagrams.
     *
     * @param context the flow
     */
    default void udpStart(UdpContext context) {}

    /**
     * A datagram from one side, before it is passed on.
     *
     * @param message the payload, which side sent it and when
     * @param context the flow, and {@link UdpContext#send} to add datagrams
     * @return the payload to send on as one datagram: {@code message.data()} as it is or changed in
     *     place, or other bytes (possibly empty, an empty datagram); null to drop it
     */
    byte[] udpMessage(UdpMessage message, UdpContext context);

    /**
     * The flow ended: the client closed or reset its stream, the flow was idle for the idle
     * timeout, or its socket failed.
     *
     * @param context the flow
     */
    default void udpEnd(UdpContext context) {}
}
