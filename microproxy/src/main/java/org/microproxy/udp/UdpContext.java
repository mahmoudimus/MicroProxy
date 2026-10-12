package org.microproxy.udp;

import java.net.InetSocketAddress;
import org.microproxy.FlowContext;

/**
 * One UDP flow, as a {@link UdpInterceptor} sees it: where it goes, and a way to add datagrams.
 * The same context is given to every hook call of the flow, so it can serve as a key for per-flow
 * state.
 */
public interface UdpContext {

    /**
     * The client connection the flow belongs to ({@link FlowContext#getConnectionId()}).
     *
     * @return the client connection's id
     */
    long connectionId();

    /**
     * The client's address.
     *
     * @return the client address
     */
    InetSocketAddress clientAddress();

    /**
     * The host the flow goes to, as the CONNECT-UDP request named it.
     *
     * @return the target host name or IP address (IPv6 without brackets)
     */
    String host();

    /**
     * The port the flow goes to.
     *
     * @return the target port
     */
    int port();

    /**
     * The address the flow's socket is connected to: the target, resolved.
     *
     * @return the target's address
     */
    InetSocketAddress targetAddress();

    /**
     * The exchange that opened the flow (its CONNECT-UDP request, on its own HTTP/3 stream).
     *
     * @return the flow context
     */
    FlowContext flowContext();

    /**
     * Sends a datagram as if one side had sent it: with {@code fromClient} it goes to the target,
     * else to the client. It does not pass through {@link UdpInterceptor#udpMessage}, and is
     * queued as relayed datagrams are, so it may be dropped as they may.
     *
     * @param fromClient true to send to the target, false to send to the client
     * @param data the payload of one datagram
     * @throws IllegalStateException if the flow has ended
     * @throws NullPointerException if {@code data} is null
     */
    void send(boolean fromClient, byte[] data);
}
