package org.microproxy.quic;

import java.net.InetSocketAddress;
import org.microproxy.FlowContext;

/**
 * One intercepted QUIC connection, as a {@link QuicInterceptor} sees it: who the client is, where
 * the connection goes, what was negotiated, and a way to add datagrams. The same context is given
 * to every connection-level hook call ({@link QuicStreamContext#connection()} returns it too), so
 * it can serve as a key for per-connection state.
 */
public interface QuicContext {

    /**
     * The client connection the QUIC connection belongs to ({@link FlowContext#getConnectionId()}).
     *
     * @return the client connection's id
     */
    long connectionId();

    /**
     * The client's address: the redirected client's, or the client of the CONNECT-UDP flow the
     * QUIC came in.
     *
     * @return the client address
     */
    InetSocketAddress clientAddress();

    /**
     * The host the connection goes to: the SNI's on the transparent QUIC listener, the CONNECT-UDP
     * target's inside a flow.
     *
     * @return the server's host name or IP address (IPv6 without brackets)
     */
    String host();

    /**
     * The port the connection goes to.
     *
     * @return the server's port
     */
    int port();

    /**
     * The address the proxy's QUIC connection to the server is connected to.
     *
     * @return the server's address
     */
    InetSocketAddress serverAddress();

    /**
     * The server name the client asked for in its ClientHello, which the proxy asked the server for
     * and issued its certificate for.
     *
     * @return the SNI
     */
    String sni();

    /**
     * The ALPN protocol negotiated with both sides: the one the server chose of those the client
     * offered.
     *
     * @return the protocol, or null for none
     */
    String alpn();

    /**
     * Whether the QUIC came inside a CONNECT-UDP flow (MASQUE), rather than to the transparent QUIC
     * listener.
     *
     * @return whether the connection is a CONNECT-UDP flow's
     */
    boolean masque();

    /**
     * The flow of the {@code CONNECT} the proxy made up to decide on the connection.
     *
     * @return the flow context
     */
    FlowContext flowContext();

    /**
     * The QUIC connection's context: this one, for a connection; the connection's, for a stream.
     *
     * @return the connection's context
     */
    default QuicContext connection() {
        return this;
    }

    /**
     * Sends a datagram as if one side had sent it: with {@code fromClient} it goes to the server,
     * else to the client. It does not pass through {@link QuicInterceptor#datagram}. Like any
     * datagram it may be lost, and is dropped when the destination takes no datagrams or it is too
     * large.
     *
     * @param fromClient true to send to the server, false to send to the client
     * @param data the payload of one datagram
     * @throws IllegalStateException if the connection has ended
     * @throws NullPointerException if {@code data} is null
     */
    void sendDatagram(boolean fromClient, byte[] data);
}
