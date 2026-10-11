package org.microproxy.tcp;

import java.net.InetSocketAddress;
import org.microproxy.FlowContext;

/**
 * One raw TCP tunnel, as a {@link TcpInterceptor} sees it: where it goes, whether the proxy
 * decrypted it, and a way to add bytes. The same context is given to every hook call of the
 * tunnel, so it can serve as a key for per-tunnel state.
 */
public interface TcpContext {

    /**
     * The client connection the tunnel belongs to ({@link FlowContext#getConnectionId()}).
     *
     * @return the client connection's id
     */
    long connectionId();

    /**
     * The client's address (the PROXY protocol's source, when the listener accepts it).
     *
     * @return the client address
     */
    InetSocketAddress clientAddress();

    /**
     * The host the tunnel goes to: the {@code CONNECT} target's, the SNI's on a transparent
     * listener, or the upstream's in {@code reverse:tcp://} mode.
     *
     * @return the target host name or IP address (IPv6 without brackets)
     */
    String host();

    /**
     * The port the tunnel goes to.
     *
     * @return the target port
     */
    int port();

    /**
     * Whether the proxy terminated the client's TLS, so the hooks see decrypted bytes: an
     * intercepted session that does not carry HTTP, or a TLS listener in {@code reverse:tcp://}
     * mode. False for a tunnel whose bytes are passed on as the client sent them, encrypted or
     * not.
     *
     * @return whether the bytes are decrypted
     */
    boolean tlsIntercepted();

    /**
     * The server name the client asked for in its TLS ClientHello, when the proxy read one (it
     * may have, and still tunnel the TLS untouched).
     *
     * @return the SNI, or null
     */
    String sni();

    /**
     * The ALPN protocol negotiated with the client, when the proxy terminated its TLS ({@code
     * imap}, {@code mqtt}, ...).
     *
     * @return the protocol, or null for none
     */
    String alpn();

    /**
     * The exchange that opened the tunnel (its {@code CONNECT}), or the client connection's flow.
     *
     * @return the flow context
     */
    FlowContext flowContext();

    /**
     * Adds bytes to the tunnel, as if one side had sent them: with {@code fromClient} they go to
     * the server, else to the client. They do not pass through {@link TcpInterceptor#tcpMessage}.
     * Called from a {@code tcpMessage} hook of the same direction, they follow that message (or
     * what replaced it); otherwise, from any hook or any thread while that direction is open, they
     * are written at once, between messages. A write that fails ends the tunnel, reported to
     * {@link TcpInterceptor#tcpError}. The call may block while the destination does not read.
     *
     * @param fromClient true to send to the server, false to send to the client
     * @param data the bytes, written as they are
     * @throws IllegalStateException if that direction has ended (its end was passed on, or the
     *     tunnel closed)
     * @throws NullPointerException if {@code data} is null
     */
    void send(boolean fromClient, byte[] data);
}
