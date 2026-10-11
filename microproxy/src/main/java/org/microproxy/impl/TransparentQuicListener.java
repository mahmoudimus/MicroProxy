package org.microproxy.impl;

import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.Function;
import org.microproxy.ClientHello;
import org.microproxy.KeyMaterial;

/**
 * The transparent QUIC listener ({@link org.microproxy.HttpProxyServerBootstrap#withTransparentQuicPort}):
 * one UDP socket that QUIC redirected by a firewall arrives at, from many clients, which the
 * listener intercepts (HTTP/3 with a certificate the proxy issues, or other protocols stream by
 * stream) or relays untouched to the server, flow by flow, as the transparent TLS listener does for
 * TCP.
 *
 * <p>The socket is a {@link QuicServer}'s, whose {@link QuicServer.DatagramFilter} is the {@link
 * QuicFlows}': they hold each new client's datagrams, read its ClientHello, decide, and intercept or
 * relay it. Every flow of the listener has the same {@link QuicFlows.Origin}: its server is the
 * host its SNI names, on the transparent TLS port, and a relayed flow gets a UDP socket of its own,
 * whose replies the listener's socket sends back (so that the NAT that redirected the client maps
 * them back to the address the client sent to).
 */
final class TransparentQuicListener implements AutoCloseable {

    /** The ALPN identifier of HTTP/3, which is served as HTTP/3 when intercepted. */
    static final String H3 = "h3";

    private final QuicFlows flows;
    private final QuicServer quic;

    private TransparentQuicListener(DefaultHttpProxyServer server, InetSocketAddress address,
            Function<String, KeyMaterial> keys) throws IOException {
        Origin origin = new Origin(server);
        this.flows = new QuicFlows(server, keys, client -> origin, server.name + "-quic", server.stats.transparentQuic);
        this.quic = QuicServer.bind(address, Http3Listener.serverConfig(server, keys != null ? keys : sni -> null),
                EndpointConfig.defaults(), flows::filter);
        QuicStats.of(server, QuicStats.TRANSPARENT).observe(quic);
        flows.start(quic);
    }

    /**
     * Binds the listener on UDP {@code address} and starts it.
     *
     * @param keys the certificate for a server name, or null when no flow can be intercepted
     * @throws IOException if the port cannot be bound
     */
    static TransparentQuicListener start(DefaultHttpProxyServer server, InetSocketAddress address,
            Function<String, KeyMaterial> keys) throws IOException {
        return new TransparentQuicListener(server, address, keys);
    }

    /** The UDP address the listener is bound to. */
    InetSocketAddress localAddress() {
        return quic.localAddress();
    }

    /** A redirected client's flow: its server is the SNI's host, on the transparent TLS port. */
    private record Origin(DefaultHttpProxyServer server) implements QuicFlows.Origin {

        @Override
        public HostAndPort destination(ClientHello hello) {
            return hello.sni() == null ? null : new HostAndPort(hello.sni(), server.transparentTlsPort);
        }

        @Override
        public InetSocketAddress address(HostAndPort destination) throws IOException {
            return server.serverResolver.resolve(destination.host(), destination.port());
        }

        @Override
        public ClientConnection connection(InetSocketAddress client) {
            return new ClientConnection(server, client);
        }

        @Override
        public boolean masque() {
            return false;
        }

        @Override
        public boolean relay(ClientConnection connection, List<ByteBuffer> held) {
            return false; // from a socket of the flow's own
        }
    }

    // ---------------------------------------------------------------------------------------
    // For tests and monitoring
    // ---------------------------------------------------------------------------------------

    /** The flows pending: ClientHellos being read or decided on. */
    int pendingFlows() {
        return flows.pendingFlows();
    }

    /** The flows relayed. */
    int relayedFlows() {
        return flows.relayedFlows();
    }

    /** The bytes of datagrams pending flows hold. */
    long heldBytes() {
        return flows.heldBytes();
    }

    /** The datagrams dropped so far. */
    long droppedDatagrams() {
        return flows.droppedDatagrams();
    }

    /** Closes the relays and the QUIC server (and with it the intercepted connections). */
    @Override
    public void close() {
        flows.close();
    }
}
