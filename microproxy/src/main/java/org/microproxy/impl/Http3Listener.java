package org.microproxy.impl;

import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.CertifiedKey;
import io.github.mahmoudimus.quic.tls.EarlyDataPolicy;
import io.github.mahmoudimus.quic.tls.Ticketer;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import org.microproxy.Http3Options;
import org.microproxy.KeyMaterial;

/**
 * The proxy's HTTP/3 listener: a {@link QuicServer} on the UDP port with the TCP listener's
 * number, offering ALPN {@code h3}, with the certificate of the proxy's TLS listener (or, for a
 * reverse proxy, one its MITM manager's CA issues, see {@link DefaultHttpProxyServer}). A reverse
 * proxy's clients send it requests for its upstream; a forward proxy's send it proxy requests,
 * {@code CONNECT} and CONNECT-UDP (MASQUE), whose UDP payloads may travel in QUIC DATAGRAM frames,
 * which only this listener accepts. Each established QUIC connection is a client connection of its
 * own ({@link ClientConnection#serveHttp3}), served on the server's connection executor, so a
 * graceful stop waits for it as for TCP clients.
 */
final class Http3Listener implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(Http3Listener.class.getName());

    /** Unidirectional streams a client may have open: control, QPACK encoder and decoder, and room for extensions. */
    private static final int MAX_UNI_STREAMS = 16;
    /** Guards the making of a proxy's ticket key and anti-replay record. */
    private static final ReentrantLock TICKETER_LOCK = new ReentrantLock();

    /** QUIC DATAGRAM payloads buffered per connection before the oldest are dropped, where they are accepted. */
    private static final int DATAGRAM_BUFFER = 1024 * 1024;

    private final DefaultHttpProxyServer server;
    private final QuicServer quic;
    private final Thread acceptor;

    private Http3Listener(DefaultHttpProxyServer server, QuicServer quic) {
        this.server = server;
        this.quic = quic;
        this.acceptor = Thread.ofVirtual().name(server.name + "-h3-acceptor").start(this::acceptLoop);
    }

    /**
     * Binds the listener and starts accepting connections.
     *
     * @param keys the certificate to present for a server name (null when the client sent none)
     * @throws IOException if the UDP port cannot be bound
     */
    static Http3Listener start(DefaultHttpProxyServer server, InetSocketAddress address, Function<String, KeyMaterial> keys)
            throws IOException {
        // A forward proxy's clients may send UDP payloads in QUIC DATAGRAM frames (RFC 9297).
        QuicServer quic = QuicServer.bind(address, serverConfig(server, keys, server.reverseProxy == null));
        QuicStats.of(server, QuicStats.DOWNSTREAM).observe(quic);
        return new Http3Listener(server, quic);
    }

    /** The QUIC congestion controller the options choose, for connections to clients and to servers. */
    static TransportConfig.CongestionControl congestionControl(Http3Options options) {
        return switch (options.quicCongestionControl()) {
            case CUBIC -> TransportConfig.CongestionControl.CUBIC;
            case NEW_RENO -> TransportConfig.CongestionControl.NEW_RENO;
            case BBR -> TransportConfig.CongestionControl.BBR;
        };
    }

    /**
     * How the proxy's QUIC servers accept clients: ALPN {@code h3}, the certificate {@code keys}
     * gives for the client's SNI, session tickets sealed with the proxy's ticket key (so that its
     * QUIC servers resume each other's sessions: the HTTP/3 listener, the transparent QUIC listener
     * and the one that intercepts HTTP/3 inside CONNECT-UDP flows), 0-RTT if the options turn it on,
     * with one anti-replay record for all of them, the HTTP/3 options' stream limits, windows and
     * congestion controller, the proxy's idle timeout, and Retry if the options ask for it.
     */
    static ServerConfig serverConfig(DefaultHttpProxyServer server, Function<String, KeyMaterial> keys) {
        return serverConfig(server, keys, false);
    }

    /**
     * {@link #serverConfig(DefaultHttpProxyServer, Function)}, accepting QUIC DATAGRAM frames (RFC
     * 9221, the {@code max_datagram_frame_size} transport parameter) when {@code datagrams}: only
     * where HTTP Datagrams have a use (CONNECT-UDP), since nothing else reads them.
     */
    static ServerConfig serverConfig(DefaultHttpProxyServer server, Function<String, KeyMaterial> keys,
            boolean datagrams) {
        Http3Options options = server.http3Options;
        TlsConfig.Builder tls = TlsConfig.builder()
                .alpnProtocols("h3")
                .certificateSelector(hello -> {
                    KeyMaterial key = keys.apply(hello.serverName());
                    return key == null ? null : new CertifiedKey(key.chain(), key.privateKey());
                })
                .sessionTickets(ticketer(server))
                .earlyData(options.zeroRtt());
        // A ticket's early data is accepted once by all the servers that take the ticket, not once by each
        if (options.zeroRtt()) tls.earlyDataPolicy(earlyDataPolicy(server));
        int idle = server.idleTimeoutMillis();
        TransportConfig transport = TransportConfig.builder()
                .maxIdleTimeout(idle > 0 ? Duration.ofMillis(idle) : Duration.ZERO)
                .maxConcurrentBidiStreams(options.maxConcurrentStreams())
                .maxConcurrentUniStreams(MAX_UNI_STREAMS)
                .streamReceiveWindow(options.streamReceiveWindow())
                .receiveWindow(options.connectionReceiveWindow())
                .datagramReceiveBufferSize(datagrams ? DATAGRAM_BUFFER : 0)
                .congestionControl(congestionControl(options))
                .qlog(QlogWriter.sink(server, true))
                .build();
        return ServerConfig.builder(tls.build()).transport(transport).retry(options.retry()).build();
    }

    /** The proxy's ticket key, which rotates every few hours; made on first use. */
    private static Ticketer ticketer(DefaultHttpProxyServer server) {
        TICKETER_LOCK.lock();
        try {
            if (server.quicTicketer == null) server.quicTicketer = Ticketer.create();
            return (Ticketer) server.quicTicketer;
        } finally {
            TICKETER_LOCK.unlock();
        }
    }

    /** The proxy's anti-replay record of the tickets whose early data its QUIC servers accepted; made on first use. */
    private static EarlyDataPolicy earlyDataPolicy(DefaultHttpProxyServer server) {
        TICKETER_LOCK.lock();
        try {
            if (server.quicEarlyDataPolicy == null) server.quicEarlyDataPolicy = EarlyDataPolicy.antiReplay();
            return (EarlyDataPolicy) server.quicEarlyDataPolicy;
        } finally {
            TICKETER_LOCK.unlock();
        }
    }

    /** The UDP address the listener is bound to. */
    InetSocketAddress localAddress() {
        return quic.localAddress();
    }

    private void acceptLoop() {
        while (true) {
            QuicConnection connection;
            try {
                connection = quic.accept();
            } catch (IOException e) {
                if (!server.isStopping()) LOG.log(Level.DEBUG, server.name + " HTTP/3 listener stopped: " + e);
                return;
            }
            if (server.refusesNewConnections()) {
                connection.close(0x0100, "the proxy is stopping");
                continue;
            }
            server.acceptHttp3(connection);
        }
    }

    /** Closes every connection and the socket. */
    @Override
    public void close() {
        quic.close();
        try {
            acceptor.join(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
