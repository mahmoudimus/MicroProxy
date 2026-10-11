package org.microproxy.impl;

import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.CertifiedKey;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.function.Function;
import org.microproxy.Http3Options;
import org.microproxy.KeyMaterial;

/**
 * The reverse proxy's HTTP/3 listener: a {@link QuicServer} on the UDP port with the TCP
 * listener's number, offering ALPN {@code h3}, with the certificate of the proxy's TLS listener
 * (or one its MITM manager's CA issues, see {@link DefaultHttpProxyServer}). Each established QUIC
 * connection is a client connection of its own ({@link ClientConnection#serveHttp3}), served on
 * the server's connection executor, so a graceful stop waits for it as for TCP clients.
 */
final class Http3Listener implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(Http3Listener.class.getName());

    /** Unidirectional streams a client may have open: control, QPACK encoder and decoder, and room for extensions. */
    private static final int MAX_UNI_STREAMS = 16;

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
        Http3Options options = server.http3Options;
        TlsConfig tls = TlsConfig.builder()
                .alpnProtocols("h3")
                .certificateSelector(hello -> {
                    KeyMaterial key = keys.apply(hello.serverName());
                    return key == null ? null : new CertifiedKey(key.chain(), key.privateKey());
                })
                .build();
        int idle = server.idleTimeoutMillis();
        TransportConfig transport = TransportConfig.builder()
                .maxIdleTimeout(idle > 0 ? Duration.ofMillis(idle) : Duration.ZERO)
                .maxConcurrentBidiStreams(options.maxConcurrentStreams())
                .maxConcurrentUniStreams(MAX_UNI_STREAMS)
                .streamReceiveWindow(options.streamReceiveWindow())
                .receiveWindow(options.connectionReceiveWindow())
                .build();
        ServerConfig config = ServerConfig.builder(tls).transport(transport).retry(options.retry()).build();
        return new Http3Listener(server, QuicServer.bind(address, config));
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
            if (server.isStopping()) {
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
