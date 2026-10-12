package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A server without a socket ({@link QuicServer#unbound}), fed datagrams by its owner; a connection
 * accepted with a configuration of its own ({@link QuicServer#inject(InetSocketAddress, ByteBuffer,
 * ServerConfig)}); and {@link QuicStream#awaitStopped()}.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class UnboundServerTest {

    private static ClientConfig client(String... alpn) {
        return ClientConfig.builder(TlsConfig.builder()
                .serverName("localhost")
                .trustManager(TestCerts.CA.trustManager())
                .alpnProtocols(alpn)
                .build()).transport(TransportConfig.builder().datagramReceiveBufferSize(64 * 1024).build()).build();
    }

    private static ServerConfig server(String alpn) {
        return ServerConfig.builder(TlsConfig.builder()
                .certificateSelector(hello -> TestCerts.CA.issue(TestCerts.KeyType.P256, "localhost"))
                .alpnProtocols(alpn)
                .build()).transport(TransportConfig.builder().datagramReceiveBufferSize(64 * 1024).build()).build();
    }

    /**
     * The owner of an unbound server carries its datagrams over a socket of its own, as a proxy
     * carries them in a CONNECT-UDP flow: every datagram the server sends goes to the sink, and
     * every one the owner hands over reaches the connection or starts one.
     */
    @Test
    void anUnboundServerRunsOverItsOwnersTransport() throws Exception {
        InetSocketAddress local = new InetSocketAddress(InetAddress.getLoopbackAddress(), 4433);
        AtomicInteger sent = new AtomicInteger();
        AtomicInteger filtered = new AtomicInteger();
        try (DatagramChannel bridge = DatagramChannel.open().bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
            QuicServer server = QuicServer.unbound(local, server(LoopbackTest.ALPN), EndpointConfig.defaults(),
                    (from, datagram) -> {
                        filtered.incrementAndGet();
                        return false; // a new client's Initials, left to the endpoint
                    },
                    (datagram, to) -> {
                        sent.incrementAndGet();
                        try {
                            bridge.send(datagram, to);
                        } catch (IOException e) {
                            // the test is over
                        }
                    });
            Thread pump = Thread.ofVirtual().start(() -> {
                ByteBuffer buf = ByteBuffer.allocate(65536);
                while (true) {
                    buf.clear();
                    InetSocketAddress from;
                    try {
                        from = (InetSocketAddress) bridge.receive(buf);
                    } catch (ClosedChannelException e) {
                        return;
                    } catch (IOException e) {
                        return;
                    }
                    buf.flip();
                    server.receive(from, ByteBuffer.allocate(buf.remaining()).put(buf).flip());
                }
            });
            try (EchoServer echo = new EchoServer(server);
                    QuicClient client = QuicClient.create(client(LoopbackTest.ALPN))) {
                assertEquals(local, server.localAddress());
                QuicConnection c = client.connect((InetSocketAddress) bridge.getLocalAddress(), "localhost",
                        Duration.ofSeconds(10));
                byte[] data = LoopbackTest.data(11, 200_000);
                assertArrayEquals(LoopbackTest.sha256().digest(data), LoopbackTest.echo(c, data));
                c.sendDatagram(new byte[] {1, 2, 3});
                assertArrayEquals(new byte[] {1, 2, 3}, c.receiveDatagram(Duration.ofSeconds(10)));
                c.close(0, "done");
                assertTrue(echo.errors().isEmpty(), echo.errors().toString());
            }
            assertTrue(sent.get() > 0);
            assertTrue(filtered.get() > 0, "the client's first Initial went past the filter");
            bridge.close();
            pump.join(5000);
        }
    }

    /**
     * A filter injects each new client's Initials with a configuration of their own: here another
     * ALPN than the server's, which only that client gets.
     */
    @Test
    void anInjectedConnectionIsAcceptedWithItsOwnConfiguration() throws Exception {
        AtomicReference<QuicServer> server = new AtomicReference<>();
        ServerConfig other = server("other-protocol");
        QuicServer.DatagramFilter filter = (from, datagram) -> {
            server.get().inject(from, datagram, other);
            return true;
        };
        try (EchoServer echo = new EchoServer(server(LoopbackTest.ALPN), EndpointConfig.defaults(), filter);
                QuicClient client = QuicClient.create(client("other-protocol"))) {
            server.set(echo.server);
            QuicConnection c = client.connect(echo.address(), "localhost", Duration.ofSeconds(10));
            assertEquals("other-protocol", c.alpn());
            byte[] data = LoopbackTest.data(12, 50_000);
            assertArrayEquals(LoopbackTest.sha256().digest(data), LoopbackTest.echo(c, data));
            QuicConnection accepted = echo.accepted.poll(10, TimeUnit.SECONDS);
            assertEquals("other-protocol", accepted.alpn());
            c.close(0, "done");
        }
    }

    /** A writer that is not writing learns of the peer's STOP_SENDING, and its code. */
    @Test
    void awaitStoppedReturnsThePeersCode() throws Exception {
        ServerConfig config = server(LoopbackTest.ALPN);
        try (QuicServer server = QuicServer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);
                QuicClient client = QuicClient.create(client(LoopbackTest.ALPN))) {
            Thread.ofVirtual().start(() -> {
                try {
                    QuicConnection c = server.accept();
                    QuicStream s = c.acceptStream();
                    s.getInputStream().read();
                    s.stopSending(7);
                } catch (IOException e) {
                    // the test fails on the client's side
                }
            });
            QuicConnection c = client.connect(server.localAddress(), "localhost", Duration.ofSeconds(10));
            QuicStream s = c.openBidirectionalStream();
            OutputStream out = s.getOutputStream();
            out.write('x');
            assertEquals(7, s.awaitStopped());
            QuicStreamException e = assertThrows(QuicStreamException.class, () -> out.write('y'));
            assertEquals(7, e.errorCode());

            QuicStream finished = c.openBidirectionalStream();
            finished.getOutputStream().close();
            assertEquals(-1, finished.awaitStopped(), "nothing can stop a finished stream");
            QuicStream open = c.openBidirectionalStream();
            open.getOutputStream().write('z');
            c.close(0, "done");
            assertEquals(-1, open.awaitStopped(), "nor a stream whose connection is gone");
        }
    }
}
