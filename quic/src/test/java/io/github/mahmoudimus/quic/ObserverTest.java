package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** {@link QuicConnection.Observer}s and {@link QuicConnection#stats()} over loopback sockets. */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ObserverTest {

    /** What an observer heard. */
    record Event(String what, QuicConnection connection, Duration elapsed, QuicConnection.Stats stats,
            ConnectionError reason, boolean handshakeCompleted) {}

    private static final class Recorder implements QuicConnection.Observer {
        final LinkedBlockingQueue<Event> events = new LinkedBlockingQueue<>();

        @Override
        public void opened(QuicConnection connection) {
            events.add(new Event("opened", connection, null, null, null, false));
        }

        @Override
        public void handshakeCompleted(QuicConnection connection, Duration elapsed) {
            events.add(new Event("handshake", connection, elapsed, null, null, true));
        }

        @Override
        public void closed(QuicConnection connection, QuicConnection.Stats stats, ConnectionError reason,
                boolean handshakeCompleted) {
            events.add(new Event("closed", connection, null, stats, reason, handshakeCompleted));
        }

        Event next() throws InterruptedException {
            Event e = events.poll(10, TimeUnit.SECONDS);
            assertNotNull(e, "no event");
            return e;
        }
    }

    @Test
    void bothSidesReportTheirConnectionsAndStats() throws Exception {
        Recorder serverSide = new Recorder();
        Recorder clientSide = new Recorder();
        try (EchoServer echo = new EchoServer(LoopbackTest.serverConfig(LoopbackTest.fastTransport()));
                QuicClient client = QuicClient.create(LoopbackTest.clientConfig(LoopbackTest.fastTransport()))) {
            echo.server.observe(serverSide);
            client.observe(clientSide);
            QuicConnection c = client.connect(echo.server.localAddress(), "localhost", Duration.ofSeconds(10));
            byte[] data = LoopbackTest.data(3, 200_000);
            LoopbackTest.echo(c, data);

            QuicConnection.Stats live = c.stats();
            assertTrue(live.sentBytes() > data.length && live.receivedBytes() > data.length, live.toString());
            assertTrue(live.sentPackets() > 0 && live.receivedPackets() > 0, live.toString());
            assertTrue(live.minRtt().compareTo(Duration.ZERO) > 0, live.toString());
            assertEquals("cubic", live.congestionController());

            assertEquals("opened", clientSide.next().what());
            Event handshake = clientSide.next();
            assertEquals("handshake", handshake.what());
            assertSame(c, handshake.connection());
            assertTrue(handshake.elapsed().compareTo(Duration.ZERO) > 0);
            assertEquals("opened", serverSide.next().what());
            assertEquals("handshake", serverSide.next().what());

            c.close(7, "done");
            Event closed = clientSide.next();
            assertEquals("closed", closed.what());
            assertTrue(closed.stats().sentBytes() >= live.sentBytes(), closed.stats().toString());
            assertEquals(ConnectionError.Kind.LOCALLY_CLOSED, closed.reason().kind());
            assertTrue(closed.handshakeCompleted());

            Event serverClosed = serverSide.next();
            assertEquals("closed", serverClosed.what());
            assertEquals(ConnectionError.Kind.APPLICATION_CLOSED, serverClosed.reason().kind());
            assertEquals(7, serverClosed.reason().code());
            assertTrue(serverClosed.stats().receivedBytes() > data.length);
            assertEquals(new EndpointStats(0, 0, 0, 0), echo.server.endpointStats());
        }
    }

    @Test
    void aFailedHandshakeIsReportedClosedWithoutCompleting() throws Exception {
        Recorder clientSide = new Recorder();
        TlsConfig tls = TlsConfig.builder()
                .serverName("localhost")
                .trustManager(TestCerts.CA.trustManager())
                .alpnProtocols("no-such-protocol")
                .build();
        try (EchoServer echo = new EchoServer(LoopbackTest.serverConfig(LoopbackTest.fastTransport()));
                QuicClient client = QuicClient.create(ClientConfig.builder(tls).build())) {
            client.observe(clientSide);
            assertThrows(IOException.class,
                    () -> client.connect(echo.server.localAddress(), "localhost", Duration.ofSeconds(5)));
            assertEquals("opened", clientSide.next().what());
            Event closed = clientSide.next();
            assertEquals("closed", closed.what());
            assertFalse(closed.handshakeCompleted());
            assertEquals(ConnectionError.Kind.CONNECTION_CLOSED, closed.reason().kind(), closed.reason().toString());
        }
    }
}
