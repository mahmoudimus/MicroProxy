package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A server's {@link QuicServer.DatagramFilter}: it sees only the datagrams no connection claims,
 * may hold a client's first Initials back and {@linkplain QuicServer#inject inject} them later,
 * and may answer other datagrams from the server's socket ({@link QuicServer#send}).
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class DatagramFilterTest {

    /** Holds every datagram the endpoint does not know, then injects it from another thread. */
    @Test
    void heldInitialsStartAConnectionWhenInjected() throws Exception {
        AtomicReference<QuicServer> server = new AtomicReference<>();
        List<ByteBuffer> seen = new CopyOnWriteArrayList<>();
        QuicServer.DatagramFilter filter = (from, datagram) -> {
            seen.add(datagram.duplicate());
            // As a proxy deciding what to do with a client: a while later, on a thread of its own.
            Thread.ofVirtual().start(() -> {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    return;
                }
                server.get().inject(from, datagram);
            });
            return true;
        };
        try (EchoServer echo = new EchoServer(LoopbackTest.serverConfig(LoopbackTest.fastTransport()),
                        EndpointConfig.defaults(), filter);
                QuicClient client = QuicClient.create(LoopbackTest.clientConfig(LoopbackTest.fastTransport()))) {
            server.set(echo.server);
            QuicConnection c = client.connect(echo.address(), "localhost", Duration.ofSeconds(10));
            byte[] data = LoopbackTest.data(7, 300_000);
            assertArrayEquals(LoopbackTest.sha256().digest(data), LoopbackTest.echo(c, data));
            c.close(0, "done");

            // Only the client's first flight came through the filter: once the connection
            // existed, its datagrams went straight to it.
            assertTrue(!seen.isEmpty() && seen.size() <= 4, "filtered " + seen.size() + " datagrams");
            ProtectedPacket first = ProtectedPacket.parse(seen.getFirst().duplicate(), 8);
            assertEquals(PacketType.INITIAL, first.type());
            QuicConnection accepted = echo.accepted.poll(10, TimeUnit.SECONDS);
            assertNotNull(accepted);
            assertEquals(first.destinationId(), accepted.initialDestinationId());
            assertTrue(echo.errors().isEmpty(), echo.errors().toString());
        }
    }

    /** Datagrams that are not QUIC go to the filter, which answers them from the server's socket. */
    @Test
    void filterAnswersFromTheServersSocket() throws Exception {
        AtomicReference<QuicServer> server = new AtomicReference<>();
        QuicServer.DatagramFilter filter = (from, datagram) -> {
            byte[] b = new byte[datagram.remaining()];
            datagram.duplicate().get(b);
            if (!new String(b, StandardCharsets.US_ASCII).startsWith("ping")) return false;
            server.get().send(ByteBuffer.wrap("pong".getBytes(StandardCharsets.US_ASCII)), from);
            return true;
        };
        try (EchoServer echo = new EchoServer(LoopbackTest.serverConfig(LoopbackTest.fastTransport()),
                        EndpointConfig.defaults(), filter);
                DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            server.set(echo.server);
            socket.setSoTimeout(5000);
            InetSocketAddress to = echo.address();
            socket.send(new DatagramPacket("ping".getBytes(StandardCharsets.US_ASCII), 4, to));
            DatagramPacket reply = new DatagramPacket(new byte[64], 64);
            socket.receive(reply);
            assertEquals("pong", new String(reply.getData(), 0, reply.getLength(), StandardCharsets.US_ASCII));
            assertEquals(to.getPort(), reply.getPort());

            // A connection the filter leaves alone is the endpoint's, as without a filter.
            try (QuicClient client = QuicClient.create(LoopbackTest.clientConfig(LoopbackTest.fastTransport()))) {
                QuicConnection c = client.connect(to, "localhost", Duration.ofSeconds(10));
                byte[] data = LoopbackTest.data(8, 1000);
                assertArrayEquals(LoopbackTest.sha256().digest(data), LoopbackTest.echo(c, data));
                c.close(0, "done");
            }
            assertTrue(echo.errors().isEmpty(), echo.errors().toString());
        }
    }
}
