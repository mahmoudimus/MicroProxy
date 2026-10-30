package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.ServerConfig;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Connection migration over real UDP sockets on loopback: a Java client moves to a new local port
 * in the middle of an echo, a NAT between client and server rebinds to a new port, a client moves
 * to the server's preferred address, and a server that disables migration refuses it. Every
 * transfer is checked with SHA-256.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class MigrationLoopbackTest {

    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    private EchoServer echo;
    private QuicClient client;
    private Nat nat;

    @AfterEach
    void stop() {
        if (client != null) {
            client.close();
        }
        if (nat != null) {
            nat.close();
        }
        if (echo != null) {
            echo.close();
            assertTrue(echo.errors().isEmpty(), "server errors: " + echo.errors());
        }
    }

    private void start(ServerConfig serverConfig) throws IOException {
        echo = new EchoServer(serverConfig);
        client = QuicClient.create(LoopbackTest.clientConfig(LoopbackTest.fastTransport()));
    }

    /** Echoes {@code data} on a new stream in the background; the future holds the SHA-256 of the echo. */
    private static CompletableFuture<byte[]> echoLater(QuicConnection c, byte[] data) {
        CompletableFuture<byte[]> f = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try {
                f.complete(LoopbackTest.echo(c, data));
            } catch (Throwable t) {
                f.completeExceptionally(t);
            }
        });
        return f;
    }

    @Test
    void clientMigratesToANewPortMidStream() throws Exception {
        start(LoopbackTest.serverConfig(LoopbackTest.fastTransport()));
        QuicConnection c = client.connect(echo.address(), "localhost", Duration.ofSeconds(10));
        QuicConnection served = echo.accepted.poll(10, TimeUnit.SECONDS);
        InetSocketAddress before = c.localAddress();
        assertEquals(before.getPort(), served.remoteAddress().getPort());
        byte[] data = LoopbackTest.data(1, 24 << 20);
        CompletableFuture<byte[]> echoed = echoLater(c, data);
        LoopbackTest.pollUntil(() -> c.stats().sentPackets() > 2000, Duration.ofSeconds(30));
        assertFalse(echoed.isDone(), "still transferring");

        InetSocketAddress after = c.migrate(new InetSocketAddress(LOOPBACK, 0));
        assertNotEquals(before.getPort(), after.getPort());
        assertEquals(after, c.localAddress());
        assertArrayEquals(LoopbackTest.sha256().digest(data), echoed.get(60, TimeUnit.SECONDS));
        LoopbackTest.pollUntil(() -> served.remoteAddress().getPort() == after.getPort(), Duration.ofSeconds(10));
        assertEquals(after.getPort(), client.localAddress().getPort(),
                "the client's first socket gave way to the new one");

        // And again, then a new connection from the client's new socket
        InetSocketAddress third = c.migrate(new InetSocketAddress(LOOPBACK, 0));
        byte[] more = LoopbackTest.data(2, 1 << 20);
        assertArrayEquals(LoopbackTest.sha256().digest(more), LoopbackTest.echo(c, more));
        assertEquals(third.getPort(), served.remoteAddress().getPort());
        try (QuicConnection other = client.connect(echo.address(), "localhost", Duration.ofSeconds(10))) {
            assertArrayEquals(LoopbackTest.sha256().digest(more), LoopbackTest.echo(other, more));
        }
        c.close();
    }

    @Test
    void clientRebindsMidStreamWithoutProbing() throws Exception {
        start(LoopbackTest.serverConfig(LoopbackTest.fastTransport()));
        QuicConnection c = client.connect(echo.address(), "localhost", Duration.ofSeconds(10));
        QuicConnection served = echo.accepted.poll(10, TimeUnit.SECONDS);
        byte[] data = LoopbackTest.data(7, 16 << 20);
        CompletableFuture<byte[]> echoed = echoLater(c, data);
        LoopbackTest.pollUntil(() -> c.stats().sentPackets() > 2000, Duration.ofSeconds(30));
        InetSocketAddress after = c.rebind(new InetSocketAddress(LOOPBACK, 0));
        assertEquals(after, c.localAddress());
        assertArrayEquals(LoopbackTest.sha256().digest(data), echoed.get(60, TimeUnit.SECONDS));
        LoopbackTest.pollUntil(() -> served.remoteAddress().getPort() == after.getPort(), Duration.ofSeconds(10));
        c.close();
    }

    @Test
    void clientMigratesOntoASocketOfItsOwn() throws Exception {
        start(LoopbackTest.serverConfig(LoopbackTest.fastTransport()));
        QuicConnection c = client.connect(echo.address(), "localhost", Duration.ofSeconds(10));
        DatagramChannel channel = DatagramChannel.open();
        channel.bind(new InetSocketAddress(LOOPBACK, 0));
        InetSocketAddress bound = (InetSocketAddress) channel.getLocalAddress();
        assertEquals(bound, c.migrate(channel));
        byte[] data = LoopbackTest.data(3, 2 << 20);
        assertArrayEquals(LoopbackTest.sha256().digest(data), LoopbackTest.echo(c, data));
        c.close();
        client.close();
        assertFalse(channel.isOpen(), "the client closed the socket it took over");
    }

    @Test
    void migrationRefusedWhenTheServerDisablesIt() throws Exception {
        start(LoopbackTest.serverConfig(LoopbackTest.fastTransport()).toBuilder().migration(false).build());
        QuicConnection c = client.connect(echo.address(), "localhost", Duration.ofSeconds(10));
        InetSocketAddress before = c.localAddress();
        IOException e = assertThrows(IOException.class, () -> c.migrate(new InetSocketAddress(LOOPBACK, 0)));
        assertTrue(e.getMessage().contains("disabled"), e.getMessage());
        assertEquals(before, c.localAddress());
        byte[] data = LoopbackTest.data(4, 1 << 20);
        assertArrayEquals(LoopbackTest.sha256().digest(data), LoopbackTest.echo(c, data));
        c.close();
    }

    @Test
    void clientMovesToThePreferredAddress() throws Exception {
        start(LoopbackTest.serverConfig(LoopbackTest.fastTransport()).toBuilder()
                .preferredAddress(new InetSocketAddress(LOOPBACK, 0), null).build());
        QuicConnection c = client.connect(echo.address(), "localhost", Duration.ofSeconds(10));
        QuicConnection served = echo.accepted.poll(10, TimeUnit.SECONDS);
        LoopbackTest.pollUntil(() -> c.remoteAddress().getPort() != echo.address().getPort(), Duration.ofSeconds(10));
        int preferred = c.remoteAddress().getPort();
        byte[] data = LoopbackTest.data(5, 4 << 20);
        assertArrayEquals(LoopbackTest.sha256().digest(data), LoopbackTest.echo(c, data));
        assertEquals(preferred, c.remoteAddress().getPort());
        assertEquals(preferred, served.localAddress().getPort(), "the server answers from its preferred address");
        c.close();
    }

    /** A NAT between client and server maps the client to a new port in the middle of an echo. */
    @Test
    void natRebindingMidStream() throws Exception {
        start(LoopbackTest.serverConfig(LoopbackTest.fastTransport()));
        nat = new Nat(echo.address());
        QuicConnection c = client.connect(nat.address(), "localhost", Duration.ofSeconds(10));
        QuicConnection served = echo.accepted.poll(10, TimeUnit.SECONDS);
        int first = nat.outsidePort();
        assertEquals(first, served.remoteAddress().getPort());
        byte[] data = LoopbackTest.data(6, 16 << 20);
        int datagramsBeforeRebind = 128;
        // Even maximum-sized UDP datagrams cannot carry the whole upload before this point.
        // Rebind in the relay thread: polling sentPackets can wake after the echo has finished.
        assertTrue((long) datagramsBeforeRebind * 65536 < data.length);
        CompletableFuture<Integer> rebound = nat.rebindAfterDatagrams(datagramsBeforeRebind);
        CompletableFuture<byte[]> echoed = echoLater(c, data);
        int after = rebound.get(30, TimeUnit.SECONDS);
        assertNotEquals(first, after);
        assertNotEquals(first, nat.outsidePort());
        assertArrayEquals(LoopbackTest.sha256().digest(data), echoed.get(60, TimeUnit.SECONDS));
        LoopbackTest.pollUntil(() -> served.remoteAddress().getPort() == after, Duration.ofSeconds(10));
        assertEquals(nat.outsidePort(), served.remoteAddress().getPort(), "the server followed the NAT");
        c.close();
    }

    /**
     * A one-client UDP NAT on loopback: what the client sends to {@link #address()} leaves for the
     * server from an outside socket, and what the server sends to that socket goes back to the
     * client. {@link #rebind()} swaps the outside socket for a new one, as a NAT whose mapping
     * expired would, and drops what still arrives at the old one.
     */
    static final class Nat implements AutoCloseable {
        private final DatagramChannel inside;
        private final InetSocketAddress server;
        private volatile DatagramChannel outside;
        private volatile InetSocketAddress client;
        private final AtomicLong rebindCountdown = new AtomicLong(-1);
        private final CompletableFuture<Integer> rebound = new CompletableFuture<>();
        final AtomicLong droppedOld = new AtomicLong();

        Nat(InetSocketAddress server) throws IOException {
            this.server = server;
            this.inside = DatagramChannel.open().bind(new InetSocketAddress(LOOPBACK, 0));
            this.outside = openOutside();
            Thread.ofVirtual().name("nat-in").start(this::fromClient);
        }

        private DatagramChannel openOutside() throws IOException {
            DatagramChannel ch = DatagramChannel.open().bind(new InetSocketAddress(LOOPBACK, 0));
            Thread.ofVirtual().name("nat-out").start(() -> fromServer(ch));
            return ch;
        }

        InetSocketAddress address() throws IOException {
            return (InetSocketAddress) inside.getLocalAddress();
        }

        int outsidePort() throws IOException {
            return ((InetSocketAddress) outside.getLocalAddress()).getPort();
        }

        void rebind() throws IOException {
            DatagramChannel old = outside;
            outside = openOutside();
            old.close();
        }

        CompletableFuture<Integer> rebindAfterDatagrams(int count) {
            if (count <= 0) throw new IllegalArgumentException("positive datagram count required");
            if (!rebindCountdown.compareAndSet(-1, count)) throw new IllegalStateException("rebind already armed");
            return rebound;
        }

        private void fromClient() {
            ByteBuffer buf = ByteBuffer.allocate(65536);
            try {
                while (true) {
                    buf.clear();
                    client = (InetSocketAddress) inside.receive(buf);
                    buf.flip();
                    if (rebindCountdown.get() > 0 && rebindCountdown.decrementAndGet() == 0) {
                        rebind();
                        rebound.complete(outsidePort());
                    }
                    try {
                        outside.send(buf, server);
                    } catch (ClosedChannelException e) {
                        // swapped meanwhile: the datagram is lost, as in a NAT that rebinds
                    }
                }
            } catch (IOException e) {
                rebound.completeExceptionally(e);
                // closed
            }
        }

        private void fromServer(DatagramChannel ch) {
            ByteBuffer buf = ByteBuffer.allocate(65536);
            try {
                while (true) {
                    buf.clear();
                    ch.receive(buf);
                    buf.flip();
                    if (ch != outside) {
                        droppedOld.incrementAndGet();
                        continue;
                    }
                    InetSocketAddress to = client;
                    if (to != null) {
                        inside.send(buf, to);
                    }
                }
            } catch (IOException e) {
                // closed
            }
        }

        @Override
        public void close() {
            try {
                inside.close();
                outside.close();
            } catch (IOException e) {
                // closing anyway
            }
        }
    }
}
