package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;
import static org.microproxy.TestSupport.eventually;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.H2StreamClient;
import org.microproxy.Http3Options;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.udp.UdpContext;
import org.microproxy.udp.UdpInterceptor;
import org.microproxy.udp.UdpMessage;

/**
 * A CONNECT-UDP flow whose queue toward the target is full drops the client's datagrams past its
 * bounds (datagrams and bytes) and counts them, keeping the first ones in order, while the other
 * direction and the connection go on.
 *
 * <p>Deterministic: the UDP hook holds the sender to the target on one datagram, so nothing drains
 * the queue while the client fills it. Which datagrams are kept and how many are dropped is then
 * decided by the queue's bounds alone, and the test waits on the flow's own count of drops ({@link
 * UdpFlow#dropped}, live, unlike the stat, which is added when the flow ends), not on time.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class UdpFlowToTargetDropsTest {

    /** The datagram the hook holds the sender to the target on. */
    private static final String HOLD = "hold";

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables) c.close();
        if (proxy != null) proxy.abort();
    }

    /** Four fit by count: of ten small datagrams the first four are kept, six dropped. */
    @Test
    void datagramsPastTheCountBoundTowardTheTargetAreDroppedAndCounted() throws Exception {
        List<byte[]> sent = new ArrayList<>();
        for (int i = 0; i < 10; i++) sent.add(utf8("q" + i));
        assertDrops(4, 65_527, sent, 4);
    }

    /**
     * Seven of 9361 bytes fill 65527 exactly, the byte bound: the seventh still fits, and past it
     * every datagram is dropped, three more of the same size and one of a single byte, though the
     * count bound (100) is far off.
     */
    @Test
    void datagramsPastTheByteBoundTowardTheTargetAreDroppedAndCounted() throws Exception {
        List<byte[]> sent = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            byte[] payload = new byte[9361];
            Arrays.fill(payload, (byte) ('a' + i));
            sent.add(payload);
        }
        sent.add(new byte[] {'z'});
        assertDrops(100, 65_527, sent, 7);
    }

    /**
     * Holds the sender to the target on one datagram, sends {@code sent}, and checks that the first
     * {@code kept} are queued and the rest dropped and counted; that while the sender is held the
     * target's datagrams still reach the client and the connection takes another flow; and that,
     * released, exactly the kept ones reach the target, in order.
     */
    private void assertDrops(int maxItems, long maxBytes, List<byte[]> sent, int kept) throws Exception {
        Target target = new Target();
        closeables.add(target);
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean held = new AtomicBoolean();
        AtomicReference<UdpFlow> flowRef = new AtomicReference<>();
        proxy = MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true).withConnectUdp(true).withMetrics(true)
                .withHttp3Options(Http3Options.builder().connectUdpQueue(maxItems, maxBytes).build())
                .withUdpInterceptor(new UdpInterceptor() {
                    @Override
                    public byte[] udpMessage(UdpMessage message, UdpContext context) {
                        // On the flow's sender to the target: holding it here leaves the queue
                        // toward the target to the client alone.
                        if (message.fromClient() && HOLD.equals(message.text()) && held.compareAndSet(false, true)) {
                            flowRef.set((UdpFlow) context);
                            holding.countDown();
                            await(release);
                        }
                        return message.data();
                    }
                })
                .start();
        StatsRegistry stats = proxy.getStats();
        try {
            H2StreamClient client = H2StreamClient.cleartext(proxy.getListenAddress(),
                    "localhost:" + proxy.getListenAddress().getPort());
            closeables.add(client);
            H2StreamClient.Stream stream = open(client, target);

            // One datagram through, so that the target knows the flow's address to answer.
            stream.sendDatagramCapsule(utf8("hello"));
            target.awaitCount(1);

            stream.sendDatagramCapsule(utf8(HOLD));
            assertTrue(holding.await(30, TimeUnit.SECONDS), "the sender to the target took the held datagram");
            UdpFlow flow = flowRef.get();
            assertEquals(0, flow.dropped(), "nothing dropped before the queue fills");

            // Nothing drains the queue now: the first `kept` fit, the rest are dropped.
            for (byte[] payload : sent) stream.sendDatagramCapsule(payload);
            long expectedDrops = sent.size() - kept;
            awaitUntil(() -> flow.dropped() >= expectedDrops,
                    () -> "the flow to drop " + expectedDrops + " (has " + flow.dropped() + ")");
            assertEquals(expectedDrops, flow.dropped());
            assertEquals(1, target.count(), "the target has had only what came before the hold");

            // The other direction goes on while this one is held, and so does the connection.
            target.answer(utf8("from the target"));
            assertEquals("from the target", text(stream.readDatagram()));
            H2StreamClient.Stream another = open(client, target);
            another.end();
            assertNull(another.readDatagram(), "the other flow ended");

            // Released, the sender sends what it held, then what was queued, in order.
            release.countDown();
            List<String> expected = new ArrayList<>(List.of(describe(utf8("hello")), describe(utf8(HOLD))));
            for (byte[] payload : sent.subList(0, kept)) expected.add(describe(payload));
            target.awaitCount(expected.size());

            stream.end();
            assertNull(stream.readDatagram(), "the flow ended");
            awaitValue(stats, "masque.udp_flows_active", 0);
            // Ended, the flow can send nothing more: what the target has is all it will have.
            assertEquals(expected, target.received());
            assertEquals(expectedDrops, flow.dropped());
            assertEquals(expectedDrops, value(stats, "masque.datagrams_dropped"), "counted when the flow ended");
            assertEquals(sent.size() + 2, value(stats, "masque.datagrams_rx"));
            assertEquals(2, value(stats, "masque.udp_flows_total"));

            // The connection is fine.
            H2StreamClient.Stream after = open(client, target);
            after.end();
            assertNull(after.readDatagram());
        } finally {
            release.countDown();
        }
    }

    private static H2StreamClient.Stream open(H2StreamClient client, Target target) throws IOException {
        H2StreamClient.Stream stream = client.open(
                client.connectUdp("/.well-known/masque/udp/127.0.0.1/" + target.port() + "/"), false);
        assertEquals(200, stream.status());
        return stream;
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String text(byte[] payload) {
        assertTrue(payload != null, "the stream ended");
        return new String(payload, StandardCharsets.UTF_8);
    }

    /** A payload, short enough to read in a failure: small ones as text, large ones as size and byte. */
    private static String describe(byte[] payload) {
        if (payload.length <= 16) return new String(payload, StandardCharsets.UTF_8);
        for (byte b : payload) {
            if (b != payload[0]) return payload.length + " mixed bytes";
        }
        return payload.length + " x '" + (char) payload[0] + "'";
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(60, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Waits for {@code condition}, an exact state the test brings about (not time passing), failing
     * after 10 s with {@code what} as it is then.
     */
    private static void awaitUntil(BooleanSupplier condition, Supplier<String> what) {
        try {
            eventually("", condition);
        } catch (AssertionError e) {
            throw new AssertionError("timed out waiting for " + what.get());
        }
    }

    /** A UDP target that records what it receives, and from where, and answers only when told to. */
    private static final class Target implements AutoCloseable {
        private final DatagramSocket socket;
        private final List<String> received = new CopyOnWriteArrayList<>();
        private volatile SocketAddress from;

        Target() throws SocketException {
            socket = new DatagramSocket(new InetSocketAddress(TestSupport.LOOPBACK, 0));
            // Room for everything a test sends at once, however late this thread reads.
            socket.setReceiveBufferSize(1 << 20);
            Thread.ofVirtual().start(() -> {
                byte[] buf = new byte[65535];
                while (!socket.isClosed()) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    try {
                        socket.receive(p);
                    } catch (IOException e) {
                        return;
                    }
                    from = p.getSocketAddress();
                    received.add(describe(Arrays.copyOf(p.getData(), p.getLength())));
                }
            });
        }

        int port() {
            return socket.getLocalPort();
        }

        int count() {
            return received.size();
        }

        List<String> received() {
            return List.copyOf(received);
        }

        void awaitCount(int n) {
            awaitUntil(() -> received.size() >= n, () -> "the target to receive " + n + " datagrams (has " + received + ")");
        }

        /** Sends {@code payload} to the flow that last sent here. */
        void answer(byte[] payload) throws IOException {
            socket.send(new DatagramPacket(payload, payload.length, from));
        }

        @Override
        public void close() {
            socket.close();
        }
    }
}
