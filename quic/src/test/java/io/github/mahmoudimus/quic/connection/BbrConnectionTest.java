package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.congestion.Bbr;
import io.github.mahmoudimus.quic.congestion.BbrConfig;
import io.github.mahmoudimus.quic.congestion.ControllerFactory;
import io.github.mahmoudimus.quic.congestion.CubicConfig;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

/**
 * BBR driving real connections on the in-memory pair, through a bottleneck link on a fake clock:
 * the bandwidth estimate, throughput beside CUBIC under random loss, and application-limited
 * traffic. Every run is deterministic.
 */
class BbrConnectionTest {

    private static final long MS = 1_000_000L;
    private static final long SECOND = 1_000 * MS;

    /** BBR with a fixed seed for its gain cycle. */
    private static final ControllerFactory BBR = (now, mtu) -> new Bbr(BbrConfig.DEFAULT, mtu, new SplittableRandom(5));

    private static TransportConfig transport(ControllerFactory cc) {
        return TransportConfig.builder()
                .congestionControllerFactory(cc)
                .streamReceiveWindow(16 << 20)
                .receiveWindow(64 << 20)
                .sendWindow(64 << 20)
                .build();
    }

    private static Connection[] connect(Pair pair, TransportConfig config) {
        Connection client = pair.connect(Pair.clientConfig(config));
        Connection server = pair.serverConnection();
        Pair.drainEvents(client);
        Pair.drainEvents(server);
        return new Connection[] {client, server};
    }

    private static Pair pair(TransportConfig config) {
        return new Pair(EndpointConfig.defaults(), Pair.serverConfig(config), EndpointConfig.defaults());
    }

    /** The outcome of a transfer: simulated seconds taken, and losses. */
    record Run(double seconds, long bytes, long lost, long queueDrops, Pair pair, Connection sender) {
        double throughput() {
            return bytes / seconds;
        }

        @Override
        public String toString() {
            return String.format("%.2f MB/s (%.2f s, %d lost, %d queue drops)", throughput() / 1e6, seconds, lost,
                    queueDrops);
        }
    }

    /** Sends data client to server on a new stream, driving until the server has read it all. */
    private static Run transfer(Pair pair, Connection from, Connection to, byte[] data) throws Exception {
        long start = pair.time;
        long lostBefore = from.recovery().lostPackets();
        StreamId s = from.openStream(Dir.UNI);
        ByteBuffer src = ByteBuffer.wrap(data);
        MessageDigest received = MessageDigest.getInstance("SHA-256");
        long total = 0;
        boolean finished = false;
        StreamId accepted = null;
        ByteBuffer buf = ByteBuffer.allocate(256 * 1024);
        for (int i = 0; i < 10_000_000; i++) {
            while (src.hasRemaining()) {
                try {
                    from.write(s, src);
                } catch (StreamException e) {
                    assertEquals(StreamException.Kind.BLOCKED, e.kind());
                    break;
                }
            }
            if (!src.hasRemaining() && !finished) {
                from.finish(s);
                finished = true;
            }
            if (!pair.step() && src.hasRemaining()) {
                throw new AssertionError("stalled");
            }
            if (accepted == null) {
                accepted = to.acceptStream(Dir.UNI);
            }
            if (accepted != null) {
                while (true) {
                    buf.clear();
                    int n;
                    try {
                        n = to.read(accepted, buf);
                    } catch (StreamException e) {
                        assertEquals(StreamException.Kind.BLOCKED, e.kind());
                        break;
                    }
                    if (n < 0) {
                        assertEquals(data.length, total);
                        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(data), received.digest());
                        return new Run((pair.time - start) / 1e9, total, from.recovery().lostPackets() - lostBefore,
                                pair.queueDrops, pair, from);
                    }
                    received.update(buf.array(), 0, n);
                    total += n;
                }
            }
        }
        throw new AssertionError("transfer did not finish");
    }

    private static byte[] data(int length) {
        byte[] b = new byte[length];
        new Random(length).nextBytes(b);
        return b;
    }

    /** A bulk transfer over a link of some rate, one-way latency, queue and random loss. */
    private static Run bulk(ControllerFactory cc, long rate, long latency, long queueLimit, double loss, int bytes)
            throws Exception {
        Pair pair = pair(transport(cc));
        pair.latency = latency;
        Connection[] c = connect(pair, transport(cc));
        pair.bandwidth = rate;
        pair.queueLimit = queueLimit;
        pair.lossRate = loss;
        return transfer(pair, c[0], c[1], data(bytes));
    }

    @Test
    void bandwidthEstimateConvergesOnABottleneck() throws Exception {
        long rate = 2_500_000; // 20 Mbit/s
        long latency = 20 * MS; // 40 ms RTT, a BDP of 100 kB
        Run run = bulk(BBR, rate, latency, 200_000, 0, 8_000_000);
        Bbr bbr = assertInstanceOf(Bbr.class, run.sender().recovery().congestion());
        long bw = bbr.bandwidthEstimate();
        System.out.printf("BBR on 20 Mbit/s, 40 ms: estimate %.3f MB/s, %s, max queue delay %d ms, mode %s%n", bw / 1e6,
                run, run.pair().maxQueueDelay / MS, bbr.mode());
        // The estimate counts whole datagrams, as the link does, and never overshoots it. quinn's
        // estimator samples one packet per acknowledgement, so where the peer acknowledges every
        // second packet a sample is half the rate; only acknowledgements of a single packet
        // (after a gap, a skipped packet number) show the full rate, and since the estimate only
        // rises it can stay at half the rate on so smooth a link (in about one run in ten).
        assertTrue(bw <= rate + rate / 20, "estimate " + bw + " for a " + rate + " B/s link");
        assertTrue(bw >= rate * 45 / 100, "estimate " + bw + " for a " + rate + " B/s link");
        assertEquals(bw * 8, bbr.metrics().bandwidthEstimate());
        assertTrue(bbr.isAtFullBandwidth());
        assertTrue(bbr.minRtt() >= 2 * latency && bbr.minRtt() < 2 * latency + 5 * MS, "min RTT " + bbr.minRtt());
        // The transfer kept up with the estimate, and the queue never filled
        assertTrue(run.throughput() > 0.8 * bw, "throughput " + run);
        assertEquals(0, run.queueDrops(), "queue drops");
    }

    @Test
    void throughputBesideCubicUnderRandomLoss() throws Exception {
        long rate = 6_250_000; // 50 Mbit/s
        long latency = 20 * MS; // 40 ms RTT, a BDP of 250 kB
        long queue = 500_000;
        int bytes = 10_000_000;
        Run cubic = bulk(CubicConfig.DEFAULT, rate, latency, queue, 0.01, bytes);
        Run bbr = bulk(BBR, rate, latency, queue, 0.01, bytes);
        Run bbrClean = bulk(BBR, rate, latency, queue, 0, bytes);
        System.out.printf("50 Mbit/s, 40 ms, 1%% loss: CUBIC %s; BBR %s; BBR without loss %s%n", cubic, bbr, bbrClean);
        assertInstanceOf(Bbr.class, bbr.sender().recovery().congestion());
        assertTrue(bbr.lost() > 0 && cubic.lost() > 0);
        // BBR does not take random loss for congestion: CUBIC collapses to a tenth of the link,
        // BBR keeps most of it
        assertTrue(bbr.throughput() >= 3 * cubic.throughput(), "BBR " + bbr + " vs CUBIC " + cubic);
        assertTrue(bbr.throughput() >= 0.4 * rate, "BBR " + bbr);
        assertTrue(bbr.throughput() >= 0.5 * bbrClean.throughput(), "BBR " + bbr + " vs lossless " + bbrClean);
    }

    /**
     * An interactive client writing a little at a time: its acknowledgements are application
     * limited, so STARTUP neither ends nor probes RTT and the estimate takes no samples; a bulk
     * transfer afterwards finds the bandwidth.
     */
    @Test
    void appLimitedTrafficKeepsStartup() throws Exception {
        long rate = 2_500_000;
        Pair pair = pair(transport(BBR));
        pair.latency = 20 * MS;
        Connection[] c = connect(pair, transport(BBR));
        pair.bandwidth = rate;
        Bbr bbr = assertInstanceOf(Bbr.class, c[0].recovery().congestion());
        StreamId s = c[0].openStream(Dir.UNI);
        List<Bbr.Mode> modes = new ArrayList<>();
        long end = pair.time + 5 * SECOND;
        while (pair.time < end) {
            c[0].write(s, ByteBuffer.wrap(new byte[2_000]));
            long wake = pair.time + 50 * MS;
            while (pair.time < wake) {
                pair.driveClient();
                pair.driveServer();
                long next = Math.min(Math.min(pair.client.nextWakeup(), pair.server.nextWakeup()), wake);
                pair.time = Math.max(pair.time + 1, next);
            }
            if (modes.isEmpty() || modes.get(modes.size() - 1) != bbr.mode()) {
                modes.add(bbr.mode());
            }
        }
        System.out.printf("BBR, 2 kB every 50 ms: modes %s, estimate %d, window %d%n", modes,
                bbr.bandwidthEstimate(), bbr.window());
        assertEquals(List.of(Bbr.Mode.STARTUP), modes);
        assertEquals(0, bbr.bandwidthEstimate(), "no samples from application-limited acknowledgements");
        // Finish the interactive stream and let the server read it
        c[0].finish(s);
        pair.drive();
        StreamId interactive = c[1].acceptStream(Dir.UNI);
        ByteBuffer buf = ByteBuffer.allocate(1 << 20);
        long read = 0;
        for (int n; (n = c[1].read(interactive, buf.clear())) >= 0; ) {
            read += n;
        }
        assertEquals(100 * 2_000, read);

        Run run = transfer(pair, c[0], c[1], data(6_000_000));
        long bw = bbr.bandwidthEstimate();
        assertTrue(bw >= rate * 45 / 100 && bw <= rate + rate / 20, "estimate " + bw + " after " + run);
        assertTrue(bbr.isAtFullBandwidth());
    }

    @Test
    void transportConfigSelectsBbr() throws Exception {
        TransportConfig config = TransportConfig.builder().congestionControl(TransportConfig.CongestionControl.BBR).build();
        Pair pair = pair(config);
        Connection[] c = connect(pair, config);
        assertInstanceOf(Bbr.class, c[0].recovery().congestion());
        assertInstanceOf(Bbr.class, c[1].recovery().congestion());
        pair.lossRate = 0.02;
        pair.latency = 10 * MS;
        Run run = transfer(pair, c[1], c[0], data(1_000_000));
        assertTrue(run.lost() > 0);
    }
}
