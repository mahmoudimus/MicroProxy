package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.congestion.Bbr;
import io.github.mahmoudimus.quic.congestion.BbrConfig;
import io.github.mahmoudimus.quic.congestion.ControllerFactory;
import io.github.mahmoudimus.quic.congestion.CubicConfig;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.LongSummaryStatistics;
import java.util.Random;
import java.util.SplittableRandom;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * BBR driving real connections on the in-memory pair, through a bottleneck link on a fake clock:
 * the bandwidth estimate on a smooth link and after a rate drop, throughput beside CUBIC under
 * random loss, and application-limited traffic. Every pair is {@linkplain Pair#seeded seeded}, so
 * every run repeats exactly.
 */
class BbrConnectionTest {

    private static final long MS = 1_000_000L;
    private static final long SECOND = 1_000 * MS;

    /** BBR with a fixed seed for its gain cycle. */
    private static ControllerFactory bbr(long seed) {
        return (now, mtu) -> new Bbr(BbrConfig.DEFAULT, now, mtu, new SplittableRandom(seed));
    }

    private static final ControllerFactory BBR = bbr(5);

    private static TransportConfig transport(ControllerFactory cc) {
        return TransportConfig.builder()
                .congestionControllerFactory(cc)
                .streamReceiveWindow(16 << 20)
                .receiveWindow(64 << 20)
                .sendWindow(64 << 20)
                .build();
    }

    /** A seeded pair, connected, with a link of some latency. */
    private static Connection[] connect(Pair pair, TransportConfig config, long latency) {
        pair.latency = latency;
        Connection client = pair.connect(pair.client(config));
        Connection server = pair.serverConnection();
        Pair.drainEvents(client);
        Pair.drainEvents(server);
        return new Connection[] {client, server};
    }

    /** The outcome of a transfer: simulated seconds taken, and losses. */
    record Run(double seconds, long bytes, long lost, long queueDrops, Pair pair, Connection sender) {
        double throughput() {
            return bytes / seconds;
        }

        Bbr bbr() {
            return assertInstanceOf(Bbr.class, sender.recovery().congestion());
        }

        @Override
        public String toString() {
            return String.format("%.2f MB/s (%.2f s, %d lost, %d queue drops)", throughput() / 1e6, seconds, lost,
                    queueDrops);
        }
    }

    private static Run transfer(Pair pair, Connection from, Connection to, byte[] data) throws Exception {
        return transfer(pair, from, to, data, p -> {});
    }

    /**
     * Sends data client to server on a new stream, driving until the server has read it all; calls
     * {@code step} after every step of the pair.
     */
    private static Run transfer(Pair pair, Connection from, Connection to, byte[] data, Consumer<Pair> step)
            throws Exception {
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
            step.accept(pair);
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

    /** A bulk transfer on a seeded pair over a link of some rate, one-way latency, queue and random loss. */
    private static Run bulk(long seed, ControllerFactory cc, long rate, long latency, long queueLimit, double loss,
            int bytes) throws Exception {
        TransportConfig config = transport(cc);
        Pair pair = Pair.seeded(seed, config);
        Connection[] c = connect(pair, config, latency);
        pair.bandwidth = rate;
        pair.queueLimit = queueLimit;
        pair.lossRate = loss;
        return transfer(pair, c[0], c[1], data(bytes));
    }

    @Test
    void seededPairsRepeatExactly() throws Exception {
        Run a = bulk(7, BBR, 2_500_000, 20 * MS, 200_000, 0.01, 2_000_000);
        Run b = bulk(7, BBR, 2_500_000, 20 * MS, 200_000, 0.01, 2_000_000);
        assertEquals(a.pair().time, b.pair().time, "the same run takes the same simulated time");
        assertEquals(a.lost(), b.lost());
        assertEquals(a.sender().recovery().sentPackets(), b.sender().recovery().sentPackets());
        assertEquals(a.bbr().bandwidthEstimate(), b.bbr().bandwidthEstimate());
        Run other = bulk(8, BBR, 2_500_000, 20 * MS, 200_000, 0.01, 2_000_000);
        assertTrue(other.pair().time != a.pair().time || other.lost() != a.lost(), "another seed, another run");
    }

    /**
     * The delivery rate sampler measures the link on a perfectly smooth path, where acknowledgements
     * cover two packets each: for twenty seeds of the pair and of the gain cycle the estimate comes
     * to the link rate (the datagrams the link carries, headers included).
     */
    @Test
    void bandwidthEstimateConvergesOnASmoothLinkForEverySeed() throws Exception {
        long rate = 2_500_000; // 20 Mbit/s
        long latency = 20 * MS; // 40 ms RTT, a BDP of 100 kB
        LongSummaryStatistics estimates = new LongSummaryStatistics();
        LongSummaryStatistics throughputs = new LongSummaryStatistics();
        LongSummaryStatistics drops = new LongSummaryStatistics();
        for (long seed = 1; seed <= 20; seed++) {
            Run run = bulk(seed, bbr(seed), rate, latency, 200_000, 0, 4_000_000);
            Bbr bbr = run.bbr();
            long bw = bbr.bandwidthEstimate();
            estimates.accept(bw);
            throughputs.accept((long) run.throughput());
            assertTrue(Math.abs(bw - rate) <= rate / 50, "seed " + seed + ": estimate " + bw + ", " + run);
            assertEquals(bw * 8, bbr.metrics().bandwidthEstimate());
            assertTrue(bbr.isAtFullBandwidth());
            assertTrue(bbr.minRtt() >= 2 * latency && bbr.minRtt() < 2 * latency + 5 * MS, "min RTT " + bbr.minRtt());
            assertTrue(run.throughput() > 0.85 * rate, "seed " + seed + ": " + run);
            drops.accept(run.queueDrops());
        }
        // STARTUP overfills the 200 kB queue (twice the BDP) before it finds the bandwidth
        System.out.printf("BBR on 20 Mbit/s, 40 ms, 20 seeds: estimate %.4f to %.4f MB/s, 4 MB transfers at %.3f to "
                + "%.3f MB/s, %d to %d queue drops%n", estimates.getMin() / 1e6, estimates.getMax() / 1e6,
                throughputs.getMin() / 1e6, throughputs.getMax() / 1e6, drops.getMin(), drops.getMax());
    }

    /**
     * The bottleneck drops from 50 to 10 Mbit/s in the middle of a transfer: the estimate and the
     * pacing rate come down to the new rate once the old maximum leaves the ten-round filter.
     */
    @Test
    void bandwidthEstimateFollowsARateDrop() throws Exception {
        TransportConfig config = transport(BBR);
        Pair pair = Pair.seeded(3, config);
        Connection[] c = connect(pair, config, 20 * MS);
        pair.bandwidth = 6_250_000;
        pair.queueLimit = 500_000;
        Bbr bbr = assertInstanceOf(Bbr.class, c[0].recovery().congestion());
        long dropAt = pair.time + 2 * SECOND;
        long[] drop = {-1, -1, -1}; // round at the drop, rounds and time to follow it
        long[] before = {0};
        Run run = transfer(pair, c[0], c[1], data(20_000_000), p -> {
            if (drop[0] < 0 && p.time >= dropAt) {
                before[0] = bbr.bandwidthEstimate();
                p.bandwidth = 1_250_000;
                drop[0] = bbr.roundCount();
            } else if (drop[0] >= 0 && drop[1] < 0 && bbr.bandwidthEstimate() <= 1_250_000 * 105 / 100
                    && bbr.pacingRate() <= 1_250_000 * 125 / 100) {
                drop[1] = bbr.roundCount() - drop[0];
                drop[2] = p.time - dropAt;
            }
        });
        System.out.printf("BBR, 50 then 10 Mbit/s at 2 s: estimate %.3f MB/s before, down after %d rounds (%d ms), "
                + "%.3f MB/s at the end; %s%n", before[0] / 1e6, drop[1], drop[2] / MS, bbr.bandwidthEstimate() / 1e6,
                run);
        assertTrue(Math.abs(before[0] - 6_250_000) <= 6_250_000 / 50, "estimate before " + before[0]);
        assertTrue(drop[1] > 0 && drop[1] <= 14, "followed after " + drop[1] + " rounds");
        long bw = bbr.bandwidthEstimate();
        assertTrue(Math.abs(bw - 1_250_000) <= 1_250_000 / 50, "estimate " + bw);
    }

    @Test
    void throughputBesideCubicUnderRandomLoss() throws Exception {
        long rate = 6_250_000; // 50 Mbit/s
        long latency = 20 * MS; // 40 ms RTT, a BDP of 250 kB
        long queue = 500_000;
        int bytes = 10_000_000;
        Run cubic = bulk(11, CubicConfig.DEFAULT, rate, latency, queue, 0.01, bytes);
        Run bbr = bulk(11, BBR, rate, latency, queue, 0.01, bytes);
        Run bbrClean = bulk(11, BBR, rate, latency, queue, 0, bytes);
        System.out.printf("50 Mbit/s, 40 ms, 1%% loss: CUBIC %s; BBR %s; BBR without loss %s%n", cubic, bbr, bbrClean);
        assertTrue(bbr.lost() > 0 && cubic.lost() > 0);
        // BBR does not take random loss for congestion: CUBIC collapses to a tenth of the link,
        // BBR keeps most of it
        assertTrue(bbr.throughput() >= 3 * cubic.throughput(), "BBR " + bbr + " vs CUBIC " + cubic);
        assertTrue(bbr.throughput() >= 0.6 * rate, "BBR " + bbr);
        assertTrue(bbr.throughput() >= 0.7 * bbrClean.throughput(), "BBR " + bbr + " vs lossless " + bbrClean);
    }

    /**
     * An interactive client writing a little at a time: its delivery rate samples are application
     * limited, so STARTUP does not end and the estimate is only a lower bound; a bulk transfer
     * afterwards finds the bandwidth.
     */
    @Test
    void appLimitedTrafficKeepsStartup() throws Exception {
        long rate = 2_500_000;
        TransportConfig config = transport(BBR);
        Pair pair = Pair.seeded(4, config);
        Connection[] c = connect(pair, config, 20 * MS);
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
        assertTrue(bbr.bandwidthEstimate() < rate / 4, "estimate " + bbr.bandwidthEstimate());
        assertTrue(bbr.window() <= 2 * BbrConfig.DEFAULT.initialWindow(), "window " + bbr.window());
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
        assertTrue(Math.abs(bw - rate) <= rate / 50, "estimate " + bw + " after " + run);
        assertTrue(bbr.isAtFullBandwidth());
    }

    @Test
    void transportConfigSelectsBbr() throws Exception {
        TransportConfig config = TransportConfig.builder().congestionControl(TransportConfig.CongestionControl.BBR).build();
        Pair pair = Pair.seeded(9, config);
        Connection[] c = connect(pair, config, 10 * MS);
        assertInstanceOf(Bbr.class, c[0].recovery().congestion());
        assertInstanceOf(Bbr.class, c[1].recovery().congestion());
        pair.lossRate = 0.02;
        Run run = transfer(pair, c[1], c[0], data(1_000_000));
        assertTrue(run.lost() > 0);
    }
}
