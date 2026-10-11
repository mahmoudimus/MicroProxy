package org.microproxy.stats;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Pushes a registry's metrics to a statsd server over UDP, every flush interval (5 seconds by
 * default, as Envoy), from a virtual thread: counters as the increase since the last flush ({@code
 * |c}), gauges as their value ({@code |g}), by their flat names after the registry's {@linkplain
 * StatsRegistry#prefix() prefix} ({@code envoy.cluster.direct.upstream_rq_total:3|c}).
 *
 * <p>Histograms keep bucket counts rather than each value, so a histogram that recorded {@code n}
 * values since the last flush is sent as one timer, their mean, sampled at {@code 1/n} ({@code
 * envoy.http.ingress.downstream_rq_time:12.5|ms|@0.25}): statsd counts it {@code n} times, which
 * keeps the count and the mean (not the spread).
 *
 * <p>With {@link Builder#dogStatsd(boolean) DogStatsD} tags, names are the tag-extracted ones and
 * the tags follow ({@code envoy.cluster.upstream_rq_xx:3|c|#envoy_cluster_name:direct,
 * envoy_response_code_class:2}). Lines are packed into datagrams of at most {@link
 * Builder#maxPacketSize} bytes. Sending is best effort: a failed send is logged and the next flush
 * goes on.
 */
public final class StatsdSink implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(StatsdSink.class.getName());

    private final StatsRegistry registry;
    private final SocketAddress target;
    private final Duration interval;
    private final boolean dogStatsd;
    private final int maxPacketSize;
    private final String prefix;
    private final DatagramChannel channel;
    /** What each counter and histogram had at the last flush. Guarded by {@link #flushLock}. */
    private final Map<Metric, long[]> last = new HashMap<>();
    private final Map<Metric, double[]> lastSums = new HashMap<>();
    private final ReentrantLock flushLock = new ReentrantLock();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition stopped = lock.newCondition();
    private volatile boolean closed;
    private Thread flusher;

    private StatsdSink(Builder b) throws IOException {
        this.registry = b.registry;
        this.target = b.target;
        this.interval = b.interval;
        this.dogStatsd = b.dogStatsd;
        this.maxPacketSize = b.maxPacketSize;
        this.prefix = registry.prefix().isEmpty() ? "" : registry.prefix() + ".";
        this.channel = DatagramChannel.open();
    }

    /**
     * Starts a sink of {@code registry}'s metrics to the statsd server at {@code host:port}.
     *
     * @param registry the metrics
     * @param hostAndPort the server, such as {@code 127.0.0.1:8125}
     * @return a builder
     * @throws IllegalArgumentException if {@code hostAndPort} has no valid port
     */
    public static Builder builder(StatsRegistry registry, String hostAndPort) {
        return new Builder(registry, parse(hostAndPort));
    }

    /**
     * Starts a sink of {@code registry}'s metrics to the statsd server at {@code target}.
     *
     * @param registry the metrics
     * @param target the server's address
     * @return a builder
     */
    public static Builder builder(StatsRegistry registry, InetSocketAddress target) {
        return new Builder(registry, target);
    }

    /** {@code host:port}, or {@code [v6]:port}, as an address resolved when sending. */
    static InetSocketAddress parse(String hostAndPort) {
        String s = Objects.requireNonNull(hostAndPort, "hostAndPort").strip();
        int colon = s.lastIndexOf(':');
        if (colon <= 0 || colon == s.length() - 1) {
            throw new IllegalArgumentException("statsd needs host:port, not '" + hostAndPort + "'");
        }
        String host = s.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        int port;
        try {
            port = Integer.parseInt(s.substring(colon + 1));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("statsd needs host:port, not '" + hostAndPort + "'", e);
        }
        if (port <= 0 || port > 65535) throw new IllegalArgumentException("not a port: " + port);
        return new InetSocketAddress(host, port);
    }

    /**
     * Starts flushing every interval, on a virtual thread, until {@link #close()}.
     *
     * @return this sink
     * @throws IllegalStateException if it was started or closed before
     */
    public StatsdSink start() {
        lock.lock();
        try {
            if (closed || flusher != null) throw new IllegalStateException("started or closed already");
            flusher = Thread.ofVirtual().name("statsd-flush").start(this::run);
        } finally {
            lock.unlock();
        }
        return this;
    }

    private void run() {
        while (true) {
            lock.lock();
            try {
                if (!closed) stopped.await(interval.toNanos(), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                return;
            } finally {
                lock.unlock();
            }
            if (closed) break;
            flush();
        }
        // The last flush starts after close() was called, so it sends everything counted before.
        flush();
    }

    /**
     * Sends what changed since the last flush now.
     *
     * @return how many datagrams were sent
     */
    public int flush() {
        flushLock.lock();
        try {
            return flushLocked();
        } finally {
            flushLock.unlock();
        }
    }

    private int flushLocked() {
        StringBuilder packet = new StringBuilder(maxPacketSize);
        int sent = 0;
        for (Metric m : registry.metrics()) {
            String line = line(m);
            if (line == null) continue;
            if (packet.length() > 0 && packet.length() + 1 + line.length() > maxPacketSize) {
                sent += send(packet);
                packet.setLength(0);
            }
            if (packet.length() > 0) packet.append('\n');
            packet.append(line);
        }
        if (packet.length() > 0) sent += send(packet);
        return sent;
    }

    /** The statsd line for {@code m}, or null when it has nothing new to say. */
    private String line(Metric m) {
        switch (m) {
            case Counter c -> {
                long now = c.value();
                long[] before = last.computeIfAbsent(m, k -> new long[1]);
                long delta = now - before[0];
                before[0] = now;
                return delta <= 0 ? null : format(m, Long.toString(delta), "c", null);
            }
            case Gauge g -> {
                return format(m, Long.toString(g.value()), "g", null);
            }
            case Histogram h -> {
                Histogram.Snapshot s = h.snapshot();
                long[] beforeCount = last.computeIfAbsent(m, k -> new long[1]);
                double[] beforeSum = lastSums.computeIfAbsent(m, k -> new double[1]);
                long n = s.count() - beforeCount[0];
                double sum = s.sum() - beforeSum[0];
                beforeCount[0] = s.count();
                beforeSum[0] = s.sum();
                if (n <= 0) return null;
                String rate = n == 1 ? null : "@" + StatsFormatter.number(1.0 / n);
                return format(m, StatsFormatter.number(Math.max(0, sum / n)), "ms", rate);
            }
            default -> {
                return null;
            }
        }
    }

    private String format(Metric m, String value, String type, String rate) {
        StringBuilder sb = new StringBuilder(96).append(prefix).append(dogStatsd ? m.tagExtractedName() : m.name())
                .append(':').append(value).append('|').append(type);
        if (rate != null) sb.append('|').append(rate);
        if (dogStatsd && !m.tags().isEmpty()) {
            sb.append("|#");
            for (int i = 0; i < m.tags().size(); i++) {
                Tag t = m.tags().get(i);
                if (i > 0) sb.append(',');
                sb.append(t.name()).append(':').append(t.value().replace(',', '_').replace('|', '_'));
            }
        }
        return sb.toString();
    }

    private int send(CharSequence packet) {
        try {
            SocketAddress to = target instanceof InetSocketAddress a && a.isUnresolved()
                    ? new InetSocketAddress(a.getHostString(), a.getPort()) : target;
            channel.send(ByteBuffer.wrap(packet.toString().getBytes(StandardCharsets.UTF_8)), to);
            return 1;
        } catch (IOException | RuntimeException e) {
            LOG.log(System.Logger.Level.DEBUG, "statsd send to " + target + " failed: " + e);
            return 0;
        }
    }

    /** Stops flushing, after a last flush, and closes the socket. */
    @Override
    public void close() {
        Thread t;
        lock.lock();
        try {
            if (closed) return;
            closed = true;
            stopped.signalAll();
            t = flusher;
        } finally {
            lock.unlock();
        }
        if (t != null) {
            try {
                t.join(TimeUnit.SECONDS.toMillis(5));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        } else {
            flush();
        }
        try {
            channel.close();
        } catch (IOException e) {
            LOG.log(System.Logger.Level.DEBUG, "closing the statsd socket failed: " + e);
        }
    }

    @Override
    public String toString() {
        return "StatsdSink[" + target + (dogStatsd ? ", DogStatsD" : "") + ", every " + interval + "]";
    }

    /** Settings for a {@link StatsdSink}. */
    public static final class Builder {
        private final StatsRegistry registry;
        private final SocketAddress target;
        private Duration interval = Duration.ofSeconds(5);
        private boolean dogStatsd;
        private int maxPacketSize = 1432;

        private Builder(StatsRegistry registry, SocketAddress target) {
            this.registry = Objects.requireNonNull(registry, "registry");
            this.target = Objects.requireNonNull(target, "target");
        }

        /**
         * How often to send (default 5 seconds).
         *
         * @param interval the flush interval, positive
         * @return this builder
         * @throws IllegalArgumentException if it is not positive
         */
        public Builder interval(Duration interval) {
            if (!interval.isPositive()) throw new IllegalArgumentException("the flush interval must be positive");
            this.interval = interval;
            return this;
        }

        /**
         * Whether to send DogStatsD tags ({@code |#name:value,...}) with the tag-extracted names
         * (default false: plain statsd, flat names).
         *
         * @param dogStatsd whether to send tags
         * @return this builder
         */
        public Builder dogStatsd(boolean dogStatsd) {
            this.dogStatsd = dogStatsd;
            return this;
        }

        /**
         * The largest datagram to send (default 1432 bytes, which fits an Ethernet frame).
         *
         * @param bytes the most bytes per datagram, from 64 to 65507
         * @return this builder
         * @throws IllegalArgumentException if it is out of range
         */
        public Builder maxPacketSize(int bytes) {
            if (bytes < 64 || bytes > 65507) throw new IllegalArgumentException("packet size out of [64, 65507]: " + bytes);
            this.maxPacketSize = bytes;
            return this;
        }

        /**
         * Opens the socket. Call {@link StatsdSink#start()} to flush every interval.
         *
         * @return the sink
         * @throws IOException if the UDP socket cannot be opened
         */
        public StatsdSink build() throws IOException {
            return new StatsdSink(this);
        }
    }
}
