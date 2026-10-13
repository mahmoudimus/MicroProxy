package org.microproxy.bench;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.BenchmarkParams;
import org.openjdk.jmh.infra.ThreadParams;

/**
 * Scenario 3: many concurrent keep-alive connections, each with a request in flight, driven by a
 * fixed set of client threads: thousands of connections, which is where one virtual thread per
 * connection and Netty's event loops differ, without thousands of client threads (JMH's {@code
 * @Threads} does not scale that far, and the client would measure itself).
 *
 * <p>{@code connections} are split evenly between the benchmark threads ({@link Threads}, 4 by
 * default; {@code -t} changes it, and must divide {@code connections}). Each thread keeps a
 * request outstanding on every one of its connections and serves them round-robin: one operation
 * reads (and checks) the oldest connection's response and sends its next request. So the score is
 * requests per second through the proxy at a concurrency of exactly {@code connections}. One
 * connection is {@link SmallGetBenchmark}'s throughput.
 */
@Fork(value = BenchConfig.FORKS, jvmArgsAppend = {BenchConfig.HEAP_MIN, BenchConfig.HEAP_MAX})
@Warmup(iterations = BenchConfig.WARMUP_ITERATIONS, time = BenchConfig.WARMUP_SECONDS)
@Measurement(iterations = BenchConfig.MEASUREMENT_ITERATIONS, time = BenchConfig.MEASUREMENT_SECONDS)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Threads(4)
public class ConcurrencyBenchmark {

    /** A plain forwarding proxy. */
    @State(Scope.Benchmark)
    public static class Plain extends ProxyState {}

    /** This thread's share of the connections, each with one request in flight. */
    @State(Scope.Thread)
    public static class Clients {

        /** Concurrent connections in total, across every benchmark thread. */
        @Param({"16", "256", "4096"})
        public int connections;

        /** The response body size. */
        @Param({"1024"})
        public int responseBytes;

        HttpConnection[] mine;
        byte[] request;
        int next;
        Plain servers;

        /**
         * Opens this thread's connections and sends a request on each.
         *
         * @param servers the trial's servers
         * @param benchmark JMH's parameters, for the thread count
         * @param thread JMH's thread parameters, for this thread's index
         * @throws IOException if the proxy cannot be reached
         */
        @Setup(Level.Trial)
        public void open(Plain servers, BenchmarkParams benchmark, ThreadParams thread) throws IOException {
            int threads = benchmark.getThreads();
            if (connections < threads || connections % threads != 0) {
                throw new IllegalArgumentException(connections + " connections cannot be split evenly between "
                        + threads + " threads: use a multiple of the thread count (-t)");
            }
            this.servers = servers;
            servers.attach();
            request = HttpConnection.get(servers.origin.plainAddress(), responseBytes, true, false, "");
            mine = new HttpConnection[connections / threads];
            for (int i = 0; i < mine.length; i++) {
                mine[i] = HttpConnection.open(servers.proxyAddress());
                mine[i].send(request);
            }
            next = 0;
            if (thread.getThreadIndex() == 0) {
                System.out.println("\n" + connections + " connections through " + servers.server);
            }
        }

        /**
         * Reads the outstanding responses, so none is left unchecked, and closes the connections.
         *
         * @throws IOException if a connection fails
         */
        @TearDown(Level.Trial)
        public void close() throws IOException {
            IOException failure = null;
            try {
                for (HttpConnection connection : mine) {
                    if (connection == null) continue;
                    try (connection) {
                        connection.readResponse(200, responseBytes);
                    } catch (IOException e) {
                        failure = e;
                    }
                }
            } finally {
                servers.detach();
            }
            if (failure != null) throw failure;
        }
    }

    /**
     * Completes the oldest outstanding request of this thread and sends the next one on its
     * connection.
     *
     * @param clients this thread's connections
     * @return the body length, for JMH to consume
     * @throws IOException if the exchange fails
     */
    @Benchmark
    public long requests(Clients clients) throws IOException {
        HttpConnection connection = clients.mine[clients.next];
        long length = connection.readResponse(200, clients.responseBytes);
        connection.send(clients.request);
        if (++clients.next == clients.mine.length) clients.next = 0;
        return length;
    }
}
