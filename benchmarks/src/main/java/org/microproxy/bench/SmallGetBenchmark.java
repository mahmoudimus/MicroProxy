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
import org.openjdk.jmh.annotations.Warmup;

/**
 * Scenario 1: a small {@code GET} (1 KB by default) over one keep-alive connection per benchmark
 * thread, measured as throughput and as a latency distribution (with percentiles).
 */
@Fork(value = BenchConfig.FORKS, jvmArgsAppend = {BenchConfig.HEAP_MIN, BenchConfig.HEAP_MAX})
@Warmup(iterations = BenchConfig.WARMUP_ITERATIONS, time = BenchConfig.WARMUP_SECONDS)
@Measurement(iterations = BenchConfig.MEASUREMENT_ITERATIONS, time = BenchConfig.MEASUREMENT_SECONDS)
public class SmallGetBenchmark {

    /** A plain forwarding proxy. */
    @State(Scope.Benchmark)
    public static class Plain extends ProxyState {}

    /** One keep-alive connection through the proxy, per benchmark thread. */
    @State(Scope.Thread)
    public static class Client {

        /** The response body size. */
        @Param({"1024"})
        public int responseBytes;

        HttpConnection connection;
        byte[] request;

        /**
         * Opens the connection and sends a first request through it.
         *
         * @param servers the trial's servers
         * @throws IOException if the proxy cannot be reached
         */
        @Setup(Level.Trial)
        public void open(Plain servers) throws IOException {
            request = HttpConnection.get(servers.origin.plainAddress(), responseBytes, true, false, "");
            connection = HttpConnection.open(servers.proxyAddress());
            connection.send(request);
            connection.readResponse(200, responseBytes);
        }

        /**
         * Closes the connection.
         *
         * @throws IOException never in practice
         */
        @TearDown(Level.Trial)
        public void close() throws IOException {
            connection.close();
        }

        long exchange() throws IOException {
            connection.send(request);
            return connection.readResponse(200, responseBytes);
        }
    }

    /**
     * Requests per second.
     *
     * @param client this thread's connection
     * @return the body length, for JMH to consume
     * @throws IOException if the exchange fails
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public long throughput(Client client) throws IOException {
        return client.exchange();
    }

    /**
     * The time of each request, sampled, with percentiles.
     *
     * @param client this thread's connection
     * @return the body length, for JMH to consume
     * @throws IOException if the exchange fails
     */
    @Benchmark
    @BenchmarkMode(Mode.SampleTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public long latency(Client client) throws IOException {
        return client.exchange();
    }
}
