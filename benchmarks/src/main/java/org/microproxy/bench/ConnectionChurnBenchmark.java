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
import org.openjdk.jmh.annotations.Warmup;

/**
 * Scenario 4: connection churn. Every request opens a new connection to the proxy and asks for
 * {@code Connection: close}, so each costs an accept, a new server connection and the teardown of
 * both: no keep-alive anywhere.
 */
@Fork(value = BenchConfig.FORKS, jvmArgsAppend = {BenchConfig.HEAP_MIN, BenchConfig.HEAP_MAX})
@Warmup(iterations = BenchConfig.WARMUP_ITERATIONS, time = BenchConfig.WARMUP_SECONDS)
@Measurement(iterations = BenchConfig.MEASUREMENT_ITERATIONS, time = BenchConfig.MEASUREMENT_SECONDS)
public class ConnectionChurnBenchmark {

    /** A plain forwarding proxy. */
    @State(Scope.Benchmark)
    public static class Plain extends ProxyState {}

    /** The request every connection sends. */
    @State(Scope.Thread)
    public static class Client {

        /** The response body size. */
        @Param({"1024"})
        public int responseBytes;

        byte[] request;
        Plain servers;

        /**
         * Builds the request.
         *
         * @param servers the trial's servers
         */
        @Setup(Level.Trial)
        public void prepare(Plain servers) {
            this.servers = servers;
            request = HttpConnection.get(servers.origin.plainAddress(), responseBytes, true, true, "");
        }

        long exchange() throws IOException {
            try (HttpConnection connection = HttpConnection.open(servers.proxyAddress())) {
                connection.send(request);
                return connection.readResponse(200, responseBytes);
            }
        }
    }

    /**
     * Connections (each with one request) per second.
     *
     * @param client this thread's request
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
     * The time of each connection's exchange, from connect to response, sampled.
     *
     * @param client this thread's request
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
