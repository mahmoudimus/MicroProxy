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
 * Scenario 5: throughput of a {@code CONNECT} tunnel. Each benchmark thread opens one tunnel
 * through the proxy to the origin, then exchanges plain bytes over it: HTTP/1.1 requests in origin
 * form, which the proxy relays without parsing. {@code responseBytes} sets how much comes back per
 * exchange (1 KB: relay latency; 1 MB: relay bandwidth).
 */
@Fork(value = BenchConfig.FORKS, jvmArgsAppend = {BenchConfig.HEAP_MIN, BenchConfig.HEAP_MAX})
@Warmup(iterations = BenchConfig.WARMUP_ITERATIONS, time = BenchConfig.WARMUP_SECONDS)
@Measurement(iterations = BenchConfig.MEASUREMENT_ITERATIONS, time = BenchConfig.MEASUREMENT_SECONDS)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class ConnectTunnelBenchmark {

    /** A forwarding proxy that tunnels {@code CONNECT} untouched. */
    @State(Scope.Benchmark)
    public static class Plain extends ProxyState {}

    /** One tunnel through the proxy, per benchmark thread. */
    @State(Scope.Thread)
    public static class Tunnel {

        /** The bytes coming back per exchange. */
        @Param({"1024", "1048576"})
        public int responseBytes;

        HttpConnection connection;
        byte[] request;

        /**
         * Opens the tunnel.
         *
         * @param servers the trial's servers
         * @throws IOException if the proxy or the origin cannot be reached
         */
        @Setup(Level.Trial)
        public void open(Plain servers) throws IOException {
            request = HttpConnection.get(servers.origin.plainAddress(), responseBytes, false, false, "");
            connection = HttpConnection.open(servers.proxyAddress());
            connection.connectTunnel(HttpConnection.authority(servers.origin.plainAddress()));
        }

        /**
         * Closes the tunnel.
         *
         * @throws IOException never in practice
         */
        @TearDown(Level.Trial)
        public void close() throws IOException {
            connection.close();
        }
    }

    /**
     * Exchanges through the tunnel per second.
     *
     * @param tunnel this thread's tunnel
     * @return the body length, for JMH to consume
     * @throws IOException if the exchange fails
     */
    @Benchmark
    public long throughput(Tunnel tunnel) throws IOException {
        tunnel.connection.send(tunnel.request);
        return tunnel.connection.readResponse(200, tunnel.responseBytes);
    }
}
