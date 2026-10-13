package org.microproxy.bench;

import java.io.IOException;
import java.util.Arrays;
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
 * Scenario 2: large bodies over a keep-alive connection, streamed by the proxy in each direction:
 * a large response ({@link #download}) and a large request body ({@link #upload}), each of {@code
 * bodyBytes} (1 MB and 16 MB by default). Reported as the average time per transfer.
 */
@Fork(value = BenchConfig.FORKS, jvmArgsAppend = {BenchConfig.HEAP_MIN, BenchConfig.HEAP_MAX})
@Warmup(iterations = BenchConfig.WARMUP_ITERATIONS, time = BenchConfig.WARMUP_SECONDS)
@Measurement(iterations = BenchConfig.MEASUREMENT_ITERATIONS, time = BenchConfig.MEASUREMENT_SECONDS)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class LargeBodyBenchmark {

    /** A plain forwarding proxy. */
    @State(Scope.Benchmark)
    public static class Plain extends ProxyState {}

    /** One keep-alive connection through the proxy, per benchmark thread. */
    @State(Scope.Thread)
    public static class Client {

        /** The size of the body sent or received. */
        @Param({"1048576", "16777216"})
        public int bodyBytes;

        HttpConnection connection;
        byte[] get;
        byte[] postHead;
        byte[] uploadChunk;
        byte[] receivedHeader;

        /**
         * Opens the connection.
         *
         * @param servers the trial's servers
         * @throws IOException if the proxy cannot be reached
         */
        @Setup(Level.Trial)
        public void open(Plain servers) throws IOException {
            get = HttpConnection.get(servers.origin.plainAddress(), bodyBytes, true, false, "");
            postHead = HttpConnection.postHead(servers.origin.plainAddress(), bodyBytes);
            uploadChunk = new byte[64 * 1024];
            Arrays.fill(uploadChunk, (byte) 'u');
            // The origin reports how many bytes it read: all of them, or the upload failed.
            receivedHeader = HttpConnection.headerLine("X-Received", Integer.toString(bodyBytes));
            connection = HttpConnection.open(servers.proxyAddress());
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
    }

    /**
     * Receives one response of {@code bodyBytes}.
     *
     * @param client this thread's connection
     * @return the body length, for JMH to consume
     * @throws IOException if the exchange fails
     */
    @Benchmark
    public long download(Client client) throws IOException {
        client.connection.send(client.get);
        return client.connection.readResponse(200, client.bodyBytes);
    }

    /**
     * Sends one request body of {@code bodyBytes}.
     *
     * @param client this thread's connection
     * @return the response's body length, for JMH to consume
     * @throws IOException if the exchange fails
     */
    @Benchmark
    public long upload(Client client) throws IOException {
        client.connection.send(client.postHead, client.uploadChunk, client.bodyBytes);
        return client.connection.readResponse(200, 0, client.receivedHeader);
    }
}
