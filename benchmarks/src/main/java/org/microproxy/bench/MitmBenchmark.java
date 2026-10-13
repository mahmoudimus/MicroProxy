package org.microproxy.bench;

import java.io.IOException;
import java.net.InetSocketAddress;
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
 * Scenario 6: intercepted HTTPS (MITM). The client sends {@code CONNECT} for the origin's TLS
 * listener; the proxy completes its own TLS connection to the origin, then the client's handshake
 * with a certificate for the origin issued by the shared test CA, and decrypts, forwards and
 * re-encrypts every request. Both proxies sign leaf certificates the same way (see {@link
 * LittleProxyMitmManager}); the client trusts only that CA.
 *
 * <ul>
 *   <li>{@link #request}: small {@code GET}s over one intercepted session per thread.
 *   <li>{@link #newSession}: a new connection, {@code CONNECT}, both handshakes and one {@code GET}
 *       per operation, with TLS session resumption as the JDK does it on either side.
 * </ul>
 */
@Fork(value = BenchConfig.FORKS, jvmArgsAppend = {BenchConfig.HEAP_MIN, BenchConfig.HEAP_MAX})
@Warmup(iterations = BenchConfig.WARMUP_ITERATIONS, time = BenchConfig.WARMUP_SECONDS)
@Measurement(iterations = BenchConfig.MEASUREMENT_ITERATIONS, time = BenchConfig.MEASUREMENT_SECONDS)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class MitmBenchmark {

    /** A proxy intercepting every {@code CONNECT} with the test CA. */
    @State(Scope.Benchmark)
    public static class Intercepting extends ProxyState {
        @Override
        protected ProxyUnderTest.Options options() {
            return new ProxyUnderTest.Options(BenchTls.authority(), false);
        }

        @Override
        protected boolean originTls() {
            return true;
        }

        HttpConnection openSession() throws IOException {
            InetSocketAddress target = origin.tlsAddress();
            HttpConnection connection = HttpConnection.open(proxyAddress());
            try {
                connection.connectTunnel(HttpConnection.authority(target));
                connection.startTls(BenchTls.clientContext(), target.getAddress().getHostAddress(), target.getPort());
                return connection;
            } catch (IOException | RuntimeException e) {
                connection.close();
                throw e;
            }
        }
    }

    /** One intercepted session per benchmark thread, and the request sent over it. */
    @State(Scope.Thread)
    public static class Session {

        /** The response body size. */
        @Param({"1024"})
        public int responseBytes;

        HttpConnection connection;
        byte[] request;
        Intercepting servers;

        /**
         * Opens the session.
         *
         * @param servers the trial's servers
         * @throws IOException if the proxy or the origin cannot be reached
         */
        @Setup(Level.Trial)
        public void open(Intercepting servers) throws IOException {
            this.servers = servers;
            request = HttpConnection.get(servers.origin.tlsAddress(), responseBytes, false, false, "");
            connection = servers.openSession();
        }

        /**
         * Closes the session.
         *
         * @throws IOException never in practice
         */
        @TearDown(Level.Trial)
        public void close() throws IOException {
            connection.close();
        }
    }

    /**
     * Requests per second over an intercepted session.
     *
     * @param session this thread's session
     * @return the body length, for JMH to consume
     * @throws IOException if the exchange fails
     */
    @Benchmark
    public long request(Session session) throws IOException {
        session.connection.send(session.request);
        return session.connection.readResponse(200, session.responseBytes);
    }

    /**
     * Intercepted sessions per second, each with one request.
     *
     * @param session this thread's request (its long-lived session is not used)
     * @return the body length, for JMH to consume
     * @throws IOException if the exchange fails
     */
    @Benchmark
    public long newSession(Session session) throws IOException {
        try (HttpConnection connection = session.servers.openSession()) {
            connection.send(session.request);
            return connection.readResponse(200, session.responseBytes);
        }
    }
}
