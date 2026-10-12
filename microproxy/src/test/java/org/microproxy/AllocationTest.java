package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Guards the per-request allocation of the plain keep-alive path (about 4.7 KB per small GET, the
 * benchmark client included, when this was written). The bound is generous, so only a real
 * regression (such as a buffer or a copy per request) fails it, not noise. For HTTP/2 and HTTP/3,
 * whose paths allocate more, it compares a proxy with metrics to one without: the codec, QUIC and
 * hook stats must add nothing per request beyond noise.
 */
class AllocationTest {

    /** Bytes allocated per request, everything in the JVM included, above which the test fails. */
    private static final long MAX_BYTES_PER_REQUEST = 8 * 1024;
    private static final int CLIENTS = 4;

    private static final byte[] RESPONSE = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + "Content-Length: 13\r\n\r\n{\"id\": 42}\n\n\n").getBytes(StandardCharsets.ISO_8859_1);

    private ServerSocket origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void start() throws IOException {
        origin = new ServerSocket(0, 64, TestSupport.LOOPBACK);
        Thread.ofVirtual().start(() -> {
            while (!origin.isClosed()) {
                try {
                    Socket s = origin.accept();
                    Thread.ofVirtual().start(() -> serve(s));
                } catch (IOException e) {
                    return;
                }
            }
        });
    }

    @AfterEach
    void stop() throws IOException {
        if (proxy != null) proxy.abort();
        origin.close();
    }

    @Test
    void smallKeepAliveRequestsAllocateLittle() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        long perRequest = bytesPerRequest();
        System.out.println("AllocationTest: " + perRequest + " bytes allocated per small keep-alive request");
    }

    /**
     * With metrics on, the proxy counts each request (its class, time, protocol, cluster) into
     * metrics it resolved when it started and when each connection was made: nothing more is
     * allocated per request, and the same bound holds.
     */
    @Test
    void smallKeepAliveRequestsAllocateLittleWithMetrics() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withName("alloc").withMetrics(true).start();
        long perRequest = bytesPerRequest();
        System.out.println("AllocationTest: " + perRequest + " bytes allocated per small keep-alive request with metrics");
        org.microproxy.stats.StatsRegistry stats = proxy.getStats();
        long requests = ((org.microproxy.stats.Counter) stats.get("http.alloc.downstream_rq_total")).value();
        assertTrue(requests >= (long) CLIENTS * 10_000, requests + " requests counted");
        assertEquals(requests, ((org.microproxy.stats.Counter) stats.get("http.alloc.downstream_rq_2xx")).value());
        assertEquals(requests, ((org.microproxy.stats.Counter) stats.get("cluster.direct.upstream_rq_total")).value());
    }

    /** Bytes per request that metrics may add to a multiplexed protocol's, beyond a tenth: noise. */
    private static final long MAX_EXTRA_BYTES_WITH_METRICS = 2048;

    /** Sends one round of requests through one of the proxies compared. */
    @FunctionalInterface
    private interface Round {
        void run() throws Exception;
    }

    /** Rounds through each proxy before any is measured. */
    private static final int WARM_UP_ROUNDS = 4;

    /** Pairs of measured rounds, one through each proxy. */
    private static final int MEASURED_PAIRS = 7;

    /**
     * The bytes per request through a proxy without metrics and one with: {without, with}, and
     * every measured round's, for a failure's message.
     *
     * <p>The count is every thread's (the request path runs on virtual threads, whose own counts
     * the JVM does not keep), and a round's moves by a tenth and more for reasons that have nothing
     * to do with metrics: the JIT still compiling the path thousands of requests in (rounds
     * allocate less and less as it does), and the timing of a busy machine, which decides how many
     * packets carry a request and its acknowledgments, and so how many are sealed, sent and
     * parsed. Comparing the best round of each proxy compares two such accidents. So both proxies
     * are warmed up first, in turn, and then measured in pairs of adjacent rounds, one through
     * each, the order alternating from pair to pair so that drift weighs on both alike: what
     * metrics cost is the median of the pairs' differences, over the median round without them.
     */
    private static Comparison compare(Round without, Round with, int requestsPerRound) throws Exception {
        com.sun.management.ThreadMXBean threads = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        for (int i = 0; i < WARM_UP_ROUNDS; i++) {
            without.run();
            with.run();
        }
        long[] plain = new long[MEASURED_PAIRS];
        long[] metrics = new long[MEASURED_PAIRS];
        long[] differences = new long[MEASURED_PAIRS];
        for (int pair = 0; pair < MEASURED_PAIRS; pair++) {
            boolean withFirst = pair % 2 == 1;
            long first = bytesPerRequest(threads, withFirst ? with : without, requestsPerRound);
            long second = bytesPerRequest(threads, withFirst ? without : with, requestsPerRound);
            plain[pair] = withFirst ? second : first;
            metrics[pair] = withFirst ? first : second;
            differences[pair] = metrics[pair] - plain[pair];
        }
        long base = median(plain);
        return new Comparison(base, base + median(differences),
                "rounds without " + Arrays.toString(plain) + ", with " + Arrays.toString(metrics));
    }

    /** What {@link #compare} measured. */
    private record Comparison(long without, long with, String rounds) {}

    private static long bytesPerRequest(com.sun.management.ThreadMXBean threads, Round round, int requests)
            throws Exception {
        long before = threads.getTotalThreadAllocatedBytes();
        round.run();
        return (threads.getTotalThreadAllocatedBytes() - before) / requests;
    }

    private static long median(long[] values) {
        long[] sorted = values.clone();
        Arrays.sort(sorted);
        int mid = sorted.length / 2;
        return sorted.length % 2 == 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    /**
     * HTTP/2 (with prior knowledge, one connection, one stream after another): the codec stats,
     * the streams gauge and the hooks' clock add nothing per request over a proxy without
     * metrics, beyond noise.
     */
    @Test
    void http2StreamsAllocateNoMoreWithMetrics() throws Exception {
        HttpProxyServer plain = MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true).start();
        proxy = MicroProxy.bootstrap().withPort(0).withName("alloc2").withMetrics(true).withHttp2Cleartext(true).start();
        String authority = "127.0.0.1:" + origin.getLocalPort();
        try (H2TestClient a = H2TestClient.cleartext(plain.getListenAddress(), authority).handshake();
                H2TestClient b = H2TestClient.cleartext(proxy.getListenAddress(), authority).handshake()) {
            Comparison bytes = compare(http2Round(a), http2Round(b), 2_000);
            System.out.println("AllocationTest: HTTP/2 " + bytes.without() + " bytes per request, " + bytes.with()
                    + " with metrics");
            assertTrue(bytes.with() <= bytes.without() + bytes.without() / 10 + MAX_EXTRA_BYTES_WITH_METRICS,
                    bytes.with() + " bytes per HTTP/2 request with metrics, " + bytes.without() + " without ("
                            + bytes.rounds() + ")");
        } finally {
            plain.abort();
        }
        assertEquals(0, ((org.microproxy.stats.Gauge) proxy.getStats().get("http2.downstream.streams_active")).value());
    }

    /** 2000 requests on {@code h2}, one stream after another. */
    private static Round http2Round(H2TestClient h2) throws IOException {
        // Room for every response's DATA: the test client gives none back
        h2.writer.writeWindowUpdate(0, 1 << 30);
        h2.writer.flush();
        int[] id = {1};
        return () -> {
            for (int i = 0; i < 2_000; i++) {
                h2.get(id[0], "/item?id=42");
                h2.response(id[0]);
                id[0] += 2;
            }
        };
    }

    /**
     * HTTP/3 to a reverse proxy (one QUIC connection, one request stream after another): the QUIC
     * connection counts its packets in plain fields of its own, which reach the registry once, when
     * it closes, so metrics add nothing per packet or request beyond noise.
     */
    @Test
    void http3StreamsAllocateNoMoreWithMetrics() throws Exception {
        org.microproxy.tls.SelfSignedSslContextSource tls = new org.microproxy.tls.SelfSignedSslContextSource();
        String upstream = "http://127.0.0.1:" + origin.getLocalPort();
        HttpProxyServer plain = MicroProxy.bootstrap().withPort(0).withReverseProxy(upstream).withSslContextSource(tls)
                .withHttp3(true).start();
        proxy = MicroProxy.bootstrap().withPort(0).withName("alloc3").withMetrics(true).withReverseProxy(upstream)
                .withSslContextSource(tls).withHttp3(true).start();
        try (H3TestClient a = h3(plain, tls); H3TestClient b = h3(proxy, tls)) {
            Comparison bytes = compare(http3Round(a), http3Round(b), 500);
            System.out.println("AllocationTest: HTTP/3 " + bytes.without() + " bytes per request, " + bytes.with()
                    + " with metrics");
            assertTrue(bytes.with() <= bytes.without() + bytes.without() / 10 + MAX_EXTRA_BYTES_WITH_METRICS,
                    bytes.with() + " bytes per HTTP/3 request with metrics, " + bytes.without() + " without ("
                            + bytes.rounds() + ")");
        } finally {
            plain.abort();
        }
        assertEquals(0, ((org.microproxy.stats.Gauge) proxy.getStats().get("http3.downstream.streams_active")).value());
    }

    private static H3TestClient h3(HttpProxyServer proxy, org.microproxy.tls.SelfSignedSslContextSource tls)
            throws IOException {
        return H3TestClient.connect(new java.net.InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort()),
                "localhost", tls.getCertificate());
    }

    /** 500 requests on {@code h3}, one stream after another. */
    private static Round http3Round(H3TestClient h3) {
        return () -> {
            for (int i = 0; i < 500; i++) {
                assertEquals(200, h3.get("/item?id=42").status());
            }
        };
    }

    /** The best of three rounds' bytes per request, failing above {@link #MAX_BYTES_PER_REQUEST}. */
    private long bytesPerRequest() throws Exception {
        com.sun.management.ThreadMXBean threads = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        assertTrue(threads.isThreadAllocatedMemorySupported() && threads.isThreadAllocatedMemoryEnabled(),
                "this JVM cannot count allocated bytes");
        byte[] request = ("GET http://127.0.0.1:" + origin.getLocalPort() + "/item?id=42 HTTP/1.1\r\n"
                + "Host: 127.0.0.1\r\nUser-Agent: allocation-test/1.0\r\nAccept: */*\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1);
        run(request, 5_000); // warm-up: class loading and JIT compilation
        long best = Long.MAX_VALUE;
        for (int round = 0; round < 3 && best > MAX_BYTES_PER_REQUEST; round++) {
            int perClient = 5_000;
            long before = threads.getTotalThreadAllocatedBytes();
            run(request, perClient);
            long perRequest = (threads.getTotalThreadAllocatedBytes() - before) / ((long) CLIENTS * perClient);
            best = Math.min(best, perRequest);
        }
        assertTrue(best <= MAX_BYTES_PER_REQUEST, best + " bytes allocated per request, more than " + MAX_BYTES_PER_REQUEST);
        return best;
    }

    /** {@link #CLIENTS} keep-alive connections, each sending {@code perClient} requests one after another. */
    private void run(byte[] request, int perClient) throws Exception {
        try (ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> clients = new ArrayList<>();
            for (int c = 0; c < CLIENTS; c++) {
                clients.add(exec.submit(() -> {
                    try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
                        s.setSoTimeout(20_000);
                        OutputStream out = s.getOutputStream();
                        InputStream in = s.getInputStream();
                        byte[] buf = new byte[4096];
                        for (int i = 0; i < perClient; i++) {
                            out.write(request);
                            readResponse(in, buf);
                        }
                    }
                    return null;
                }));
            }
            for (Future<?> f : clients) f.get();
        }
    }

    /** Reads one response with a 13-byte body, allocating nothing. */
    private static void readResponse(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        int headEnd = -1;
        while (true) {
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) throw new EOFException();
            total += n;
            if (headEnd < 0) {
                for (int i = 3; i < total; i++) {
                    if (buf[i] == '\n' && buf[i - 1] == '\r' && buf[i - 2] == '\n' && buf[i - 3] == '\r') {
                        headEnd = i + 1;
                        break;
                    }
                }
            }
            if (headEnd >= 0 && total >= headEnd + 13) {
                assertEquals(headEnd + 13, total, "one response at a time");
                return;
            }
        }
    }

    private static void serve(Socket s) {
        try (s) {
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            byte[] buf = new byte[4096];
            int state = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                for (int i = 0; i < n; i++) {
                    byte c = buf[i];
                    // Counts CR LF CR LF: the end of a request head (the test sends no bodies).
                    state = c == (state % 2 == 0 ? '\r' : '\n') ? state + 1 : (c == '\r' ? 1 : 0);
                    if (state == 4) {
                        out.write(RESPONSE);
                        out.flush();
                        state = 0;
                    }
                }
            }
        } catch (IOException ignored) {
            // the test is over
        }
    }
}
