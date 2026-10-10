package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.HeaderField;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpObject;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * HTTP/2 between the proxy and origin servers ({@code withHttp2Upstream}), on intercepted HTTPS:
 * negotiation, the translation of messages, multiplexing exchanges onto shared connections within
 * the server's stream limit, failures and retries, and flow control from the server to a slow client.
 */
class Http2UpstreamTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("H2 Upstream Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("H2 Upstream Proxy CA");

    private H2TestOrigin origin;
    private HttpsServer http1Origin;
    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new ArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.close();
        if (http1Origin != null) http1Origin.stop(0);
        for (AutoCloseable c : closeables) c.close();
    }

    static SSLContext originContext() {
        return originCa.serverContext("localhost", "127.0.0.1");
    }

    private H2TestOrigin origin(H2TestOrigin.Handler handler) throws IOException {
        origin = new H2TestOrigin(originContext(), handler);
        return origin;
    }

    private H2TestOrigin origin(H2TestOrigin.Options options, H2TestOrigin.Handler handler) throws IOException {
        origin = new H2TestOrigin(originContext(), options, handler);
        return origin;
    }

    static HttpProxyServerBootstrap mitm() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("h2up")
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp2Upstream(true);
    }

    private HttpClient http1Client() {
        return TestSupport.client(proxy, proxyCa.clientContext());
    }

    private HttpClient http2Client() {
        return Http2ProxyTest.h2Client(proxy, proxyCa.clientContext());
    }

    private static HttpRequest get(String url) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30)).build();
    }

    /** Answers with the request's pseudo-headers and fields, one per line. */
    static void echo(H2TestOrigin.Stream s) throws IOException {
        byte[] body = s.readBody();
        StringBuilder sb = new StringBuilder();
        for (HeaderField f : s.headers) sb.append(f.name()).append(": ").append(f.value()).append('\n');
        sb.append('\n').append(new String(body, StandardCharsets.UTF_8));
        byte[] out = sb.toString().getBytes(StandardCharsets.UTF_8);
        s.respond(200, false, "content-type", "text/plain", "content-length", Integer.toString(out.length));
        s.data(out, true);
    }

    static List<String> lines(String body, String name) {
        String prefix = name + ": ";
        return body.lines().takeWhile(l -> !l.isEmpty()).filter(l -> l.startsWith(prefix))
                .map(l -> l.substring(prefix.length())).toList();
    }

    @Test
    void anHttp1ClientsRequestReachesTheServerAsHttp2() throws Exception {
        origin(Http2UpstreamTest::echo);
        proxy = mitm().start();
        HttpRequest request = HttpRequest.newBuilder(URI.create(origin.url("/path?q=1")))
                .timeout(Duration.ofSeconds(30))
                .header("Cookie", "a=1; b=2")
                .header("X-Custom", "yes")
                .POST(HttpRequest.BodyPublishers.ofString("hello"))
                .build();
        HttpResponse<String> response = TestSupport.send(http1Client(), request);
        assertEquals(200, response.statusCode());
        assertEquals(HttpClient.Version.HTTP_1_1, response.version());
        String body = response.body();
        assertEquals(List.of("POST"), lines(body, ":method"));
        assertEquals(List.of("https"), lines(body, ":scheme"));
        assertEquals(List.of("localhost:" + origin.port()), lines(body, ":authority"));
        assertEquals(List.of("/path?q=1"), lines(body, ":path"));
        // Cookie crumbs, lower-case names, no Host or connection-specific fields.
        assertEquals(List.of("a=1", "b=2"), lines(body, "cookie"));
        assertEquals(List.of("yes"), lines(body, "x-custom"));
        assertEquals(List.of(), lines(body, "host"));
        assertEquals(List.of(), lines(body, "connection"));
        assertEquals(List.of("1.1 h2up"), lines(body, "via"));
        assertTrue(body.endsWith("\n\nhello"), body);
        // The response: Via says HTTP/2, the status line HTTP/1.1.
        assertEquals(List.of("2 h2up"), response.headers().allValues("via"));
        assertEquals(1, origin.accepts.get());
    }

    @Test
    void streamsOfOneClientShareOneServerConnection() throws Exception {
        int n = 12;
        CountDownLatch all = new CountDownLatch(n);
        origin(s -> {
            s.readBody();
            if (!s.header(":path").equals("/warmup")) {
                all.countDown();
                // Every stream is open on the server at once before any is answered.
                if (!all.await(20, TimeUnit.SECONDS)) throw new IOException("not all streams arrived");
            }
            byte[] out = s.header(":path").getBytes(StandardCharsets.UTF_8);
            s.respond(200, false);
            s.data(out, true);
        });
        proxy = mitm().withHttp2(true).start();
        HttpClient client = http2Client();
        // One client connection: the JDK client makes one per request until it has one.
        assertEquals(200, TestSupport.send(client, get(origin.url("/warmup"))).statusCode());
        List<CompletableFuture<HttpResponse<String>>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            futures.add(client.sendAsync(get(origin.url("/s" + i)), HttpResponse.BodyHandlers.ofString()));
        }
        for (int i = 0; i < n; i++) {
            HttpResponse<String> r = futures.get(i).get(30, TimeUnit.SECONDS);
            assertEquals(200, r.statusCode());
            assertEquals(HttpClient.Version.HTTP_2, r.version());
            assertEquals("/s" + i, r.body());
        }
        assertEquals(1, origin.accepts.get(), "one TCP connection to the server");
        assertEquals(n, origin.maxOpenStreams.get());
    }

    @Test
    void separateClientConnectionsShareOneServerConnectionThroughThePool() throws Exception {
        int n = 6;
        CountDownLatch all = new CountDownLatch(n);
        origin(s -> {
            s.readBody();
            all.countDown();
            if (!all.await(20, TimeUnit.SECONDS)) throw new IOException("not all streams arrived");
            s.respond(200, false);
            s.data("ok".getBytes(StandardCharsets.UTF_8), true);
        });
        proxy = mitm().withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).start();
        List<CompletableFuture<HttpResponse<String>>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            // A client each: separate client connections, each with its own CONNECT.
            futures.add(http1Client().sendAsync(get(origin.url("/c" + i)), HttpResponse.BodyHandlers.ofString()));
        }
        for (CompletableFuture<HttpResponse<String>> f : futures) {
            assertEquals("ok", f.get(30, TimeUnit.SECONDS).body());
        }
        assertEquals(1, origin.accepts.get(), "one TCP connection to the server for every client");
        assertEquals(n, origin.maxOpenStreams.get());
    }

    @Test
    void withoutThePoolEachClientConnectionHasItsOwn() throws Exception {
        origin(Http2UpstreamTest::echo);
        proxy = mitm().start();
        for (int i = 0; i < 3; i++) {
            assertEquals(200, TestSupport.send(http1Client(), get(origin.url("/x"))).statusCode());
        }
        assertEquals(3, origin.accepts.get());
        // Requests on one client connection reuse its server connection.
        HttpClient client = http1Client();
        for (int i = 0; i < 3; i++) {
            assertEquals(200, TestSupport.send(client, get(origin.url("/y"))).statusCode());
        }
        assertEquals(4, origin.accepts.get());
    }

    @Test
    void theServersStreamLimitIsRespected() throws Exception {
        int n = 6;
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.maxConcurrentStreams = 2;
        CountDownLatch all = new CountDownLatch(n);
        origin(options, s -> {
            s.readBody();
            if (!s.header(":path").equals("/warmup")) {
                all.countDown();
                // All six are open at once, on connections of at most two streams.
                if (!all.await(20, TimeUnit.SECONDS)) throw new IOException("not all streams arrived");
            }
            s.respond(200, false);
            s.data("ok".getBytes(StandardCharsets.UTF_8), true);
        });
        proxy = mitm().withHttp2(true).start();
        HttpClient client = http2Client();
        assertEquals(200, TestSupport.send(client, get(origin.url("/warmup"))).statusCode());
        List<CompletableFuture<HttpResponse<String>>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            futures.add(client.sendAsync(get(origin.url("/" + i)), HttpResponse.BodyHandlers.ofString()));
        }
        for (CompletableFuture<HttpResponse<String>> f : futures) {
            assertEquals("ok", f.get(30, TimeUnit.SECONDS).body());
        }
        assertEquals(0, origin.refused.get(), "no stream past the server's limit");
        assertEquals(2, origin.maxOpenStreams.get());
        assertEquals(3, origin.accepts.get());
        // Later streams reuse those connections.
        assertEquals("ok", TestSupport.send(client, get(origin.url("/again"))).body());
        assertEquals(3, origin.accepts.get());
    }

    @Test
    void streamsTheServerDidNotProcessBeforeGoAwayAreRetried() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        origin(s -> {
            s.readBody();
            if (requests.incrementAndGet() == 1) {
                // Going away before processing anything: the proxy retries on a new connection.
                s.conn.goAway(0, ErrorCode.NO_ERROR);
                return;
            }
            s.respond(200, false);
            s.data("second".getBytes(StandardCharsets.UTF_8), true);
        });
        proxy = mitm().start();
        HttpResponse<String> response = TestSupport.send(http1Client(), get(origin.url("/retry")));
        assertEquals(200, response.statusCode());
        assertEquals("second", response.body());
        assertEquals(2, requests.get());
        assertEquals(2, origin.accepts.get());
    }

    @Test
    void refusedStreamsAreRetried() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        origin(s -> {
            s.readBody();
            if (requests.incrementAndGet() == 1) {
                s.reset(ErrorCode.REFUSED_STREAM);
                return;
            }
            s.respond(200, false);
            s.data("again".getBytes(StandardCharsets.UTF_8), true);
        });
        proxy = mitm().start();
        HttpResponse<String> response = TestSupport.send(http1Client(), get(origin.url("/refused")));
        assertEquals("again", response.body());
        assertEquals(2, requests.get());
    }

    @Test
    void aStreamResetByTheServerIsA502() throws Exception {
        List<ProxyFailure> failures = new CopyOnWriteArrayList<>();
        origin(s -> {
            s.readBody();
            s.reset(ErrorCode.INTERNAL_ERROR);
        });
        proxy = mitm().withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
            @Override
            public org.microproxy.http.HttpResponse proxyToServerFailure(ProxyFailure failure) {
                failures.add(failure);
                return null;
            }
        }).start();
        HttpResponse<String> response = TestSupport.send(http1Client(), get(origin.url("/reset")));
        assertEquals(502, response.statusCode());
        assertEquals(1, failures.size());
        assertTrue(failures.getFirst() instanceof ProxyFailure.BadServerResponse, failures.toString());
        // The connection is still good for other streams.
        origin.close();
    }

    @Test
    void aResetAfterTheResponseStartedResetsTheClientsStream() throws Exception {
        origin(s -> {
            s.readBody();
            s.respond(200, false);
            s.data(new byte[1000], false);
            s.reset(ErrorCode.INTERNAL_ERROR);
        });
        proxy = mitm().withHttp2(true).start();
        try (H2TestClient client = H2TestClient.connect(proxy.getListenAddress(), "localhost:" + origin.port(),
                proxyCa.clientContext()).handshake()) {
            client.get(1, "/partial");
            H2TestClient.Response r = client.response(1);
            assertEquals(200, r.status());
            assertNotNull(r.reset(), "the client's stream is reset, not ended");
        }
    }

    @Test
    void serversWithoutHttp2GetHttp11() throws Exception {
        http1Origin = TestSupport.httpsOrigin(originContext(), exchange -> {
            byte[] out = exchange.getProtocol().getBytes(StandardCharsets.UTF_8);
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        proxy = mitm().withHttp2(true).start();
        String url = TestSupport.localhostUrl(http1Origin, "/");
        for (HttpClient client : List.of(http1Client(), http2Client())) {
            for (int i = 0; i < 3; i++) {
                HttpResponse<String> r = TestSupport.send(client, get(url));
                assertEquals(200, r.statusCode());
                assertEquals("HTTP/1.1", r.body());
            }
        }
    }

    @Test
    void responsesWithoutContentLengthAreChunkedForHttp1Clients() throws Exception {
        byte[] large = H2TestOrigin.bytes(300_000, 3);
        origin(s -> {
            s.readBody();
            s.respond(200, false, "content-type", "application/octet-stream");
            s.data(large, true);
        });
        proxy = mitm().start();
        HttpResponse<byte[]> r = http1Client().send(get(origin.url("/big")), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode());
        assertArrayEquals(large, r.body());
        assertEquals(List.of("chunked"), r.headers().allValues("transfer-encoding"));
    }

    @Test
    void largeBodiesBothWays() throws Exception {
        byte[] upload = H2TestOrigin.bytes(2_000_000, 1);
        origin(s -> {
            byte[] body = s.readBody();
            byte[] out = (body.length + " " + Http2ProxyTest.sha256(body)).getBytes(StandardCharsets.UTF_8);
            s.respond(200, false);
            s.data(out, true);
        });
        proxy = mitm().withHttp2(true).start();
        for (HttpClient client : List.of(http1Client(), http2Client())) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(origin.url("/upload")))
                    .timeout(Duration.ofSeconds(30)).POST(HttpRequest.BodyPublishers.ofByteArray(upload)).build();
            HttpResponse<String> r = TestSupport.send(client, request);
            assertEquals(upload.length + " " + Http2ProxyTest.sha256(upload), r.body());
        }
    }

    @Test
    void aSlowClientHoldsBackTheServerInsteadOfBeingBufferedFor() throws Exception {
        byte[] large = H2TestOrigin.bytes(8 << 20, 5);
        List<H2TestOrigin.Stream> streams = new CopyOnWriteArrayList<>();
        origin(s -> {
            streams.add(s);
            s.readBody();
            s.respond(200, false);
            s.data(large, true);
        });
        int window = 128 * 1024;
        proxy = mitm().withHttp2(true)
                .withHttp2Options(Http2Options.builder().initialWindowSize(window).build()).start();
        try (H2TestClient client = H2TestClient.connect(proxy.getListenAddress(), "localhost:" + origin.port(),
                proxyCa.clientContext()).handshake()) {
            client.get(1, "/large");
            // The client reads the head and then nothing: it never opens its windows.
            client.awaitFrame(f -> f instanceof Frame.Headers h && h.streamId() == 1);
            eventually("the server to wait for window", () -> !streams.isEmpty() && streams.getFirst().blocked);
            long sent = streams.getFirst().sent.get();
            // At most the proxy's stream window, the client's window (64 KiB) and a relay buffer.
            assertTrue(sent <= window + 65_535 + 64 * 1024, "the server sent " + sent + " bytes");
            assertTrue(sent < large.length / 4);
            // Once the client reads, everything arrives.
            H2TestClient.Response r = client.response(1);
            assertNull(r.reset());
            assertEquals(Http2ProxyTest.sha256(large), Http2ProxyTest.sha256(r.body()));
        }
    }

    @Test
    void connectionIsolationFollowsTheMitmManager() throws Exception {
        origin(Http2UpstreamTest::echo);
        // A manager that may set up server TLS differently per client: its connections are never shared.
        MitmManager perClient = new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()) {
            @Override
            public SSLContext serverSslContext(String host, int port, FlowContext flowContext) {
                return originCa.clientContext();
            }
        };
        proxy = MicroProxy.bootstrap().withPort(0).withManInTheMiddle(perClient).withHttp2Upstream(true)
                .withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).start();
        for (int i = 0; i < 3; i++) {
            assertEquals(200, TestSupport.send(http1Client(), get(origin.url("/a"))).statusCode());
        }
        assertEquals(3, origin.accepts.get());
        proxy.abort();

        // A shared manager with the pool on: one connection for every client.
        proxy = mitm().withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).start();
        int before = origin.accepts.get();
        for (int i = 0; i < 3; i++) {
            assertEquals(200, TestSupport.send(http1Client(), get(origin.url("/b"))).statusCode());
        }
        assertEquals(before + 1, origin.accepts.get());
        proxy.abort();

        // Different managers per client connection (forConnection): never the same connection.
        AtomicInteger next = new AtomicInteger();
        MitmManager a = new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext());
        MitmManager b = new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext());
        MitmManager chooser = new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()) {
            @Override
            public MitmManager forConnection(FlowContext flowContext) {
                return next.getAndIncrement() % 2 == 0 ? a : b;
            }
        };
        proxy = MicroProxy.bootstrap().withPort(0).withManInTheMiddle(chooser).withHttp2Upstream(true)
                .withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).start();
        before = origin.accepts.get();
        for (int i = 0; i < 4; i++) {
            assertEquals(200, TestSupport.send(http1Client(), get(origin.url("/c"))).statusCode());
        }
        assertEquals(before + 2, origin.accepts.get(), "one connection per manager");
    }

    @Test
    void hooksFirePerExchangeAndReusedConnectionsLookPooled() throws Exception {
        origin(Http2UpstreamTest::echo);
        List<String> events = new CopyOnWriteArrayList<>();
        AtomicInteger bytesIn = new AtomicInteger();
        AtomicInteger bytesOut = new AtomicInteger();
        List<Integer> statuses = new CopyOnWriteArrayList<>();
        List<FlowTimings> timings = new CopyOnWriteArrayList<>();
        proxy = mitm().withHttp2(true)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
                        events.add("serverConnected");
                    }

                    @Override
                    public void requestSentToServer(FullFlowContext ctx, org.microproxy.http.HttpRequest request) {
                        events.add("requestSent " + request.uri());
                    }

                    @Override
                    public void responseReceivedFromServer(FullFlowContext ctx, org.microproxy.http.HttpResponse response) {
                        events.add("responseReceived " + response.status().code());
                    }

                    @Override
                    public void bytesReceivedFromServer(FullFlowContext ctx, int n) {
                        bytesIn.addAndGet(n);
                    }

                    @Override
                    public void bytesSentToServer(FullFlowContext ctx, int n) {
                        bytesOut.addAndGet(n);
                    }

                    @Override
                    public void responseCompleted(FlowContext ctx, org.microproxy.http.HttpResponse response) {
                        if (ctx.getStreamId() != 0) {
                            statuses.add(ctx.upstreamStatus().orElse(-1));
                            timings.add(ctx.timings());
                        }
                    }
                })
                .withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                    @Override
                    public void proxyToServerConnectionStarted() {
                        events.add("connectionStarted");
                    }

                    @Override
                    public HttpObject serverToProxyResponse(HttpObject o) {
                        if (o instanceof org.microproxy.http.HttpResponse r) events.add("filter " + r.protocolVersion());
                        return o;
                    }
                }).start();
        HttpClient client = http2Client();
        for (int i = 0; i < 3; i++) {
            assertEquals(200, TestSupport.send(client, get(origin.url("/h" + i))).statusCode());
        }
        eventually("three completed exchanges", () -> statuses.size() == 3);
        assertEquals(List.of(200, 200, 200), statuses);
        // One connection (made for the CONNECT), then one stream per exchange.
        assertEquals(1, events.stream().filter(e -> e.equals("serverConnected")).count(), events.toString());
        assertEquals(1, events.stream().filter(e -> e.equals("connectionStarted")).count(), events.toString());
        assertEquals(3, events.stream().filter(e -> e.startsWith("requestSent /h")).count(), events.toString());
        assertEquals(3, events.stream().filter(e -> e.equals("responseReceived 200")).count(), events.toString());
        assertEquals(3, events.stream().filter(e -> e.equals("filter HTTP/2.0")).count(), events.toString());
        assertTrue(bytesIn.get() > 0 && bytesOut.get() > 0);
        for (FlowTimings t : timings) {
            assertTrue(t.requestSentNanos() >= 0 && t.firstResponseByteNanos() >= t.requestSentNanos()
                    && t.responseCompleteNanos() >= t.firstResponseByteNanos(), t.toString());
            // Streams on a connection made earlier: no connection phases of their own.
            assertEquals(-1, t.connectStartNanos(), t.toString());
        }
    }

    @Test
    void anHttp1OnlyClientWithAnHttp2ServerAndExpectContinue() throws Exception {
        origin(Http2UpstreamTest::echo);
        proxy = mitm().start();
        HttpRequest request = HttpRequest.newBuilder(URI.create(origin.url("/continue")))
                .timeout(Duration.ofSeconds(30)).expectContinue(true)
                .POST(HttpRequest.BodyPublishers.ofString("body after continue")).build();
        HttpResponse<String> r = TestSupport.send(http1Client(), request);
        assertEquals(200, r.statusCode());
        assertTrue(r.body().endsWith("\n\nbody after continue"), r.body());
    }

    @Test
    void headRequestsAndEmptyResponses() throws Exception {
        origin(s -> {
            s.readBody();
            if (s.header(":path").equals("/204")) {
                s.respond(204, true);
            } else {
                s.respond(200, true, "content-length", "1234");
            }
        });
        proxy = mitm().withHttp2(true).start();
        for (HttpClient client : List.of(http1Client(), http2Client())) {
            HttpResponse<String> head = TestSupport.send(client, HttpRequest.newBuilder(URI.create(origin.url("/h")))
                    .timeout(Duration.ofSeconds(30)).method("HEAD", HttpRequest.BodyPublishers.noBody()).build());
            assertEquals(200, head.statusCode());
            assertEquals("1234", head.headers().firstValue("content-length").orElseThrow());
            HttpResponse<String> empty = TestSupport.send(client, get(origin.url("/204")));
            assertEquals(204, empty.statusCode());
            assertEquals("", empty.body());
        }
    }

    /** Opens a TLS session through the proxy's CONNECT, as an HTTP/1.1 client. */
    static SSLSocket tunnel(HttpProxyServer proxy, String target) throws IOException {
        InetSocketAddress address = proxy.getListenAddress();
        Socket raw = new Socket(address.getAddress(), address.getPort());
        raw.setSoTimeout(20_000);
        TestSupport.write(raw.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
        String head = TestSupport.readUntil(raw.getInputStream(), "\r\n\r\n");
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        // An HTTP/1.1 client that sends no ALPN: one that offered only http/1.1 would have that
        // offer mirrored to the server, and never get HTTP/2 there (see AlpnMirroringTest).
        SSLSocket tls = (SSLSocket) proxyCa.clientContext().getSocketFactory().createSocket(raw, "localhost", 443, true);
        tls.startHandshake();
        return tls;
    }

    @Test
    void http1ChunkedTrailersReachTheServerAndComeBack() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        origin(s -> {
            byte[] body = s.readBody();
            seen.add(s.header("te") + " " + s.trailer("x-checksum") + " " + new String(body, StandardCharsets.UTF_8));
            s.respond(200, false, "content-type", "text/plain");
            s.data("response".getBytes(StandardCharsets.UTF_8), false);
            s.trailers("grpc-status", "0", "grpc-message", "fine");
        });
        proxy = mitm().start();
        try (SSLSocket tls = tunnel(proxy, "localhost:" + origin.port())) {
            OutputStream out = tls.getOutputStream();
            TestSupport.write(out, "POST /trailers HTTP/1.1\r\nHost: localhost:" + origin.port()
                    + "\r\nTE: trailers\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + "5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n");
            InputStream in = tls.getInputStream();
            String response = TestSupport.readUntil(in, "\r\n0\r\n");
            String trailers = TestSupport.readUntil(in, "\r\n\r\n");
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            assertTrue(response.toLowerCase().contains("transfer-encoding: chunked"), response);
            assertTrue(response.contains("response"), response);
            assertTrue(trailers.contains("grpc-status: 0"), trailers);
            assertTrue(trailers.contains("grpc-message: fine"), trailers);
        }
        assertEquals(List.of("trailers abc hello"), seen);
    }

    @Test
    void aClientThatNeverSendsItsClientHelloDoesNotHoldUpOthers() throws Exception {
        origin(Http2UpstreamTest::echo);
        // Shared connections, so the second client would wait for the first one's.
        proxy = mitm().withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).start();
        try (Socket silent = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            silent.setSoTimeout(20_000);
            String target = "localhost:" + origin.port();
            TestSupport.write(silent.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
            String head = TestSupport.readUntil(silent.getInputStream(), "\r\n\r\n");
            assertTrue(head.startsWith("HTTP/1.1 200"), head);
            // The first client's connection to the server is made, and waits for a ClientHello
            // that never comes. Another client's request completes well within the connect
            // timeout (40 s), which it would otherwise wait out.
            long start = System.nanoTime();
            HttpResponse<String> response = TestSupport.send(http1Client(), get(origin.url("/other")));
            long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertEquals(200, response.statusCode());
            assertTrue(millis < 5_000, "took " + millis + " ms");
            assertEquals(List.of("/other"), lines(response.body(), ":path"));
        }
    }

    @Test
    void theProxyStoppingClosesServerConnections() throws Exception {
        origin(Http2UpstreamTest::echo);
        proxy = mitm().withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).start();
        assertEquals(200, TestSupport.send(http1Client(), get(origin.url("/"))).statusCode());
        assertEquals(1, origin.connections.size());
        proxy.stop();
        proxy = null;
        eventually("the server connection to close", () -> origin.connections.getFirst().socket.isClosed()
                || isClosedByPeer(origin.connections.getFirst()));
        assertFalse(origin.connections.isEmpty());
    }

    private static boolean isClosedByPeer(H2TestOrigin.Conn c) {
        return c.socket.isClosed() || c.socket.isInputShutdown();
    }

    @Test
    void connectionsCarryingAProxyHeaderServeOneClientOnly() throws Exception {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.proxyProtocol = true;
        origin(options, Http2UpstreamTest::echo);
        // Even with the shared pool on: each connection names its client in its PROXY header.
        proxy = mitm().withSendProxyProtocol(true)
                .withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).start();
        for (int i = 0; i < 3; i++) {
            HttpClient client = http1Client();
            assertEquals(200, TestSupport.send(client, get(origin.url("/p" + i))).statusCode());
            assertEquals(200, TestSupport.send(client, get(origin.url("/q" + i))).statusCode());
        }
        assertEquals(3, origin.accepts.get(), "one connection per client connection");
        assertEquals(3, origin.proxyHeaders.size());
        assertTrue(origin.proxyHeaders.stream().allMatch(h -> h.startsWith("PROXY TCP4 127.0.0.1 ")), origin.proxyHeaders.toString());
        assertEquals(3, origin.proxyHeaders.stream().distinct().count(), "a client each");
    }

    @Test
    void http2InsideAChainedProxysConnectTunnel() throws Exception {
        origin(Http2UpstreamTest::echo);
        ChainTestSupport.RequestLog upstreamLog = new ChainTestSupport.RequestLog();
        HttpProxyServer upstream = MicroProxy.bootstrap().withPort(0).plusActivityTracker(upstreamLog).start();
        closeables.add(upstream::abort);
        proxy = mitm().withHttp2(true)
                .withChainProxyManager(ChainTestSupport.always(ChainTestSupport.http(upstream.getListenAddress())))
                .start();
        HttpClient client = http2Client();
        for (int i = 0; i < 3; i++) {
            HttpResponse<String> r = TestSupport.send(client, get(origin.url("/chained" + i)));
            assertEquals(200, r.statusCode());
            // (The test origin speaks nothing but HTTP/2.)
            assertEquals(List.of("/chained" + i), lines(r.body(), ":path"));
        }
        assertEquals(1, origin.accepts.get());
        assertEquals(List.of("CONNECT localhost:" + origin.port()), upstreamLog.received);
    }

    @Test
    void aServerThatDropsTheConnectionFailsItsExchanges() throws Exception {
        origin(s -> {
            s.readBody();
            if (s.header(":path").equals("/midway")) {
                s.respond(200, false);
                s.data(new byte[100], false);
            }
            s.conn.socket.close();
        });
        proxy = mitm().withHttp2(true).start();
        assertEquals(502, TestSupport.send(http1Client(), get(origin.url("/before"))).statusCode());
        try (H2TestClient client = H2TestClient.connect(proxy.getListenAddress(), "localhost:" + origin.port(),
                proxyCa.clientContext()).handshake()) {
            client.get(1, "/before");
            assertEquals(502, client.response(1).status());
            client.get(3, "/midway");
            H2TestClient.Response r = client.response(3);
            assertEquals(200, r.status());
            assertNotNull(r.reset(), "the response had started: the client's stream is reset");
        }
    }
}
