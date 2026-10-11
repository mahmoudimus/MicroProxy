package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3FrameWriter;
import io.github.mahmoudimus.http3.Http3StreamType;
import io.github.mahmoudimus.http3.QpackEncoder;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * The HTTP/3 listener's limits and protocol handling: the stream limit, header section size,
 * QPACK abuse, unknown frames and streams, rapid resets, malformed requests, CONNECT, GOAWAY on a
 * graceful stop, and the exchange as filters see it.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3HardeningTest {

    private final CountDownLatch release = new CountDownLatch(1);
    private final java.util.concurrent.atomic.AtomicInteger slowArrived = new java.util.concurrent.atomic.AtomicInteger();
    private HttpServer origin;
    private HttpProxyServer proxy;
    private SelfSignedSslContextSource tls;

    @AfterEach
    void tearDown() {
        release.countDown();
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    /** A reverse proxy for an origin whose {@code /slow} waits for {@link #release}. */
    private void start(Consumer<HttpProxyServerBootstrap> configure) {
        origin = TestSupport.origin(exchange -> {
            if (exchange.getRequestURI().getPath().equals("/slow")) {
                slowArrived.incrementAndGet();
                try {
                    release.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            TestSupport.echo().handle(exchange);
        });
        tls = new SelfSignedSslContextSource();
        HttpProxyServerBootstrap b = MicroProxy.bootstrap()
                .withPort(0)
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withSslContextSource(tls)
                .withHttp3(true);
        configure.accept(b);
        proxy = b.start();
    }

    private H3TestClient client() throws IOException {
        return client(new H3TestClient.Options());
    }

    private H3TestClient client(H3TestClient.Options options) throws IOException {
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        return H3TestClient.connect(address, "localhost", tls.getCertificate(), options);
    }

    private static long closeCode(H3TestClient client) throws IOException {
        ConnectionError e = client.quic.awaitClosed(Duration.ofSeconds(10));
        assertNotNull(e, "the proxy closed the connection");
        assertEquals(ConnectionError.Kind.APPLICATION_CLOSED, e.kind(), e.toString());
        return e.code();
    }

    @Test
    void theStreamLimitIsQuics() throws Exception {
        start(b -> b.withHttp3Options(Http3Options.builder().maxConcurrentStreams(2).build()));
        try (H3TestClient client = client(); ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<H3TestClient.Response> a = pool.submit(() -> client.get("/slow"));
            Future<H3TestClient.Response> b = pool.submit(() -> client.get("/slow"));
            TestSupport.eventually("two slow requests at the origin", () -> slowArrived.get() == 2);
            // A third stream waits until the client may open it: QUIC holds it back.
            Future<H3TestClient.Response> c = pool.submit(() -> client.get("/fast"));
            assertThrows(TimeoutException.class, () -> c.get(300, TimeUnit.MILLISECONDS));
            release.countDown();
            assertEquals(200, a.get().status());
            assertEquals(200, b.get().status());
            assertEquals(200, c.get().status());
        }
    }

    @Test
    void anOversizedHeaderSectionIsAnswered431AndTheConnectionGoesOn() throws Exception {
        start(b -> b.withMaxHeaderSize(2048).withMaxInitialLineLength(1024));
        H3TestClient.Options careless = new H3TestClient.Options();
        careless.obeyFieldSectionSize = false;
        try (H3TestClient client = client(careless)) {
            assertEquals(3072, client.serverSettings().maxFieldSectionSize(), "the HTTP/1 parser limits, together");
            H3TestClient.Response r = client.request("GET", "/x",
                    List.of(new HeaderField("x-big", "v".repeat(5000))), null, List.of());
            assertEquals(431, r.status());
            assertEquals(200, client.get("/after").status());
        }
    }

    @Test
    void aQpackBombIsStoppedByTheSectionSize() throws Exception {
        start(b -> b.withMaxHeaderSize(8192));
        H3TestClient.Options careless = new H3TestClient.Options();
        careless.obeyFieldSectionSize = false;
        try (H3TestClient client = client(careless)) {
            client.serverSettings();
            // One 3000-byte entry, referenced ten times: 30 KB decoded from a few bytes.
            List<HeaderField> fields = new ArrayList<>();
            for (int i = 0; i < 10; i++) fields.add(new HeaderField("x-bomb", "b".repeat(3000)));
            H3TestClient.Response r = client.request("GET", "/bomb", fields, null, List.of());
            assertEquals(431, r.status());
            assertEquals(200, client.get("/after").status(), "the decoder stayed in step with the encoder");
        }
    }

    @Test
    void tooManyBlockedStreamsCloseTheConnection() throws Exception {
        start(b -> b.withHttp3Options(Http3Options.builder().qpackBlockedStreams(2).build()));
        try (H3TestClient client = client()) {
            assertEquals(2, client.serverSettings().qpackBlockedStreams());
            // Sections that reference entries whose instructions never arrive block their streams.
            QpackEncoder withheld = new QpackEncoder(4096);
            withheld.setPeerSettings(4096, 100);
            for (int i = 0; i < 3; i++) {
                QuicStream s = client.quic.openBidirectionalStream();
                OutputStream out = s.getOutputStream();
                new Http3FrameWriter(out).writeHeaders(withheld.encode(s.id(),
                        client.head("GET", "/blocked/" + i, List.of(new HeaderField("x-unique", "value-" + i)))));
                out.close();
            }
            assertEquals(0x0200, closeCode(client), "QPACK_DECOMPRESSION_FAILED");
        }
    }

    @Test
    void aBadEncoderStreamClosesTheConnection() throws Exception {
        start(b -> {});
        try (H3TestClient client = client()) {
            client.serverSettings();
            // Set Dynamic Table Capacity far above SETTINGS_QPACK_MAX_TABLE_CAPACITY.
            client.encoderOut.write(new byte[] {0x3f, (byte) 0xe1, (byte) 0xff, (byte) 0xff, 0x0f});
            client.encoderOut.flush();
            assertEquals(0x0201, closeCode(client), "QPACK_ENCODER_STREAM_ERROR");
        }
    }

    @Test
    void unknownFramesAreIgnoredWithinALimit() throws Exception {
        start(b -> b.withHttp3Options(Http3Options.builder().maxUnknownFrames(50).build()));
        try (H3TestClient client = client()) {
            // A few grease frames are fine.
            QuicStream s = client.quic.openBidirectionalStream();
            OutputStream out = s.getOutputStream();
            Http3FrameWriter w = new Http3FrameWriter(out);
            w.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Unknown(0x21, new byte[] {1, 2, 3}));
            w.writeHeaders(client.encode(s.id(), client.head("GET", "/grease", List.of())));
            w.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Unknown(0x40, new byte[0]));
            out.close();
            assertEquals(200, client.readResponse(s).status());
            // Many are a flood.
            QuicStream flood = client.quic.openBidirectionalStream();
            OutputStream fo = flood.getOutputStream();
            Http3FrameWriter fw = new Http3FrameWriter(fo);
            fw.writeHeaders(client.encode(flood.id(), client.head("POST", "/flood", List.of())));
            for (int i = 0; i < 100; i++) fw.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Unknown(0x21, new byte[0]));
            fo.flush();
            assertEquals(0x0107, closeCode(client), "H3_EXCESSIVE_LOAD");
        }
    }

    @Test
    void unknownStreamsAreAbandonedWithinALimit() throws Exception {
        start(b -> b.withHttp3Options(Http3Options.builder().maxUnknownStreams(5).build()));
        try (H3TestClient client = client()) {
            client.serverSettings();
            for (int i = 0; i < 10 && client.quic.isOpen(); i++) {
                QuicStream s = client.quic.openUnidirectionalStream();
                OutputStream out = s.getOutputStream();
                out.write(Http3StreamType.encode(0x21 + 0x1fL * i)); // reserved (grease) stream types
                out.write("ignored".getBytes(StandardCharsets.US_ASCII));
                out.close();
            }
            assertEquals(0x0107, closeCode(client), "H3_EXCESSIVE_LOAD");
        }
    }

    @Test
    void rapidResetsCloseTheConnection() throws Exception {
        start(b -> b.withHttp3Options(Http3Options.builder().maxRapidResets(3).build()));
        try (H3TestClient client = client()) {
            for (int i = 0; i < 6 && client.quic.isOpen(); i++) {
                QuicStream s = client.send(client.head("GET", "/slow", List.of()), true);
                s.reset(0x010c);
                s.stopSending(0x010c);
            }
            assertEquals(0x0107, closeCode(client), "H3_EXCESSIVE_LOAD");
        }
    }

    @Test
    void malformedRequestsResetTheirStreamOnly() throws Exception {
        start(b -> {});
        try (H3TestClient client = client()) {
            QuicStream s = client.send(List.of(new HeaderField(":method", "GET"), new HeaderField(":scheme", "https")), true);
            QuicStreamException e = assertThrows(QuicStreamException.class, () -> client.readResponse(s));
            assertEquals(0x010e, e.errorCode(), "H3_MESSAGE_ERROR");
            assertEquals(200, client.get("/still-fine").status());
        }
    }

    @Test
    void aReverseProxyRefusesConnectAndUnknownExtendedConnects() throws Exception {
        start(b -> {});
        try (H3TestClient client = client()) {
            QuicStream s = client.send(List.of(new HeaderField(":method", "CONNECT"),
                    new HeaderField(":authority", "example.com:443")), false);
            assertEquals(400, client.readResponse(s).status(), "a reverse proxy opens no tunnels");
            QuicStream wt = client.send(List.of(new HeaderField(":method", "CONNECT"), new HeaderField(":protocol", "webtransport"),
                    new HeaderField(":scheme", "https"), new HeaderField(":authority", "localhost"),
                    new HeaderField(":path", "/chat")), false);
            assertEquals(501, client.readResponse(wt).status());
            QuicStream udp = client.send(List.of(new HeaderField(":method", "CONNECT"), new HeaderField(":protocol", "connect-udp"),
                    new HeaderField(":scheme", "https"), new HeaderField(":authority", "localhost"),
                    new HeaderField(":path", "/.well-known/masque/udp/127.0.0.1/53/")), false);
            assertEquals(501, client.readResponse(udp).status(), "a reverse proxy proxies no UDP");
        }
    }

    @Test
    void aGracefulStopSendsGoAwayAndFinishesTheStreamsInProgress() throws Exception {
        start(b -> {});
        try (H3TestClient client = client(); ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            assertEquals(200, client.get("/first").status());
            Future<H3TestClient.Response> slow = pool.submit(() -> client.get("/slow"));
            TestSupport.eventually("the slow request to reach the origin", () -> slowArrived.get() == 1);
            Future<?> stopping = pool.submit(proxy::stop);
            long goAway = client.awaitGoAway(Duration.ofSeconds(10));
            assertTrue(goAway >= 8, "GOAWAY names the first stream not processed: " + goAway);
            // A stream opened after GOAWAY is refused, to be retried elsewhere.
            QuicStream late = client.send(client.head("GET", "/late", List.of()), true);
            QuicStreamException refused = assertThrows(QuicStreamException.class, () -> client.readResponse(late));
            assertEquals(0x010b, refused.errorCode(), "H3_REQUEST_REJECTED");
            release.countDown();
            assertEquals(200, slow.get().status(), "the stream in progress completes");
            stopping.get(20, TimeUnit.SECONDS);
            proxy = null;
        }
    }

    @Test
    void filtersSeeHttp3Requests() throws Exception {
        List<String> seen = new java.util.concurrent.CopyOnWriteArrayList<>();
        start(b -> b.withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                seen.add(originalRequest.method() + " " + originalRequest.uri() + " " + originalRequest.protocolVersion()
                        + " " + ctx.getHttpVersion() + " stream=" + ctx.getStreamId());
                return new HttpFiltersAdapter(originalRequest, ctx) {
                    @Override
                    public HttpObject proxyToClientResponse(HttpObject httpObject) {
                        if (httpObject instanceof HttpResponse r) r.headers().set("x-filtered", "yes");
                        return httpObject;
                    }
                };
            }
        }));
        try (H3TestClient client = client()) {
            H3TestClient.Response r = client.get("/filtered");
            assertEquals("yes", r.header("x-filtered"));
            client.get("/second");
        }
        assertEquals(List.of("GET /filtered HTTP/3.0 HTTP/3.0 stream=0", "GET /second HTTP/3.0 HTTP/3.0 stream=4"), seen);
        assertEquals(HttpVersion.HTTP_3_0, HttpVersion.valueOf("HTTP/3.0"));
    }
}
