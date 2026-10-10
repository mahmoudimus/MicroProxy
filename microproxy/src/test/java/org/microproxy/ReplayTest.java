package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.extras.ClientReplay;
import org.microproxy.extras.HarRecorder;
import org.microproxy.extras.ModifyHeaders;
import org.microproxy.extras.RecordedExchange;
import org.microproxy.extras.ServerReplay;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.warc.WarcRecorder;

/** Recording traffic as HAR or WARC, then replaying it: server replay and client replay. */
class ReplayTest {

    @TempDir
    Path dir;
    private HttpServer origin;
    private HttpProxyServer proxy;
    private final AtomicInteger hits = new AtomicInteger();
    private final List<String> received = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() {
        origin = startOrigin();
    }

    private HttpServer startOrigin() {
        return TestSupport.origin(exchange -> {
            int n = hits.incrementAndGet();
            byte[] in = exchange.getRequestBody().readAllBytes();
            received.add(exchange.getRequestMethod() + " " + exchange.getRequestURI() + " "
                    + exchange.getRequestHeaders().getFirst("X-Replayed") + " " + new String(in, StandardCharsets.UTF_8));
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            if (path.equals("/gzip")) {
                body = HttpBodiesTest.gzip("zipped text".getBytes(StandardCharsets.UTF_8));
                exchange.getResponseHeaders().set("Content-Encoding", "gzip");
                exchange.getResponseHeaders().set("Content-Type", "text/plain");
            } else {
                body = ("call " + n + " " + path + (in.length > 0 ? " got " + new String(in, StandardCharsets.UTF_8) : ""))
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            }
            exchange.getResponseHeaders().set("X-Origin", "live");
            // Length 0: chunked, so the recorders must de-chunk.
            exchange.sendResponseHeaders(200, path.equals("/chunked") ? 0 : body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    /** Records some traffic with {@code recorder} first among the filters. */
    private void record(HttpFiltersSource recorder) {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(recorder).start();
        HttpClient client = client(proxy);
        get(client, url(origin, "/seq"));
        get(client, url(origin, "/seq"));
        get(client, url(origin, "/gzip"));
        get(client, url(origin, "/chunked"));
        send(client, HttpRequest.newBuilder(URI.create(url(origin, "/form?_=1")))
                .POST(HttpRequest.BodyPublishers.ofString("x=1")).build());
        proxy.stop();
        proxy = null;
    }

    private List<ResponseSource> sources = new CopyOnWriteArrayList<>();

    private HttpClient replaying(ServerReplay replay) {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(replay)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void responseSentToClient(FlowContext ctx, org.microproxy.http.HttpResponse r, ResponseSource s) {
                        sources.add(s);
                    }
                }).start();
        return client(proxy);
    }

    private static String gunzip(byte[] data) throws IOException {
        return new String(new GZIPInputStream(new ByteArrayInputStream(data)).readAllBytes(), StandardCharsets.UTF_8);
    }

    private void assertReplays(ServerReplay replay, boolean warc) throws IOException, InterruptedException {
        int before = hits.get();
        HttpClient client = replaying(replay);
        assertEquals("call 1 /seq", get(client, url(origin, "/seq")).body());
        assertEquals("call 2 /seq", get(client, url(origin, "/seq")).body(), "recordings replay in order");
        HttpResponse<byte[]> gzip = client.send(HttpRequest.newBuilder(URI.create(url(origin, "/gzip"))).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        if (warc) {
            // WARC keeps the coding the body was received with.
            assertEquals("gzip", gzip.headers().firstValue("Content-Encoding").orElseThrow());
            assertEquals("zipped text", gunzip(gzip.body()));
        } else {
            // HAR stores the decoded body.
            assertTrue(gzip.headers().firstValue("Content-Encoding").isEmpty());
            assertEquals("zipped text", new String(gzip.body(), StandardCharsets.UTF_8));
        }
        assertEquals("call 4 /chunked", get(client, url(origin, "/chunked")).body());
        HttpResponse<String> form = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/form?_=2")))
                .POST(HttpRequest.BodyPublishers.ofString("x=1")).build());
        assertEquals("call 5 /form got x=1", form.body(), "the _ parameter is ignored, the body matches");
        assertEquals("live", form.headers().firstValue("X-Origin").orElseThrow());
        assertEquals(before, hits.get(), "no server was contacted");
        TestSupport.eventually("five sources", () -> sources.size() == 5);
        assertEquals(List.of(ResponseSource.REPLAY), sources.stream().distinct().toList());
        assertEquals(0, replay.remaining());
    }

    @Test
    void harExportReplaysAsServerResponses() throws Exception {
        Path file = dir.resolve("flows.har");
        HarRecorder har = HarRecorder.builder(file).build();
        record(har);
        har.close();
        assertEquals(5, RecordedExchange.load(file).size());
        assertReplays(ServerReplay.builder().load(file).ignoreParams("_").build(), false);
    }

    @Test
    void warcRecordingsReplayAsServerResponses() throws Exception {
        Path warcs = dir.resolve("warcs");
        WarcRecorder recorder = WarcRecorder.builder(warcs).build();
        record(recorder);
        recorder.close();
        List<RecordedExchange> read = RecordedExchange.load(warcs);
        assertEquals(5, read.size());
        assertEquals("POST", read.get(4).method());
        assertEquals("x=1", new String(read.get(4).requestBody(), StandardCharsets.UTF_8));
        assertReplays(ServerReplay.builder().load(warcs).ignoreParams("_").build(), true);
    }

    @Test
    void unmatchedRequestsAreForwardedAnsweredOrKilled() throws Exception {
        Path file = dir.resolve("one.har");
        HarRecorder har = HarRecorder.builder(file).build();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(har).start();
        get(client(proxy), url(origin, "/only"));
        proxy.stop();
        har.close();

        HttpClient forward = replaying(ServerReplay.builder().load(file).build());
        assertEquals("call 2 /other", get(forward, url(origin, "/other")).body());
        proxy.stop();
        HttpClient answer = replaying(ServerReplay.builder().load(file).extra(ServerReplay.Extra.status(404)).build());
        assertEquals(404, get(answer, url(origin, "/other")).statusCode());
        proxy.stop();
        replaying(ServerReplay.builder().load(file).extra(ServerReplay.Extra.kill()).build());
        assertEquals("", TestSupport.rawExchange(proxy.getListenAddress(), "GET " + url(origin, "/other")
                + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
        assertEquals(2, hits.get());
    }

    @Test
    void clientReplaySendsRecordedRequestsThroughTheFilters() throws Exception {
        Path file = dir.resolve("client.har");
        HarRecorder har = HarRecorder.builder(file).build();
        record(har);
        har.close();
        received.clear();

        Path again = dir.resolve("again.har");
        HarRecorder second = HarRecorder.builder(again).build();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(HttpFiltersChain.of(second, ModifyHeaders.of("|~q|X-Replayed|yes"))).start();
        ClientReplay.Result result = ClientReplay.builder(proxy.getListenAddress()).concurrency(2).build()
                .replay(RecordedExchange.load(file));
        assertEquals(5, result.sent());
        assertEquals(0, result.failed());
        assertEquals(List.of(200, 200, 200, 200, 200), result.statuses());
        assertEquals(5, received.size());
        assertTrue(received.stream().allMatch(r -> r.contains(" yes ")), "filters applied: " + received);
        assertTrue(received.contains("POST /form?_=1 yes x=1"), received.toString());
        TestSupport.eventually("five new entries", () -> second.recordedEntries() == 5);
        second.close();
        assertEquals(5, RecordedExchange.load(again).size());
    }

    @Test
    void clientReplayOfHttpsUrlsUsesTls() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Replay Origin CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"),
                TestSupport.fixed(200, "secure hello"));
        try {
            RecordedExchange e = new RecordedExchange(null, "GET", url(secure, "/s"), List.of(), new byte[0], 0, "",
                    List.of(), new byte[0], true);
            proxy = MicroProxy.bootstrap().withPort(0)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(
                            CertificateAuthority.generate("Replay Proxy CA"), originCa.clientContext()))
                    .start();
            ClientReplay.Result result = ClientReplay.builder(proxy.getListenAddress()).build().replay(List.of(e));
            assertEquals(List.of(200), result.statuses());
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void recordingsMayBeDirectoriesOfFiles() throws Exception {
        Path recordings = Files.createDirectories(dir.resolve("mixed"));
        HarRecorder har = HarRecorder.builder(recordings.resolve("a.har")).build();
        record(har);
        har.close();
        Files.writeString(recordings.resolve("notes.txt"), "ignored");
        assertEquals(5, RecordedExchange.load(recordings).size());
    }
}
