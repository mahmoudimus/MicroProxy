package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;

/** HAR files written by {@link HarRecorder}, checked by parsing them back. */
class HarRecorderTest {

    static final byte[] IMAGE = {(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10, 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 1, 2, 3,
        (byte) 0xff, (byte) 0xfe, 0, 0, 1};

    @TempDir
    Path dir;
    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(exchange -> {
            byte[] in = exchange.getRequestBody().readAllBytes();
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            switch (path) {
                case "/gzip" -> {
                    body = gzip("<h1>compressed page</h1>");
                    exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
                    exchange.getResponseHeaders().set("Content-Encoding", "gzip");
                }
                case "/image" -> {
                    body = IMAGE;
                    exchange.getResponseHeaders().set("Content-Type", "image/png");
                }
                case "/big" -> {
                    body = "x".repeat(5000).getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "text/plain");
                }
                default -> {
                    body = ("hello " + exchange.getRequestURI() + (in.length > 0 ? " got " + new String(in, StandardCharsets.UTF_8) : ""))
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
                    exchange.getResponseHeaders().add("Set-Cookie", "sid=xyz; Path=/; HttpOnly; Secure; SameSite=Lax; "
                            + "Expires=Wed, 21 Oct 2037 07:28:00 GMT");
                }
            }
            exchange.getResponseHeaders().set("Location", "/next");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    static byte[] gzip(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(s.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
        return out.toByteArray();
    }

    private HttpClient start(HttpFiltersSource... sources) {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(HttpFiltersChain.of(sources)).start();
        return client(proxy);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) {
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o) {
        return (List<Object>) o;
    }

    private static List<Map<String, Object>> entries(Path har) throws IOException {
        Map<String, Object> log = obj(obj(Json.parse(Files.readString(har))).get("log"));
        assertEquals("1.2", log.get("version"));
        assertEquals("MicroProxy", obj(log.get("creator")).get("name"));
        assertEquals(List.of(), log.get("pages"));
        return list(log.get("entries")).stream().map(HarRecorderTest::obj).toList();
    }

    private static String nameValue(Object list, String name) {
        for (Object o : list(list)) {
            Map<String, Object> m = obj(o);
            if (name.equalsIgnoreCase((String) m.get("name"))) return (String) m.get("value");
        }
        return null;
    }

    @Test
    void writesAStructurallyValidHar() throws Exception {
        Path file = dir.resolve("out/flows.har");
        HarRecorder har = HarRecorder.builder(file).build();
        HttpClient client = start(har, BlockList.of("|~u /blocked|403"));
        send(client, HttpRequest.newBuilder(URI.create(url(origin, "/text?a=1&b=two%20words")))
                .header("Cookie", "c=1; d=2").build());
        get(client, url(origin, "/gzip"));
        send(client, HttpRequest.newBuilder(URI.create(url(origin, "/image"))).build());
        send(client, HttpRequest.newBuilder(URI.create(url(origin, "/form")))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("x=1&y=hello+world")).build());
        assertEquals(403, get(client, url(origin, "/blocked")).statusCode());
        TestSupport.eventually("five entries", () -> har.recordedEntries() == 5);
        assertFalse(Files.exists(file), "written on close");
        har.close();

        List<Map<String, Object>> entries = entries(file);
        assertEquals(5, entries.size());

        Map<String, Object> text = entries.get(0);
        Map<String, Object> req = obj(text.get("request"));
        assertEquals("GET", req.get("method"));
        assertEquals(url(origin, "/text?a=1&b=two%20words"), req.get("url"));
        assertEquals("HTTP/1.1", req.get("httpVersion"));
        assertEquals("c=1; d=2", nameValue(req.get("headers"), "Cookie"));
        assertEquals("1", nameValue(req.get("cookies"), "c"));
        assertEquals("2", nameValue(req.get("cookies"), "d"));
        assertEquals("1", nameValue(req.get("queryString"), "a"));
        assertEquals("two words", nameValue(req.get("queryString"), "b"));
        assertEquals(0L, req.get("bodySize"));
        assertTrue((Long) req.get("headersSize") > 0);
        assertNull(req.get("postData"));
        Map<String, Object> res = obj(text.get("response"));
        assertEquals(200L, res.get("status"));
        assertEquals("OK", res.get("statusText"));
        assertEquals("/next", res.get("redirectURL"));
        Map<String, Object> content = obj(res.get("content"));
        assertEquals("hello /text?a=1&b=two%20words", content.get("text"));
        assertEquals("text/plain; charset=utf-8", content.get("mimeType"));
        assertNull(content.get("encoding"));
        Map<String, Object> cookie = obj(list(res.get("cookies")).getFirst());
        assertEquals("sid", cookie.get("name"));
        assertEquals("xyz", cookie.get("value"));
        assertEquals("/", cookie.get("path"));
        assertEquals(true, cookie.get("httpOnly"));
        assertEquals(true, cookie.get("secure"));
        assertEquals("Lax", cookie.get("sameSite"));
        assertEquals("2037-10-21T07:28:00Z", cookie.get("expires"));
        Instant started = Instant.parse((String) text.get("startedDateTime"));
        assertTrue(Math.abs(started.toEpochMilli() - System.currentTimeMillis()) < 60_000);
        Map<String, Object> timings = obj(text.get("timings"));
        for (String phase : List.of("send", "wait", "receive")) {
            assertTrue(((Number) timings.get(phase)).doubleValue() >= 0, phase);
        }
        for (String phase : List.of("blocked", "dns", "connect", "ssl")) {
            double v = ((Number) timings.get(phase)).doubleValue();
            assertTrue(v == -1 || v >= 0, phase);
        }
        assertTrue(((Number) timings.get("connect")).doubleValue() >= 0, "a new connection");
        assertTrue(((Number) text.get("time")).doubleValue() >= 0);
        assertEquals("127.0.0.1", text.get("serverIPAddress"));
        assertEquals("server", text.get("_source"));
        assertEquals(Map.of(), text.get("cache"));

        Map<String, Object> gz = obj(obj(entries.get(1).get("response")).get("content"));
        assertEquals("<h1>compressed page</h1>", gz.get("text"), "decoded");
        assertEquals(24L, gz.get("size"));
        assertEquals(24L - gzip("<h1>compressed page</h1>").length, gz.get("compression"));
        assertEquals("gzip", nameValue(obj(entries.get(1).get("response")).get("headers"), "Content-Encoding"));
        assertEquals("127.0.0.1", entries.get(1).get("serverIPAddress"), "known for a reused connection too");

        Map<String, Object> image = obj(obj(entries.get(2).get("response")).get("content"));
        assertEquals("base64", image.get("encoding"));
        assertArrayEquals(IMAGE, Base64.getDecoder().decode((String) image.get("text")));

        Map<String, Object> post = obj(obj(entries.get(3).get("request")).get("postData"));
        assertEquals("application/x-www-form-urlencoded", post.get("mimeType"));
        assertEquals("x=1&y=hello+world", post.get("text"));
        assertEquals("hello world", nameValue(post.get("params"), "y"));
        assertEquals(17L, obj(entries.get(3).get("request")).get("bodySize"));

        Map<String, Object> blocked = entries.get(4);
        assertEquals(403L, obj(blocked.get("response")).get("status"));
        assertEquals("filter", blocked.get("_source"));
        assertNull(blocked.get("serverIPAddress"));
        Map<String, Object> blockedTimings = obj(blocked.get("timings"));
        assertEquals(0L, blockedTimings.get("send"));
        assertEquals(0L, blockedTimings.get("wait"));

        // And it reads back for replay.
        List<RecordedExchange> read = RecordedExchange.readHar(file);
        assertEquals(5, read.size());
        assertEquals("<h1>compressed page</h1>", new String(read.get(1).responseBody(), StandardCharsets.UTF_8));
        assertNull(read.get(1).responseHeader("Content-Encoding"), "the body is stored decoded");
        assertArrayEquals(IMAGE, read.get(2).responseBody());
        assertEquals("x=1&y=hello+world", new String(read.get(3).requestBody(), StandardCharsets.UTF_8));
    }

    @Test
    void filtersLimitsAndStreaming() throws Exception {
        Path file = dir.resolve("streamed.zhar");
        HarRecorder har = HarRecorder.builder(file).stream(true).maxBodySize(100)
                .filter(FlowFilter.parse("!~u /image")).build();
        assertTrue(Files.exists(file), "a streamed file exists from the start");
        HttpClient client = start(har);
        get(client, url(origin, "/big"));
        get(client, url(origin, "/image"));
        get(client, url(origin, "/text"));
        TestSupport.eventually("two entries", () -> har.recordedEntries() == 2);
        har.close();
        List<RecordedExchange> read = RecordedExchange.readHar(file);
        assertEquals(2, read.size());
        RecordedExchange big = read.getFirst();
        assertFalse(big.complete(), "truncated");
        assertFalse(big.replayable());
        assertEquals(100, big.responseBody().length);
        assertTrue(read.get(1).complete());
        assertTrue(read.get(1).url().endsWith("/text"));
    }

    @Test
    void headsOnlyKeepBodiesOut() throws Exception {
        Path file = dir.resolve("heads.har");
        HarRecorder har = HarRecorder.builder(file).content(false).build();
        HttpClient client = start(har);
        get(client, url(origin, "/big"));
        TestSupport.eventually("an entry", () -> har.recordedEntries() == 1);
        har.save(dir.resolve("copy.har"));
        har.close();
        Map<String, Object> entry = entries(file).getFirst();
        Map<String, Object> content = obj(obj(entry.get("response")).get("content"));
        assertNull(content.get("text"));
        assertEquals(5000L, content.get("size"));
        assertEquals(1, entries(dir.resolve("copy.har")).size());
    }

    @Test
    void mostlyBinaryFollowsMitmproxy() {
        assertFalse(HarRecorder.isMostlyBinary("plain text".getBytes(StandardCharsets.UTF_8)));
        assertFalse(HarRecorder.isMostlyBinary("ünïcödé ünïcödé ünïcödé".getBytes(StandardCharsets.UTF_8)));
        assertTrue(HarRecorder.isMostlyBinary(IMAGE));
        assertTrue(HarRecorder.isMostlyBinary(new byte[] {0, 0, 0, 0}));
        assertFalse(HarRecorder.isMostlyBinary(new byte[0]));
    }
}
