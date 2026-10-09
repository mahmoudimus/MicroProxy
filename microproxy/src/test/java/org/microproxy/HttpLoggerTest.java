package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpFiltersBuilder.Body;
import org.microproxy.WebSocketTestSupport.EchoServer;
import org.microproxy.extras.HttpLogger;
import org.microproxy.extras.HttpLogger.Format;
import org.microproxy.extras.HttpLogger.Level;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

class HttpLoggerTest {

    private static final Pattern PREFIX = Pattern.compile("^\\[conn (\\d+) #(\\d+)] ");

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final List<String> out = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(echo());
        origin.createContext("/error", TestSupport.fixed(500, "server broke"));
        origin.createContext("/gzip", exchange -> {
            byte[] body = HttpBodiesTest.gzip("décodé ".repeat(20).getBytes(StandardCharsets.UTF_8));
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            exchange.getResponseHeaders().set("Content-Encoding", "gzip");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        origin.createContext("/binary", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
            exchange.sendResponseHeaders(200, 1000);
            exchange.getResponseBody().write(new byte[1000]);
            exchange.close();
        });
        origin.createContext("/cookie", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Set-Cookie", "session=topsecret");
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private HttpLogger.Builder logger(Level level) {
        return HttpLogger.builder().level(level).sink(out::add);
    }

    private HttpClient start(HttpFiltersSource... sources) {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().withPort(0);
        for (HttpFiltersSource s : sources) b.plusFiltersSource(s);
        proxy = b.start();
        return client(proxy);
    }

    /**
     * Waits for {@code n} messages and checks that every line of each text message has the exchange
     * prefix (JSON messages carry {@code conn} and {@code seq} fields instead).
     */
    private List<String> await(int n) throws InterruptedException {
        for (int i = 0; i < 500 && out.size() < n; i++) Thread.sleep(10);
        List<String> messages = List.copyOf(out);
        assertEquals(n, messages.size(), String.join("\n----\n", messages));
        for (String m : messages) {
            if (m.startsWith("{")) continue;
            for (String line : m.split("\n", -1)) {
                assertTrue(PREFIX.matcher(line).find(), "unprefixed line '" + line + "' in\n" + m);
            }
        }
        return messages;
    }

    private static HttpRequest post(String url, String body) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20))
                .header("Content-Type", "text/plain").POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    /** {@code message}'s lines without their prefix. */
    private static List<String> lines(String message) {
        return message.lines().map(l -> PREFIX.matcher(l).replaceFirst("")).toList();
    }

    private static String port(HttpServer server) {
        return String.valueOf(server.getAddress().getPort());
    }

    // --- levels --------------------------------------------------------------------------------

    @Test
    void basicLogsOneLinePerMessage() throws Exception {
        HttpClient client = start(logger(Level.BASIC).build());
        get(client, url(origin, "/a?x=1"));
        send(client, post(url(origin, "/b"), "hello"));
        List<String> log = await(4);
        String base = Pattern.quote("http://127.0.0.1:" + port(origin));
        assertTrue(log.get(0).matches("\\[conn \\d+ #\\d+] --> GET " + base + "/a\\?x=1 HTTP/1\\.1"), log.get(0));
        assertTrue(log.get(1).matches("\\[conn \\d+ #\\d+] <-- 200 OK " + base
                + "/a\\?x=1 \\([\\d.]+ ms, ttfb [\\d.]+ ms, source=server, \\d+-byte body\\)"), log.get(1));
        assertTrue(log.get(2).matches("\\[conn \\d+ #\\d+] --> POST " + base + "/b HTTP/1\\.1 \\(5-byte body\\)"),
                log.get(2));
        assertTrue(log.get(3).contains("<-- 200 OK "), log.get(3));
        assertFalse(String.join("\n", log).toLowerCase().contains("content-type"), "no headers at BASIC");
    }

    @Test
    void headersShowsHeadersAndWhatTheProxyChangedButNoBodies() throws Exception {
        HttpClient client = start(logger(Level.HEADERS).build());
        send(client, HttpRequest.newBuilder(URI.create(url(origin, "/a"))).header("X-Test", "hello").build());
        send(client, post(url(origin, "/b"), "hello"));
        List<String> log = await(4);

        List<String> get = lines(log.get(0));
        assertEquals("--> GET http://127.0.0.1:" + port(origin) + "/a HTTP/1.1", get.getFirst());
        assertTrue(get.contains("X-Test: hello"), get.toString());
        // Forwarded in origin form, with a Via header.
        int forwarded = get.indexOf("--> forwarded as GET /a HTTP/1.1");
        assertTrue(forwarded > 0, get.toString());
        assertTrue(get.subList(forwarded, get.size()).stream().anyMatch(l -> l.startsWith("+ Via: 1.1 ")), get.toString());
        assertEquals("--> END GET", get.getLast());

        List<String> response = lines(log.get(1));
        assertTrue(response.getFirst().startsWith("<-- 200 OK http://127.0.0.1:"), response.getFirst());
        assertTrue(response.contains("Content-type: text/plain"), "as the server spelled it: " + response);
        assertTrue(response.contains("<-- delivered as HTTP/1.1 200 OK"), "the proxy adds Via: " + response);
        assertTrue(response.getLast().matches("<-- END HTTP \\(\\d+-byte body\\)"), response.getLast());
        assertFalse(log.get(1).contains("method: GET"), "no body at HEADERS");

        List<String> postLines = lines(log.get(2));
        assertEquals("--> END POST (5-byte body)", postLines.getLast());
        assertFalse(postLines.contains("hello"));
    }

    @Test
    void bodyShowsTextBodiesOnBothSides() throws Exception {
        HttpClient client = start(logger(Level.BODY).build());
        get(client, url(origin, "/a"));
        send(client, post(url(origin, "/b"), "hello world\nsecond line"));
        List<String> log = await(4);

        assertEquals("--> END GET (no body)", lines(log.get(0)).getLast());
        List<String> response = lines(log.get(1));
        assertTrue(response.contains("method: GET"), "the echoed body is logged: " + response);

        List<String> post = lines(log.get(2));
        int blank = post.indexOf("");
        assertEquals(List.of("hello world", "second line", "--> END POST (23-byte body)"),
                post.subList(blank + 1, post.size()));
        List<String> echoed = lines(log.get(3));
        assertTrue(echoed.contains("method: POST"), echoed.toString());
        assertTrue(echoed.contains("second line"), echoed.toString());
        assertTrue(echoed.getLast().matches("<-- END HTTP \\(\\d+-byte body\\)"), echoed.getLast());
    }

    @Test
    void bodiesAreCutAtTheCapWithoutChangingWhatIsForwarded() throws Exception {
        HttpClient client = start(logger(Level.BODY).maxBodyBytes(10).build());
        String body = "0123456789abcdefghij";
        HttpResponse<String> response = send(client, post(url(origin, "/b"), body));
        assertEquals(body, echoedBody(response.body()));
        List<String> log = await(2);
        List<String> request = lines(log.get(0));
        assertEquals(List.of("", "0123456789", "--> END POST (20-byte body, first 10 bytes shown)"),
                request.subList(request.size() - 3, request.size()));
        List<String> echoed = lines(log.get(1));
        assertEquals("method: PO", echoed.get(echoed.size() - 2));
        assertTrue(echoed.getLast().endsWith("-byte body, first 10 bytes shown)"), echoed.getLast());
    }

    @Test
    void encodedBodiesAreDecodedWhenWhollySeen() throws Exception {
        HttpClient client = start(logger(Level.BODY).build());
        HttpResponse<String> raw = get(client, url(origin, "/gzip"));
        assertEquals(200, raw.statusCode());
        List<String> response = lines(await(2).get(1));
        assertTrue(response.contains("Content-encoding: gzip"), response.toString());
        assertTrue(response.contains("décodé ".repeat(20)), response.toString());
        assertTrue(response.getLast().matches("<-- END HTTP \\(\\d+-byte body, gzip-decoded, 180 bytes decoded\\)"),
                response.getLast());

        // Longer than the cap: the encoded body is not decoded at all.
        out.clear();
        proxy.abort();
        client = start(logger(Level.BODY).maxBodyBytes(8).build());
        get(client, url(origin, "/gzip"));
        response = lines(await(2).get(1));
        assertTrue(response.stream().anyMatch(l -> l.matches("<\\d+ bytes, gzip-encoded, longer than 8 bytes: not decoded>")),
                response.toString());
    }

    @Test
    void binaryBodiesAreSummarised() throws Exception {
        HttpClient client = start(logger(Level.BODY).build());
        get(client, url(origin, "/binary"));
        List<String> response = lines(await(2).get(1));
        assertTrue(response.contains("<1000 bytes of application/octet-stream>"), response.toString());
        assertEquals("<-- END HTTP (1000-byte body)", response.getLast());
    }

    // --- redaction and changes ------------------------------------------------------------------

    @Test
    void headersAndQueryParametersAreRedactedOnBothSides() throws Exception {
        var rewrite = HttpFilters.builder()
                .beforeSending(req -> {
                    req.headers().set("Authorization", "Bearer forwardedsecret");
                    return null;
                })
                .build();
        HttpClient client = start(logger(Level.HEADERS).redact("x-api-key").redactQueryParams("TOKEN").build(), rewrite);
        send(client, HttpRequest.newBuilder(URI.create(url(origin, "/cookie?token=topsecret&x=1")))
                .header("Authorization", "Bearer topsecret")
                .header("Cookie", "c=topsecret")
                .header("X-Api-Key", "topsecret")
                .build());
        List<String> log = await(2);
        String all = String.join("\n", log);
        assertFalse(all.contains("topsecret"), all);
        assertFalse(all.contains("forwardedsecret"), all);
        List<String> request = lines(log.get(0));
        assertEquals("--> GET http://127.0.0.1:" + port(origin) + "/cookie?token=██&x=1 HTTP/1.1", request.getFirst());
        assertTrue(request.containsAll(List.of("Authorization: ██", "Cookie: ██", "X-Api-Key: ██",
                "--> forwarded as GET /cookie?token=██&x=1 HTTP/1.1", "- Authorization: ██", "+ Authorization: ██")),
                request.toString());
        assertTrue(lines(log.get(1)).contains("Set-cookie: ██"), log.get(1));

        // Without redaction, everything shows.
        out.clear();
        proxy.abort();
        client = start(logger(Level.HEADERS).redactNothing().build());
        send(client, HttpRequest.newBuilder(URI.create(url(origin, "/cookie?token=topsecret")))
                .header("Authorization", "Bearer topsecret").build());
        log = await(2);
        assertTrue(lines(log.get(0)).contains("Authorization: Bearer topsecret"), log.get(0));
        assertTrue(lines(log.get(1)).contains("Set-cookie: session=topsecret"), log.get(1));
    }

    @Test
    void filtersChangesShowAsForwardedAndDeliveredDiffs() throws Exception {
        HttpLogger logger = logger(Level.HEADERS).build();
        HttpFiltersBuilder.Built built = HttpFilters.builder()
                .log(logger)
                .beforeSending(req -> {
                    req.headers().set("X-Added", "yes");
                    req.headers().remove("X-Gone");
                    return null;
                })
                .beforeResponding(res -> {
                    res.headers().set("X-Resp", "1");
                    return res;
                })
                .build();
        HttpClient client = start(built);
        HttpResponse<String> response = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/a")))
                .header("X-Gone", "bye").build());
        assertEquals(List.of("yes"), TestSupport.echoedHeader(response.body(), "x-added"));
        List<String> log = await(2);
        List<String> request = lines(log.get(0));
        assertTrue(request.containsAll(List.of("X-Gone: bye", "- X-Gone: bye", "+ X-Added: yes")), request.toString());
        assertTrue(request.indexOf("+ X-Added: yes") > request.indexOf("--> forwarded as GET /a HTTP/1.1"));
        List<String> delivered = lines(log.get(1));
        assertFalse(delivered.contains("X-Resp: 1"), "as the server sent it: " + delivered);
        assertTrue(delivered.indexOf("+ X-Resp: 1") > delivered.indexOf("<-- delivered as HTTP/1.1 200 OK"),
                delivered.toString());
    }

    @Test
    void responseLinesNameTheSourceAndTheServersStatus() throws Exception {
        var filters = HttpFilters.builder()
                .onRequest(req -> req.uri().endsWith("/blocked")
                        ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN, "no") : null)
                .onResponse(res -> res.status().code() == 500 ? res.setStatus(HttpResponseStatus.OK) : res)
                .build();
        HttpClient client = start(logger(Level.BODY).build(), filters);
        assertEquals(200, get(client, url(origin, "/error")).statusCode());
        assertEquals(403, get(client, url(origin, "/blocked")).statusCode());
        int closed;
        try (ServerSocket s = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            closed = s.getLocalPort();
        }
        assertEquals(502, get(client, "http://127.0.0.1:" + closed + "/").statusCode());
        List<String> log = await(6);

        List<String> rewritten = lines(log.get(1));
        assertTrue(rewritten.getFirst().matches("<-- 200 OK \\S+/error \\([\\d.]+ ms, ttfb [\\d.]+ ms, source=filter,"
                + " upstream=500\\)"), rewritten.getFirst());
        assertTrue(rewritten.contains("<-- delivered as HTTP/1.1 200 OK"), rewritten.toString());
        assertTrue(rewritten.contains("server broke"), rewritten.toString());

        List<String> blocked = lines(log.get(3));
        assertTrue(blocked.getFirst().matches("<-- 403 Forbidden \\S+/blocked \\([\\d.]+ ms, source=filter\\)"),
                blocked.getFirst());
        assertEquals(List.of("", "no", "<-- END HTTP (2-byte body)"), blocked.subList(blocked.size() - 3, blocked.size()));
        assertEquals("--> END GET (no body)", lines(log.get(2)).getLast());

        assertTrue(lines(log.get(5)).getFirst().matches("<-- 502 Bad Gateway \\S+ \\([\\d.]+ ms, source=proxy\\)"),
                log.get(5));
    }

    // --- JSON -----------------------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void jsonLinesAreOneObjectPerMessage() throws Exception {
        HttpClient client = start(logger(Level.BODY).format(Format.JSON).redactQueryParams("token").build());
        send(client, HttpRequest.newBuilder(URI.create(url(origin, "/j?token=topsecret")))
                .header("Content-Type", "text/plain").header("Authorization", "Bearer topsecret")
                .POST(HttpRequest.BodyPublishers.ofString("hello\n\"quoted\"")).build());
        List<String> log = await(2);
        log.forEach(line -> assertFalse(line.contains("\n"), line));
        Map<String, Object> request = (Map<String, Object>) MiniJson.parse(log.get(0));
        Map<String, Object> response = (Map<String, Object>) MiniJson.parse(log.get(1));

        assertEquals("request", request.get("type"));
        assertEquals(1L, request.get("seq"));
        assertEquals(response.get("conn"), request.get("conn"));
        assertEquals("POST", request.get("method"));
        assertEquals("http://127.0.0.1:" + port(origin) + "/j?token=██", request.get("url"));
        assertTrue(((List<Object>) request.get("headers")).contains(List.of("Content-Type", "text/plain")));
        assertTrue(((List<Object>) request.get("headers")).contains(List.of("Authorization", "██")));
        assertFalse(log.get(0).contains("topsecret"), log.get(0));
        Map<String, Object> forwarded = (Map<String, Object>) request.get("forwarded");
        assertEquals("/j?token=██", forwarded.get("uri"));
        assertTrue(((List<List<String>>) forwarded.get("added")).stream().anyMatch(h -> h.getFirst().equals("Via")));
        assertEquals("hello\n\"quoted\"", request.get("body"));
        assertEquals(14L, request.get("body_bytes"));
        assertInstanceOf(String.class, request.get("time"));

        assertEquals("response", response.get("type"));
        assertEquals(200L, response.get("status"));
        assertEquals("SERVER", response.get("source"));
        assertEquals(200L, response.get("upstream_status"));
        assertInstanceOf(Double.class, response.get("total_ms"));
        assertInstanceOf(Double.class, response.get("ttfb_ms"));
        assertTrue(((String) response.get("body")).contains("method: POST"));
        assertInstanceOf(Map.class, response.get("delivered"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void jsonAtBasicHasNoHeaders() throws Exception {
        HttpClient client = start(logger(Level.BASIC).format(Format.JSON).build());
        send(client, post(url(origin, "/j"), "hello"));
        List<String> log = await(2);
        Map<String, Object> request = (Map<String, Object>) MiniJson.parse(log.get(0));
        assertNull(request.get("headers"));
        assertEquals(5L, request.get("body_bytes"));
        Map<String, Object> response = (Map<String, Object>) MiniJson.parse(log.get(1));
        assertNull(response.get("headers"));
        assertEquals(200L, response.get("status"));
    }

    // --- selection, numbering, failures --------------------------------------------------------

    @Test
    void onlyMatchingExchangesAreLoggedAndExchangesAreNumberedPerConnection() throws Exception {
        start(logger(Level.BASIC).only((req, ctx) -> !req.uri().contains("/skip")).build());
        String base = "http://127.0.0.1:" + port(origin);
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            for (String path : List.of("/one", "/skip", "/three")) {
                assertEquals(200, RawProxyClient.exchange(s, "GET " + base + path + " HTTP/1.1\r\nHost: x\r\n\r\n").status());
            }
        }
        List<String> log = await(4);
        Matcher first = PREFIX.matcher(log.get(0));
        Matcher last = PREFIX.matcher(log.get(3));
        assertTrue(first.find() && last.find());
        assertEquals(first.group(1), last.group(1), "same connection");
        assertEquals("1", first.group(2));
        assertEquals("3", last.group(2), "the skipped request still counts");
        assertFalse(String.join("\n", log).contains("/skip"));
    }

    @Test
    void failingSinksAndPredicatesNeverDisturbTheProxy() {
        AtomicInteger calls = new AtomicInteger();
        HttpClient client = start(HttpLogger.builder().level(Level.BODY).sink(line -> {
            calls.incrementAndGet();
            throw new IllegalStateException("sink down");
        }).build());
        for (int i = 0; i < 3; i++) {
            HttpResponse<String> response = send(client, post(url(origin, "/s"), "body"));
            assertEquals("body", echoedBody(response.body()));
        }
        assertTrue(calls.get() >= 3);

        proxy.abort();
        client = start(HttpLogger.builder().only((req, ctx) -> {
            throw new IllegalStateException("predicate down");
        }).sink(out::add).build());
        assertEquals(200, get(client, url(origin, "/p")).statusCode());
        assertTrue(out.isEmpty());
    }

    // --- interception, WebSockets, fast path ------------------------------------------------------

    @Test
    void interceptedRequestsAreLoggedInsideTheTlsSession() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Logger Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Logger Proxy CA");
        HttpsServer https = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), echo());
        try {
            proxy = MicroProxy.bootstrap().withPort(0)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .plusFiltersSource(logger(Level.BODY).redactQueryParams("token").build())
                    .start();
            HttpClient client = client(proxy, proxyCa.clientContext());
            HttpResponse<String> response = send(client, post(url(https, "/private?token=t0p"), "secret"));
            assertEquals(200, response.statusCode());
            List<String> log = await(4);
            String hostPort = "127.0.0.1:" + https.getAddress().getPort();
            assertEquals("--> CONNECT " + hostPort + " HTTP/1.1", lines(log.get(0)).getFirst());
            assertTrue(lines(log.get(1)).getFirst().matches("<-- 200 Connection established " + Pattern.quote(hostPort)
                    + " \\([\\d.]+ ms, source=proxy\\)"), log.get(1));
            List<String> inside = lines(log.get(2));
            assertEquals("--> POST https://" + hostPort + "/private?token=██ HTTP/1.1", inside.getFirst());
            assertTrue(inside.contains("secret"), inside.toString());
            assertTrue(lines(log.get(3)).getFirst().startsWith("<-- 200 OK https://" + hostPort + "/private"), log.get(3));
            Matcher connect = PREFIX.matcher(log.get(0));
            Matcher post = PREFIX.matcher(log.get(2));
            assertTrue(connect.find() && post.find());
            assertEquals(connect.group(1), post.group(1), "one client connection");
            assertEquals(List.of("1", "2"), List.of(connect.group(2), post.group(2)));
            // Bodies are not redacted (the echoed body repeats the URI), lines and headers are.
            assertFalse(lines(log.get(2)).getFirst().contains("t0p"));
            assertFalse(lines(log.get(3)).getFirst().contains("t0p"));
        } finally {
            https.stop(0);
        }
    }

    @Test
    void webSocketFramesAreLoggedOnlyWhenAskedFor() throws Exception {
        start(logger(Level.BODY).webSocketFrames(true).build());
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("ping"));
            assertEquals("echo:ping", WebSocketTestSupport.readFrame(s.getInputStream()).payloadAsText());
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.binary(new byte[300]));
            List<String> log = await(5);
            assertTrue(lines(log.get(1)).getFirst().startsWith("<-- 101 Switching Protocols "), log.get(1));
            assertEquals(List.of("--> WS text (4 bytes): ping"), lines(log.get(2)));
            assertEquals(List.of("<-- WS text (9 bytes): echo:ping"), lines(log.get(3)));
            assertEquals(List.of("--> WS binary (300 bytes)"), lines(log.get(4)));
            // Watching frames does not touch the extensions negotiation.
            assertTrue(server.upgradeRequest.contains("Sec-WebSocket-Extensions"), server.upgradeRequest);
        }

        out.clear();
        proxy.abort();
        start(logger(Level.BODY).build());
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("ping"));
            assertEquals("echo:ping", WebSocketTestSupport.readFrame(s.getInputStream()).payloadAsText());
            Thread.sleep(100);
            assertEquals(2, await(2).size(), "no frames without webSocketFrames(true)");
        }
    }

    @Test
    void headersLevelKeepsTheFastPathForLargeBodies() throws Exception {
        HttpLogger logger = logger(Level.HEADERS).build();
        FlowContext ctx = new FlowContext(7, () -> null, () -> null, new ClientDetails());
        SelectiveFilters filters = logger.filterRequest(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/"), ctx);
        for (Body body : Body.values()) assertFalse(filters.sees(body), body.name());
        SelectiveFilters bodies = logger(Level.BODY).build()
                .filterRequest(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/"), ctx);
        assertTrue(bodies.sees(Body.REQUEST) && bodies.sees(Body.RESPONSE));
        assertFalse(bodies.sees(Body.OBSERVED_WEBSOCKET_FRAMES));

        HttpClient client = start(logger);
        String big = "x".repeat(3_000_000);
        HttpResponse<String> response = send(client, post(url(origin, "/big"), big));
        assertEquals(big, echoedBody(response.body()));
        List<String> log = await(2);
        assertEquals("--> END POST (3000000-byte body)", lines(log.get(0)).getLast());
    }

    // --- built filters returned from a lambda source --------------------------------------------

    /** {@code built}, returned as it is from a lambda source for every request. */
    private HttpProxyServer startWithLambdaSource(HttpFilters built) {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource((request, ctx) -> built).start();
        return proxy;
    }

    /** The {@code [conn N #S] } prefix shared by every line of {@code message}. */
    private static String prefixOf(String message) {
        Matcher m = PREFIX.matcher(message);
        assertTrue(m.find(), message);
        String prefix = m.group();
        for (String line : message.split("\n", -1)) {
            assertTrue(line.startsWith(prefix), "line '" + line + "' mixed into the message of " + prefix + "\n" + message);
        }
        return prefix;
    }

    @Test
    void builtFiltersFromALambdaSourceLogEachOfManyConcurrentExchanges() throws Exception {
        HttpFilters built = HttpFilters.builder().log(logger(Level.HEADERS).build())
                .beforeSending(req -> {
                    req.headers().set("X-Added", "yes");
                    return null;
                })
                .build();
        startWithLambdaSource(built);
        String base = "http://127.0.0.1:" + port(origin);
        int clients = 8;
        int requests = 3;
        java.util.concurrent.CyclicBarrier together = new java.util.concurrent.CyclicBarrier(clients);
        List<java.util.concurrent.Future<?>> done = new ArrayList<>();
        try (var pool = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            for (int c = 0; c < clients; c++) {
                int client = c;
                done.add(pool.submit(() -> {
                    // One keep-alive connection per client, its requests one after another.
                    try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
                        together.await();
                        for (int r = 1; r <= requests; r++) {
                            RawProxyClient.Response response = RawProxyClient.exchange(s, "GET " + base + "/c" + client
                                    + "/r" + r + " HTTP/1.1\r\nHost: x\r\nX-Client: " + client + "\r\n\r\n");
                            assertEquals(List.of("yes"), TestSupport.echoedHeader(response.body(), "x-added"));
                        }
                    }
                    return null;
                }));
            }
            for (var f : done) f.get();
        }
        List<String> log = await(2 * clients * requests);

        // Each exchange logs one complete request and one complete response, nothing else mixed in.
        Map<String, List<String>> byExchange = new LinkedHashMap<>();
        for (String message : log) byExchange.computeIfAbsent(prefixOf(message), k -> new ArrayList<>()).add(message);
        assertEquals(clients * requests, byExchange.size(), byExchange.keySet().toString());
        Map<String, String> clientOfConnection = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : byExchange.entrySet()) {
            Matcher id = PREFIX.matcher(e.getKey());
            assertTrue(id.find());
            List<String> messages = e.getValue();
            assertEquals(2, messages.size(), String.join("\n----\n", messages));
            List<String> request = lines(messages.get(0));
            Matcher path = Pattern.compile("^--> GET " + Pattern.quote(base) + "/c(\\d+)/r(\\d+) HTTP/1\\.1$")
                    .matcher(request.getFirst());
            assertTrue(path.find(), request.toString());
            assertTrue(request.contains("X-Client: " + path.group(1)), request.toString());
            assertTrue(request.contains("+ X-Added: yes"), request.toString());
            assertEquals("--> END GET", request.getLast());
            List<String> response = lines(messages.get(1));
            assertTrue(response.getFirst().startsWith("<-- 200 OK " + base + "/c" + path.group(1) + "/r" + path.group(2) + " "),
                    response.toString());
            assertTrue(response.getLast().startsWith("<-- END HTTP"), response.toString());
            // Sequential exchanges on one keep-alive connection are numbered 1, 2, 3 in order.
            assertEquals(path.group(2), id.group(2), "sequence number of " + request.getFirst());
            String previous = clientOfConnection.put(id.group(1), path.group(1));
            assertTrue(previous == null || previous.equals(path.group(1)), "one client per connection");
        }
        assertEquals(clients, clientOfConnection.size());
    }

    @Test
    void builtFiltersFromALambdaSourceLogInterceptedRequests() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Lambda Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Lambda Proxy CA");
        HttpsServer https = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), echo());
        try {
            HttpFilters built = HttpFilters.builder().log(logger(Level.BODY).build()).build();
            proxy = MicroProxy.bootstrap().withPort(0)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .withFiltersSource((request, ctx) -> built)
                    .start();
            HttpClient client = client(proxy, proxyCa.clientContext());
            assertEquals(200, send(client, post(url(https, "/one"), "first")).statusCode());
            assertEquals(200, send(client, post(url(https, "/two"), "second")).statusCode());
            List<String> log = await(6);
            String hostPort = "127.0.0.1:" + https.getAddress().getPort();
            assertEquals("--> CONNECT " + hostPort + " HTTP/1.1", lines(log.get(0)).getFirst());
            assertTrue(lines(log.get(1)).getFirst().startsWith("<-- 200 Connection established "), log.get(1));
            List<String> one = lines(log.get(2));
            assertEquals("--> POST https://" + hostPort + "/one HTTP/1.1", one.getFirst());
            assertTrue(one.contains("first") && !one.contains("second"), one.toString());
            assertTrue(lines(log.get(3)).getFirst().startsWith("<-- 200 OK https://" + hostPort + "/one"), log.get(3));
            List<String> two = lines(log.get(4));
            assertEquals("--> POST https://" + hostPort + "/two HTTP/1.1", two.getFirst());
            assertTrue(two.contains("second") && !two.contains("first"), two.toString());
            assertTrue(lines(log.get(5)).getFirst().startsWith("<-- 200 OK https://" + hostPort + "/two"), log.get(5));
            List<String> prefixes = log.stream().map(HttpLoggerTest::prefixOf).toList();
            Matcher connect = PREFIX.matcher(prefixes.get(0));
            Matcher second = PREFIX.matcher(prefixes.get(4));
            assertTrue(connect.find() && second.find());
            assertEquals(connect.group(1), second.group(1), "one client connection");
            assertEquals(List.of(prefixes.get(0), prefixes.get(2), prefixes.get(4)),
                    List.of(prefixes.get(1), prefixes.get(3), prefixes.get(5)), "each response with its request");
            assertEquals(List.of("1", "3"), List.of(connect.group(2), second.group(2)));
        } finally {
            https.stop(0);
        }
    }

    @Test
    void builtFiltersFromALambdaSourceLogWebSocketFrames() throws Exception {
        AtomicInteger rewritten = new AtomicInteger();
        HttpFilters built = HttpFilters.builder().log(logger(Level.BODY).webSocketFrames(true).build())
                .onWebSocketFrame((frame, fromClient) -> {
                    rewritten.incrementAndGet();
                    return frame;
                })
                .build();
        startWithLambdaSource(built);
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("ping"));
            assertEquals("echo:ping", WebSocketTestSupport.readFrame(s.getInputStream()).payloadAsText());
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.binary(new byte[300]));
            List<String> log = await(5);
            assertTrue(lines(log.get(1)).getFirst().startsWith("<-- 101 Switching Protocols "), log.get(1));
            assertEquals(List.of("--> WS text (4 bytes): ping"), lines(log.get(2)));
            assertEquals(List.of("<-- WS text (9 bytes): echo:ping"), lines(log.get(3)));
            assertEquals(List.of("--> WS binary (300 bytes)"), lines(log.get(4)));
            assertEquals(1, log.stream().map(HttpLoggerTest::prefixOf).distinct().count(), "frames log under the upgrade");
            assertTrue(rewritten.get() >= 3, "the frame hook ran too");
        }
    }

    @Test
    void builtFiltersFromALambdaSourceStartAfreshAfterAbortedExchanges() throws Exception {
        HttpFilters built = HttpFilters.builder().log(logger(Level.BODY).build())
                .onResponse(res -> res.headers().contains("X-Abort") ? null : res)
                .build();
        origin.createContext("/abort", exchange -> {
            exchange.getResponseHeaders().set("X-Abort", "1");
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        startWithLambdaSource(built);
        String base = "http://127.0.0.1:" + port(origin);
        try (Socket refused = TestSupport.refusingPort();
                Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            // A failed exchange, then one on the same keep-alive connection: each has its own state.
            assertEquals(502, RawProxyClient.exchange(s, "GET http://127.0.0.1:" + refused.getLocalPort()
                    + "/gone HTTP/1.1\r\nHost: x\r\n\r\n").status());
            assertEquals(200, RawProxyClient.exchange(s, "POST " + base + "/after HTTP/1.1\r\nHost: x\r\n"
                    + "Content-Length: 5\r\n\r\nhello").status());
        }
        List<String> log = await(4);
        assertTrue(lines(log.get(1)).getFirst().startsWith("<-- 502 Bad Gateway "), log.get(1));
        List<String> after = lines(log.get(2));
        assertEquals("--> POST " + base + "/after HTTP/1.1", after.getFirst());
        assertEquals("--> END POST (5-byte body)", after.getLast());
        assertTrue(lines(log.get(3)).getFirst().startsWith("<-- 200 OK " + base + "/after "), log.get(3));
        assertEquals(List.of("#1", "#1", "#2", "#2"),
                log.stream().map(m -> prefixOf(m).replaceAll(".* (#\\d+)] $", "$1")).toList());

        // An exchange the filters abort, and a client that leaves mid-body: later exchanges log whole.
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            TestSupport.write(s.getOutputStream(), "GET " + base + "/abort HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            s.getInputStream().readAllBytes();
        }
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            TestSupport.write(s.getOutputStream(), "POST " + base + "/partial HTTP/1.1\r\nHost: x\r\n"
                    + "Content-Length: 100\r\n\r\nonly part");
        }
        HttpResponse<String> response = send(client(proxy), post(url(origin, "/last"), "done"));
        assertEquals("done", echoedBody(response.body()));
        TestSupport.eventually("the /last exchange's log", () -> out.stream().filter(m -> m.contains("/last ")).count() == 2);
        List<String> last = out.stream().filter(m -> m.contains("/last ")).toList();
        assertEquals("--> POST " + base + "/last HTTP/1.1", lines(last.get(0)).getFirst());
        assertEquals("--> END POST (4-byte body)", lines(last.get(0)).getLast());
        assertTrue(lines(last.get(0)).contains("done"), last.get(0));
        assertTrue(lines(last.get(1)).getFirst().startsWith("<-- 200 OK " + base + "/last "), last.get(1));
        for (String m : last) assertFalse(m.contains("/abort") || m.contains("/partial") || m.contains("only part"), m);
        assertEquals(prefixOf(last.get(0)), prefixOf(last.get(1)));
    }

    @Test
    void builtFiltersBindOneCopyPerExchangeAndStayStateless() {
        HttpFiltersBuilder.Built built = HttpFilters.builder().log(logger(Level.HEADERS).build()).build();
        FlowContext ctx = new FlowContext(3, () -> null, () -> null, new ClientDetails());
        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://x/");
        HttpFilters first = built.filterRequest(request, ctx);
        HttpFilters second = built.filterRequest(request, ctx);
        assertTrue(first != built && second != built && first != second, "a copy per exchange");
        assertTrue(first.equals(((HttpFiltersBuilder.Built) first).filterRequest(request, ctx)),
                "a bound copy is not bound again");
        // A lambda source returns the shared instance; the proxy binds it the same way.
        HttpFiltersSource lambda = (req, c) -> built;
        HttpFilters chained = HttpFiltersChain.of(lambda, HttpFilters.builder().onRequest(r -> null).build())
                .filterRequest(request, ctx);
        HttpFilters member = ((HttpFiltersChain.Chained) chained).members().getFirst();
        assertInstanceOf(HttpFiltersBuilder.Built.class, member);
        assertTrue(member != built, "chains bind built filters from other sources too");

        // A skipped exchange gets a shared bound copy that logs nothing.
        HttpFiltersBuilder.Built skipping = HttpFilters.builder()
                .log(logger(Level.HEADERS).only((req, c) -> false).build()).build();
        HttpFilters skipped = skipping.filterRequest(request, ctx);
        assertTrue(skipped != skipping, "bound, so it does not warn about being unbound");
        assertTrue(skipped == skipping.filterRequest(request, ctx), "and shared, as it keeps no state");
    }

    // --- a tiny JSON reader for the assertions ------------------------------------------------------

    /** Parses JSON into maps, lists, strings, longs, doubles, booleans and null. */
    static final class MiniJson {
        private final String s;
        private int i;

        private MiniJson(String s) {
            this.s = s;
        }

        static Object parse(String json) throws IOException {
            MiniJson p = new MiniJson(json);
            Object v = p.value();
            p.ws();
            if (p.i != json.length()) throw new IOException("trailing data at " + p.i + ": " + json);
            return v;
        }

        private void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        private Object value() throws IOException {
            ws();
            char c = s.charAt(i);
            if (c == '{') {
                i++;
                Map<String, Object> map = new LinkedHashMap<>();
                ws();
                if (s.charAt(i) == '}') {
                    i++;
                    return map;
                }
                while (true) {
                    ws();
                    String key = string();
                    ws();
                    expect(':');
                    if (map.put(key, value()) != null) throw new IOException("duplicate key " + key);
                    ws();
                    if (s.charAt(i) == ',') {
                        i++;
                    } else {
                        expect('}');
                        return map;
                    }
                }
            }
            if (c == '[') {
                i++;
                List<Object> list = new ArrayList<>();
                ws();
                if (s.charAt(i) == ']') {
                    i++;
                    return list;
                }
                while (true) {
                    list.add(value());
                    ws();
                    if (s.charAt(i) == ',') {
                        i++;
                    } else {
                        expect(']');
                        return list;
                    }
                }
            }
            if (c == '"') return string();
            for (String word : List.of("true", "false", "null")) {
                if (s.startsWith(word, i)) {
                    i += word.length();
                    return word.equals("null") ? null : Boolean.valueOf(word);
                }
            }
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            String number = s.substring(start, i);
            if (number.isEmpty()) throw new IOException("unexpected '" + c + "' at " + start);
            return number.contains(".") || number.contains("e") || number.contains("E")
                    ? (Object) Double.valueOf(number) : (Object) Long.valueOf(number);
        }

        private String string() throws IOException {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c < 0x20) throw new IOException("raw control character in string at " + (i - 1));
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '"', '\\', '/' -> sb.append(e);
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'u' -> {
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> throw new IOException("bad escape \\" + e);
                }
            }
        }

        private void expect(char c) throws IOException {
            if (i >= s.length() || s.charAt(i) != c) throw new IOException("expected '" + c + "' at " + i + ": " + s);
            i++;
        }
    }
}
