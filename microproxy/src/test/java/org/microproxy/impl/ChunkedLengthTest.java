package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.write;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.ActivityTracker;
import org.microproxy.FlowContext;
import org.microproxy.FlowRecord;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.extras.AccessLogFormat;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;
import org.microproxy.stats.Counter;

/**
 * {@code withAllowChunkedLength}: HTTP/1.1 requests with both {@code Transfer-Encoding} and
 * {@code Content-Length} are accepted only when asked for, framed by the chunked coding alone, and
 * the client connection closes after the response, so that nothing after the body is read as a
 * request. Smuggling-style payloads check that neither the client side nor the server side can be
 * desynchronized.
 */
class ChunkedLengthTest {

    private static final HttpCodec.Limits LIMITS = new HttpCodec.Limits(8192, 16384, 1 << 20);

    /** What the origin read: one line per request, {@code METHOD uri | content-length | transfer-encoding | body}. */
    private final List<String> received = new CopyOnWriteArrayList<>();
    /** How each origin connection ended: {@code end} for a clean close between requests, else the error. */
    private final List<String> originEnds = new CopyOnWriteArrayList<>();
    private TestSupport.RawServer origin;
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() throws IOException {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.close();
    }

    /**
     * An origin that reads requests with the proxy's own strict codec, one after another on each
     * connection, and answers each {@code 200 ok}.
     */
    private void startOrigin() {
        origin = TestSupport.rawServer(s -> {
            ByteReader in = new ByteReader(s.getInputStream(), 1024).strictLineEndings();
            try {
                HttpRequest request;
                while ((request = HttpCodec.readRequest(in, LIMITS)) != null) {
                    String contentLength = request.headers().get(HttpHeaderNames.CONTENT_LENGTH);
                    String transferEncoding = request.headers().get(HttpHeaderNames.TRANSFER_ENCODING);
                    String body = body(new HttpCodec.BodyReader(in, Framing.forRequest(request), LIMITS));
                    received.add(request.method() + " " + request.uri() + " | " + contentLength + " | "
                            + transferEncoding + " | " + body);
                    write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
                originEnds.add("end");
            } catch (IOException e) {
                originEnds.add(String.valueOf(e));
            }
        });
    }

    private static String body(HttpCodec.BodyReader reader) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpContent c;
        while ((c = reader.next()) != null) {
            out.writeBytes(c.content());
            if (c instanceof LastHttpContent) break;
        }
        return out.toString(StandardCharsets.ISO_8859_1);
    }

    private String target(String path) {
        return "http://127.0.0.1:" + origin.port() + path;
    }

    /** Sends {@code bytes} in one write and reads everything until the proxy closes. */
    private String exchange(String bytes) throws IOException {
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(20_000);
            write(s.getOutputStream(), bytes);
            return new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }

    private static int count(String text, String part) {
        int n = 0;
        for (int i = text.indexOf(part); i >= 0; i = text.indexOf(part, i + 1)) n++;
        return n;
    }

    // -------------------------------------------------------------------------------------------
    // Framing rules
    // -------------------------------------------------------------------------------------------

    private static HttpRequest request(HttpVersion version, String... headers) {
        HttpRequest request = new DefaultHttpRequest(version, HttpMethod.POST, "/");
        for (int i = 0; i < headers.length; i += 2) request.headers().add(headers[i], headers[i + 1]);
        return request;
    }

    private static HttpRequest connect(String... headers) {
        HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, "example.com:443");
        for (int i = 0; i < headers.length; i += 2) request.headers().add(headers[i], headers[i + 1]);
        return request;
    }

    @Test
    void onlyASoundChunkedCodingWithAValidLengthQualifies() throws Exception {
        HttpRequest both = request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", "chunked");
        assertThrows(HttpParseException.class, () -> Framing.forRequest(both));
        assertThrows(HttpParseException.class, () -> Framing.forRequest(both, false));
        assertSame(Framing.CHUNKED, Framing.forRequest(both, true));
        assertFalse(both.headers().contains(HttpHeaderNames.CONTENT_LENGTH), "Content-Length is removed");
        assertEquals("chunked", both.headers().get(HttpHeaderNames.TRANSFER_ENCODING));

        assertSame(Framing.CHUNKED, Framing.forRequest(
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", "gzip, chunked"), true));
        assertSame(Framing.CHUNKED, Framing.forRequest(
                request(HttpVersion.HTTP_1_1, "Content-Length", "4, 4", "Transfer-Encoding", "CHUNKED"), true));

        List<HttpRequest> refused = List.of(
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", "chunked, gzip"),
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", "identity"),
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", "chunked, chunked"),
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", "chunked",
                        "Transfer-Encoding", "chunked"),
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", "xchunked"),
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", "\"chunked\""),
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", ""),
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Content-Length", "5", "Transfer-Encoding", "chunked"),
                request(HttpVersion.HTTP_1_1, "Content-Length", "4, 5", "Transfer-Encoding", "chunked"),
                request(HttpVersion.HTTP_1_1, "Content-Length", "+4", "Transfer-Encoding", "chunked"),
                request(HttpVersion.HTTP_1_1, "Content-Length", "", "Transfer-Encoding", "chunked"),
                request(HttpVersion.HTTP_1_1, "Content-Length", "4", "Transfer-Encoding", "chunked",
                        "Upgrade", "websocket", "Connection", "Upgrade"),
                connect("Content-Length", "4", "Transfer-Encoding", "chunked"),
                request(HttpVersion.HTTP_1_0, "Content-Length", "4", "Transfer-Encoding", "chunked"));
        for (HttpRequest r : refused) {
            assertThrows(HttpParseException.class, () -> Framing.forRequest(r, true), r.headers().toString());
        }
    }

    // -------------------------------------------------------------------------------------------
    // Through the proxy
    // -------------------------------------------------------------------------------------------

    private static final String SMUGGLED = "GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n";

    private void startProxy(HttpProxyServerBootstrap bootstrap) {
        proxy = bootstrap.withPort(0).start();
    }

    @Test
    void refusedByDefaultAndWithLittleProxyCompatibility() throws Exception {
        startOrigin();
        String request = "POST " + target("/one") + " HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n"
                + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        startProxy(MicroProxy.bootstrap());
        assertTrue(exchange(request).startsWith("HTTP/1.1 400 "));
        proxy.abort();
        // LittleProxy (Netty's HttpObjectDecoder, RFC 9112 mode) answers 400 too.
        startProxy(MicroProxy.bootstrap().withLittleProxyCompatibility());
        assertTrue(exchange(request).startsWith("HTTP/1.1 400 "));
        assertTrue(received.isEmpty(), received.toString());
    }

    @Test
    void acceptedRequestsAreFramedByTheChunkedCodingAndEndTheConnection() throws Exception {
        startOrigin();
        List<String> seenByFilters = new CopyOnWriteArrayList<>();
        List<String> logged = new CopyOnWriteArrayList<>();
        AccessLogFormat format = AccessLogFormat.envoy("%MP_CHUNKED_LENGTH% %RESPONSE_CODE%");
        startProxy(MicroProxy.bootstrap().withName("edge").withAllowChunkedLength(true).withMetrics(true)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest request, FlowContext ctx) {
                        return new HttpFilters() {
                            @Override
                            public HttpResponse clientToProxyRequest(HttpObject o) {
                                if (o instanceof HttpRequest r) {
                                    seenByFilters.add(ctx.isChunkedWithContentLength() + " "
                                            + r.headers().contains(HttpHeaderNames.CONTENT_LENGTH));
                                }
                                return null;
                            }
                        };
                    }
                })
                .plusActivityTracker(new ActivityTracker() {
                    @Override
                    public void flowEnded(FlowRecord record) {
                        logged.add(format.format(record));
                    }
                }));
        // Content-Length says 4: a hop that framed by it would read "5\r\nh" as the body and the
        // rest as a request. The proxy reads the chunked body, then closes: the "pipelined"
        // request after it is never read.
        String response = exchange("POST " + target("/one") + " HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n"
                + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" + SMUGGLED);
        assertTrue(response.startsWith("HTTP/1.1 200 "), response);
        assertEquals(1, count(response, "HTTP/1.1 "), response);
        assertTrue(response.toLowerCase(java.util.Locale.ROOT).contains("connection: close"), response);
        assertTrue(response.endsWith("ok"), response);
        // The server got the body by its chunked coding, without the dropped Content-Length.
        assertEquals(List.of("POST /one | null | chunked | hello"), received);
        // Its connection closed cleanly after that request: nothing else went to it.
        eventually("the origin connection's end", () -> !originEnds.isEmpty());
        assertEquals(List.of("end"), originEnds);
        assertEquals(List.of("true false"), seenByFilters);
        eventually("the access log record", () -> !logged.isEmpty());
        assertEquals(List.of("true 200"), logged);
        assertEquals(1, ((Counter) proxy.getStats().get("http.edge.downstream_rq_chunked_length")).value());
    }

    @Test
    void aLongerContentLengthCannotHideARequestInTheBody() throws Exception {
        startOrigin();
        startProxy(MicroProxy.bootstrap().withAllowChunkedLength(true));
        // A hop that framed by Content-Length would take the empty chunked body and the request
        // after it for one 60-byte body; one that frames by chunked would see two requests. The
        // proxy forwards the first and closes the connection before the second.
        String smuggled = "GET " + target("/smuggled") + " HTTP/1.1\r\nHost: x\r\n\r\n";
        String response = exchange("POST " + target("/one") + " HTTP/1.1\r\nHost: x\r\nContent-Length: "
                + (5 + smuggled.length()) + "\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + smuggled);
        assertEquals(1, count(response, "HTTP/1.1 "), response);
        assertTrue(response.startsWith("HTTP/1.1 200 "), response);
        assertEquals(List.of("POST /one | null | chunked | "), received);
        eventually("the origin connection's end", () -> !originEnds.isEmpty());
        assertEquals(List.of("end"), originEnds);
    }

    @Test
    void aMalformedChunkIsStillRefused() throws Exception {
        startOrigin();
        startProxy(MicroProxy.bootstrap().withAllowChunkedLength(true));
        String response = exchange("POST " + target("/one") + " HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
                + "Transfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n" + SMUGGLED);
        assertTrue(response.startsWith("HTTP/1.1 400 "), response);
        assertEquals(1, count(response, "HTTP/1.1 "), response);
        // The server never got a whole request: its connection was closed mid-body.
        eventually("the origin connection's end", () -> !originEnds.isEmpty());
        assertTrue(received.isEmpty(), received.toString());
        assertFalse(originEnds.contains("end"), originEnds.toString());
    }

    @Test
    void obsoleteFoldingAndBadCodingsAreStillRefused() throws Exception {
        startOrigin();
        startProxy(MicroProxy.bootstrap().withAllowChunkedLength(true));
        for (String headers : List.of(
                "Content-Length: 4\r\nTransfer-Encoding: gzip\r\n",
                "Content-Length: 4\r\nTransfer-Encoding:\r\n chunked\r\n",
                "Content-Length: 4\r\nTransfer-Encoding : chunked\r\n",
                "Content-Length: 4\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n",
                "Content-Length: 4\r\nTransfer-Encoding: chunked, chunked\r\n")) {
            String response = exchange("POST " + target("/one") + " HTTP/1.1\r\nHost: x\r\n" + headers
                    + "\r\n5\r\nhello\r\n0\r\n\r\n");
            assertTrue(response.startsWith("HTTP/1.1 400 "), headers + " -> " + response);
        }
        String http10 = exchange("POST " + target("/one") + " HTTP/1.0\r\nHost: x\r\nContent-Length: 4\r\n"
                + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
        assertTrue(http10.startsWith("HTTP/1.1 400 ") || http10.startsWith("HTTP/1.0 400 "), http10);
        assertTrue(received.isEmpty(), received.toString());
    }

    @Test
    void otherRequestsKeepTheirConnection() throws Exception {
        startOrigin();
        startProxy(MicroProxy.bootstrap().withAllowChunkedLength(true));
        // Without both framings, pipelined requests are served one after another as usual.
        String response = exchange("POST " + target("/one") + " HTTP/1.1\r\nHost: x\r\n"
                + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                + "GET " + target("/two") + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        assertEquals(2, count(response, "HTTP/1.1 200 "), response);
        assertEquals(List.of("POST /one | null | chunked | hello", "GET /two | null | null | "), received);
    }

    @Test
    void serverResponsesWithBothFramingsAreFramedByTheChunkedCoding() throws Exception {
        // Not an option: RFC 9112 section 6.3 has an intermediary drop the Content-Length of such
        // a response and forward it by its transfer coding, which the proxy always does.
        origin = TestSupport.rawServer(s -> {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            HttpCodec.readRequest(in, LIMITS);
            write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + "5\r\nhello\r\n0\r\n\r\n");
            HttpCodec.readRequest(in, LIMITS);
            write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });
        startProxy(MicroProxy.bootstrap());
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(20_000);
            write(s.getOutputStream(), "GET " + target("/one") + " HTTP/1.1\r\nHost: x\r\n\r\n"
                    + "GET " + target("/two") + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            WireLevelTest.Reply first = WireLevelTest.read(in, HttpMethod.GET);
            assertEquals("hello", first.body());
            assertNull(first.head().headers().get(HttpHeaderNames.CONTENT_LENGTH), first.head().headers().toString());
            WireLevelTest.Reply second = WireLevelTest.read(in, HttpMethod.GET);
            assertEquals("ok", second.body());
        }
    }

    // -------------------------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------------------------

    @Test
    void offByDefaultAndSetFromProperties() {
        DefaultHttpProxyServerBootstrap b = (DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap();
        assertFalse(b.allowChunkedLength);
        b.withLittleProxyCompatibility();
        assertFalse(b.allowChunkedLength, "compatibility mode does not turn it on");
        Properties p = new Properties();
        p.setProperty("allow_chunked_length", "true");
        DefaultHttpProxyServerBootstrap fromFile = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertTrue(fromFile.allowChunkedLength);
        assertTrue(fromFile.copy().allowChunkedLength);
    }
}
