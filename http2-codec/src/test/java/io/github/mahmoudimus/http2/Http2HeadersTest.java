package io.github.mahmoudimus.http2;

import static io.github.mahmoudimus.http2.TestBytes.assertContains;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class Http2HeadersTest {

    private static List<HeaderField> fields(String... namesAndValues) {
        List<HeaderField> out = new ArrayList<>();
        for (int i = 0; i < namesAndValues.length; i += 2) out.add(new HeaderField(namesAndValues[i], namesAndValues[i + 1]));
        return out;
    }

    private static List<HeaderField> get(String... more) {
        List<HeaderField> f = fields(":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/");
        f.addAll(fields(more));
        return f;
    }

    private static void assertMalformedRequest(List<HeaderField> fields, String message) {
        Http2Exception e = assertThrows(Http2Exception.class, () -> Http2Headers.toRequest(3, fields));
        assertEquals(ErrorCode.PROTOCOL_ERROR, e.errorCode());
        assertFalse(e.isConnectionError());
        assertEquals(3, e.streamId());
        assertContains(e.getMessage(), message);
    }

    private static void assertMalformedResponse(List<HeaderField> fields, String message) {
        Http2Exception e = assertThrows(Http2Exception.class, () -> Http2Headers.toResponse(3, fields));
        assertEquals(ErrorCode.PROTOCOL_ERROR, e.errorCode());
        assertFalse(e.isConnectionError());
        assertContains(e.getMessage(), message);
    }

    // --- requests ------------------------------------------------------------------------------

    @Test
    void extendedConnectHasSchemeAndPath() throws Exception {
        RequestHeaders r = Http2Headers.toRequest(1, fields(":method", "CONNECT", ":protocol", "websocket",
                ":scheme", "https", ":authority", "example.com", ":path", "/chat"));
        assertEquals("CONNECT", r.method());
        assertEquals("https", r.scheme());
        assertEquals("/chat", r.path());
        assertMalformedRequest(fields(":method", "GET", ":protocol", "websocket", ":scheme", "https",
                ":authority", "example.com", ":path", "/chat"), ":protocol");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "websocket", ":authority", "example.com"), ":scheme");
    }

    @Test
    void malformedExtendedConnect() {
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "websocket", ":scheme", "https",
                ":authority", "a"), ":path");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "websocket", ":scheme", "https",
                ":path", "/"), ":authority");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "", ":scheme", "https", ":path", "/",
                ":authority", "a"), ":protocol");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "websocket", ":protocol", "websocket",
                ":scheme", "https", ":path", "/", ":authority", "a"), "duplicate :protocol");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "websocket", ":scheme", "https", ":path", "x",
                ":authority", "a"), ":path must start with /");
    }

    @Test
    void validRequest() throws Http2Exception {
        RequestHeaders r = Http2Headers.toRequest(1, get("accept", "*/*", "content-length", "12", "te", "trailers"));
        assertEquals("GET", r.method());
        assertEquals("https", r.scheme());
        assertEquals("example.com", r.authority());
        assertEquals("/", r.path());
        assertEquals(12, r.contentLength());
        assertEquals("*/*", r.get("accept"));
        assertEquals(3, r.fields().size());
        assertFalse(r.isConnect());
    }

    @Test
    void uppercaseName() {
        assertMalformedRequest(get("Accept", "*/*"), "upper-case");
    }

    @Test
    void invalidNameCharacters() {
        assertMalformedRequest(get("x y", "1"), "invalid character");
        assertMalformedRequest(get("x:y", "1"), "invalid character");
        assertMalformedRequest(get("xé", "1"), "invalid character");
        assertMalformedRequest(get("", "1"), "empty field name");
    }

    @Test
    void invalidValues() {
        assertMalformedRequest(get("x-a", "a\r\nb"), "CR or LF");
        assertMalformedRequest(get("x-a", "a\u0000"), "NUL");
        assertMalformedRequest(get("x-a", " a"), "whitespace");
        assertMalformedRequest(get("x-a", "a\t"), "whitespace");
        assertDoesNotThrow(() -> Http2Headers.toRequest(1, get("x-a", "a b\tc", "x-b", "")));
    }

    @Test
    void connectionSpecificFields() {
        for (String name : List.of("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade")) {
            assertMalformedRequest(get(name, "x"), "connection-specific");
        }
    }

    @Test
    void teOtherThanTrailers() {
        assertMalformedRequest(get("te", "gzip"), "te other than trailers");
        assertMalformedRequest(get("te", "trailers, gzip"), "te other than trailers");
        assertDoesNotThrow(() -> Http2Headers.toRequest(1, get("te", "trailers")));
    }

    @Test
    void missingPseudoHeaders() {
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":authority", "a"), "missing :path");
        assertMalformedRequest(fields(":method", "GET", ":path", "/", ":authority", "a"), "missing :scheme");
        assertMalformedRequest(fields(":scheme", "https", ":path", "/", ":authority", "a"), "missing :method");
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":path", ""), "missing :path");
    }

    @Test
    void duplicatePseudoHeader() {
        assertMalformedRequest(fields(":method", "GET", ":method", "POST", ":scheme", "https", ":path", "/"), "duplicate :method");
        assertMalformedRequest(get(":path", "/again"), "duplicate :path");
    }

    @Test
    void pseudoHeaderAfterRegularField() {
        assertMalformedRequest(fields(":method", "GET", "accept", "*/*", ":scheme", "https", ":path", "/"), "after a regular field");
    }

    @Test
    void unknownOrResponsePseudoHeaders() {
        assertMalformedRequest(withFirst(":status", "200"), "not allowed in a request");
        assertMalformedRequest(withFirst(":protocol", "websocket"), "not allowed in a request");
    }

    private static List<HeaderField> withFirst(String name, String value) {
        List<HeaderField> f = new ArrayList<>(fields(name, value));
        f.addAll(get());
        return f;
    }

    @Test
    void authorityRules() throws Http2Exception {
        // host instead of :authority is enough; it becomes the authority.
        RequestHeaders r = Http2Headers.toRequest(1, fields(":method", "GET", ":scheme", "http", ":path", "/x", "host", "h.example"));
        assertEquals("h.example", r.authority());
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":path", "/"), "no :authority or host");
        assertMalformedRequest(get("host", "other.example"), "differs from :authority");
        assertDoesNotThrow(() -> Http2Headers.toRequest(1, get("host", "EXAMPLE.com")));
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":authority", "user@example.com", ":path", "/"), "userinfo");
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":authority", "", ":path", "/"), "empty :authority");
        assertMalformedRequest(get("host", "a", "host", "a"), "more than one host");
        // Other schemes need no authority.
        assertNull(Http2Headers.toRequest(1, fields(":method", "GET", ":scheme", "urn", ":path", "x")).authority());
    }

    @Test
    void pathRules() {
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":authority", "a", ":path", "x"), ":path must start with /");
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":authority", "a", ":path", "*"), ":path must start with /");
        assertDoesNotThrow(() -> Http2Headers.toRequest(1, fields(":method", "OPTIONS", ":scheme", "https", ":authority", "a", ":path", "*")));
    }

    @Test
    void connect() throws Http2Exception {
        RequestHeaders r = Http2Headers.toRequest(1, fields(":method", "CONNECT", ":authority", "example.com:443"));
        assertTrue(r.isConnect());
        assertNull(r.scheme());
        assertNull(r.path());
        assertEquals("example.com:443", r.authority());
        assertMalformedRequest(fields(":method", "CONNECT"), "CONNECT without :authority");
        assertMalformedRequest(fields(":method", "CONNECT", ":authority", "a:1", ":path", "/"), "CONNECT with :scheme or :path");
    }

    @Test
    void cookieCrumbsAreJoined() throws Http2Exception {
        RequestHeaders r = Http2Headers.toRequest(1, get("cookie", "a=1", "accept", "*/*", "cookie", "b=2", "cookie", "c=3"));
        assertEquals(List.of(new HeaderField("cookie", "a=1; b=2; c=3"), new HeaderField("accept", "*/*")), r.fields());
        // Never-indexed crumbs stay sensitive once joined.
        List<HeaderField> f = get();
        f.add(new HeaderField("cookie", "a=1"));
        f.add(new HeaderField("cookie", "s=2", true));
        assertTrue(Http2Headers.toRequest(1, f).fields().get(0).sensitive());
    }

    @Test
    void contentLengthSyntax() throws Http2Exception {
        assertEquals(-1, Http2Headers.toRequest(1, get()).contentLength());
        assertEquals(5, Http2Headers.toRequest(1, get("content-length", "5", "content-length", "5")).contentLength());
        assertEquals(5, Http2Headers.toRequest(1, get("content-length", "5, 5")).contentLength());
        assertMalformedRequest(get("content-length", "5", "content-length", "6"), "conflicting");
        assertMalformedRequest(get("content-length", "-1"), "invalid content-length");
        assertMalformedRequest(get("content-length", "+1"), "invalid content-length");
        assertMalformedRequest(get("content-length", "1,"), "invalid content-length");
        assertMalformedRequest(get("content-length", "99999999999999999999"), "invalid content-length");
    }

    @Test
    void contentLengthAgainstData() throws Http2Exception {
        Http2Headers.checkContentLength(1, -1, 1000, true); // nothing declared
        Http2Headers.checkContentLength(1, 10, 4, false);
        Http2Headers.checkContentLength(1, 10, 10, true);
        Http2Exception over = assertThrows(Http2Exception.class, () -> Http2Headers.checkContentLength(1, 10, 11, false));
        assertEquals(ErrorCode.PROTOCOL_ERROR, over.errorCode());
        assertFalse(over.isConnectionError());
        assertThrows(Http2Exception.class, () -> Http2Headers.checkContentLength(1, 10, 9, true));
    }

    // --- responses and trailers ----------------------------------------------------------------

    @Test
    void responses() throws Http2Exception {
        ResponseHeaders r = Http2Headers.toResponse(1, fields(":status", "200", "content-type", "text/plain", "content-length", "3"));
        assertEquals(200, r.status());
        assertEquals(3, r.contentLength());
        assertEquals("text/plain", r.get("content-type"));
        assertFalse(r.isInformational());
        assertTrue(Http2Headers.toResponse(1, fields(":status", "103", "link", "</a>")).isInformational());

        assertMalformedResponse(fields("content-type", "x"), "missing :status");
        assertMalformedResponse(fields(":status", "20"), "invalid :status");
        assertMalformedResponse(fields(":status", "2000"), "invalid :status");
        assertMalformedResponse(fields(":status", "abc"), "invalid :status");
        assertMalformedResponse(fields(":status", "099"), "invalid :status");
        assertMalformedResponse(fields(":status", "200", ":status", "204"), "duplicate :status");
        assertMalformedResponse(fields(":status", "200", ":path", "/"), "not allowed in a response");
        assertMalformedResponse(fields(":status", "200", "Content-Type", "x"), "upper-case");
        assertMalformedResponse(fields(":status", "200", "transfer-encoding", "chunked"), "connection-specific");
        assertMalformedResponse(fields("server", "x", ":status", "200"), "after a regular field");
    }

    @Test
    void trailers() throws Http2Exception {
        assertEquals(fields("grpc-status", "0"), Http2Headers.validateTrailers(1, fields("grpc-status", "0")));
        assertThrows(Http2Exception.class, () -> Http2Headers.validateTrailers(1, fields(":status", "200")));
        assertThrows(Http2Exception.class, () -> Http2Headers.validateTrailers(1, fields("connection", "close")));
    }

    // --- from HTTP/1 ---------------------------------------------------------------------------

    @Test
    void fromHttp1Request() throws Http2Exception {
        List<Map.Entry<String, String>> h1 = List.of(
                Map.entry("Host", "example.com"),
                Map.entry("User-Agent", "test"),
                Map.entry("Connection", "keep-alive, X-Hop"),
                Map.entry("Keep-Alive", "timeout=5"),
                Map.entry("X-Hop", "gone"),
                Map.entry("Proxy-Connection", "keep-alive"),
                Map.entry("Transfer-Encoding", "chunked"),
                Map.entry("Upgrade", "h2c"),
                Map.entry("HTTP2-Settings", "AAMAAABkAAQAAP__"),
                Map.entry("TE", "trailers, deflate;q=0.5"),
                Map.entry("Cookie", "a=1; b=2;c=3"),
                Map.entry("Accept", " text/html "));
        List<HeaderField> h2 = Http2Headers.fromHttp1Request("GET", "https", null, "/index", h1);
        assertEquals(fields(
                ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/index",
                "user-agent", "test",
                "te", "trailers",
                "cookie", "a=1", "cookie", "b=2", "cookie", "c=3",
                "accept", "text/html"), h2);
        // And it validates as an HTTP/2 request, with the crumbs joined again.
        RequestHeaders r = Http2Headers.toRequest(1, h2);
        assertEquals("a=1; b=2; c=3", r.get("cookie"));
    }

    @Test
    void fromHttp1RequestEdgeCases() throws Http2Exception {
        // An explicit authority wins over host; TE without trailers is dropped.
        List<HeaderField> h2 = Http2Headers.fromHttp1Request("POST", "http", "a.example:8080", "/",
                List.of(Map.entry("host", "a.example:8080"), Map.entry("te", "gzip")));
        assertEquals(fields(":method", "POST", ":scheme", "http", ":authority", "a.example:8080", ":path", "/"), h2);
        // CONNECT carries only :method and :authority.
        assertEquals(fields(":method", "CONNECT", ":authority", "a.example:443"),
                Http2Headers.fromHttp1Request("CONNECT", null, "a.example:443", null, List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> Http2Headers.fromHttp1Request("GET", "http", "a", "/", List.of(Map.entry("x-bad", "a\nb"))));
        assertThrows(IllegalArgumentException.class,
                () -> Http2Headers.fromHttp1Request("GET", "http", "a", "/", List.of(Map.entry("bad name", "x"))));
    }

    @Test
    void fromHttp1Response() throws Http2Exception {
        List<HeaderField> h2 = Http2Headers.fromHttp1Response(404, List.of(
                Map.entry("Content-Type", "text/plain"),
                Map.entry("Connection", "close"),
                Map.entry("Transfer-Encoding", "chunked"),
                Map.entry("Set-Cookie", "id=1; Path=/")));
        // set-cookie is not a cookie: its value is not split.
        assertEquals(fields(":status", "404", "content-type", "text/plain", "set-cookie", "id=1; Path=/"), h2);
        assertEquals(404, Http2Headers.toResponse(1, h2).status());
        assertThrows(IllegalArgumentException.class, () -> Http2Headers.fromHttp1Response(99, List.of()));
    }
}
