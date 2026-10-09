package io.github.mahmoudimus.http3;

import static io.github.mahmoudimus.http3.TestBytes.assertContains;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Request, response and trailer validation (RFC 9114 §4.2, §4.3; RFC 9220). */
class Http3HeadersTest {

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
        Http3Exception e = assertThrows(Http3Exception.class, () -> Http3Headers.toRequest(4, fields));
        assertEquals(Http3ErrorCode.H3_MESSAGE_ERROR, e.errorCode());
        assertFalse(e.isConnectionError());
        assertEquals(4, e.streamId());
        assertContains(e.getMessage(), message);
    }

    private static void assertMalformedResponse(List<HeaderField> fields, String message) {
        Http3Exception e = assertThrows(Http3Exception.class, () -> Http3Headers.toResponse(0, fields));
        assertEquals(Http3ErrorCode.H3_MESSAGE_ERROR, e.errorCode());
        assertEquals(0, e.streamId()); // stream 0 is a real stream in QUIC
        assertFalse(e.isConnectionError());
        assertContains(e.getMessage(), message);
    }

    // --- requests ------------------------------------------------------------------------------

    @Test
    void validRequest() throws Http3Exception {
        RequestHeaders r = Http3Headers.toRequest(0, get("accept", "*/*", "content-length", "12", "te", "trailers"));
        assertEquals("GET", r.method());
        assertEquals("https", r.scheme());
        assertEquals("example.com", r.authority());
        assertEquals("/", r.path());
        assertNull(r.protocol());
        assertEquals(12, r.contentLength());
        assertEquals("*/*", r.get("accept"));
        assertEquals(List.of("trailers"), r.getAll("te"));
        assertEquals(3, r.fields().size());
        assertFalse(r.isConnect());
        assertFalse(r.isExtendedConnect());
    }

    @Test
    void pseudoHeaderRules() {
        assertMalformedRequest(fields(":scheme", "https", ":authority", "a", ":path", "/"), "missing :method");
        assertMalformedRequest(fields(":method", "GET", ":authority", "a", ":path", "/"), "missing :scheme");
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":authority", "a"), "missing :path");
        assertMalformedRequest(fields(":method", "GET", ":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/"),
                "duplicate :method");
        assertMalformedRequest(fields(":method", "GET", "accept", "*/*", ":scheme", "https", ":authority", "a", ":path", "/"),
                "after a regular field");
        assertMalformedRequest(get("accept", "*/*", ":path", "/x"), "after a regular field");
        assertMalformedRequest(fields(":method", "GET", ":status", "200", ":scheme", "https", ":authority", "a", ":path", "/"),
                "not allowed in a request");
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":authority", "a", ":path", "x"), "must start with /");
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":path", "/"), "no :authority or host");
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":authority", "", ":path", "/"), "empty :authority");
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":authority", "u@h", ":path", "/"), "userinfo");
        assertMalformedRequest(get("host", "other.com"), "differs from :authority");
    }

    @Test
    void hostStandsInForAuthority() throws Http3Exception {
        RequestHeaders r = Http3Headers.toRequest(0, fields(":method", "OPTIONS", ":scheme", "http", ":path", "*", "host", "h.example"));
        assertEquals("h.example", r.authority());
        assertEquals("*", r.path());
        assertDoesNotThrow(() -> Http3Headers.toRequest(0, get("host", "EXAMPLE.com")));
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":path", "/", "host", ""), "empty host");
        assertMalformedRequest(fields(":method", "GET", ":scheme", "https", ":path", "/", "host", "a", "host", "b"), "more than one host");
    }

    @Test
    void connect() throws Http3Exception {
        RequestHeaders r = Http3Headers.toRequest(0, fields(":method", "CONNECT", ":authority", "proxy.example:443"));
        assertTrue(r.isConnect());
        assertFalse(r.isExtendedConnect());
        assertNull(r.scheme());
        assertNull(r.path());
        assertMalformedRequest(fields(":method", "CONNECT", ":authority", "a:1", ":path", "/"), "CONNECT with :scheme or :path");
        assertMalformedRequest(fields(":method", "CONNECT"), "CONNECT without :authority");
    }

    @Test
    void extendedConnect() throws Http3Exception {
        List<HeaderField> ws = fields(":method", "CONNECT", ":protocol", "websocket", ":scheme", "https",
                ":path", "/chat", ":authority", "example.com", "sec-websocket-version", "13");
        RequestHeaders r = Http3Headers.toRequest(0, ws);
        assertTrue(r.isConnect());
        assertTrue(r.isExtendedConnect());
        assertEquals("websocket", r.protocol());
        assertEquals("/chat", r.path());
        // Without SETTINGS_ENABLE_CONNECT_PROTOCOL, :protocol is not allowed.
        Http3Exception e = assertThrows(Http3Exception.class, () -> Http3Headers.toRequest(4, ws, false));
        assertContains(e.getMessage(), "SETTINGS_ENABLE_CONNECT_PROTOCOL");
        assertMalformedRequest(fields(":method", "GET", ":protocol", "websocket", ":scheme", "https", ":path", "/", ":authority", "a"),
                ":protocol with :method GET");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "websocket", ":authority", "a"), "without :scheme");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "websocket", ":scheme", "https", ":authority", "a"),
                "without :path");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "connect-udp", ":scheme", "https", ":path", "/x"),
                "without :authority");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "", ":scheme", "https", ":path", "/", ":authority", "a"),
                "empty :protocol");
        assertMalformedRequest(fields(":method", "CONNECT", ":protocol", "a", ":protocol", "b", ":scheme", "https", ":path", "/",
                ":authority", "a"), "duplicate :protocol");
    }

    @Test
    void fieldNameAndValueRules() {
        assertMalformedRequest(get("Accept", "*/*"), "upper-case");
        assertMalformedRequest(get("bad name", "x"), "invalid character");
        assertMalformedRequest(get("", "x"), "empty field name");
        assertMalformedRequest(get("x-a", "a\r\nb"), "NUL, CR or LF");
        assertMalformedRequest(get("x-a", " padded"), "whitespace");
        assertMalformedRequest(get("x-a", "Ā"), "not octets");
        for (String name : Http3Headers.CONNECTION_SPECIFIC) assertMalformedRequest(get(name, "x"), "connection-specific");
        assertMalformedRequest(get("te", "gzip"), "te other than trailers");
    }

    @Test
    void contentLength() throws Http3Exception {
        assertEquals(5, Http3Headers.toRequest(0, get("content-length", "5, 5", "content-length", "5")).contentLength());
        assertMalformedRequest(get("content-length", "5", "content-length", "6"), "conflicting");
        assertMalformedRequest(get("content-length", "-1"), "invalid content-length");
        assertMalformedRequest(get("content-length", "1234567890123456789"), "invalid content-length");
        assertDoesNotThrow(() -> Http3Headers.checkContentLength(0, 10, 10, true));
        assertDoesNotThrow(() -> Http3Headers.checkContentLength(0, -1, 99, true));
        assertThrows(Http3Exception.class, () -> Http3Headers.checkContentLength(0, 10, 11, false));
        assertThrows(Http3Exception.class, () -> Http3Headers.checkContentLength(0, 10, 9, true));
    }

    @Test
    void cookieCrumbsAreJoined() throws Http3Exception {
        List<HeaderField> f = get("cookie", "a=1", "accept", "*/*");
        f.add(new HeaderField("cookie", "b=2", true));
        RequestHeaders r = Http3Headers.toRequest(0, f);
        assertEquals(new HeaderField("cookie", "a=1; b=2", true), r.fields().get(0));
        assertEquals(2, r.fields().size());
    }

    // --- responses and trailers ----------------------------------------------------------------

    @Test
    void responses() throws Http3Exception {
        ResponseHeaders r = Http3Headers.toResponse(0, fields(":status", "200", "content-type", "text/plain", "content-length", "3"));
        assertEquals(200, r.status());
        assertEquals("text/plain", r.get("content-type"));
        assertEquals(3, r.contentLength());
        assertFalse(r.isInformational());
        assertTrue(Http3Headers.toResponse(0, fields(":status", "103", "link", "</a>")).isInformational());
        assertMalformedResponse(fields("content-type", "x"), "missing :status");
        assertMalformedResponse(fields(":status", "2000"), "invalid :status");
        assertMalformedResponse(fields(":status", "099"), "invalid :status");
        assertMalformedResponse(fields(":status", "20x"), "invalid :status");
        assertMalformedResponse(fields(":status", "200", ":status", "204"), "duplicate");
        assertMalformedResponse(fields(":status", "200", ":path", "/"), "not allowed in a response");
        assertMalformedResponse(fields(":status", "200", "transfer-encoding", "chunked"), "connection-specific");
    }

    @Test
    void trailers() throws Http3Exception {
        assertEquals(fields("grpc-status", "0"), Http3Headers.validateTrailers(0, fields("grpc-status", "0")));
        assertThrows(Http3Exception.class, () -> Http3Headers.validateTrailers(0, fields(":status", "200")));
        assertThrows(Http3Exception.class, () -> Http3Headers.validateTrailers(0, fields("Upper", "x")));
    }
}
