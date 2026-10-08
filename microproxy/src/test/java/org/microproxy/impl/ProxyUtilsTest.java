package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpRequest;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * The allocation-free helpers behave like the regular expressions they replaced, and the helpers
 * LittleProxy's {@code ProxyUtilsTest} covers behave the same here (differences are noted).
 */
class ProxyUtilsTest {

    private static final Pattern ABSOLUTE = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*://.*");
    private static final Pattern HTTP = Pattern.compile("^(http|ws)s?://.*", Pattern.CASE_INSENSITIVE);

    @Test
    void uriChecksMatchTheOldPatterns() {
        for (String uri : List.of("http://a/b", "HTTPS://a", "ws://x", "wss://x:1/", "ftp://x", "a+b.c-d://x", "1http://x",
                "http:/x", "/path", "", "h", "host:443", "x://", "mailto:me", "HTTP://", "http//x")) {
            assertEquals(ABSOLUTE.matcher(uri).matches(), ProxyUtils.isAbsoluteUri(uri), uri);
            boolean http = HTTP.matcher(uri).matches();
            assertEquals(http, ProxyUtils.parseHostAndPort(uri) != null, uri);
            if (!http) assertSame(uri, ProxyUtils.stripHost(uri));
        }
        assertEquals("h:8", ProxyUtils.parseHostAndPort("HTTP://u:p@h:8/x"));
        assertEquals("/x?y", ProxyUtils.stripHost("Http://h/x?y"));
        assertEquals("/?q", ProxyUtils.stripHost("http://h?q"));
    }

    @Test
    void hopByHopStrippingIsCaseInsensitive() {
        HttpHeaders h = new HttpHeaders();
        h.add("Keep-Alive", "timeout=5").add("X-Kept", "1").add("TE", "trailers").add("upgrade", "h2c");
        ProxyUtils.stripHopByHopHeaders(h);
        assertEquals(1, h.size());
        assertEquals("X-Kept", h.nameAt(0));
    }

    @Test
    void connectionTokensAndListElements() {
        HttpHeaders h = new HttpHeaders();
        h.add("Connection", " close , X-Private").add("X-Private", "secret").add("Transfer-Encoding", "chunked");
        assertTrue(h.containsValue("connection", "CLOSE", true));
        assertFalse(h.containsValue("connection", "CLOSE", false));
        assertFalse(h.containsValue("connection", "clos", true));
        ProxyUtils.stripConnectionTokens(h);
        assertFalse(h.contains("X-Private"));
        assertTrue(h.contains("Transfer-Encoding"));
        assertEquals(1, h.count("connection"));
    }

    @Test
    void sdchIsRemovedOnlyWhenPresent() {
        HttpHeaders h = new HttpHeaders();
        h.add("Accept-Encoding", "gzip,deflate");
        ProxyUtils.removeSdchEncoding(h);
        assertEquals("gzip,deflate", h.get("Accept-Encoding"));
        h.set("Accept-Encoding", "gzip, SDCH, br");
        ProxyUtils.removeSdchEncoding(h);
        assertEquals("gzip, br", h.get("Accept-Encoding"));
        HttpHeaders none = new HttpHeaders();
        ProxyUtils.removeSdchEncoding(none);
        assertNull(none.get("Accept-Encoding"));
    }

    @Test
    void httpDateIsCachedPerSecond() {
        String a = ProxyUtils.httpDate();
        assertTrue(a.matches("[A-Z][a-z]{2}, \\d{2} [A-Z][a-z]{2} \\d{4} \\d{2}:\\d{2}:\\d{2} GMT"), a);
        // Within one second the same string comes back.
        String b = ProxyUtils.httpDate();
        if (a.equals(b)) assertSame(a, b);
    }

    // ---------------------------------------------------------------------------------------
    // Ported from LittleProxy's ProxyUtilsTest
    // ---------------------------------------------------------------------------------------

    @Test
    void parseHostAndPortOfAbsoluteUris() {
        assertEquals("www.test.com:80", ProxyUtils.parseHostAndPort("http://www.test.com:80/test"));
        assertEquals("www.test.com:80", ProxyUtils.parseHostAndPort("https://www.test.com:80/test"));
        assertEquals("www.test.com:443", ProxyUtils.parseHostAndPort("https://www.test.com:443/test"));
        assertEquals("www.test.com", ProxyUtils.parseHostAndPort("http://www.test.com"));
        assertEquals("[::1]:8080", ProxyUtils.parseHostAndPort("http://[::1]:8080/x"));
        // Unlike LittleProxy, scheme-less strings are not URIs here: the Host header decides.
        assertNull(ProxyUtils.parseHostAndPort("www.test.com:80/test"));
        assertNull(ProxyUtils.parseHostAndPort("httpbin.org:443/get"));
        assertNull(ProxyUtils.parseHostAndPort(""));
        assertNull(ProxyUtils.parseHostAndPort("invalid://"));
    }

    @Test
    void defaultPortFollowsTheScheme() {
        assertEquals(80, ProxyUtils.defaultPort("http://a/"));
        assertEquals(443, ProxyUtils.defaultPort("HTTPS://a/"));
        assertEquals(443, ProxyUtils.defaultPort("wss://a/"));
        assertEquals(80, ProxyUtils.defaultPort("ws://a/"));
        assertEquals(80, ProxyUtils.defaultPort("/relative"));
    }

    @Test
    void addViaAddsANewHeader() {
        HttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/endpoint");
        ProxyUtils.addVia(request, "hostname");
        assertEquals(List.of("1.1 hostname"), request.headers().getAll("Via"));
    }

    @Test
    void addViaAppendsToAnExistingHeader() {
        HttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/endpoint");
        request.headers().add("Via", "1.1 otherproxy");
        ProxyUtils.addVia(request, "hostname");
        assertEquals(List.of("1.1 otherproxy", "1.1 hostname"), request.headers().getAll("Via"));
    }

    @Test
    void addViaUsesTheMessageVersion() {
        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_0, HttpResponseStatus.OK);
        ProxyUtils.addVia(response, "old");
        assertEquals("1.0 old", response.headers().get("Via"));
    }

    private static List<String> transferEncodings(String... fieldValues) {
        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        for (String v : fieldValues) response.headers().add("Transfer-Encoding", v);
        return response.headers().getAllElements("Transfer-Encoding");
    }

    @Test
    void commaSeparatedValuesAcrossFields() {
        // LittleProxy's getAllCommaSeparatedHeaderValues is HttpHeaders.getAllElements here.
        assertEquals(List.of(), transferEncodings());
        assertEquals(List.of(), transferEncodings("", ""));
        assertEquals(List.of("chunked"), transferEncodings("chunked"));
        assertEquals(List.of("chunked"), transferEncodings(" chunked  , "));
        assertEquals(List.of("compress", "gzip"), transferEncodings("compress, gzip"));
        assertEquals(List.of("compress", "gzip"), transferEncodings("compress, gzip, ,"));
        assertEquals(List.of("gzip", "chunked"), transferEncodings("gzip", "chunked"));
        assertEquals(List.of("gzip", "compress", "deflate", "gzip"), transferEncodings("gzip, compress", "deflate, gzip"));
        assertEquals(List.of("gzip", "compress", "deflate", "gzip", "gzip", "deflate"),
                transferEncodings(" gzip,compress,", "\tdeflate\t,  gzip, ", ",gzip,,deflate,\t, ,"));
    }

    @Test
    void splitListTrimsAndDropsEmptyElements() {
        assertEquals(List.of("one"), HttpHeaders.splitList("one"));
        assertEquals(List.of("one", "two", "three"), HttpHeaders.splitList("one,two,three"));
        assertEquals(List.of("one", "two", "three"), HttpHeaders.splitList("one, two, three"));
        assertEquals(List.of("one", "two", "three"), HttpHeaders.splitList(" one,two,  three "));
        assertEquals(List.of("one", "two", "three"), HttpHeaders.splitList("\t\tone ,\t two,  three\t"));
        for (String empty : List.of("", ",", " ", "\t", "  \t  \t  ", " ,  ,\t, ")) {
            assertTrue(HttpHeaders.splitList(empty).isEmpty(), "'" + empty + "'");
        }
    }

    private static boolean selfTerminating(HttpResponseStatus status, String... headerPairs) {
        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, status);
        for (int i = 0; i < headerPairs.length; i += 2) response.headers().add(headerPairs[i], headerPairs[i + 1]);
        return ProxyUtils.isResponseSelfTerminating(response);
    }

    @Test
    void isResponseSelfTerminating() {
        HttpResponseStatus ok = HttpResponseStatus.OK;
        // Responses that never have a body.
        assertTrue(selfTerminating(HttpResponseStatus.CONTINUE));
        assertTrue(selfTerminating(HttpResponseStatus.SWITCHING_PROTOCOLS));
        assertTrue(selfTerminating(HttpResponseStatus.NO_CONTENT));
        assertTrue(selfTerminating(HttpResponseStatus.NOT_MODIFIED));
        // LittleProxy counts 205 as bodiless; RFC 9112 6.3 does not, so a 205 must delimit its
        // (empty) body like any other response.
        assertFalse(selfTerminating(HttpResponseStatus.valueOf(205)));
        assertTrue(selfTerminating(HttpResponseStatus.valueOf(205), "Content-Length", "0"));
        // Transfer-Encoding: self-terminating exactly when chunked is the final coding.
        assertTrue(selfTerminating(ok, "Transfer-Encoding", "chunked"));
        assertTrue(selfTerminating(ok, "Transfer-Encoding", "gzip, chunked"));
        assertFalse(selfTerminating(ok, "Transfer-Encoding", "chunked, gzip"));
        assertFalse(selfTerminating(ok, "Transfer-Encoding", "gzip, chunked", "Transfer-Encoding", "deflate, gzip"));
        assertTrue(selfTerminating(ok, "Transfer-Encoding", "gzip", "Transfer-Encoding", "deflate,chunked"));
        // Content-Length, which Transfer-Encoding overrides.
        assertTrue(selfTerminating(ok, "Content-Length", "15"));
        assertTrue(selfTerminating(ok, "Transfer-Encoding", "gzip, chunked", "Content-Length", "15"));
        assertFalse(selfTerminating(ok, "Transfer-Encoding", "gzip", "Content-Length", "15"));
        // Nothing at all: the body ends when the connection closes.
        assertFalse(selfTerminating(ok));
    }

    @Test
    void webSocketUpgradeDetection() {
        HttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/endpoint");
        request.headers().add("Host", "echo.websocket.org");
        request.headers().add("Origin", "https://tests.w");
        request.headers().add("Sec-WebSocket-Extensions", "permessage-deflate");
        request.headers().add("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        request.headers().add("Sec-Fetch-Mode", "websocket");
        request.headers().add("Connection", "keep-alive, Upgrade");
        request.headers().add("Upgrade", "websocket");
        assertTrue(ProxyUtils.isSwitchingToWebSocketProtocol(request));
        request.headers().set("Upgrade", "h2c");
        assertFalse(ProxyUtils.isSwitchingToWebSocketProtocol(request));
        HttpRequest noConnection = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/");
        noConnection.headers().add("Upgrade", "websocket");
        assertFalse(ProxyUtils.isSwitchingToWebSocketProtocol(noConnection), "Upgrade must be a connection option");

        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.SWITCHING_PROTOCOLS);
        response.headers().add("Upgrade", "websocket");
        response.headers().add("Connection", "Upgrade");
        response.headers().add("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assertTrue(ProxyUtils.isSwitchingToWebSocketProtocol(response));
        HttpResponse notSwitching = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        notSwitching.headers().add("Upgrade", "websocket");
        assertFalse(ProxyUtils.isSwitchingToWebSocketProtocol(notSwitching));
    }

    private static List<String> withoutSdch(String... acceptEncodings) {
        HttpHeaders headers = new HttpHeaders();
        for (String v : acceptEncodings) headers.add("Accept-Encoding", v);
        ProxyUtils.removeSdchEncoding(headers);
        return headers.getAll("Accept-Encoding");
    }

    @Test
    void removeSdchEncodingCases() {
        // Without sdch nothing changes, not even the field layout.
        assertEquals(List.of(""), withoutSdch(""));
        assertEquals(List.of("gzip"), withoutSdch("gzip"));
        assertEquals(List.of("gzip", "deflate", "br"), withoutSdch("gzip", "deflate", "br"));
        assertEquals(List.of("gzip, deflate, br"), withoutSdch("gzip, deflate, br"));
        // With sdch the remaining codings are merged into one field (LittleProxy keeps the fields).
        assertEquals(List.of(), withoutSdch("sdch"));
        assertEquals(List.of(), withoutSdch("SDCH"));
        assertEquals(List.of("gzip"), withoutSdch("sdch", "gzip"));
        assertEquals(List.of("gzip"), withoutSdch("sdch, gzip"));
        assertEquals(List.of("gzip, deflate"), withoutSdch("gzip", "sdch", "deflate"));
        assertEquals(List.of("gzip, deflate"), withoutSdch("gzip, sdch, deflate"));
        assertEquals(List.of("gzip, deflate"), withoutSdch("gzip,deflate,sdch"));
        assertEquals(List.of("gzip, deflate, br"), withoutSdch("gzip", "deflate, sdch", "br"));
    }

    @Test
    void clientKeepAliveHonoursVersionAndConnectionHeaders() {
        HttpRequest http11 = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/");
        assertTrue(ProxyUtils.isClientKeepAlive(http11));
        http11.headers().set("Proxy-Connection", "close");
        assertFalse(ProxyUtils.isClientKeepAlive(http11));
        HttpRequest http10 = new DefaultHttpRequest(HttpVersion.HTTP_1_0, HttpMethod.GET, "/");
        assertFalse(ProxyUtils.isClientKeepAlive(http10));
        http10.headers().set("Proxy-Connection", "Keep-Alive");
        assertTrue(ProxyUtils.isClientKeepAlive(http10));
        http10.headers().set("Connection", "close");
        assertFalse(ProxyUtils.isClientKeepAlive(http10));
    }

    @Test
    void methodChecks() {
        assertTrue(ProxyUtils.isCONNECT(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, "h:443")));
        assertFalse(ProxyUtils.isCONNECT(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/")));
        assertTrue(ProxyUtils.isHEAD(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.HEAD, "/")));
        assertFalse(ProxyUtils.isHEAD(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/")));
    }

    @Test
    void createFullHttpResponseSetsExactLengthAndDate() {
        String body = "Bad Gateway: é";
        FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1,
                HttpResponseStatus.BAD_GATEWAY, body);
        assertEquals(String.valueOf(body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length),
                response.headers().get("Content-Length"));
        assertEquals("text/html; charset=utf-8", response.headers().get("Content-Type"));
        assertTrue(response.headers().contains("Date"));
        FullHttpResponse empty = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, null);
        assertEquals("0", empty.headers().get("Content-Length"));
        assertFalse(empty.headers().contains("Content-Type"));
    }
}
