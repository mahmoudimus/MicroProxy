package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpContent;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.DefaultLastHttpContent;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;

class HttpCodecTest {

    private static final HttpCodec.Limits LIMITS = new HttpCodec.Limits(100, 200, 4);

    private static ByteReader reader(String s) {
        return new ByteReader(new ByteArrayInputStream(s.getBytes(StandardCharsets.ISO_8859_1)), 8);
    }

    @Test
    void parsesRequestHeadPreservingHeaderOrderAndCase() throws IOException {
        HttpRequest r = HttpCodec.readRequest(reader("\r\nGET http://a/b HTTP/1.1\r\nHost: a\r\nX-Foo:  bar \r\nx-foo: baz\r\n\r\n"), LIMITS);
        assertEquals(HttpMethod.GET, r.method());
        assertEquals("http://a/b", r.uri());
        assertEquals(HttpVersion.HTTP_1_1, r.protocolVersion());
        assertEquals(java.util.List.of("bar", "baz"), r.headers().getAll("X-FOO"));
        assertEquals("Host: a\r\nX-Foo: bar\r\nx-foo: baz\r\n", r.headers().toString());
    }

    @Test
    void cleanEofBeforeRequestIsNull() throws IOException {
        assertNull(HttpCodec.readRequest(reader(""), LIMITS));
    }

    @Test
    void rejectsMalformedRequests() {
        assertThrows(HttpParseException.class, () -> HttpCodec.readRequest(reader("GARBAGE\r\n\r\n"), LIMITS));
        assertThrows(HttpParseException.class, () -> HttpCodec.readRequest(reader("GET / HTTP/1.1\r\nBad Header: x\r\n\r\n"), LIMITS));
        assertThrows(HttpParseException.class, () -> HttpCodec.readRequest(reader("GET / HTTP/1.1\r\nA: b\r\n folded\r\n\r\n"), LIMITS));
        HttpParseException tooLong = assertThrows(HttpParseException.class,
                () -> HttpCodec.readRequest(reader("GET /" + "x".repeat(200) + " HTTP/1.1\r\n\r\n"), LIMITS));
        assertEquals(414, tooLong.status().code());
        HttpParseException tooBig = assertThrows(HttpParseException.class,
                () -> HttpCodec.readRequest(reader("GET / HTTP/1.1\r\nA: " + "x".repeat(300) + "\r\n\r\n"), LIMITS));
        assertEquals(431, tooBig.status().code());
        assertThrows(HttpParseException.class, () -> HttpCodec.readRequest(reader("GET / HTTP/2.0\r\n\r\n"), LIMITS));
    }

    @Test
    void parsesResponsesWithAndWithoutReason() throws IOException {
        HttpResponse r = HttpCodec.readResponse(reader("HTTP/1.0 404\r\nA:b\r\n folded\r\n\r\n"), LIMITS);
        assertEquals(404, r.status().code());
        assertEquals("b folded", r.headers().get("a"));
        assertEquals("Custom Thing", HttpCodec.readResponse(reader("HTTP/1.1 299 Custom Thing\r\n\r\n"), LIMITS)
                .status().reasonPhrase());
    }

    @Test
    void decodesChunkedBodyInLimitedPiecesWithTrailers() throws IOException {
        ByteReader in = reader("a;ext=1\r\n0123456789\r\n0\r\nX-T: 1\r\n\r\nNEXT");
        HttpCodec.BodyReader body = new HttpCodec.BodyReader(in, Framing.CHUNKED, LIMITS);
        StringBuilder data = new StringBuilder();
        HttpContent c;
        int pieces = 0;
        LastHttpContent last = null;
        while ((c = body.next()) != null) {
            pieces++;
            assertTrue(c.contentLength() <= 4);
            data.append(c.contentAsString());
            if (c instanceof LastHttpContent l) last = l;
        }
        assertEquals("0123456789", data.toString());
        assertEquals(4, pieces);
        assertEquals("1", last.trailingHeaders().get("x-t"));
        assertEquals("NEXT", new String(in.drainBuffered(), StandardCharsets.ISO_8859_1) + readRest(in));
    }

    private static String readRest(ByteReader in) throws IOException {
        byte[] buf = new byte[100];
        int n = in.read(buf, 0, 100);
        return n < 0 ? "" : new String(buf, 0, n, StandardCharsets.ISO_8859_1);
    }

    @Test
    void fixedLengthBodyFailsOnEarlyEof() throws IOException {
        HttpCodec.BodyReader body = new HttpCodec.BodyReader(reader("abc"), new Framing(Framing.Kind.LENGTH, 5), LIMITS);
        assertEquals("abc", body.next().contentAsString());
        assertThrows(EOFException.class, body::next);
    }

    @Test
    void framingRules() throws IOException {
        DefaultHttpResponse ok = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        assertEquals(Framing.UNTIL_CLOSE, Framing.forResponse(ok, HttpMethod.GET));
        assertEquals(Framing.NONE, Framing.forResponse(ok, HttpMethod.HEAD));
        assertEquals(Framing.NONE, Framing.forResponse(ok, HttpMethod.CONNECT));
        ok.headers().set("Content-Length", "3");
        assertEquals(3, Framing.forResponse(ok, HttpMethod.GET).length());
        ok.headers().set("Transfer-Encoding", "gzip, chunked");
        assertEquals(Framing.CHUNKED, Framing.forResponse(ok, HttpMethod.GET));
        assertNull(ok.headers().get("Content-Length"), "Content-Length must be dropped when chunked");
        assertEquals(Framing.NONE, Framing.forResponse(
                new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_MODIFIED), HttpMethod.GET));
    }

    @Test
    void writerRechunksAndFixesFullMessageLength() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpCodec.HttpWriter writer = new HttpCodec.HttpWriter(out);
        DefaultHttpResponse head = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        head.headers().set("Transfer-Encoding", "chunked");
        writer.writeHead(head, true);
        writer.writeContent(new DefaultHttpContent("hello".getBytes(StandardCharsets.US_ASCII)));
        DefaultLastHttpContent last = new DefaultLastHttpContent();
        last.trailingHeaders().set("X-Sum", "1");
        writer.writeContent(last);
        assertEquals("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Sum: 1\r\n\r\n",
                out.toString(StandardCharsets.ISO_8859_1));

        out.reset();
        DefaultFullHttpResponse full = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, "abc");
        full.headers().set("Content-Length", "999");
        writer.writeHead(full, true);
        assertEquals("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", out.toString(StandardCharsets.ISO_8859_1));
    }

    @Test
    void hostAndPortParsing() {
        assertEquals(new HostAndPort("example.com", 443), HostAndPort.parse("example.com:443", 80));
        assertEquals(new HostAndPort("example.com", 80), HostAndPort.parse("example.com", 80));
        assertEquals(new HostAndPort("::1", 8443), HostAndPort.parse("[::1]:8443", 80));
        assertEquals("[::1]:8443", HostAndPort.parse("[::1]:8443", 80).toString());
        assertThrows(IllegalArgumentException.class, () -> HostAndPort.parse("host:99999", 80));
        assertThrows(IllegalArgumentException.class, () -> HostAndPort.parse("user@host:1", 80));
    }

    @Test
    void uriHelpers() {
        assertEquals("/path?q=1", ProxyUtils.stripHost("http://host:8080/path?q=1"));
        assertEquals("/", ProxyUtils.stripHost("https://host"));
        assertEquals("/?q", ProxyUtils.stripHost("http://host?q"));
        assertEquals("/already", ProxyUtils.stripHost("/already"));
        assertEquals("host:8080", ProxyUtils.parseHostAndPort("http://user:pw@host:8080/x"));
        assertNull(ProxyUtils.parseHostAndPort("/relative"));
        assertInstanceOf(String.class, ProxyUtils.httpDate());
    }

    private static String chunkedBody(String sizeLine) throws IOException {
        HttpCodec.Limits limits = new HttpCodec.Limits(8192, 16384, 1 << 20);
        ByteReader in = reader("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + sizeLine + "\r\nhello\r\n0\r\n\r\n");
        HttpResponse head = HttpCodec.readResponse(in, limits);
        HttpCodec.BodyReader body = new HttpCodec.BodyReader(in, Framing.forResponse(head, HttpMethod.GET), limits);
        StringBuilder text = new StringBuilder();
        HttpContent c;
        while ((c = body.next()) != null) {
            text.append(new String(c.content(), StandardCharsets.ISO_8859_1));
            if (c instanceof LastHttpContent) break;
        }
        return text.toString();
    }

    @Test
    void chunkSizesAreHexDigitsOnly() throws IOException {
        assertEquals("hello", chunkedBody("5"));
        assertEquals("hello", chunkedBody("5;name=value"));
        assertEquals("hello", chunkedBody("5 \t; name"), "whitespace before an extension is allowed");
        assertEquals("hello", chunkedBody("05"));
        for (String bad : new String[] {"-5", "+5", " 5", "0x5", "5 5", "5 ", "", "g"}) {
            assertThrows(HttpParseException.class, () -> chunkedBody(bad), "chunk size '" + bad + "'");
        }
    }
}
