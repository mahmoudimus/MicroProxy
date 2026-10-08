package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpRequest;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

class HttpBodiesTest {

    static byte[] gzip(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(data);
        }
        return out.toByteArray();
    }

    static byte[] deflate(byte[] data, boolean raw) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DeflaterOutputStream d = new DeflaterOutputStream(out, new Deflater(Deflater.DEFAULT_COMPRESSION, raw))) {
            d.write(data);
        }
        return out.toByteArray();
    }

    private static FullHttpResponse response(byte[] body, String encoding, String contentType) {
        FullHttpResponse r = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, body);
        if (encoding != null) r.headers().set("Content-Encoding", encoding);
        if (contentType != null) r.headers().set("Content-Type", contentType);
        r.headers().set("ETag", "\"v1\"");
        return r;
    }

    @Test
    void gzipRoundTripKeepsEncodingAndDropsValidators() throws IOException {
        FullHttpResponse r = response(gzip("héllo".getBytes(StandardCharsets.UTF_8)), "gzip", "text/html; charset=UTF-8");
        assertTrue(HttpBodies.canDecode(r));
        assertEquals("héllo", HttpBodies.text(r));
        HttpBodies.setText(r, "bye");
        assertEquals("gzip", r.headers().get("Content-Encoding"));
        assertNull(r.headers().get("ETag"));
        assertEquals("bye", HttpBodies.text(r));
    }

    @Test
    void deflateAcceptsZlibAndRawStreams() throws IOException {
        byte[] text = "deflated".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(text, HttpBodies.decoded(response(deflate(text, false), "deflate", null)));
        assertArrayEquals(text, HttpBodies.decoded(response(deflate(text, true), "deflate", null)));
    }

    @Test
    void stackedCodingsAndRemoval() throws IOException {
        byte[] text = "twice".getBytes(StandardCharsets.US_ASCII);
        FullHttpResponse r = response(gzip(deflate(text, false)), "deflate, gzip", "text/plain");
        assertArrayEquals(text, HttpBodies.decoded(r));
        HttpBodies.removeContentEncoding(r);
        assertNull(r.headers().get("Content-Encoding"));
        assertArrayEquals(text, r.content());
    }

    @Test
    void unsupportedCodingsAreReported() {
        FullHttpResponse r = response(new byte[] {1, 2}, "dcb", "text/html");
        assertFalse(HttpBodies.canDecode(r));
        assertThrows(IOException.class, () -> HttpBodies.decoded(r));
    }

    // "XXXXXXXXXXYYYYYYYYYY" from the brotli project's test vectors (tests/testdata/10x10y).
    private static final byte[] BROTLI_10X10Y = {
        0x1b, 0x13, 0x00, 0x00, (byte) 0xa4, (byte) 0xb0, (byte) 0xb2, (byte) 0xea, (byte) 0x81, 0x47, 0x02, (byte) 0x8a};

    @Test
    void brotliIsDecodedAndRewrittenAsGzip() throws IOException {
        FullHttpResponse r = response(BROTLI_10X10Y, "br", "text/plain");
        assertTrue(HttpBodies.canDecode(r));
        assertEquals("XXXXXXXXXXYYYYYYYYYY", HttpBodies.text(r));
        HttpBodies.setText(r, "rewritten");
        assertEquals("gzip", r.headers().get("Content-Encoding"));
        assertEquals("rewritten", HttpBodies.text(r));
    }

    // ("zstd through the proxy! " * 40).strip() compressed by zstd -19: a repeat-offset match.
    private static final byte[] ZSTD_SAMPLE = hex(
            "28b52ffd04680501 00c07a7374642074 68726f7567682074 68652070726f7879 2120010090de6a8e 0160d331d9");

    private static byte[] hex(String s) {
        return java.util.HexFormat.of().parseHex(s.replace(" ", ""));
    }

    @Test
    void zstdIsDecodedWhenTheModuleIsPresentAndRewrittenAsGzip() throws IOException {
        assertTrue(HttpBodies.DECODABLE.contains("zstd"));
        FullHttpResponse r = response(ZSTD_SAMPLE, "zstd", "text/plain");
        assertTrue(HttpBodies.canDecode(r));
        assertEquals(("zstd through the proxy! ".repeat(40)).strip(), HttpBodies.text(r));
        HttpBodies.setText(r, "rewritten");
        assertEquals("gzip", r.headers().get("Content-Encoding"));
        assertEquals("rewritten", HttpBodies.text(r));
        FullHttpResponse corrupt = response(new byte[] {0x28, (byte) 0xB5, 0x2F, (byte) 0xFD, 1}, "zstd", "text/plain");
        assertThrows(IOException.class, () -> HttpBodies.decoded(corrupt));
    }

    @Test
    void corruptBrotliIsAnIOException() {
        FullHttpResponse r = response(new byte[] {(byte) 0xff, 0x13, 0x00}, "br", "text/plain");
        assertThrows(IOException.class, () -> HttpBodies.decoded(r));
    }

    @Test
    void acceptEncodingIsNarrowedToDecodableCodings() {
        HttpRequest req = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/");
        req.headers().set("Accept-Encoding", "zstd, br;q=0.9, gzip, dcb, dcz");
        HttpBodies.restrictAcceptEncoding(req);
        assertEquals("zstd, br;q=0.9, gzip", req.headers().get("Accept-Encoding"));
        req.headers().set("Accept-Encoding", "dcz, *");
        HttpBodies.restrictAcceptEncoding(req);
        assertEquals("identity", req.headers().get("Accept-Encoding"));
    }

    @Test
    void compressionBombsAreCapped() throws IOException {
        FullHttpResponse r = response(gzip(new byte[2_000_000]), "gzip", null);
        assertTrue(r.content().length < 10_000);
        assertThrows(IOException.class, () -> HttpBodies.decoded(r, 1_000_000));
    }

    @Test
    void charsetAndMediaTypeParsing() {
        assertEquals(StandardCharsets.ISO_8859_1,
                HttpBodies.charset(response(new byte[0], null, "text/html; Charset=\"iso-8859-1\"; x=y"), StandardCharsets.UTF_8));
        assertEquals(StandardCharsets.UTF_8,
                HttpBodies.charset(response(new byte[0], null, "text/html; charset=bogus-charset"), StandardCharsets.UTF_8));
        assertEquals("application/json", HttpBodies.mediaType(response(new byte[0], null, "Application/JSON ; charset=utf-8")));
        assertTrue(HttpBodies.isText(response(new byte[0], null, "application/vnd.api+json")));
        assertFalse(HttpBodies.isText(response(new byte[0], null, "image/png")));
    }
}
