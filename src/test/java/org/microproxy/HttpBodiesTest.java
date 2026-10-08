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
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpBodies;
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
        FullHttpResponse r = response(new byte[] {1, 2}, "br", "text/html");
        assertFalse(HttpBodies.canDecode(r));
        assertThrows(IOException.class, () -> HttpBodies.decoded(r));
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
