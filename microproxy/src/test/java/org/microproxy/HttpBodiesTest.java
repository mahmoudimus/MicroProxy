package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.microproxy.http.DefaultFullHttpRequest;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.thirdparty.jaybrotli.internal.match.ByteComparisons;

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
    void brotliIsDecodedAndRewrittenAsBrotli() throws IOException {
        FullHttpResponse r = response(BROTLI_10X10Y, "br", "text/plain");
        assertTrue(HttpBodies.canDecode(r));
        assertEquals("XXXXXXXXXXYYYYYYYYYY", HttpBodies.text(r));
        HttpBodies.setText(r, "rewritten");
        assertEquals("br", r.headers().get("Content-Encoding"));
        assertNull(r.headers().get("ETag"));
        assertEquals("rewritten", HttpBodies.text(r));
    }

    /** A fixture made by the reference Brotli encoder (see brotli/generate.py next to this class). */
    private static byte[] resource(String name) throws IOException {
        try (InputStream in = HttpBodiesTest.class.getResourceAsStream("brotli/" + name)) {
            assertNotNull(in, name);
            return in.readAllBytes();
        }
    }

    @ParameterizedTest
    @CsvSource({
        "license.txt, license.txt.q11w22.br",
        "records.json, records.json.q1w16.br",
        "records.json, records.json.q6w24.br"})
    void brotliFromTheReferenceEncoderIsDecoded(String source, String compressed) throws IOException {
        byte[] expected = resource(source);
        FullHttpResponse r = response(resource(compressed), "br", "text/plain");
        assertArrayEquals(expected, HttpBodies.decoded(r));
        assertArrayEquals(Arrays.copyOf(expected, 1000), HttpBodies.decodedPrefix(r, 1000));
        assertArrayEquals(expected, HttpBodies.decodedPrefix(r, expected.length + 1));
    }

    @Test
    void editedBrotliBodiesStayBrotli() throws IOException {
        FullHttpResponse r = response(resource("records.json.q6w24.br"), "br", "application/json");
        String edited = HttpBodies.text(r).replace("item", "thing");
        HttpBodies.setText(r, edited);
        assertEquals("br", r.headers().get("Content-Encoding"));
        assertEquals(edited, HttpBodies.text(r));
        assertTrue(r.content().length < edited.length() / 5, r.content().length + " bytes");

        // Under another coding, too.
        byte[] text = "under gzip".getBytes(StandardCharsets.US_ASCII);
        FullHttpResponse stacked = response(gzip(HttpBodies.encode("br", text)), "br, gzip", "text/plain");
        assertArrayEquals(text, HttpBodies.decoded(stacked));
        HttpBodies.setText(stacked, "still under gzip");
        assertEquals("br, gzip", stacked.headers().get("Content-Encoding"));
        assertEquals("still under gzip", HttpBodies.text(stacked));
    }

    @Test
    void brotliEncodingRoundTrips() throws IOException {
        Random random = new Random(3);
        List<byte[]> inputs = new ArrayList<>();
        // Empty, tiny, around the window sizes chosen for small bodies, and incompressible.
        for (int n : new int[] {0, 1, 1008, 1009, 4080, 4081, 70_000}) {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte) ("<p>Hello, Brotli!</p>\n".charAt(i % 22) + i / 4096);
            inputs.add(b);
        }
        byte[] noise = new byte[50_000];
        random.nextBytes(noise);
        inputs.add(noise);
        for (byte[] input : inputs) {
            byte[] encoded = HttpBodies.encode("br", input);
            assertArrayEquals(input, HttpBodies.decode("br", encoded, input.length), input.length + " bytes");
        }
    }

    // 2,000,000 and 128 MiB of zero bytes, compressed by the reference encoder (quality 5).
    private static final byte[] BROTLI_BOMB_2M = hex("9b7f841e002400e2b14072f83c00");
    private static final byte[] BROTLI_BOMB_128M = hex("cbffff3f002400e2b14072effff8ffff078004401c1680eefd1fffffff00900088"
            + "c302d0bdffe3ffff1f001200715800baf77ffcffff034002200e0b40f7fe8fffff7f004800c46101e8defff1ffff0f000980382c00ddfb3ffe"
            + "ffff012001108705a07bffc7ffff3f002400e2b00074effff8ffff078004401c1680eefd1fffffff00900088c302d0bdffe3ffff1f00120071"
            + "5800baf77ffcffff034002200e0b40f7fe8fffff7f004800c46101e8defff1ffff0f000980382c00ddfb3ffeffff012001108705a07bff37");

    @Test
    void brotliCompressionBombsAreCapped() throws IOException {
        FullHttpResponse small = response(BROTLI_BOMB_2M, "br", null);
        assertEquals(2_000_000, HttpBodies.decoded(small, 2_000_000).length);
        IOException e = assertThrows(IOException.class, () -> HttpBodies.decoded(small, 1_999_999));
        assertEquals("decoded body exceeds 1999999 bytes", e.getMessage());

        FullHttpResponse big = response(BROTLI_BOMB_128M, "br", null);
        e = assertThrows(IOException.class, () -> HttpBodies.decoded(big));
        assertEquals("decoded body exceeds " + HttpBodies.DEFAULT_MAX_DECODED_BYTES + " bytes", e.getMessage());
        assertArrayEquals(new byte[1000], HttpBodies.decodedPrefix(big, 1000));
    }

    @Test
    void truncatedBrotliIsAnIOException() throws IOException {
        byte[] full = resource("license.txt.q11w22.br");
        for (int n = 0; n < full.length; n++) {
            byte[] cut = Arrays.copyOf(full, n);
            IOException e = assertThrows(IOException.class, () -> HttpBodies.decode("br", cut, 1 << 20), "cut to " + n);
            assertEquals("corrupt brotli data", e.getMessage());
        }
        for (int n = 0; n < BROTLI_10X10Y.length; n++) {
            FullHttpResponse cut = response(Arrays.copyOf(BROTLI_10X10Y, n), "br", null);
            assertThrows(IOException.class, () -> HttpBodies.decoded(cut), "cut to " + n);
            assertThrows(IOException.class, () -> HttpBodies.decodedPrefix(cut, 100), "cut to " + n);
        }
    }

    @Test
    void malformedBrotliIsRejectedAsTheReferenceDecoderDoes() {
        // "The quick brown fox jumps over the lazy dog." from the reference encoder, with the
        // meta-block's declared length lowered by one: the last literals run past its end.
        byte[] overrun = hex("1b2a000044db46a92e245b3214c553916772f2e728ba4055d9ca6681f9c22b4f47e445596d4c708b1e185bdd7f084c06");
        assertThrows(IOException.class, () -> HttpBodies.decode("br", overrun, 1 << 20));
        assertThrows(IOException.class, () -> HttpBodies.decodedPrefix(response(overrun, "br", null), 100));
        // Bytes after the end of a stream, zero or not, near it or further on.
        for (String tail : new String[] {"00", "2a", "0000000000000000002a", "1b130000a4b0b2ea8147028a"}) {
            byte[] trailing = hex("1b130000a4b0b2ea8147028a" + tail);
            assertThrows(IOException.class, () -> HttpBodies.decode("br", trailing, 1 << 20), tail);
            assertThrows(IOException.class, () -> HttpBodies.decodedPrefix(response(trailing, "br", null), 100), tail);
        }
    }

    @Test
    void brotliInsertRunningPastItsMetaBlockIsRejectedWhenTheInputEndsThere() throws IOException {
        // An insert command longer than what remains of its meta-block, in a stream whose input
        // ends exactly where the meta-block's declared length (MLEN) is reached, so the output
        // adds up to the declared length; the reference decoder rejects it.
        byte[] overrun = hex("1b190200c4cf6ddf29e9f63281fbf14bd519701208986c4e30eddc9b1c160427135ca643797b70c8"
                + "ed700828a9df8775a3538a8467ecc90beb9d9b122261ff864e0746eac2f9870e7250500e6ca20a61b6a0"
                + "a20b75ccc2844bd0b00acfc844d699cf5e1501");
        IOException e = assertThrows(IOException.class, () -> HttpBodies.decode("br", overrun, 1 << 20));
        assertEquals("corrupt brotli data", e.getMessage());
        FullHttpResponse r = response(overrun, "br", "text/plain");
        e = assertThrows(IOException.class, () -> HttpBodies.decoded(r));
        assertEquals("corrupt brotli data", e.getMessage());
        e = assertThrows(IOException.class, () -> HttpBodies.decodedPrefix(r, 1 << 20));
        assertEquals("corrupt brotli data", e.getMessage());
        FullHttpResponse stacked = response(gzip(overrun), "br, gzip", "text/plain");
        e = assertThrows(IOException.class, () -> HttpBodies.decoded(stacked));
        assertEquals("corrupt brotli data", e.getMessage());
        e = assertThrows(IOException.class, () -> HttpBodies.decodedPrefix(stacked, 1 << 20));
        assertEquals("corrupt brotli data", e.getMessage());
    }

    @Test
    void brotliNeedsNoVectorApiAndFollowsTheSimdSwitch() throws Exception {
        // Without the incubator module (as the proxy normally runs): loads quietly, scalar.
        assertEquals(List.of("scalar", ""), probe());
        assertEquals("scalar", probe("--add-modules", "jdk.incubator.vector", "-Dmicroproxy.simd=false").get(0));
        assertTrue(probe("--add-modules", "jdk.incubator.vector").get(0).startsWith("vector"));
        assertEquals("scalar", probe("--add-modules", "jdk.incubator.vector", "-Djaybrotli.simd=false").get(0));
    }

    /** Runs {@link BrotliProbe} in a new JVM with {@code options}: its output and error output. */
    private static List<String> probe(String... options) throws Exception {
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-cp", System.getProperty("java.class.path")));
        command.addAll(List.of(options));
        command.add(BrotliProbe.class.getName());
        ProcessBuilder builder = new ProcessBuilder(command);
        // These make the JVM print a notice on its error output.
        builder.environment().keySet().removeAll(List.of("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"));
        Process process = builder.start();
        process.getOutputStream().close();
        byte[] err = process.getErrorStream().readAllBytes();
        byte[] out = process.getInputStream().readAllBytes();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS));
        String error = new String(err, StandardCharsets.UTF_8);
        assertEquals(0, process.exitValue(), error);
        return List.of(new String(out, StandardCharsets.UTF_8).strip(), error.strip());
    }

    /** Encodes and decodes a body, then prints the byte comparisons the Brotli encoder chose. */
    static final class BrotliProbe {
        public static void main(String[] args) throws IOException {
            byte[] text = "<li>a list item, again and again</li>\n".repeat(500).getBytes(StandardCharsets.US_ASCII);
            if (!Arrays.equals(text, HttpBodies.decode("br", HttpBodies.encode("br", text), text.length))) {
                throw new AssertionError("round trip");
            }
            System.out.println(ByteComparisons.selected().description());
        }
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
    void decodedPrefixCutsInsteadOfFailing() throws IOException {
        FullHttpResponse bomb = response(gzip(new byte[2_000_000]), "gzip", null);
        assertEquals(1000, HttpBodies.decodedPrefix(bomb, 1000).length);
        byte[] text = "stacked and short".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(text, HttpBodies.decodedPrefix(response(gzip(deflate(text, false)), "deflate, gzip", null), 100));
        assertArrayEquals(text, HttpBodies.decodedPrefix(response(deflate(text, true), "deflate", null), 100));
        assertEquals("XXXXX", new String(HttpBodies.decodedPrefix(response(BROTLI_10X10Y, "br", null), 5),
                StandardCharsets.US_ASCII));
        assertEquals("zstd ", new String(HttpBodies.decodedPrefix(response(ZSTD_SAMPLE, "zstd", null), 5),
                StandardCharsets.US_ASCII));
        assertArrayEquals(text, HttpBodies.decodedPrefix(response(text, null, null), 100), "no coding");
        assertThrows(IOException.class, () -> HttpBodies.decodedPrefix(response(new byte[] {(byte) 0xff, 0x13}, "br", null), 10));
        assertThrows(IOException.class, () -> HttpBodies.decodedPrefix(response(new byte[] {1, 2}, "gzip", null), 10));
        assertThrows(IOException.class, () -> HttpBodies.decodedPrefix(response(new byte[] {1, 2}, "dcb", null), 10));
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
