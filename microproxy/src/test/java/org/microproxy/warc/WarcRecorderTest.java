package org.microproxy.warc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.cache.HttpCache;

class WarcRecorderTest {

    /** A parsed WARC record. */
    record WarcRecord(Map<String, String> fields, byte[] block) {
        String field(String name) {
            return fields.get(name.toLowerCase());
        }

        String text() {
            return new String(block, StandardCharsets.ISO_8859_1);
        }

        byte[] payload() {
            String t = text();
            int split = t.indexOf("\r\n\r\n");
            return java.util.Arrays.copyOfRange(block, split + 4, block.length);
        }
    }

    @TempDir
    Path dir;
    private HttpServer origin;
    private HttpProxyServer proxy;
    private WarcRecorder recorder;

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(exchange -> {
            byte[] in = exchange.getRequestBody().readAllBytes();
            String path = exchange.getRequestURI().getPath();
            byte[] body = path.equals("/big") ? new byte[3 << 20]
                    : ("hello " + path + (in.length > 0 ? " got " + new String(in, StandardCharsets.UTF_8) : ""))
                            .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.getResponseHeaders().set("Cache-Control", "max-age=60");
            // Length 0 makes the JDK server use chunked transfer coding.
            exchange.sendResponseHeaders(200, path.equals("/chunked") ? 0 : body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
    }

    @AfterEach
    void tearDown() throws IOException {
        if (proxy != null) proxy.abort();
        if (recorder != null) recorder.close();
        origin.stop(0);
    }

    private void start(WarcRecorder.Builder builder, HttpCache cache) throws IOException {
        recorder = builder.build();
        var b = MicroProxy.bootstrap().withPort(0).withFiltersSource(recorder);
        if (cache != null) b.withHttpCache(cache);
        proxy = b.start();
        proxy.closeOnStop(recorder);
    }

    /** Stops the proxy, which closes the recorder once in-flight exchanges are written. */
    private void finish() {
        proxy.stop();
    }

    private List<Path> warcFiles() throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.toString().endsWith(".warc.gz")).sorted().toList();
        }
    }

    static List<WarcRecord> read(Path file) throws IOException {
        List<WarcRecord> records = new ArrayList<>();
        try (DataInputStream in = new DataInputStream(new GZIPInputStream(Files.newInputStream(file)))) {
            while (true) {
                String version;
                try {
                    version = line(in);
                } catch (EOFException e) {
                    break;
                }
                assertEquals("WARC/1.1", version);
                Map<String, String> fields = new LinkedHashMap<>();
                String l;
                while (!(l = line(in)).isEmpty()) {
                    int colon = l.indexOf(':');
                    fields.put(l.substring(0, colon).toLowerCase(), l.substring(colon + 1).strip());
                }
                byte[] block = new byte[Integer.parseInt(fields.get("content-length"))];
                in.readFully(block);
                byte[] end = new byte[4];
                in.readFully(end);
                assertEquals("\r\n\r\n", new String(end, StandardCharsets.US_ASCII));
                records.add(new WarcRecord(fields, block));
            }
        }
        return records;
    }

    private static String line(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != '\n') {
            if (c < 0) throw new EOFException();
            b.write(c);
        }
        String s = b.toString(StandardCharsets.UTF_8);
        return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
    }

    static String sha1(byte[] data) throws Exception {
        return "sha1:" + Warc.base32(MessageDigest.getInstance("SHA-1").digest(data));
    }

    @Test
    void recordsRequestAndResponsePairs() throws Exception {
        start(WarcRecorder.builder(dir), null);
        get(client(proxy), url(origin, "/page"));
        get(client(proxy), url(origin, "/chunked"));
        send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/form")))
                .POST(HttpRequest.BodyPublishers.ofString("a=1")).build());
        finish();
        assertEquals(3, recorder.recordedExchanges());

        List<Path> files = warcFiles();
        assertEquals(1, files.size());
        assertTrue(files.get(0).getFileName().toString().matches("microproxy-\\d{17}-00000\\.warc\\.gz"));
        List<WarcRecord> records = read(files.get(0));
        assertEquals(7, records.size());
        WarcRecord info = records.get(0);
        assertEquals("warcinfo", info.field("WARC-Type"));
        assertTrue(info.text().contains("software: MicroProxy"));
        for (WarcRecord r : records) {
            assertEquals(sha1(r.block()), r.field("WARC-Block-Digest"));
            if (r != info) assertEquals(info.field("WARC-Record-ID"), r.field("WARC-Warcinfo-ID"));
        }

        WarcRecord page = records.get(1);
        assertEquals("response", page.field("WARC-Type"));
        assertEquals(url(origin, "/page"), page.field("WARC-Target-URI"));
        assertEquals("127.0.0.1", page.field("WARC-IP-Address"));
        assertEquals("application/http;msgtype=response", page.field("Content-Type"));
        assertTrue(page.text().startsWith("HTTP/1.1 200 OK\r\n"), page.text());
        assertEquals("hello /page", new String(page.payload(), StandardCharsets.UTF_8));
        assertEquals(sha1(page.payload()), page.field("WARC-Payload-Digest"));
        WarcRecord pageRequest = records.get(2);
        assertEquals("request", pageRequest.field("WARC-Type"));
        assertEquals(page.field("WARC-Record-ID"), pageRequest.field("WARC-Concurrent-To"));
        assertTrue(pageRequest.text().startsWith("GET /page HTTP/1.1\r\n"), pageRequest.text());

        WarcRecord chunked = records.get(3);
        assertFalse(chunked.text().toLowerCase().contains("transfer-encoding"), chunked.text());
        assertTrue(chunked.text().contains("Content-Length: " + "hello /chunked".length()), chunked.text());

        WarcRecord form = records.get(6);
        assertTrue(form.text().startsWith("POST /form HTTP/1.1\r\n"));
        assertEquals("a=1", new String(form.payload(), StandardCharsets.UTF_8));
        assertEquals("hello /form got a=1", new String(records.get(5).payload(), StandardCharsets.UTF_8));
    }

    @Test
    void largeBodiesSpillToDiskAndAreTruncatedAtTheLimit() throws Exception {
        start(WarcRecorder.builder(dir).maxBodySize(2 << 20), null);
        assertEquals(3 << 20, get(client(proxy), url(origin, "/big")).body().length());
        finish();
        WarcRecord big = read(warcFiles().get(0)).get(1);
        assertEquals("length", big.field("WARC-Truncated"));
        assertEquals(2 << 20, big.payload().length);
        try (Stream<Path> files = Files.list(dir)) {
            assertEquals(1, files.count(), "temporary spool files are gone");
        }
    }

    @Test
    void filesRotateAtTheSizeLimit() throws Exception {
        start(WarcRecorder.builder(dir).maxFileSize(1), null);
        for (int i = 0; i < 3; i++) get(client(proxy), url(origin, "/p" + i));
        finish();
        List<Path> files = warcFiles();
        assertEquals(3, files.size());
        for (Path f : files) {
            List<WarcRecord> records = read(f);
            assertEquals("warcinfo", records.get(0).field("WARC-Type"));
            assertEquals(f.getFileName().toString(), records.get(0).field("WARC-Filename"));
            assertEquals(3, records.size());
        }
    }

    @Test
    void cachedResponsesAreNotRecorded() throws Exception {
        start(WarcRecorder.builder(dir), HttpCache.builder().build());
        get(client(proxy), url(origin, "/page"));
        get(client(proxy), url(origin, "/page"));
        finish();
        assertEquals(1, recorder.recordedExchanges());
        assertEquals(3, read(warcFiles().get(0)).size());
    }
}
