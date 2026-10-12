package org.microproxy.warc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;

class WarcReaderTest {

    @TempDir
    Path dir;

    private static List<WarcReader.Record> readAll(WarcReader reader) throws IOException {
        List<WarcReader.Record> out = new ArrayList<>();
        for (WarcReader.Record r; (r = reader.next()) != null; ) out.add(r);
        return out;
    }

    @Test
    void readsWhatTheRecorderWrites() throws IOException {
        for (boolean compress : new boolean[] {true, false}) {
            Path warcs = dir.resolve("c" + compress);
            com.sun.net.httpserver.HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "archived"));
            WarcRecorder recorder = WarcRecorder.builder(warcs).compress(compress).build();
            HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(recorder).start();
            try {
                TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/page"));
            } finally {
                proxy.stop();
                origin.stop(0);
                recorder.close();
            }
            Path file;
            try (Stream<Path> files = Files.list(warcs)) {
                file = files.findFirst().orElseThrow();
            }
            try (WarcReader reader = WarcReader.open(file)) {
                List<WarcReader.Record> records = readAll(reader);
                assertEquals(List.of("warcinfo", "response", "request"), records.stream().map(WarcReader.Record::type).toList());
                WarcReader.Record response = records.get(1);
                assertEquals("WARC/1.1", response.version());
                assertTrue(response.field("warc-target-uri").endsWith("/page"), "fields ignore case");
                assertEquals(response.id(), records.get(2).field("WARC-Concurrent-To"));
                String block = new String(response.block(), StandardCharsets.ISO_8859_1);
                assertTrue(block.startsWith("HTTP/1.1 200"), block);
                assertTrue(block.endsWith("\r\n\r\narchived"), block);
            }
        }
    }

    @Test
    void readsFoldedFieldsAndRejectsOtherData() throws IOException {
        String warc = "WARC/1.0\r\nWARC-Type: resource\r\nWARC-Target-URI: http://x/\r\n  continued\r\n"
                + "Content-Length: 3\r\n\r\nabc\r\n\r\n";
        try (WarcReader reader = new WarcReader(new ByteArrayInputStream(warc.getBytes(StandardCharsets.UTF_8)))) {
            WarcReader.Record r = reader.next();
            assertEquals("http://x/ continued", r.field("WARC-Target-URI"));
            assertEquals("abc", new String(r.block(), StandardCharsets.UTF_8));
            assertNull(reader.next());
        }
        try (WarcReader reader = new WarcReader(new ByteArrayInputStream("{\"log\":{}}".getBytes(StandardCharsets.UTF_8)))) {
            assertThrows(IOException.class, reader::next);
        }
        String cut = "WARC/1.1\r\nWARC-Type: response\r\nContent-Length: 10\r\n\r\nabc";
        try (WarcReader reader = new WarcReader(new ByteArrayInputStream(cut.getBytes(StandardCharsets.UTF_8)))) {
            assertThrows(java.io.EOFException.class, reader::next);
        }
    }
}
