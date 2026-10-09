package io.github.mahmoudimus.http2;

import static io.github.mahmoudimus.http2.TestBytes.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Every example of RFC 7541 Appendix C, decoded and encoded, with the dynamic table compared after
 * each header list. The data was taken from the RFC text by script; table entries are listed
 * newest first, as in the RFC.
 */
class HpackRfcExamplesTest {

    record Step(String hex, List<HeaderField> headers, List<HeaderField> table, int tableSize) {}

    static Step step(String hex, List<HeaderField> headers, List<HeaderField> table, int tableSize) {
        return new Step(hex, headers, table, tableSize);
    }

    static HeaderField f(String name, String value) {
        return new HeaderField(name, value);
    }

    static final List<Step> C2 = List.of(
            // C.2.1 Literal Header Field with Indexing
            step("400a637573746f6d2d6b65790d637573746f6d2d686561646572",
                    List.of(f("custom-key", "custom-header")),
                    List.of(f("custom-key", "custom-header")),
                    55),
            // C.2.2 Literal Header Field without Indexing
            step("040c2f73616d706c652f70617468",
                    List.of(f(":path", "/sample/path")),
                    List.of(),
                    0),
            // C.2.3 Literal Header Field Never Indexed
            step("100870617373776f726406736563726574",
                    List.of(f("password", "secret")),
                    List.of(),
                    0),
            // C.2.4 Indexed Header Field
            step("82",
                    List.of(f(":method", "GET")),
                    List.of(),
                    0));

    static final List<Step> C3 = List.of(
            // C.3.1 First Request
            step("828684410f7777772e6578616d706c652e636f6d",
                    List.of(f(":method", "GET"), f(":scheme", "http"), f(":path", "/"), f(":authority", "www.example.com")),
                    List.of(f(":authority", "www.example.com")),
                    57),
            // C.3.2 Second Request
            step("828684be58086e6f2d6361636865",
                    List.of(f(":method", "GET"), f(":scheme", "http"), f(":path", "/"), f(":authority", "www.example.com"), f("cache-control", "no-cache")),
                    List.of(f("cache-control", "no-cache"), f(":authority", "www.example.com")),
                    110),
            // C.3.3 Third Request
            step("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
                    List.of(f(":method", "GET"), f(":scheme", "https"), f(":path", "/index.html"), f(":authority", "www.example.com"), f("custom-key", "custom-value")),
                    List.of(f("custom-key", "custom-value"), f("cache-control", "no-cache"), f(":authority", "www.example.com")),
                    164));

    static final List<Step> C4 = List.of(
            // C.4.1 First Request
            step("828684418cf1e3c2e5f23a6ba0ab90f4ff",
                    List.of(f(":method", "GET"), f(":scheme", "http"), f(":path", "/"), f(":authority", "www.example.com")),
                    List.of(f(":authority", "www.example.com")),
                    57),
            // C.4.2 Second Request
            step("828684be5886a8eb10649cbf",
                    List.of(f(":method", "GET"), f(":scheme", "http"), f(":path", "/"), f(":authority", "www.example.com"), f("cache-control", "no-cache")),
                    List.of(f("cache-control", "no-cache"), f(":authority", "www.example.com")),
                    110),
            // C.4.3 Third Request
            step("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
                    List.of(f(":method", "GET"), f(":scheme", "https"), f(":path", "/index.html"), f(":authority", "www.example.com"), f("custom-key", "custom-value")),
                    List.of(f("custom-key", "custom-value"), f("cache-control", "no-cache"), f(":authority", "www.example.com")),
                    164));

    static final List<Step> C5 = List.of(
            // C.5.1 First Response
            step("4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
                    List.of(f(":status", "302"), f("cache-control", "private"), f("date", "Mon, 21 Oct 2013 20:13:21 GMT"), f("location", "https://www.example.com")),
                    List.of(f("location", "https://www.example.com"), f("date", "Mon, 21 Oct 2013 20:13:21 GMT"), f("cache-control", "private"), f(":status", "302")),
                    222),
            // C.5.2 Second Response
            step("4803333037c1c0bf",
                    List.of(f(":status", "307"), f("cache-control", "private"), f("date", "Mon, 21 Oct 2013 20:13:21 GMT"), f("location", "https://www.example.com")),
                    List.of(f(":status", "307"), f("location", "https://www.example.com"), f("date", "Mon, 21 Oct 2013 20:13:21 GMT"), f("cache-control", "private")),
                    222),
            // C.5.3 Third Response
            step("88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
                    List.of(f(":status", "200"), f("cache-control", "private"), f("date", "Mon, 21 Oct 2013 20:13:22 GMT"), f("location", "https://www.example.com"), f("content-encoding", "gzip"), f("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")),
                    List.of(f("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"), f("content-encoding", "gzip"), f("date", "Mon, 21 Oct 2013 20:13:22 GMT")),
                    215));

    static final List<Step> C6 = List.of(
            // C.6.1 First Response
            step("488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
                    List.of(f(":status", "302"), f("cache-control", "private"), f("date", "Mon, 21 Oct 2013 20:13:21 GMT"), f("location", "https://www.example.com")),
                    List.of(f("location", "https://www.example.com"), f("date", "Mon, 21 Oct 2013 20:13:21 GMT"), f("cache-control", "private"), f(":status", "302")),
                    222),
            // C.6.2 Second Response
            step("4883640effc1c0bf",
                    List.of(f(":status", "307"), f("cache-control", "private"), f("date", "Mon, 21 Oct 2013 20:13:21 GMT"), f("location", "https://www.example.com")),
                    List.of(f(":status", "307"), f("location", "https://www.example.com"), f("date", "Mon, 21 Oct 2013 20:13:21 GMT"), f("cache-control", "private")),
                    222),
            // C.6.3 Third Response
            step("88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
                    List.of(f(":status", "200"), f("cache-control", "private"), f("date", "Mon, 21 Oct 2013 20:13:22 GMT"), f("location", "https://www.example.com"), f("content-encoding", "gzip"), f("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")),
                    List.of(f("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"), f("content-encoding", "gzip"), f("date", "Mon, 21 Oct 2013 20:13:22 GMT")),
                    215));


    /** Name and value only: the RFC's lists do not show the never-indexed flag. */
    private static List<String> plain(List<HeaderField> fields) {
        List<String> out = new ArrayList<>();
        for (HeaderField f : fields) out.add(f.name() + ": " + f.value());
        return out;
    }

    private static List<String> table(HpackDecoder d) {
        List<HeaderField> entries = new ArrayList<>();
        for (int i = 1; i <= d.dynamicTableLength(); i++) entries.add(d.dynamicTableEntry(i));
        return plain(entries);
    }

    private static List<String> table(HpackEncoder e) {
        List<HeaderField> entries = new ArrayList<>();
        for (int i = 1; i <= e.dynamicTableLength(); i++) entries.add(e.dynamicTableEntry(i));
        return plain(entries);
    }

    private static void decodeSequence(List<Step> steps, int tableSize) throws Http2Exception {
        HpackDecoder decoder = new HpackDecoder(tableSize);
        for (Step s : steps) {
            List<HeaderField> decoded = decoder.decode(1, hex(s.hex()));
            assertEquals(plain(s.headers()), plain(decoded), s.hex());
            assertEquals(plain(s.table()), table(decoder), "dynamic table after " + s.hex());
            assertEquals(s.tableSize(), decoder.dynamicTableSize(), "table size after " + s.hex());
        }
    }

    private static void encodeSequence(List<Step> steps, int tableSize, boolean huffman) {
        HpackEncoder encoder = new HpackEncoder(tableSize).setHuffman(huffman).setNeverIndexSensitiveNames(false);
        for (Step s : steps) {
            assertEquals(s.hex(), hex(encoder.encode(s.headers())), "encoding of " + s.headers());
            assertEquals(plain(s.table()), table(encoder), "encoder table after " + s.hex());
            assertEquals(s.tableSize(), encoder.dynamicTableSize());
        }
    }

    @Test
    void c2FieldRepresentationsDecode() throws Http2Exception {
        for (Step s : C2) decodeSequence(List.of(s), 4096);
    }

    @Test
    void c2NeverIndexedLiteralKeepsItsFlag() throws Http2Exception {
        HeaderField password = new HpackDecoder().decode(1, hex(C2.get(2).hex())).get(0);
        assertTrue(password.sensitive());
        // Re-encoded by an intermediary, it stays never-indexed: the same bytes come out.
        assertEquals(C2.get(2).hex(), hex(new HpackEncoder().setHuffman(false).encode(List.of(password))));
    }

    @Test
    void c2FieldRepresentationsEncode() {
        // C.2.2 uses "without indexing", which this encoder only chooses for oversized fields.
        encodeSequence(List.of(C2.get(0)), 4096, false);
        encodeSequence(List.of(C2.get(3)), 4096, false);
    }

    @Test
    void c3RequestsWithoutHuffman() throws Http2Exception {
        decodeSequence(C3, 4096);
        encodeSequence(C3, 4096, false);
    }

    @Test
    void c4RequestsWithHuffman() throws Http2Exception {
        decodeSequence(C4, 4096);
        encodeSequence(C4, 4096, true);
    }

    @Test
    void c5ResponsesWithoutHuffmanAndEviction() throws Http2Exception {
        decodeSequence(C5, 256);
        encodeSequence(C5, 256, false);
    }

    @Test
    void c6ResponsesWithHuffmanAndEviction() throws Http2Exception {
        decodeSequence(C6, 256);
        encodeSequence(C6, 256, true);
    }

    @Test
    void c1IntegerRepresentations() {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        HpackEncoder.writeInt(out, 0, 5, 10);
        assertEquals("0a", hex(out.toByteArray()));
        out.reset();
        HpackEncoder.writeInt(out, 0, 5, 1337);
        assertEquals("1f9a0a", hex(out.toByteArray()));
        out.reset();
        HpackEncoder.writeInt(out, 0, 8, 42);
        assertEquals("2a", hex(out.toByteArray()));
    }
}
