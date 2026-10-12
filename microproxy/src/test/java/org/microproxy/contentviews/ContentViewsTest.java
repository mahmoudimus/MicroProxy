package org.microproxy.contentviews;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.contentviews.ProtobufTest.bytes;
import static org.microproxy.contentviews.ProtobufTest.hex;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.http.HttpHeaders;

class ContentViewsTest {

    private static final ContentViews VIEWS = ContentViews.defaults();

    private static String render(String view, byte[] data, ContentView.Metadata m) throws DecodeException {
        return VIEWS.get(view).orElseThrow().render(data, m);
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // --- registry --------------------------------------------------------------------------------

    @Test
    void autoPicksTheHighestPriorityAndFallsBack() {
        byte[] graphql = utf8("{\"query\": \"{ me { id } }\"}");
        ContentView.Metadata json = ContentView.Metadata.of("application/json; charset=utf-8");
        assertEquals("graphql", VIEWS.select(graphql, json).orElseThrow().name());
        assertEquals("graphql", VIEWS.render(graphql, json).orElseThrow().view());
        assertEquals("json", VIEWS.render(utf8("{\"a\": 1}"), json).orElseThrow().view());
        // Nothing renders invalid JSON, and nothing applies to plain text.
        assertEquals(Optional.empty(), VIEWS.render(utf8("{oops"), json));
        assertEquals(Optional.empty(), VIEWS.render(utf8("hi"), ContentView.Metadata.of("text/plain")));
        // A named view renders what auto would not choose; an unknown name is an error.
        assertEquals("00000000  68 69", VIEWS.render("hex", utf8("hi"), ContentView.Metadata.of((String) null))
                .orElseThrow().text().substring(0, 15));
        assertThrows(IllegalArgumentException.class, () -> VIEWS.render("nope", new byte[0], json));
        assertEquals(List.of("auto", "graphql", "grpc", "hex", "json", "msgpack", "multipart", "protobuf", "query",
                "socketio", "urlencoded"), VIEWS.names());
    }

    @Test
    void customViewsReplaceByName() {
        ContentView shout = new ContentView() {
            @Override
            public String name() {
                return "json";
            }

            @Override
            public double priority(byte[] data, ContentView.Metadata metadata) {
                return 5;
            }

            @Override
            public String render(byte[] data, ContentView.Metadata metadata) {
                return new String(data, StandardCharsets.UTF_8).toUpperCase(java.util.Locale.ROOT);
            }
        };
        ContentViews custom = VIEWS.with(shout);
        assertEquals("{\"A\": 1}", custom.render(utf8("{\"a\": 1}"), ContentView.Metadata.of("text/plain"))
                .orElseThrow().text());
        assertEquals(VIEWS.names(), custom.names());
        // A view that throws is skipped, not propagated.
        ContentView broken = new ContentView() {
            @Override
            public String name() {
                return "broken";
            }

            @Override
            public double priority(byte[] data, ContentView.Metadata metadata) {
                return 9;
            }

            @Override
            public String render(byte[] data, ContentView.Metadata metadata) {
                throw new IllegalStateException("bug");
            }
        };
        assertEquals("json", VIEWS.with(broken).render(utf8("[]"), ContentView.Metadata.of("application/json"))
                .orElseThrow().view());
    }

    @Test
    void metadata() {
        ContentView.Metadata m = ContentView.Metadata.of("multipart/form-data; boundary=\"a b\"; charset=UTF-8");
        assertEquals("multipart/form-data", m.mediaType());
        assertEquals("a b", m.parameter("Boundary"));
        assertEquals(null, m.parameter("missing"));
        assertTrue(m.trailers().isEmpty());
        assertEquals("/x?y=1", ContentView.Metadata.forRequest(new org.microproxy.http.DefaultHttpRequest(
                org.microproxy.http.HttpVersion.HTTP_1_1, org.microproxy.http.HttpMethod.GET,
                "http://example.com/x?y=1")).path());
    }

    // --- JSON and GraphQL ----------------------------------------------------------------------------

    @Test
    void json() throws DecodeException {
        assertEquals("""
                {
                  "a": [
                    1,
                    2.5e3,
                    {
                      "b": null
                    }
                  ],
                  "c": "é\\n",
                  "d": {},
                  "e": []
                }
                """, render("json", utf8("{\"a\":[1,2.5e3,{\"b\":null}],\"c\":\"\\u00e9\\n\",\"d\":{},\"e\":[]}"),
                ContentView.Metadata.of("application/vnd.api+json")));
        assertThrows(DecodeException.class, () -> render("json", utf8("[1,]"), ContentView.Metadata.of("application/json")));
        assertThrows(DecodeException.class, () -> render("json", utf8("[1] 2"), ContentView.Metadata.of("application/json")));
        assertThrows(DecodeException.class, () -> render("json", utf8("[".repeat(1000)), ContentView.Metadata.of("application/json")));
    }

    @Test
    void graphqlQueryWithVariables() throws DecodeException {
        String body = "{\"operationName\":\"Q\",\"query\":\"query Q($id: ID!, $n: Int = 10) { user(id: $id) { name"
                + " ...F friends(first: $n, where: {active: true}) @include(if: true) { name } ... on Admin { level } } }"
                + " fragment F on User { email }\",\"variables\":{\"id\":\"1\"}}";
        assertEquals("""
                {
                  "operationName": "Q",
                  "query": "...",
                  "variables": {
                    "id": "1"
                  }
                }
                ---
                query Q($id: ID!, $n: Int = 10) {
                  user(id: $id) {
                    name
                    ...F
                    friends(first: $n, where: { active: true }) @include(if: true) {
                      name
                    }
                    ... on Admin {
                      level
                    }
                  }
                }

                fragment F on User {
                  email
                }
                """, render("graphql", utf8(body), ContentView.Metadata.of("application/json")));
    }

    /** mitmproxy's GraphQL view tests. */
    @Test
    void graphqlAsMitmproxyRecognizesIt() throws DecodeException {
        ContentView v = VIEWS.get("graphql").orElseThrow();
        ContentView.Metadata json = ContentView.Metadata.of("application/json");
        assertEquals(2, v.priority(utf8("{\"query\": \"query P { \\n }\"}"), json));
        assertEquals(2, v.priority(utf8("[{\"query\": \"query P { \\n }\"}]"), json));
        assertEquals(0, v.priority(utf8("[{\"query\": \"query P { \\n }\"}]"), ContentView.Metadata.of("text/html")));
        assertEquals(0, v.priority(utf8("[{\"xquery\": \"query P { \\n }\"}]"), json));
        assertEquals(0, v.priority(utf8("[]"), json));
        assertEquals(0, v.priority(utf8("}"), json));
        // A query that already has lines is kept as written; a batch is numbered.
        assertEquals("--- 0/1\n{\n  \"query\": \"...\"\n}\n---\nquery P {\n  a\n}\n--- 1/1\n{\n  \"query\": \"...\"\n}\n---\n{\n  b\n}\n",
                v.render(utf8("[{\"query\": \"query P {\\n  a\\n}\"}, {\"query\": \"{ b }\"}]"), json));
        assertThrows(DecodeException.class, () -> v.render(utf8("\"valid json\""), json));
    }

    // --- msgpack -----------------------------------------------------------------------------------

    /** mitmproxy_rs's msgpack vector. */
    @Test
    void msgpackObject() throws DecodeException {
        byte[] data = hex("83a46e616d65a84a6f686e20446f65a3616765" + "1e" + "a474616773" + "92a9646576656c6f706572a472757374");
        assertEquals("name: John Doe\nage: 30\ntags:\n- developer\n- rust\n",
                render("msgpack", data, ContentView.Metadata.of("application/msgpack")));
        assertEquals("msgpack", VIEWS.render(data, ContentView.Metadata.of("application/x-msgpack")).orElseThrow().view());
    }

    /** Each format of the MessagePack specification: hex in, YAML out. */
    static List<String[]> msgpackCases() {
        return Arrays.asList(new String[][] {
            {"05", "5"},
            {"7f", "127"},
            {"ff", "-1"},
            {"e0", "-32"},
            {"c0", "null"},
            {"c2", "false"},
            {"c3", "true"},
            {"cc ff", "255"},
            {"cd 0100", "256"},
            {"ce 00010000", "65536"},
            {"cf ffffffffffffffff", "18446744073709551615"},
            {"d0 80", "-128"},
            {"d1 ff00", "-256"},
            {"d2 80000000", "-2147483648"},
            {"d3 8000000000000000", "-9223372036854775808"},
            {"ca 3fc00000", "1.5"},
            {"cb 3ff8000000000000", "1.5"},
            {"cb 7ff8000000000000", ".nan"},
            {"a3 616263", "abc"},
            {"a0", "''"},
            {"d9 03 616263", "abc"},
            {"da 0003 616263", "abc"},
            {"db 00000003 616263", "abc"},
            {"a3 313233", "'123'"},
            {"c4 03 010203", "!binary '010203'"},
            {"c5 0001 ff", "!binary ff"},
            {"c6 00000000", "!binary ''"},
            {"90", "[]"},
            {"80", "{}"},
            {"dc 0002 0102", "- 1\n- 2"},
            {"dd 00000001 c0", "- null"},
            {"de 0001 a161 01", "a: 1"},
            {"df 00000001 01 a162", "1: b"},
            {"81 92 01 02 c3", "'- 1 - 2': true"},
            {"d4 01 ab", "!ext1 ab"},
            {"d5 02 abcd", "!ext2 abcd"},
            {"d8 05 00112233445566778899aabbccddeeff", "!ext5 00112233445566778899aabbccddeeff"},
            {"c7 02 07 abcd", "!ext7 abcd"},
            {"c8 0001 07 ab", "!ext7 ab"},
            {"c9 00000000 07", "!ext7 ''"},
            {"d6 ff 00000000", "1970-01-01T00:00:00Z  # timestamp"},
            {"d7 ff 0000000400000001", "1970-01-01T00:00:01.000000001Z  # timestamp"},
            {"c7 0c ff 00000001 0000000000000002", "1970-01-01T00:00:02.000000001Z  # timestamp"},
            {"01 02", "1\n---\n2"}
        });
    }

    @ParameterizedTest
    @MethodSource("msgpackCases")
    void msgpackFormats(String hex, String yaml) throws DecodeException {
        assertEquals(yaml + "\n", MsgPackView.render(hex(hex)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "c1", "cc", "a5 6162", "dc ffff", "df ffffffff", "92 01", "c4 05 00", "d6 ff 00"})
    void msgpackErrors(String hex) {
        assertThrows(DecodeException.class, () -> MsgPackView.render(hex(hex)));
    }

    @Test
    void msgpackDepthIsBounded() {
        byte[] deep = new byte[1000];
        Arrays.fill(deep, (byte) 0x91);
        assertThrows(DecodeException.class, () -> MsgPackView.render(deep));
    }

    // --- forms ---------------------------------------------------------------------------------------

    @Test
    void urlEncodedForms() throws DecodeException {
        ContentView.Metadata form = ContentView.Metadata.of("application/x-www-form-urlencoded");
        assertEquals("a:\n- '1'\n- ✓\nb: x y\nc: ''\n", render("urlencoded", utf8("a=1&b=x+y&a=%E2%9C%93&c"), form));
        assertEquals("urlencoded", VIEWS.render(utf8("a=1"), form).orElseThrow().view());
        assertThrows(DecodeException.class, () -> render("urlencoded", utf8("&&"), form));
    }

    @Test
    void queryStrings() throws DecodeException {
        ContentView.Metadata get = new ContentView.Metadata(null, null, null, "/search?q=proto+buf&page=2#top", true);
        assertEquals("query", VIEWS.render(new byte[0], get).orElseThrow().view());
        assertEquals("q: proto buf\npage: '2'\n", render("query", new byte[0], get));
        assertFalse(VIEWS.get("query").orElseThrow().matches(new byte[0], get.withPath("/search")));
        assertFalse(VIEWS.get("query").orElseThrow().matches(utf8("x"), get));
    }

    @Test
    void multipartForms() throws DecodeException {
        String body = "preamble\r\n--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nHello\r\n"
                + "--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n"
                + "Content-Type: application/octet-stream\r\n\r\n\u0000\u0001\u0002\r\n"
                + "--XyZ\r\nContent-Disposition: form-data; name=\"note\"; filename=\"n.txt\"\r\n\r\nline one\r\n"
                + "--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nWorld\r\n--XyZ--\r\nepilogue";
        ContentView.Metadata m = ContentView.Metadata.of("multipart/form-data; boundary=XyZ");
        assertEquals("""
                title:
                - Hello
                - World
                file:
                  filename: a.bin
                  content-type: application/octet-stream
                  size: 3
                note:
                  filename: n.txt
                  size: 8
                  content: line one
                """, render("multipart", body.getBytes(StandardCharsets.ISO_8859_1), m));
        assertThrows(DecodeException.class, () -> render("multipart", utf8("no boundary"), m));
        assertThrows(DecodeException.class, () -> render("multipart", utf8("--XyZ\r\n\r\nunterminated"), m));
        assertThrows(DecodeException.class, () -> render("multipart", utf8("x"), ContentView.Metadata.of("multipart/form-data")));
    }

    // --- Socket.IO -----------------------------------------------------------------------------------

    @Test
    void socketIoPolling() throws DecodeException {
        ContentView.Metadata polling = new ContentView.Metadata("text/plain", null, null,
                "/socket.io/?EIO=4&transport=polling", false);
        String body = "0{\"sid\":\"abc\", \"pingInterval\": 25000}\u001e40\u001e42[\"chat\",{\"x\":1}]\u001e"
                + "42/admin,7[\"x\"]\u001e451-[\"up\",{\"_placeholder\":true,\"num\":0}]\u001e2\u001e43/admin,7";
        assertEquals("socketio", VIEWS.render(utf8(body), polling).orElseThrow().view());
        assertEquals("""
                EngineIO.OPEN {"sid":"abc","pingInterval":25000}
                SocketIO.CONNECT
                SocketIO.EVENT ["chat",{"x":1}]
                SocketIO.EVENT /admin ack=7 ["x"]
                SocketIO.BINARY_EVENT attachments=1 ["up",{"_placeholder":true,"num":0}]
                EngineIO.PING
                SocketIO.ACK /admin ack=7
                """, render("socketio", utf8(body), polling));
    }

    /** mitmproxy's Socket.IO view tests. */
    @Test
    void socketIoAsMitmproxyParsesIt() throws DecodeException {
        ContentView.Metadata m = new ContentView.Metadata(null, null, null, "/asdf/socket.io/?EIO=4", true);
        for (String bad : List.of("HTTP/1.1", "GET", "4", "")) {
            assertThrows(DecodeException.class, () -> render("socketio", utf8(bad), m), bad);
        }
        for (String good : List.of("0", "6", "40", "42", "42eventdata")) assertTrue(!render("socketio", utf8(good), m).isEmpty());
        assertEquals("EngineIO.OPEN payload\n", render("socketio", utf8("0payload"), m));
        assertEquals("SocketIO.CONNECT payload\n", render("socketio", utf8("40payload"), m));
        ContentView v = VIEWS.get("socketio").orElseThrow();
        assertFalse(v.matches(new byte[0], m));
        assertFalse(v.matches(utf8("message"), m.withPath("/ws")));
        assertTrue(v.matches(utf8("message"), m));
    }

    @Test
    void hexDump() throws DecodeException {
        assertEquals("00000000  00 01 41 42 43 44 45 46  47 48 49 4a 4b 4c 4d 4e  ..ABCDEFGHIJKLMN\n"
                + "00000010  ff                                                .\n",
                render("hex", bytes(0, 1, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 0xff),
                        ContentView.Metadata.of((String) null)));
        assertFalse(VIEWS.get("hex").orElseThrow().matches(bytes(1), ContentView.Metadata.of((String) null)));
    }

    @Test
    void headersMayBeNull() {
        ContentView.Metadata m = new ContentView.Metadata(null, null, null, null, false);
        assertTrue(m.headers().isEmpty());
        assertEquals(null, m.header("x"));
        assertEquals("", m.mediaType());
        assertEquals(new HttpHeaders().size(), m.trailers().size());
    }
}
