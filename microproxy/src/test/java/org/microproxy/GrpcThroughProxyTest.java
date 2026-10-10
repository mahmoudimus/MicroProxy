package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.HeaderField;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.contentviews.ContentViews;
import org.microproxy.contentviews.Grpc;
import org.microproxy.contentviews.Protobuf;
import org.microproxy.extras.HttpLogger;

/**
 * gRPC through the intercepting proxy, with HTTP/2 on both sides: {@code application/grpc}
 * requests with {@code te: trailers}, length-prefixed messages streamed both ways at once, and
 * {@code grpc-status} in the response trailers. The origin is the codec-based test server; no
 * gRPC library is involved, only its wire format.
 */
class GrpcThroughProxyTest {

    private H2TestOrigin origin;
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() throws IOException {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.close();
    }

    /** One gRPC message: a compression flag, a 4-byte length and the payload. */
    static byte[] message(String payload) {
        byte[] p = payload.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(5 + p.length).put((byte) 0).putInt(p.length).put(p).array();
    }

    /** Splits length-prefixed messages out of {@code buffer}, leaving any partial one in it. */
    static List<String> messages(ByteArrayOutputStream buffer) {
        List<String> out = new ArrayList<>();
        byte[] all = buffer.toByteArray();
        int pos = 0;
        while (all.length - pos >= 5) {
            int length = ByteBuffer.wrap(all, pos + 1, 4).getInt();
            if (all.length - pos - 5 < length) break;
            out.add(new String(all, pos + 5, length, StandardCharsets.UTF_8));
            pos += 5 + length;
        }
        buffer.reset();
        buffer.write(all, pos, all.length - pos);
        return out;
    }

    /** A bidirectional streaming method: each request message is answered at once, uppercased. */
    private void start() throws IOException {
        start(null);
    }

    private void start(HttpFiltersSource filters) throws IOException {
        origin = new H2TestOrigin(Http2UpstreamTest.originContext(), s -> {
            if (!"application/grpc".equals(s.header("content-type")) || !"trailers".equals(s.header("te"))) {
                s.respond(200, true, "content-type", "application/grpc", "grpc-status", "3",
                        "grpc-message", "missing te or content-type");
                return;
            }
            s.respond(200, false, "content-type", "application/grpc");
            ByteArrayOutputStream pending = new ByteArrayOutputStream();
            int count = 0;
            byte[] data;
            while ((data = s.read()) != null) {
                pending.write(data);
                for (String m : messages(pending)) {
                    s.data(message(m.toUpperCase()), false);
                    count++;
                }
            }
            String tag = s.trailer("x-request-tag");
            s.trailers("grpc-status", "0", "grpc-message", "echoed " + count + (tag != null ? " " + tag : ""));
        });
        HttpProxyServerBootstrap bootstrap = Http2UpstreamTest.mitm().withHttp2(true);
        if (filters != null) bootstrap.plusFiltersSource(filters);
        proxy = bootstrap.start();
    }

    private H2TestClient client() throws IOException {
        return H2TestClient.connect(proxy.getListenAddress(), "localhost:" + origin.port(),
                Http2UpstreamTest.proxyCa.clientContext()).handshake();
    }

    private static List<HeaderField> grpcRequest(H2TestClient c) {
        return c.request("POST", "/echo.Echo/Chat", "content-type", "application/grpc", "te", "trailers",
                "grpc-timeout", "10S");
    }

    private static String value(List<HeaderField> fields, String name) {
        for (HeaderField f : fields) {
            if (f.name().equals(name)) return f.value();
        }
        return null;
    }

    @Test
    void bidirectionalStreamingWithTrailers() throws Exception {
        start();
        try (H2TestClient c = client()) {
            c.headers(1, grpcRequest(c), false);
            ByteArrayOutputStream received = new ByteArrayOutputStream();
            Frame.Headers head = (Frame.Headers) c.awaitFrame(f -> f instanceof Frame.Headers h && h.streamId() == 1);
            List<HeaderField> fields = c.fields(head);
            assertEquals("200", value(fields, ":status"));
            assertEquals("application/grpc", value(fields, "content-type"));
            // Each message is answered before the next is sent: the request is still open while
            // the response streams, through the proxy, in both directions at once.
            for (String m : List.of("one", "two", "three")) {
                c.data(1, message(m), false);
                List<String> answers = new ArrayList<>();
                while (answers.isEmpty()) {
                    Frame.Data d = (Frame.Data) c.awaitFrame(f -> f instanceof Frame.Data x && x.streamId() == 1);
                    assertFalse(d.endStream());
                    received.write(d.data());
                    answers.addAll(messages(received));
                }
                assertEquals(List.of(m.toUpperCase()), answers);
            }
            c.data(1, new byte[0], true);
            Frame.Headers trailers = (Frame.Headers) c.awaitFrame(f -> f instanceof Frame.Headers h && h.streamId() == 1);
            assertTrue(trailers.endStream());
            List<HeaderField> t = c.fields(trailers);
            assertEquals("0", value(t, "grpc-status"));
            assertEquals("echoed 3", value(t, "grpc-message"));
            assertEquals(null, value(t, ":status"));
        }
    }

    @Test
    void requestTrailersReachTheServer() throws Exception {
        start();
        try (H2TestClient c = client()) {
            c.headers(1, grpcRequest(c), false);
            c.data(1, message("unary"), false);
            c.headers(1, List.of(new HeaderField("x-request-tag", "tagged")), true);
            H2TestClient.Response r = c.response(1);
            assertEquals(200, r.status());
            assertEquals(List.of("UNARY"), messages(bytes(r.body())));
            assertEquals("0", value(r.trailers(), "grpc-status"));
            assertEquals("echoed 1 tagged", value(r.trailers(), "grpc-message"));
        }
    }

    @Test
    void manyConcurrentCallsShareTheServerConnection() throws Exception {
        start();
        List<String> results = new CopyOnWriteArrayList<>();
        try (H2TestClient c = client()) {
            int calls = 20;
            for (int i = 0; i < calls; i++) {
                int id = 2 * i + 1;
                c.headers(id, grpcRequest(c), false);
                c.data(id, message("call " + i), true);
            }
            for (int i = 0; i < calls; i++) {
                H2TestClient.Response r = c.response(2 * i + 1);
                results.add(messages(bytes(r.body())).getFirst() + " " + value(r.trailers(), "grpc-status"));
            }
        }
        for (int i = 0; i < 20; i++) assertTrue(results.contains("CALL " + i + " 0"), results.toString());
        assertEquals(1, origin.accepts.get());
    }

    @Test
    void anErrorStatusInTrailersOnlyResponses() throws Exception {
        start();
        try (H2TestClient c = client()) {
            // Without te: trailers the method answers with a trailers-only error.
            c.headers(1, c.request("POST", "/echo.Echo/Chat", "content-type", "application/grpc"), false);
            c.data(1, message("x"), true);
            // Trailers-Only: one HEADERS frame that ends the stream, as the server sent it.
            Frame.Headers h = (Frame.Headers) c.awaitFrame(f -> f instanceof Frame.Headers x && x.streamId() == 1);
            assertTrue(h.endStream());
            List<HeaderField> fields = c.fields(h);
            assertEquals("200", value(fields, ":status"));
            assertEquals("3", value(fields, "grpc-status"));
        }
    }

    /**
     * A call logged at BODY with content views: each message decoded as protobuf, and the
     * trailers both ways, with grpc-status explained.
     */
    @Test
    void httpLoggerDecodesTheCallsMessagesAndTrailers() throws Exception {
        List<String> log = new CopyOnWriteArrayList<>();
        start(HttpLogger.builder().level(HttpLogger.Level.BODY).contentViews(ContentViews.defaults()).sink(log::add)
                .build());
        Map<Object, Object> request = new LinkedHashMap<>();
        request.put(1, "unary");
        request.put(2, 7L);
        byte[] proto = Protobuf.encode(request);
        try (H2TestClient c = client()) {
            c.headers(1, grpcRequest(c), false);
            c.data(1, Grpc.join(List.of(proto, proto)), false);
            c.headers(1, List.of(new HeaderField("x-request-tag", "tagged")), true);
            H2TestClient.Response r = c.response(1);
            assertEquals(200, r.status());
            assertEquals("0", value(r.trailers(), "grpc-status"));
            List<byte[]> answers = Grpc.messages(r.body(), null);
            assertEquals(Map.of(1, "UNARY", 2, 7L), Protobuf.decode(answers.getFirst()).toPlain());
        }
        // The CONNECT that opened the session, then the call.
        for (int i = 0; i < 500 && log.size() < 4; i++) Thread.sleep(10);
        assertEquals(4, log.size(), String.join("\n----\n", log));
        List<String> req = lines(log.get(2));
        int blank = req.indexOf("");
        assertEquals(List.of("1: unary", "2: 7  # !sint: -4", "", "---", "", "1: unary", "2: 7  # !sint: -4",
                "--> trailers", "x-request-tag: tagged", "--> END POST (28-byte body, grpc view)"),
                req.subList(blank + 1, req.size()), req.toString());
        List<String> res = lines(log.get(3));
        blank = res.indexOf("");
        assertEquals(List.of("1: UNARY", "2: 7  # !sint: -4", "", "---", "", "1: UNARY", "2: 7  # !sint: -4",
                "<-- trailers", "grpc-status: 0  # OK", "grpc-message: echoed 2 tagged", "<-- END HTTP (28-byte body, grpc view)"),
                res.subList(blank + 1, res.size()), res.toString());
        assertTrue(res.getFirst().startsWith("<-- 200 OK https://localhost:" + origin.port() + "/echo.Echo/Chat"),
                res.getFirst());
    }

    /** A logged message's lines without their prefix. */
    private static List<String> lines(String message) {
        return message.lines().map(l -> l.replaceFirst("^\\[conn \\d+ #\\d+ stream \\d+] ", "")).toList();
    }

    private static ByteArrayOutputStream bytes(byte[] b) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(b);
        return out;
    }
}
