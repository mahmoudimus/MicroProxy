package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.Http2Settings;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.frames.Field;
import org.microproxy.frames.FrameContext;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.Http2Frame;
import org.microproxy.frames.Http3Frame;
import org.microproxy.frames.HttpFrame;
import org.microproxy.http.WebSocketFrame;

/**
 * Frame interception on live HTTP/2 connections: an HTTP/2 client (the raw-frame test client) on
 * intercepted TLS, the proxy, and an HTTP/2 origin (the codec-based test origin), with frames
 * edited, dropped and added in each direction; illegal results; flow control with resized DATA;
 * END_STREAM when its DATA is dropped; gRPC, WebSockets and h2c with an interceptor in place.
 */
class Http2FrameInterceptorTest {

    /** One interceptor call. */
    record Seen(HttpFrame frame, FrameDirection direction, long connectionId, long streamId, FlowContext flow, String server) {}

    private H2TestOrigin origin;
    private HttpProxyServer proxy;
    private final List<Seen> seen = new CopyOnWriteArrayList<>();
    /** What the interceptor does; pass-through unless a test says otherwise. */
    private volatile FrameInterceptor behaviour = (f, d, c) -> f;
    private final FrameInterceptor recorder = (f, d, c) -> {
        seen.add(new Seen(f, d, c.connectionId(), c.streamId(), c.flowContext(), c.server()));
        return behaviour.intercept(f, d, c);
    };
    /** Request bodies and header blocks the origin received. */
    private final List<String> bodies = new CopyOnWriteArrayList<>();
    private final List<List<HeaderField>> requests = new CopyOnWriteArrayList<>();
    private final List<String> warnings = new CopyOnWriteArrayList<>();
    private final Logger framesLog = Logger.getLogger("org.microproxy.impl.Http2Frames");
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord r) {
            if (r.getLevel().intValue() >= java.util.logging.Level.WARNING.intValue()) warnings.add(r.getMessage());
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
    };

    @BeforeEach
    void captureLogs() {
        framesLog.addHandler(capture);
    }

    @AfterEach
    void tearDown() throws IOException {
        framesLog.removeHandler(capture);
        if (proxy != null) proxy.abort();
        if (origin != null) origin.close();
    }

    private void start(H2TestOrigin.Handler handler) throws IOException {
        start(new H2TestOrigin.Options(), handler);
    }

    private void start(H2TestOrigin.Options options, H2TestOrigin.Handler handler) throws IOException {
        origin = new H2TestOrigin(Http2UpstreamTest.originContext(), options, handler);
        proxy = Http2UpstreamTest.mitm().withHttp2(true).withFrameInterceptor(recorder).start();
    }

    private H2TestClient client() throws IOException {
        H2TestClient c = H2TestClient.connect(proxy.getListenAddress(), "localhost:" + origin.port(),
                Http2UpstreamTest.proxyCa.clientContext());
        c.reader.setDeliverUnknownFrames(true);
        return c.handshake();
    }

    /** Answers with the request body, recording it and the request's header block; no content-length. */
    private void echoBody(H2TestOrigin.Stream s) throws IOException {
        requests.add(s.headers);
        String body = new String(s.readBody(), StandardCharsets.UTF_8);
        bodies.add(body);
        s.respond(200, false, "content-type", "text/plain");
        s.data(("echo:" + body).getBytes(StandardCharsets.UTF_8), true);
    }

    private static String value(List<HeaderField> fields, String name) {
        for (HeaderField f : fields) {
            if (f.name().equals(name)) return f.value();
        }
        return null;
    }

    private static <T extends HttpFrame> List<Seen> seen(List<Seen> all, Class<T> type, FrameDirection direction) {
        return all.stream().filter(s -> type.isInstance(s.frame) && s.direction == direction).toList();
    }

    private H2TestClient.Response post(H2TestClient c, int stream, String body) throws IOException {
        c.headers(stream, c.request("POST", "/echo"), false);
        c.data(stream, body.getBytes(StandardCharsets.UTF_8), true);
        return c.response(stream);
    }

    @Test
    void aPassThroughInterceptorSeesEachHopInBothDirections() throws Exception {
        start(this::echoBody);
        try (H2TestClient c = client()) {
            H2TestClient.Response r = post(c, 1, "hello");
            assertEquals(200, r.status());
            assertEquals("echo:hello", r.text());
        }
        assertEquals(List.of("hello"), bodies);
        for (FrameDirection d : FrameDirection.values()) {
            assertFalse(seen(seen, Http2Frame.Headers.class, d).isEmpty(), "HEADERS " + d);
            assertFalse(seen(seen, Http2Frame.Data.class, d).isEmpty(), "DATA " + d);
            assertFalse(seen(seen, Http2Frame.Settings.class, d).isEmpty(), "SETTINGS " + d);
        }
        // The client's request opens its stream: no exchange yet. Everything after belongs to one.
        Seen fromClient = seen(seen, Http2Frame.Headers.class, FrameDirection.FROM_CLIENT).getFirst();
        assertEquals(1, fromClient.streamId);
        assertNull(fromClient.flow);
        assertNull(fromClient.server);
        assertTrue(fromClient.connectionId > 0);
        Seen toServer = seen(seen, Http2Frame.Headers.class, FrameDirection.TO_SERVER).getFirst();
        assertNotNull(toServer.flow);
        assertEquals(fromClient.connectionId, toServer.connectionId);
        assertEquals("localhost:" + origin.port(), toServer.server);
        assertEquals("POST", ((Http2Frame.Headers) toServer.frame).get(":method"));
        Seen fromServer = seen(seen, Http2Frame.Headers.class, FrameDirection.FROM_SERVER).getFirst();
        assertEquals("200", ((Http2Frame.Headers) fromServer.frame).get(":status"));
        assertEquals(toServer.streamId, fromServer.streamId);
        Seen toClient = seen(seen, Http2Frame.Data.class, FrameDirection.TO_CLIENT).getLast();
        assertTrue(((Http2Frame.Data) toClient.frame).endStream());
        assertEquals(1, toClient.streamId);
        assertNotNull(toClient.flow);
        assertEquals(1, toClient.flow.getStreamId());
        // The proxy's SETTINGS to the client advertise extended CONNECT.
        Http2Frame.Settings own = (Http2Frame.Settings) seen(seen, Http2Frame.Settings.class, FrameDirection.TO_CLIENT)
                .getFirst().frame;
        assertEquals(1L, own.get(Http2Frame.SETTINGS_ENABLE_CONNECT_PROTOCOL));
        assertEquals(List.of(), warnings);
    }

    @Test
    void headerBlocksAreEditedInEachDirection() throws Exception {
        behaviour = (f, d, c) -> {
            if (!(f instanceof Http2Frame.Headers h)) return f;
            return switch (d) {
                case FROM_CLIENT -> h.withHeader("x-from-client", "1");
                case TO_SERVER -> h.withHeader("x-to-server", "2").withoutHeader("user-agent");
                case FROM_SERVER -> h.withHeader("x-from-server", "3");
                case TO_CLIENT -> h.withHeader("x-to-client", "4");
            };
        };
        start(this::echoBody);
        try (H2TestClient c = client()) {
            c.headers(1, c.request("POST", "/echo", "user-agent", "test"), false);
            c.data(1, "x".getBytes(StandardCharsets.UTF_8), true);
            H2TestClient.Response r = c.response(1);
            assertEquals("3", r.header("x-from-server"));
            assertEquals("4", r.header("x-to-client"));
        }
        List<HeaderField> request = requests.getFirst();
        assertEquals("1", value(request, "x-from-client"));
        assertEquals("2", value(request, "x-to-server"));
        assertNull(value(request, "user-agent"));
    }

    @Test
    void dataIsEditedInEachDirection() throws Exception {
        behaviour = (f, d, c) -> {
            if (f instanceof Http2Frame.Headers h && d == FrameDirection.TO_CLIENT) return h.withoutHeader("content-length");
            if (!(f instanceof Http2Frame.Data data)) return f;
            return switch (d) {
                case FROM_CLIENT -> data.withText(data.text().replace("hunter2", "*******"));
                case TO_SERVER -> data.withText(data.text().replace("password", "PASSWORD"));
                case FROM_SERVER -> data.withText(data.text().replace("echo:", "ECHO:"));
                case TO_CLIENT -> data.data().length == 0 ? data : data.withText(data.text() + " (seen)");
            };
        };
        start(this::echoBody);
        try (H2TestClient c = client()) {
            assertEquals("ECHO:PASSWORD=******* (seen)", post(c, 1, "password=hunter2").text());
        }
        assertEquals(List.of("PASSWORD=*******"), bodies);
    }

    @Test
    void resizingAReceivedBodyNeedsItsContentLengthFixed() throws Exception {
        byte[] body = "0123456789".getBytes(StandardCharsets.UTF_8);
        AtomicReference<Boolean> fixLength = new AtomicReference<>(false);
        behaviour = (f, d, c) -> {
            if (d != FrameDirection.FROM_SERVER) return f;
            if (f instanceof Http2Frame.Headers h && fixLength.get()) return h.withoutHeader("content-length");
            if (f instanceof Http2Frame.Data data && data.data().length > 0) return data.withText(data.text() + data.text());
            return f;
        };
        start(s -> {
            s.respond(200, false, "content-length", Integer.toString(body.length));
            s.data(body, true);
        });
        try (H2TestClient c = client()) {
            // The DATA no longer matches content-length: the proxy resets the server stream as
            // malformed, and the client stream fails.
            c.get(1, "/a");
            H2TestClient.Response broken = c.response(1);
            assertNotNull(broken.reset(), "the client stream fails");
            fixLength.set(true);
            c.get(3, "/b");
            H2TestClient.Response fixed = c.response(3);
            assertNull(fixed.reset());
            assertEquals("01234567890123456789", fixed.text());
        }
    }

    @Test
    void droppingTheDataThatEndsAStreamKeepsTheEnd() throws Exception {
        // The origin sends "head" then "tail" (END_STREAM); the client sends "one" then "two" (END_STREAM).
        behaviour = (f, d, c) -> {
            if (f instanceof Http2Frame.Data data && data.endStream() && data.data().length > 0
                    && (d == FrameDirection.FROM_SERVER || d == FrameDirection.FROM_CLIENT)) {
                return null;
            }
            return f;
        };
        start(s -> {
            requests.add(s.headers);
            bodies.add(new String(s.readBody(), StandardCharsets.UTF_8));
            s.respond(200, false);
            s.data("head".getBytes(StandardCharsets.UTF_8), false);
            s.data("tail".getBytes(StandardCharsets.UTF_8), true);
        });
        try (H2TestClient c = client()) {
            c.headers(1, c.request("POST", "/"), false);
            c.data(1, "one".getBytes(StandardCharsets.UTF_8), false);
            c.data(1, "two".getBytes(StandardCharsets.UTF_8), true);
            H2TestClient.Response r = c.response(1);
            assertNull(r.reset());
            assertEquals("head", r.text());
        }
        assertEquals(List.of("one"), bodies);
    }

    @Test
    void droppingEveryDataFrameSentStillEndsTheStreams() throws Exception {
        behaviour = (f, d, c) -> f instanceof Http2Frame.Data && !d.inbound() ? null : f;
        start(this::echoBody);
        try (H2TestClient c = client()) {
            H2TestClient.Response r = post(c, 1, "dropped");
            assertNull(r.reset());
            assertEquals(200, r.status());
            assertEquals("", r.text());
        }
        assertEquals(List.of(""), bodies);
    }

    @Test
    void framesAreAddedInEachDirection() throws Exception {
        behaviour = (f, d, c) -> {
            switch (f) {
                case Http2Frame.Data data when d == FrameDirection.FROM_CLIENT && data.data().length > 0 ->
                        c.send(Http2Frame.data(data.streamId(), "+client".getBytes(StandardCharsets.UTF_8), false));
                case Http2Frame.Data data when d == FrameDirection.TO_SERVER && data.data().length > 0 ->
                        c.send(Http2Frame.data(data.streamId(), "+proxy".getBytes(StandardCharsets.UTF_8), false));
                case Http2Frame.Data data when d == FrameDirection.FROM_SERVER && data.endStream() ->
                        c.send(Http2Frame.headers(data.streamId(), List.of(new Field("x-checksum", "abc")), true));
                case Http2Frame.Headers h when d == FrameDirection.TO_CLIENT && h.get(":status") != null ->
                        c.send(Http2Frame.unknown(0xf0, 0, 0, "hint".getBytes(StandardCharsets.UTF_8)));
                default -> {}
            }
            return f;
        };
        start(this::echoBody);
        try (H2TestClient c = client()) {
            H2TestClient.Response r = post(c, 1, "body");
            // The client's DATA arrives as two pieces, and the proxy adds to each as it sends it.
            assertEquals("echo:body+proxy+client+proxy", r.text());
            // Trailers added from the server reach the client as trailers.
            assertEquals("abc", value(r.trailers(), "x-checksum"));
            Frame.Unknown hint = (Frame.Unknown) c.awaitFrame(x -> x instanceof Frame.Unknown);
            assertEquals(0xf0, hint.type());
            assertEquals("hint", new String(hint.payload(), StandardCharsets.UTF_8));
        }
    }

    @Test
    void priorityAndExtensionFramesFromTheClientCanBeDropped() throws Exception {
        behaviour = (f, d, c) -> f instanceof Http2Frame.Priority || f instanceof Http2Frame.Unknown ? null : f;
        start(this::echoBody);
        try (H2TestClient c = client()) {
            c.writer.writeFrame(new Frame.Priority(3, new Frame.PrioritySpec(0, false, 32)));
            c.writer.writeFrame(new Frame.Unknown(0xf1, 0, 0, new byte[] {1, 2, 3}));
            c.writer.flush();
            assertEquals("echo:x", post(c, 1, "x").text());
        }
        assertEquals(1, seen(seen, Http2Frame.Priority.class, FrameDirection.FROM_CLIENT).size());
        Http2Frame.Unknown u = (Http2Frame.Unknown) seen(seen, Http2Frame.Unknown.class, FrameDirection.FROM_CLIENT)
                .getFirst().frame;
        assertArrayEquals(new byte[] {1, 2, 3}, u.payload());
    }

    @Test
    void illegalResultsAreLoggedAndTheFrameGoesOnUnchanged() throws Exception {
        behaviour = (f, d, c) -> switch (f) {
            // Moving a stream, dropping HEADERS, an invalid field name, an HTTP/3 frame, a read-only
            // frame edited, the proxy's own SETTINGS changed, a server's SETTINGS made laxer, and a
            // failing interceptor: all rejected, and the exchange goes on as if nothing happened.
            case Http2Frame.Headers h when d == FrameDirection.FROM_CLIENT -> new Http2Frame.Headers(99, h.fields(), h.endStream());
            case Http2Frame.Headers h when d == FrameDirection.TO_SERVER -> null;
            case Http2Frame.Headers h when d == FrameDirection.TO_CLIENT -> h.withHeader("X-Upper", "1");
            case Http2Frame.Headers h -> throw new IllegalStateException("interceptor bug");
            case Http2Frame.Data data when d == FrameDirection.TO_CLIENT -> Http3Frame.data(data.data());
            case Http2Frame.WindowUpdate w -> new Http2Frame.WindowUpdate(w.streamId(), w.increment() + 1);
            case Http2Frame.Settings s when d == FrameDirection.TO_CLIENT && !s.ack() ->
                    s.withValue(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 5);
            case Http2Frame.Settings s when d == FrameDirection.FROM_SERVER && !s.ack() ->
                    s.withValue(Http2Frame.SETTINGS_INITIAL_WINDOW_SIZE, 1 << 20);
            default -> f;
        };
        start(this::echoBody);
        try (H2TestClient c = client()) {
            assertEquals(100L, c.setting(Http2Settings.MAX_CONCURRENT_STREAMS));
            H2TestClient.Response r = post(c, 1, "still works");
            assertEquals(200, r.status());
            assertEquals("echo:still works", r.text());
            assertNull(r.header("x-upper"));
        }
        assertEquals(List.of("still works"), bodies);
        for (String expected : List.of("stream ids are read-only", "HEADERS cannot be dropped", "upper-case name",
                "not an HTTP/2 frame", "WINDOW_UPDATE is read-only", "MAX_CONCURRENT_STREAMS is read-only",
                "larger INITIAL_WINDOW_SIZE", "frame interceptor failed")) {
            assertTrue(warnings.stream().anyMatch(w -> w.contains(expected)), expected + " in " + warnings);
        }
    }

    @Test
    void theContextRefusesFramesOnceTheCallHasReturned() throws Exception {
        AtomicReference<FrameContext> kept = new AtomicReference<>();
        behaviour = (f, d, c) -> {
            kept.compareAndSet(null, c);
            return f;
        };
        start(this::echoBody);
        try (H2TestClient c = client()) {
            post(c, 1, "x");
        }
        assertThrows(IllegalStateException.class, () -> kept.get().send(Http2Frame.data(1, new byte[0], false)));
    }

    @Test
    void stricterSettingsFromTheServerAreHonoured() throws Exception {
        behaviour = (f, d, c) -> f instanceof Http2Frame.Settings s && !s.ack() && d == FrameDirection.FROM_SERVER
                ? s.withValue(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 1) : f;
        start(s -> {
            Thread.sleep(150);
            s.respond(200, false);
            s.data("ok".getBytes(StandardCharsets.UTF_8), true);
        });
        HttpClient client = Http2ProxyTest.h2Client(proxy, Http2UpstreamTest.proxyCa.clientContext());
        List<CompletableFuture<HttpResponse<String>>> futures = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            futures.add(client.sendAsync(HttpRequest.newBuilder(URI.create(origin.url("/" + i))).timeout(Duration.ofSeconds(30))
                    .build(), HttpResponse.BodyHandlers.ofString()));
        }
        for (CompletableFuture<HttpResponse<String>> f : futures) assertEquals("ok", f.get(30, TimeUnit.SECONDS).body());
        // The server allows any number of streams, but the proxy believes it allows one.
        assertEquals(1, origin.maxOpenStreams.get());
        assertTrue(origin.accepts.get() > 1);
    }

    /**
     * Bodies several times the windows, with DATA doubled or emptied on the way: received DATA counts
     * at its wire size, sent DATA at its new size, so nothing stalls and nothing overruns a window.
     */
    @Test
    void resizedDataKeepsFlowControlInStep() throws Exception {
        int size = 3 << 20;
        behaviour = (f, d, c) -> {
            if (f instanceof Http2Frame.Headers h && d == FrameDirection.FROM_CLIENT) return h.withoutHeader("content-length");
            if (!(f instanceof Http2Frame.Data data) || data.data().length == 0) return f;
            return d == FrameDirection.TO_SERVER ? f : data.withData(twice(data.data()));
        };
        start(s -> {
            long received = 0;
            byte[] piece;
            while ((piece = s.read()) != null) received += piece.length;
            s.respond(200, false, "x-received", Long.toString(received));
            s.data(H2TestOrigin.bytes(size, 7), true);
        });
        HttpClient client = Http2ProxyTest.h2Client(proxy, Http2UpstreamTest.proxyCa.clientContext());
        HttpResponse<byte[]> r = client.send(HttpRequest.newBuilder(URI.create(origin.url("/big"))).timeout(Duration.ofSeconds(60))
                .POST(HttpRequest.BodyPublishers.ofByteArray(H2TestOrigin.bytes(size, 3))).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode());
        // Doubled coming in from the client; doubled coming in from the server and again going out.
        assertEquals(Long.toString(2L * size), r.headers().firstValue("x-received").orElseThrow());
        assertEquals(4 * size, r.body().length);
        byte[] original = H2TestOrigin.bytes(size, 7);
        assertEquals(original[0], r.body()[0]);
    }

    /** Received DATA emptied: its window is still credited back, so a body larger than the windows gets through. */
    @Test
    void emptiedDataStillCreditsTheWindows() throws Exception {
        int size = 3 << 20;
        behaviour = (f, d, c) -> {
            if (f instanceof Http2Frame.Headers h && d == FrameDirection.FROM_CLIENT) return h.withoutHeader("content-length");
            if (f instanceof Http2Frame.Headers h && d == FrameDirection.FROM_SERVER) return h.withoutHeader("content-length");
            return f instanceof Http2Frame.Data data && d.inbound() ? data.withData(new byte[0]) : f;
        };
        start(s -> {
            long received = 0;
            byte[] piece;
            while ((piece = s.read()) != null) received += piece.length;
            s.respond(200, false, "x-received", Long.toString(received), "content-length", Integer.toString(size));
            s.data(H2TestOrigin.bytes(size, 7), true);
        });
        HttpClient client = Http2ProxyTest.h2Client(proxy, Http2UpstreamTest.proxyCa.clientContext());
        HttpResponse<byte[]> r = client.send(HttpRequest.newBuilder(URI.create(origin.url("/big"))).timeout(Duration.ofSeconds(60))
                .POST(HttpRequest.BodyPublishers.ofByteArray(H2TestOrigin.bytes(size, 3))).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode());
        assertEquals("0", r.headers().firstValue("x-received").orElseThrow());
        assertEquals(0, r.body().length);
    }

    private static byte[] twice(byte[] b) {
        byte[] out = new byte[b.length * 2];
        System.arraycopy(b, 0, out, 0, b.length);
        System.arraycopy(b, 0, out, b.length, b.length);
        return out;
    }

    @Test
    void endStreamSetByTheInterceptorIsIgnored() throws Exception {
        behaviour = (f, d, c) -> f instanceof Http2Frame.Headers h && d == FrameDirection.TO_CLIENT ? h.withEndStream(true) : f;
        start(this::echoBody);
        try (H2TestClient c = client()) {
            assertEquals("echo:body", post(c, 1, "body").text());
        }
    }

    @Test
    void manyConcurrentStreamsAreInterceptedEachOnTheirOwn() throws Exception {
        behaviour = (f, d, c) -> f instanceof Http2Frame.Headers h && d == FrameDirection.TO_SERVER
                ? h.withHeader("x-flow-stream", Integer.toString(c.flowContext().getStreamId())) : f;
        start(s -> {
            String value = s.header("x-flow-stream");
            s.respond(200, false);
            s.data((value == null ? "none" : value).getBytes(StandardCharsets.UTF_8), true);
        });
        try (H2TestClient c = client()) {
            for (int i = 0; i < 20; i++) c.get(1 + 2 * i, "/" + i);
            Set<String> answers = new HashSet<>();
            for (int i = 0; i < 20; i++) {
                H2TestClient.Response r = c.response(1 + 2 * i);
                assertEquals(Integer.toString(1 + 2 * i), r.text());
                answers.add(r.text());
            }
            assertEquals(20, answers.size());
        }
    }

    /** gRPC through an interceptor that passes everything on: messages both ways at once, and trailers. */
    @Test
    void grpcTrailersPassThroughAnInterceptor() throws Exception {
        start(s -> {
            s.respond(200, false, "content-type", "application/grpc");
            ByteArrayOutputStream pending = new ByteArrayOutputStream();
            int count = 0;
            byte[] data;
            while ((data = s.read()) != null) {
                pending.write(data);
                for (String m : GrpcThroughProxyTest.messages(pending)) {
                    s.data(GrpcThroughProxyTest.message(m.toUpperCase()), false);
                    count++;
                }
            }
            s.trailers("grpc-status", "0", "grpc-message", "echoed " + count);
        });
        try (H2TestClient c = client()) {
            c.headers(1, c.request("POST", "/echo.Echo/Chat", "content-type", "application/grpc", "te", "trailers"), false);
            c.awaitFrame(f -> f instanceof Frame.Headers h && h.streamId() == 1);
            ByteArrayOutputStream received = new ByteArrayOutputStream();
            for (String m : List.of("one", "two")) {
                c.data(1, GrpcThroughProxyTest.message(m), false);
                List<String> answers = new ArrayList<>();
                while (answers.isEmpty()) {
                    Frame.Data d = (Frame.Data) c.awaitFrame(f -> f instanceof Frame.Data x && x.streamId() == 1);
                    received.write(d.data());
                    answers.addAll(GrpcThroughProxyTest.messages(received));
                }
                assertEquals(List.of(m.toUpperCase()), answers);
            }
            c.data(1, new byte[0], true);
            Frame.Headers trailers = (Frame.Headers) c.awaitFrame(f -> f instanceof Frame.Headers h && h.streamId() == 1);
            assertTrue(trailers.endStream());
            List<HeaderField> t = c.fields(trailers);
            assertEquals("0", value(t, "grpc-status"));
            assertEquals("echoed 2", value(t, "grpc-message"));
        }
        // The trailers were intercepted on both hops.
        assertTrue(seen(seen, Http2Frame.Headers.class, FrameDirection.FROM_SERVER).stream()
                .anyMatch(s -> "0".equals(((Http2Frame.Headers) s.frame).get("grpc-status"))));
        assertTrue(seen(seen, Http2Frame.Headers.class, FrameDirection.TO_CLIENT).stream()
                .anyMatch(s -> "0".equals(((Http2Frame.Headers) s.frame).get("grpc-status"))));
    }

    /** A WebSocket over HTTP/2 on both sides: its bytes are DATA frames, which the interceptor sees. */
    @Test
    void webSocketsOverHttp2WithAnInterceptor() throws Exception {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.enableConnectProtocol = true;
        start(options, s -> {
            s.respond(200, false);
            InputStream in = s.input();
            while (true) {
                WebSocketFrame frame = WebSocketTestSupport.readFrame(in);
                s.data(frame.toWire(false), false);
                if (frame.isClose()) {
                    s.readBody();
                    s.data(new byte[0], true);
                    return;
                }
            }
        });
        try (H2TestClient c = client()) {
            c.headers(1, c.request("CONNECT", "/chat", ":protocol", "websocket", "sec-websocket-version", "13"), false);
            Frame.Headers h = (Frame.Headers) c.awaitFrame(x -> x instanceof Frame.Headers y && y.streamId() == 1);
            assertEquals("200", value(c.fields(h), ":status"));
            c.data(1, WebSocketFrame.text("hello").toWire(true), false);
            byte[] expected = WebSocketFrame.text("hello").toWire(false);
            ByteArrayOutputStream echoed = new ByteArrayOutputStream();
            while (echoed.size() < expected.length) {
                echoed.write(((Frame.Data) c.awaitFrame(x -> x instanceof Frame.Data d && d.streamId() == 1)).data());
            }
            assertEquals("hello", WebSocketTestSupport.readFrame(new ByteArrayInputStream(echoed.toByteArray())).payloadAsText());
            c.data(1, WebSocketFrame.close(1000, "bye").toWire(true), true);
            c.awaitFrame(x -> x instanceof Frame.Data d && d.streamId() == 1 && d.endStream());
        }
        for (FrameDirection d : FrameDirection.values()) {
            assertFalse(seen(seen, Http2Frame.Data.class, d).isEmpty(), "DATA " + d);
        }
        Http2Frame.Headers extended = (Http2Frame.Headers) seen(seen, Http2Frame.Headers.class, FrameDirection.TO_SERVER)
                .getFirst().frame;
        assertEquals("websocket", extended.get(":protocol"));
    }

    /** Prior-knowledge h2c clients go through the same hooks. */
    @Test
    void h2cClientsAreIntercepted() throws Exception {
        HttpServer plain = TestSupport.origin(TestSupport.echo());
        try {
            behaviour = (f, d, c) -> f instanceof Http2Frame.Headers h && d == FrameDirection.FROM_CLIENT
                    ? h.withHeader("x-h2c", "seen") : f;
            proxy = MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true).withFrameInterceptor(recorder).start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(),
                    "127.0.0.1:" + plain.getAddress().getPort()).handshake()) {
                c.get(1, "/h2c");
                H2TestClient.Response r = c.response(1);
                assertEquals(List.of("seen"), TestSupport.echoedHeader(r.text(), "x-h2c"));
            }
            assertNull(seen.getFirst().server);
            assertTrue(seen.stream().noneMatch(s -> s.direction == FrameDirection.TO_SERVER));
        } finally {
            plain.stop(0);
        }
    }

    @Test
    void withoutAnInterceptorNothingIsCalled() throws Exception {
        origin = new H2TestOrigin(Http2UpstreamTest.originContext(), this::echoBody);
        proxy = Http2UpstreamTest.mitm().withHttp2(true).start();
        try (H2TestClient c = client()) {
            assertEquals("echo:x", post(c, 1, "x").text());
        }
        assertTrue(seen.isEmpty());
        assertNull(MicroProxy.bootstrap().getFrameInterceptor());
        assertInstanceOf(FrameInterceptor.class, MicroProxy.bootstrap().withFrameInterceptor(recorder).getFrameInterceptor());
    }
}
