package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.http2.FlowController;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.microproxy.FlowContext;
import org.microproxy.MicroProxy;
import org.microproxy.frames.Field;
import org.microproxy.frames.FrameContext;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.FrameProtocol;
import org.microproxy.frames.Http2Frame;
import org.microproxy.frames.Http3Frame;
import org.microproxy.frames.HttpFrame;

/**
 * The rules {@link Http2Frames} enforces on what a frame interceptor returns, frame by frame, on an
 * endpoint that writes nothing; and that an endpoint without an interceptor has no hook at all.
 */
class Http2FramesTest {

    private static final FrameDirection IN = FrameDirection.FROM_SERVER;
    private static final FrameDirection OUT = FrameDirection.TO_CLIENT;

    /** An endpoint whose interceptor is {@code behaviour}. */
    private static final class Endpoint extends Http2Endpoint {
        Endpoint(FrameInterceptor interceptor) {
            super(new DefaultHttpProxyServer((DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap().withPort(0)
                    .withFrameInterceptor(interceptor)), "[test] ", new FlowController());
        }

        @Override
        String peer() {
            return "server";
        }

        @Override
        void writeFailed() {}

        @Override
        FrameDirection receivedDirection() {
            return IN;
        }

        @Override
        FrameDirection sentDirection() {
            return OUT;
        }

        @Override
        FlowContext flowOf(Stream s) {
            return null;
        }

        @Override
        FlowContext flowOf(int streamId) {
            return null;
        }

        @Override
        long frameConnectionId() {
            return 42;
        }

        @Override
        InetSocketAddress frameClientAddress() {
            return null;
        }

        @Override
        String frameServer() {
            return "example.com:443";
        }
    }

    private final AtomicReference<FrameInterceptor> behaviour = new AtomicReference<>((f, d, c) -> f);
    private final Endpoint endpoint = new Endpoint((f, d, c) -> behaviour.get().intercept(f, d, c));

    private List<Http2Frame> run(Http2Frame frame, FrameDirection direction, FrameInterceptor interceptor) {
        behaviour.set(interceptor);
        return endpoint.frames.intercept(frame, direction, null);
    }

    private static List<Field> request() {
        return List.of(new Field(":method", "GET"), new Field(":scheme", "https"), new Field(":authority", "example.com"),
                new Field(":path", "/"));
    }

    private static Http2Frame.Data data(String text, boolean end) {
        return new Http2Frame.Data(1, text.getBytes(), end);
    }

    @Test
    void withoutAnInterceptorThereIsNoHook() {
        Endpoint plain = new Endpoint(null);
        assertNull(plain.frames);
        assertNotNull(endpoint.frames);
    }

    @Test
    void passingTheFrameOnReturnsItAlone() {
        Http2Frame.Data d = data("x", true);
        List<Http2Frame> out = run(d, IN, (f, dir, c) -> f);
        assertEquals(1, out.size());
        assertSame(d, out.getFirst());
    }

    @Test
    void theContextDescribesTheFrame() {
        AtomicReference<FrameContext> seen = new AtomicReference<>();
        run(data("x", false), IN, (f, d, c) -> {
            seen.set(c);
            return f;
        });
        FrameContext c = seen.get();
        assertEquals(FrameProtocol.HTTP_2, c.protocol());
        assertEquals(1, c.streamId());
        assertEquals(42, c.connectionId());
        assertEquals("example.com:443", c.server());
        assertNull(c.flowContext());
        assertNull(c.clientAddress());
        // Only during the call.
        assertThrows(IllegalStateException.class, () -> c.send(data("late", false)));
    }

    @Test
    void dataCanBeEditedSplitAndDropped() {
        List<Http2Frame> out = run(data("hello world", false), IN, (f, d, c) -> {
            c.send(data(" and more", false));
            return ((Http2Frame.Data) f).withText("HELLO");
        });
        assertEquals(List.of(data("HELLO", false), data(" and more", false)), out);
        assertEquals(List.of(), run(data("x", false), IN, (f, d, c) -> null));
    }

    @Test
    void endStreamIsTheProxys() {
        // Dropped: an empty DATA frame ends the stream instead.
        assertEquals(List.of(new Http2Frame.Data(1, new byte[0], true)), run(data("x", true), IN, (f, d, c) -> null));
        // Moved to the last DATA frame.
        assertEquals(List.of(data("a", false), data("b", true)), run(data("ab", true), IN, (f, d, c) -> {
            c.send(data("b", false));
            return data("a", true);
        }));
        // Set where the original had none: cleared.
        assertEquals(List.of(data("a", false)), run(data("a", false), IN, (f, d, c) -> data("a", true)));
        // Moved to trailers added after the last DATA.
        Http2Frame.Headers trailers = new Http2Frame.Headers(1, List.of(new Field("grpc-status", "0")), false);
        assertEquals(List.of(data("a", false), trailers.withEndStream(true)), run(data("a", true), OUT, (f, d, c) -> {
            c.send(trailers);
            return f;
        }));
        // HEADERS keep theirs.
        Http2Frame.Headers head = new Http2Frame.Headers(1, request(), true);
        assertEquals(List.of(head.withHeader("x-a", "1")), run(head, OUT, (f, d, c) -> head.withHeader("x-a", "1").withEndStream(false)));
    }

    @Test
    void anExtensionFrameMayGoWithAnything() {
        Http2Frame.Unknown ext = new Http2Frame.Unknown(0xf0, 0, 0, new byte[] {1, 2});
        Http2Frame.Settings settings = new Http2Frame.Settings(false, Map.of(Http2Frame.SETTINGS_MAX_FRAME_SIZE, 16_384L));
        assertEquals(List.of(settings, ext), run(settings, OUT, (f, d, c) -> {
            c.send(ext);
            return f;
        }));
        assertEquals(List.of(ext.withPayload(new byte[] {3})), run(ext, IN, (f, d, c) -> ext.withPayload(new byte[] {3})));
        assertEquals(List.of(), run(ext, IN, (f, d, c) -> null));
    }

    /** Results that break a rule: the original goes on alone. */
    @Test
    void illegalResultsAreReplacedByTheOriginal() {
        Http2Frame.Headers head = new Http2Frame.Headers(1, request(), false);
        Http2Frame.Data body = data("body", false);
        Http2Frame.Data last = data("body", true);
        Http2Frame.RstStream rst = new Http2Frame.RstStream(1, 8);
        Http2Frame.GoAway goAway = new Http2Frame.GoAway(5, 0, new byte[0]);
        Http2Frame.Settings ack = new Http2Frame.Settings(true, Map.of());
        Http2Frame.WindowUpdate window = new Http2Frame.WindowUpdate(0, 1000);
        Http2Frame.Ping ping = new Http2Frame.Ping(true, 7);
        Http2Frame.Priority priority = new Http2Frame.Priority(3, 0, false, 16);
        Http2Frame.Settings own = new Http2Frame.Settings(false, Map.of(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 100L));

        record Case(String name, Http2Frame frame, FrameDirection direction, FrameInterceptor interceptor) {}
        List<Case> cases = new ArrayList<>(List.of(
                new Case("another stream", head, OUT, (f, d, c) -> new Http2Frame.Headers(3, request(), false)),
                new Case("HEADERS dropped", head, OUT, (f, d, c) -> null),
                new Case("HEADERS replaced by DATA", head, OUT, (f, d, c) -> data("x", false)),
                new Case("DATA added after HEADERS", head, OUT, (f, d, c) -> {
                    c.send(data("x", false));
                    return f;
                }),
                new Case("upper-case field", head, OUT, (f, d, c) -> head.withHeader("X-Upper", "1")),
                new Case("connection-specific field", head, IN, (f, d, c) -> head.withHeader("connection", "close")),
                new Case("pseudo-header after a field", head, OUT,
                        (f, d, c) -> head.withFields(List.of(new Field("a", "b"), new Field(":path", "/")))),
                new Case("CR in a value", head, OUT, (f, d, c) -> head.withHeader("x", "a\r\nb: c")),
                new Case("an HTTP/3 frame", body, OUT, (f, d, c) -> Http3Frame.data(new byte[1])),
                new Case("trailers on a stream that goes on", body, OUT, (f, d, c) -> {
                    c.send(new Http2Frame.Headers(1, List.of(), false));
                    return f;
                }),
                new Case("DATA after trailers", last, OUT, (f, d, c) -> {
                    c.send(new Http2Frame.Headers(1, List.of(), false));
                    c.send(data("more", false));
                    return f;
                }),
                new Case("a frame after the end of the stream", last, OUT, (f, d, c) -> {
                    c.send(new Http2Frame.Unknown(0xf0, 0, 1, new byte[0]));
                    return f;
                }),
                new Case("an extension frame on another stream", body, OUT,
                        (f, d, c) -> new Http2Frame.Unknown(0xf0, 0, 9, new byte[0])),
                new Case("an extension frame too large", body, OUT,
                        (f, d, c) -> new Http2Frame.Unknown(0xf0, 0, 1, new byte[20_000])),
                new Case("RST_STREAM dropped", rst, OUT, (f, d, c) -> null),
                new Case("RST_STREAM moved", rst, OUT, (f, d, c) -> new Http2Frame.RstStream(3, 8)),
                new Case("GOAWAY's last stream", goAway, OUT, (f, d, c) -> new Http2Frame.GoAway(7, 0, new byte[0])),
                new Case("GOAWAY dropped", goAway, IN, (f, d, c) -> null),
                new Case("SETTINGS ACK edited", ack, IN, (f, d, c) -> null),
                new Case("WINDOW_UPDATE edited", window, OUT, (f, d, c) -> new Http2Frame.WindowUpdate(0, 1001)),
                new Case("PING edited", ping, OUT, (f, d, c) -> new Http2Frame.Ping(true, 8)),
                new Case("something added to PING", ping, OUT, (f, d, c) -> {
                    c.send(new Http2Frame.Unknown(0xf0, 0, 0, new byte[0]));
                    return f;
                }),
                new Case("PRIORITY on itself", priority, IN, (f, d, c) -> new Http2Frame.Priority(3, 3, false, 16)),
                new Case("the proxy's own settings", own, OUT, (f, d, c) -> own.withValue(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 5)),
                new Case("a larger window than the peer's", new Http2Frame.Settings(false, Map.of(4, 1000L)), IN,
                        (f, d, c) -> ((Http2Frame.Settings) f).withValue(4, 2000)),
                new Case("a setting the peer lowered left out", new Http2Frame.Settings(false, Map.of(4, 1000L)), IN,
                        (f, d, c) -> ((Http2Frame.Settings) f).withoutValue(4)),
                new Case("an invalid frame size", new Http2Frame.Settings(false, Map.of()), IN,
                        (f, d, c) -> ((Http2Frame.Settings) f).withValue(Http2Frame.SETTINGS_MAX_FRAME_SIZE, 100)),
                new Case("ENABLE_CONNECT_PROTOCOL turned on", new Http2Frame.Settings(false, Map.of()), IN,
                        (f, d, c) -> ((Http2Frame.Settings) f).withValue(Http2Frame.SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)),
                new Case("the interceptor throws", body, IN, (f, d, c) -> {
                    throw new IllegalStateException("boom");
                })));
        for (Case c : cases) {
            List<Http2Frame> out = run(c.frame, c.direction, c.interceptor);
            assertEquals(List.of(c.frame), out, c.name);
        }
    }

    @Test
    void legalEditsOfOtherFrames() {
        Http2Frame.Settings server = new Http2Frame.Settings(false, Map.of(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 100L));
        Http2Frame.Settings stricter = server.withValue(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 1)
                .withValue(Http2Frame.SETTINGS_INITIAL_WINDOW_SIZE, 1000).withValue(0x99, 1);
        assertEquals(List.of(stricter), run(server, IN, (f, d, c) -> stricter));
        Http2Frame.Settings own = new Http2Frame.Settings(false, Map.of(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 100L));
        assertEquals(List.of(own.withValue(0x99, 7)), run(own, OUT, (f, d, c) -> own.withValue(0x99, 7)));
        Http2Frame.RstStream rst = new Http2Frame.RstStream(1, 8);
        assertEquals(List.of(rst.withErrorCode(0)), run(rst, OUT, (f, d, c) -> rst.withErrorCode(0)));
        Http2Frame.GoAway goAway = new Http2Frame.GoAway(5, 0, new byte[0]);
        Http2Frame.GoAway edited = goAway.withErrorCode(11).withDebugData("calm".getBytes());
        assertEquals(List.of(edited), run(goAway, IN, (f, d, c) -> edited));
        Http2Frame.Priority priority = new Http2Frame.Priority(3, 0, false, 16);
        assertEquals(List.of(), run(priority, IN, (f, d, c) -> null));
        // Read-only frames may come back as equal copies.
        Http2Frame.Ping ping = new Http2Frame.Ping(true, 7);
        assertEquals(List.of(ping), run(ping, OUT, (f, d, c) -> new Http2Frame.Ping(true, 7)));
    }

    @Test
    void theInterceptorIsCalledOncePerFrame() {
        AtomicInteger calls = new AtomicInteger();
        run(data("x", true), IN, (f, d, c) -> {
            calls.incrementAndGet();
            return f;
        });
        assertEquals(1, calls.get());
    }

    @Test
    void fieldValidation() {
        Field.validate(request());
        Field.validate(List.of(new Field(":status", "200"), new Field("te", "trailers")));
        for (List<Field> bad : List.of(
                List.of(new Field("", "x")),
                List.of(new Field("a b", "x")),
                List.of(new Field(":nope", "x")),
                List.of(new Field(":path", "/"), new Field(":path", "/")),
                List.of(new Field(":status", "200"), new Field(":method", "GET")),
                List.of(new Field("te", "gzip")),
                List.of(new Field("x", " padded")),
                List.of(new Field("x", "Ā")),
                List.of(new Field("transfer-encoding", "chunked")))) {
            assertThrows(IllegalArgumentException.class, () -> Field.validate(bad), bad.toString());
        }
    }

    @Test
    void frameHelpers() {
        Http2Frame.Headers h = new Http2Frame.Headers(1, request(), false).withHeader(":protocol", "websocket")
                .withHeader("x-a", "1").withHeader("x-a", "2").withoutHeader(":scheme");
        assertEquals(List.of(":method", ":authority", ":path", ":protocol", "x-a"), h.fields().stream().map(Field::name).toList());
        assertEquals("2", h.get("x-a"));
        assertEquals("PROTOCOL_ERROR", Http2Frame.errorName(1));
        assertEquals("0x99", Http2Frame.errorName(0x99));
        assertEquals("MAX_FRAME_SIZE", Http2Frame.settingName(5));
        assertEquals(5, Http2Frame.settingId("SETTINGS_MAX_FRAME_SIZE"));
        assertEquals(0x99, Http2Frame.settingId("0x99"));
        assertThrows(IllegalArgumentException.class, () -> Http2Frame.settingId("NOPE"));
        assertEquals(data("a", true), data("a", true));
        assertFalse(data("a", true).equals(data("b", true)));
        assertTrue(new Http3Frame.Unknown(0x21, new byte[0]).isReserved());
        assertThrows(IllegalArgumentException.class, () -> new Http3Frame.Unknown(0x04, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new Http2Frame.Unknown(0x04, 0, 0, new byte[0]));
        HttpFrame f = Http2Frame.data(1, new byte[0], false);
        assertEquals("DATA", f.typeName());
        assertEquals(FrameProtocol.HTTP_2, f.protocol());
    }
}
