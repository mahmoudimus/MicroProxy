package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.starlark.ScriptedReadmeTest.inReadme;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3FrameReader;
import io.github.mahmoudimus.http3.Http3FrameWriter;
import io.github.mahmoudimus.http3.Http3Settings;
import io.github.mahmoudimus.http3.Http3StreamType;
import io.github.mahmoudimus.http3.QpackDecoder;
import io.github.mahmoudimus.http3.QpackEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.FlowContext;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.frames.Field;
import org.microproxy.frames.FrameContext;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.FrameProtocol;
import org.microproxy.frames.Http2Frame;
import org.microproxy.frames.Http3Frame;
import org.microproxy.frames.Http3FramePipeline;
import org.microproxy.frames.HttpFrame;

/**
 * {@code on_frame}: the README's examples on live HTTP/2 (h2c) connections and over the HTTP/3
 * pipeline, return values, failures, the {@code h2} and {@code h3} constructors, and typed scripts.
 */
class ScriptedFrameTest {

    static final String REWRITE_HEADER = """
            def on_frame(frame, ctx):
                if frame.type == "HEADERS" and frame.direction == "from_client":
                    frame.headers["user-agent"] = "MicroProxy"
                    frame.headers.remove("x-debug")
            """;

    static final String REDACT = """
            def on_frame(frame, ctx):
                if frame.type == "HEADERS":
                    frame.headers.remove("content-length")  # redacting changes the body's length
                elif frame.type == "DATA" and frame.text != None:
                    frame.text = re.sub(r"\\b[0-9]{13,16}\\b", "<card>", frame.text)
            """;

    static final String DROP = """
            def on_frame(frame, ctx):
                if frame.type in ("PRIORITY", "UNKNOWN"):
                    return False
            """;

    static final String LOG_SERVERS = """
            def on_frame(frame, ctx):
                if frame.direction != "from_server":
                    return None
                if frame.type == "SETTINGS" and not frame.ack:
                    log.info("%s settings: %s" % (ctx.server, frame.settings))
                elif frame.type == "GOAWAY":
                    log.warn("%s goes away: %s after stream %d (%s)" % (
                        ctx.server, frame.error, frame.last_stream_id, frame.debug_data))
            """;

    static final String INJECT = """
            def on_frame(frame, ctx):
                # Trailers after the last DATA frame of every response, and a hint before it.
                if frame.type == "DATA" and frame.direction == "to_client" and frame.end_stream:
                    hint = h2.unknown(0xf0, 0, "checked")
                    return [frame, hint, h2.headers(frame.stream_id, {"x-proxied-by": "MicroProxy"})]
            """;

    static final String HTTP3 = """
            def on_frame(frame, ctx):
                if frame.protocol != "h3":
                    return None
                if frame.type == "HEADERS" and ":method" in frame.headers:
                    frame.headers["x-seen-by"] = "MicroProxy"
                elif frame.type == "DATA" and frame.text != None:
                    return [frame, h3.data(" (checked)")]
                elif frame.type == "SETTINGS":
                    frame.settings["MAX_FIELD_SECTION_SIZE"] = 16384
            """;

    static final String TYPED = """
            def on_frame(frame: Frame, ctx: FrameContext) -> list[Frame] | bool | None:
                if frame.type == "UNKNOWN":
                    return False
                if frame.type == "HEADERS" and frame.direction == "from_client":
                    headers = cast(Headers, frame.headers)
                    headers["x-stream"] = str(ctx.stream_id)
                return None
            """;

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final List<String> logs = new CopyOnWriteArrayList<>();
    private final Logger scriptLog = Logger.getLogger("microproxy.script");
    private final Logger proxyLog = Logger.getLogger(ScriptedProxy.class.getName());
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord r) {
            if (r.getLevel().intValue() >= Level.INFO.intValue()) {
                logs.add(java.text.MessageFormat.format(r.getMessage(), r.getParameters()));
            }
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
    };

    private Level scriptLevel;

    @BeforeEach
    void captureLogs() {
        scriptLevel = scriptLog.getLevel();
        scriptLog.setLevel(Level.INFO);
        scriptLog.addHandler(capture);
        proxyLog.addHandler(capture);
    }

    @AfterEach
    void tearDown() {
        scriptLog.setLevel(scriptLevel);
        scriptLog.removeHandler(capture);
        proxyLog.removeHandler(capture);
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    private static ScriptedProxy script(String source) throws Exception {
        return ScriptedProxy.builder(source, "frames.star").build();
    }

    /** An h2c proxy whose frames go through {@code source}'s on_frame, before an HTTP/1 echo origin. */
    private RawH2 start(String source) throws Exception {
        ScriptedProxy script = script(source);
        assertTrue(script.definesFrameHook());
        origin = origin(echo());
        proxy = MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true).withFrameInterceptor(script.frameInterceptor()).start();
        return new RawH2(proxy.getListenAddress(), "127.0.0.1:" + origin.getAddress().getPort());
    }

    /** A FrameContext for calling an interceptor directly; added frames are collected. */
    private static final class Context implements FrameContext {
        final List<HttpFrame> sent = new ArrayList<>();
        private final FrameProtocol protocol;

        Context(FrameProtocol protocol) {
            this.protocol = protocol;
        }

        @Override
        public FrameProtocol protocol() {
            return protocol;
        }

        @Override
        public long connectionId() {
            return 3;
        }

        @Override
        public InetSocketAddress clientAddress() {
            return null;
        }

        @Override
        public String server() {
            return "origin.example:443";
        }

        @Override
        public long streamId() {
            return 1;
        }

        @Override
        public FlowContext flowContext() {
            return null;
        }

        @Override
        public void send(HttpFrame frame) {
            sent.add(frame);
        }
    }

    @Test
    void rewritesAHeaderInHeadersFrames() throws Exception {
        try (RawH2 h2 = start(inReadme(REWRITE_HEADER))) {
            h2.request(1, "GET", "/", null, "user-agent", "curl", "x-debug", "1");
            String body = h2.response(1).body();
            assertEquals(List.of("MicroProxy"), echoedHeader(body, "user-agent"));
            assertEquals(List.of(), echoedHeader(body, "x-debug"));
        }
    }

    @Test
    void redactsAPatternInDataPayloads() throws Exception {
        try (RawH2 h2 = start(inReadme(REDACT))) {
            h2.request(1, "POST", "/pay", "card=4111111111111111&cvc=123", "content-length", "30");
            RawH2.Response r = h2.response(1);
            assertEquals("card=<card>&cvc=123", echoedBody(r.body()));
            assertNull(r.header("content-length"));
        }
    }

    @Test
    void dropsPriorityAndExtensionFrames() throws Exception {
        try (RawH2 h2 = start(inReadme(DROP))) {
            h2.frame(new Frame.Priority(3, new Frame.PrioritySpec(0, false, 16)));
            h2.frame(new Frame.Unknown(0xf1, 0, 0, new byte[] {1}));
            h2.request(1, "GET", "/", null);
            assertTrue(h2.response(1).body().startsWith("method: GET"));
        }
        FrameInterceptor i = script(DROP).frameInterceptor();
        assertNull(i.intercept(new Http2Frame.Priority(3, 0, false, 16), FrameDirection.FROM_CLIENT, new Context(FrameProtocol.HTTP_2)));
        Http2Frame.Ping ping = new Http2Frame.Ping(false, 1);
        assertSame(ping, i.intercept(ping, FrameDirection.FROM_CLIENT, new Context(FrameProtocol.HTTP_2)));
    }

    @Test
    void logsSettingsAndGoAwayFromServers() throws Exception {
        FrameInterceptor i = script(inReadme(LOG_SERVERS)).frameInterceptor();
        Http2Frame.Settings settings = new Http2Frame.Settings(false, Map.of(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 100L));
        assertSame(settings, i.intercept(settings, FrameDirection.FROM_SERVER, new Context(FrameProtocol.HTTP_2)));
        Http2Frame.GoAway goAway = new Http2Frame.GoAway(7, 11, "calm down".getBytes(StandardCharsets.UTF_8));
        assertSame(goAway, i.intercept(goAway, FrameDirection.FROM_SERVER, new Context(FrameProtocol.HTTP_2)));
        i.intercept(settings, FrameDirection.FROM_CLIENT, new Context(FrameProtocol.HTTP_2));
        assertEquals(2, logs.size(), logs.toString());
        assertTrue(logs.get(0).endsWith("origin.example:443 settings: {\"MAX_CONCURRENT_STREAMS\": 100}"), logs.get(0));
        assertTrue(logs.get(1).endsWith("origin.example:443 goes away: ENHANCE_YOUR_CALM after stream 7 (calm down)"), logs.get(1));
    }

    @Test
    void injectsFrames() throws Exception {
        try (RawH2 h2 = start(inReadme(INJECT))) {
            h2.request(1, "GET", "/", null);
            RawH2.Response r = h2.response(1);
            assertTrue(r.body().startsWith("method: GET"));
            // The END_STREAM moved to the trailers; the hint came before them.
            assertEquals("MicroProxy", r.trailer("x-proxied-by"));
            assertEquals(1, r.extensions().size());
            assertEquals("checked", new String(r.extensions().getFirst().payload(), StandardCharsets.UTF_8));
        }
    }

    @Test
    void typedScriptsRunAndAreChecked() throws Exception {
        try (RawH2 h2 = start(inReadme(TYPED))) {
            h2.request(5, "GET", "/", null);
            assertEquals(List.of("5"), echoedHeader(h2.response(5).body(), "x-stream"));
        }
        String error = assertThrows(ScriptException.class, () -> script("""
                def on_frame(frame: Frame, ctx: FrameContext):
                    return frame.paylod
                """)).getMessage();
        assertTrue(error.contains("'frame' of type 'Frame' does not have field 'paylod'"), error);
        error = assertThrows(ScriptException.class, () -> script("""
                def on_frame(frame: Frame, ctx: FrameContext):
                    frame.error_code = "CANCEL"
                """)).getMessage();
        assertTrue(error.contains("cannot assign type 'str' to 'frame.error_code' of type 'int | None'"), error);
        error = assertThrows(ScriptException.class, () -> script("""
                def on_frame(frame: Frame, ctx: FrameContext) -> str:
                    return ctx.server
                """)).getMessage();
        assertTrue(error.contains("declares return type 'str' but may return 'str | None'"), error);
        error = assertThrows(ScriptException.class, () -> script("""
                def on_frame(frame: Frame, ctx: FrameContext) -> Frame:
                    return h2.data(frame.stream_id, "x")
                def helper(ctx: FrameContext) -> str:
                    return ctx.stream_id
                """)).getMessage();
        assertTrue(error.contains("declares return type 'str' but may return 'int'"), error);
    }

    @Test
    void framesAreEditedInPlaceAndReplaced() throws Exception {
        FrameInterceptor i = script("""
                def on_frame(frame, ctx):
                    if frame.type == "DATA":
                        frame.payload = frame.payload + b"!"
                    elif frame.type == "RST_STREAM":
                        frame.error_code = 0
                    elif frame.type == "GOAWAY":
                        frame.debug_data = "bye"
                    elif frame.type == "SETTINGS":
                        frame.settings["MAX_CONCURRENT_STREAMS"] = 1
                        frame.settings["0x99"] = 7
                    elif frame.type == "HEADERS":
                        return h2.headers(frame.stream_id, [(":status", "204"), ("X-Made", "yes")], end_stream=True)
                    elif frame.type == "UNKNOWN":
                        return []
                """).frameInterceptor();
        Context ctx = new Context(FrameProtocol.HTTP_2);
        Http2Frame.Data data = (Http2Frame.Data) i.intercept(Http2Frame.data(1, "hi".getBytes(StandardCharsets.UTF_8), true),
                FrameDirection.TO_CLIENT, ctx);
        assertEquals("hi!", data.text());
        assertTrue(data.endStream());
        assertEquals(0, ((Http2Frame.RstStream) i.intercept(new Http2Frame.RstStream(1, 8), FrameDirection.TO_SERVER, ctx)).errorCode());
        assertEquals("bye", ((Http2Frame.GoAway) i.intercept(new Http2Frame.GoAway(1, 0, new byte[0]),
                FrameDirection.TO_CLIENT, ctx)).debugText());
        Http2Frame.Settings settings = (Http2Frame.Settings) i.intercept(new Http2Frame.Settings(false,
                Map.of(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 100L)), FrameDirection.FROM_SERVER, ctx);
        assertEquals(Map.of(Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS, 1L, 0x99, 7L), settings.values());
        Http2Frame.Headers h = (Http2Frame.Headers) i.intercept(new Http2Frame.Headers(1, List.of(new Field(":status", "200")), false),
                FrameDirection.TO_CLIENT, ctx);
        assertEquals(List.of(new Field(":status", "204"), new Field("x-made", "yes")), h.fields());
        assertNull(i.intercept(Http2Frame.unknown(0xf0, 0, 0, new byte[0]), FrameDirection.FROM_CLIENT, ctx));
        assertTrue(ctx.sent.isEmpty());
        // Read-only frames: the value comes back unchanged.
        Http2Frame.WindowUpdate w = new Http2Frame.WindowUpdate(0, 10);
        assertSame(w, i.intercept(w, FrameDirection.TO_CLIENT, ctx));
    }

    @Test
    void theFrameValueDescribesTheFrame() throws Exception {
        FrameInterceptor i = script("""
                def on_frame(frame, ctx):
                    log.info("%s %s %d %s %s %s %s %s %s" % (frame.protocol, frame.type, frame.type_code, frame.stream_id,
                        frame.end_stream, frame.direction, frame.headers.get(":path"), ctx.connection_id, ctx.protocol))
                    log.info("%s %s %s %s" % (frame.payload, frame.text, frame.settings, frame.error_code))
                """).frameInterceptor();
        i.intercept(new Http2Frame.Headers(1, List.of(new Field(":path", "/x")), true), FrameDirection.FROM_CLIENT,
                new Context(FrameProtocol.HTTP_2));
        assertTrue(logs.get(0).endsWith("h2 HEADERS 1 1 True from_client /x 3 h2"), logs.get(0));
        assertTrue(logs.get(1).endsWith("None None None None"), logs.get(1));
    }

    @Test
    void aFailingHookPassesTheFrameOn() throws Exception {
        Http2Frame.Data data = Http2Frame.data(1, "x".getBytes(StandardCharsets.UTF_8), false);
        for (String source : List.of(
                "def on_frame(frame, ctx):\n    fail(\"boom\")\n",
                "def on_frame(frame, ctx):\n    return 42\n",
                "def on_frame(frame, ctx):\n    return [frame, 1]\n",
                "def on_frame(frame, ctx):\n    frame.settings[\"NOPE\"] = 1\n    return frame\n",
                "def on_frame(frame, ctx):\n    frame.error_code = 1\n")) {
            Context ctx = new Context(FrameProtocol.HTTP_2);
            assertSame(data, script(source).frameInterceptor().intercept(data, FrameDirection.FROM_CLIENT, ctx), source);
            assertTrue(ctx.sent.isEmpty());
        }
        assertTrue(logs.stream().allMatch(l -> l.contains("on_frame failed")), logs.toString());
    }

    @Test
    void scriptsWithoutTheHookLeaveFramesAlone() throws Exception {
        ScriptedProxy script = script("def on_request(req, ctx):\n    return None\n");
        assertFalse(script.definesFrameHook());
        Http2Frame.Data data = Http2Frame.data(1, new byte[1], false);
        assertSame(data, script.frameInterceptor().intercept(data, FrameDirection.FROM_CLIENT, new Context(FrameProtocol.HTTP_2)));
    }

    /** {@code --script} installs the interceptor only for a script that defines on_frame. */
    @Test
    void theLauncherInstallsTheInterceptorOnlyForScriptsWithTheHook(@TempDir Path dir) throws Exception {
        Path with = Files.writeString(dir.resolve("with.star"), DROP);
        Path without = Files.writeString(dir.resolve("without.star"), "def on_request(req, ctx):\n    return None\n");
        for (Path file : List.of(with, without)) {
            StarlarkLauncherExtension extension = new StarlarkLauncherExtension();
            assertTrue(extension.parseOption("--script", new ArrayDeque<>(List.of(file.toString()))));
            HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap();
            ByteArrayOutputStream console = new ByteArrayOutputStream();
            extension.configure(bootstrap, new PrintStream(console, true, StandardCharsets.UTF_8));
            boolean hook = file == with;
            assertEquals(hook, bootstrap.getFrameInterceptor() != null, file.toString());
            assertEquals(hook, console.toString(StandardCharsets.UTF_8).contains("on_frame()"), console.toString(StandardCharsets.UTF_8));
        }
    }

    @Test
    void constructorsCheckTheirArguments() throws Exception {
        for (String bad : List.of("h2.data(0, \"x\")", "h2.unknown(1, 0, \"x\")", "h2.headers(1, 3)",
                "h2.headers(1, [(\"a\",)])", "h3.unknown(0x01, \"x\")")) {
            FrameInterceptor i = script("def on_frame(frame, ctx):\n    return " + bad + "\n").frameInterceptor();
            Http2Frame.Data data = Http2Frame.data(1, new byte[1], false);
            assertSame(data, i.intercept(data, FrameDirection.FROM_CLIENT, new Context(FrameProtocol.HTTP_2)), bad);
        }
    }

    /** The README's HTTP/3 example, on a request stream and a control stream through the pipeline. */
    @Test
    void http3FramesGoThroughThePipeline() throws Exception {
        ScriptedProxy script = script(inReadme(HTTP3));
        Http3FramePipeline pipeline = Http3FramePipeline.builder(script.frameInterceptor())
                .direction(FrameDirection.FROM_CLIENT).build();

        ByteArrayOutputStream request = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(request);
        w.writeHeaders(new QpackEncoder().encode(0, List.of(new HeaderField(":method", "POST"), new HeaderField(":scheme", "https"),
                new HeaderField(":authority", "example.com"), new HeaderField(":path", "/"))));
        w.writeData("body".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        pipeline.requestStream(0, new ByteArrayInputStream(request.toByteArray()), out);

        Http3FrameReader r = new Http3FrameReader(new ByteArrayInputStream(out.toByteArray()));
        io.github.mahmoudimus.http3.Http3Frame.Headers h = (io.github.mahmoudimus.http3.Http3Frame.Headers) r.readFrame();
        assertTrue(new QpackDecoder().decode(0, h.fieldSection()).contains(new HeaderField("x-seen-by", "MicroProxy")));
        assertArrayEquals("body".getBytes(StandardCharsets.UTF_8), ((io.github.mahmoudimus.http3.Http3Frame.Data) r.readFrame()).data());
        assertArrayEquals(" (checked)".getBytes(StandardCharsets.UTF_8),
                ((io.github.mahmoudimus.http3.Http3Frame.Data) r.readFrame()).data());
        assertNull(r.readFrame());

        ByteArrayOutputStream control = new ByteArrayOutputStream();
        Http3FrameWriter cw = new Http3FrameWriter(control);
        cw.writeStreamType(Http3StreamType.CONTROL);
        cw.writeSettings(Http3Settings.builder().maxFieldSectionSize(65_536).build());
        ByteArrayOutputStream controlOut = new ByteArrayOutputStream();
        pipeline.controlStream(2, new ByteArrayInputStream(control.toByteArray()), controlOut);
        Http3FrameReader cr = new Http3FrameReader(new ByteArrayInputStream(controlOut.toByteArray()));
        assertEquals(Http3StreamType.CONTROL, cr.readStreamType());
        io.github.mahmoudimus.http3.Http3Frame.Settings s = (io.github.mahmoudimus.http3.Http3Frame.Settings) cr.readFrame();
        assertEquals(16_384L, s.values().get(Http3Settings.MAX_FIELD_SECTION_SIZE));
    }

    @Test
    void http3FramesHaveTheirOwnValues() throws Exception {
        FrameInterceptor i = script("""
                def on_frame(frame, ctx):
                    log.info("%s %s %d %d %s" % (frame.protocol, frame.type, frame.type_code, frame.stream_id, ctx.protocol))
                    if frame.type == "UNKNOWN":
                        frame.payload = b"edited"
                    return frame
                """).frameInterceptor();
        Context ctx = new Context(FrameProtocol.HTTP_3);
        HttpFrame out = i.intercept(new Http3Frame.Unknown(0x21, new byte[0]), FrameDirection.FROM_CLIENT, ctx);
        assertArrayEquals("edited".getBytes(StandardCharsets.UTF_8), assertInstanceOf(Http3Frame.Unknown.class, out).payload());
        assertTrue(logs.getFirst().endsWith("h3 UNKNOWN 33 1 h3"), logs.getFirst());
    }
}
