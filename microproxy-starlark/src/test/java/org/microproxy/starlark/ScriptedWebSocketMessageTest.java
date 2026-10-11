package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.starlark.ScriptedReadmeTest.inReadme;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.H2StreamClient;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.WebSocketPeer;
import org.microproxy.http.WebSocketFrame;

/** {@code on_websocket_message}: whole, inflated messages for scripts, and the README's examples. */
@Timeout(30)
class ScriptedWebSocketMessageTest {

    static final String JSON_FIELD = """
            def on_websocket_message(msg, ctx):
                if msg.type != "text" or not msg.from_client or not msg.text.startswith("{"):
                    return None
                data = json.decode(msg.text)
                if data.get("room") == "staging":
                    data["room"] = "production"
                    msg.text = json.encode(data)
            """;

    static final String DROP_LARGE = """
            MAX_UPLOAD = 64 * 1024

            def on_websocket_message(msg, ctx):
                if msg.type == "binary" and msg.length > MAX_UPLOAD:
                    log.warn("dropped a %d-byte upload from %s" % (msg.length, ctx.client_ip))
                    return [websocket_message('{"error": "upload too large"}', from_client=False)]
                return None
            """;

    static final String CHAT_LOG = """
            def on_request(req: Request, ctx: Context) -> Response | None:
                ctx.vars["chat"] = req.path
                return None

            def on_websocket_message(msg: WebSocketMessage, ctx: Context) -> None:
                if msg.type == "text":
                    sender = "client" if msg.from_client else "server"
                    log.info("%s %s: %s" % (ctx.vars["chat"], sender, cast(str, msg.text)))
                return None
            """;

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    private void start(String source) throws Exception {
        start(MicroProxy.bootstrap(), source);
    }

    private void start(HttpProxyServerBootstrap bootstrap, String source) throws Exception {
        proxy = bootstrap.withPort(0).withFiltersSource(ScriptedProxy.builder(source, "ws.star").build()).start();
    }

    /** Collects what scripts log, at INFO and above (the tests' logging configuration shows warnings only). */
    private static final class ScriptLog extends Handler implements AutoCloseable {
        final List<String> lines = new CopyOnWriteArrayList<>();
        private final Logger logger = Logger.getLogger("microproxy.script");
        private final Level level = logger.getLevel();

        ScriptLog() {
            logger.setLevel(Level.INFO);
            logger.addHandler(this);
        }

        @Override
        public void publish(LogRecord record) {
            lines.add(java.text.MessageFormat.format(record.getMessage(), record.getParameters()));
        }

        @Override
        public void flush() {}

        @Override
        public void close() {
            logger.removeHandler(this);
            logger.setLevel(level);
        }
    }

    @Test
    void readmeJsonFieldExample() throws Exception {
        start(inReadme(JSON_FIELD));
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            // Split mid-string: only the joined message is JSON.
            client.sendMessage(WebSocketFrame.OPCODE_TEXT,
                    "{\"room\": \"staging\", \"text\": \"ping\"}".getBytes(StandardCharsets.UTF_8), false, 3);
            client.sendText("ping, not JSON");
            client.sendText("{\"room\": \"lobby\"}");
            client.sendText("ping");
            assertEquals("echo:ping, not JSON", client.readMessage().text());
            assertEquals("echo:ping", client.readMessage().text());
            assertEquals(List.of("{\"room\":\"production\",\"text\":\"ping\"}", "ping, not JSON", "{\"room\": \"lobby\"}",
                    "ping"), server.texts());
        }
    }

    @Test
    void readmeDropLargeBinaryExample() throws Exception {
        start(inReadme(DROP_LARGE));
        try (ScriptLog log = new ScriptLog();
                WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.sendMessage(WebSocketFrame.OPCODE_BINARY, new byte[100 * 1024], false, 4);
            assertEquals("{\"error\": \"upload too large\"}", client.readMessage().text());
            client.sendMessage(WebSocketFrame.OPCODE_BINARY, new byte[1024], false, 2);
            assertEquals(1024, client.readMessage().payload().length, "small uploads go through and are echoed");
            assertEquals(1, server.received.size());
            assertTrue(log.lines.stream().anyMatch(l -> l.contains("dropped a 102400-byte upload from 127.0.0.1")),
                    log.lines.toString());
        }
    }

    @Test
    void readmeCompressedChatLogExample() throws Exception {
        start(inReadme(CHAT_LOG));
        try (ScriptLog log = new ScriptLog();
                WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), "permessage-deflate")) {
            client.sendMessage(WebSocketFrame.OPCODE_TEXT, "ping, is anyone here?".getBytes(StandardCharsets.UTF_8),
                    true, 2);
            WebSocketPeer.Message echo = client.readMessage();
            assertTrue(echo.compressed());
            assertEquals("echo:ping, is anyone here?", echo.text());
            assertTrue(server.received.getFirst().compressed());
            eventually("both messages logged", () -> log.lines.size() >= 2);
            assertTrue(log.lines.get(0).endsWith("/chat client: ping, is anyone here?"), log.lines.toString());
            assertTrue(log.lines.get(1).endsWith("/chat server: echo:ping, is anyone here?"), log.lines.toString());
        }
    }

    @Test
    void typedScriptsReturnListsOfMessages() throws Exception {
        start("""
                def on_websocket_message(msg: WebSocketMessage, ctx: Context) -> WebSocketMessage | list[WebSocketMessage] | bool | None:
                    if not msg.from_client:
                        return None
                    text = cast(str, msg.text)
                    if text == "whoami":
                        return [websocket_message("you are " + ctx.client_ip, from_client=False)]
                    if text == "twice":
                        again: WebSocketMessage = websocket_message("ping again", from_client=True)
                        msg.text = "ping once"
                        return [msg, again]
                    if text == "bytes":
                        return websocket_message(b"\\x00\\x01", from_client=True)
                    if text == "drop":
                        return False
                    if text == "empty":
                        return []
                    return True
                """);
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.sendText("whoami");
            assertEquals("you are 127.0.0.1", client.readMessage().text());
            client.sendText("twice");
            assertEquals("echo:ping once", client.readMessage().text());
            assertEquals("echo:ping again", client.readMessage().text());
            client.sendText("drop");
            client.sendText("empty");
            client.sendText("bytes");
            WebSocketPeer.Message binary = client.readMessage();
            assertEquals(WebSocketFrame.OPCODE_BINARY, binary.opcode());
            client.sendText("ping as is");
            assertEquals("echo:ping as is", client.readMessage().text());
            assertEquals(List.of("ping once", "ping again", "\u0000\u0001", "ping as is"), server.texts());
        }
    }

    @Test
    void typesAreCheckedWhenTheScriptLoads() {
        assertThrows(ScriptException.class, () -> StarlarkScript.compile("""
                def on_websocket_message(msg: WebSocketMessage, ctx: Context) -> None:
                    n: str = msg.length
                """, "bad.star", StarlarkScript.Limits.DEFAULT));
        assertThrows(ScriptException.class, () -> StarlarkScript.compile("""
                def on_websocket_message(msg: WebSocketMessage, ctx: Context) -> None:
                    print(msg.lenght)
                """, "bad.star", StarlarkScript.Limits.DEFAULT));
    }

    @Test
    void frameAndMessageHooksRunInThatOrder() throws Exception {
        start("""
                def on_websocket_frame(req, frame, ctx):
                    if frame.from_client and frame.type in ("text", "continuation"):
                        ctx.vars.setdefault("order", []).append("frame " + frame.text)
                        frame.text = frame.text + "."

                def on_websocket_message(msg, ctx):
                    if msg.from_client:
                        ctx.vars["order"].append("message " + msg.text)
                        msg.text = msg.text + " " + ",".join(ctx.vars["order"])
                """);
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.send(WebSocketFrame.of(false, 0, WebSocketFrame.OPCODE_TEXT, "ping".getBytes()));
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_PING, new byte[0]));
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_CONTINUATION, "pong".getBytes()));
            assertEquals("echo:ping.pong. frame ping,frame pong,message ping.pong.", client.readMessage().text());
        }
    }

    @Test
    void aFailingOrBadlyTypedHookSendsTheMessageOn() throws Exception {
        start("""
                def on_websocket_message(msg, ctx):
                    if msg.text == "ping fail":
                        fail("boom")
                    if msg.text == "ping number":
                        return 42
                    if msg.text == "ping list":
                        return ["not a message"]
                """);
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            for (String text : List.of("ping fail", "ping number", "ping list")) {
                client.sendText(text);
                assertEquals("echo:" + text, client.readMessage().text());
            }
        }
    }

    @Test
    void messagesOverHttp2AreJoinedForScripts() throws Exception {
        start(MicroProxy.bootstrap().withHttp2Cleartext(true), """
                def on_websocket_message(msg, ctx):
                    if msg.from_client:
                        msg.text = msg.text.upper()
                """);
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                H2StreamClient c = H2StreamClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + server.port())) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/chat", "sec-websocket-extensions", "permessage-deflate"), false);
            assertEquals(200, ws.status());
            WebSocketPeer peer = WebSocketPeer.client(ws.in(), ws.out(),
                    WebSocketPeer.Agreement.parse(ws.header("sec-websocket-extensions")));
            peer.sendMessage(WebSocketFrame.OPCODE_TEXT, "ping over h2".getBytes(StandardCharsets.UTF_8), true, 2);
            WebSocketPeer.Message echo = peer.readMessage();
            assertTrue(echo.compressed());
            assertEquals("echo:PING OVER H2", echo.text());
            assertEquals(List.of("PING OVER H2"), server.texts());
            ws.reset(io.github.mahmoudimus.http2.ErrorCode.CANCEL);
        }
    }
}
