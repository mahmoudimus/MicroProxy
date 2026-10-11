package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.net.Socket;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.H2StreamClient;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.WebSocketTestSupport;
import org.microproxy.WebSocketTestSupport.EchoServer;
import org.microproxy.http.WebSocketFrame;

class ScriptedWebSocketTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    private void start(String source) throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(ScriptedProxy.builder(source, "ws.star").build()).start();
    }

    @Test
    void scriptsRewriteAndDropFrames() throws Exception {
        start("""
                def on_websocket_frame(req: Request, frame: WebSocketFrame, ctx: Context) -> bool | None:
                    if frame.type != "text":
                        return None
                    text = cast(str, frame.text)
                    if frame.from_client:
                        if "password" in text:
                            return False  # never reaches the server
                        ctx.vars["sent"] = ctx.vars.get("sent", 0) + 1
                        frame.text = text.upper()
                    else:
                        frame.text = text + " (" + str(ctx.vars["sent"]) + " sent to " + req.path + ")"
                    return None
                """);
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            OutputStream out = s.getOutputStream();
            WebSocketTestSupport.sendFromClient(out, WebSocketFrame.text("hello"));
            WebSocketTestSupport.sendFromClient(out, WebSocketFrame.text("my password is hunter2"));
            WebSocketTestSupport.sendFromClient(out, WebSocketFrame.text("ping"));
            WebSocketFrame echo = WebSocketTestSupport.readFrame(s.getInputStream());
            assertEquals("echo:PING (2 sent to /chat)", echo.payloadAsText());
            WebSocketTestSupport.sendFromClient(out, WebSocketFrame.close(1000, "done"));
            assertTrue(WebSocketTestSupport.readFrame(s.getInputStream()).isClose());

            List<String> texts = server.received.stream()
                    .map(f -> f.isClose() ? "<close>" : f.payloadAsText()).toList();
            assertEquals(List.of("HELLO", "PING", "<close>"), texts);
            assertFalse(server.upgradeRequest.toLowerCase().contains("sec-websocket-extensions"));
        }
    }

    @Test
    void theHookSeesFramesOfWebSocketsOverHttp2() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true)
                .withFiltersSource(ScriptedProxy.builder("""
                        def on_request(req, ctx):
                            ctx.vars["version"] = req.http_version
                            ctx.vars["upgrade"] = req.headers.get("Upgrade")

                        def on_websocket_frame(req, frame, ctx):
                            if frame.type != "text":
                                return None
                            if frame.from_client:
                                if "drop" in frame.text:
                                    return False
                                frame.text = frame.text.upper()
                            else:
                                frame.text = "%s via %s %s %s" % (frame.text, ctx.vars["version"], req.method, ctx.vars["upgrade"])
                        """, "ws2.star").build())
                .start();
        try (EchoServer server = new EchoServer();
                H2StreamClient c = H2StreamClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + server.raw().port())) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/chat"), false);
            assertEquals(200, ws.status());
            WebSocketTestSupport.sendFromClient(ws.out(), WebSocketFrame.text("please drop me"));
            WebSocketTestSupport.sendFromClient(ws.out(), WebSocketFrame.text("ping"));
            assertEquals("echo:PING via HTTP/2 GET websocket", WebSocketTestSupport.readFrame(ws.in()).payloadAsText());
            WebSocketTestSupport.sendFromClient(ws.out(), WebSocketFrame.close(1000, ""));
            assertTrue(WebSocketTestSupport.readFrame(ws.in()).isClose());
            ws.end();
            assertNull(ws.awaitEnd());
            List<String> texts = server.received.stream().map(f -> f.isClose() ? "<close>" : f.payloadAsText()).toList();
            assertEquals(List.of("PING", "<close>"), texts);
            assertTrue(server.received.stream().allMatch(WebSocketFrame::isMasked));
        }
    }

    @Test
    void aFailingHookForwardsTheFrame() throws Exception {
        start("""
                def on_websocket_frame(req, frame, ctx):
                    fail("boom")
                """);
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("ping"));
            assertEquals("echo:ping", WebSocketTestSupport.readFrame(s.getInputStream()).payloadAsText());
        }
    }

    @Test
    void withoutTheHookCompressionIsLeftAlone() throws Exception {
        start("""
                def on_request(req, ctx):
                    req.headers["X-Seen"] = "yes"
                """);
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("ping"));
            assertEquals("echo:ping", WebSocketTestSupport.readFrame(s.getInputStream()).payloadAsText());
            assertTrue(server.upgradeRequest.toLowerCase().contains("sec-websocket-extensions: permessage-deflate"),
                    server.upgradeRequest);
        }
    }

    @Test
    void readmeRedactionExample() throws Exception {
        start("""
                def on_websocket_frame(req, frame, ctx):
                    if frame.type != "text" or not frame.text.startswith("{"):
                        return None
                    msg = json.decode(frame.text)
                    if "token" in msg:
                        msg["token"] = "<redacted>"
                        frame.text = json.encode(msg)
                """);
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("{\"token\":\"abc\",\"n\":1}"));
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.close(1000, ""));
            WebSocketTestSupport.readFrame(s.getInputStream());
            assertEquals("{\"n\":1,\"token\":\"<redacted>\"}", server.received.get(0).payloadAsText()); // keys sorted
        }
    }

    @Test
    void readmeTypedNumberingExample() throws Exception {
        start("""
                def on_websocket_frame(req: Request, frame: WebSocketFrame, ctx: Context) -> bool | None:
                    if frame.type != "text" or frame.from_client:
                        return None
                    n: int = ctx.vars.get("n", 0) + 1
                    ctx.vars["n"] = n
                    frame.text = "#%d %s" % (n, cast(str, frame.text))
                    return None
                """);
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            for (int i = 1; i <= 2; i++) {
                WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("ping"));
                assertEquals("#" + i + " echo:ping", WebSocketTestSupport.readFrame(s.getInputStream()).payloadAsText());
            }
        }
    }

    @Test
    void readmeExamplesCompile() throws Exception {
        StarlarkScript.compile("""
                def on_websocket_frame(req, frame, ctx):
                    if req.path == "/admin/ws" and frame.from_client and frame.type == "text":
                        if frame.text.startswith("DELETE "):
                            log.warn("blocked %s from %s" % (frame.text, ctx.client_ip))
                            return False
                    if frame.type == "ping" and not frame.from_client:
                        return False
                """, "block.star", StarlarkScript.Limits.DEFAULT);
        start("""
                def on_websocket_frame(req, frame, ctx):
                    if frame.type == "binary":
                        frame.payload = b"v2" + frame.payload[2:]
                """);
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.binary("v1data".getBytes()));
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.close(1000, ""));
            WebSocketTestSupport.readFrame(s.getInputStream());
            assertEquals("v2data", new String(server.received.get(0).payload()));
        }
    }
}
