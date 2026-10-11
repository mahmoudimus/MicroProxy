package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.starlark.ScriptedReadmeTest.inReadme;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;

/**
 * {@code on_tcp_start}, {@code on_tcp_message} and {@code on_tcp_end}: the README's examples on
 * live tunnels, return values, {@code ctx.send} and {@code ctx.vars}, failures, and typed scripts.
 */
class ScriptedTcpTest {

    static final String BANNER = """
            def on_tcp_message(msg, ctx):
                # The server's first message is its greeting.
                if not msg.from_client and not ctx.vars.get("greeted"):
                    ctx.vars["greeted"] = True
                    if msg.text != None:
                        return msg.text.replace("ESMTP", "ESMTP (via MicroProxy)")
            """;

    static final String LOG_LINES = """
            def on_tcp_start(ctx):
                log.info("%s opened by %s (tls %s, sni %s)" % (ctx.server, ctx.client_ip, ctx.tls, ctx.sni))

            def on_tcp_message(msg, ctx):
                # TCP has no message boundaries: keep a line's start until its end arrives.
                side = "C" if msg.from_client else "S"
                lines = (ctx.vars.get(side, "") + (msg.text or "")).split("\\n")
                for line in lines[:-1]:
                    log.info("%s: %s" % (side, line.rstrip("\\r")))
                ctx.vars[side] = lines[-1]

            def on_tcp_end(ctx):
                log.info("%s closed%s" % (ctx.server, "" if ctx.error == None else ": " + ctx.error))
            """;

    static final String DROP_COMMAND = """
            def on_tcp_message(msg, ctx):
                # Never let a POP3 client delete mail: answer DELE in the server's place.
                if msg.from_client and msg.text != None and msg.text.upper().startswith("DELE "):
                    ctx.send(False, "-ERR deleting is disabled here\\r\\n")
                    return False
            """;

    static final String TYPED = """
            def on_tcp_message(msg: TcpMessage, ctx: TcpContext) -> TcpMessage | str | bool | None:
                if msg.text == None:
                    return None
                text = cast(str, msg.text)
                if msg.from_client:
                    return msg.with_text(text.upper())
                ctx.vars["lines"] = ctx.vars.get("lines", 0) + text.count("\\n")
                return text + "!"
            """;

    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables) c.close();
    }

    private HttpProxyServer start(String source) throws Exception {
        ScriptedProxy script = ScriptedProxy.builder(source, "tcp.star").build();
        assertTrue(script.definesTcpHooks());
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).withTcpInterceptor(script.tcpInterceptor()).start();
        closeables.add(proxy::abort);
        return proxy;
    }

    /** A line server: a greeting, then {@code +OK <line>} per line until QUIT. */
    private TestSupport.RawServer lineServer(String greeting) {
        TestSupport.RawServer server = TestSupport.rawServer(s -> {
            OutputStream out = s.getOutputStream();
            out.write((greeting + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            String line;
            while ((line = in.readLine()) != null) {
                out.write(("+OK " + line + "\r\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
                if (line.equals("QUIT")) return;
            }
        });
        closeables.add(server);
        return server;
    }

    private static Socket tunnel(HttpProxyServer proxy, TestSupport.RawServer origin) throws IOException {
        Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort());
        s.setSoTimeout(20_000);
        TestSupport.write(s.getOutputStream(), "CONNECT 127.0.0.1:" + origin.port() + " HTTP/1.1\r\nHost: x\r\n\r\n");
        String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        return s;
    }

    private static String line(Socket s) throws IOException {
        return TestSupport.readUntil(s.getInputStream(), "\r\n");
    }

    private static void send(Socket s, String line) throws IOException {
        TestSupport.write(s.getOutputStream(), line + "\r\n");
    }

    @Test
    void bannerExample() throws Exception {
        TestSupport.RawServer origin = lineServer("220 mail.test ESMTP ready");
        HttpProxyServer proxy = start(inReadme(BANNER));
        try (Socket s = tunnel(proxy, origin)) {
            assertEquals("220 mail.test ESMTP (via MicroProxy) ready\r\n", line(s));
            send(s, "EHLO ESMTP");
            assertEquals("+OK EHLO ESMTP\r\n", line(s), "only the greeting");
        }
    }

    @Test
    void logLinesExample() throws Exception {
        List<String> logged = new CopyOnWriteArrayList<>();
        Logger logger = Logger.getLogger("microproxy.script");
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                String message = java.text.MessageFormat.format(record.getMessage(), record.getParameters());
                logged.add(message.substring(message.indexOf(": ") + 2));
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        java.util.logging.Level level = logger.getLevel();
        // (The tests' logging configuration shows warnings only.)
        logger.setLevel(java.util.logging.Level.INFO);
        logger.addHandler(handler);
        try {
            TestSupport.RawServer origin = lineServer("+OK POP3 ready");
            HttpProxyServer proxy = start(inReadme(LOG_LINES));
            String server = "127.0.0.1:" + origin.port();
            try (Socket s = tunnel(proxy, origin)) {
                assertEquals("+OK POP3 ready\r\n", line(s));
                // A line written in two pieces is logged once, whole.
                TestSupport.write(s.getOutputStream(), "US");
                Thread.sleep(50);
                TestSupport.write(s.getOutputStream(), "ER alice\r\n");
                assertEquals("+OK USER alice\r\n", line(s));
                send(s, "QUIT");
                assertEquals("+OK QUIT\r\n", line(s));
            }
            TestSupport.eventually("the tunnel's end is logged", () -> logged.contains(server + " closed"));
            assertEquals(List.of(server + " opened by 127.0.0.1 (tls False, sni None)", "S: +OK POP3 ready",
                    "C: USER alice", "S: +OK USER alice", "C: QUIT", "S: +OK QUIT", server + " closed"), logged);
        } finally {
            logger.removeHandler(handler);
            logger.setLevel(level);
        }
    }

    @Test
    void dropCommandExample() throws Exception {
        TestSupport.RawServer origin = lineServer("+OK POP3 ready");
        HttpProxyServer proxy = start(inReadme(DROP_COMMAND));
        try (Socket s = tunnel(proxy, origin)) {
            assertEquals("+OK POP3 ready\r\n", line(s));
            send(s, "DELE 1");
            assertEquals("-ERR deleting is disabled here\r\n", line(s));
            send(s, "RETR 1");
            assertEquals("+OK RETR 1\r\n", line(s), "the server never saw DELE");
        }
    }

    @Test
    void typedScriptsReplaceWithCopiesAndBytes() throws Exception {
        TestSupport.RawServer origin = lineServer("hi");
        HttpProxyServer proxy = start(inReadme(TYPED));
        try (Socket s = tunnel(proxy, origin)) {
            assertEquals("hi\r\n!", TestSupport.readUntil(s.getInputStream(), "!"));
            send(s, "quiet");
            assertEquals("+OK QUIET\r\n!", TestSupport.readUntil(s.getInputStream(), "!"));
        }
    }

    @Test
    void typedScriptsFailToLoadOnAMisspeltField() {
        ScriptException e = assertThrows(ScriptException.class, () -> ScriptedProxy.builder("""
                def on_tcp_message(msg: TcpMessage, ctx: TcpContext) -> None:
                    print(msg.payload, ctx.alpn)
                """, "typo.star").build());
        assertTrue(e.getMessage().contains("payload"), e.getMessage());
    }

    @Test
    void returnValuesAndContext() throws Exception {
        TestSupport.RawServer origin = lineServer("hello");
        HttpProxyServer proxy = start("""
                def on_tcp_start(ctx):
                    ctx.vars["n"] = 0
                    ctx.send(False, "proxy says hi\\r\\n")

                def on_tcp_message(msg, ctx):
                    ctx.vars["n"] += 1
                    if not msg.from_client:
                        return None
                    if msg.text.startswith("bytes"):
                        return b"as bytes\\r\\n"
                    if msg.text.startswith("true"):
                        msg.data = b"changed in place\\r\\n"
                        return True
                    if msg.text.startswith("fail"):
                        fail("broken")
                    if msg.text.startswith("count"):
                        return "count %d\\r\\n" % ctx.vars["n"]
                    return msg.text.replace("x", "y")
                """);
        try (Socket s = tunnel(proxy, origin)) {
            assertEquals("proxy says hi\r\n", line(s), "sent at the start");
            assertEquals("hello\r\n", line(s));
            send(s, "bytes");
            assertEquals("+OK as bytes\r\n", line(s));
            send(s, "true");
            assertEquals("+OK changed in place\r\n", line(s));
            send(s, "fail");
            assertEquals("+OK fail\r\n", line(s), "a failing hook passes the bytes on");
            send(s, "xx");
            assertEquals("+OK yy\r\n", line(s));
            send(s, "count");
            // hello, bytes, +OK, true, +OK, fail, +OK, xx, +OK, count: the tenth message.
            assertEquals("+OK count 10\r\n", line(s));
        }
    }

    @Test
    void scriptsWithoutTcpHooksDoNotAskForTheInterceptor() throws Exception {
        assertFalse(ScriptedProxy.builder("def on_request(req, ctx):\n    pass\n", "http.star").build().definesTcpHooks());
        assertTrue(ScriptedProxy.builder("def on_tcp_end(ctx):\n    pass\n", "end.star").build().definesTcpHooks());
    }
}
