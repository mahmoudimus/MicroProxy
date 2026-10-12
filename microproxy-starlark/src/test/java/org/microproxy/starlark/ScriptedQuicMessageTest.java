package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.starlark.ScriptedReadmeTest.inReadme;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.DoqOrigin;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.dns.DnsMessage;
import org.microproxy.quic.MessageFramer;
import org.microproxy.quic.QuicFraming;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * {@code on_quic_message} and the {@code dns} module: the README's DNS over QUIC script, which
 * logs queries and rewrites the address of a blocked name, between Java DoQ peers through the
 * transparent QUIC listener; a typed script that drops, adds and answers messages; a framer of the
 * script's own ({@code quic_message_length}); and the module on its own.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ScriptedQuicMessageTest {

    static final String HOST = "origin.test";
    static final String ECHO = "framed-echo";

    static final String DOQ = """
            BLOCKED = ["ads.example", "tracker.example"]

            def on_quic_message(msg, ctx):
                # DNS over QUIC (ALPN doq): one DNS message each way on each stream.
                if ctx.alpn != "doq":
                    return None
                m = dns.decode(msg.data)
                q = m["questions"][0]
                if msg.from_client:
                    log.info("%s asks for %s %s" % (ctx.client_ip, q["name"], q["type"]))
                elif q["name"].lower() in BLOCKED:
                    for answer in m["answers"]:
                        if answer["type"] == "A":
                            answer["data"] = "0.0.0.0"
                            answer["ttl"] = 60
                    msg.data = dns.encode(m)
            """;

    static final String FRAMER = """
            def quic_message_length(data):
                # Each message: a byte with the length of what follows, then that many bytes.
                return 1 + data[0]

            def on_quic_message(msg, ctx):
                # The message as quic_message_length cut it, its length byte included.
                if msg.from_client and msg.text != None:
                    return msg.text.upper()
            """;

    static final String TYPED = """
            def on_quic_message(msg: QuicMessage, ctx: QuicContext) -> list[QuicMessage] | QuicMessage | str | bool | None:
                if not msg.from_client:
                    return None
                text = cast(str, msg.text)
                if text == "drop":
                    return False
                if text == "ping":
                    return msg.with_text("pong").with_from_client(False)
                if text == "twice":
                    ctx.vars["twice"] = ctx.stream_id
                    return [msg, msg.with_text("again")]
                if text == "raw":
                    return "replaced"
                msg.text = text + "@" + str(msg.stream_id)
                return None
            """;

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();
    private final List<String> logged = new CopyOnWriteArrayList<>();
    private final Handler handler = new Handler() {
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
    /** Held for the test: a logger that nothing references may be collected, with the handler on it. */
    private final Logger scriptLog = Logger.getLogger("microproxy.script");
    private java.util.logging.Level level;
    private DoqOrigin origin;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("Scripted QUIC Messages Origin CA");
        proxyCa = CertificateAuthority.generate("Scripted QUIC Messages Proxy CA");
    }

    @BeforeEach
    void logging() {
        level = scriptLog.getLevel();
        scriptLog.setLevel(java.util.logging.Level.INFO);
        scriptLog.addHandler(handler);
    }

    @AfterEach
    void tearDown() throws Exception {
        scriptLog.removeHandler(handler);
        scriptLog.setLevel(level);
        for (AutoCloseable c : closeables) c.close();
    }

    /** A transparent proxy whose QUIC goes through {@code source}'s hooks, framed by {@code rules}, and a client. */
    private QuicConnection connect(String source, String rules, String alpn) throws Exception {
        origin = new DoqOrigin(originCa, Map.of("www.example", "192.0.2.10", "ads.example", "192.0.2.66"), "doq", ECHO);
        closeables.add(origin);
        ScriptedProxy script = ScriptedProxy.builder(source, "messages.star").build();
        assertTrue(script.definesQuicHooks());
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(origin.port())
                .withTransparentQuicPort(0)
                .withServerResolver((host, port) -> {
                    if (host.endsWith(".test")) return new InetSocketAddress(TestSupport.LOOPBACK, port);
                    throw new UnknownHostException(host);
                })
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withQuicInterceptor(script.quicInterceptor());
        QuicFraming framing = bootstrap.getQuicFraming().withRules(rules);
        if (script.definesQuicFramer()) framing = framing.withFramer("script", script.quicFramer());
        HttpProxyServer proxy = bootstrap.withQuicFraming(framing).start();
        closeables.add(proxy::abort);
        QuicClient client = QuicClient.create(ClientConfig.builder(TlsConfig.builder()
                        .alpnProtocols(alpn)
                        .serverName(HOST)
                        .trustAllCertificates(true)
                        .build())
                .build());
        closeables.add(client);
        return client.connect(new InetSocketAddress(TestSupport.LOOPBACK, proxy.getTransparentQuicAddress().getPort()),
                HOST, Duration.ofSeconds(10));
    }

    @Test
    void readmeDnsOverQuicExample() throws Exception {
        QuicConnection c = connect(inReadme(DOQ), "", "doq");
        DnsMessage www = DoqOrigin.query(c, DnsMessage.query(0, "www.example", DnsMessage.A));
        assertEquals("192.0.2.10", www.answers().getFirst().data().text());
        assertEquals(300, www.answers().getFirst().ttl());
        DnsMessage ads = DoqOrigin.query(c, DnsMessage.query(0, "Ads.Example", DnsMessage.A));
        assertEquals("0.0.0.0", ads.answers().getFirst().data().text());
        assertEquals(60, ads.answers().getFirst().ttl());
        assertEquals("Ads.Example", ads.questions().getFirst().name());
        assertTrue(logged.contains("127.0.0.1 asks for www.example A"), logged.toString());
        assertTrue(logged.contains("127.0.0.1 asks for Ads.Example A"), logged.toString());
    }

    @Test
    void typedScriptDropsAddsAndAnswers() throws Exception {
        QuicConnection c = connect(TYPED, ECHO + "=lf", ECHO);
        QuicStream s = c.openBidirectionalStream();
        try (OutputStream out = s.getOutputStream()) {
            out.write("hello\ndrop\nping\ntwice\nraw\n".getBytes(StandardCharsets.UTF_8));
        }
        List<String> lines = new ArrayList<>(Arrays.asList(
                new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8).split("\n")));
        assertTrue(lines.remove("pong"), lines.toString());
        assertEquals(List.of("hello@0", "twice", "again", "replaced"), lines);
    }

    @Test
    void aFramerOfTheScriptsOwn() throws Exception {
        QuicConnection c = connect(inReadme(FRAMER), ECHO + "=script", ECHO);
        QuicStream s = c.openBidirectionalStream();
        OutputStream out = s.getOutputStream();
        out.write(new byte[] {3, 'a', 'b'});
        out.flush();
        Thread.sleep(50);
        out.write(new byte[] {'c', 1, 'z', 0});
        out.close();
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.writeBytes(new byte[] {3, 'A', 'B', 'C', 1, 'Z', 0});
        assertEquals(Arrays.toString(expected.toByteArray()), Arrays.toString(s.getInputStream().readAllBytes()));
    }

    @Test
    void scriptFramerErrorsResetTheStream() throws Exception {
        QuicConnection c = connect("""
                def quic_message_length(data):
                    if data[0] == 0:
                        fail("not a message")
                    return None if len(data) < 2 else 2

                def on_quic_message(msg, ctx):
                    return None
                """, ECHO + "=script", ECHO);
        QuicStream s = c.openBidirectionalStream();
        OutputStream out = s.getOutputStream();
        out.write(new byte[] {1, 2, 0, 9});
        out.flush();
        QuicStreamException e = assertThrows(QuicStreamException.class, () -> s.getInputStream().readAllBytes());
        assertEquals(QuicFraming.DEFAULT_ERROR_CODE, e.errorCode());
    }

    @Test
    void withoutTheMessageHookStreamsGoThroughStreamData() throws Exception {
        ScriptedProxy script = ScriptedProxy.builder("def on_quic_stream_data(msg, ctx):\n    return None\n", "s.star")
                .build();
        assertFalse(script.definesQuicFramer());
        assertEquals(List.of(), Arrays.stream(script.quicInterceptor().getClass().getDeclaredMethods())
                .filter(m -> m.getName().equals("streamMessage")).toList(), "not framed");
    }

    // ---------------------------------------------------------------------------------------
    // The dns module on its own
    // ---------------------------------------------------------------------------------------

    private static void check(String... lines) throws Exception {
        StringBuilder src = new StringBuilder("def checks():\n");
        for (String line : lines) src.append("    ").append(line).append('\n');
        StarlarkScript.compile(src.toString(), "dns.star", StarlarkScript.Limits.DEFAULT).call("checks", Mutability.create("t"));
    }

    @Test
    void dnsModule() throws Exception {
        byte[] response = DnsMessage.query(0x1234, "example.com", DnsMessage.A).reply(List.of(
                DnsMessage.ResourceRecord.of("example.com", DnsMessage.A, 300, DnsMessage.Address.of("192.0.2.1")),
                DnsMessage.ResourceRecord.of("example.com", DnsMessage.MX, 300, new DnsMessage.Mx(10, "mx.example.com")),
                DnsMessage.ResourceRecord.of("example.com", DnsMessage.TXT, 300, new DnsMessage.Txt(List.of("v=1"))),
                new DnsMessage.ResourceRecord("example.com", 99, DnsMessage.IN, 1, new byte[] {7})))
                .encode();
        StringBuilder literal = new StringBuilder("b'");
        for (byte b : response) literal.append(String.format("\\x%02x", b & 0xff));
        literal.append("'");
        check("m = dns.decode(" + literal + ")",
                "if m['id'] != 0x1234 or not m['response'] or m['rcode'] != 0 or not m['recursion_desired']: fail(m)",
                "if m['questions'] != [{'name': 'example.com', 'type': 'A', 'class': 1}]: fail(m['questions'])",
                "a = m['answers']",
                "if a[0] != {'name': 'example.com', 'type': 'A', 'class': 1, 'ttl': 300, 'data': '192.0.2.1'}: fail(a[0])",
                "if a[1]['data'] != {'preference': 10, 'exchange': 'mx.example.com'}: fail(a[1])",
                "if a[2]['data'] != ['v=1']: fail(a[2])",
                "if a[3]['type'] != 'TYPE99' or a[3]['data'] != b'\\x07': fail(a[3])",
                "if dns.encode(m) != " + literal + ": fail('round trip')",
                "a[0]['data'] = '0.0.0.0'",
                "m['rcode'] = 3",
                "back = dns.decode(dns.encode(m))",
                "if back['answers'][0]['data'] != '0.0.0.0' or back['rcode'] != 3: fail(back)",
                "q = dns.encode({'id': 7, 'recursion_desired': True, 'questions': [{'name': 'x.test', 'type': 'AAAA'}]})",
                "d = dns.decode(q)",
                "if d['id'] != 7 or d['response'] or d['questions'][0]['type'] != 'AAAA': fail(d)",
                "if not dns.render(q).startswith(';; query, opcode: QUERY, status: NOERROR, id: 7'): fail(dns.render(q))",
                "r = dns.encode({'response': True, 'answers': [{'name': 'x.test', 'type': 28, 'data': '2001:db8::1'},"
                        + " {'name': 'x.test', 'type': 'SOA', 'data': {'mname': 'ns.test', 'rname': 'h.test', 'serial': 1}}]})",
                "if dns.decode(r)['answers'][0]['data'] != '2001:db8::1': fail(dns.decode(r))",
                "if dns.decode(r)['answers'][1]['data']['serial'] != 1: fail(dns.decode(r))");
        for (String bad : List.of("dns.decode(b'\\x00')", "dns.encode([])",
                "dns.encode({'answers': [{'name': 'x', 'type': 'A', 'data': 'not-an-ip'}]})",
                "dns.encode({'answers': [{'name': 'x', 'type': 'A'}]})",
                "dns.encode({'questions': [{'name': 'x', 'type': 'NOPE'}]})")) {
            Exception e = assertThrows(Exception.class, () -> check(bad));
            assertTrue(e.getMessage().contains("dns."), e.getMessage());
        }
    }
}
