package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;
import static org.microproxy.TestSupport.eventually;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.dns.DnsMessage;
import org.microproxy.quic.MessageFramer;
import org.microproxy.quic.QuicFraming;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.quic.QuicMessage;
import org.microproxy.quic.QuicStreamContext;
import org.microproxy.quic.QuicStreamMessage;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * QUIC stream hooks that see whole messages: DNS over QUIC between Java peers through the
 * transparent QUIC listener, a hook logging queries and rewriting the answer for a blocked name;
 * each built-in framer with messages split across reads and joined in one; the size limit and a
 * framer that cannot read the bytes, which reset the stream; a custom framer; answering a side
 * from the hook; connections without a framer, whose streams still go through {@code
 * streamData}; the {@link FlowRecord} of a framed connection, whose bytes are counted as read; and
 * the stats of the messages, the message hook's calls and the streams reset for their framing.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class QuicMessageHooksTest {

    static final String HOST = "origin.test";
    static final String ECHO = "framed-echo";

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> seen = new CopyOnWriteArrayList<>();
    private final AtomicInteger chunks = new AtomicInteger();
    private HttpProxyServer proxy;
    private DoqOrigin origin;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("QUIC Messages Origin CA");
        proxyCa = CertificateAuthority.generate("QUIC Messages Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private void start(QuicInterceptor hooks, QuicFraming framing) throws Exception {
        start(hooks, framing, null);
    }

    /** Starts the proxy, with {@code tracker} when it is not null. */
    private void start(QuicInterceptor hooks, QuicFraming framing, ActivityTracker tracker) throws Exception {
        start(hooks, framing, tracker, false);
    }

    /** Starts the proxy, with {@code tracker} when it is not null, and with metrics or without. */
    private void start(QuicInterceptor hooks, QuicFraming framing, ActivityTracker tracker, boolean metrics)
            throws Exception {
        origin = new DoqOrigin(originCa, Map.of("allowed.test", "192.0.2.10", "blocked.test", "192.0.2.66"), "doq", ECHO);
        closeables.add(origin);
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(origin.port())
                .withTransparentQuicPort(0)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withQuicInterceptor(hooks)
                .withQuicFraming(framing)
                .withMetrics(metrics);
        if (tracker != null) bootstrap.plusActivityTracker(tracker);
        proxy = bootstrap.start();
    }

    private QuicConnection connect(String alpn) throws IOException {
        ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                        .alpnProtocols(alpn)
                        .serverName(HOST)
                        .trustManager(H3TestClient.trusting(proxyCa.getCertificate()))
                        .build())
                .build();
        QuicClient client = QuicClient.create(config);
        closeables.add(client);
        InetSocketAddress at = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getTransparentQuicAddress().getPort());
        return client.connect(at, HOST, Duration.ofSeconds(10));
    }

    /** Counts chunks, and records whole messages: their direction, stream and payload. */
    private abstract class Recording implements QuicInterceptor {
        @Override
        public byte[] streamData(QuicStreamMessage message, QuicStreamContext stream) {
            chunks.incrementAndGet();
            return message.data();
        }
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------------------------------------------
    // DNS over QUIC
    // ---------------------------------------------------------------------------------------

    /** Logs each query and answer, and answers blocked.test with 0.0.0.0, rewriting the server's answer. */
    private QuicInterceptor doqBlocker() {
        return new Recording() {
            @Override
            public List<QuicMessage> streamMessage(QuicMessage message, QuicStreamContext stream) {
                DnsMessage dns = message.dns();
                seen.add((message.fromClient() ? "query " : "answer ") + stream.streamId() + " "
                        + dns.questions().getFirst().name() + " " + dns.answers().size());
                if (message.fromClient() || !dns.questions().getFirst().name().equals("blocked.test")) {
                    return List.of(message);
                }
                List<DnsMessage.ResourceRecord> answers = new ArrayList<>();
                for (DnsMessage.ResourceRecord r : dns.answers()) {
                    answers.add(r.type() == DnsMessage.A ? r.withData(DnsMessage.Address.of("0.0.0.0")).withTtl(5) : r);
                }
                return List.of(message.withDns(dns.withAnswers(answers)));
            }
        };
    }

    @Test
    void dnsOverQuicIsLoggedAndRewritten() throws Exception {
        start(doqBlocker(), QuicFraming.defaults());
        QuicConnection c = connect("doq");
        assertEquals("doq", c.alpn());
        DnsMessage allowed = DoqOrigin.query(c, DnsMessage.query(0, "allowed.test", DnsMessage.A));
        assertEquals("192.0.2.10", allowed.answers().getFirst().data().text());
        assertEquals(300, allowed.answers().getFirst().ttl());
        DnsMessage blocked = DoqOrigin.query(c, DnsMessage.query(0, "blocked.test", DnsMessage.A));
        assertEquals("0.0.0.0", blocked.answers().getFirst().data().text());
        assertEquals(5, blocked.answers().getFirst().ttl());
        assertEquals(0, blocked.id());
        DnsMessage missing = DoqOrigin.query(c, DnsMessage.query(0, "missing.test", DnsMessage.A));
        assertEquals(3, missing.rcode());
        // Many streams at once.
        List<Thread> threads = new ArrayList<>();
        List<String> answers = new CopyOnWriteArrayList<>();
        for (int i = 0; i < 20; i++) {
            String name = i % 2 == 0 ? "allowed.test" : "blocked.test";
            threads.add(Thread.ofVirtual().start(() -> {
                try {
                    answers.add(name + " " + DoqOrigin.query(c, DnsMessage.query(0, name, DnsMessage.A)).answers()
                            .getFirst().data().text());
                } catch (IOException e) {
                    answers.add("failed " + e);
                }
            }));
        }
        for (Thread t : threads) t.join();
        assertEquals(10, answers.stream().filter(a -> a.equals("allowed.test 192.0.2.10")).count(), answers.toString());
        assertEquals(10, answers.stream().filter(a -> a.equals("blocked.test 0.0.0.0")).count(), answers.toString());
        assertTrue(seen.contains("query 0 allowed.test 0"), seen.toString());
        assertTrue(seen.contains("answer 0 allowed.test 1"), seen.toString());
        assertTrue(seen.contains("answer 4 blocked.test 1"), seen.toString());
        assertEquals(0, chunks.get(), "framing replaces the chunk hook");
        assertTrue(origin.events.contains("blocked.test A"), origin.events.toString());
    }

    @Test
    void aFramedSessionIsOneRecordWhenItEnds() throws Exception {
        RecordedFlows flows = new RecordedFlows();
        start(doqBlocker(), QuicFraming.defaults(), flows);
        QuicConnection c = connect("doq");
        DnsMessage query = DnsMessage.query(0, "blocked.test", DnsMessage.A);
        assertEquals("0.0.0.0", DoqOrigin.query(c, query).answers().getFirst().data().text());
        c.close(0, "");
        FlowRecord r = flows.await(FlowRecord.Kind.QUIC);
        assertEquals("quic_streams", r.responseCodeDetails());
        // Bytes are counted as they are read, before they make messages: the query with its length.
        int framed = 2 + query.encode().length;
        assertEquals(framed, r.bytesReceived(), r.toString());
        assertEquals(r.bytesReceived(), r.upstreamBytesSent());
        assertTrue(r.bytesSent() > framed, "the answer repeats the question: " + r);
        assertEquals(r.bytesSent(), r.upstreamBytesReceived());
        assertEquals(origin.port(), r.upstreamAddress().getPort());
        assertEquals(1, flows.records.size(), flows.records.toString());
    }

    @Test
    void withoutFramingDnsOverQuicGoesThroughStreamData() throws Exception {
        start(doqBlocker(), QuicFraming.defaults().withRule("doq", QuicFraming.NONE));
        QuicConnection c = connect("doq");
        DnsMessage blocked = DoqOrigin.query(c, DnsMessage.query(0, "blocked.test", DnsMessage.A));
        assertEquals("192.0.2.66", blocked.answers().getFirst().data().text(), "not rewritten");
        assertTrue(chunks.get() >= 2, "the chunk hook saw both directions");
        assertEquals(List.of(), seen);
    }

    @Test
    void anInterceptorWithoutAMessageHookIsNotFramed() throws Exception {
        start((message, stream) -> {
            chunks.incrementAndGet();
            return message.data();
        }, QuicFraming.defaults());
        QuicConnection c = connect("doq");
        assertEquals("192.0.2.66", DoqOrigin.query(c, DnsMessage.query(0, "blocked.test", DnsMessage.A)).answers()
                .getFirst().data().text());
        assertTrue(chunks.get() >= 2);
    }

    // ---------------------------------------------------------------------------------------
    // Framers
    // ---------------------------------------------------------------------------------------

    /** Upper-cases the client's messages and adds "!" to them; records both sides' payloads. */
    private QuicInterceptor shouting() {
        return new Recording() {
            @Override
            public List<QuicMessage> streamMessage(QuicMessage message, QuicStreamContext stream) {
                seen.add((message.fromClient() ? "c:" : "s:") + message.text());
                if (!message.fromClient()) return List.of(message);
                return List.of(message.withText(message.text().toUpperCase(Locale.ROOT) + "!"));
            }
        };
    }

    /** Writes the pieces with pauses between them, so that the proxy reads them apart. */
    private static void writeSlowly(OutputStream out, byte[] bytes, int... cuts) throws Exception {
        int at = 0;
        for (int cut : cuts) {
            out.write(bytes, at, cut - at);
            out.flush();
            Thread.sleep(60);
            at = cut;
        }
        out.write(bytes, at, bytes.length - at);
        out.flush();
    }

    /** Reads payloads framed by {@code framer} until the stream ends. */
    private static List<String> readMessages(InputStream in, MessageFramer framer) throws IOException {
        byte[] all = in.readAllBytes();
        List<String> out = new ArrayList<>();
        int at = 0;
        while (at < all.length) {
            int n = (int) framer.frameLength(all, at, all.length - at);
            if (n < 0 || at + n > all.length) throw new IOException("a partial message at " + at);
            out.add(new String(framer.payload(java.util.Arrays.copyOfRange(all, at, at + n)), StandardCharsets.UTF_8));
            at += n;
        }
        return out;
    }

    @ParameterizedTest
    @ValueSource(strings = {"u16", "u32", "varint", "lf", "crlf"})
    void framersCutSplitAndJoinedMessages(String name) throws Exception {
        MessageFramer framer = MessageFramer.named(name);
        start(shouting(), QuicFraming.defaults().withRule(ECHO, name));
        QuicConnection c = connect(ECHO);
        QuicStream s = c.openBidirectionalStream();
        OutputStream out = s.getOutputStream();
        byte[] first = framer.frame(utf8("hello"));
        // The first message cut inside its prefix (or before its delimiter), then two more in one write.
        writeSlowly(out, first, 1, first.length - 1);
        ByteArrayOutputStream joined = new ByteArrayOutputStream();
        joined.writeBytes(framer.frame(utf8("second")));
        joined.writeBytes(framer.frame(utf8("x".repeat(500))));
        byte[] third = framer.frame(utf8("last"));
        joined.write(third, 0, 2);
        writeSlowly(out, joined.toByteArray());
        writeSlowly(out, java.util.Arrays.copyOfRange(third, 2, third.length));
        out.close();
        assertEquals(List.of("HELLO!", "SECOND!", "X".repeat(500) + "!", "LAST!"), readMessages(s.getInputStream(), framer),
                "each payload framed again, its prefix computed for the new length");
        assertEquals(List.of("c:hello", "c:second", "c:" + "x".repeat(500), "c:last"),
                seen.stream().filter(m -> m.startsWith("c:")).toList());
        eventually("the echoed messages", () -> seen.stream().filter(m -> m.startsWith("s:")).count() == 4);
        assertEquals(0, chunks.get());
    }

    @Test
    void aMessageTooLargeResetsTheStream() throws Exception {
        start(shouting(), QuicFraming.defaults().withRule(ECHO, "u16").withMaxMessageSize(64).withErrorCode(0x55));
        QuicConnection c = connect(ECHO);
        // Within the limit, a stream goes through; the next one is too large.
        QuicStream ok = c.openBidirectionalStream();
        try (OutputStream out = ok.getOutputStream()) {
            out.write(MessageFramer.u16().frame(utf8("fine")));
        }
        assertEquals(List.of("FINE!"), readMessages(ok.getInputStream(), MessageFramer.u16()));
        QuicStream big = c.openBidirectionalStream();
        OutputStream out = big.getOutputStream();
        out.write(MessageFramer.u16().frame(new byte[100]));
        out.flush();
        QuicStreamException e = assertThrows(QuicStreamException.class, () -> big.getInputStream().readAllBytes());
        assertEquals(QuicStreamException.Kind.RESET, e.kind());
        assertEquals(0x55, e.errorCode());
        assertEquals(0x55, big.awaitStopped(), "the client is asked to stop sending, with the same code");
        eventually("the server's side reset",
                () -> origin.events.contains("reset 85") || origin.events.contains("stopped 85"));
        assertTrue(seen.stream().noneMatch(m -> m.length() > 60), "the hook never saw it");
        // The connection goes on.
        QuicStream after = c.openBidirectionalStream();
        try (OutputStream o = after.getOutputStream()) {
            o.write(MessageFramer.u16().frame(utf8("again")));
        }
        assertEquals(List.of("AGAIN!"), readMessages(after.getInputStream(), MessageFramer.u16()));
    }

    @Test
    void aLineTooLongResetsTheStream() throws Exception {
        start(shouting(), QuicFraming.defaults().withRule(ECHO, "lf").withMaxMessageSize(32));
        QuicConnection c = connect(ECHO);
        QuicStream s = c.openBidirectionalStream();
        OutputStream out = s.getOutputStream();
        out.write(utf8("short\n" + "y".repeat(40)));
        out.flush();
        QuicStreamException e = assertThrows(QuicStreamException.class, () -> s.getInputStream().readAllBytes());
        assertEquals(QuicFraming.DEFAULT_ERROR_CODE, e.errorCode());
        assertTrue(seen.contains("c:short"), seen.toString());
    }

    @Test
    void customFramersAndMalformedBytes() throws Exception {
        // Messages of the form M<length byte><payload>, given to the hook whole; anything else is malformed.
        MessageFramer m = (data, offset, length) -> {
            if (data[offset] != 'M') throw new IllegalArgumentException("no M");
            return length < 2 ? MessageFramer.NEED_MORE : 2 + (data[offset + 1] & 0xff);
        };
        start(new Recording() {
            @Override
            public List<QuicMessage> streamMessage(QuicMessage message, QuicStreamContext stream) {
                seen.add(message.text());
                byte[] d = message.data().clone();
                d[2] = (byte) Character.toUpperCase(d[2]);
                return List.of(message.withData(d));
            }
        }, QuicFraming.none().withRule(ECHO, m));
        QuicConnection c = connect(ECHO);
        QuicStream s = c.openBidirectionalStream();
        try (OutputStream out = s.getOutputStream()) {
            out.write(new byte[] {'M', 2, 'h', 'i', 'M', 1, 'z'});
        }
        assertEquals("M\u0002HiM\u0001Z", new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8),
                "sent as the hook returned them, uppercased again on the way back");
        QuicStream bad = c.openBidirectionalStream();
        OutputStream out = bad.getOutputStream();
        out.write(new byte[] {'M', 1, 'a', 'X'});
        out.flush();
        QuicStreamException e = assertThrows(QuicStreamException.class, () -> bad.getInputStream().readAllBytes());
        assertEquals(2, e.errorCode());
        assertTrue(seen.contains("M\u0001a"), "the message before the malformed bytes went through: " + seen);
    }

    @Test
    void hooksDropAndAnswerMessages() throws Exception {
        start(new Recording() {
            @Override
            public List<QuicMessage> streamMessage(QuicMessage message, QuicStreamContext stream) {
                if (!message.fromClient()) return List.of(message);
                return switch (message.text()) {
                    case "drop" -> null;
                    case "ask" -> List.of(message.withText("answered by the proxy").withFromClient(false));
                    case "twice" -> List.of(message, message.withText("again"));
                    default -> List.of(message);
                };
            }
        }, QuicFraming.defaults().withRule(ECHO, "lf"));
        QuicConnection c = connect(ECHO);
        QuicStream s = c.openBidirectionalStream();
        try (OutputStream out = s.getOutputStream()) {
            out.write(utf8("one\ndrop\nask\ntwice\nlast\nunfinished"));
        }
        List<String> lines = new ArrayList<>(List.of(new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                .split("\n", -1)));
        assertTrue(lines.remove("answered by the proxy"), lines.toString());
        assertEquals(List.of("one", "twice", "again", "last", "unfinished"), lines,
                "dropped, answered, doubled, and the bytes left at the end passed on as they were");
    }

    /**
     * {@code quic.messages_rx} and {@code messages_tx}, the message hook's calls, drops, rewrites
     * and errors under {@code hooks.quic_message}, and a stream reset for a message over the limit
     * under {@code quic.framing_errors}.
     */
    @Test
    void messagesTheHookAndFramingErrorsAreCounted() throws Exception {
        start(new Recording() {
            @Override
            public List<QuicMessage> streamMessage(QuicMessage message, QuicStreamContext stream) {
                if (!message.fromClient()) return List.of(message);
                return switch (message.text()) {
                    case "drop" -> null;
                    case "twice" -> List.of(message, message.withText("again"));
                    case "boom" -> throw new IllegalStateException("a hook that fails");
                    default -> List.of(message);
                };
            }
        }, QuicFraming.defaults().withRule(ECHO, "lf").withMaxMessageSize(32), null, true);
        StatsRegistry r = proxy.getStats();
        QuicConnection c = connect(ECHO);
        QuicStream s = c.openBidirectionalStream();
        try (OutputStream out = s.getOutputStream()) {
            out.write(utf8("one\ndrop\ntwice\nboom\n"));
        }
        assertEquals("one\ntwice\nagain\nboom\n", new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8),
                "dropped, doubled, and passed on when the hook threw");
        // Four messages from the client, and the four the server echoed
        assertEquals(8, value(r, "quic.messages_rx"));
        assertEquals(8, value(r, "quic.messages_tx"));
        assertEquals(8, value(r, "hooks.quic_message.invocations"));
        assertEquals(1, value(r, "hooks.quic_message.drops"));
        assertEquals(1, value(r, "hooks.quic_message.rewrites"));
        assertEquals(1, value(r, "hooks.quic_message.errors"));
        assertEquals(0, value(r, "hooks.quic_stream.invocations"), "framed streams do not go through streamData");
        assertEquals(0, value(r, "quic.framing_errors"));

        QuicStream big = c.openBidirectionalStream();
        OutputStream out = big.getOutputStream();
        out.write(utf8("y".repeat(40)));
        out.flush();
        assertThrows(QuicStreamException.class, () -> big.getInputStream().readAllBytes());
        awaitValue(r, "quic.framing_errors", 1);
        assertEquals(8, value(r, "quic.messages_rx"), "the hook never saw it");
    }
}
