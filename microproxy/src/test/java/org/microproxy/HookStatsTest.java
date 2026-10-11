package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http2.ErrorCode;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.frames.Http2Frame;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tcp.TcpContext;
import org.microproxy.tcp.TcpInterceptor;
import org.microproxy.tcp.TcpMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The hooks' stats, {@code hooks.<family>.*}: the TCP hooks' and the frame interceptor's calls,
 * errors, drops and rewrites, and how long they took; and that nothing is counted without
 * metrics.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class HookStatsTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("Hook Stats Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Hook Stats Proxy CA");

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private HttpsServer origin;

    @AfterEach
    void tearDown() {
        proxies.close();
        if (origin != null) origin.stop(0);
    }

    /** Drops {@code drop}, rewrites {@code secret}, throws on {@code boom}, and passes the rest on. */
    private static final TcpInterceptor EDITING = new TcpInterceptor() {
        @Override
        public byte[] tcpMessage(TcpMessage message, TcpContext context) {
            String text = message.text();
            if (text.startsWith("drop")) return null;
            if (text.startsWith("boom")) throw new IllegalStateException("a broken hook");
            if (text.contains("secret")) return text.replace("secret", "public").getBytes(StandardCharsets.UTF_8);
            return message.data();
        }
    };

    @Test
    void tcpHooksAreCounted() throws Exception {
        try (TestSupport.RawServer echo = TcpInterceptorTest.lineEcho()) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withMetrics(true).withTcpInterceptor(EDITING));
            StatsRegistry r = proxy.getStats();
            try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
                assertEquals(200, ChainTestSupport.status(ChainTestSupport.connect(s, "127.0.0.1:" + echo.port())));
                TcpInterceptorTest.send(s, "hello secret");
                assertEquals("echo: hello public", TcpInterceptorTest.line(s));
                // A hook that throws passes the bytes on
                TcpInterceptorTest.send(s, "boom");
                assertEquals("echo: boom", TcpInterceptorTest.line(s));
                TcpInterceptorTest.send(s, "drop this");
                awaitValue(r, "hooks.tcp.drops", 1);
                s.shutdownOutput();
                s.getInputStream().readAllBytes();
            }
            awaitValue(r, "tunnel.active", 0);
            assertEquals(1, value(r, "tunnel.h1_connect.total"));
            // The client's three messages and the server's two answers
            assertEquals(5, value(r, "hooks.tcp.invocations"));
            assertEquals(5, value(r, "hooks.tcp.latency_us"));
            assertEquals(1, value(r, "hooks.tcp.drops"));
            assertEquals(1, value(r, "hooks.tcp.errors"));
            assertEquals(1, value(r, "hooks.tcp.rewrites"));
            Histogram.Snapshot latency = ((Histogram) r.get("hooks.tcp.latency_us")).snapshot();
            assertEquals(Histogram.microsecondBounds().length, latency.bounds().length, "microsecond buckets");
        }
    }

    @Test
    void theFrameInterceptorIsCounted() throws Exception {
        origin = HttpsServer.create(new InetSocketAddress(TestSupport.LOOPBACK, 0), 10);
        origin.setHttpsConfigurator(new HttpsConfigurator(originCa.serverContext("127.0.0.1")));
        origin.createContext("/", TestSupport.echo());
        origin.setExecutor(Executors.newCachedThreadPool());
        origin.start();
        // PINGs from the client are dropped; everything else goes on as it is.
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withMetrics(true)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp2(true)
                .withFrameInterceptor((frame, direction, ctx) -> frame instanceof Http2Frame.Ping p && !p.ack() ? null : frame));
        StatsRegistry r = proxy.getStats();
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        try (H2TestClient h2 = H2TestClient.connect(proxy.getListenAddress(), target, proxyCa.clientContext()).handshake()) {
            h2.ping(42);
            h2.get(1, "/x");
            assertEquals(200, h2.response(1).status());
            h2.rst(1, ErrorCode.NO_ERROR);
        }
        assertTrue(value(r, "hooks.frame_interceptor.invocations") >= 4, "SETTINGS, PING, HEADERS, the response");
        assertEquals(value(r, "hooks.frame_interceptor.invocations"), value(r, "hooks.frame_interceptor.latency_us"));
        assertEquals(1, value(r, "hooks.frame_interceptor.drops"));
        assertEquals(0, value(r, "hooks.frame_interceptor.rewrites"));
        assertEquals(0, value(r, "hooks.frame_interceptor.errors"));
    }

    @Test
    void nothingIsCountedWithoutMetrics() throws Exception {
        try (TestSupport.RawServer echo = TcpInterceptorTest.lineEcho()) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTcpInterceptor(EDITING));
            try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
                assertEquals(200, ChainTestSupport.status(ChainTestSupport.connect(s, "127.0.0.1:" + echo.port())));
                TcpInterceptorTest.send(s, "hello secret");
                assertEquals("echo: hello public", TcpInterceptorTest.line(s));
            }
            assertEquals(0, proxy.getStats().size());
        }
    }
}
