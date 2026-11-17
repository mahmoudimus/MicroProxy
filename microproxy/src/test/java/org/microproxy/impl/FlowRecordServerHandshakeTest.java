package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.ActivityTrackerAdapter;
import org.microproxy.FlowRecord;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.MitmServerHandshake;
import org.microproxy.TestSupport;
import org.microproxy.extras.AccessLogFormat;
import org.microproxy.tls.BrowserProfile;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SslContexts;

/**
 * {@link FlowRecord#serverHandshake()}: the server handshake mode an intercepted {@code CONNECT}
 * actually used, on the tunnel's record and on the records of the requests inside its session;
 * empty when the proxy did not intercept.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class FlowRecordServerHandshakeTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("Record Mode Origin CA");
    static final CertificateAuthority strangerCa = CertificateAuthority.generate("Record Mode Stranger CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Record Mode Proxy CA");

    private static final Optional<MitmServerHandshake> DEFERRED = Optional.of(MitmServerHandshake.DEFERRED);
    private static final Optional<MitmServerHandshake> EAGER = Optional.of(MitmServerHandshake.EAGER);

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<FlowRecord> records = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private static SSLContext profile() {
        return BrowserProfile.chrome156().sslContext(SslContexts.trustManagerOf(originCa.clientContext()));
    }

    /** The proxy, intercepting with {@code serverContext} unless it is null, every request's server {@code backend}. */
    private void start(HttpProxyServerBootstrap bootstrap, SSLContext serverContext, CertificateAuthority backend,
            HttpFilters filters) {
        HttpsServer server = TestSupport.httpsOrigin(backend.serverContext("localhost", "127.0.0.1"),
                TestSupport.fixed(200, "origin"));
        closeables.add(() -> server.stop(0));
        InetSocketAddress target = new InetSocketAddress(TestSupport.LOOPBACK, server.getAddress().getPort());
        HttpFiltersSource resolve = HttpFilters.builder().resolveWith(h -> target).build();
        if (serverContext != null) {
            bootstrap.withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, serverContext));
        }
        proxy = bootstrap.withPort(0)
                .withFiltersSource(filters == null ? resolve : HttpFiltersChain.of((r, c) -> filters, resolve))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void flowEnded(FlowRecord record) {
                        records.add(record);
                    }
                })
                .start();
    }

    private void start(HttpProxyServerBootstrap bootstrap, SSLContext serverContext, CertificateAuthority backend) {
        start(bootstrap, serverContext, backend, null);
    }

    /** A CONNECT and, when answered 200, a GET inside the intercepted session; the CONNECT's status. */
    private int connectAndGet() throws IOException {
        return connectAndGet(proxyCa.clientContext());
    }

    /** As {@link #connectAndGet()}, the client trusting {@code trust}'s certificates. */
    private int connectAndGet(SSLContext trust) throws IOException {
        try (Socket raw = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            raw.setSoTimeout(20_000);
            TestSupport.write(raw.getOutputStream(), "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n");
            InputStream in = raw.getInputStream();
            String head = TestSupport.readUntil(in, "\r\n\r\n");
            int status = Integer.parseInt(head.substring(9, 12));
            if (status != 200) return status;
            SSLSocket tls = (SSLSocket) trust.getSocketFactory().createSocket(raw, "localhost", 443, true);
            SSLParameters params = tls.getSSLParameters();
            params.setApplicationProtocols(new String[] {"http/1.1"});
            tls.setSSLParameters(params);
            tls.startHandshake();
            TestSupport.write(tls.getOutputStream(), "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            tls.getInputStream().readAllBytes();
            return status;
        }
    }

    private FlowRecord awaitRecord(FlowRecord.Kind kind) {
        TestSupport.eventually(kind + "'s record", () -> records.stream().anyMatch(r -> r.kind() == kind));
        return records.stream().filter(r -> r.kind() == kind).findFirst().orElseThrow();
    }

    /** The tunnel's record and the inner request's both say {@code mode}, and the access log shows it. */
    private void assertIntercepted(Optional<MitmServerHandshake> mode) {
        FlowRecord tunnel = awaitRecord(FlowRecord.Kind.TUNNEL);
        FlowRecord inner = awaitRecord(FlowRecord.Kind.HTTP1);
        assertEquals(mode, tunnel.serverHandshake(), tunnel.toString());
        assertEquals(mode, inner.serverHandshake(), inner.toString());
        AccessLogFormat format = AccessLogFormat.envoy("%MP_SERVER_HANDSHAKE%");
        assertEquals(mode.orElseThrow().name(), format.format(tunnel));
        assertEquals(mode.orElseThrow().name(), format.format(inner));
    }

    private static HttpProxyServerBootstrap littleProxy() {
        return MicroProxy.bootstrap().withLittleProxyCompatibility(true);
    }

    @Test
    void theDefaultsRecordDeferred() throws Exception {
        start(MicroProxy.bootstrap(), originCa.clientContext(), originCa);
        assertEquals(200, connectAndGet());
        assertIntercepted(DEFERRED);
    }

    @Test
    void littleProxysPresetWithAJdkContextRecordsEager() throws Exception {
        start(littleProxy(), originCa.clientContext(), originCa);
        assertEquals(200, connectAndGet());
        assertIntercepted(EAGER);
    }

    @Test
    void littleProxysPresetWithABrowserProfileRecordsDeferred() throws Exception {
        start(littleProxy(), profile(), originCa);
        assertEquals(200, connectAndGet());
        assertIntercepted(DEFERRED);
    }

    @Test
    void aFilterOverrideIsRecorded() throws Exception {
        start(littleProxy(), originCa.clientContext(), originCa, new HttpFilters() {
            @Override
            public MitmServerHandshake proxyToServerMitmHandshake() {
                return MitmServerHandshake.DEFERRED;
            }
        });
        assertEquals(200, connectAndGet());
        assertIntercepted(DEFERRED);
        proxy.abort();
        records.clear();
        start(MicroProxy.bootstrap(), profile(), originCa, new HttpFilters() {
            @Override
            public MitmServerHandshake proxyToServerMitmHandshake() {
                return MitmServerHandshake.EAGER;
            }
        });
        assertEquals(200, connectAndGet());
        assertIntercepted(EAGER);
    }

    @Test
    void aFailedHandshakeIsRecordedWithItsMode() throws Exception {
        // DEFERRED: TUNNEL 200 and the request inside answered 502; EAGER: TUNNEL 502.
        start(MicroProxy.bootstrap(), originCa.clientContext(), strangerCa);
        assertEquals(200, connectAndGet());
        FlowRecord inner = awaitRecord(FlowRecord.Kind.HTTP1);
        assertEquals(502, inner.responseCode());
        assertIntercepted(DEFERRED);
        proxy.abort();
        records.clear();
        start(littleProxy(), originCa.clientContext(), strangerCa);
        assertEquals(502, connectAndGet());
        FlowRecord tunnel = awaitRecord(FlowRecord.Kind.TUNNEL);
        assertEquals(502, tunnel.responseCode());
        assertEquals(EAGER, tunnel.serverHandshake());
    }

    @Test
    void aTunnelThatIsNotInterceptedRecordsNone() throws Exception {
        start(MicroProxy.bootstrap(), null, originCa);
        assertEquals(200, connectAndGet(originCa.clientContext()));
        FlowRecord tunnel = awaitRecord(FlowRecord.Kind.TUNNEL);
        assertEquals(Optional.empty(), tunnel.serverHandshake());
        assertEquals("-", AccessLogFormat.envoy("%MP_SERVER_HANDSHAKE%").format(tunnel));
    }

    @Test
    void aConnectAFilterKeepsFromInterceptionRecordsNone() throws Exception {
        start(littleProxy(), originCa.clientContext(), originCa, new HttpFilters() {
            @Override
            public boolean proxyToServerAllowMitm() {
                return false;
            }
        });
        assertEquals(200, connectAndGet(originCa.clientContext()));
        assertEquals(Optional.empty(), awaitRecord(FlowRecord.Kind.TUNNEL).serverHandshake());
    }

    @Test
    void aDeferredSessionDeclinedAtItsClientHelloRecordsNone() throws Exception {
        start(MicroProxy.bootstrap(), originCa.clientContext(), originCa, new HttpFilters() {
            @Override
            public boolean proxyToServerAllowMitm(org.microproxy.ClientHello hello) {
                return false;
            }
        });
        // Tunnelled to the origin, whose certificate the client does not trust: only the CONNECT matters.
        try (Socket raw = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            raw.setSoTimeout(20_000);
            TestSupport.write(raw.getOutputStream(), "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n");
            assertTrue(TestSupport.readUntil(raw.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
            SSLSocket tls = (SSLSocket) originCa.clientContext().getSocketFactory()
                    .createSocket(raw, "localhost", 443, true);
            tls.startHandshake();
            TestSupport.write(tls.getOutputStream(), "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            assertTrue(new String(tls.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1).endsWith("origin"));
        }
        assertEquals(Optional.empty(), awaitRecord(FlowRecord.Kind.TUNNEL).serverHandshake());
    }

    /** A plain HTTP server that answers what cannot start a request (a ClientHello) with 400, as nginx does. */
    private InetSocketAddress plainHttpServer() {
        TestSupport.RawServer server = TestSupport.rawServer(s -> {
            InputStream in = s.getInputStream();
            int first = in.read();
            if (first < 'A' || first > 'Z') {
                TestSupport.write(s.getOutputStream(),
                        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                return;
            }
            TestSupport.readUntil(in, "\r\n\r\n");
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\nplain");
        });
        closeables.add(server);
        return new InetSocketAddress(TestSupport.LOOPBACK, server.port());
    }

    /** A CONNECT to {@code target}, then plain HTTP in the tunnel; the response. */
    private String plainThroughConnect(InetSocketAddress target) throws IOException {
        String hostAndPort = "127.0.0.1:" + target.getPort();
        try (Socket raw = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            raw.setSoTimeout(20_000);
            TestSupport.write(raw.getOutputStream(), "CONNECT " + hostAndPort + " HTTP/1.1\r\nHost: " + hostAndPort
                    + "\r\n\r\n");
            assertTrue(TestSupport.readUntil(raw.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
            TestSupport.write(raw.getOutputStream(), "GET / HTTP/1.1\r\nHost: " + hostAndPort
                    + "\r\nConnection: close\r\n\r\n");
            return new String(raw.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }

    @Test
    void aServerThatDoesNotSpeakTlsRecordsNone() throws Exception {
        // EAGER: the handshake finds no TLS server before the CONNECT is answered, and tunnels.
        InetSocketAddress plain = plainHttpServer();
        proxy = littleProxy().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void flowEnded(FlowRecord record) {
                        records.add(record);
                    }
                })
                .start();
        assertTrue(plainThroughConnect(plain).endsWith("plain"));
        assertEquals(Optional.empty(), awaitRecord(FlowRecord.Kind.TUNNEL).serverHandshake());
        proxy.abort();
        records.clear();
        // DEFERRED: the client's plain HTTP is served as HTTP; no TLS with the server at all.
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void flowEnded(FlowRecord record) {
                        records.add(record);
                    }
                })
                .start();
        assertTrue(plainThroughConnect(plain).endsWith("plain"));
        assertEquals(Optional.empty(), awaitRecord(FlowRecord.Kind.TUNNEL).serverHandshake());
        assertEquals(Optional.empty(), awaitRecord(FlowRecord.Kind.HTTP1).serverHandshake());
    }

    @Test
    void aRecordBuiltWithoutAModeHasNone() {
        FlowRecord record = FlowRecord.builder(new org.microproxy.FlowContext(1, () -> null, () -> null,
                new org.microproxy.ClientDetails()), FlowRecord.Kind.TUNNEL).build();
        assertEquals(Optional.empty(), record.serverHandshake());
        assertEquals(EAGER, FlowRecord.builder(record.context(), FlowRecord.Kind.TUNNEL)
                .serverHandshake(MitmServerHandshake.EAGER).build().serverHandshake());
    }
}
