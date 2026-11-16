package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.LogRecord;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import io.github.mahmoudimus.quic.tls.FingerprintSslContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.MitmServerHandshake;
import org.microproxy.ProtocolPolicy;
import org.microproxy.TestSupport;
import org.microproxy.tls.BrowserProfile;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SslContexts;

/**
 * A MITM manager whose server context is a browser profile's ({@link BrowserProfile#sslContext})
 * makes the server handshake {@link MitmServerHandshake#DEFERRED}, so that it can mirror the
 * client's ClientHello, unless EAGER was asked for explicitly: by the user's policy or a request's
 * filters, never by {@link ProtocolPolicy#littleProxy()}'s preset.
 *
 * <p>Which mode ran is told by a server whose certificate the proxy does not trust: EAGER answers
 * the {@code CONNECT} itself with {@code 502}; DEFERRED answers it {@code 200} and the request
 * inside the session {@code 502}.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class BrowserProfileHandshakeModeTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("Profile Mode Origin CA");
    static final CertificateAuthority strangerCa = CertificateAuthority.generate("Profile Mode Stranger CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Profile Mode Proxy CA");

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private static SSLContext profile() {
        return BrowserProfile.chrome156().sslContext(SslContexts.trustManagerOf(originCa.clientContext()));
    }

    /** The intercepting proxy, every request's server {@code backend}, its server context {@code serverContext}. */
    private void start(HttpProxyServerBootstrap bootstrap, SSLContext serverContext, CertificateAuthority backend,
            HttpFilters filters) {
        HttpsServer server = TestSupport.httpsOrigin(backend.serverContext("localhost", "127.0.0.1"),
                TestSupport.fixed(200, "origin"));
        closeables.add(() -> server.stop(0));
        InetSocketAddress target = new InetSocketAddress(TestSupport.LOOPBACK, server.getAddress().getPort());
        HttpFiltersSource resolve = HttpFilters.builder().resolveWith(h -> target).build();
        proxy = bootstrap.withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, serverContext))
                .withFiltersSource(filters == null ? resolve : HttpFiltersChain.of((r, c) -> filters, resolve))
                .start();
    }

    private void start(HttpProxyServerBootstrap bootstrap, SSLContext serverContext, CertificateAuthority backend) {
        start(bootstrap, serverContext, backend, null);
    }

    /** A CONNECT's status, and, when it was 200, the response to a GET inside the session. */
    private record Outcome(int connectStatus, String inside) {}

    private Outcome connectAndGet() throws IOException {
        try (Socket raw = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            raw.setSoTimeout(20_000);
            TestSupport.write(raw.getOutputStream(), "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n");
            InputStream in = raw.getInputStream();
            String head = TestSupport.readUntil(in, "\r\n\r\n");
            int status = Integer.parseInt(head.substring(9, 12));
            if (status != 200) return new Outcome(status, null);
            SSLSocket tls = (SSLSocket) proxyCa.clientContext().getSocketFactory()
                    .createSocket(raw, "localhost", 443, true);
            SSLParameters params = tls.getSSLParameters();
            params.setApplicationProtocols(new String[] {"http/1.1"});
            tls.setSSLParameters(params);
            tls.startHandshake();
            TestSupport.write(tls.getOutputStream(), "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            return new Outcome(status, new String(tls.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1));
        }
    }

    private void assertDeferred() throws IOException {
        Outcome outcome = connectAndGet();
        assertEquals(200, outcome.connectStatus(), "the CONNECT was answered before the server's handshake");
        assertTrue(outcome.inside().startsWith("HTTP/1.1 502"), outcome.inside());
    }

    private void assertEager() throws IOException {
        assertEquals(502, connectAndGet().connectStatus(), "the server's handshake failed before the CONNECT's answer");
    }

    private static HttpProxyServerBootstrap littleProxy() {
        return MicroProxy.bootstrap().withLittleProxyCompatibility(true);
    }

    @Test
    void theContextOfABrowserProfileIsAFingerprintContext() throws Exception {
        assertTrue(FingerprintSslContext.isFingerprint(profile()));
        assertFalse(FingerprintSslContext.isFingerprint(originCa.clientContext()));
        assertFalse(FingerprintSslContext.isFingerprint(SSLContext.getDefault()));
        assertFalse(FingerprintSslContext.isFingerprint(null));
    }

    @Test
    void littleProxysPresetWithABrowserProfileDefers() throws Exception {
        start(littleProxy(), profile(), strangerCa);
        assertDeferred();
    }

    @Test
    void littleProxysPresetWithABrowserProfileReachesATrustedServer() throws Exception {
        start(littleProxy(), profile(), originCa);
        Outcome outcome = connectAndGet();
        assertEquals(200, outcome.connectStatus());
        assertTrue(outcome.inside().startsWith("HTTP/1.1 200") && outcome.inside().endsWith("origin"),
                outcome.inside());
    }

    @Test
    void littleProxysPresetAppliedByHandWithABrowserProfileDefers() throws Exception {
        start(MicroProxy.bootstrap().onHttp1(p -> p.preset(ProtocolPolicy.littleProxy())), profile(), strangerCa);
        assertDeferred();
    }

    @Test
    void littleProxysPresetWithAJdkContextStaysEager() throws Exception {
        start(littleProxy(), originCa.clientContext(), strangerCa);
        assertEager();
    }

    @Test
    void theDefaultsDeferWithEitherContext() throws Exception {
        start(MicroProxy.bootstrap(), originCa.clientContext(), strangerCa);
        assertDeferred();
        proxy.abort();
        start(MicroProxy.bootstrap(), profile(), strangerCa);
        assertDeferred();
    }

    @Test
    void anExplicitEagerPolicyWinsOverABrowserProfileWithOneWarning() throws Exception {
        TlsDiagnosticsTest.Captured log = new TlsDiagnosticsTest.Captured(ClientConnection.class.getName());
        try {
            start(littleProxy().onHttp1(p -> p.mitmServerHandshake(MitmServerHandshake.EAGER)), profile(), strangerCa);
            for (int i = 0; i < 3; i++) assertEager();
            List<LogRecord> warnings = log.records.stream()
                    .filter(r -> r.getLevel() == java.util.logging.Level.WARNING
                            && r.getMessage().contains("browser profile"))
                    .toList();
            assertEquals(1, warnings.size(), warnings.stream().map(LogRecord::getMessage).toList().toString());
        } finally {
            log.close();
        }
    }

    @Test
    void anExplicitEagerForAllProtocolsWinsOverABrowserProfile() throws Exception {
        start(MicroProxy.bootstrap().onAllProtocols(p -> p.mitmServerHandshake(MitmServerHandshake.EAGER)), profile(),
                strangerCa);
        assertEager();
    }

    @Test
    void anEagerPolicyWithAJdkContextLogsNoWarning() throws Exception {
        TlsDiagnosticsTest.Captured log = new TlsDiagnosticsTest.Captured(ClientConnection.class.getName());
        try {
            start(MicroProxy.bootstrap().onHttp1(p -> p.mitmServerHandshake(MitmServerHandshake.EAGER)),
                    originCa.clientContext(), strangerCa);
            assertEager();
            assertTrue(log.records.stream().noneMatch(r -> r.getMessage().contains("browser profile")),
                    log.records.stream().map(LogRecord::getMessage).toList().toString());
        } finally {
            log.close();
        }
    }

    @Test
    void aFilterChoosingEagerWinsOverABrowserProfile() throws Exception {
        start(littleProxy(), profile(), strangerCa, new HttpFilters() {
            @Override
            public MitmServerHandshake proxyToServerMitmHandshake() {
                return MitmServerHandshake.EAGER;
            }
        });
        assertEager();
    }

    @Test
    void presetAndExplicitValuesAreToldApart() {
        assertFalse(ProtocolPolicy.littleProxy().mitmServerHandshakeExplicit());
        assertFalse(ProtocolPolicy.defaults().mitmServerHandshakeExplicit());
        assertFalse(ProtocolPolicy.empty().mitmServerHandshakeExplicit());
        assertFalse(ProtocolPolicy.builder().preset(ProtocolPolicy.littleProxy()).build().mitmServerHandshakeExplicit());
        assertFalse(ProtocolPolicy.builder().set("preset", "littleproxy").build().mitmServerHandshakeExplicit());
        assertTrue(ProtocolPolicy.builder().mitmServerHandshake(MitmServerHandshake.EAGER).build()
                .mitmServerHandshakeExplicit());
        assertTrue(ProtocolPolicy.builder().set("mitm_server_handshake", "eager").build().mitmServerHandshakeExplicit());
        // A setter after the preset makes it explicit, even with the preset's own value.
        ProtocolPolicy reset = ProtocolPolicy.builder().preset(ProtocolPolicy.littleProxy())
                .mitmServerHandshake(MitmServerHandshake.EAGER).build();
        assertTrue(reset.mitmServerHandshakeExplicit());
        assertTrue(!reset.equals(ProtocolPolicy.builder().preset(ProtocolPolicy.littleProxy()).build()));
        // Merging keeps where the value came from.
        assertFalse(ProtocolPolicy.empty().orElse(ProtocolPolicy.littleProxy()).mitmServerHandshakeExplicit());
        assertTrue(reset.orElse(ProtocolPolicy.defaults()).mitmServerHandshakeExplicit());
        assertTrue(ProtocolPolicy.builder().preset(reset).build().mitmServerHandshakeExplicit(),
                "a user-built policy used as a preset carries its explicit value");
        assertFalse(BootstrapView.protocolPolicy(littleProxy(), 1).mitmServerHandshakeExplicit());
        assertTrue(BootstrapView.protocolPolicy(littleProxy()
                .onAllProtocols(p -> p.mitmServerHandshake(MitmServerHandshake.EAGER)), 1).mitmServerHandshakeExplicit());
    }
}
