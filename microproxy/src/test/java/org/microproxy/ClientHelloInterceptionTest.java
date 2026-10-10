package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TlsHellos.issuer;
import static org.microproxy.TlsHellos.throughConnect;

import com.sun.net.httpserver.HttpsServer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Deciding on interception once the client's ClientHello is known: the host rules (mitmproxy's
 * {@code ignore_hosts} / {@code allow_hosts}), the filter and MITM manager hooks, and what the
 * proxy does with clients that do not send a ClientHello at all.
 */
class ClientHelloInterceptionTest {

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;
    private static String proxyIssuer;
    private static String originIssuer;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private HttpsServer origin;
    private String target;

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("ClientHello Proxy CA");
        originCa = CertificateAuthority.generate("ClientHello Origin CA");
        proxyIssuer = proxyCa.getCertificate().getSubjectX500Principal().getName();
        originIssuer = originCa.getCertificate().getSubjectX500Principal().getName();
    }

    @BeforeEach
    void startOrigin() {
        origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        target = "127.0.0.1:" + origin.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        proxies.close();
        origin.stop(0);
    }

    private HttpProxyServerBootstrap mitm() {
        return MicroProxy.bootstrap().withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()));
    }

    /** A context that trusts both the proxy's and the origin's CA, to see who answered. */
    private static SSLContext trustBoth() throws Exception {
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("proxy", proxyCa.getCertificate());
        ks.setCertificateEntry("origin", originCa.getCertificate());
        javax.net.ssl.TrustManagerFactory tmf =
                javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        return context;
    }

    /** CONNECTs with {@code sni}, and returns who issued the certificate the client saw, plus the answer. */
    private String[] visit(HttpProxyServer proxy, String sni, String... alpn) throws Exception {
        try (SSLSocket tls = throughConnect(proxy, target, sni, trustBoth(), alpn)) {
            String who = issuer(tls);
            String response = TlsHellos.get(tls, "localhost:" + origin.getAddress().getPort(), "/hello");
            return new String[] {who, response};
        }
    }

    @Test
    void withoutRulesEveryHostIsIntercepted() throws Exception {
        HttpProxyServer proxy = proxies.start(mitm());
        String[] seen = visit(proxy, "localhost");
        assertEquals(proxyIssuer, seen[0]);
        assertTrue(seen[1].startsWith("HTTP/1.1 200"), seen[1]);
        assertTrue(seen[1].contains("h:via: 1.1 "), "proxied: " + seen[1]);
    }

    @Test
    void anIgnoredSniIsTunnelledSoTheClientSeesTheRealCertificate() throws Exception {
        HttpProxyServer proxy = proxies.start(mitm().withIgnoreHosts("^localhost:"));
        String[] ignored = visit(proxy, "localhost");
        assertEquals(originIssuer, ignored[0], "the origin's own certificate");
        assertTrue(ignored[1].startsWith("HTTP/1.1 200"), ignored[1]);
        assertTrue(!ignored[1].contains("h:via:"), "untouched: " + ignored[1]);
        // Without SNI only the CONNECT target is matched, which the rule does not name.
        assertEquals(proxyIssuer, visit(proxy, null)[0]);
    }

    @Test
    void anIgnoredConnectTargetIsTunnelledWithoutWaitingForTheClient() throws Exception {
        List<ClientHello> asked = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(mitm().withIgnoreHosts("127\\.0\\.0\\.1")
                .withFiltersSource((request, ctx) -> HttpFilters.builder().allowMitmFor(h -> asked.add(h)).build()));
        assertEquals(originIssuer, visit(proxy, "localhost")[0]);
        assertEquals(List.of(), asked, "decided at the CONNECT, before any ClientHello");
    }

    @Test
    void onlyAllowedHostsAreIntercepted() throws Exception {
        HttpProxyServer proxy = proxies.start(mitm().withAllowHosts("^localhost:\\d+$"));
        assertEquals(proxyIssuer, visit(proxy, "localhost")[0], "the SNI is allowed");
        assertEquals(originIssuer, visit(proxy, null)[0], "no SNI, and the CONNECT target is not allowed");
        // Ignore rules still apply to allowed hosts.
        HttpProxyServer both = proxies.start(mitm().withAllowHosts("localhost").withIgnoreHosts("LOCALHOST"));
        assertEquals(originIssuer, visit(both, "localhost")[0], "patterns ignore case");
    }

    @Test
    void filtersDecideByTheClientHelloAndSeeItLater() throws Exception {
        List<ClientHello> asked = new CopyOnWriteArrayList<>();
        List<ClientHello> inSession = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(mitm().withFiltersSource((request, ctx) -> {
            if (!request.method().name().equals("CONNECT")) {
                inSession.add(ctx.getClientHello());
                return null;
            }
            return HttpFilters.builder().allowMitmFor(hello -> {
                asked.add(hello);
                return !"localhost".equals(hello.sni());
            }).build();
        }));
        assertEquals(originIssuer, visit(proxy, "localhost", "http/1.1")[0], "declined: tunnelled");
        assertEquals(1, asked.size());
        assertEquals("localhost", asked.getFirst().sni());
        assertEquals(List.of("http/1.1"), asked.getFirst().alpnProtocols());
        assertEquals(List.of(), inSession, "a tunnel has no requests the proxy sees");

        assertEquals(proxyIssuer, visit(proxy, null, "http/1.1")[0], "allowed: intercepted");
        assertEquals(2, asked.size());
        assertNull(asked.get(1).sni());
        // Requests inside the session see the ClientHello it started with.
        assertEquals(1, inSession.size());
        assertNotNull(inSession.getFirst());
        assertArrayEquals(asked.get(1).raw(), inSession.getFirst().raw());
    }

    @Test
    void theMitmManagerDecidesByTheClientHello() throws Exception {
        List<String> asked = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withManInTheMiddle(
                new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()) {
                    @Override
                    public boolean shouldIntercept(ClientHello clientHello, FlowContext flow) {
                        asked.add(clientHello.sni() + " " + (flow.getClientHello() == clientHello));
                        return clientHello.sni() == null;
                    }
                }));
        assertEquals(originIssuer, visit(proxy, "localhost")[0]);
        assertEquals(proxyIssuer, visit(proxy, null)[0]);
        assertEquals(List.of("localhost true", "null true"), asked);
    }

    @Test
    void theConnectTimeHookStillDecidesFirst() throws Exception {
        List<String> calls = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(mitm().withFiltersSource((request, ctx) -> HttpFilters.builder()
                .allowMitm(() -> {
                    calls.add("allowMitm");
                    return false;
                })
                .allowMitmFor(h -> calls.add("allowMitmFor")).build()));
        assertEquals(originIssuer, visit(proxy, "localhost")[0]);
        assertEquals(List.of("allowMitm"), calls);
    }

    @Test
    void aClientOfferingOnlyOtherProtocolsIsTunnelled() throws Exception {
        HttpProxyServer proxy = proxies.start(mitm());
        try (SSLSocket tls = throughConnect(proxy, target, "localhost", trustBoth(), "imap", "acme-tls/1")) {
            assertEquals(originIssuer, issuer(tls), "the proxy cannot speak those: not intercepted");
        }
        // GREASE alongside an HTTP protocol does not stop interception.
        String grease = new String(new byte[] {0x0a, 0x0a}, StandardCharsets.ISO_8859_1);
        assertEquals(proxyIssuer, visit(proxy, "localhost", grease, "http/1.1")[0]);
    }

    @Test
    void otherProtocolsAreTunnelledWithTheBytesAlreadyRead() throws Exception {
        try (TestSupport.RawServer echo = TestSupport.rawServer(ClientHelloInterceptionTest::echoBytes)) {
            HttpProxyServer proxy = proxies.start(mitm());
            for (byte[] first : List.of(new byte[] {0, 1, 2, 3, 'x'},
                    // A TLS handshake record, but holding a ServerHello rather than a ClientHello.
                    new byte[] {0x16, 0x03, 0x01, 0x00, 0x04, 2, 0, 0, 0},
                    // An alert record.
                    new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 2, 40},
                    "SSH-2.0-client\r\n".getBytes(StandardCharsets.US_ASCII),
                    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII))) {
                try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
                    assertEquals(200, ChainTestSupport.status(ChainTestSupport.connect(s, "127.0.0.1:" + echo.port())));
                    s.getOutputStream().write(first);
                    s.getOutputStream().flush();
                    assertArrayEquals(first, s.getInputStream().readNBytes(first.length), new String(first, StandardCharsets.ISO_8859_1));
                }
            }
        }
    }

    @Test
    void aServerThatSpeaksFirstIsNotKeptWaiting() throws Exception {
        try (TestSupport.RawServer banner = TestSupport.rawServer(s -> {
            OutputStream out = s.getOutputStream();
            out.write("220 smtp.test ESMTP\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            echoBytes(s);
        })) {
            HttpProxyServer proxy = proxies.start(mitm());
            try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
                assertEquals(200, ChainTestSupport.status(ChainTestSupport.connect(s, "127.0.0.1:" + banner.port())));
                // The client says nothing until the server has: the proxy relays the banner.
                assertEquals("220 smtp.test ESMTP\r\n", TestSupport.readUntil(s.getInputStream(), "\r\n"));
                TestSupport.write(s.getOutputStream(), "EHLO me\r\n");
                assertEquals("EHLO me\r\n", TestSupport.readUntil(s.getInputStream(), "\r\n"));
            }
        }
    }

    @Test
    void aHelloSplitIntoManyRecordsAndWritesIsIntercepted() throws Exception {
        // A raw ClientHello replayed in one-byte records, each written on its own: the proxy reads
        // all of them before deciding, and replays them into its handshake.
        HttpProxyServer proxy = proxies.start(mitm().withIgnoreHosts("^ignored\\.test:"));
        byte[] records = TlsHellos.records(TlsHellos.message(TlsHellos.fromJdkClient("ignored.test", "http/1.1")), 1);
        try (TestSupport.RawServer echo = TestSupport.rawServer(ClientHelloInterceptionTest::echoBytes)) {
            try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
                assertEquals(200, ChainTestSupport.status(ChainTestSupport.connect(s, "127.0.0.1:" + echo.port())));
                OutputStream out = s.getOutputStream();
                for (byte b : records) {
                    out.write(b);
                    out.flush();
                }
                // Ignored by its SNI: tunnelled, so the "server" echoes the very same records.
                assertArrayEquals(records, s.getInputStream().readNBytes(records.length));
            }
        }
    }

    /** Echoes every byte back until the peer closes. */
    static void echoBytes(Socket s) throws Exception {
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
            out.flush();
        }
    }
}
