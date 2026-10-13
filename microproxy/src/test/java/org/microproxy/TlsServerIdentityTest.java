package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * {@link HttpFilters#proxyToServerTlsIdentity}: the server name sent as SNI and the host the
 * certificate is verified against, apart from the address dialled. The test server listens on
 * 127.0.0.1 with a certificate for {@code example.test} only, and answers with the server name
 * its client sent. Requests choose their identity with an {@code X-Tls} field: {@code name}, or
 * {@code name,verification-host}, or {@code ,verification-host} for the verification host alone.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class TlsServerIdentityTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("TLS Identity Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("TLS Identity Proxy CA");

    private HttpsServer origin;
    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<ProxyFailure> failures = new CopyOnWriteArrayList<>();
    /** New server connections, by the server they went to. */
    private final List<String> connected = new CopyOnWriteArrayList<>();

    @BeforeEach
    void startOrigin() {
        origin = TestSupport.httpsOrigin(originCa.serverContext("example.test"), exchange -> {
            String sni = "none";
            if (((HttpsExchange) exchange).getSSLSession() instanceof ExtendedSSLSession session) {
                for (SNIServerName name : session.getRequestedServerNames()) {
                    if (name instanceof SNIHostName host) sni = host.getAsciiName();
                }
            }
            exchange.getRequestBody().readAllBytes();
            byte[] body = sni.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        origin.stop(0);
        for (AutoCloseable c : closeables) c.close();
    }

    /** The identity an {@code X-Tls} field names, or null without one. */
    static TlsServerIdentity identity(String field) {
        if (field == null) return null;
        int comma = field.indexOf(',');
        if (comma < 0) return TlsServerIdentity.of(field);
        String name = field.substring(0, comma);
        return TlsServerIdentity.of(name.isEmpty() ? null : name, field.substring(comma + 1));
    }

    /** A forward proxy whose filters take each request's identity from its {@code X-Tls} field. */
    private HttpProxyServerBootstrap forward() {
        return MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource((request, flow) -> new HttpFilters() {
                    @Override
                    public TlsServerIdentity proxyToServerTlsIdentity(String serverHostAndPort) {
                        return identity(request.headers().get("X-Tls"));
                    }
                })
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
                        connected.add(ctx.getServerHostAndPort());
                    }
                })
                .withFailureResponder((request, failure) -> {
                    failures.add(failure);
                    return null;
                });
    }

    private String url() {
        return "https://127.0.0.1:" + origin.getAddress().getPort() + "/";
    }

    private TlsOriginationTest.Http1.Response send(TlsOriginationTest.Http1 client, String tls) throws IOException {
        return tls == null ? client.send("GET", url(), null) : client.send("GET", url(), null, "X-Tls", tls);
    }

    private TlsOriginationTest.Http1.Response originate(String tls) throws IOException {
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            return send(client, tls);
        }
    }

    private ProxyFailure.TlsFailed lastTlsFailure() {
        return assertInstanceOf(ProxyFailure.TlsFailed.class, failures.getLast());
    }

    @Test
    void theServerNameIsSentAndVerifiedWhileTheIpAddressIsDialled() throws Exception {
        proxy = forward().start();
        TlsOriginationTest.Http1.Response r = originate("example.test");
        assertEquals(200, r.status(), r.toString());
        assertEquals("example.test", r.body());
        assertEquals(List.of(), failures);
    }

    @Test
    void withoutAnIdentityTheAddressIsVerifiedAndFails() throws Exception {
        proxy = forward().start();
        assertEquals(502, originate(null).status());
        assertEquals(ProxyFailure.TlsFailed.Reason.HOSTNAME_MISMATCH, lastTlsFailure().reason());
    }

    @Test
    void aWrongVerificationHostFailsThoughTheServerNameMatches() throws Exception {
        proxy = forward().start();
        // The certificate is valid for the SNI name, which the JDK's own check would accept:
        // the verification host alone counts.
        assertEquals(502, originate("example.test,wrong.test").status());
        ProxyFailure.TlsFailed failure = lastTlsFailure();
        assertEquals(ProxyFailure.TlsFailed.Reason.HOSTNAME_MISMATCH, failure.reason());
        assertInstanceOf(java.security.cert.CertificateException.class, failure.cause().getCause());
    }

    @Test
    void theVerificationHostAloneKeepsTheDefaultServerName() throws Exception {
        proxy = forward().start();
        // The request names an IP address, so no SNI is sent; the certificate is checked against
        // the verification host.
        TlsOriginationTest.Http1.Response r = originate(",example.test");
        assertEquals(200, r.status(), r.toString());
        assertEquals("none", r.body());
    }

    @Test
    void aServerNameWithAnotherVerificationHostThatTheCertificateCovers() throws Exception {
        HttpsServer both = TestSupport.httpsOrigin(originCa.serverContext("example.test", "lb.internal.test"),
                TestSupport.fixed(200, "both"));
        closeables.add(() -> both.stop(0));
        proxy = forward().start();
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            TlsOriginationTest.Http1.Response r = client.send("GET",
                    "https://127.0.0.1:" + both.getAddress().getPort() + "/", null, "X-Tls", "example.test,lb.internal.test");
            assertEquals(200, r.status(), r.toString());
        }
    }

    @Test
    void aClientsConnectionIsNeverReusedForAnotherIdentity() throws Exception {
        proxy = forward().start();
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            assertEquals(200, send(client, "example.test").status());
            assertEquals(200, send(client, "example.test").status());
            assertEquals(1, connected.size(), "the second request reused the connection: " + connected);
            // Another identity: the connection made for example.test would have served it.
            assertEquals(502, send(client, "example.test,wrong.test").status());
        }
        assertEquals(ProxyFailure.TlsFailed.Reason.HOSTNAME_MISMATCH, lastTlsFailure().reason());
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            assertEquals(200, send(client, "example.test").status());
            // Nor for the default identity.
            assertEquals(502, send(client, null).status());
        }
    }

    @Test
    void thePoolNeverHandsAConnectionToAnotherIdentity() throws Exception {
        proxy = forward().withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true)
                .withPoolPerRequestInMitm(true).start();
        assertEquals(200, originate("example.test").status());
        TestSupport.eventually("an idle pooled connection",
                () -> proxy.getServerConnectionPoolMetrics().idleConnections() == 1);
        assertEquals(502, originate("example.test,wrong.test").status());
        assertEquals(502, originate(null).status());
        // The idle connection is still there for its own identity.
        assertEquals(200, originate("example.test").status());
        assertEquals(1, connected.size(), "one connection, reused: " + connected);
    }

    @Test
    void anInterceptedConnectUsesTheIdentityForItsHandshake() throws Exception {
        // Filters that name the identity by the server, so the CONNECT's own (deferred) handshake
        // uses it too: it succeeds, though the certificate is not valid for 127.0.0.1, and the
        // session's request goes on the connection it made.
        String server = "127.0.0.1:" + origin.getAddress().getPort();
        List<String> asked = new CopyOnWriteArrayList<>();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(HttpFilters.builder().tlsIdentity(hostAndPort -> {
                    asked.add(hostAndPort);
                    return hostAndPort.equals(server) ? TlsServerIdentity.of("example.test") : null;
                }).build())
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
                        connected.add(ctx.getServerHostAndPort());
                    }
                })
                .start();
        HttpResponse<String> r = TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()), "https://" + server + "/");
        assertEquals(200, r.statusCode(), r.body());
        assertEquals("example.test", r.body());
        assertEquals(List.of(server), connected, "the CONNECT's connection served the session");
        assertEquals(server, asked.getFirst());
    }

    @Test
    void inAChainTheFirstIdentityWins() {
        HttpFiltersSource none = (request, flow) -> new HttpFilters() {};
        HttpFiltersSource a = HttpFilters.builder().tlsIdentity(h -> TlsServerIdentity.of("a.test")).build();
        HttpFiltersSource b = HttpFilters.builder().tlsIdentity(h -> TlsServerIdentity.of("b.test")).build();
        org.microproxy.http.HttpRequest request = new org.microproxy.http.DefaultHttpRequest(
                org.microproxy.http.HttpVersion.HTTP_1_1, org.microproxy.http.HttpMethod.GET, "https://x.test/");
        assertEquals(TlsServerIdentity.of("a.test"),
                HttpFiltersChain.of(none, a, b).filterRequest(request, null).proxyToServerTlsIdentity("x.test:443"));
        assertNull(HttpFiltersChain.of(none, none).filterRequest(request, null).proxyToServerTlsIdentity("x.test:443"));
    }

    @Test
    void identitiesAreValidated() {
        assertThrows(IllegalArgumentException.class, () -> TlsServerIdentity.of("127.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> TlsServerIdentity.of("::1"));
        assertThrows(IllegalArgumentException.class, () -> TlsServerIdentity.of(null, null));
        assertThrows(IllegalArgumentException.class, () -> TlsServerIdentity.of(" "));
        TlsServerIdentity id = TlsServerIdentity.of("Example.TEST.", "10.0.0.1");
        assertEquals("example.test", id.serverName());
        assertEquals("10.0.0.1", id.verificationHost());
        assertNull(TlsServerIdentity.of("a.test").verificationHost());
    }
}
