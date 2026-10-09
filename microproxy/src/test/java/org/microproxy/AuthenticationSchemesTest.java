package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Authentication beyond Basic: Bearer tokens with custom challenges, per-request checks, and the
 * user reaching filters and the chained proxy manager.
 */
class AuthenticationSchemesTest {

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final AtomicInteger calls = new AtomicInteger();
    /** "<method> <user>" for each request the filters saw. */
    private final List<String> filtered = new CopyOnWriteArrayList<>();
    /** The user the chained proxy manager was asked about, per route lookup. */
    private final List<String> routed = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    /**
     * Accepts {@code Bearer token-<user>} and Basic {@code basic:pw}; answers {@code Bearer revoked}
     * with 403 and anything else with a Bearer challenge.
     */
    private class Tokens implements ProxyAuthenticator {
        @Override
        public boolean authenticate(String userName, String password) {
            return "basic".equals(userName) && "pw".equals(password);
        }

        @Override
        public AuthResult authenticate(HttpRequest request, FlowContext flow) {
            calls.incrementAndGet();
            String value = request.headers().get(HttpHeaderNames.PROXY_AUTHORIZATION);
            if (value == null || !value.startsWith("Bearer ")) {
                AuthResult basic = ProxyAuthenticator.super.authenticate(request, flow);
                return basic instanceof AuthResult.Accepted ? basic : challenge("missing_token");
            }
            String token = value.substring("Bearer ".length());
            if (token.equals("revoked")) {
                return AuthResult.reject(new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                        HttpResponseStatus.FORBIDDEN, "token revoked\n"));
            }
            if (token.equals("anonymous")) {
                return AuthResult.accept(null);
            }
            return token.startsWith("token-") ? AuthResult.accept(token.substring(6)) : challenge("invalid_token");
        }

        private static AuthResult challenge(String error) {
            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                    HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED, "{\"error\":\"" + error + "\"}");
            response.headers().set(HttpHeaderNames.PROXY_AUTHENTICATE, "Bearer realm=\"api\", error=\"" + error + "\"");
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
            return AuthResult.reject(response);
        }
    }

    private HttpProxyServerBootstrap bootstrap(ProxyAuthenticator authenticator) {
        return MicroProxy.bootstrap().withPort(0).withProxyAuthenticator(authenticator)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest request, FlowContext ctx) {
                        filtered.add(request.method() + " " + ctx.getClientDetails().getUserName());
                        return null;
                    }
                })
                .withChainProxyManager((request, chainedProxies, clientDetails) -> {
                    routed.add(clientDetails.getUserName());
                    chainedProxies.add(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
                });
    }

    /** GETs {@code path} from the origin on {@code s}, with the given extra header lines. */
    private RawProxyClient.Response get(Socket s, String path, String... headerLines) throws IOException {
        StringBuilder request = new StringBuilder("GET ").append(TestSupport.url(origin, path))
                .append(" HTTP/1.1\r\nHost: 127.0.0.1\r\n");
        for (String line : headerLines) request.append(line).append("\r\n");
        return RawProxyClient.exchange(s, request.append("\r\n").toString());
    }

    @Test
    void bearerTokensGetCustomChallengesAndTheUserReachesFiltersAndRouting() throws Exception {
        proxy = bootstrap(new Tokens()).start();
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            RawProxyClient.Response missing = get(s, "/missing");
            assertEquals(407, missing.status());
            assertEquals("Bearer realm=\"api\", error=\"missing_token\"", missing.header("Proxy-Authenticate"));
            assertEquals("application/json", missing.header("Content-Type"));
            assertEquals("{\"error\":\"missing_token\"}", missing.body());

            RawProxyClient.Response invalid = get(s, "/invalid", "Proxy-Authorization: Bearer nonsense");
            assertEquals(407, invalid.status());
            assertEquals("Bearer realm=\"api\", error=\"invalid_token\"", invalid.header("Proxy-Authenticate"));

            RawProxyClient.Response ok = get(s, "/ok", "Proxy-Authorization: Bearer token-alice");
            assertEquals(200, ok.status());
            assertTrue(echoedHeader(ok.body(), "proxy-authorization").isEmpty(), "the token is not forwarded");
            // Authenticated once per connection by default: the next request is not checked again.
            RawProxyClient.Response again = get(s, "/again", "Proxy-Authorization: Bearer token-alice");
            assertEquals(200, again.status());
            assertTrue(echoedHeader(again.body(), "proxy-authorization").isEmpty());
        }
        assertEquals(3, calls.get());
        assertEquals(List.of("GET alice", "GET alice"), filtered);
        assertEquals(List.of("alice"), routed, "the second request reuses the server connection");
    }

    @Test
    void aRejectionCanBeForbiddenAndAcceptanceAnonymous() throws Exception {
        proxy = bootstrap(new Tokens()).start();
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            RawProxyClient.Response revoked = get(s, "/revoked", "Proxy-Authorization: Bearer revoked");
            assertEquals(403, revoked.status());
            assertEquals("token revoked\n", revoked.body());
            assertNull(revoked.header("Proxy-Authenticate"));
            assertEquals(200, get(s, "/anonymous", "Proxy-Authorization: Bearer anonymous").status());
        }
        assertEquals(List.of("GET null"), filtered);
    }

    @Test
    void basicStillWorksThroughTheDefaultMethod() throws Exception {
        proxy = bootstrap(new Tokens()).start();
        String basic = Base64.getEncoder().encodeToString("basic:pw".getBytes(StandardCharsets.UTF_8));
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            RawProxyClient.Response r = get(s, "/basic", "Proxy-Authorization: Basic " + basic);
            assertEquals(200, r.status());
            assertTrue(echoedHeader(r.body(), "proxy-authorization").isEmpty());
        }
        assertEquals(List.of("GET basic"), filtered);
    }

    @Test
    void everyRequestIsCheckedWhenTheAuthenticatorAsks() throws Exception {
        proxy = bootstrap(new Tokens() {
            @Override
            public boolean authenticateEveryRequest() {
                return true;
            }
        }).start();
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            assertEquals(200, get(s, "/1", "Proxy-Authorization: Bearer token-alice").status());
            RawProxyClient.Response expired = get(s, "/2", "Proxy-Authorization: Bearer nonsense");
            assertEquals(407, expired.status());
            assertEquals("Bearer realm=\"api\", error=\"invalid_token\"", expired.header("Proxy-Authenticate"));
            assertEquals(407, get(s, "/3").status());
            assertEquals(200, get(s, "/4", "Proxy-Authorization: Bearer token-bob").status());
        }
        assertEquals(4, calls.get());
        assertEquals(List.of("GET alice", "GET bob"), filtered);
        assertEquals(List.of("alice", "bob"), routed, "bob does not reuse the connection routed for alice");
    }

    @Test
    void credentialsAreNotForwardedEvenByATransparentProxy() throws Exception {
        proxy = bootstrap(new Tokens()).withTransparent(true).start();
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            for (int i = 0; i < 2; i++) {
                RawProxyClient.Response r = get(s, "/t" + i, "Proxy-Authorization: Bearer token-alice");
                assertEquals(200, r.status());
                assertTrue(echoedHeader(r.body(), "proxy-authorization").isEmpty(), "request " + i);
            }
        }
    }

    @Test
    void connectIsAuthenticatedWithTheCustomScheme() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Bearer Tunnel CA");
        HttpsServer secure = TestSupport.httpsOrigin(ca.serverContext("127.0.0.1"), echo());
        String target = "127.0.0.1:" + secure.getAddress().getPort();
        proxy = bootstrap(new Tokens()).start();
        try {
            try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
                RawProxyClient.Response r = RawProxyClient.connect(s, target);
                assertEquals(407, r.status());
                assertEquals("Bearer realm=\"api\", error=\"missing_token\"", r.header("Proxy-Authenticate"));
                assertEquals("{\"error\":\"missing_token\"}", r.body());
                // The same connection can answer the challenge.
                assertEquals(200, RawProxyClient.connect(s, target, "Proxy-Authorization: Bearer token-alice").status());
                SSLSocket tls = RawProxyClient.tls(s, ca.clientContext(), "127.0.0.1", secure.getAddress().getPort());
                assertEquals(200, RawProxyClient.exchange(tls, "GET /x HTTP/1.1\r\nHost: " + target + "\r\n\r\n").status());
            }
            assertEquals(List.of("CONNECT alice"), filtered);
            assertEquals(List.of("alice"), routed);
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void interceptedRequestsAreCoveredByTheirConnect() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Bearer Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Bearer Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), echo());
        String target = "127.0.0.1:" + secure.getAddress().getPort();
        List<String> serverUsers = new CopyOnWriteArrayList<>();
        proxy = bootstrap(new Tokens() {
            @Override
            public boolean authenticateEveryRequest() {
                return true;
            }
        }).withManInTheMiddle(MitmManager.perConnection(flow -> {
            serverUsers.add(flow.getClientDetails().getUserName());
            return new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext());
        })).start();
        try {
            try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
                assertEquals(200, RawProxyClient.connect(s, target, "Proxy-Authorization: Bearer token-alice").status());
                SSLSocket tls = RawProxyClient.tls(s, proxyCa.clientContext(), "127.0.0.1", secure.getAddress().getPort());
                // Inside the session requests carry no proxy credentials and are not challenged; a
                // stray Proxy-Authorization is not forwarded either.
                RawProxyClient.Response plain = RawProxyClient.exchange(tls,
                        "GET /one HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
                assertEquals(200, plain.status());
                RawProxyClient.Response stray = RawProxyClient.exchange(tls,
                        "GET /two HTTP/1.1\r\nHost: " + target + "\r\nProxy-Authorization: Bearer token-bob\r\n\r\n");
                assertEquals(200, stray.status());
                assertTrue(echoedHeader(stray.body(), "proxy-authorization").isEmpty());
            }
            assertEquals(1, calls.get());
            assertEquals(List.of("CONNECT alice", "GET alice", "GET alice"), filtered);
            assertEquals(List.of("alice"), serverUsers, "the MITM manager was chosen knowing the user");
        } finally {
            secure.stop(0);
        }
    }
}
