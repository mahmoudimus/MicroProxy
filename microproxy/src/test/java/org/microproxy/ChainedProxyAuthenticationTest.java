package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.authenticated;
import static org.microproxy.ChainTestSupport.connect;
import static org.microproxy.ChainTestSupport.http;
import static org.microproxy.ChainTestSupport.open;
import static org.microproxy.ChainTestSupport.status;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;

/**
 * Client authentication combined with chaining: who the client is reaches the {@link
 * ChainedProxyManager}, client credentials stay with the proxy that checked them, and an
 * upstream's 407 is relayed.
 *
 * <p>LittleProxy: AuthenticatingProxyWithChainingTest, impl/RealChainedProxyAuthenticationTest.
 */
class ChainedProxyAuthenticationTest {

    private static CertificateAuthority originCa;
    private static HttpServer origin;
    private static HttpsServer secureOrigin;

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    /** "user:password" pairs the upstream's authenticator was asked about. */
    private final List<String> upstreamAuthAttempts = new CopyOnWriteArrayList<>();
    /** Proxy-Authorization values (or "none") of requests reaching the upstream. */
    private final List<String> upstreamProxyAuthorization = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void startOrigins() {
        originCa = CertificateAuthority.generate("Auth Chain Origin CA");
        origin = TestSupport.origin(echo());
        secureOrigin = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), echo());
    }

    @AfterAll
    static void stopOrigins() {
        origin.stop(0);
        secureOrigin.stop(0);
    }

    @AfterEach
    void tearDown() {
        proxies.close();
    }

    private static String basic(String user, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    private static ProxyAuthenticator only(String user, String password, List<String> attempts) {
        return (u, p) -> {
            if (attempts != null) attempts.add(u + ":" + p);
            return u.equals(user) && p.equals(password);
        };
    }

    /** An upstream proxy, optionally requiring credentials, that records what reaches it. */
    private HttpProxyServer upstream(boolean requireAuth) {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().withProxyAlias("upstream")
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void requestReceivedFromClient(FlowContext ctx, org.microproxy.http.HttpRequest request) {
                        String value = request.headers().get("Proxy-Authorization");
                        upstreamProxyAuthorization.add(value == null ? "none" : value);
                    }
                });
        if (requireAuth) b.withProxyAuthenticator(only("upstreamUser", "upstreamPass", upstreamAuthAttempts));
        return proxies.start(b);
    }

    private HttpResponse<String> get(HttpProxyServer proxy, String url, String proxyAuthorization) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url));
        if (proxyAuthorization != null) b.header("Proxy-Authorization", proxyAuthorization);
        return send(client(proxy), b.build());
    }

    /** CONNECT with credentials on a raw socket; returns the status. */
    private static int connectWith(HttpProxyServer proxy, String target, String proxyAuthorization) throws Exception {
        try (Socket s = open(proxy.getListenAddress())) {
            TestSupport.write(s.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target
                    + "\r\nProxy-Authorization: " + proxyAuthorization + "\r\n\r\n");
            return status(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n"));
        }
    }

    private static String secureTarget() {
        return "127.0.0.1:" + secureOrigin.getAddress().getPort();
    }

    @Test
    void authenticatedUserReachesTheChainedProxyManager() throws Exception {
        List<ClientDetails> seen = new CopyOnWriteArrayList<>();
        List<String> users = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                .withProxyAuthenticator(only("user1", "user2", null))
                .withChainProxyManager((request, queue, details) -> {
                    seen.add(details);
                    users.add(request.method() + " " + details.getUserName());
                    queue.add(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
                }));
        assertEquals(407, get(proxy, url(origin, "/"), null).statusCode());
        assertEquals(List.of(), users, "unauthenticated requests never reach the chained proxy manager");

        assertEquals(200, get(proxy, url(origin, "/"), basic("user1", "user2")).statusCode());
        assertEquals(200, connectWith(proxy, secureTarget(), basic("user1", "user2")));
        assertEquals(List.of("GET user1", "CONNECT user1"), users);
        for (ClientDetails details : seen) {
            assertTrue(details.getClientAddress().getAddress().isLoopbackAddress());
        }
    }

    @Test
    void clientCredentialsAreNotForwardedToAnUpstreamWithoutCredentials() {
        HttpProxyServer up = upstream(false);
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                .withProxyAuthenticator(only("clientUser", "clientPass", null))
                .withChainProxyManager(always(http(up.getListenAddress()))));
        HttpResponse<String> response = get(proxy, url(origin, "/"), basic("clientUser", "clientPass"));
        assertEquals(200, response.statusCode());
        assertEquals(List.of("none"), upstreamProxyAuthorization);
        assertEquals(List.of(), echoedHeader(response.body(), "proxy-authorization"));
    }

    @Test
    void eachProxyChecksItsOwnCredentials() throws Exception {
        HttpProxyServer up = upstream(true);
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                .withProxyAuthenticator(only("clientUser", "clientPass", null))
                .withChainProxyManager(always(authenticated(up.getListenAddress(), "upstreamUser", "upstreamPass"))));
        assertEquals(200, get(proxy, url(origin, "/"), basic("clientUser", "clientPass")).statusCode());
        assertEquals(200, connectWith(proxy, secureTarget(), basic("clientUser", "clientPass")));
        assertEquals(List.of(basic("upstreamUser", "upstreamPass"), basic("upstreamUser", "upstreamPass")),
                upstreamProxyAuthorization);
        assertFalse(upstreamAuthAttempts.contains("clientUser:clientPass"));
    }

    @Test
    void upstream407IsRelayedForPlainRequests() throws Exception {
        HttpProxyServer up = upstream(true);
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                .withChainProxyManager(always(authenticated(up.getListenAddress(), "upstreamUser", "wrong"))));
        HttpResponse<String> response = get(proxy, url(origin, "/"), null);
        // As in LittleProxy: the status reaches the client, the hop-by-hop Proxy-Authenticate does not
        // (the challenge is for credentials the client cannot supply: they are the chained proxy's).
        assertEquals(407, response.statusCode());
        assertEquals(List.of(), response.headers().allValues("proxy-authenticate"));
        assertEquals(List.of("upstreamUser:wrong"), upstreamAuthAttempts);
    }

    @Test
    void credentialsMeantForTheUpstreamAreStrippedSoItsChallengeIsRelayed() {
        // LittleProxy scenario 3: the downstream does not authenticate, so the client's
        // Proxy-Authorization is a hop-by-hop header the downstream drops.
        HttpProxyServer up = upstream(true);
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withChainProxyManager(always(http(up.getListenAddress()))));
        HttpResponse<String> response = get(proxy, url(origin, "/"), basic("upstreamUser", "upstreamPass"));
        assertEquals(407, response.statusCode());
        assertEquals(List.of("none"), upstreamProxyAuthorization);
    }

    @Test
    void upstream407OnConnectIsBadGateway() throws Exception {
        HttpProxyServer up = upstream(true);
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                .withChainProxyManager(always(authenticated(up.getListenAddress(), "upstreamUser", "wrong"))));
        try (Socket s = open(proxy.getListenAddress())) {
            assertEquals(502, status(connect(s, secureTarget())));
        }
        assertEquals(List.of("upstreamUser:wrong"), upstreamAuthAttempts);
    }
}
