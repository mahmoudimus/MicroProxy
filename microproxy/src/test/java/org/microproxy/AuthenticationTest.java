package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

class AuthenticationTest {

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final AtomicInteger authCalls = new AtomicInteger();
    private final AtomicReference<String> userSeenByFilters = new AtomicReference<>();

    @BeforeEach
    void setUp() {
        origin = origin(echo());
        proxy = MicroProxy.bootstrap().withPort(0)
                .withProxyAuthenticator(new ProxyAuthenticator() {
                    @Override
                    public boolean authenticate(String userName, String password) {
                        authCalls.incrementAndGet();
                        return "user".equals(userName) && "p:ss".equals(password);
                    }

                    @Override
                    public String getRealm() {
                        return "test-realm";
                    }
                })
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                        userSeenByFilters.set(ctx.getClientDetails().getUserName());
                        return null;
                    }
                })
                .start();
    }

    @AfterEach
    void tearDown() {
        proxy.abort();
        origin.stop(0);
    }

    private static String basic(String user, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void missingCredentialsGet407() {
        HttpResponse<String> response = TestSupport.get(client(proxy), url(origin, "/"));
        assertEquals(407, response.statusCode());
        assertEquals("Basic realm=\"test-realm\"", response.headers().firstValue("proxy-authenticate").orElseThrow());
    }

    @Test
    void wrongCredentialsGet407() {
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/")))
                .header("Proxy-Authorization", basic("user", "wrong")).build());
        assertEquals(407, response.statusCode());
    }

    @Test
    void validCredentialsAreAcceptedOncePerConnectionAndNotForwarded() {
        HttpClient client = client(proxy);
        for (int i = 0; i < 3; i++) {
            HttpResponse<String> response = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/" + i)))
                    .header("Proxy-Authorization", basic("user", "p:ss")).build());
            assertEquals(200, response.statusCode());
            assertTrue(echoedHeader(response.body(), "proxy-authorization").isEmpty());
        }
        assertEquals(1, authCalls.get());
        assertEquals("user", userSeenByFilters.get());
    }

    private static HttpProxyServer authenticating(ProxyAuthenticator authenticator) {
        return MicroProxy.bootstrap().withPort(0).withProxyAuthenticator(authenticator).start();
    }

    @Test
    void connectWithoutCredentialsGets407WithTheRealm() throws Exception {
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            RawProxyClient.Response r = RawProxyClient.connect(s, "127.0.0.1:443");
            assertEquals(407, r.status());
            assertEquals("Basic realm=\"test-realm\"", r.header("Proxy-Authenticate"));
        }
        assertEquals(0, authCalls.get());
    }

    @Test
    void connectWithCredentialsOpensTheTunnel() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Tunnel Origin CA");
        HttpsServer secure = TestSupport.httpsOrigin(ca.serverContext("127.0.0.1"), echo());
        String target = "127.0.0.1:" + secure.getAddress().getPort();
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            assertEquals(200, RawProxyClient.connect(s, target, "Proxy-Authorization: " + basic("user", "p:ss")).status());
            SSLSocket tls = RawProxyClient.tls(s, ca.clientContext(), "127.0.0.1", secure.getAddress().getPort());
            RawProxyClient.Response r = RawProxyClient.exchange(tls, "GET /tunnelled HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
            assertEquals(200, r.status());
            assertEquals("/tunnelled", TestSupport.echoedUri(r.body()));
            assertEquals(1, authCalls.get());
            assertEquals("user", userSeenByFilters.get());
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void postIsForwardedOnlyWithCredentials() {
        AtomicInteger posts = new AtomicInteger();
        origin.createContext("/post", exchange -> {
            posts.incrementAndGet();
            echo().handle(exchange);
        });
        HttpRequest.Builder post = HttpRequest.newBuilder(URI.create(url(origin, "/post")))
                .POST(HttpRequest.BodyPublishers.ofString("form=data"));
        HttpResponse<String> rejected = send(client(proxy), post.build());
        assertEquals(407, rejected.statusCode());
        assertEquals(0, posts.get(), "the body of an unauthenticated request goes nowhere");

        HttpResponse<String> accepted = send(client(proxy),
                post.header("Proxy-Authorization", basic("user", "p:ss")).build());
        assertEquals(200, accepted.statusCode());
        assertEquals("form=data", TestSupport.echoedBody(accepted.body()));
        assertEquals("POST", accepted.body().lines().findFirst().orElseThrow().substring("method: ".length()));
        assertEquals(1, posts.get());
    }

    @Test
    void clientAnsweringTheChallengeIsAuthenticatedOnce() {
        // LittleProxy's AuthenticationCalledOnceTest: 407, retry with credentials, one check.
        HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                .proxy(java.net.ProxySelector.of(proxy.getListenAddress()))
                .authenticator(new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return getRequestorType() == RequestorType.PROXY
                                ? new PasswordAuthentication("user", "p:ss".toCharArray()) : null;
                    }
                }).build();
        assertEquals(200, TestSupport.get(client, url(origin, "/first")).statusCode());
        assertEquals(200, TestSupport.get(client, url(origin, "/second")).statusCode());
        assertEquals(1, authCalls.get(), "checked once, not again for the retry's connection or later requests");
    }

    @Test
    void malformedCredentialsAreRejectedWithoutConsultingTheAuthenticator() {
        for (String value : List.of("Bearer abc", "Basic !!!", "Basic "
                + Base64.getEncoder().encodeToString("no-colon".getBytes(StandardCharsets.UTF_8)))) {
            HttpResponse<String> r = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/")))
                    .header("Proxy-Authorization", value).build());
            assertEquals(407, r.statusCode(), value);
        }
        assertEquals(0, authCalls.get());
    }

    @Test
    void realmDefaultsAndIsSanitized() {
        HttpProxyServer noRealm = authenticating((u, p) -> false);
        HttpProxyServer quoted = authenticating(new ProxyAuthenticator() {
            @Override
            public boolean authenticate(String userName, String password) {
                return false;
            }

            @Override
            public String getRealm() {
                return "my \"quoted\" realm";
            }
        });
        try {
            assertEquals("Basic realm=\"Restricted Files\"", TestSupport.get(client(noRealm), url(origin, "/"))
                    .headers().firstValue("proxy-authenticate").orElseThrow());
            assertEquals("Basic realm=\"my quoted realm\"", TestSupport.get(client(quoted), url(origin, "/"))
                    .headers().firstValue("proxy-authenticate").orElseThrow());
        } finally {
            noRealm.abort();
            quoted.abort();
        }
    }

    @Test
    void interceptedSessionsAuthenticateOnConnectOnly() throws Exception {
        // LittleProxy's MITMUsernamePasswordAuthenticatingProxyTest.
        CertificateAuthority originCa = CertificateAuthority.generate("Auth Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Auth Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), echo());
        AtomicInteger mitmAuthCalls = new AtomicInteger();
        List<String> users = new java.util.concurrent.CopyOnWriteArrayList<>();
        HttpProxyServer mitm = MicroProxy.bootstrap().withPort(0)
                .withProxyAuthenticator((user, password) -> {
                    mitmAuthCalls.incrementAndGet();
                    return "user".equals(user) && "p:ss".equals(password);
                })
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                        users.add(req.method() + " " + ctx.getClientDetails().getUserName());
                        return null;
                    }
                })
                .start();
        int port = secure.getAddress().getPort();
        String target = "127.0.0.1:" + port;
        try {
            try (Socket s = RawProxyClient.open(mitm.getListenAddress())) {
                RawProxyClient.Response r = RawProxyClient.connect(s, target);
                assertEquals(407, r.status());
                assertTrue(r.header("Proxy-Authenticate").startsWith("Basic realm="));
            }
            try (Socket s = RawProxyClient.open(mitm.getListenAddress())) {
                assertEquals(200, RawProxyClient.connect(s, target, "Proxy-Authorization: " + basic("user", "p:ss")).status());
                SSLSocket tls = RawProxyClient.tls(s, proxyCa.clientContext(), "127.0.0.1", port);
                for (String path : List.of("/one", "/two")) {
                    // The decrypted requests carry no credentials and are not challenged again.
                    RawProxyClient.Response r = RawProxyClient.exchange(tls, "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
                    assertEquals(200, r.status(), r.toString());
                    assertEquals(path, TestSupport.echoedUri(r.body()));
                    assertTrue(TestSupport.echoedHeader(r.body(), "proxy-authorization").isEmpty());
                }
            }
            assertEquals(1, mitmAuthCalls.get());
            assertEquals(List.of("CONNECT user", "GET user", "GET user"), users);
        } finally {
            mitm.abort();
            secure.stop(0);
        }
    }
}
