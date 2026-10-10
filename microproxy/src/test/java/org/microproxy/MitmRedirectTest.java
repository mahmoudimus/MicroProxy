package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Requests inside an intercepted session normally go to the {@code CONNECT} target. A filter that
 * gives one an absolute URI (as map_remote and scripts assigning {@code req.uri} do) sends it to
 * that URI's server instead, over TLS for {@code https}, with a server connection of its own.
 */
class MitmRedirectTest {

    static CertificateAuthority originCa;
    static CertificateAuthority proxyCa;

    private HttpsServer origin;
    private HttpsServer other;
    private HttpServer plain;
    private HttpProxyServer proxy;
    private final List<String> connected = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void createAuthorities() {
        originCa = CertificateAuthority.generate("Redirect Origin CA");
        proxyCa = CertificateAuthority.generate("Redirect Proxy CA");
    }

    @BeforeEach
    void setUp() {
        origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), exchange -> {
            exchange.getResponseHeaders().set("X-Origin", "first");
            echo().handle(exchange);
        });
        other = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), exchange -> {
            exchange.getResponseHeaders().set("X-Origin", "other");
            echo().handle(exchange);
        });
        plain = TestSupport.origin(exchange -> {
            exchange.getResponseHeaders().set("X-Origin", "plain");
            echo().handle(exchange);
        });
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
        other.stop(0);
        plain.stop(0);
    }

    /** A proxy that intercepts, and sends {@code /elsewhere/...} to {@code target}. */
    private HttpProxyServerBootstrap redirecting(String target, boolean http2) {
        HttpFiltersBuilder.Built filters = HttpFilters.builder()
                .onRequest(req -> {
                    if (req.uri().startsWith("/elsewhere/")) {
                        req.setUri(target + req.uri().substring("/elsewhere".length()));
                    }
                    return null;
                })
                .build();
        return MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp2(http2)
                .withFiltersSource(filters)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
                        connected.add(ctx.getServerHostAndPort());
                    }
                });
    }

    private static String authority(HttpServer server) {
        return "127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    void anAbsoluteUriFromAFilterLeavesTheInterceptedSession() {
        String target = "https://" + authority(other);
        proxy = redirecting(target, false).start();
        HttpClient client = client(proxy, proxyCa.clientContext());

        HttpResponse<String> moved = get(client, url(origin, "/elsewhere/a?x=1"));
        assertEquals(200, moved.statusCode());
        assertEquals("other", moved.headers().firstValue("X-Origin").orElseThrow());
        assertEquals("/a?x=1", echoedUri(moved.body()));
        // Host names the new server, and the request reached it in origin-form.
        assertEquals(List.of(authority(other)), echoedHeader(moved.body(), HttpHeaderNames.HOST));

        // The session itself still reaches its CONNECT target.
        HttpResponse<String> stays = get(client, url(origin, "/here"));
        assertEquals("first", stays.headers().firstValue("X-Origin").orElseThrow());
        assertEquals(List.of(authority(origin)), echoedHeader(stays.body(), HttpHeaderNames.HOST));

        // A connection per server, each reused: the CONNECT's, and one to the new server.
        assertEquals("other", get(client, url(origin, "/elsewhere/b")).headers().firstValue("X-Origin").orElseThrow());
        assertEquals("first", get(client, url(origin, "/again")).headers().firstValue("X-Origin").orElseThrow());
        assertEquals(List.of(authority(origin), authority(other)), connected);
    }

    @Test
    void aPlainHttpTargetIsReachedWithoutTls() {
        proxy = redirecting("http://" + authority(plain), false).start();
        HttpResponse<String> moved = get(client(proxy, proxyCa.clientContext()), url(origin, "/elsewhere/p"));
        assertEquals("plain", moved.headers().firstValue("X-Origin").orElseThrow());
        assertEquals("/p", echoedUri(moved.body()));
        assertEquals(List.of(authority(plain)), echoedHeader(moved.body(), HttpHeaderNames.HOST));
    }

    @Test
    void http2StreamsAreRedirectedToo() {
        proxy = redirecting("https://" + authority(other), true).start();
        HttpClient client = Http2ProxyTest.h2Client(proxy, proxyCa.clientContext());
        HttpResponse<String> moved = get(client, url(origin, "/elsewhere/h2"));
        assertEquals(HttpClient.Version.HTTP_2, moved.version());
        assertEquals("other", moved.headers().firstValue("X-Origin").orElseThrow());
        assertEquals("/h2", echoedUri(moved.body()));
        assertEquals("first", get(client, url(origin, "/stay")).headers().firstValue("X-Origin").orElseThrow());
    }

    @Test
    void anUnchangedOriginFormRequestStaysPinned() {
        // A filter that only edits the path keeps the request on the session's server.
        HttpFiltersBuilder.Built filters = HttpFilters.builder().onRequest(req -> {
            if (req.method().equals(org.microproxy.http.HttpMethod.CONNECT)) return null;
            req.setUri("/rewritten");
            req.headers().set(HttpHeaderNames.HOST, "elsewhere.invalid");
            return null;
        }).build();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(filters).start();
        HttpResponse<String> response = get(client(proxy, proxyCa.clientContext()), url(origin, "/x"));
        assertEquals("first", response.headers().firstValue("X-Origin").orElseThrow());
        assertEquals("/rewritten", echoedUri(response.body()));
    }

    @Test
    void anHttpsUriOnAPlainRequestIsFetchedOverTls() {
        // Outside interception: a forward request pointed at an https:// URI gets TLS to the
        // server (with the MITM manager's trust), not plain text to port 443.
        HttpFiltersBuilder.Built filters = HttpFilters.builder().onRequest(req -> {
            req.setUri("https://" + authority(other) + "/secure");
            return null;
        }).build();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(filters).start();
        HttpResponse<String> response = get(client(proxy), url(plain, "/insecure"));
        assertEquals(200, response.statusCode());
        assertEquals("other", response.headers().firstValue("X-Origin").orElseThrow());
        assertEquals("/secure", echoedUri(response.body()));
        assertTrue(echoedHeader(response.body(), HttpHeaderNames.HOST).contains(authority(other)));
    }

    @Test
    void mapRemoteMovesInterceptedRequestsToAnotherHost() {
        String from = "https://" + authority(origin).replace(".", "\\.") + "/api/";
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(org.microproxy.extras.MapRemote.of(
                        "|~m GET|" + from + "|https://localhost:" + other.getAddress().getPort() + "/v2/"))
                .start();
        HttpClient client = client(proxy, proxyCa.clientContext());
        HttpResponse<String> moved = get(client, url(origin, "/api/users?id=7"));
        assertEquals("other", moved.headers().firstValue("X-Origin").orElseThrow());
        assertEquals("/v2/users?id=7", echoedUri(moved.body()));
        // Host is the new server's, as written in the replacement; TLS used its name (SNI, checked).
        assertEquals(List.of("localhost:" + other.getAddress().getPort()), echoedHeader(moved.body(), HttpHeaderNames.HOST));
        // The filter keeps POSTs on the intercepted server.
        HttpResponse<String> post = TestSupport.send(client, java.net.http.HttpRequest.newBuilder(
                java.net.URI.create(url(origin, "/api/users"))).POST(java.net.http.HttpRequest.BodyPublishers.ofString("x")).build());
        assertEquals("first", post.headers().firstValue("X-Origin").orElseThrow());
    }
}
