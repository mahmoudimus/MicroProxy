package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.connectStatus;
import static org.microproxy.ChainTestSupport.encrypted;
import static org.microproxy.ChainTestSupport.http;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/**
 * The request mix of LittleProxy's BaseProxyTest run through a chained proxy reached in plain TCP
 * or over TLS (UnencryptedTCPChainedProxyTest, EncryptedTCPChainedProxyTest): POST with a body,
 * HEAD followed by GET, and unreachable or unresolvable servers answered with 502.
 */
class ChainedRequestsTest {

    private static final SelfSignedSslContextSource UPSTREAM_TLS = new SelfSignedSslContextSource();
    private static final String UNRESOLVABLE = "unresolvable.chain.test";
    private static final String BODY = "0123456789abcdef";
    private static HttpServer origin;

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final ChainTestSupport.RequestLog upstreamLog = new ChainTestSupport.RequestLog();

    @BeforeAll
    static void startOrigin() {
        origin = TestSupport.origin(exchange -> {
            byte[] request = exchange.getRequestBody().readAllBytes();
            byte[] out = exchange.getRequestMethod().equals("POST") ? request : BODY.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            if (exchange.getRequestMethod().equals("HEAD")) {
                exchange.getResponseHeaders().set("Content-Length", String.valueOf(out.length));
                exchange.sendResponseHeaders(200, -1);
            } else {
                exchange.sendResponseHeaders(200, out.length);
                exchange.getResponseBody().write(out);
            }
            exchange.close();
        });
    }

    @AfterAll
    static void stopOrigin() {
        origin.stop(0);
    }

    @AfterEach
    void tearDown() {
        proxies.close();
    }

    /** Downstream proxy chained to a fresh upstream; the upstream cannot resolve {@link #UNRESOLVABLE}. */
    private HttpProxyServer chain(boolean encryptedChain) {
        HttpProxyServerBootstrap up = MicroProxy.bootstrap().plusActivityTracker(upstreamLog)
                .withServerResolver((host, port) -> {
                    if (host.equals(UNRESOLVABLE)) throw new UnknownHostException(host);
                    return new DefaultHostResolver().resolve(host, port);
                });
        if (encryptedChain) up.withSslContextSource(UPSTREAM_TLS);
        InetSocketAddress address = proxies.start(up).getListenAddress();
        ChainedProxy chained = encryptedChain
                ? encrypted(address, SslContexts.trusting(UPSTREAM_TLS.getCertificate())) : http(address);
        // Only the upstream resolves server names: the downstream hands them on.
        return proxies.start(MicroProxy.bootstrap().withChainProxyManager(always(chained))
                .withServerResolver((host, port) -> {
                    throw new UnknownHostException("the downstream must not resolve " + host);
                }));
    }

    private static HttpResponse<String> post(HttpClient client, String url, String body) {
        return send(client, HttpRequest.newBuilder(URI.create(url)).POST(HttpRequest.BodyPublishers.ofString(body)).build());
    }

    @ParameterizedTest(name = "encrypted chain: {0}")
    @ValueSource(booleans = {false, true})
    void postWithBody(boolean encryptedChain) {
        HttpProxyServer down = chain(encryptedChain);
        String body = "x".repeat(100_000);
        HttpResponse<String> response = post(client(down), url(origin, "/post"), body);
        assertEquals(200, response.statusCode());
        assertEquals(body, response.body());
        assertEquals(List.of("POST " + url(origin, "/post")), upstreamLog.received);
    }

    @ParameterizedTest(name = "encrypted chain: {0}")
    @ValueSource(booleans = {false, true})
    void headFollowedByGet(boolean encryptedChain) {
        HttpProxyServer down = chain(encryptedChain);
        HttpClient client = client(down);
        HttpResponse<String> head = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/r")))
                .method("HEAD", HttpRequest.BodyPublishers.noBody()).build());
        assertEquals(200, head.statusCode());
        assertEquals("", head.body());
        assertEquals(String.valueOf(BODY.length()), head.headers().firstValue("content-length").orElseThrow());
        HttpResponse<String> get = TestSupport.get(client, url(origin, "/r"));
        assertEquals(200, get.statusCode());
        assertEquals(BODY, get.body());
        assertEquals(String.valueOf(BODY.length()), get.headers().firstValue("content-length").orElseThrow());
        assertEquals(List.of("HEAD " + url(origin, "/r"), "GET " + url(origin, "/r")), upstreamLog.received);
    }

    @ParameterizedTest(name = "encrypted chain: {0}")
    @ValueSource(booleans = {false, true})
    void unreachableServerIsBadGateway(boolean encryptedChain) throws Exception {
        int deadPort;
        try (ServerSocket s = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            deadPort = s.getLocalPort();
        }
        HttpProxyServer down = chain(encryptedChain);
        String target = "127.0.0.1:" + deadPort;
        assertEquals(502, post(client(down), "http://" + target + "/", "body").statusCode());
        assertEquals(502, TestSupport.get(client(down), "http://" + target + "/").statusCode());
        assertEquals(502, connectStatus(down.getListenAddress(), target));
        assertEquals(List.of("POST http://" + target + "/", "GET http://" + target + "/", "CONNECT " + target),
                upstreamLog.received);
    }

    @ParameterizedTest(name = "encrypted chain: {0}")
    @ValueSource(booleans = {false, true})
    void unresolvableServerIsBadGateway(boolean encryptedChain) throws Exception {
        HttpProxyServer down = chain(encryptedChain);
        HttpResponse<String> response = TestSupport.get(client(down), "http://" + UNRESOLVABLE + "/x");
        assertEquals(502, response.statusCode());
        assertEquals(502, connectStatus(down.getListenAddress(), UNRESOLVABLE + ":443"));
        assertEquals(List.of("GET http://" + UNRESOLVABLE + "/x", "CONNECT " + UNRESOLVABLE + ":443"), upstreamLog.received);
    }
}
