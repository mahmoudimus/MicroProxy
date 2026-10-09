package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.connectStatus;
import static org.microproxy.ChainTestSupport.encrypted;
import static org.microproxy.ChainTestSupport.http;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpObject;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/**
 * A MITM proxy chained to an upstream proxy, reached in plain TCP or over TLS: filters see the
 * decrypted traffic while the upstream sees only the CONNECT.
 *
 * <p>LittleProxy: MitmWithChainedProxyTest, MitmWithUnencryptedTCPChainedProxyTest,
 * MitmWithEncryptedTCPChainedProxyTest, MitmWithBadServerAuthenticationTCPChainedProxyTest,
 * MitmWithBadClientAuthenticationTCPChainedProxyTest,
 * MitmWithClientAuthenticationNotRequiredTCPChainedProxyTest.
 */
class MitmChainedProxyTest {

    private static final SelfSignedSslContextSource UPSTREAM_TLS = new SelfSignedSslContextSource();
    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;
    private static HttpServer origin;
    private static HttpsServer secureOrigin;

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final ChainTestSupport.RequestLog upstreamLog = new ChainTestSupport.RequestLog();
    private final List<String> requestPre = new CopyOnWriteArrayList<>();
    private final List<String> requestPost = new CopyOnWriteArrayList<>();
    private final List<String> responsePreFor = new CopyOnWriteArrayList<>();
    private final List<String> responsePostFor = new CopyOnWriteArrayList<>();
    private final StringBuffer responsePreBody = new StringBuffer();
    private final StringBuffer responsePostBody = new StringBuffer();

    @BeforeAll
    static void startOrigins() {
        originCa = CertificateAuthority.generate("MITM Chain Origin CA");
        proxyCa = CertificateAuthority.generate("MITM Chain Proxy CA");
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

    /** Records what the filters of the MITM proxy see, as LittleProxy's MitmWithChainedProxyTest does. */
    private final HttpFiltersSource recordingFilters = new HttpFiltersSourceAdapter() {
        @Override
        public HttpFilters filterRequest(org.microproxy.http.HttpRequest original, FlowContext ctx) {
            String method = original.method().name();
            return new HttpFilters() {
                @Override
                public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                    if (o instanceof org.microproxy.http.HttpRequest r) requestPre.add(r.method().name());
                    return null;
                }

                @Override
                public org.microproxy.http.HttpResponse proxyToServerRequest(HttpObject o) {
                    if (o instanceof org.microproxy.http.HttpRequest r) requestPost.add(r.method().name());
                    return null;
                }

                @Override
                public HttpObject serverToProxyResponse(HttpObject o) {
                    if (o instanceof org.microproxy.http.HttpResponse && !method.equals("CONNECT")) responsePreFor.add(method);
                    if (o instanceof HttpContent c) responsePreBody.append(c.contentAsString());
                    return o;
                }

                @Override
                public HttpObject proxyToClientResponse(HttpObject o) {
                    if (o instanceof org.microproxy.http.HttpResponse && !method.equals("CONNECT")) responsePostFor.add(method);
                    if (o instanceof HttpContent c) responsePostBody.append(c.contentAsString());
                    return o;
                }
            };
        }
    };

    private HttpProxyServer mitmDownstream(ChainedProxy chained) {
        return proxies.start(MicroProxy.bootstrap()
                .withChainProxyManager(always(chained))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(recordingFilters));
    }

    /** The chained proxy for an upstream reached in plain TCP or over TLS. */
    private ChainedProxy upstream(boolean encryptedChain) {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().plusActivityTracker(upstreamLog);
        if (encryptedChain) b.withSslContextSource(UPSTREAM_TLS);
        InetSocketAddress address = proxies.start(b).getListenAddress();
        return encryptedChain ? encrypted(address, SslContexts.trusting(UPSTREAM_TLS.getCertificate())) : http(address);
    }

    private static HttpResponse<String> post(HttpClient client, String url, String body) {
        return send(client, HttpRequest.newBuilder(URI.create(url)).POST(HttpRequest.BodyPublishers.ofString(body)).build());
    }

    private String secureTarget() {
        return "127.0.0.1:" + secureOrigin.getAddress().getPort();
    }

    @ParameterizedTest(name = "encrypted chain: {0}")
    @ValueSource(booleans = {false, true})
    void interceptedGetThroughChain(boolean encryptedChain) {
        HttpProxyServer down = mitmDownstream(upstream(encryptedChain));
        HttpResponse<String> response = TestSupport.get(client(down, proxyCa.clientContext()), url(secureOrigin, "/g"));
        assertEquals(200, response.statusCode());
        assertEquals("/g", echoedUri(response.body()));
        assertEquals(List.of("CONNECT", "GET"), requestPre);
        assertEquals(List.of("CONNECT", "GET"), requestPost);
        assertEquals(List.of("GET"), responsePreFor);
        assertEquals(List.of("GET"), responsePostFor);
        assertEquals(response.body(), responsePreBody.toString());
        assertEquals(response.body(), responsePostBody.toString());
        assertEquals(List.of("CONNECT " + secureTarget()), upstreamLog.received);
    }

    @ParameterizedTest(name = "encrypted chain: {0}")
    @ValueSource(booleans = {false, true})
    void interceptedPostThroughChain(boolean encryptedChain) {
        HttpProxyServer down = mitmDownstream(upstream(encryptedChain));
        HttpResponse<String> response = post(client(down, proxyCa.clientContext()), url(secureOrigin, "/p"), "decrypted body");
        assertEquals(200, response.statusCode());
        assertEquals("decrypted body", echoedBody(response.body()));
        assertEquals(List.of("CONNECT", "POST"), requestPre);
        assertEquals(List.of("CONNECT", "POST"), requestPost);
        assertEquals(List.of("POST"), responsePreFor);
        assertEquals(List.of("POST"), responsePostFor);
        assertEquals(response.body(), responsePreBody.toString());
        assertEquals(response.body(), responsePostBody.toString());
        assertEquals(List.of("CONNECT " + secureTarget()), upstreamLog.received);
    }

    @ParameterizedTest(name = "encrypted chain: {0}")
    @ValueSource(booleans = {false, true})
    void plainHttpThroughMitmChainIsForwarded(boolean encryptedChain) {
        HttpProxyServer down = mitmDownstream(upstream(encryptedChain));
        HttpResponse<String> get = TestSupport.get(client(down), url(origin, "/plain"));
        assertEquals(200, get.statusCode());
        HttpResponse<String> post = post(client(down), url(origin, "/plain"), "plain body");
        assertEquals(200, post.statusCode());
        assertEquals("plain body", echoedBody(post.body()));
        assertEquals(List.of("GET", "POST"), requestPre);
        assertEquals(List.of("GET", "POST"), responsePostFor);
        assertEquals(get.body() + post.body(), responsePostBody.toString());
        assertEquals(List.of("GET " + url(origin, "/plain"), "POST " + url(origin, "/plain")), upstreamLog.received);
    }

    @Test
    void untrustedChainedProxyCertificateMeansBadGateway() throws Exception {
        InetSocketAddress address = proxies.start(MicroProxy.bootstrap().withSslContextSource(UPSTREAM_TLS)
                .plusActivityTracker(upstreamLog)).getListenAddress();
        HttpProxyServer down = mitmDownstream(encrypted(address, new SelfSignedSslContextSource().getSslContext()));
        assertEquals(502, connectStatus(down.getListenAddress(), secureTarget()));
        assertEquals(502, TestSupport.get(client(down), url(origin, "/")).statusCode());
        // The JDK client reports the failed CONNECT as an IOException.
        assertThrows(java.io.UncheckedIOException.class,
                () -> TestSupport.get(client(down, proxyCa.clientContext()), url(secureOrigin, "/")));
        assertEquals(List.of(), upstreamLog.received);
    }

    @Test
    void missingClientCertificateMeansBadGateway() throws Exception {
        InetSocketAddress address = proxies.start(MicroProxy.bootstrap().withSslContextSource(UPSTREAM_TLS)
                .withAuthenticateSslClients(true).plusActivityTracker(upstreamLog)).getListenAddress();
        HttpProxyServer down = mitmDownstream(encrypted(address, SslContexts.trusting(UPSTREAM_TLS.getCertificate())));
        assertEquals(502, connectStatus(down.getListenAddress(), secureTarget()));
        assertEquals(502, TestSupport.get(client(down), url(origin, "/")).statusCode());
        assertEquals(List.of(), upstreamLog.received);
    }

    @Test
    void clientCertificateNotRequiredThroughMitmChain() {
        InetSocketAddress address = proxies.start(MicroProxy.bootstrap().withSslContextSource(UPSTREAM_TLS)
                .plusActivityTracker(upstreamLog)).getListenAddress();
        HttpProxyServer down = mitmDownstream(encrypted(address, UPSTREAM_TLS.getSslContext()));
        assertEquals(200, TestSupport.get(client(down, proxyCa.clientContext()), url(secureOrigin, "/c")).statusCode());
        assertEquals(List.of("CONNECT " + secureTarget()), upstreamLog.received);
    }
}
