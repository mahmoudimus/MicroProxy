package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.connectStatus;
import static org.microproxy.ChainTestSupport.encrypted;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/**
 * TLS between a proxy and its chained proxy: server and client authentication failures, client
 * certificates, CONNECT over the TLS chain, and falling back after a failed handshake.
 *
 * <p>LittleProxy: EncryptedTCPChainedProxyTest, BadServerAuthenticationTCPChainedProxyTest,
 * BadClientAuthenticationTCPChainedProxyTest, ClientAuthenticationNotRequiredTCPChainedProxyTest,
 * ChainedProxyWithFallbackToDirectDueToSSLTest, ChainedProxyWithFallbackToOtherChainedProxyDueToSSLTest.
 */
class ChainedProxyTlsTest {

    /** The upstream proxy's identity; its context also trusts (only) itself and can act as a client cert. */
    private static final SelfSignedSslContextSource UPSTREAM_TLS = new SelfSignedSslContextSource();
    /** An unrelated identity: trusts only its own certificate, so not the upstream's. */
    private static final SelfSignedSslContextSource OTHER_TLS = new SelfSignedSslContextSource();

    private static CertificateAuthority originCa;
    private static HttpServer origin;
    private static HttpsServer secureOrigin;

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final ChainTestSupport.RequestLog upstreamLog = new ChainTestSupport.RequestLog();

    @BeforeAll
    static void startOrigins() {
        originCa = CertificateAuthority.generate("TLS Chain Origin CA");
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

    private InetSocketAddress tlsUpstream(boolean requireClientCertificates) {
        return proxies.start(MicroProxy.bootstrap().withProxyAlias("upstream").withSslContextSource(UPSTREAM_TLS)
                .withAuthenticateSslClients(requireClientCertificates).plusActivityTracker(upstreamLog))
                .getListenAddress();
    }

    private HttpProxyServer downstream(ChainedProxy... chain) {
        return proxies.start(MicroProxy.bootstrap().withProxyAlias("downstream").withChainProxyManager(always(chain)));
    }

    private static String secureTarget() {
        return "127.0.0.1:" + secureOrigin.getAddress().getPort();
    }

    /** Trusts the upstream's certificate but holds no client certificate. */
    private static SSLContext trustingUpstreamWithoutClientCertificate() {
        return SslContexts.trusting(UPSTREAM_TLS.getCertificate());
    }

    @Test
    void getPostAndConnectOverTlsChain() {
        HttpProxyServer down = downstream(encrypted(tlsUpstream(false), trustingUpstreamWithoutClientCertificate()));

        HttpResponse<String> response = get(client(down), url(origin, "/get"));
        assertEquals(200, response.statusCode());
        assertEquals("/get", echoedUri(response.body()));

        response = send(client(down), HttpRequest.newBuilder(URI.create(url(origin, "/post")))
                .POST(HttpRequest.BodyPublishers.ofString("over tls")).build());
        assertEquals(200, response.statusCode());
        assertEquals("over tls", echoedBody(response.body()));

        response = get(client(down, originCa.clientContext()), url(secureOrigin, "/https"));
        assertEquals(200, response.statusCode());
        assertEquals("/https", echoedUri(response.body()));

        assertEquals(List.of("GET " + url(origin, "/get"), "POST " + url(origin, "/post"), "CONNECT " + secureTarget()),
                upstreamLog.received);
    }

    @Test
    void untrustedChainedProxyCertificateMeansBadGateway() throws Exception {
        List<Throwable> failures = new CopyOnWriteArrayList<>();
        InetSocketAddress upstream = tlsUpstream(false);
        ChainedProxy untrusted = new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return upstream;
            }

            @Override
            public boolean requiresEncryption() {
                return true;
            }

            @Override
            public SSLContext getSslContext() {
                return OTHER_TLS.getSslContext();
            }

            @Override
            public void connectionFailed(Throwable cause) {
                failures.add(cause);
            }
        };
        HttpProxyServer down = downstream(untrusted);
        assertEquals(502, get(client(down), url(origin, "/")).statusCode());
        assertEquals(502, send(client(down), HttpRequest.newBuilder(URI.create(url(origin, "/")))
                .POST(HttpRequest.BodyPublishers.ofString("body")).build()).statusCode());
        assertEquals(502, connectStatus(down.getListenAddress(), secureTarget()));
        assertEquals(3, failures.size());
        failures.forEach(f -> assertInstanceOf(SSLHandshakeException.class, f));
        assertEquals(List.of(), upstreamLog.received);
    }

    @Test
    void missingClientCertificateMeansBadGateway() throws Exception {
        HttpProxyServer down = downstream(encrypted(tlsUpstream(true), trustingUpstreamWithoutClientCertificate()));
        assertEquals(502, get(client(down), url(origin, "/")).statusCode());
        assertEquals(502, connectStatus(down.getListenAddress(), secureTarget()));
        assertEquals(List.of(), upstreamLog.received);
    }

    @Test
    void clientCertificateFromTheChainedProxySslContext() {
        // A ChainedProxy presents a client certificate by returning an SSLContext with a key manager.
        HttpProxyServer down = downstream(encrypted(tlsUpstream(true), UPSTREAM_TLS.getSslContext()));
        assertEquals(200, get(client(down), url(origin, "/cert")).statusCode());
        assertEquals(200, get(client(down, originCa.clientContext()), url(secureOrigin, "/cert")).statusCode());
        assertEquals(List.of("GET " + url(origin, "/cert"), "CONNECT " + secureTarget()), upstreamLog.received);
    }

    @Test
    void clientCertificateIsIgnoredWhenNotRequired() {
        // LittleProxy ClientAuthenticationNotRequiredTCPChainedProxyTest: with or without one, it works.
        HttpProxyServer down = downstream(encrypted(tlsUpstream(false), UPSTREAM_TLS.getSslContext()));
        assertEquals(200, get(client(down), url(origin, "/with")).statusCode());
        assertEquals(1, upstreamLog.received.size());
    }

    @Test
    void failedHandshakeFallsBackToDirectConnection() throws Exception {
        HttpProxyServer down = downstream(encrypted(tlsUpstream(false), OTHER_TLS.getSslContext()),
                ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        HttpResponse<String> response = get(client(down), url(origin, "/direct"));
        assertEquals(200, response.statusCode());
        assertEquals("/direct", echoedUri(response.body()));
        assertEquals(List.of("1.1 downstream"), TestSupport.echoedHeader(response.body(), "via"));
        assertEquals(200, get(client(down, originCa.clientContext()), url(secureOrigin, "/direct")).statusCode());
        assertEquals(List.of(), upstreamLog.received);
    }

    @Test
    void failedHandshakeFallsBackToTheNextChainedProxy() throws Exception {
        InetSocketAddress upstream = tlsUpstream(false);
        HttpProxyServer down = downstream(encrypted(upstream, OTHER_TLS.getSslContext()),
                encrypted(upstream, trustingUpstreamWithoutClientCertificate()));
        HttpResponse<String> response = get(client(down), url(origin, "/next"));
        assertEquals(200, response.statusCode());
        assertEquals(List.of("1.1 downstream", "1.1 upstream"), TestSupport.echoedHeader(response.body(), "via"));
        assertEquals(200, get(client(down, originCa.clientContext()), url(secureOrigin, "/next")).statusCode());
        assertEquals(List.of("GET " + url(origin, "/next"), "CONNECT " + secureTarget()), upstreamLog.received);
    }
}
