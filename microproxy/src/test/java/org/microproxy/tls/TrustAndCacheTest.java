package org.microproxy.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpVersion;

class TrustAndCacheTest {

    @Test
    void systemDefaultPlusTrustsExtraAnchorsAndStillChecksHostNames() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Extra Anchor CA");
        HttpsServer right = TestSupport.httpsOrigin(ca.serverContext("127.0.0.1"), TestSupport.fixed(200, "ok"));
        HttpsServer wrongName = TestSupport.httpsOrigin(ca.serverContext("not-this-host.example"), TestSupport.fixed(200, "ok"));
        try (HttpClient client = HttpClient.newBuilder().sslContext(SslContexts.systemDefaultPlus(ca.getCertificate()))
                .proxy(HttpClient.Builder.NO_PROXY).build()) {
            assertEquals(200, client.send(HttpRequest.newBuilder(URI.create(TestSupport.url(right, "/"))).build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
            assertThrows(Exception.class, () -> client.send(
                    HttpRequest.newBuilder(URI.create(TestSupport.url(wrongName, "/"))).build(),
                    HttpResponse.BodyHandlers.ofString()));
        } finally {
            right.stop(0);
            wrongName.stop(0);
        }
        // The JDK roots are still there.
        assertTrue(SslContexts.systemDefaultPlusTrustManager().getAcceptedIssuers().length > 10);
    }

    @Test
    void certificateCacheIsBounded() {
        CertificateAuthorityMitmManager mitm =
                new CertificateAuthorityMitmManager(CertificateAuthority.generate("Bounded CA"), SslContexts.trustAll(), 3);
        for (int i = 0; i < 10; i++) {
            mitm.clientSslContextFor(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, "h" + i + ".test:443"), null);
        }
        assertEquals(3, mitm.cachedHostCount());
    }

    @Test
    void impersonationCopiesDnsAndIpNamesFromTheRealCertificate() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("SAN Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("SAN Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1", "alias.test"), TestSupport.fixed(200, "ok"));
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())).start();
        try {
            HttpResponse<String> r = TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()), TestSupport.url(secure, "/"));
            X509Certificate presented = (X509Certificate) r.sslSession().orElseThrow().getPeerCertificates()[0];
            List<String> names = presented.getSubjectAlternativeNames().stream().map(san -> (String) san.get(1)).toList();
            assertTrue(names.contains("alias.test"), names.toString());
            assertTrue(names.contains("127.0.0.1"), names.toString());
        } finally {
            proxy.abort();
            secure.stop(0);
        }
    }
}
