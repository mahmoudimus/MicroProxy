package org.microproxy;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;

/** ALPN and client authentication on the proxy's own TLS listener. */
class Http2TlsListenerTest {
    private HttpProxyServer proxy;

    @AfterEach
    void stop() {
        if (proxy != null) proxy.abort();
    }

    @Test
    void tlsListenerStillRequiresAndAcceptsClientCertificatesWithHttp2() throws Exception {
        org.microproxy.tls.SelfSignedSslContextSource source = new org.microproxy.tls.SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(source).withAuthenticateSslClients(true)
                .withHttp2(true).withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                    @Override
                    public org.microproxy.http.HttpResponse clientToProxyRequest(org.microproxy.http.HttpObject o) {
                        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
                    }
                }).start();
        assertThrows(java.io.IOException.class, () -> {
            try (H2TestClient c = H2TestClient.directTls(proxy.getListenAddress(), "example.com",
                    org.microproxy.tls.SslContexts.trusting(source.getCertificate()))) {
                c.handshake();
            }
        });
        try (H2TestClient c = H2TestClient.directTls(proxy.getListenAddress(), "example.com", source.getSslContext()).handshake()) {
            c.get(1, "/");
            assertEquals(200, c.response(1).status());
        }
    }

    @Test
    void tlsListenerNegotiatesHttp2AndKeepsHttp1Fallback() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("listener CA");
        proxy = MicroProxy.bootstrap().withPort(0).withHttp2(true)
                .withSslContextSource(() -> ca.serverContext("localhost", "127.0.0.1"))
                .withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                    @Override
                    public org.microproxy.http.HttpResponse clientToProxyRequest(org.microproxy.http.HttpObject o) {
                        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                                "TLS listener".getBytes(StandardCharsets.UTF_8));
                    }
                }).start();
        try (H2TestClient c = H2TestClient.directTls(proxy.getListenAddress(), "example.com", ca.clientContext()).handshake()) {
            c.get(1, "/");
            assertEquals("TLS listener", c.response(1).text());
        }
        try (SSLSocket s = (SSLSocket) ca.clientContext().getSocketFactory().createSocket(
                proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            SSLParameters parameters = s.getSSLParameters();
            parameters.setApplicationProtocols(new String[] {"http/1.1"});
            s.setSSLParameters(parameters);
            s.startHandshake();
            assertEquals("http/1.1", s.getApplicationProtocol());
            TestSupport.write(s.getOutputStream(), "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
            assertTrue(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
        }
    }
}
