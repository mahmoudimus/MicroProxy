package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.Socket;
import java.security.cert.Certificate;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/**
 * A proxy served over TLS, with and without {@link HttpProxyServerBootstrap#withAuthenticateSslClients}
 * (LittleProxy's ClientToProxyConnectionTest client-authentication cases, end to end).
 */
class ClientCertificateTest {

    private final SelfSignedSslContextSource proxySource = new SelfSignedSslContextSource();
    private HttpServer origin;
    private HttpProxyServer proxy;
    private final CompletableFuture<Certificate[]> clientCertificates = new CompletableFuture<>();

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(TestSupport.fixed(200, "over tls"));
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private void start(SslContextSource source, boolean authenticateClients) {
        proxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(source)
                .withAuthenticateSslClients(authenticateClients)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void clientSSLHandshakeSucceeded(FlowContext ctx, SSLSession session) {
                        try {
                            clientCertificates.complete(session.getPeerCertificates());
                        } catch (SSLPeerUnverifiedException e) {
                            clientCertificates.complete(null);
                        }
                    }
                }).start();
    }

    /** Connects over TLS with {@code clientContext} and proxies one GET. */
    private RawProxyClient.Response get(SSLContext clientContext) throws IOException {
        try (Socket plain = RawProxyClient.open(proxy.getListenAddress())) {
            SSLSocket tls = RawProxyClient.tls(plain, clientContext, "localhost", proxy.getListenAddress().getPort());
            return RawProxyClient.exchange(tls,
                    "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        }
    }

    /** Trusts the proxy's certificate but has none of its own. */
    private SSLContext anonymousClient() {
        return SslContexts.trusting(proxySource.getCertificate());
    }

    @Test
    void clientWithoutCertificateIsRejected() {
        start(proxySource, true);
        assertThrows(IOException.class, () -> get(anonymousClient()));
    }

    @Test
    void clientWithUntrustedCertificateIsRejected() {
        start(proxySource, true);
        // Presents its own self-signed certificate, which the proxy does not trust.
        SSLContext stranger = new SelfSignedSslContextSource(true, true).getSslContext();
        assertThrows(IOException.class, () -> get(stranger));
    }

    @Test
    void clientWithTrustedCertificateIsServed() throws Exception {
        start(proxySource, true);
        // The source trusts its own certificate, so it can serve as the client too.
        RawProxyClient.Response r = get(proxySource.getSslContext());
        assertEquals(200, r.status());
        assertEquals("over tls", r.body());
        assertEquals(proxySource.getCertificate(), clientCertificates.get(5, TimeUnit.SECONDS)[0]);
    }

    @Test
    void withoutClientAuthenticationAnyClientIsServed() throws Exception {
        start(proxySource, false);
        assertEquals(200, get(anonymousClient()).status());
        assertNull(clientCertificates.get(5, TimeUnit.SECONDS), "no certificate was asked for");
    }

    @Test
    void wantClientAuthSetBySourceIsKept() throws Exception {
        // The source may ask for (not require) certificates itself; the proxy must not undo that.
        SslContextSource wanting = new SslContextSource() {
            @Override
            public SSLContext getSslContext() {
                return proxySource.getSslContext();
            }

            @Override
            public void configure(SSLSocket socket, boolean clientMode) {
                if (!clientMode) socket.setWantClientAuth(true);
            }
        };
        start(wanting, false);
        assertEquals(200, get(proxySource.getSslContext()).status());
        assertEquals(proxySource.getCertificate(), clientCertificates.get(5, TimeUnit.SECONDS)[0],
                "a client with a certificate presents it");
    }

    @Test
    void wantClientAuthStillServesAnonymousClients() throws Exception {
        SslContextSource wanting = new SslContextSource() {
            @Override
            public SSLContext getSslContext() {
                return proxySource.getSslContext();
            }

            @Override
            public void configure(SSLSocket socket, boolean clientMode) {
                if (!clientMode) socket.setWantClientAuth(true);
            }
        };
        start(wanting, false);
        assertEquals(200, get(anonymousClient()).status());
    }
}
