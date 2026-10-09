package org.microproxy.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpVersion;

/**
 * The TLS helpers: {@link TrustingTrustManager}, {@link SslContexts}, {@link
 * SelfSignedSslContextSource} and certificate issuing in {@link CertificateAuthorityMitmManager}
 * (LittleProxy's TrustingTrustManagerTest, SelfSignedSslEngineSourceTest and
 * SelfSignedMitmManagerTest).
 */
class TlsUtilitiesTest {

    // --- a loopback TLS handshake ----------------------------------------------------------------

    /**
     * Runs a handshake between a server using {@code serverContext} and a client using {@code
     * clientContext}, verifying {@code host} if given, and returns the server's certificate chain.
     */
    private static X509Certificate[] handshake(SSLContext serverContext, SSLContext clientContext, String verifyHost)
            throws Exception {
        return handshake(serverContext, clientContext, verifyHost, false);
    }

    private static X509Certificate[] handshake(
            SSLContext serverContext, SSLContext clientContext, String verifyHost, boolean needClientAuth)
            throws Exception {
        try (SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            server.setNeedClientAuth(needClientAuth);
            CompletableFuture<Void> served = CompletableFuture.runAsync(() -> {
                try (SSLSocket s = (SSLSocket) server.accept()) {
                    s.setSoTimeout(5000);
                    s.startHandshake();
                    s.getOutputStream().write('x');
                    s.getOutputStream().flush();
                    s.getInputStream().read();
                } catch (IOException ignored) {
                    // the client side reports failures
                }
            });
            try (SSLSocket client = (SSLSocket) clientContext.getSocketFactory()
                    .createSocket("127.0.0.1", server.getLocalPort())) {
                client.setSoTimeout(5000);
                if (verifyHost != null) {
                    SSLParameters params = client.getSSLParameters();
                    params.setEndpointIdentificationAlgorithm("HTTPS");
                    client.setSSLParameters(params);
                }
                client.startHandshake();
                if (client.getInputStream().read() != 'x') throw new IOException("no data");
                client.getOutputStream().write('y');
                client.getOutputStream().flush();
                return (X509Certificate[]) client.getSession().getPeerCertificates();
            } finally {
                served.get(5, TimeUnit.SECONDS);
            }
        }
    }

    private static List<String> subjectAltNames(X509Certificate cert) throws Exception {
        return cert.getSubjectAlternativeNames().stream().map(san -> (String) san.get(1)).toList();
    }

    // --- TrustingTrustManager ------------------------------------------------------------------

    @Test
    void trustingTrustManagerAcceptsAnythingAndNamesNoIssuers() throws Exception {
        TrustingTrustManager tm = new TrustingTrustManager();
        X509Certificate cert = CertificateAuthority.generate("Anything").getCertificate();
        for (X509Certificate[] chain : new X509Certificate[][] {null, {}, {cert}}) {
            for (String authType : new String[] {null, "", "RSA", "EC", "DHE_DSS", "UNKNOWN"}) {
                assertDoesNotThrow(() -> tm.checkClientTrusted(chain, authType));
                assertDoesNotThrow(() -> tm.checkServerTrusted(chain, authType));
                assertDoesNotThrow(() -> tm.checkClientTrusted(chain, authType, (Socket) null));
                assertDoesNotThrow(() -> tm.checkServerTrusted(chain, authType, (Socket) null));
                assertDoesNotThrow(() -> tm.checkClientTrusted(chain, authType, (SSLEngine) null));
                assertDoesNotThrow(() -> tm.checkServerTrusted(chain, authType, (SSLEngine) null));
            }
        }
        // LittleProxy returns null here; an empty array is what the JSSE contract asks for.
        assertArrayEquals(new X509Certificate[0], tm.getAcceptedIssuers());
    }

    // --- SslContexts -----------------------------------------------------------------------------

    @Test
    void trustAllAcceptsUnknownIssuersAndWrongHostNames() throws Exception {
        CertificateAuthority unknown = CertificateAuthority.generate("Unknown CA");
        SSLContext wrongName = unknown.serverContext("somewhere-else.example");
        assertEquals(unknown.getCertificate(), handshake(wrongName, SslContexts.trustAll(), "127.0.0.1")[1]);
        assertEquals("TLS", SslContexts.trustAll().getProtocol());
    }

    @Test
    void trustingAcceptsOnlyItsAnchorsAndChecksHostNames() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Anchor CA");
        CertificateAuthority other = CertificateAuthority.generate("Other CA");
        SSLContext client = SslContexts.trusting(ca.getCertificate());
        assertDoesNotThrow(() -> handshake(ca.serverContext("127.0.0.1"), client, "127.0.0.1"));
        assertThrows(IOException.class, () -> handshake(other.serverContext("127.0.0.1"), client, null));
        assertThrows(IOException.class, () -> handshake(ca.serverContext("elsewhere.example"), client, "127.0.0.1"));
        // Without host-name checking requested, the name does not matter.
        assertDoesNotThrow(() -> handshake(ca.serverContext("elsewhere.example"), client, null));
    }

    @Test
    void systemDefaultRejectsPrivateCas() {
        CertificateAuthority ca = CertificateAuthority.generate("Private CA");
        assertThrows(IOException.class, () -> handshake(ca.serverContext("127.0.0.1"), SslContexts.systemDefault(), null));
    }

    @Test
    void withKeyPresentsTheGivenChain() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Chain CA");
        var keyPair = CertificateAuthority.newEcKeyPair();
        X509Certificate leaf = ca.issue(keyPair.getPublic(), List.of("127.0.0.1"));
        SSLContext server = SslContexts.withKey(keyPair.getPrivate(), new X509Certificate[] {leaf, ca.getCertificate()}, null);
        X509Certificate[] chain = handshake(server, SslContexts.trusting(ca.getCertificate()), "127.0.0.1");
        assertArrayEquals(new X509Certificate[] {leaf, ca.getCertificate()}, chain);
    }

    // --- SelfSignedSslContextSource ------------------------------------------------------------

    @Test
    void selfSignedCertificateCoversTheLoopbackNames() throws Exception {
        SelfSignedSslContextSource source = new SelfSignedSslContextSource();
        X509Certificate cert = source.getCertificate();
        assertEquals("TLS", source.getSslContext().getProtocol());
        assertEquals(List.of("localhost", "127.0.0.1", "0:0:0:0:0:0:0:1"), subjectAltNames(cert));
        assertTrue(cert.getSubjectX500Principal().getName().contains("CN=localhost"), cert.getSubjectX500Principal().getName());
        assertEquals(cert.getSubjectX500Principal(), cert.getIssuerX500Principal());
        cert.verify(cert.getPublicKey()); // self-signed
        cert.checkValidity(new Date());
        assertNotEquals(cert, new SelfSignedSslContextSource().getCertificate(), "each source makes its own");
    }

    @Test
    void selfSignedCertificateCanNameOtherHosts() throws Exception {
        SelfSignedSslContextSource source = new SelfSignedSslContextSource(false, true, "proxy.test", "10.1.2.3");
        assertEquals(List.of("proxy.test", "10.1.2.3"), subjectAltNames(source.getCertificate()));
    }

    @Test
    void oneSourceServesBothEndsBecauseItTrustsItself() throws Exception {
        SelfSignedSslContextSource source = new SelfSignedSslContextSource();
        assertEquals(source.getCertificate(),
                handshake(source.getSslContext(), source.getSslContext(), "127.0.0.1")[0]);
        // ...but by default it trusts nothing else.
        SelfSignedSslContextSource stranger = new SelfSignedSslContextSource();
        assertThrows(IOException.class, () -> handshake(stranger.getSslContext(), source.getSslContext(), null));
    }

    @Test
    void trustAllServersAcceptsOtherCertificates() throws Exception {
        SelfSignedSslContextSource trusting = new SelfSignedSslContextSource(true);
        SelfSignedSslContextSource stranger = new SelfSignedSslContextSource();
        assertEquals(stranger.getCertificate(), handshake(stranger.getSslContext(), trusting.getSslContext(), null)[0]);
    }

    @Test
    void withoutSendCertsTheSourceCannotServe() throws Exception {
        SelfSignedSslContextSource silent = new SelfSignedSslContextSource(false, false);
        assertThrows(IOException.class, () -> handshake(silent.getSslContext(), SslContexts.trustAll(), null),
                "with no certificate to present, a server handshake fails");
        // As a client it presents nothing, so a server that requires certificates refuses it.
        SSLContext demanding = new SelfSignedSslContextSource(true, true).getSslContext();
        SSLContext anonymous = new SelfSignedSslContextSource(true, false).getSslContext();
        assertThrows(IOException.class, () -> handshake(demanding, anonymous, null, true));
        assertDoesNotThrow(() -> handshake(demanding, new SelfSignedSslContextSource(true, true).getSslContext(), null, true));
    }

    // --- CertificateAuthorityMitmManager -------------------------------------------------------

    private static DefaultHttpRequest connect(String authority) {
        return new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, authority);
    }

    @Test
    void mitmManagerUsesTheGivenUpstreamContextForEveryServer() {
        SSLContext upstream = SslContexts.trustAll();
        CertificateAuthorityMitmManager mitm = new CertificateAuthorityMitmManager(
                CertificateAuthority.generate("Upstream CA"), upstream);
        assertSame(upstream, mitm.serverSslContext("localhost", 8090));
        assertSame(upstream, mitm.serverSslContext("example.com", 443));
        assertTrue(new CertificateAuthorityMitmManager(CertificateAuthority.generate("Default CA"))
                .serverSslContext("example.com", 443) != null, "the default validates against the JDK trust store");
    }

    @Test
    void mitmManagerIssuesCachedCertificatesPerHost() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Issuing CA");
        CertificateAuthorityMitmManager mitm = new CertificateAuthorityMitmManager(ca, SslContexts.trustAll());
        assertSame(ca, mitm.getCertificateAuthority());

        SSLContext first = mitm.clientSslContextFor(connect("intercepted.test:443"), null);
        assertSame(first, mitm.clientSslContextFor(connect("intercepted.test:443"), null), "cached");
        assertSame(first, mitm.clientSslContextFor(connect("intercepted.test:8443"), null), "per host, not port");
        assertNotSame(first, mitm.clientSslContextFor(connect("other.test:443"), null));
        assertEquals(2, mitm.cachedHostCount());

        X509Certificate[] chain = handshake(first, SslContexts.trusting(ca.getCertificate()), null);
        assertEquals(List.of("intercepted.test"), subjectAltNames(chain[0]));
        assertEquals(ca.getCertificate(), chain[1], "the chain includes the CA");
        chain[0].verify(ca.getCertificate().getPublicKey());
    }

    @Test
    void mitmManagerHandlesIpv6ConnectTargets() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("V6 CA");
        CertificateAuthorityMitmManager mitm = new CertificateAuthorityMitmManager(ca, SslContexts.trustAll());
        SSLContext context = mitm.clientSslContextFor(connect("[::1]:443"), null);
        assertEquals(List.of("0:0:0:0:0:0:0:1"),
                subjectAltNames(handshake(context, SslContexts.trusting(ca.getCertificate()), null)[0]));
    }

    @Test
    void mitmManagerNeedsRoomForAtLeastOneHost() {
        CertificateAuthority ca = CertificateAuthority.generate("Size CA");
        assertThrows(IllegalArgumentException.class, () -> new CertificateAuthorityMitmManager(ca, SslContexts.trustAll(), 0));
    }
}
