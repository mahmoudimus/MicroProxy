package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.InstantSource;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The Chrome profile's TLS 1.3 client against the JDK's TLS 1.3 server. */
class TlsClientConnectionTest {

    private static final String HOST = "tls.test";

    private SSLServerSocket server;

    @AfterEach
    void close() throws IOException {
        if (server != null) server.close();
    }

    /** A JDK TLS 1.3 server for {@link #HOST} that answers each line with "echo: line", then closes. */
    private CompletableFuture<SSLSocket> serve(CertifiedKey key, Consumer<SSLParameters> params) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(keyManagers(key), new TrustManager[] {TestCerts.CA.trustManager()}, new SecureRandom());
        server = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        SSLParameters p = server.getSSLParameters();
        p.setProtocols(new String[] {"TLSv1.3"});
        params.accept(p);
        server.setSSLParameters(p);
        CompletableFuture<SSLSocket> accepted = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try {
                while (true) {
                    SSLSocket s = (SSLSocket) server.accept();
                    s.setHandshakeApplicationProtocolSelector((sock, offered) -> offered.contains("h2") ? "h2" : null);
                    Thread.ofVirtual().start(() -> echo(s, accepted));
                }
            } catch (IOException e) {
                accepted.completeExceptionally(e);
            }
        });
        return accepted;
    }

    private static void echo(SSLSocket s, CompletableFuture<SSLSocket> accepted) {
        try (s) {
            s.startHandshake();
            accepted.complete(s);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            for (int b; (b = in.read()) >= 0; ) {
                if (b == '\n') {
                    out.write(("echo: " + line.toString(StandardCharsets.UTF_8) + "\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    line.reset();
                } else {
                    line.write(b);
                }
            }
        } catch (IOException e) {
            accepted.completeExceptionally(e);
        }
    }

    private static javax.net.ssl.KeyManager[] keyManagers(CertifiedKey key) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("k", key.privateKey(), new char[0], key.chain().toArray(X509Certificate[]::new));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(ks, new char[0]);
        return kmf.getKeyManagers();
    }

    private static TlsClientConnection.Config config(ClientSessionStore sessions, X509KeyManager km) {
        return new TlsClientConnection.Config(BrowserProfiles.chrome156(), TestCerts.CA.trustManager(), km, sessions,
                Map.of("h2", new byte[0]), CertificateDecompressor.ZLIB, new SecureRandom(), InstantSource.system(),
                64 * 1024);
    }

    private TlsClientConnection connect(TlsClientConnection.Config config, String verifyHost) throws IOException {
        Socket plain = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
        plain.setSoTimeout(10_000);
        return new TlsClientConnection(config, plain.getInputStream(), plain.getOutputStream(), HOST, verifyHost,
                List.of("h2", "http/1.1"), HOST + ":443");
    }

    private static String roundTrip(TlsClientConnection c, String line) throws IOException {
        byte[] data = (line + "\n").getBytes(StandardCharsets.UTF_8);
        c.write(data, 0, data.length);
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        while (!got.toString(StandardCharsets.UTF_8).endsWith("\n")) {
            byte[] chunk = c.read();
            if (chunk == null) break;
            got.write(chunk);
        }
        return got.toString(StandardCharsets.UTF_8);
    }

    @Test
    void handshakesNegotiatesH2AndCarriesData() throws Exception {
        CompletableFuture<SSLSocket> accepted = serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> {});
        TlsClientConnection c = connect(config(ClientSessionStore.NONE, null), HOST);
        c.handshake();
        assertEquals("h2", c.applicationProtocol());
        assertEquals("TLSv1.3", c.protocol());
        assertEquals(HOST, ((X509Certificate) c.peerCertificates().get(0)).getSubjectX500Principal().getName().substring(3));
        assertEquals("echo: hello\n", roundTrip(c, "hello"));
        // one of Chrome's two shares: the JDK's server takes X25519MLKEM768 where it has it (newer
        // Java 25 updates do), X25519 otherwise
        assertTrue(c.negotiatedGroup() == NamedGroup.X25519 || c.negotiatedGroup() == NamedGroup.X25519_MLKEM768,
                String.valueOf(c.negotiatedGroup()));
        SSLSocket s = accepted.get(5, TimeUnit.SECONDS);
        assertEquals("TLSv1.3", s.getSession().getProtocol());
        c.closeWrite();
        assertNull(c.read());
    }

    @Test
    void largeWritesAreSplitIntoRecordsTheServerReads() throws Exception {
        serve(TestCerts.CA.issue(KeyType.RSA, HOST), p -> {});
        TlsClientConnection c = connect(config(ClientSessionStore.NONE, null), HOST);
        c.handshake();
        String big = "x".repeat(50_000);
        assertEquals("echo: " + big + "\n", roundTrip(c, big));
        assertEquals(SignatureScheme.RSA_PSS_RSAE_SHA256, c.peerSignatureScheme());
    }

    @Test
    void aHelloRetryRequestForP256IsAnswered() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> p.setNamedGroups(new String[] {"secp256r1"}));
        TlsClientConnection c = connect(config(ClientSessionStore.NONE, null), HOST);
        c.handshake();
        assertEquals(NamedGroup.SECP256R1, c.negotiatedGroup());
        assertEquals("echo: retried\n", roundTrip(c, "retried"));
    }

    @Test
    void theSecondConnectionResumesWithTheFirstsTicket() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> {});
        ClientSessionMemoryCache sessions = new ClientSessionMemoryCache();
        TlsClientConnection first = connect(config(sessions, null), HOST);
        first.handshake();
        // the JDK sends its NewSessionTicket after the handshake; reading data takes it in
        assertEquals("echo: one\n", roundTrip(first, "one"));
        assertFalse(first.resumed());
        TlsClientConnection second = connect(config(sessions, null), HOST);
        second.handshake();
        assertTrue(second.resumed());
        assertEquals("echo: two\n", roundTrip(second, "two"));
        assertEquals(first.peerCertificates(), second.peerCertificates());
    }

    @Test
    void aClientCertificateIsSentWhenAskedFor() throws Exception {
        CompletableFuture<SSLSocket> accepted =
                serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> p.setNeedClientAuth(true));
        CertifiedKey client = TestCerts.CA.issue(KeyType.P256, "client.test");
        X509KeyManager km = (X509KeyManager) keyManagers(client)[0];
        TlsClientConnection c = connect(config(ClientSessionStore.NONE, km), HOST);
        c.handshake();
        assertEquals("echo: authenticated\n", roundTrip(c, "authenticated"));
        X509Certificate seen = (X509Certificate) accepted.get(5, TimeUnit.SECONDS).getSession().getPeerCertificates()[0];
        assertArrayEquals(client.chain().get(0).getEncoded(), seen.getEncoded());
    }

    @Test
    void aCertificateForAnotherNameFailsWithBadCertificate() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, "other.test"), p -> {});
        TlsClientConnection c = connect(config(ClientSessionStore.NONE, null), HOST);
        TlsClientConnection.TlsAlertException e = assertThrows(TlsClientConnection.TlsAlertException.class, c::handshake);
        assertEquals(TlsAlert.BAD_CERTIFICATE, e.alert());
        assertFalse(e.received());
    }

    @Test
    void anUntrustedCertificateFails() throws Exception {
        serve(TestCerts.OTHER_CA.issue(KeyType.P256, HOST), p -> {});
        TlsClientConnection c = connect(config(ClientSessionStore.NONE, null), HOST);
        TlsClientConnection.TlsAlertException e = assertThrows(TlsClientConnection.TlsAlertException.class, c::handshake);
        assertFalse(e.received());
    }

    @Test
    void theNameIsNotCheckedWithoutAVerifyHost() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, "other.test"), p -> {});
        TlsClientConnection c = connect(config(ClientSessionStore.NONE, null), null);
        c.handshake();
        assertEquals("echo: unchecked\n", roundTrip(c, "unchecked"));
    }

    @Test
    void eachCipherSuiteTheServerPicksWorks() throws Exception {
        for (String suite : List.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")) {
            serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> p.setCipherSuites(new String[] {suite}));
            TlsClientConnection c = connect(config(ClientSessionStore.NONE, null), HOST);
            c.handshake();
            assertEquals(suite, c.cipherSuite().name());
            assertEquals("echo: " + suite + "\n", roundTrip(c, suite));
            server.close();
        }
        server = null;
        assertEquals(3, CipherSuite.values().length);
    }
}
