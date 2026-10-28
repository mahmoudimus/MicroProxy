package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.Arrays;
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

/** The Chrome profile against the JDK's TLS 1.2 server: a TLS 1.2-only server picks one of the profile's TLS 1.2 suites. */
class Tls12ClientTest {

    private static final String HOST = "tls12.test";

    private SSLServerSocket server;

    @AfterEach
    void close() throws IOException {
        if (server != null) server.close();
    }

    private CompletableFuture<SSLSocket> serve(CertifiedKey key, Consumer<SSLParameters> params) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(keyManagers(key), new TrustManager[] {TestCerts.CA.trustManager()}, new SecureRandom());
        server = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        SSLParameters p = server.getSSLParameters();
        p.setProtocols(new String[] {"TLSv1.2"});
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

    private static TlsClientConnection.Config config(X509KeyManager km, Tls12SessionCache sessions) {
        return new TlsClientConnection.Config(BrowserProfiles.chrome156(), TestCerts.CA.trustManager(), km,
                ClientSessionStore.NONE, Map.of("h2", new byte[0]), CertificateDecompressor.ZLIB, new SecureRandom(),
                InstantSource.system(), 64 * 1024, sessions);
    }

    private TlsClientConnection connect(TlsClientConnection.Config config) throws IOException {
        Socket plain = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
        plain.setSoTimeout(10_000);
        return new TlsClientConnection(config, plain.getInputStream(), plain.getOutputStream(), HOST, HOST,
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

    /** The profile's TLS 1.2 suites the JDK's server supports and allows by default. */
    private static List<String> jdkSuites(KeyType key) throws Exception {
        List<String> enabled = Arrays.asList(SSLContext.getDefault().getDefaultSSLParameters().getCipherSuites());
        List<String> out = new ArrayList<>();
        for (Tls12CipherSuite s : BrowserProfiles.chrome156().tls12CipherSuites()) {
            boolean ecdsa = s.keyExchange == Tls12CipherSuite.KeyExchange.ECDHE_ECDSA;
            if (ecdsa != (key == KeyType.P256)) continue;
            if (!s.bulk.cbc() && enabled.contains(s.name())) out.add(s.name());
        }
        return out;
    }

    @Test
    void everyAllowedAeadProfileSuiteTheJdkOffersWorks() throws Exception {
        List<String> tried = new ArrayList<>();
        for (KeyType key : List.of(KeyType.P256, KeyType.RSA)) {
            for (String suite : jdkSuites(key)) {
                serve(TestCerts.CA.issue(key, HOST), p -> p.setCipherSuites(new String[] {suite}));
                TlsClientConnection c = connect(config(null, new Tls12SessionCache()));
                c.handshake();
                assertEquals("TLSv1.2", c.protocol(), suite);
                assertEquals(suite, c.cipherSuiteName());
                assertEquals("h2", c.applicationProtocol());
                assertEquals("echo: " + suite + "\n", roundTrip(c, suite));
                assertEquals("echo: " + "y".repeat(40_000) + "\n", roundTrip(c, "y".repeat(40_000)), suite);
                c.closeWrite();
                server.close();
                tried.add(suite);
            }
        }
        server = null;
        // ECDHE with both key types, GCM and ChaCha20. CBC is rejected separately.
        assertTrue(tried.contains("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"), tried.toString());
        assertTrue(tried.contains("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"), tried.toString());
        assertTrue(tried.contains("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"), tried.toString());
    }

    @Test
    void callerKeyConstraintsInspectActualTls12TrafficKeys() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> {});
        TlsClientConnection c = connect(config(null, new Tls12SessionCache()));
        c.acceptance(null, FingerprintSslContextTest.realTrafficKeyRestriction());
        assertThrows(IOException.class, c::handshake);
    }

    @Test
    void cbcIsRejectedEvenWhenItIsPresentInTheBrowserHello() throws Exception {
        String suite = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
        serve(TestCerts.CA.issue(KeyType.RSA, HOST), p -> p.setCipherSuites(new String[] {suite}));
        TlsClientConnection c = connect(config(null, new Tls12SessionCache()));
        TlsClientConnection.TlsAlertException failure = assertThrows(TlsClientConnection.TlsAlertException.class, c::handshake);
        assertEquals(TlsAlert.HANDSHAKE_FAILURE, failure.alert());
    }

    @Test
    void mutualTls12AuthenticationCannotResumePastANewLocalKeyRestriction() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> p.setNeedClientAuth(true));
        CertifiedKey client = TestCerts.CA.issue(KeyType.RSA, "client.test");
        X509KeyManager km = (X509KeyManager) keyManagers(client)[0];
        Tls12SessionCache sessions = new Tls12SessionCache();
        TlsClientConnection first = connect(config(km, sessions));
        first.handshake();
        assertFalse(first.localCertificates().isEmpty());
        assertEquals("echo: one\n", roundTrip(first, "one"));
        String previous = Security.getProperty("jdk.tls.disabledAlgorithms");
        try {
            Security.setProperty("jdk.tls.disabledAlgorithms", previous + ", RSA keySize < 4096");
            assertThrows(TlsClientConnection.TlsAlertException.class, connect(config(km, sessions))::handshake);
        } finally {
            Security.setProperty("jdk.tls.disabledAlgorithms", previous);
            first.closeWrite();
        }
    }

    @Test
    void tls12ResumptionCannotBypassACurrentPeerKeyRestriction() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> {});
        Tls12SessionCache sessions = new Tls12SessionCache();
        TlsClientConnection first = connect(config(null, sessions));
        first.handshake();
        assertEquals("echo: one\n", roundTrip(first, "one"));
        String previous = Security.getProperty("jdk.tls.disabledAlgorithms");
        try {
            Security.setProperty("jdk.tls.disabledAlgorithms", previous + ", EC keySize < 384");
            assertThrows(TlsClientConnection.TlsAlertException.class, connect(config(null, sessions))::handshake);
        } finally {
            Security.setProperty("jdk.tls.disabledAlgorithms", previous);
            first.closeWrite();
        }
    }

    @Test
    void theSecondConnectionResumesWithTheTicket() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> {});
        Tls12SessionCache sessions = new Tls12SessionCache();
        TlsClientConnection first = connect(config(null, sessions));
        first.handshake();
        assertFalse(first.resumed());
        assertEquals("echo: one\n", roundTrip(first, "one"));
        TlsClientConnection second = connect(config(null, sessions));
        second.handshake();
        assertTrue(second.resumed());
        assertEquals("echo: two\n", roundTrip(second, "two"));
        assertEquals(first.peerCertificates(), second.peerCertificates());
    }

    @Test
    void aClientCertificateIsSentWhenAskedFor() throws Exception {
        CompletableFuture<SSLSocket> accepted = serve(TestCerts.CA.issue(KeyType.RSA, HOST), p -> p.setNeedClientAuth(true));
        CertifiedKey client = TestCerts.CA.issue(KeyType.P256, "client.test");
        TlsClientConnection c = connect(config((X509KeyManager) keyManagers(client)[0], new Tls12SessionCache()));
        c.handshake();
        assertEquals("echo: authenticated\n", roundTrip(c, "authenticated"));
        X509Certificate seen = (X509Certificate) accepted.get(5, TimeUnit.SECONDS).getSession().getPeerCertificates()[0];
        assertArrayEquals(client.chain().get(0).getEncoded(), seen.getEncoded());
    }

    @Test
    void tls12CanBeRefused() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, HOST), p -> {});
        TlsClientConnection c = connect(config(null, new Tls12SessionCache()));
        c.allowTls12(false);
        TlsClientConnection.TlsAlertException e = assertThrows(TlsClientConnection.TlsAlertException.class, c::handshake);
        assertEquals(TlsAlert.PROTOCOL_VERSION, e.alert());
    }

    @Test
    void aCertificateForAnotherNameFails() throws Exception {
        serve(TestCerts.CA.issue(KeyType.RSA, "other.test"), p -> {});
        TlsClientConnection c = connect(config(null, new Tls12SessionCache()));
        TlsClientConnection.TlsAlertException e = assertThrows(TlsClientConnection.TlsAlertException.class, c::handshake);
        assertEquals(TlsAlert.BAD_CERTIFICATE, e.alert());
    }
}
