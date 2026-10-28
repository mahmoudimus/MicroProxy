package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** {@link FingerprintSslContext} used as JSSE callers, MicroProxy's {@code Tls.clientHandshake} among them, use one. */
class FingerprintSslContextTest {

    private static final String HOST = "tls.test";

    private ServerSocket server;

    @AfterEach
    void close() throws IOException {
        if (server != null) server.close();
    }

    private CompletableFuture<SSLSocket> serveTls(CertifiedKey key, Consumer<SSLParameters> params) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("k", key.privateKey(), new char[0], key.chain().toArray(X509Certificate[]::new));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(ks, new char[0]);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
        SSLServerSocket s = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        SSLParameters p = s.getSSLParameters();
        p.setProtocols(new String[] {"TLSv1.3"});
        params.accept(p);
        s.setSSLParameters(p);
        server = s;
        CompletableFuture<SSLSocket> accepted = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try (SSLSocket c = (SSLSocket) s.accept()) {
                c.setHandshakeApplicationProtocolSelector((sock, offered) -> offered.isEmpty() ? null : offered.get(0));
                c.startHandshake();
                accepted.complete(c);
                InputStream in = c.getInputStream();
                OutputStream out = c.getOutputStream();
                byte[] buf = new byte[4096];
                for (int n; (n = in.read(buf)) > 0; ) {
                    out.write(buf, 0, n);
                    out.flush();
                }
            } catch (IOException e) {
                accepted.completeExceptionally(e);
            }
        });
        return accepted;
    }

    /** A plain server that reads the whole ClientHello record, writes {@code reply} and closes, resetting if asked. */
    private void servePlain(byte[] reply, boolean reset) throws IOException {
        server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        ServerSocket s = server;
        Thread.ofVirtual().start(() -> {
            try (Socket c = s.accept()) {
                java.io.DataInputStream in = new java.io.DataInputStream(c.getInputStream());
                byte[] header = new byte[5];
                in.readFully(header);
                in.readFully(new byte[((header[3] & 0xff) << 8) | (header[4] & 0xff)]);
                c.getOutputStream().write(reply);
                c.getOutputStream().flush();
                if (reset) c.setSoLinger(true, 0);
            } catch (IOException ignored) {
                // the client gave up
            }
        });
    }

    private void servePlain(byte[] reply) throws IOException {
        servePlain(reply, false);
    }

    private static X509TrustManager pkix(X509Certificate anchor) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("ca", anchor);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ks);
        return (X509TrustManager) tmf.getTrustManagers()[0];
    }

    /** Opens a plain connection and layers a socket on it, configured as MicroProxy's Tls.clientHandshake does. */
    private SSLSocket layered(SSLContext ctx, String sni, List<String> alpn) throws IOException {
        Socket plain = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
        plain.setSoTimeout(10_000);
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(plain, HOST, server.getLocalPort(), true);
        socket.setUseClientMode(true);
        socket.setEnabledProtocols(new String[] {"TLSv1.3"});
        SSLParameters params = socket.getSSLParameters();
        params.setServerNames(sni == null ? List.of() : List.of(new SNIHostName(sni)));
        params.setEndpointIdentificationAlgorithm("HTTPS");
        params.setApplicationProtocols(alpn.toArray(String[]::new));
        socket.setSSLParameters(params);
        return socket;
    }

    private static SSLContext chrome(X509TrustManager trust) {
        return FingerprintSslContext.builder(BrowserProfiles.chrome156()).trustManager(trust).build();
    }

    @Test
    void handshakesAndCarriesDataLikeAJdkSocket() throws Exception {
        CompletableFuture<SSLSocket> accepted = serveTls(TestCerts.CA.issue(KeyType.P256, HOST), p -> {});
        SSLContext ctx = chrome(pkix(TestCerts.CA.certificate));
        try (SSLSocket socket = layered(ctx, HOST, List.of("h2", "http/1.1"))) {
            socket.startHandshake();
            assertEquals("h2", socket.getApplicationProtocol());
            assertEquals("TLSv1.3", socket.getSession().getProtocol());
            assertEquals(HOST, ((ExtendedSSLSession) socket.getSession()).getRequestedServerNames().stream()
                    .map(n -> ((SNIHostName) n).getAsciiName()).findFirst().orElseThrow());
            socket.getOutputStream().write("ping".getBytes(StandardCharsets.US_ASCII));
            byte[] got = socket.getInputStream().readNBytes(4);
            assertArrayEquals("ping".getBytes(StandardCharsets.US_ASCII), got);
            X509Certificate leaf = (X509Certificate) socket.getSession().getPeerCertificates()[0];
            assertTrue(leaf.getSubjectX500Principal().getName().contains(HOST));
        }
        assertEquals("TLSv1.3", accepted.get(5, TimeUnit.SECONDS).getSession().getProtocol());
    }

    @Test
    void anUnrecognizedNameAlertReadsAsTheJdksDoes() throws Exception {
        SNIMatcher never = new SNIMatcher(0) {
            @Override
            public boolean matches(SNIServerName name) {
                return false;
            }
        };
        serveTls(TestCerts.CA.issue(KeyType.P256, HOST), p -> p.setSNIMatchers(List.of(never)));
        try (SSLSocket socket = layered(chrome(pkix(TestCerts.CA.certificate)), HOST, List.of("h2"))) {
            SSLHandshakeException e = assertThrows(SSLHandshakeException.class, socket::startHandshake);
            assertEquals("Received fatal alert: unrecognized_name", e.getMessage());
        }
    }

    @Test
    void aPlaintextServerIsAnUnrecognizedSslMessage() throws Exception {
        servePlain("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        try (SSLSocket socket = layered(chrome(pkix(TestCerts.CA.certificate)), HOST, List.of("h2"))) {
            SSLException e = assertThrows(SSLException.class, socket::startHandshake);
            assertEquals("Unsupported or unrecognized SSL message", e.getMessage());
        }
    }

    @Test
    void aServerThatHangsUpTerminatedTheHandshake() throws Exception {
        servePlain(new byte[0]);
        try (SSLSocket socket = layered(chrome(pkix(TestCerts.CA.certificate)), HOST, List.of("h2"))) {
            SSLHandshakeException e = assertThrows(SSLHandshakeException.class, socket::startHandshake);
            assertEquals("Remote host terminated the handshake", e.getMessage());
            assertInstanceOf(EOFException.class, e.getCause());
        }
    }

    @Test
    void aResetIsAConnectionResetSslException() throws Exception {
        servePlain(new byte[0], true);
        try (SSLSocket socket = layered(chrome(pkix(TestCerts.CA.certificate)), HOST, List.of("h2"))) {
            SSLException e = assertThrows(SSLException.class, socket::startHandshake);
            assertInstanceOf(java.net.SocketException.class, e.getCause());
            assertTrue(String.valueOf(e.getMessage()).toLowerCase().contains("reset"), e.getMessage());
        }
    }

    @Test
    void aNameMismatchHasTheJdksCertificateExceptionAsItsCause() throws Exception {
        serveTls(TestCerts.CA.issue(KeyType.P256, "other.test"), p -> {});
        try (SSLSocket socket = layered(chrome(pkix(TestCerts.CA.certificate)), HOST, List.of("h2"))) {
            SSLHandshakeException e = assertThrows(SSLHandshakeException.class, socket::startHandshake);
            Throwable cause = rootOf(e, CertificateException.class);
            assertNotNull(cause, "no CertificateException in " + e);
            assertTrue(cause.getMessage().startsWith("No subject alternative names matching DNS name " + HOST));
        }
    }

    @Test
    void anUntrustedCertificateHasThePkixFailureAsItsCause() throws Exception {
        serveTls(TestCerts.OTHER_CA.issue(KeyType.P256, HOST), p -> {});
        try (SSLSocket socket = layered(chrome(pkix(TestCerts.CA.certificate)), HOST, List.of("h2"))) {
            SSLHandshakeException e = assertThrows(SSLHandshakeException.class, socket::startHandshake);
            assertNotNull(rootOf(e, CertificateException.class), "no CertificateException in " + e);
            // the PKIX failure MicroProxy reads as an untrusted certificate
            assertTrue(rootOf(e, CertPathBuilderException.class) != null || rootOf(e, CertPathValidatorException.class) != null,
                    "no certification path failure in " + e);
            // the session of a failed socket is the JDK's null session
            assertEquals("NONE", socket.getSession().getProtocol());
        }
    }

    @Test
    void onlyTls13CanBeEnabledForNow() throws Exception {
        servePlain(new byte[0]);
        try (SSLSocket socket = layered(chrome(pkix(TestCerts.CA.certificate)), HOST, List.of("h2"))) {
            assertArrayEquals(new String[] {"TLSv1.3"}, socket.getSupportedProtocols());
            assertThrows(IllegalArgumentException.class, () -> socket.setEnabledProtocols(new String[] {"TLSv1.2"}));
            assertThrows(IllegalArgumentException.class, () -> socket.setUseClientMode(false));
        }
    }

    private static Throwable rootOf(Throwable t, Class<? extends Throwable> type) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (type.isInstance(c)) return c;
        }
        return null;
    }
}
