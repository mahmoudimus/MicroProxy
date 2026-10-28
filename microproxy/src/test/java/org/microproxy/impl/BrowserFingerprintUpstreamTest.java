package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.github.mahmoudimus.quic.tls.BrowserProfiles;
import io.github.mahmoudimus.quic.tls.FingerprintSslContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.ClientHello;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.extras.TlsFingerprints;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * A man-in-the-middle proxy whose upstream SSLContext is {@link FingerprintSslContext} with the
 * Chrome 156 profile: the origin receives Chrome 156's ClientHello from the proxy, read by the
 * proxy's own parser, and the request goes through.
 */
class BrowserFingerprintUpstreamTest {

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;
    private final List<ClientHello> hellos = new CopyOnWriteArrayList<>();
    private ServerSocket origin;
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("Fingerprint Proxy CA");
        originCa = CertificateAuthority.generate("Fingerprint Origin CA");
    }

    @AfterEach
    void stop() throws IOException {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.close();
    }

    /** An HTTPS origin that keeps each connection's ClientHello, then answers {@code 200 ok} over HTTP/1.1. */
    private void startOrigin() throws IOException {
        origin = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        SSLContext tls = originCa.serverContext("localhost", "127.0.0.1");
        Thread.ofVirtual().start(() -> {
            while (!origin.isClosed()) {
                try {
                    Socket plain = origin.accept();
                    Thread.ofVirtual().start(() -> serve(plain, tls));
                } catch (IOException e) {
                    return;
                }
            }
        });
    }

    private void serve(Socket plain, SSLContext tls) {
        try (plain) {
            DataInputStream in = new DataInputStream(plain.getInputStream());
            ByteArrayOutputStream raw = new ByteArrayOutputStream();
            ByteArrayOutputStream message = new ByteArrayOutputStream();
            int need = -1;
            while (need < 0 || message.size() < need) {
                byte[] header = new byte[5];
                in.readFully(header);
                byte[] fragment = new byte[((header[3] & 0xff) << 8) | (header[4] & 0xff)];
                in.readFully(fragment);
                raw.write(header);
                raw.write(fragment);
                message.write(fragment);
                byte[] m = message.toByteArray();
                if (need < 0 && m.length >= 4) need = 4 + (((m[1] & 0xff) << 16) | ((m[2] & 0xff) << 8) | (m[3] & 0xff));
            }
            hellos.add(TlsClientHello.parse(message.toByteArray()));
            SSLSocket s = (SSLSocket) tls.getSocketFactory().createSocket(plain, new ByteArrayInputStream(raw.toByteArray()), true);
            s.setUseClientMode(false);
            s.setHandshakeApplicationProtocolSelector((sock, offered) -> offered.contains("http/1.1") ? "http/1.1" : null);
            s.startHandshake();
            InputStream body = s.getInputStream();
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            while (!head.toString(StandardCharsets.ISO_8859_1).endsWith("\r\n\r\n")) {
                int b = body.read();
                if (b < 0) return;
                head.write(b);
            }
            OutputStream out = s.getOutputStream();
            out.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
        } catch (IOException | TlsClientHello.Malformed e) {
            // the test fails on the missing hello or response
        }
    }

    private static X509TrustManager trusting(CertificateAuthority ca) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("ca", ca.getCertificate());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ks);
        return (X509TrustManager) tmf.getTrustManagers()[0];
    }

    private String fetchThroughProxy(HttpProxyServerBootstrap bootstrap) throws Exception {
        SSLContext chrome = FingerprintSslContext.builder(BrowserProfiles.chrome156()).trustManager(trusting(originCa)).build();
        proxy = bootstrap.withAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, chrome))
                .start();
        HttpClient client = TestSupport.client(proxy, proxyCa.clientContext());
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create("https://localhost:" + origin.getLocalPort() + "/hello"))
                        .timeout(Duration.ofSeconds(20)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        return response.body();
    }

    @Test
    void byDefaultTheOriginGetsChromesExactHello() throws Exception {
        startOrigin();
        // HTTP/2 upstream is on by default, so the proxy offers h2 and http/1.1, as Chrome does
        assertEquals("ok", fetchThroughProxy(MicroProxy.bootstrap()));
        assertEquals(1, hellos.size());
        ClientHello hello = hellos.get(0);
        assertEquals("localhost", hello.sni());
        assertEquals(List.of("h2", "http/1.1"), hello.alpnProtocols());
        assertEquals("t13d1517h2_8daaf6152771_cb7bf5808d99", TlsFingerprints.ja4(hello));
    }

    @Test
    void withHttp1OnlyUpstreamsOnlyTheAlpnPartDiffers() throws Exception {
        startOrigin();
        assertEquals("ok", fetchThroughProxy(MicroProxy.bootstrap().withHttp2Upstream(false)));
        ClientHello hello = hellos.get(0);
        assertNotNull(hello);
        assertEquals(List.of("http/1.1"), hello.alpnProtocols());
        assertEquals("t13d1517h1_8daaf6152771_cb7bf5808d99", TlsFingerprints.ja4(hello));
    }
    @Test
    void aResumedConnectionsHelloHasChromesJa3Too() throws Exception {
        startOrigin();
        proxy = MicroProxy.bootstrap().withAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa,
                        FingerprintSslContext.builder(BrowserProfiles.chrome156()).trustManager(trusting(originCa)).build()))
                .start();
        // the origin closes each connection, so the second request makes a new one, resuming the first's session
        for (int i = 0; i < 2; i++) {
            HttpResponse<String> response = TestSupport.client(proxy, proxyCa.clientContext()).send(
                    HttpRequest.newBuilder(URI.create("https://localhost:" + origin.getLocalPort() + "/hello"))
                            .timeout(Duration.ofSeconds(20)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals("ok", response.body());
        }
        assertEquals(2, hellos.size());
        assertEquals(Chrome156FingerprintTest.CHROME_156_JA3, Chrome156FingerprintTest.unshuffledJa3(hellos.get(0)));
        assertEquals(Chrome156FingerprintTest.CHROME_156_RESUMED_JA3, Chrome156FingerprintTest.unshuffledJa3(hellos.get(1)));
    }
}
