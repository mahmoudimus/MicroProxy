package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.mahmoudimus.http2.FrameWriter;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.HpackDecoder;
import io.github.mahmoudimus.http2.HpackEncoder;
import io.github.mahmoudimus.http2.Http2ClientProfile;
import io.github.mahmoudimus.quic.tls.BrowserProfiles;
import io.github.mahmoudimus.quic.tls.FingerprintSslContext;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.Http2Options;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * With Chrome's TLS and HTTP/2 profiles, the frames a MicroProxy man-in-the-middle proxy opens an
 * HTTP/2 connection to a server with are Chrome 156's, byte for byte where Chrome's are fixed:
 * its SETTINGS, its connection WINDOW_UPDATE, the flags and priority of its first HEADERS, and its
 * pseudo-header order (from {@code quic/src/test/resources/fingerprints/chrome-156/h2-preface-0.bin}).
 */
class BrowserHttp2FingerprintTest {

    /** Chrome 156's SETTINGS frame: 1:65536, 2:0, 4:6291456, 6:262144. */
    private static final String CHROME_SETTINGS = "000018040000000000000100010000000200000000000400600000000600040000";
    /** Chrome 156's connection WINDOW_UPDATE: 15663105. */
    private static final String CHROME_WINDOW_UPDATE = "00000408000000000000ef0001";

    private final CertificateAuthority proxyCa = CertificateAuthority.generate("H2 Fingerprint Proxy CA");
    private final CertificateAuthority originCa = CertificateAuthority.generate("H2 Fingerprint Origin CA");
    private SSLServerSocket origin;
    private HttpProxyServer proxy;

    @AfterEach
    void stop() throws IOException {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.close();
    }

    /** One connection's frames up to the first HEADERS, raw, and that HEADERS' fields. */
    record Seen(List<byte[]> frames, List<HeaderField> fields) {}

    private CompletableFuture<Seen> startOrigin() throws Exception {
        SSLContext tls = originCa.serverContext("localhost", "127.0.0.1");
        origin = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        CompletableFuture<Seen> seen = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try (SSLSocket s = (SSLSocket) origin.accept()) {
                s.setHandshakeApplicationProtocolSelector((sock, offered) -> offered.contains("h2") ? "h2" : null);
                s.startHandshake();
                DataInputStream in = new DataInputStream(s.getInputStream());
                OutputStream raw = s.getOutputStream();
                FrameWriter writer = new FrameWriter(raw);
                in.readFully(new byte[24]);
                writer.writeSettings(java.util.Map.of());
                writer.writeSettingsAck();
                writer.flush();
                List<byte[]> frames = new ArrayList<>();
                HpackDecoder decoder = new HpackDecoder(65_536);
                while (true) {
                    byte[] header = new byte[9];
                    in.readFully(header);
                    int length = ((header[0] & 0xff) << 16) | ((header[1] & 0xff) << 8) | (header[2] & 0xff);
                    byte[] frame = java.util.Arrays.copyOf(header, 9 + length);
                    in.readFully(frame, 9, length);
                    boolean settingsAck = header[3] == 4 && (header[4] & 1) != 0;
                    if (!settingsAck) frames.add(frame);
                    if (header[3] == 1) {
                        int streamId = ((header[5] & 0x7f) << 24) | ((header[6] & 0xff) << 16)
                                | ((header[7] & 0xff) << 8) | (header[8] & 0xff);
                        int offset = 9 + ((header[4] & 0x20) != 0 ? 5 : 0);
                        List<HeaderField> fields = decoder.decode(streamId,
                                java.util.Arrays.copyOfRange(frame, offset, frame.length));
                        writer.writeHeaders(streamId, new HpackEncoder().encode(List.of(new HeaderField(":status", "200"))), false);
                        writer.writeData(streamId, "ok".getBytes(StandardCharsets.US_ASCII), 0, 2, true);
                        writer.flush();
                        seen.complete(new Seen(frames, fields));
                        // let the proxy read the response before the connection goes
                        s.setSoTimeout(2000);
                        try {
                            while (in.read() >= 0) {
                                // drain
                            }
                        } catch (IOException ignored) {
                            // done
                        }
                        return;
                    }
                }
            } catch (Exception e) {
                seen.completeExceptionally(e);
            }
        });
        return seen;
    }

    private static X509TrustManager trusting(CertificateAuthority ca) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("ca", ca.getCertificate());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ks);
        return (X509TrustManager) tmf.getTrustManagers()[0];
    }

    @Test
    void aBrowserProfileGivesTheConnectionItsHttp2FingerprintAndTheRequestItsHeaders() throws Exception {
        CompletableFuture<Seen> seen = startOrigin();
        org.microproxy.tls.BrowserProfile chrome = org.microproxy.tls.BrowserProfile.chrome156();
        // no Http2Options.upstreamProfile: the HTTP/2 profile comes with the TLS socket
        proxy = MicroProxy.bootstrap()
                .withAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, chrome.sslContext(trusting(originCa))))
                .withFiltersSource(chrome.filtersSource(true))
                .start();
        HttpClient client = TestSupport.client(proxy, proxyCa.clientContext());
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create("https://localhost:" + origin.getLocalPort() + "/hello"))
                        .timeout(Duration.ofSeconds(20)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        Seen s = seen.get(10, TimeUnit.SECONDS);
        HexFormat hex = HexFormat.of();
        assertEquals(CHROME_SETTINGS, hex.formatHex(s.frames().get(0)));
        assertEquals(CHROME_WINDOW_UPDATE, hex.formatHex(s.frames().get(1)));
        List<String> names = s.fields().stream().map(HeaderField::name).toList();
        assertEquals(List.of(":method", ":authority", ":scheme", ":path", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "user-agent", "accept"), names.subList(0, 10));
        String userAgent = s.fields().stream().filter(f -> f.name().equals("user-agent")).findFirst().orElseThrow().value();
        assertEquals(chrome.requestHeaders().get(4).getValue(), userAgent);
        assertEquals(false, names.contains("via"));
    }

    @Test
    void theProxysHttp2ConnectionOpensAsChromes() throws Exception {
        CompletableFuture<Seen> seen = startOrigin();
        SSLContext chrome = FingerprintSslContext.builder(BrowserProfiles.chrome156()).trustManager(trusting(originCa)).build();
        proxy = MicroProxy.bootstrap()
                .withAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, chrome))
                .withHttp2Options(Http2Options.builder().upstreamProfile(Http2ClientProfile.chrome156()).build())
                .start();
        HttpClient client = TestSupport.client(proxy, proxyCa.clientContext());
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create("https://localhost:" + origin.getLocalPort() + "/hello"))
                        .timeout(Duration.ofSeconds(20)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertEquals("ok", response.body());

        Seen s = seen.get(10, TimeUnit.SECONDS);
        HexFormat hex = HexFormat.of();
        assertEquals(CHROME_SETTINGS, hex.formatHex(s.frames().get(0)));
        assertEquals(CHROME_WINDOW_UPDATE, hex.formatHex(s.frames().get(1)));
        byte[] headers = s.frames().get(2);
        assertEquals(1, headers[3], "HEADERS");
        // END_HEADERS | PRIORITY, and END_STREAM for a request without a body: Chrome's 37
        assertEquals(37, headers[4]);
        assertEquals("80000000ff", hex.formatHex(headers, 9, 14));
        assertEquals(List.of(":method", ":authority", ":scheme", ":path"),
                s.fields().stream().map(HeaderField::name).filter(n -> n.startsWith(":")).toList());
    }
}
