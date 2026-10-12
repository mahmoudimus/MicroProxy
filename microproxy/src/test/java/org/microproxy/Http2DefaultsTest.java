package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * HTTP/2 to clients and to servers is on by default, with no flag, bootstrap call or property: a
 * client offering {@code h2} through the intercepting proxy or on its TLS listener gets it, and a
 * server offering {@code h2} is spoken to in it. {@code withHttp2(false)} / {@code --no-http2} /
 * {@code http2=false} and {@code withHttp2Upstream(false)} / {@code --no-http2-upstream} / {@code
 * http2_upstream=false} turn each side off on its own. (Without the codec the defaults fall back
 * to HTTP/1.1: {@code Http2CodecAbsentTest}.)
 */
class Http2DefaultsTest {

    private static final CertificateAuthority originCa = CertificateAuthority.generate("H2 Defaults Origin CA");
    private static final CertificateAuthority proxyCa = CertificateAuthority.generate("H2 Defaults Proxy CA");

    private final List<AutoCloseable> closeables = new ArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables.reversed()) c.close();
    }

    private HttpProxyServer start(HttpProxyServerBootstrap bootstrap) {
        HttpProxyServer proxy = bootstrap.start();
        closeables.add(proxy::abort);
        return proxy;
    }

    private static HttpProxyServerBootstrap mitm() {
        return MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()));
    }

    /** An HTTP/1.1-only HTTPS origin (the JDK's server negotiates no ALPN). */
    private HttpsServer http1Origin() {
        HttpsServer origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"),
                TestSupport.fixed(200, "from the origin"));
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    /**
     * An origin that offers {@code h2} and {@code http/1.1}, and says in its body which one the
     * proxy picked.
     */
    private H2TestOrigin dualOrigin() throws IOException {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.http1Handler = socket -> {
            TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
            TestSupport.write(socket.getOutputStream(),
                    "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nhttp/1.1");
        };
        H2TestOrigin origin = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"), options, s -> {
            s.readBody();
            s.respond(200, false, "content-length", "2");
            s.data("h2".getBytes(StandardCharsets.US_ASCII), true);
        });
        closeables.add(origin);
        return origin;
    }

    private static HttpResponse<String> get(HttpClient client, String url) {
        return TestSupport.send(client, HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20)).build());
    }

    @Test
    void aClientOfferingH2GetsItThroughTheInterceptingProxy() {
        HttpsServer origin = http1Origin();
        HttpProxyServer proxy = start(mitm());
        HttpResponse<String> response = get(Http2ProxyTest.h2Client(proxy, proxyCa.clientContext()),
                TestSupport.localhostUrl(origin, "/"));
        assertEquals(200, response.statusCode());
        assertEquals("from the origin", response.body());
        assertEquals(HttpClient.Version.HTTP_2, response.version(), "h2 to the client, HTTP/1.1 to the server");
        // A client offering only HTTP/1.1 keeps it.
        HttpResponse<String> http1 = get(TestSupport.client(proxy, proxyCa.clientContext()),
                TestSupport.localhostUrl(origin, "/"));
        assertEquals(HttpClient.Version.HTTP_1_1, http1.version());
        assertEquals("from the origin", http1.body());
    }

    @Test
    void withHttp2FalseClientsGetHttp1() {
        HttpsServer origin = http1Origin();
        HttpProxyServer proxy = start(mitm().withHttp2(false));
        HttpResponse<String> response = get(Http2ProxyTest.h2Client(proxy, proxyCa.clientContext()),
                TestSupport.localhostUrl(origin, "/"));
        assertEquals("from the origin", response.body());
        assertEquals(HttpClient.Version.HTTP_1_1, response.version());
    }

    @Test
    void aServerOfferingH2IsSpokenToInItByDefault() throws IOException {
        H2TestOrigin origin = dualOrigin();
        HttpProxyServer proxy = start(mitm());
        // An HTTP/1.1 client: the server side is independent of the client side.
        HttpResponse<String> response = get(TestSupport.client(proxy, proxyCa.clientContext()), origin.url("/"));
        assertEquals(200, response.statusCode());
        assertEquals("h2", response.body());
        assertEquals(HttpClient.Version.HTTP_1_1, response.version());
        // And HTTP/2 end to end for a client that offers it.
        HttpResponse<String> h2 = get(Http2ProxyTest.h2Client(proxy, proxyCa.clientContext()), origin.url("/"));
        assertEquals("h2", h2.body());
        assertEquals(HttpClient.Version.HTTP_2, h2.version());
    }

    @Test
    void withHttp2UpstreamFalseServersGetHttp1() throws IOException {
        H2TestOrigin origin = dualOrigin();
        HttpProxyServer proxy = start(mitm().withHttp2Upstream(false));
        HttpResponse<String> response = get(TestSupport.client(proxy, proxyCa.clientContext()), origin.url("/"));
        assertEquals("http/1.1", response.body());
        // The client side stays on: an h2 client still gets HTTP/2 from the proxy.
        HttpResponse<String> h2 = get(Http2ProxyTest.h2Client(proxy, proxyCa.clientContext()), origin.url("/"));
        assertEquals("http/1.1", h2.body());
        assertEquals(HttpClient.Version.HTTP_2, h2.version());
    }

    @Test
    void theTlsListenerOffersH2ByDefault() throws Exception {
        CertificateAuthority listenerCa = CertificateAuthority.generate("H2 Defaults Listener CA");
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withPort(0)
                .withSslContextSource(() -> listenerCa.serverContext("localhost", "127.0.0.1"))
                .withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                    @Override
                    public org.microproxy.http.HttpResponse clientToProxyRequest(org.microproxy.http.HttpObject o) {
                        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                                "listener".getBytes(StandardCharsets.UTF_8));
                    }
                });
        HttpProxyServer on = start(bootstrap);
        try (H2TestClient c = H2TestClient.directTls(on.getListenAddress(), "example.com", listenerCa.clientContext())
                .handshake()) {
            c.get(1, "/");
            assertEquals("listener", c.response(1).text());
        }
        HttpProxyServer off = start(bootstrap.withHttp2(false));
        assertEquals("", negotiated(off, listenerCa, "h2", "http/1.1"), "no ALPN answer: HTTP/1.1");
    }

    /** The ALPN protocol the proxy's TLS listener picks for a client offering {@code offered}. */
    private static String negotiated(HttpProxyServer proxy, CertificateAuthority ca, String... offered)
            throws IOException {
        try (SSLSocket s = (SSLSocket) ca.clientContext().getSocketFactory().createSocket(
                proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            SSLParameters parameters = s.getSSLParameters();
            parameters.setApplicationProtocols(offered);
            s.setSSLParameters(parameters);
            s.startHandshake();
            return s.getApplicationProtocol();
        }
    }

    // --- the launcher and properties ----------------------------------------------------------------

    private HttpProxyServer launch(String... args) throws IOException {
        HttpProxyServer proxy = Launcher.start(args, new PrintStream(new ByteArrayOutputStream(), true,
                StandardCharsets.UTF_8));
        closeables.add(proxy::abort);
        return proxy;
    }

    /** What the h2 client and the origin got through a launched proxy: "client version / origin protocol". */
    private String through(HttpProxyServer proxy, Path ca, H2TestOrigin origin) throws IOException {
        CertificateAuthority launcherCa = CertificateAuthority.load(ca, "microproxy".toCharArray());
        HttpResponse<String> response = get(Http2ProxyTest.h2Client(proxy, launcherCa.clientContext()), origin.url("/"));
        assertEquals(200, response.statusCode());
        return response.version() + " / " + response.body();
    }

    @Test
    void theLauncherSpeaksHttp2BothWaysUnlessToldNotTo(@TempDir Path dir) throws IOException {
        H2TestOrigin origin = dualOrigin();
        Path ca = dir.resolve("ca.p12");
        String[] mitm = {"--port", "0", "--mitm", "--mitm-ca", ca.toString(), "--mitm-trust-all"};
        assertEquals("HTTP_2 / h2", through(launch(mitm), ca, origin), "no flag");
        assertEquals("HTTP_1_1 / h2", through(launch(with(mitm, "--no-http2")), ca, origin));
        assertEquals("HTTP_2 / http/1.1", through(launch(with(mitm, "--no-http2-upstream")), ca, origin));
        assertEquals("HTTP_1_1 / http/1.1", through(launch(with(mitm, "--no-http2", "--no-http2-upstream")), ca, origin));
        assertEquals("HTTP_2 / h2", through(launch(with(mitm, "--http2", "--http2-upstream")), ca, origin));
    }

    @Test
    void propertiesTurnHttp2OffAndFlagsTurnItBackOn(@TempDir Path dir) throws IOException {
        H2TestOrigin origin = dualOrigin();
        Path ca = dir.resolve("ca.p12");
        Path props = dir.resolve("proxy.properties");
        Files.writeString(props, "port=0\nhttp2=false\nhttp2_upstream=false\n");
        String[] mitm = {"--config", props.toString(), "--mitm", "--mitm-ca", ca.toString(), "--mitm-trust-all"};
        assertEquals("HTTP_1_1 / http/1.1", through(launch(mitm), ca, origin));
        assertEquals("HTTP_2 / h2", through(launch(with(mitm, "--http2", "--http2-upstream")), ca, origin),
                "flags override the file");
        Files.writeString(props, "port=0\nhttp2=true\nhttp2_upstream=true\n");
        assertEquals("HTTP_2 / h2", through(launch(mitm), ca, origin));
    }

    private static String[] with(String[] args, String... more) {
        List<String> all = new ArrayList<>(List.of(args));
        all.addAll(List.of(more));
        return all.toArray(String[]::new);
    }
}
