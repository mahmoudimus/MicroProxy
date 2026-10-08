package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.connect;
import static org.microproxy.ChainTestSupport.connectStatus;
import static org.microproxy.ChainTestSupport.http;
import static org.microproxy.ChainTestSupport.open;
import static org.microproxy.ChainTestSupport.status;

import com.sun.net.httpserver.HttpsServer;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * LittleProxy issue #71 (Issue71NonSslConnectTest): with MITM on, a CONNECT to a server that does
 * not speak TLS (e.g. {@code ws://} through a proxy) falls back to a plain tunnel instead of 502.
 */
class MitmNonTlsServerTest {

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private TestSupport.RawServer plainOrigin;

    @BeforeAll
    static void createAuthorities() {
        proxyCa = CertificateAuthority.generate("Non-TLS Test Proxy CA");
        originCa = CertificateAuthority.generate("Non-TLS Test Origin CA");
    }

    @AfterEach
    void tearDown() {
        proxies.close();
        if (plainOrigin != null) {
            try {
                plainOrigin.close();
            } catch (java.io.IOException ignored) {
                // closing
            }
        }
    }

    /**
     * A plain HTTP/1.1 server that, like Jetty or nginx, answers bytes that cannot start a request
     * (such as a TLS ClientHello) with 400 and closes. (The JDK's own HttpServer instead waits for
     * a line ending that never comes.)
     */
    private static TestSupport.RawServer plainHttpServer() {
        return TestSupport.rawServer(s -> {
            java.io.InputStream in = s.getInputStream();
            int first = in.read();
            if (first < 'A' || first > 'Z') {
                TestSupport.write(s.getOutputStream(),
                        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                return;
            }
            String head = (char) first + TestSupport.readUntil(in, "\r\n\r\n");
            String body = "plain " + head.substring(0, head.indexOf("\r\n"));
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                    + body.length() + "\r\n\r\n" + body);
        });
    }

    private HttpProxyServerBootstrap mitm() {
        return MicroProxy.bootstrap().withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()));
    }

    /** CONNECTs to {@code target} through {@code proxy}, then sends a plaintext GET in the tunnel. */
    private static String plaintextThroughConnect(HttpProxyServer proxy, String target) throws Exception {
        try (Socket s = open(proxy.getListenAddress())) {
            String established = connect(s, target);
            assertEquals(200, status(established), established);
            TestSupport.write(s.getOutputStream(),
                    "GET /ws HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n");
            return new String(s.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
        }
    }

    @Test
    void connectToPlainHttpServerFallsBackToATunnel() throws Exception {
        plainOrigin = plainHttpServer();
        AtomicInteger clientHandshakes = new AtomicInteger();
        HttpProxyServer proxy = proxies.start(mitm().plusActivityTracker(new ActivityTrackerAdapter() {
            @Override
            public void clientSSLHandshakeStarted(FlowContext ctx) {
                clientHandshakes.incrementAndGet();
            }
        }));
        String target = "127.0.0.1:" + plainOrigin.port();
        String response = plaintextThroughConnect(proxy, target);
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        // The tunnel is raw: the origin's answer arrives untouched (no Via from the proxy).
        assertTrue(response.endsWith("\r\n\r\nplain GET /ws HTTP/1.1"), response);
        assertTrue(!response.toLowerCase().contains("via:"), response);
        assertEquals(0, clientHandshakes.get(), "the proxy must not start TLS with the client");
    }

    @Test
    void connectToPlainServerThroughChainedProxyFallsBackToATunnel() throws Exception {
        plainOrigin = plainHttpServer();
        ChainTestSupport.RequestLog upstreamLog = new ChainTestSupport.RequestLog();
        HttpProxyServer upstream = proxies.start(MicroProxy.bootstrap().plusActivityTracker(upstreamLog));
        HttpProxyServer proxy = proxies.start(mitm().withChainProxyManager(always(http(upstream.getListenAddress()))));
        String target = "127.0.0.1:" + plainOrigin.port();
        String response = plaintextThroughConnect(proxy, target);
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        // One CONNECT for the failed TLS attempt, one for the tunnel.
        assertEquals(List.of("CONNECT " + target, "CONNECT " + target), upstreamLog.received);
    }

    @Test
    void untrustedTlsServerIsStillRejectedRatherThanTunnelled() throws Exception {
        CertificateAuthority unknown = CertificateAuthority.generate("Unknown CA");
        HttpsServer secure = TestSupport.httpsOrigin(unknown.serverContext("127.0.0.1"), TestSupport.echo());
        try {
            HttpProxyServer proxy = proxies.start(mitm());
            assertEquals(502, connectStatus(proxy.getListenAddress(), "127.0.0.1:" + secure.getAddress().getPort()));
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void tlsServerIsStillIntercepted() {
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), TestSupport.echo());
        try {
            HttpProxyServer proxy = proxies.start(mitm());
            var response = TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()), TestSupport.url(secure, "/tls"));
            assertEquals(200, response.statusCode());
            assertEquals("/tls", TestSupport.echoedUri(response.body()));
        } finally {
            secure.stop(0);
        }
    }
}
