package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.connect;
import static org.microproxy.ChainTestSupport.http;
import static org.microproxy.ChainTestSupport.open;
import static org.microproxy.ChainTestSupport.socks;
import static org.microproxy.ChainTestSupport.status;

import java.io.InputStream;
import java.net.Socket;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Where an outgoing PROXY header goes when requests are chained, matching LittleProxy
 * (ProxyProtocolHttpConnectChainedProxyTest, Socks4/5ChainedProxyWithMissConfiguredSendProxyProtocolTest):
 * the header must reach the final server, so it is tunnelled after an HTTP chained proxy accepts
 * the CONNECT, and skipped when there is no tunnel to the final server (SOCKS, or a plain request
 * forwarded to an HTTP chained proxy).
 */
class ProxyProtocolChainTest {

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();

    @AfterEach
    void tearDown() {
        proxies.close();
    }

    private HttpProxyServer downstream(ChainedProxyManager chain) {
        return proxies.start(MicroProxy.bootstrap().withSendProxyProtocol(true).withChainProxyManager(chain));
    }

    /** A plain origin that records the head of the first request on each connection. */
    private static TestSupport.RawServer recordingOrigin(List<String> heads) {
        return TestSupport.rawServer(s -> {
            heads.add(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n"));
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });
    }

    private static String expectedHeader(Socket client, HttpProxyServer proxy) {
        return "PROXY TCP4 127.0.0.1 127.0.0.1 " + client.getLocalPort() + " " + proxy.getListenAddress().getPort() + "\r\n";
    }

    /** Opens a CONNECT tunnel to {@code origin} through {@code proxy} and sends a GET in it. */
    private static String getThroughTunnel(Socket s, TestSupport.RawServer origin) throws Exception {
        String target = "127.0.0.1:" + origin.port();
        String established = connect(s, target);
        assertEquals(200, status(established), established);
        TestSupport.write(s.getOutputStream(), "GET /t HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
        return TestSupport.readUntil(s.getInputStream(), "ok");
    }

    @Test
    void directTunnelGetsTheHeaderFirst() throws Exception {
        List<String> heads = new java.util.concurrent.CopyOnWriteArrayList<>();
        try (TestSupport.RawServer origin = recordingOrigin(heads)) {
            HttpProxyServer proxy = downstream(always(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION));
            try (Socket s = open(proxy.getListenAddress())) {
                getThroughTunnel(s, origin);
                assertEquals(List.of(expectedHeader(s, proxy) + "GET /t HTTP/1.1\r\nHost: 127.0.0.1:" + origin.port() + "\r\n\r\n"), heads);
            }
        }
    }

    @Test
    void headerIsTunnelledThroughHttpConnectChainedProxy() throws Exception {
        List<String> heads = new java.util.concurrent.CopyOnWriteArrayList<>();
        try (TestSupport.RawServer origin = recordingOrigin(heads);
                ChainTestSupport.RecordingConnectProxy intermediate = new ChainTestSupport.RecordingConnectProxy()) {
            HttpProxyServer proxy = downstream(always(http(intermediate.address())));
            try (Socket s = open(proxy.getListenAddress())) {
                getThroughTunnel(s, origin);
                assertEquals(1, intermediate.firstHeads.size());
                String intermediateSaw = intermediate.firstHeads.get(0);
                assertTrue(intermediateSaw.startsWith("CONNECT 127.0.0.1:" + origin.port() + " HTTP/1.1\r\n"), intermediateSaw);
                assertFalse(intermediateSaw.contains("PROXY"), intermediateSaw);
                assertEquals(1, heads.size());
                assertTrue(heads.get(0).startsWith(expectedHeader(s, proxy) + "GET /t HTTP/1.1\r\n"), heads.get(0));
            }
        }
    }

    @Test
    void plainRequestToHttpChainedProxyCarriesNoHeader() throws Exception {
        List<String> heads = new java.util.concurrent.CopyOnWriteArrayList<>();
        try (TestSupport.RawServer origin = recordingOrigin(heads)) {
            // The upstream does not accept the PROXY protocol: a header sent to it would be a bad request.
            HttpProxyServer upstream = proxies.start(MicroProxy.bootstrap());
            HttpProxyServer proxy = downstream(always(http(upstream.getListenAddress())));
            HttpResponse<String> response = TestSupport.get(TestSupport.client(proxy), "http://127.0.0.1:" + origin.port() + "/p");
            assertEquals(200, response.statusCode());
            assertEquals(1, heads.size());
            assertTrue(heads.get(0).startsWith("GET /p HTTP/1.1\r\n"), heads.get(0));
        }
    }

    @Test
    void socks4ChainedProxyCarriesNoHeader() throws Exception {
        socksChainedProxyCarriesNoHeader(ChainedProxyType.SOCKS4);
    }

    @Test
    void socks5ChainedProxyCarriesNoHeader() throws Exception {
        socksChainedProxyCarriesNoHeader(ChainedProxyType.SOCKS5);
    }

    private void socksChainedProxyCarriesNoHeader(ChainedProxyType type) throws Exception {
        List<String> heads = new java.util.concurrent.CopyOnWriteArrayList<>();
        try (TestSupport.RawServer origin = recordingOrigin(heads); SocksServer socksServer = new SocksServer(null, null)) {
            HttpProxyServer proxy = downstream(always(socks(socksServer.address(), type, null, null)));
            HttpResponse<String> response = TestSupport.get(TestSupport.client(proxy), "http://127.0.0.1:" + origin.port() + "/s");
            assertEquals(200, response.statusCode());
            assertEquals("ok", response.body());
            try (Socket s = open(proxy.getListenAddress())) {
                getThroughTunnel(s, origin);
            }
            assertEquals(2, heads.size());
            assertTrue(heads.get(0).startsWith("GET /s HTTP/1.1\r\n"), heads.get(0));
            assertTrue(heads.get(1).startsWith("GET /t HTTP/1.1\r\n"), heads.get(1));
            assertEquals(2, socksServer.targets.size());
        }
    }

    @Test
    void mitmOverHttpChainSendsTheHeaderBeforeTheServerTlsHandshake() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("PROXY Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("PROXY Proxy CA");
        SSLContext serverContext = originCa.serverContext("127.0.0.1");
        CompletableFuture<String> headerSeen = new CompletableFuture<>();
        CompletableFuture<String> requestSeen = new CompletableFuture<>();
        // A TLS origin behind a PROXY-protocol-aware front: cleartext PROXY line, then TLS.
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
                    InputStream in = s.getInputStream();
                    headerSeen.complete(TestSupport.readUntil(in, "\r\n"));
                    SSLSocket tls = (SSLSocket) serverContext.getSocketFactory().createSocket(s, null, true);
                    tls.setUseClientMode(false);
                    requestSeen.complete(TestSupport.readUntil(tls.getInputStream(), "\r\n\r\n"));
                    TestSupport.write(tls.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret");
                });
                ChainTestSupport.RecordingConnectProxy intermediate = new ChainTestSupport.RecordingConnectProxy()) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSendProxyProtocol(true)
                    .withChainProxyManager(always(http(intermediate.address())))
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())));
            HttpResponse<String> response = TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()),
                    "https://127.0.0.1:" + origin.port() + "/m");
            assertEquals(200, response.statusCode());
            assertEquals("secret", response.body());
            assertTrue(headerSeen.get(5, TimeUnit.SECONDS).matches(
                    "PROXY TCP4 127\\.0\\.0\\.1 127\\.0\\.0\\.1 \\d+ " + proxy.getListenAddress().getPort() + "\r\n"),
                    headerSeen.get());
            assertTrue(requestSeen.get(5, TimeUnit.SECONDS).startsWith("GET /m HTTP/1.1\r\n"), requestSeen.get());
            assertEquals(1, intermediate.firstHeads.size());
            assertTrue(intermediate.firstHeads.get(0).startsWith("CONNECT "), intermediate.firstHeads.get(0));
        }
    }
}
