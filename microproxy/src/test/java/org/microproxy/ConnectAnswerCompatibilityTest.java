package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.readUntil;
import static org.microproxy.TestSupport.url;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The proxy's {@code 200 Connection established}: response filters see it by default, and, as in
 * LittleProxy (ClientToProxyConnection.RespondCONNECTSuccessful writes it straight to the
 * channel), not with {@code withLittleProxyCompatibility()}; trackers see it either way.
 */
class ConnectAnswerCompatibilityTest {

    /** Records every hook, and the hooks only MicroProxy has; may refuse the CONNECT's answer. */
    private static final class Filters extends RecordingFilters {
        private final boolean refuseConnect;

        Filters(List<String> events, boolean refuseConnect) {
            super(events);
            this.refuseConnect = refuseConnect;
        }

        @Override
        public HttpObject proxyToClientResponse(HttpObject httpObject) {
            super.proxyToClientResponse(httpObject);
            if (refuseConnect && httpObject instanceof HttpResponse r && r.status().code() == 200) {
                return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN);
            }
            return httpObject;
        }

        @Override
        public void proxyToClientResponseSent(HttpResponse response, ResponseSource source) {
            events.add("proxyToClientResponseSent:" + response.status().code());
        }

        @Override
        public void exchangeEnded(boolean completed) {
            events.add("exchangeEnded:" + completed);
        }
    }

    /** The events of each request's filters, by method. */
    private final Map<String, List<String>> events = new ConcurrentHashMap<>();
    /** The statuses of the responses trackers were told were sent, and completed. */
    private final List<String> sent = new CopyOnWriteArrayList<>();
    private final List<String> completed = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;
    private TestSupport.RawServer tunnelEcho;

    @BeforeEach
    void setUp() {
        tunnelEcho = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()));
    }

    @AfterEach
    void tearDown() throws IOException {
        if (proxy != null) proxy.abort();
        tunnelEcho.close();
    }

    private HttpProxyServerBootstrap bootstrap(boolean compatible, boolean refuseConnect) {
        return MicroProxy.bootstrap().withPort(0).withLittleProxyCompatibility(compatible)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest request, FlowContext ctx) {
                        return new Filters(events.computeIfAbsent(request.method().name(),
                                m -> new CopyOnWriteArrayList<>()), refuseConnect);
                    }
                })
                .plusActivityTracker(new ActivityTracker() {
                    @Override
                    public void responseSentToClient(FlowContext flowContext, HttpResponse response) {
                        sent.add(String.valueOf(response.status().code()));
                    }

                    @Override
                    public void responseCompleted(FlowContext flowContext, HttpResponse response) {
                        completed.add(String.valueOf(response.status().code()));
                    }
                });
    }

    /** Opens a tunnel to the echo server; returns the CONNECT's response head, and checks the tunnel when it is a 200. */
    private String tunnel() throws IOException {
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(20_000);
            String target = "127.0.0.1:" + tunnelEcho.port();
            write(s.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
            String head = readUntil(s.getInputStream(), "\r\n\r\n");
            if (head.startsWith("HTTP/1.1 200")) {
                write(s.getOutputStream(), "ping");
                assertEquals("ping", new String(s.getInputStream().readNBytes(4), java.nio.charset.StandardCharsets.US_ASCII));
            }
            return head;
        }
    }

    private List<String> connectEvents() {
        return events.getOrDefault("CONNECT", List.of());
    }

    @Test
    void byDefaultResponseFiltersSeeTheConnectAnswer() throws Exception {
        proxy = bootstrap(false, false).start();
        assertTrue(tunnel().startsWith("HTTP/1.1 200 Connection established"));
        eventually("the tunnel's end", () -> connectEvents().contains("exchangeEnded:true"));
        List<String> connect = connectEvents();
        assertTrue(connect.contains("serverToProxyResponse:full"), connect.toString());
        assertTrue(connect.contains("proxyToClientResponse:full"), connect.toString());
        assertTrue(connect.contains("proxyToClientResponseSent:200"), connect.toString());
        assertEquals(List.of("200"), sent);
        assertEquals(List.of("200"), completed);
    }

    @Test
    void compatibilityModeWritesTheConnectAnswerStraightToTheClient() throws Exception {
        proxy = bootstrap(true, false).start();
        assertTrue(tunnel().startsWith("HTTP/1.1 200 Connection established"));
        eventually("the tunnel's end", () -> connectEvents().contains("exchangeEnded:true"));
        List<String> connect = connectEvents();
        assertFalse(connect.contains("serverToProxyResponse:full"), connect.toString());
        assertFalse(connect.contains("proxyToClientResponse:full"), connect.toString());
        assertFalse(connect.contains("serverToProxyResponseReceiving"), connect.toString());
        assertFalse(connect.contains("serverToProxyResponseReceived"), connect.toString());
        // The request side is as before, and so are the hooks LittleProxy does not have.
        assertTrue(connect.contains("clientToProxyRequest:head"), connect.toString());
        assertTrue(connect.contains("proxyToServerRequest:head"), connect.toString());
        assertTrue(connect.contains("proxyToServerConnectionSucceeded"), connect.toString());
        assertTrue(connect.contains("proxyToClientResponseSent:200"), connect.toString());
        // LittleProxy's ResponseWrittenMonitor tells trackers about the 200; so does MicroProxy.
        assertEquals(List.of("200"), sent);
        assertEquals(List.of("200"), completed);
    }

    @Test
    void onlyByDefaultCanAFilterRefuseTheConnectAnswer() throws Exception {
        proxy = bootstrap(false, true).start();
        assertTrue(tunnel().startsWith("HTTP/1.1 403"));
        proxy.abort();
        events.clear();
        sent.clear();
        proxy = bootstrap(true, true).start();
        // The filter is not asked: the tunnel opens.
        assertTrue(tunnel().startsWith("HTTP/1.1 200"));
        assertEquals(List.of("200"), sent);
    }

    @Test
    void compatibilityModeAppliesToInterceptedConnectsToo() {
        CertificateAuthority originCa = CertificateAuthority.generate("Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), echo());
        try {
            proxy = bootstrap(true, false)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .start();
            assertEquals(200, get(client(proxy, proxyCa.clientContext()), url(secure, "/mitm")).statusCode());
            List<String> connect = connectEvents();
            assertTrue(connect.contains("proxyToServerConnectionSucceeded"), connect.toString());
            assertFalse(connect.contains("serverToProxyResponse:full"), connect.toString());
            assertFalse(connect.contains("proxyToClientResponse:full"), connect.toString());
            // The decrypted requests inside the session are filtered as usual.
            List<String> inside = events.get("GET");
            assertTrue(inside.contains("serverToProxyResponse:head"), inside.toString());
            assertTrue(inside.contains("proxyToClientResponse:head"), inside.toString());
            assertEquals("200", sent.getFirst(), sent.toString());
        } finally {
            secure.stop(0);
        }
    }
}
