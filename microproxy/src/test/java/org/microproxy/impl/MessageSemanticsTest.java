package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;
import org.microproxy.impl.WireLevelTest.Reply;

/**
 * Connection persistence, message framing and header rewriting as seen on the wire (ported from
 * LittleProxy's {@code KeepAliveTest}, {@code MessageTerminationTest}, {@code ProxyHeadersTest},
 * {@code ServerErrorTest}, {@code ConnectResponseFiltersTest} and {@code DirectRequestTest}).
 */
class MessageSemanticsTest {

    private static final HttpCodec.Limits LIMITS = new HttpCodec.Limits(8192, 16384, 1 << 20);

    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        origin = origin(echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private void start() {
        start(MicroProxy.bootstrap());
    }

    private void start(HttpProxyServerBootstrap bootstrap) {
        proxy = bootstrap.withPort(0).withProxyAlias("semantics").start();
    }

    private static HttpFiltersSource filters(HttpFilters filters) {
        return new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return filters;
            }
        };
    }

    private Socket connect() throws IOException {
        Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort());
        s.setSoTimeout(10_000);
        return s;
    }

    private String originAuthority() {
        return "127.0.0.1:" + origin.getAddress().getPort();
    }

    private static String get(String authority, String path) {
        return "GET http://" + authority + path + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n";
    }

    private static int closedPort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            return s.getLocalPort();
        }
    }

    /** Asserts the proxy still serves requests on {@code s}. */
    private void assertStillUsable(Socket s, ByteReader in) throws IOException {
        write(s.getOutputStream(), get(originAuthority(), "/still-open"));
        Reply reply = WireLevelTest.read(in, HttpMethod.GET);
        assertNotNull(reply, "the proxy closed the connection");
        assertEquals(200, reply.head().status().code());
        assertTrue(reply.body().contains("uri: /still-open"), reply.body());
    }

    // -------------------------------------------------------------------------------------------
    // Keep-alive
    // -------------------------------------------------------------------------------------------

    @Test
    void clientConnectionSurvivesServerClosingAfterEachResponse() throws Exception {
        start();
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nsuccess");
                });
                Socket s = connect()) {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            for (int i = 0; i < 2; i++) {
                write(s.getOutputStream(), get("127.0.0.1:" + raw.port(), "/success"));
                Reply reply = WireLevelTest.read(in, HttpMethod.GET);
                assertEquals(200, reply.head().status().code());
                assertTrue(HttpUtil.isTransferEncodingChunked(reply.head()), "close-delimited bodies are re-chunked");
                assertTrue(HttpUtil.isKeepAlive(reply.head()));
                assertEquals("success", reply.body());
            }
            assertStillUsable(s, in);
        }
    }

    @Test
    void badGatewayKeepsTheClientConnectionOpen() throws Exception {
        start();
        int port = closedPort();
        try (Socket s = connect()) {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            for (int i = 0; i < 2; i++) {
                write(s.getOutputStream(), get("127.0.0.1:" + port, "/success"));
                Reply reply = WireLevelTest.read(in, HttpMethod.GET);
                assertEquals(502, reply.head().status().code());
                assertTrue(HttpUtil.isKeepAlive(reply.head()));
            }
            assertStillUsable(s, in);
        }
    }

    @Test
    void gatewayTimeoutKeepsTheClientConnectionOpen() throws Exception {
        start(MicroProxy.bootstrap().withIdleConnectionTimeout(Duration.ofMillis(500)));
        try (TestSupport.RawServer silent = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    Thread.sleep(5000);
                });
                Socket s = connect()) {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            for (int i = 0; i < 2; i++) {
                write(s.getOutputStream(), get("127.0.0.1:" + silent.port(), "/slow"));
                Reply reply = WireLevelTest.read(in, HttpMethod.GET);
                assertEquals(504, reply.head().status().code());
                assertEquals("Gateway Timeout", reply.body(), "exactly one response per request");
                assertTrue(HttpUtil.isKeepAlive(reply.head()));
            }
            assertStillUsable(s, in);
        }
    }

    private static HttpFilters shortCircuit(FullHttpResponse response) {
        return new HttpFilters() {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                if (!(o instanceof HttpRequest r) || r.uri().endsWith("/still-open")) return null;
                FullHttpResponse copy = new DefaultFullHttpResponse(response.protocolVersion(), response.status(),
                        response.headers().copy(), response.content().clone());
                return copy;
            }
        };
    }

    @Test
    void shortCircuitResponseKeepsTheClientConnectionOpen() throws Exception {
        FullHttpResponse ok = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        HttpUtil.setContentLength(ok, 0);
        start(MicroProxy.bootstrap().withFiltersSource(filters(shortCircuit(ok))));
        try (Socket s = connect()) {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            for (int i = 0; i < 2; i++) {
                write(s.getOutputStream(), get(originAuthority(), "/short"));
                Reply reply = WireLevelTest.read(in, HttpMethod.GET);
                assertEquals(200, reply.head().status().code());
                assertEquals("", reply.body());
            }
            assertStillUsable(s, in);
        }
    }

    @Test
    void shortCircuitResponseWithConnectionCloseClosesTheClientConnection() throws Exception {
        FullHttpResponse ok = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        HttpUtil.setContentLength(ok, 0);
        HttpUtil.setKeepAlive(ok, false);
        start(MicroProxy.bootstrap().withFiltersSource(filters(shortCircuit(ok))));
        try (Socket s = connect()) {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            write(s.getOutputStream(), get(originAuthority(), "/short"));
            Reply reply = WireLevelTest.read(in, HttpMethod.GET);
            assertEquals(200, reply.head().status().code());
            assertFalse(HttpUtil.isKeepAlive(reply.head()));
            assertNull(HttpCodec.readResponse(in, LIMITS), "expected the proxy to close the connection");
        }
    }

    @Test
    void http10ClientWithoutKeepAliveIsDisconnectedAfterTheResponse() throws Exception {
        start();
        try (Socket s = connect()) {
            write(s.getOutputStream(), "GET http://" + originAuthority() + "/old HTTP/1.0\r\n\r\n");
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            Reply reply = WireLevelTest.read(in, HttpMethod.GET);
            assertEquals(200, reply.head().status().code());
            assertFalse(HttpUtil.isKeepAlive(reply.head()));
            assertTrue(reply.body().contains("uri: /old"), reply.body());
            assertNull(HttpCodec.readResponse(in, LIMITS), "expected the proxy to close the connection");
        }
    }

    @Test
    void http10ClientAskingForKeepAliveKeepsItsConnection() throws Exception {
        start();
        try (Socket s = connect()) {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            for (int i = 0; i < 2; i++) {
                write(s.getOutputStream(), "GET http://" + originAuthority() + "/old" + i + " HTTP/1.0\r\n"
                        + "Connection: keep-alive\r\n\r\n");
                Reply reply = WireLevelTest.read(in, HttpMethod.GET);
                assertEquals(200, reply.head().status().code());
                assertFalse(HttpUtil.isTransferEncodingChunked(reply.head()), "HTTP/1.0 cannot read chunked bodies");
                assertTrue(reply.body().contains("uri: /old" + i), reply.body());
            }
            assertStillUsable(s, in);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Message termination
    // -------------------------------------------------------------------------------------------

    @Test
    void contentLengthResponseIsRelayedWithItsContentLength() throws Exception {
        start();
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 8\r\n\r\nSuccess!");
                });
                Socket s = connect()) {
            write(s.getOutputStream(), get("127.0.0.1:" + raw.port(), "/"));
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            Reply reply = WireLevelTest.read(in, HttpMethod.GET);
            assertEquals("8", reply.head().headers().get("Content-Length"));
            assertNull(reply.head().headers().get("Transfer-Encoding"));
            assertEquals("Success!", reply.body());
            assertTrue(HttpUtil.isKeepAlive(reply.head()), "the server closing is no reason to close the client");
            assertStillUsable(s, in);
        }
    }

    @Test
    void headResponsesKeepTheirHeadersAndHaveNoBody() throws Exception {
        start();
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    while (true) {
                        String request = TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                        if (request.isEmpty()) return;
                        // The length a GET would have had, or no framing headers at all.
                        write(socket.getOutputStream(), request.contains("/with-length")
                                ? "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n" : "HTTP/1.1 200 OK\r\n\r\n");
                    }
                });
                Socket s = connect()) {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            String authority = "127.0.0.1:" + raw.port();
            write(s.getOutputStream(), "HEAD http://" + authority + "/with-length HTTP/1.1\r\nHost: " + authority + "\r\n\r\n");
            Reply withLength = WireLevelTest.read(in, HttpMethod.HEAD);
            assertEquals("1234", withLength.head().headers().get("Content-Length"));
            assertNull(withLength.head().headers().get("Transfer-Encoding"));
            assertEquals("", withLength.body());

            write(s.getOutputStream(), "HEAD http://" + authority + "/bare HTTP/1.1\r\nHost: " + authority + "\r\n\r\n");
            Reply bare = WireLevelTest.read(in, HttpMethod.HEAD);
            assertEquals(200, bare.head().status().code());
            assertNull(bare.head().headers().get("Content-Length"), "no Content-Length may be invented for HEAD");
            assertNull(bare.head().headers().get("Transfer-Encoding"));
            // No body bytes were sent: the next response parses cleanly.
            assertStillUsable(s, in);
        }
    }

    @Test
    void bufferedResponsesGetAnExactContentLength() throws Exception {
        start(MicroProxy.bootstrap().withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public int getMaximumResponseBufferSizeInBytes() {
                return 100_000;
            }
        }));
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                            + "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
                });
                Socket s = connect()) {
            write(s.getOutputStream(), get("127.0.0.1:" + raw.port(), "/"));
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            Reply reply = WireLevelTest.read(in, HttpMethod.GET);
            assertEquals("11", reply.head().headers().get("Content-Length"));
            assertNull(reply.head().headers().get("Transfer-Encoding"));
            assertEquals("hello world", reply.body());
            assertStillUsable(s, in);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Proxy headers
    // -------------------------------------------------------------------------------------------

    @Test
    void responseHopByHopHeadersAreRemovedAndViaIsAppended() throws Exception {
        start();
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\n"
                            + "Connection: Dummy-Header\r\n"
                            + "Dummy-Header: dummy-value\r\n"
                            + "Keep-Alive: timeout=5\r\n"
                            + "Proxy-Authenticate: Basic realm=x\r\n"
                            + "Via: 1.0 upstream\r\n"
                            + "X-End-To-End: kept\r\n"
                            + "Content-Length: 2\r\n\r\nok");
                });
                Socket s = connect()) {
            write(s.getOutputStream(), get("127.0.0.1:" + raw.port(), "/connectionheaders"));
            Reply reply = WireLevelTest.read(new ByteReader(s.getInputStream(), 1024), HttpMethod.GET);
            var headers = reply.head().headers();
            assertFalse(headers.contains("Dummy-Header"), "headers named in Connection are hop-by-hop");
            assertFalse(headers.contains("Keep-Alive"));
            assertFalse(headers.contains("Proxy-Authenticate"));
            assertEquals("kept", headers.get("X-End-To-End"));
            assertEquals(List.of("1.0 upstream", "1.1 semantics"), headers.getAllElements("Via"));
            assertEquals("ok", reply.body());
        }
    }

    @Test
    void requestProxyCredentialsAreNotForwarded() throws Exception {
        start();
        try (Socket s = connect()) {
            write(s.getOutputStream(), "GET http://" + originAuthority() + "/creds HTTP/1.1\r\nHost: x\r\n"
                    + "Proxy-Authorization: Basic dXNlcjpwYXNz\r\nProxy-Authenticate: Basic\r\n\r\n");
            Reply reply = WireLevelTest.read(new ByteReader(s.getInputStream(), 1024), HttpMethod.GET);
            assertEquals(200, reply.head().status().code());
            assertTrue(echoedHeader(reply.body(), "proxy-authorization").isEmpty());
            assertTrue(echoedHeader(reply.body(), "proxy-authenticate").isEmpty());
        }
    }

    // -------------------------------------------------------------------------------------------
    // Server errors
    // -------------------------------------------------------------------------------------------

    private void assertBadGatewayFor(String serverReply) throws Exception {
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    write(socket.getOutputStream(), serverReply);
                });
                Socket s = connect()) {
            write(s.getOutputStream(), get("127.0.0.1:" + raw.port(), "/"));
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            Reply reply = WireLevelTest.read(in, HttpMethod.GET);
            assertEquals(502, reply.head().status().code(), "for " + serverReply);
            assertStillUsable(s, in);
        }
    }

    @Test
    void malformedServerResponsesGiveBadGateway() throws Exception {
        start();
        assertBadGatewayFor("HTTP/1.12312312312312411231231231 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        assertBadGatewayFor("this is not HTTP\r\n\r\n");
        assertBadGatewayFor("HTTP/1.1 2x0 OK\r\nContent-Length: 0\r\n\r\n");
        assertBadGatewayFor(""); // closed without answering
    }

    // -------------------------------------------------------------------------------------------
    // CONNECT responses through filters
    // -------------------------------------------------------------------------------------------

    @Test
    void connectResponseHeadersCanBeChangedByResponseFilters() throws Exception {
        start(MicroProxy.bootstrap().withFiltersSource(filters(new HttpFilters() {
            @Override
            public HttpObject serverToProxyResponse(HttpObject o) {
                if (o instanceof HttpResponse r) r.headers().set("X-Server-Side", "1");
                return o;
            }

            @Override
            public HttpObject proxyToClientResponse(HttpObject o) {
                if (o instanceof HttpResponse r) r.headers().set("X-Client-Side", "2");
                return o;
            }
        })));
        try (Socket s = connect()) {
            write(s.getOutputStream(), "CONNECT " + originAuthority() + " HTTP/1.1\r\nHost: " + originAuthority() + "\r\n\r\n");
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            HttpResponse established = HttpCodec.readResponse(in, LIMITS);
            assertEquals(200, established.status().code());
            assertEquals("Connection established", established.status().reasonPhrase());
            assertEquals("1", established.headers().get("X-Server-Side"));
            assertEquals("2", established.headers().get("X-Client-Side"));
            assertEquals("1.1 semantics", established.headers().get("Via"));
            // The tunnel works: speak HTTP to the origin through it.
            write(s.getOutputStream(), "GET /tunnelled HTTP/1.1\r\nHost: " + originAuthority() + "\r\n\r\n");
            Reply reply = WireLevelTest.read(in, HttpMethod.GET);
            assertTrue(reply.body().contains("uri: /tunnelled"), reply.body());
            assertTrue(echoedHeader(reply.body(), "via").isEmpty(), "tunnelled bytes are not rewritten");
        }
    }

    @Test
    void connectCanBeRefusedByAResponseFilter() throws Exception {
        start(MicroProxy.bootstrap().withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                boolean connect = originalRequest.method().equals(HttpMethod.CONNECT);
                return new HttpFilters() {
                    @Override
                    public HttpObject proxyToClientResponse(HttpObject o) {
                        return connect ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN,
                                "no tunnels") : o;
                    }
                };
            }
        }));
        try (Socket s = connect()) {
            write(s.getOutputStream(), "CONNECT " + originAuthority() + " HTTP/1.1\r\nHost: " + originAuthority() + "\r\n\r\n");
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            Reply refused = WireLevelTest.read(in, HttpMethod.GET);
            assertEquals(403, refused.head().status().code());
            assertEquals("no tunnels", refused.body());
            assertStillUsable(s, in);
        }
    }
}
