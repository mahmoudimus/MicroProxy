package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.LastHttpContent;

/** Byte-level checks with hand-written requests. */
class WireLevelTest {

    private static final HttpCodec.Limits LIMITS = new HttpCodec.Limits(8192, 16384, 1 << 20);

    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        origin = origin(echo());
        proxy = MicroProxy.bootstrap().withPort(0).withProxyAlias("wire").withMaxHeaderSize(2048).start();
    }

    @AfterEach
    void tearDown() {
        proxy.abort();
        origin.stop(0);
    }

    private String originAuthority() {
        return "127.0.0.1:" + origin.getAddress().getPort();
    }

    /** A response plus its full body, read with the proxy's own codec. */
    record Reply(HttpResponse head, String body) {}

    static Reply read(ByteReader in, HttpMethod method) throws IOException {
        HttpResponse head = HttpCodec.readResponse(in, LIMITS);
        if (head == null) return null;
        HttpCodec.BodyReader body = new HttpCodec.BodyReader(in, Framing.forResponse(head, method), LIMITS);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        HttpContent c;
        while ((c = body.next()) != null) {
            buf.writeBytes(c.content());
            if (c instanceof LastHttpContent) break;
        }
        return new Reply(head, buf.toString(StandardCharsets.UTF_8));
    }

    private Socket connect() throws IOException {
        Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort());
        s.setSoTimeout(10_000);
        return s;
    }

    @Test
    void hopByHopAndConnectionTokensAreStripped() throws Exception {
        try (Socket s = connect()) {
            write(s.getOutputStream(), "GET http://" + originAuthority() + "/x HTTP/1.1\r\n"
                    + "Host: ignored.example\r\n"
                    + "Connection: X-Custom, keep-alive\r\n"
                    + "X-Custom: secret\r\n"
                    + "Keep-Alive: timeout=5\r\n"
                    + "Proxy-Connection: keep-alive\r\n"
                    + "TE: trailers\r\n"
                    + "X-End-To-End: yes\r\n\r\n");
            Reply reply = read(new ByteReader(s.getInputStream(), 1024), HttpMethod.GET);
            assertEquals(200, reply.head().status().code());
            String body = reply.body();
            assertTrue(echoedHeader(body, "x-custom").isEmpty());
            assertTrue(echoedHeader(body, "keep-alive").isEmpty());
            assertTrue(echoedHeader(body, "proxy-connection").isEmpty());
            assertTrue(echoedHeader(body, "te").isEmpty());
            assertEquals(java.util.List.of("yes"), echoedHeader(body, "x-end-to-end"));
            assertEquals(java.util.List.of(originAuthority()), echoedHeader(body, "host"),
                    "Host must be replaced by the absolute-form authority");
            assertEquals(java.util.List.of("1.1 wire"), echoedHeader(body, "via"));
        }
    }

    @Test
    void originFormRequestsAreRejected() throws Exception {
        String response = TestSupport.rawExchange(proxy.getListenAddress(),
                "GET /loop HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        assertTrue(response.startsWith("HTTP/1.1 400 "), response);
    }

    @Test
    void requestSmugglingIsRejected() throws Exception {
        String response = TestSupport.rawExchange(proxy.getListenAddress(),
                "POST http://" + originAuthority() + "/ HTTP/1.1\r\nHost: x\r\n"
                        + "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
        assertTrue(response.startsWith("HTTP/1.1 400 "), response);
        response = TestSupport.rawExchange(proxy.getListenAddress(),
                "POST http://" + originAuthority() + "/ HTTP/1.1\r\nHost: x\r\n"
                        + "Content-Length: 4\r\nContent-Length: 5\r\n\r\nabcde");
        assertTrue(response.startsWith("HTTP/1.1 400 "), response);
    }

    @Test
    void oversizedHeadersAreRejected() throws Exception {
        String response = TestSupport.rawExchange(proxy.getListenAddress(),
                "GET http://" + originAuthority() + "/ HTTP/1.1\r\nX-Big: " + "a".repeat(4000) + "\r\n\r\n");
        assertTrue(response.startsWith("HTTP/1.1 431 "), response);
    }

    @Test
    void pipelinedRequestsAreAnsweredInOrder() throws Exception {
        try (Socket s = connect()) {
            String a = originAuthority();
            write(s.getOutputStream(), "GET http://" + a + "/one HTTP/1.1\r\nHost: " + a + "\r\n\r\n"
                    + "GET http://" + a + "/two HTTP/1.1\r\nHost: " + a + "\r\n\r\n"
                    + "GET http://" + a + "/three HTTP/1.1\r\nHost: " + a + "\r\nConnection: close\r\n\r\n");
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            assertTrue(read(in, HttpMethod.GET).body().contains("uri: /one"));
            assertTrue(read(in, HttpMethod.GET).body().contains("uri: /two"));
            Reply third = read(in, HttpMethod.GET);
            assertTrue(third.body().contains("uri: /three"));
            assertFalse(HttpUtil.isKeepAlive(third.head()));
            assertNull(HttpCodec.readResponse(in, LIMITS), "proxy must close after Connection: close");
        }
    }

    @Test
    void expectContinueIsRelayed() throws Exception {
        try (Socket s = connect()) {
            String a = originAuthority();
            write(s.getOutputStream(), "POST http://" + a + "/upload HTTP/1.1\r\nHost: " + a + "\r\n"
                    + "Content-Length: 5\r\nExpect: 100-continue\r\n\r\n");
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            HttpResponse interim = HttpCodec.readResponse(in, LIMITS);
            assertEquals(100, interim.status().code());
            write(s.getOutputStream(), "hello");
            Reply reply = read(in, HttpMethod.POST);
            assertEquals(200, reply.head().status().code());
            assertTrue(reply.body().endsWith("\n\nhello"), reply.body());
        }
    }

    @Test
    void expectContinueIsSynthesizedWhenServerIgnoresIt() throws Exception {
        // This origin never sends 100 (Continue): it just waits for the body.
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    byte[] body = socket.getInputStream().readNBytes(5);
                    write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
                            + new String(body, StandardCharsets.ISO_8859_1));
                });
                Socket s = connect()) {
            write(s.getOutputStream(), "PUT http://127.0.0.1:" + raw.port() + "/ HTTP/1.1\r\nHost: x\r\n"
                    + "Content-Length: 5\r\nExpect: 100-continue\r\n\r\n");
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            long start = System.nanoTime();
            assertEquals(100, HttpCodec.readResponse(in, LIMITS).status().code());
            assertTrue(System.nanoTime() - start < 5_000_000_000L);
            write(s.getOutputStream(), "12345");
            Reply reply = read(in, HttpMethod.PUT);
            assertEquals("12345", reply.body());
        }
    }

    @Test
    void earlyFinalResponseToExpectContinueSkipsTheBody() throws Exception {
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    write(socket.getOutputStream(), "HTTP/1.1 413 Too Big\r\nContent-Length: 0\r\n\r\n");
                });
                Socket s = connect()) {
            write(s.getOutputStream(), "PUT http://127.0.0.1:" + raw.port() + "/ HTTP/1.1\r\nHost: x\r\n"
                    + "Content-Length: 100000000\r\nExpect: 100-continue\r\n\r\n");
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            HttpResponse response = HttpCodec.readResponse(in, LIMITS);
            assertEquals(413, response.status().code());
            assertFalse(HttpUtil.isKeepAlive(response), "body was never sent, so the connection must close");
        }
    }

    @Test
    void responsesDelimitedByCloseAreRechunkedForHttp11Clients() throws Exception {
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil close");
                });
                Socket s = connect()) {
            write(s.getOutputStream(), "GET http://127.0.0.1:" + raw.port() + "/ HTTP/1.1\r\nHost: x\r\n\r\n");
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            Reply reply = read(in, HttpMethod.GET);
            assertTrue(HttpUtil.isTransferEncodingChunked(reply.head()));
            assertTrue(HttpUtil.isKeepAlive(reply.head()));
            assertEquals("until close", reply.body());
        }
    }

    @Test
    void chunkedResponsesAreDechunkedForHttp10Clients() throws Exception {
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
            TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
            write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        })) {
            String response = TestSupport.rawExchange(proxy.getListenAddress(),
                    "GET http://127.0.0.1:" + raw.port() + "/ HTTP/1.0\r\n\r\n");
            assertFalse(response.toLowerCase().contains("transfer-encoding"), response);
            assertTrue(response.endsWith("\r\n\r\nhello world"), response);
        }
    }

    @Test
    void trailersArePreserved() throws Exception {
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                            + "3\r\nabc\r\n0\r\nX-Checksum: 42\r\n\r\n");
                });
                Socket s = connect()) {
            write(s.getOutputStream(), "GET http://127.0.0.1:" + raw.port() + "/ HTTP/1.1\r\nHost: x\r\n\r\n");
            InputStream in = s.getInputStream();
            String all = TestSupport.readUntil(in, "X-Checksum: 42\r\n\r\n");
            assertTrue(all.endsWith("3\r\nabc\r\n0\r\nX-Checksum: 42\r\n\r\n"), all);
        }
    }

    @Test
    void transparentModeLeavesHeadersAlone() throws Exception {
        proxy.abort();
        proxy = MicroProxy.bootstrap().withPort(0).withTransparent(true).start();
        try (Socket s = connect()) {
            write(s.getOutputStream(), "GET http://" + originAuthority() + "/x HTTP/1.1\r\nHost: "
                    + originAuthority() + "\r\nX-Foo: bar\r\n\r\n");
            Reply reply = read(new ByteReader(s.getInputStream(), 1024), HttpMethod.GET);
            assertTrue(echoedHeader(reply.body(), "via").isEmpty());
            assertNull(reply.head().headers().get("Via"));
            assertTrue(reply.body().contains("uri: /x"));
        }
    }

    @Test
    void webSocketUpgradeBecomesATunnel() throws Exception {
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    String request = TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    if (!request.toLowerCase().contains("upgrade: websocket")) return;
                    write(socket.getOutputStream(), "HTTP/1.1 101 Switching Protocols\r\n"
                            + "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
                    InputStream in = socket.getInputStream();
                    byte[] buf = new byte[4];
                    in.readNBytes(buf, 0, 4);
                    socket.getOutputStream().write(("echo:" + new String(buf, StandardCharsets.ISO_8859_1)).getBytes());
                    socket.getOutputStream().flush();
                });
                Socket s = connect()) {
            write(s.getOutputStream(), "GET http://127.0.0.1:" + raw.port() + "/ws HTTP/1.1\r\nHost: x\r\n"
                    + "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
            String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            assertTrue(head.startsWith("HTTP/1.1 101 "), head);
            assertTrue(head.contains("Upgrade: websocket"), head);
            write(s.getOutputStream(), "ping");
            assertEquals("echo:ping", new String(s.getInputStream().readNBytes(9), StandardCharsets.ISO_8859_1));
        }
    }

    @Test
    void serverClosingIdleKeepAliveConnectionIsRetriedTransparently() throws Exception {
        // An origin that answers one request per connection but claims keep-alive, then closes.
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                    write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                });
                Socket s = connect()) {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            for (int i = 0; i < 3; i++) {
                write(s.getOutputStream(), "GET http://127.0.0.1:" + raw.port() + "/ HTTP/1.1\r\nHost: x\r\n\r\n");
                Reply reply = read(in, HttpMethod.GET);
                assertEquals(200, reply.head().status().code());
                assertEquals("ok", reply.body());
                Thread.sleep(50);
            }
        }
    }

    /** Restarts the proxy with {@code filters} for every request. */
    private void restartWith(HttpFilters filters) {
        proxy.abort();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return filters;
            }
        }).start();
    }

    @Test
    void chunkedShortCircuitResponsesKeepTheConnectionUsable() throws Exception {
        restartWith(new HttpFilters() {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                DefaultFullHttpResponse r = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                        "short".getBytes(StandardCharsets.UTF_8));
                r.headers().set(HttpHeaderNames.TRANSFER_ENCODING, "chunked");
                return r;
            }
        });
        try (Socket s = connect()) {
            ByteReader in = new ByteReader(s.getInputStream(), 1024);
            for (int i = 0; i < 2; i++) {
                write(s.getOutputStream(), "GET http://" + originAuthority() + "/ HTTP/1.1\r\nHost: x\r\n\r\n");
                Reply reply = read(in, HttpMethod.GET);
                assertEquals(200, reply.head().status().code(), "response " + i);
                assertEquals("short", reply.body());
            }
        }
    }

    @Test
    void fullReplacementResponsesGetAContentLength() throws Exception {
        restartWith(new HttpFilters() {
            @Override
            public HttpObject serverToProxyResponse(HttpObject o) {
                if (o instanceof HttpResponse) {
                    return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                            "replaced".getBytes(StandardCharsets.UTF_8));
                }
                return o;
            }
        });
        for (String version : new String[] {"HTTP/1.1", "HTTP/1.0"}) {
            try (Socket s = connect()) {
                ByteReader in = new ByteReader(s.getInputStream(), 1024);
                write(s.getOutputStream(), "GET http://" + originAuthority() + "/ " + version + "\r\nHost: x\r\n"
                        + "Connection: keep-alive\r\n\r\n");
                Reply reply = read(in, HttpMethod.GET);
                assertEquals("replaced", reply.body(), version);
                assertEquals("8", reply.head().headers().get(HttpHeaderNames.CONTENT_LENGTH), version);
                assertNull(reply.head().headers().get(HttpHeaderNames.TRANSFER_ENCODING), version);
                // A complete body needs no connection close to delimit it.
                assertFalse("close".equalsIgnoreCase(reply.head().headers().get(HttpHeaderNames.CONNECTION)), version);
            }
        }
    }
}
