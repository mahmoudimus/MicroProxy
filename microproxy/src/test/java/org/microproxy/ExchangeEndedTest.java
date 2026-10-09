package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.get;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.http.HttpClient;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/** {@link HttpFilters#exchangeEnded} is called exactly once per exchange, however it ends. */
class ExchangeEndedTest {

    /** "METHOD uri completed=..." per exchangeEnded call, and the events before it. */
    private final List<String> events = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    private final class Recording implements HttpFilters {
        private final String name;

        Recording(HttpRequest request) {
            this.name = request.method() + " " + request.uri();
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (httpObject instanceof HttpRequest r && r.uri().contains("/blocked")) {
                return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN, "no");
            }
            return null;
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            return name.contains("/abort") ? null : httpObject;
        }

        @Override
        public void proxyToClientResponseSent(HttpResponse response, ResponseSource source) {
            events.add("sent " + name);
        }

        @Override
        public void exchangeEnded(boolean completed) {
            events.add("ended " + name + " completed=" + completed);
        }
    }

    private HttpProxyServerBootstrap recording() {
        return MicroProxy.bootstrap().withPort(0).withFiltersSource((request, flow) -> new Recording(request));
    }

    private List<String> ended() {
        return events.stream().filter(e -> e.startsWith("ended ")).toList();
    }

    private void assertSentThenEnded(String name) {
        int sent = events.indexOf("sent " + name);
        int ended = events.indexOf("ended " + name + " completed=true");
        assertTrue(sent >= 0 && ended > sent, name + ": " + events);
        assertEquals(1, events.stream().filter(e -> e.startsWith("ended " + name + " ")).count(), events.toString());
    }

    @Test
    void completedShortCircuitedFailedAndAbortedExchanges() throws Exception {
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        try (ServerSocket closed = new ServerSocket(0)) {
            int refusedPort = closed.getLocalPort();
            closed.close();
            proxy = recording().start();
            HttpClient client = client(proxy);
            String base = TestSupport.url(origin, "");

            assertEquals(200, get(client, base + "/ok").statusCode());
            assertEquals(403, get(client, base + "/blocked").statusCode());
            assertEquals(502, get(client, "http://127.0.0.1:" + refusedPort + "/down").statusCode());
            eventually("three exchanges ended", () -> ended().size() == 3);
            assertSentThenEnded("GET " + base + "/ok");
            assertSentThenEnded("GET " + base + "/blocked");
            assertSentThenEnded("GET http://127.0.0.1:" + refusedPort + "/down");
            assertEquals(6, events.size(), events.toString());

            events.clear();
            String abort = base + "/abort";
            String reply = TestSupport.rawExchange(proxy.getListenAddress(),
                    "GET " + abort + " HTTP/1.1\r\nHost: x\r\n\r\n");
            assertEquals("", reply, "a filter returning null drops the client");
            eventually("the aborted exchange ended", () -> ended().size() == 1);
            assertEquals(List.of("ended GET " + abort + " completed=false"), events);
        } finally {
            origin.stop(0);
        }
    }

    @Test
    void clientLeavingHalfWayThroughTheResponse() throws Exception {
        CountDownLatch clientGone = new CountDownLatch(1);
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            OutputStream out = s.getOutputStream();
            TestSupport.write(out, "HTTP/1.1 200 OK\r\nContent-Length: 10000000\r\n\r\nfirst");
            clientGone.await(10, TimeUnit.SECONDS);
            byte[] chunk = new byte[16384];
            for (int i = 0; i < 600; i++) out.write(chunk);
        })) {
            proxy = recording().start();
            String url = "http://127.0.0.1:" + origin.port() + "/big";
            try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
                s.setSoTimeout(10_000);
                TestSupport.write(s.getOutputStream(), "GET " + url + " HTTP/1.1\r\nHost: x\r\n\r\n");
                assertTrue(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
            }
            clientGone.countDown();
            eventually("the abandoned exchange ended", () -> ended().size() == 1);
            assertEquals(List.of("ended GET " + url + " completed=false"), events);
        }
    }

    @Test
    void tunnelsEndWhenClosedAndInterceptedConnectsWhenInterceptionStarts() throws Exception {
        try (TestSupport.RawServer echo = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()))) {
            proxy = recording().start();
            String target = "127.0.0.1:" + echo.port();
            try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
                assertEquals(200, ChainTestSupport.status(ChainTestSupport.connect(s, target)));
                TestSupport.write(s.getOutputStream(), "ping");
                assertEquals("ping", new String(s.getInputStream().readNBytes(4)));
                assertEquals(List.of("sent CONNECT " + target), events, "the tunnel's exchange is still going");
            }
            eventually("the tunnel's exchange ended", () -> ended().size() == 1);
            assertEquals(List.of("sent CONNECT " + target, "ended CONNECT " + target + " completed=true"), events);
        }
        proxy.abort();

        events.clear();
        CertificateAuthority originCa = CertificateAuthority.generate("Ended Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Ended Proxy CA");
        HttpsServer origin = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), TestSupport.fixed(200, "ok"));
        try {
            proxy = recording().withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .start();
            HttpClient client = client(proxy, proxyCa.clientContext());
            assertEquals(200, get(client, TestSupport.url(origin, "/one")).statusCode());
            assertEquals(200, get(client, TestSupport.url(origin, "/two")).statusCode());
            eventually("three exchanges ended", () -> ended().size() == 3);
            String connect = "CONNECT 127.0.0.1:" + origin.getAddress().getPort();
            assertSentThenEnded(connect);
            assertSentThenEnded("GET /one");
            assertSentThenEnded("GET /two");
            assertTrue(events.indexOf("ended " + connect + " completed=true") < events.indexOf("sent GET /one"),
                    "the CONNECT ends when interception starts: " + events);
            assertEquals(6, events.size(), events.toString());
        } finally {
            origin.stop(0);
        }
    }

    @Test
    void everyChainMemberIsToldEvenWhenOneThrows() throws Exception {
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        try {
            HttpFiltersSource throwing = (request, flow) -> new HttpFilters() {
                @Override
                public void exchangeEnded(boolean completed) {
                    events.add("throwing");
                    throw new IllegalStateException("boom");
                }
            };
            proxy = MicroProxy.bootstrap().withPort(0)
                    .withFiltersSource(throwing)
                    .plusFiltersSource((request, flow) -> new Recording(request))
                    .start();
            HttpClient client = client(proxy);
            assertEquals(200, get(client, TestSupport.url(origin, "/a")).statusCode());
            assertEquals(200, get(client, TestSupport.url(origin, "/b")).statusCode(),
                    "a throwing hook does not break the connection");
            eventually("both exchanges ended", () -> ended().size() == 2);
            assertEquals(4, events.stream().filter(e -> e.equals("throwing") || e.startsWith("ended")).count());
        } finally {
            origin.stop(0);
        }
    }
}
