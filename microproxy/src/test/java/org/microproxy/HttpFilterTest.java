package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpRequest;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;

class HttpFilterTest {

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

    private void start(Function<org.microproxy.http.HttpRequest, HttpFilters> filters, int requestBuffer, int responseBuffer) {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(new HttpFiltersSource() {
            @Override
            public HttpFilters filterRequest(org.microproxy.http.HttpRequest originalRequest, FlowContext ctx) {
                return filters.apply(originalRequest);
            }

            @Override
            public int getMaximumRequestBufferSizeInBytes() {
                return requestBuffer;
            }

            @Override
            public int getMaximumResponseBufferSizeInBytes() {
                return responseBuffer;
            }
        }).start();
    }

    @Test
    void clientToProxyRequestCanShortCircuit() {
        start(req -> new HttpFilters() {
            @Override
            public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof org.microproxy.http.HttpRequest r && r.uri().endsWith("/blocked")) {
                    return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN, "nope");
                }
                return null;
            }
        }, 0, 0);
        var client = client(proxy);
        HttpResponse<String> blocked = get(client, url(origin, "/blocked"));
        assertEquals(403, blocked.statusCode());
        assertEquals("nope", blocked.body());
        assertEquals(200, get(client, url(origin, "/allowed")).statusCode());
    }

    @Test
    void proxyToServerRequestCanAddHeaders() {
        start(req -> new HttpFilters() {
            @Override
            public org.microproxy.http.HttpResponse proxyToServerRequest(HttpObject o) {
                if (o instanceof org.microproxy.http.HttpRequest r) {
                    r.headers().set("X-Injected", "by-filter");
                }
                return null;
            }
        }, 0, 0);
        HttpResponse<String> response = get(client(proxy), url(origin, "/"));
        assertEquals(List.of("by-filter"), echoedHeader(response.body(), "x-injected"));
    }

    @Test
    void bufferedRequestIsSeenWhole() {
        AtomicReference<String> seen = new AtomicReference<>();
        start(req -> new HttpFilters() {
            @Override
            public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof FullHttpRequest full) {
                    seen.set(full.contentAsString());
                    full.setContent("rewritten".getBytes(StandardCharsets.UTF_8));
                }
                return null;
            }
        }, 1 << 20, 0);
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/p")))
                .POST(HttpRequest.BodyPublishers.ofInputStream(
                        () -> new java.io.ByteArrayInputStream("original body".getBytes(StandardCharsets.UTF_8))))
                .build());
        assertEquals("original body", seen.get());
        assertEquals("rewritten", echoedBody(response.body()));
        assertEquals(List.of("9"), echoedHeader(response.body(), "content-length"));
    }

    @Test
    void tooLargeBufferedRequestGets413() {
        start(req -> new HttpFilters() {}, 10, 0);
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/p")))
                .POST(HttpRequest.BodyPublishers.ofString("this is more than ten bytes")).build());
        assertEquals(413, response.statusCode());
    }

    @Test
    void filtersCanAskToBufferOneRequest() {
        start(req -> new HttpFilters() {
            @Override
            public int requestBufferSizeInBytes(org.microproxy.http.HttpRequest request) {
                return request.uri().endsWith("/small") ? 10 : 1 << 20;
            }

            @Override
            public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof org.microproxy.http.FullHttpRequest full) {
                    full.setContent(full.contentAsString().toUpperCase().getBytes(StandardCharsets.UTF_8));
                }
                return null;
            }
        }, 0, 0);
        HttpResponse<String> ok = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/big")))
                .POST(HttpRequest.BodyPublishers.ofString("shout")).build());
        assertEquals("SHOUT", echoedBody(ok.body()));
        HttpResponse<String> tooLarge = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/small")))
                .POST(HttpRequest.BodyPublishers.ofString("this is more than ten bytes")).build());
        assertEquals(413, tooLarge.statusCode());
    }

    @Test
    void bufferedResponseCanBeRewritten() {
        start(req -> new HttpFilters() {
            @Override
            public HttpObject serverToProxyResponse(HttpObject o) {
                if (o instanceof FullHttpResponse full) {
                    full.setContent(full.contentAsString().toUpperCase().getBytes(StandardCharsets.UTF_8));
                    full.headers().set("X-Filtered", "yes");
                }
                return o;
            }
        }, 0, 1 << 20);
        HttpResponse<String> response = get(client(proxy), url(origin, "/lower"));
        assertTrue(response.body().startsWith("METHOD: GET"), response.body());
        assertEquals("yes", response.headers().firstValue("x-filtered").orElseThrow());
    }

    @Test
    void bodyPiecesReachObservingFiltersInsideAChain() {
        List<String> pieces = new CopyOnWriteArrayList<>();
        HttpFiltersSource quiet = new HttpFiltersSourceAdapter();
        HttpFiltersSource observing = new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(org.microproxy.http.HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFilters() {
                    @Override
                    public HttpObject serverToProxyResponse(HttpObject o) {
                        if (o instanceof HttpContent c) pieces.add(c.contentAsString());
                        return o;
                    }
                };
            }
        };
        // A plain adapter subclass that overrides nothing: on its own, bodies take the fast path.
        HttpFiltersSource noOverrides = new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(org.microproxy.http.HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFiltersAdapter(originalRequest, ctx);
            }
        };
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(HttpFiltersChain.of(quiet, noOverrides, observing)).start();
        HttpResponse<String> response = get(client(proxy), url(origin, "/streamed"));
        assertTrue(response.body().startsWith("method: GET"), response.body());
        assertEquals(response.body(), String.join("", pieces));
    }

    @Test
    void streamingFiltersSeeHeadThenContentThenLast() {
        List<String> events = new CopyOnWriteArrayList<>();
        start(req -> new HttpFilters() {
            @Override
            public HttpObject serverToProxyResponse(HttpObject o) {
                events.add("s2p:" + kind(o));
                return o;
            }

            @Override
            public HttpObject proxyToClientResponse(HttpObject o) {
                events.add("p2c:" + kind(o));
                return o;
            }

            @Override
            public void proxyToServerRequestSending() {
                events.add("sending");
            }

            @Override
            public void proxyToServerRequestSent() {
                events.add("sent");
            }

            @Override
            public void serverToProxyResponseReceiving() {
                events.add("receiving");
            }

            @Override
            public void serverToProxyResponseReceived() {
                events.add("received");
            }

            @Override
            public InetSocketAddress proxyToServerResolutionStarted(String hostAndPort) {
                events.add("resolving");
                return null;
            }

            @Override
            public void proxyToServerConnectionSucceeded(FullFlowContext ctx) {
                events.add("connected:" + ctx.getServerHostAndPort());
            }
        }, 0, 0);
        assertEquals(200, get(client(proxy), url(origin, "/s")).statusCode());
        // The client can have the whole response a moment before the proxy reports it received.
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!events.contains("received") && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        String port = String.valueOf(origin.getAddress().getPort());
        assertEquals(List.of("resolving", "connected:127.0.0.1:" + port, "sending", "sent", "receiving",
                "s2p:head", "p2c:head", "s2p:last", "p2c:last", "received"), events);
    }

    private static String kind(HttpObject o) {
        if (o instanceof org.microproxy.http.HttpResponse) return "head";
        if (o instanceof LastHttpContent) return "last";
        if (o instanceof HttpContent) return "content";
        return "?";
    }

    @Test
    void nullFromProxyToClientResponseDisconnects() {
        start(req -> new HttpFilters() {
            @Override
            public HttpObject proxyToClientResponse(HttpObject o) {
                return null;
            }
        }, 0, 0);
        assertThrows(java.io.UncheckedIOException.class, () -> get(client(proxy), url(origin, "/")));
    }

    @Test
    void filtersSourceReturningNullMeansNoFiltering() {
        start(req -> null, 0, 0);
        assertEquals(200, get(client(proxy), url(origin, "/")).statusCode());
    }

    @Test
    void resolutionCanBeOverriddenByFilter() {
        start(req -> new HttpFilters() {
            @Override
            public InetSocketAddress proxyToServerResolutionStarted(String hostAndPort) {
                return new InetSocketAddress(TestSupport.LOOPBACK, origin.getAddress().getPort());
            }
        }, 0, 0);
        HttpResponse<String> response = get(client(proxy), "http://rewritten.invalid:1234/x");
        assertEquals(200, response.statusCode());
        assertInstanceOf(String.class, response.body());
        assertEquals(List.of("rewritten.invalid:1234"), echoedHeader(response.body(), "host"));
    }
}
