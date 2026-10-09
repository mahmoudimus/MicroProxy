package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Responses that filters make or replace: short-circuits from each hook, internal redirects, the
 * CONNECT response, and answers to requests addressed to the proxy itself (ported from
 * LittleProxy's {@code HttpFilterTest}, {@code InternalRedirectTest}, {@code
 * ConnectResponseFiltersTest} and {@code DirectRequestTest}).
 */
class FilterResponsesTest {

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final AtomicInteger originHits = new AtomicInteger();
    private final AtomicInteger serverConnections = new AtomicInteger();

    @BeforeEach
    void setUp() {
        origin = origin(exchange -> {
            originHits.incrementAndGet();
            echo().handle(exchange);
        });
        origin.createContext("/redirect", exchange -> {
            originHits.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            byte[] body = "you are being redirected".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Location", "/final");
            // A chunked body for /redirect/chunked, a Content-Length one otherwise.
            boolean chunked = exchange.getRequestURI().getPath().endsWith("/chunked");
            exchange.sendResponseHeaders(302, chunked ? 0 : body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        origin.createContext("/final", exchange -> {
            originHits.incrementAndGet();
            TestSupport.fixed(200, "Final response from internal redirect!").handle(exchange);
        });
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private HttpProxyServer start(HttpFiltersSource source) {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(source)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
                        serverConnections.incrementAndGet();
                    }
                })
                .start();
        return proxy;
    }

    private static FullHttpResponse forbidden(String body) {
        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN, body);
    }

    /**
     * Each of the four message hooks answers one path itself; other responses get a header from
     * the server-side and the client-side response hooks.
     */
    private HttpFiltersSource shortCircuitingFilters(int responseBuffer) {
        return new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(org.microproxy.http.HttpRequest originalRequest, FlowContext ctx) {
                String uri = originalRequest.uri();
                return new HttpFilters() {
                    @Override
                    public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                        return o instanceof org.microproxy.http.HttpRequest && uri.endsWith("/c2p") ? forbidden("c2p") : null;
                    }

                    @Override
                    public org.microproxy.http.HttpResponse proxyToServerRequest(HttpObject o) {
                        return o instanceof org.microproxy.http.HttpRequest r && r.uri().equals("/p2s") ? forbidden("p2s") : null;
                    }

                    @Override
                    public HttpObject serverToProxyResponse(HttpObject o) {
                        if (o instanceof org.microproxy.http.HttpResponse r) {
                            if (uri.endsWith("/s2p")) return forbidden("s2p");
                            r.headers().set("Header-Pre", "1");
                        }
                        return o;
                    }

                    @Override
                    public HttpObject proxyToClientResponse(HttpObject o) {
                        if (o instanceof org.microproxy.http.HttpResponse r) {
                            if (uri.endsWith("/p2c")) return forbidden("p2c");
                            r.headers().set("Header-Post", "2");
                        }
                        return o;
                    }
                };
            }

            @Override
            public int getMaximumResponseBufferSizeInBytes() {
                return responseBuffer;
            }
        };
    }

    private void assertEachHookCanAnswer(int responseBuffer) {
        start(shortCircuitingFilters(responseBuffer));
        HttpClient client = client(proxy);
        HttpResponse<String> ok = get(client, url(origin, "/ok"));
        assertEquals(200, ok.statusCode());
        assertEquals("1", ok.headers().firstValue("Header-Pre").orElseThrow());
        assertEquals("2", ok.headers().firstValue("Header-Post").orElseThrow());
        assertEquals(1, originHits.get());

        // Requests answered before reaching the server do not reach it.
        for (String hook : List.of("c2p", "p2s")) {
            HttpResponse<String> response = get(client, url(origin, "/" + hook));
            assertEquals(403, response.statusCode(), hook);
            assertEquals(hook, response.body());
            assertEquals(1, originHits.get(), hook + " must not contact the server");
        }
        // Responses replaced after the server answered.
        for (String hook : List.of("s2p", "p2c")) {
            HttpResponse<String> response = get(client, url(origin, "/" + hook));
            assertEquals(403, response.statusCode(), hook);
            assertEquals(hook, response.body());
        }
        assertEquals(3, originHits.get());
        // The client connection, and the server connection, are still good.
        assertEquals(200, get(client, url(origin, "/after")).statusCode());
        assertEquals(4, originHits.get());
        assertEquals(1, serverConnections.get(), "the replaced responses' bodies must be consumed, not leak");
    }

    @Test
    void eachHookCanAnswerInsteadOfTheServerWithBuffering() {
        assertEachHookCanAnswer(1 << 20);
    }

    @Test
    void eachHookCanAnswerInsteadOfTheServerWhileStreaming() {
        assertEachHookCanAnswer(0);
    }

    // -------------------------------------------------------------------------------------------
    // Internal redirects
    // -------------------------------------------------------------------------------------------

    /** Follows a 302 by fetching the target itself and answering with that response instead. */
    private HttpFiltersSource followingRedirects(boolean inClientHook) {
        HttpClient direct = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();
        return new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(org.microproxy.http.HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFilters() {
                    private HttpObject follow(HttpObject o) {
                        if (o instanceof org.microproxy.http.HttpResponse r && r.status().code() == 302) {
                            URI target = URI.create(originalRequest.uri()).resolve(r.headers().get(HttpHeaderNames.LOCATION));
                            try {
                                HttpResponse<byte[]> fetched = direct.send(HttpRequest.newBuilder(target)
                                        .timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.ofByteArray());
                                FullHttpResponse replacement = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                                        HttpResponseStatus.valueOf(fetched.statusCode()), fetched.body());
                                replacement.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
                                return replacement;
                            } catch (IOException e) {
                                throw new UncheckedIOException(e);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.BAD_GATEWAY);
                            }
                        }
                        return o;
                    }

                    @Override
                    public HttpObject serverToProxyResponse(HttpObject o) {
                        return inClientHook ? o : follow(o);
                    }

                    @Override
                    public HttpObject proxyToClientResponse(HttpObject o) {
                        return inClientHook ? follow(o) : o;
                    }
                };
            }
        };
    }

    private void assertRedirectIsFollowedInternally(boolean inClientHook) {
        start(followingRedirects(inClientHook));
        HttpClient client = client(proxy);
        for (String path : List.of("/redirect", "/redirect/chunked")) {
            HttpResponse<String> response = get(client, url(origin, path));
            assertEquals(200, response.statusCode(), "the client must not see the 302 for " + path);
            assertEquals("Final response from internal redirect!", response.body());
        }
        assertEquals(200, get(client, url(origin, "/final")).statusCode());
        // The 302 bodies were read and discarded: the one server connection served every request.
        assertEquals(1, serverConnections.get());
    }

    @Test
    void serverToProxyResponseCanReplaceAStreamedResponse() {
        assertRedirectIsFollowedInternally(false);
    }

    @Test
    void proxyToClientResponseCanReplaceAStreamedResponse() {
        assertRedirectIsFollowedInternally(true);
    }

    // -------------------------------------------------------------------------------------------
    // CONNECT
    // -------------------------------------------------------------------------------------------

    @Test
    void connectResponseReachesTheResponseFiltersWhenIntercepting() {
        CertificateAuthority originCa = CertificateAuthority.generate("Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), echo());
        List<String> calls = new CopyOnWriteArrayList<>();
        try {
            proxy = MicroProxy.bootstrap().withPort(0)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .withFiltersSource(new HttpFiltersSourceAdapter() {
                        @Override
                        public HttpFilters filterRequest(org.microproxy.http.HttpRequest originalRequest, FlowContext ctx) {
                            String method = originalRequest.method().name();
                            return new HttpFilters() {
                                @Override
                                public org.microproxy.http.HttpResponse proxyToServerRequest(HttpObject o) {
                                    if (o instanceof org.microproxy.http.HttpRequest r) {
                                        calls.add("proxyToServerRequest:" + r.method());
                                    }
                                    return null;
                                }

                                @Override
                                public HttpObject serverToProxyResponse(HttpObject o) {
                                    if (o instanceof org.microproxy.http.HttpResponse r) {
                                        calls.add("serverToProxyResponse:" + r.status().code() + "(" + method + ")");
                                    }
                                    return o;
                                }

                                @Override
                                public HttpObject proxyToClientResponse(HttpObject o) {
                                    if (o instanceof org.microproxy.http.HttpResponse r) {
                                        calls.add("proxyToClientResponse:" + r.status().code() + "(" + method + ")");
                                    }
                                    return o;
                                }
                            };
                        }
                    })
                    .start();
            assertEquals(200, get(client(proxy, proxyCa.clientContext()), url(secure, "/")).statusCode());
            assertEquals(List.of("proxyToServerRequest:CONNECT", "serverToProxyResponse:200(CONNECT)",
                    "proxyToClientResponse:200(CONNECT)", "proxyToServerRequest:GET", "serverToProxyResponse:200(GET)",
                    "proxyToClientResponse:200(GET)"), calls);
        } finally {
            secure.stop(0);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Requests addressed to the proxy itself
    // -------------------------------------------------------------------------------------------

    @Test
    void filterCanAnswerARequestSentDirectlyToTheProxy() {
        start(RecordingFilters.sourceOf(new HttpFilters() {
            @Override
            public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                return new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN);
            }
        }));
        // No proxy configured: the client sends an origin-form request straight to the proxy.
        HttpClient direct = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();
        HttpResponse<String> response = get(direct,
                "http://127.0.0.1:" + proxy.getListenAddress().getPort() + "/directToProxy");
        assertEquals(403, response.statusCode());
        assertEquals("", response.body());
        assertEquals(0, originHits.get());
    }

    @Test
    void requestsToTheProxyAsOriginAreForwardedWhenAllowed() {
        // The origin-form request is forwarded to its Host, which is the proxy itself; the second
        // pass carries the proxy's Via header, and the filter answers it.
        AtomicBoolean sawRequestWithoutVia = new AtomicBoolean();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withAllowRequestToOriginServer(true)
                .withProxyAlias("loop-alias")
                .withFiltersSource(RecordingFilters.sourceOf(new HttpFilters() {
                    @Override
                    public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                        if (o instanceof org.microproxy.http.HttpRequest r) {
                            String via = r.headers().get(HttpHeaderNames.VIA);
                            if (via != null && via.contains("loop-alias")) {
                                return new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NO_CONTENT);
                            }
                            sawRequestWithoutVia.set(true);
                        }
                        return null;
                    }
                }))
                .start();
        HttpClient direct = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();
        HttpResponse<String> response = get(direct,
                "http://127.0.0.1:" + proxy.getListenAddress().getPort() + "/originrequest");
        assertEquals(204, response.statusCode());
        assertTrue(sawRequestWithoutVia.get());
    }

}
