package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpsServer;
import java.io.UncheckedIOException;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.extras.MapRemote;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

class ScriptedMitmTest {

    static CertificateAuthority originCa;
    static CertificateAuthority proxyCa;

    private HttpsServer origin;
    private HttpProxyServer proxy;

    @BeforeAll
    static void createAuthorities() {
        originCa = CertificateAuthority.generate("Test Origin CA");
        proxyCa = CertificateAuthority.generate("Test Proxy CA");
    }

    @BeforeEach
    void setUp() {
        origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private void start(boolean intercept) throws Exception {
        ScriptedProxy script = ScriptedProxy.builder("""
                def allow_mitm(req, ctx):
                    return req.method == "CONNECT" and req.host == "127.0.0.1" and INTERCEPT

                def on_request(req, ctx):
                    if req.method != "CONNECT":
                        req.headers["X-Url"] = req.url

                def on_response(req, res, ctx):
                    res.headers["X-Tls"] = str(ctx.tls)
                    if req.method != "CONNECT":
                        t = ctx.timings
                        # The server handshake belongs to the CONNECT; the client's to this session.
                        res.headers["X-Timings"] = "%s %s" % (t.tls_ms != None, t.client_tls_ms != None)
                """.replace("INTERCEPT", intercept ? "True" : "False"), "mitm.star").build();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(script)
                .withChainProxyManager(script)
                .start();
    }

    @Test
    void interceptedRequestsSeeTheirHttpsUrl() throws Exception {
        start(true);
        String target = url(origin, "/a?b=1");
        HttpResponse<String> response = get(client(proxy, proxyCa.clientContext()), target);
        assertEquals(200, response.statusCode());
        assertEquals(List.of(target), echoedHeader(response.body(), "x-url"));
        assertEquals("True", response.headers().firstValue("x-tls").orElseThrow());
        assertEquals("False True", response.headers().firstValue("x-timings").orElseThrow());
    }

    @Test
    void scriptsSeeTheHttpVersion() throws Exception {
        ScriptedProxy script = ScriptedProxy.builder("""
                def on_request(req, ctx):
                    if req.method != "CONNECT":
                        req.headers["X-Seen-Version"] = req.http_version

                def on_response(req, res, ctx):
                    res.headers["X-Version"] = req.http_version
                """, "version.star").build();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp2(true)
                .withFiltersSource(script)
                .start();
        HttpClient h2 = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
                .proxy(ProxySelector.of(proxy.getListenAddress())).sslContext(proxyCa.clientContext()).build();
        HttpResponse<String> response = get(h2, url(origin, "/v"));
        assertEquals(HttpClient.Version.HTTP_2, response.version());
        assertEquals(List.of("HTTP/2"), echoedHeader(response.body(), "x-seen-version"));
        assertEquals("HTTP/2", response.headers().firstValue("x-version").orElseThrow());

        HttpResponse<String> http1 = get(client(proxy, proxyCa.clientContext()), url(origin, "/v"));
        assertEquals(List.of("HTTP/1.1"), echoedHeader(http1.body(), "x-seen-version"));
        assertEquals("HTTP/1.1", http1.headers().firstValue("x-version").orElseThrow());
    }

    @Test
    void allowMitmCanDecline() throws Exception {
        start(false);
        assertEquals(200, get(client(proxy, originCa.clientContext()), url(origin, "/")).statusCode());
        assertThrows(UncheckedIOException.class, () -> get(client(proxy, proxyCa.clientContext()), url(origin, "/")));
    }

    @Test
    void assigningAnAbsoluteUriMovesTheRequestToAnotherServer() throws Exception {
        HttpsServer other = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), exchange -> {
            exchange.getResponseHeaders().set("X-Origin", "other");
            echo().handle(exchange);
        });
        try {
            ScriptedProxy script = ScriptedProxy.builder("""
                    def on_request(req, ctx):
                        if req.method != "CONNECT" and req.path.startswith("/elsewhere/"):
                            req.uri = "https://localhost:PORT" + req.uri[len("/elsewhere"):]
                    """.replace("PORT", String.valueOf(other.getAddress().getPort())), "move.star").build();
            // Scripts compose with the addons like any filters source: here map_remote runs after the
            // script and sees the URL the script made.
            proxy = MicroProxy.bootstrap().withPort(0)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .withFiltersSource(HttpFiltersChain.of(script, MapRemote.of("|/moved/|/mapped/")))
                    .start();
            HttpClient client = client(proxy, proxyCa.clientContext());
            HttpResponse<String> moved = get(client, url(origin, "/elsewhere/moved/x?y=1"));
            assertEquals("other", moved.headers().firstValue("X-Origin").orElseThrow());
            assertEquals("/mapped/x?y=1", TestSupport.echoedUri(moved.body()));
            assertEquals(List.of("localhost:" + other.getAddress().getPort()), echoedHeader(moved.body(), "host"));
            HttpResponse<String> stays = get(client, url(origin, "/here"));
            assertEquals(List.of(), stays.headers().allValues("X-Origin"));
        } finally {
            other.stop(0);
        }
    }
}
