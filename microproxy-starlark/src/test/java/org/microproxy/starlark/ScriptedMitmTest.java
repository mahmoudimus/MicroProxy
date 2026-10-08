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
import java.net.http.HttpResponse;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
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
    }

    @Test
    void allowMitmCanDecline() throws Exception {
        start(false);
        assertEquals(200, get(client(proxy, originCa.clientContext()), url(origin, "/")).statusCode());
        assertThrows(UncheckedIOException.class, () -> get(client(proxy, proxyCa.clientContext()), url(origin, "/")));
    }
}
