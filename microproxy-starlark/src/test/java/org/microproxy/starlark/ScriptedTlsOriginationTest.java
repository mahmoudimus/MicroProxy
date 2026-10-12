package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Scripts see a client's {@code https://} request to a forward proxy, which the proxy fetches over
 * TLS of its own, as {@code https}: in {@code on_request} and, when the server's certificate is
 * refused, in {@code on_failure}.
 */
class ScriptedTlsOriginationTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("Scripted Origination Origin CA");
    static final CertificateAuthority strangerCa = CertificateAuthority.generate("Scripted Origination Stranger CA");

    private HttpProxyServer proxy;
    private HttpsServer origin;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    private void start(CertificateAuthority serverCa) throws Exception {
        origin = TestSupport.httpsOrigin(serverCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        ScriptedProxy script = ScriptedProxy.builder("""
                def on_request(req, ctx):
                    req.headers["X-Seen"] = "%s %s %s %d" % (req.scheme, req.url, req.host, req.port)

                def on_response(req, res, ctx):
                    # The proxy has made the request origin-form for the server by now.
                    res.headers["X-Url"] = req.scheme + " " + req.url

                def on_failure(req, failure, ctx):
                    return response(599, "%s %s %s" % (failure.kind, ",".join(ctx.response_flags), req.url))
                """, "origination.star").build();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(
                        CertificateAuthority.generate("Scripted Origination Proxy CA"), originCa.clientContext()))
                .withFiltersSource(script).start();
    }

    private String fetch(String url) throws Exception {
        String authority = url.substring("https://".length(), url.indexOf('/', "https://".length()));
        return TestSupport.rawExchange(proxy.getListenAddress(),
                "GET " + url + " HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n");
    }

    @Test
    void onRequestSeesTheHttpsScheme() throws Exception {
        start(originCa);
        int port = origin.getAddress().getPort();
        String url = "https://127.0.0.1:" + port + "/path?q=1";
        String raw = fetch(url);
        assertTrue(raw.startsWith("HTTP/1.1 200"), raw);
        String body = raw.substring(raw.indexOf("\r\n\r\n") + 4);
        assertEquals(List.of("https " + url + " 127.0.0.1 " + port), TestSupport.echoedHeader(body, "x-seen"));
        assertEquals("/path?q=1", TestSupport.echoedUri(body));
        assertTrue(raw.contains("\r\nX-Url: https " + url + "\r\n"), raw);
    }

    @Test
    void onFailureSeesTheRefusedCertificate() throws Exception {
        start(strangerCa);
        String url = "https://127.0.0.1:" + origin.getAddress().getPort() + "/x";
        String raw = fetch(url);
        assertTrue(raw.startsWith("HTTP/1.1 599"), raw);
        assertTrue(raw.endsWith("tls_failed UF " + url), raw);
    }
}
