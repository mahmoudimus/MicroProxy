package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.extras.RewriteRules;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

class RewriteRulesTest {

    private static final String PAGE = "<html><body>Hello World</body></html>";

    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(exchange -> {
            byte[] body;
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/big")) {
                body = ("Hello World " + "x".repeat(5000)).getBytes(StandardCharsets.UTF_8);
            } else {
                body = PAGE.getBytes(StandardCharsets.UTF_8);
            }
            exchange.getResponseHeaders().set("Content-Type", path.equals("/image") ? "image/png" : "text/html; charset=utf-8");
            exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'");
            exchange.getResponseHeaders().set("X-Saw-Header", String.valueOf(exchange.getRequestHeaders().getFirst("X-Added")));
            if (path.equals("/gzip")) {
                body = HttpBodiesTest.gzip(body);
                exchange.getResponseHeaders().set("Content-Encoding", "gzip");
            } else if (path.equals("/zstd")) {
                // PAGE compressed by the zstd CLI.
                body = java.util.HexFormat.of().parseHex("28b52ffd04582901003c68746d6c3e3c626f64793e48656c6c6f20576f726c64"
                        + "3c2f626f64793e3c2f68746d6c3e29bceed1");
                exchange.getResponseHeaders().set("Content-Encoding", "zstd");
            }
            exchange.getResponseHeaders().set("X-Accept-Encoding",
                    String.valueOf(exchange.getRequestHeaders().getFirst("Accept-Encoding")));
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(RewriteRules.builder()
                .add(RewriteRules.Rule.matching("http://127\\.0\\.0\\.1:\\d+/(page|gzip|zstd|image|big).*")
                        .replaceInBody("W(o)rld", "W$1rld!")
                        .replaceLiteralInBody("Hello", "Howdy")
                        .removeResponseHeader("Content-Security-Policy")
                        .setRequestHeader("X-Added", "yes"))
                .maxBodySize(1000)
                .build()).start();
    }

    @AfterEach
    void tearDown() {
        proxy.abort();
        origin.stop(0);
    }

    @Test
    void rewritesMatchingTextResponses() {
        HttpResponse<String> r = get(client(proxy), url(origin, "/page?x=1"));
        assertEquals("<html><body>Howdy World!</body></html>", r.body());
        assertFalse(r.headers().firstValue("content-security-policy").isPresent());
        assertEquals("yes", r.headers().firstValue("x-saw-header").orElseThrow());
        assertEquals(String.valueOf(r.body().length()), r.headers().firstValue("content-length").orElseThrow());
    }

    @Test
    void decodesAndReencodesGzip() throws Exception {
        HttpResponse<byte[]> r = client(proxy).send(HttpRequest.newBuilder(URI.create(url(origin, "/gzip"))).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals("gzip", r.headers().firstValue("content-encoding").orElseThrow());
        String body = new String(new GZIPInputStream(new ByteArrayInputStream(r.body())).readAllBytes(), StandardCharsets.UTF_8);
        assertEquals("<html><body>Howdy World!</body></html>", body);
    }

    @Test
    void decodesZstdAndReencodesItAsGzip() throws Exception {
        HttpResponse<byte[]> r = client(proxy).send(HttpRequest.newBuilder(URI.create(url(origin, "/zstd")))
                        .header("Accept-Encoding", "zstd, dcz, gzip").build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals("gzip", r.headers().firstValue("content-encoding").orElseThrow());
        String body = new String(new GZIPInputStream(new ByteArrayInputStream(r.body())).readAllBytes(), StandardCharsets.UTF_8);
        assertEquals("<html><body>Howdy World!</body></html>", body);
        // The server was only offered codings the rules can read.
        assertEquals("zstd, gzip", r.headers().firstValue("x-accept-encoding").orElseThrow());
    }

    @Test
    void leavesOtherResponsesAlone() {
        // Not matched by the rule.
        HttpResponse<String> other = get(client(proxy), url(origin, "/other"));
        assertEquals(PAGE, other.body());
        assertTrue(other.headers().firstValue("content-security-policy").isPresent());
        // Matched, but not text: headers change, body does not.
        HttpResponse<String> image = get(client(proxy), url(origin, "/image"));
        assertEquals(PAGE, image.body());
        assertFalse(image.headers().firstValue("content-security-policy").isPresent());
        // Matched, but larger than maxBodySize: streamed through unmodified.
        HttpResponse<String> big = get(client(proxy), url(origin, "/big"));
        assertTrue(big.body().startsWith("Hello World xxx"));
        assertEquals(5012, big.body().length());
    }

    @Test
    void matchesHttpsUrlsInsideInterceptedSessions() {
        CertificateAuthority originCa = CertificateAuthority.generate("Rewrite Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Rewrite Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"),
                TestSupport.fixed(200, "secret page"));
        HttpProxyServer mitm = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(RewriteRules.builder()
                        .add(RewriteRules.Rule.prefix("https://127.0.0.1:" + secure.getAddress().getPort() + "/")
                                .setResponseHeader("X-Rewritten", "https"))
                        .build())
                .start();
        try {
            HttpResponse<String> r = get(client(mitm, proxyCa.clientContext()), url(secure, "/s"));
            assertEquals("https", r.headers().firstValue("x-rewritten").orElseThrow());
        } finally {
            mitm.abort();
            secure.stop(0);
        }
    }
}
