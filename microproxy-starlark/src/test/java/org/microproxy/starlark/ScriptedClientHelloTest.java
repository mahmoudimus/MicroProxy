package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.TlsHellos;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/** Scripts deciding on interception by the ClientHello ({@code on_client_hello}), and {@code ctx.client_hello}. */
class ScriptedClientHelloTest {

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private HttpsServer origin;
    private HttpProxyServer proxy;

    @BeforeAll
    static void createAuthorities() {
        originCa = CertificateAuthority.generate("Hello Origin CA");
        proxyCa = CertificateAuthority.generate("Hello Proxy CA");
    }

    @BeforeEach
    void setUp() {
        origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private void start(String source) throws Exception {
        ScriptedProxy script = ScriptedProxy.builder(source, "hello.star").build();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(script)
                .start();
    }

    private static String issuerName(CertificateAuthority ca) {
        return ca.getCertificate().getSubjectX500Principal().getName();
    }

    /** CONNECTs with {@code sni} and {@code alpn}; returns who issued the certificate, and the GET's answer. */
    private String[] visit(String sni, SSLContext trust, String... alpn) throws Exception {
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        try (SSLSocket tls = TlsHellos.throughConnect(proxy, target, sni, trust, alpn)) {
            return new String[] {TlsHellos.issuer(tls), TlsHellos.get(tls, target, "/in")};
        }
    }

    @Test
    void onClientHelloDecidesBySni() throws Exception {
        start("""
                def on_client_hello(hello: ClientHello, ctx: Context) -> bool:
                    return hello.sni != "localhost"
                """);
        assertEquals(issuerName(originCa), visit("localhost", originCa.clientContext())[0], "tunnelled");
        String[] intercepted = visit(null, proxyCa.clientContext());
        assertEquals(issuerName(proxyCa), intercepted[0]);
        assertTrue(intercepted[1].startsWith("HTTP/1.1 200"), intercepted[1]);
    }

    @Test
    void laterHooksSeeTheClientHello() throws Exception {
        start("""
                def on_client_hello(hello, ctx):
                    ctx.vars["seen"] = True

                # Unannotated: the checker does not narrow "ClientHello | None" after a None test.
                def on_request(req, ctx):
                    hello = ctx.client_hello
                    if req.method == "CONNECT":
                        req.headers["X-Unused"] = "1"
                        if hello != None:
                            fail("no ClientHello before the CONNECT is answered")
                        return None
                    req.headers["X-Sni"] = str(hello.sni)
                    req.headers["X-Alpn"] = ",".join(hello.alpn)
                    req.headers["X-Versions"] = ",".join(hello.versions)
                    req.headers["X-Suites"] = str(len(hello.cipher_suites) > 0)
                    return None
                """);
        String[] seen = visit("localhost", proxyCa.clientContext(), "http/1.1");
        assertEquals(issuerName(proxyCa), seen[0]);
        String body = seen[1].substring(seen[1].indexOf("\r\n\r\n") + 4);
        assertEquals(List.of("localhost"), TestSupport.echoedHeader(body, "x-sni"));
        assertEquals(List.of("http/1.1"), TestSupport.echoedHeader(body, "x-alpn"));
        assertTrue(TestSupport.echoedHeader(body, "x-versions").getFirst().contains("TLSv1.3"), body);
        assertEquals(List.of("True"), TestSupport.echoedHeader(body, "x-suites"));
    }

    static final String README_EXAMPLE = """
            def on_client_hello(hello, ctx):
                # Banks keep their own certificates: tunnel them untouched.
                return not (hello.sni or "").endswith(".bank.example")

            def on_request(req, ctx):
                hello = ctx.client_hello
                if hello != None:
                    req.headers["X-Client-Alpn"] = ",".join(hello.alpn)
            """;

    @Test
    void theReadmeExampleRunsAsWritten() throws Exception {
        start(ScriptedReadmeTest.inReadme(README_EXAMPLE));
        assertEquals(issuerName(originCa), visit("www.bank.example", originCa.clientContext(), "http/1.1")[0]);
        String[] intercepted = visit("localhost", proxyCa.clientContext(), "http/1.1");
        assertEquals(issuerName(proxyCa), intercepted[0]);
        String body = intercepted[1].substring(intercepted[1].indexOf("\r\n\r\n") + 4);
        assertEquals(List.of("http/1.1"), TestSupport.echoedHeader(body, "x-client-alpn"));
    }

    @Test
    void aFailingHookDeclinesInterception() throws Exception {
        start("""
                def on_client_hello(hello, ctx):
                    return "yes"
                """);
        assertEquals(issuerName(originCa), visit("localhost", originCa.clientContext())[0]);
    }

    @Test
    void theClientHelloIsTyped() {
        ScriptException e = assertThrows(ScriptException.class, () -> ScriptedProxy.builder("""
                def on_client_hello(hello: ClientHello, ctx: Context) -> bool:
                    return hello.snii == "x"
                """, "typo.star").build());
        assertTrue(e.getMessage().contains("snii"), e.getMessage());
        assertThrows(ScriptException.class, () -> ScriptedProxy.builder("""
                def on_client_hello(hello: ClientHello, ctx: Context) -> bool:
                    return hello.alpn + 1 == 2
                """, "types.star").build());
    }
}
