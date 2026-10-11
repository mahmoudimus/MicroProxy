package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.ActivityTrackerAdapter;
import org.microproxy.FlowContext;
import org.microproxy.H2StreamClient;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.HttpRequest;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Scripts see requests forwarded to the proxy a client uses through MicroProxy ({@code
 * ctx.forwarded_via}): an intercepted HTTPS proxy, or a plain-HTTP proxy whose session is plain HTTP.
 */
class ScriptedForwardingTest {

    static final CertificateAuthority serverCa = CertificateAuthority.generate("Scripted Forwarding Server CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Scripted Forwarding Proxy CA");

    private HttpProxyServer proxy;
    private HttpProxyServer corp;
    private TestSupport.RawServer echo;

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        if (corp != null) corp.abort();
        if (echo != null) echo.close();
    }

    @Test
    void scriptsBlockAndMarkForwardedConnects() throws Exception {
        echo = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()));
        List<String> corpSaw = new CopyOnWriteArrayList<>();
        corp = MicroProxy.bootstrap().withPort(0)
                .withSslContextSource(() -> serverCa.serverContext("localhost", "127.0.0.1"))
                .withHttp2(true)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void requestReceivedFromClient(FlowContext ctx, HttpRequest r) {
                        corpSaw.add(r.method() + " " + r.uri() + " " + r.headers().get("X-Forwarded-Via"));
                    }
                }).start();
        ScriptedProxy script = ScriptedProxy.builder("""
                def allow_mitm(req, ctx):
                    # Intercept the session with the corporate proxy, not the tunnels through it.
                    return ctx.forwarded_via == None

                def on_request(req, ctx):
                    if req.method == "CONNECT" and ctx.forwarded_via != None:
                        if req.host == "blocked.test":
                            return response(403, "not through " + ctx.forwarded_via)
                        req.headers["X-Forwarded-Via"] = ctx.forwarded_via
                    return None
                """, "forwarding.star").build();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, serverCa.clientContext()))
                .withHttp2(true)
                .withHttp2Upstream(true)
                .withFiltersSource(script)
                .start();
        String corpTarget = "localhost:" + corp.getListenAddress().getPort();
        String target = "127.0.0.1:" + echo.port();
        try (H2StreamClient c = H2StreamClient.intercepted(proxy.getListenAddress(), corpTarget, proxyCa.clientContext())) {
            H2StreamClient.Stream blocked = c.open(H2StreamClient.connect("blocked.test:443"), false);
            assertEquals(403, blocked.status());
            assertEquals("not through " + corpTarget, blocked.text());
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target), false);
            assertEquals(200, tunnel.status());
            tunnel.out().write("scripted".getBytes(StandardCharsets.UTF_8));
            tunnel.end();
            assertEquals("scripted", tunnel.text());
        }
        assertEquals(List.of("CONNECT " + target + " " + corpTarget), corpSaw);
    }

    @Test
    void scriptsSeeTheHttpProxyOfAPlainSession() throws Exception {
        echo = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()));
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        try {
            List<String> corpSaw = new CopyOnWriteArrayList<>();
            // A plain-HTTP forward proxy.
            corp = MicroProxy.bootstrap().withPort(0)
                    .plusActivityTracker(new ActivityTrackerAdapter() {
                        @Override
                        public void requestReceivedFromClient(FlowContext ctx, HttpRequest r) {
                            corpSaw.add(r.method() + " " + r.uri() + " " + r.headers().get("X-Forwarded-Via"));
                        }
                    }).start();
            ScriptedProxy script = ScriptedProxy.builder("""
                    def allow_mitm(req, ctx):
                        return ctx.forwarded_via == None

                    def on_request(req, ctx):
                        if ctx.forwarded_via != None:
                            if req.host == "blocked.test":
                                return response(403, "not through " + ctx.forwarded_via)
                            req.headers["X-Forwarded-Via"] = ctx.forwarded_via
                        return None
                    """, "plain-forwarding.star").build();
            proxy = MicroProxy.bootstrap().withPort(0)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, serverCa.clientContext()))
                    .withFiltersSource(script)
                    .start();
            String corpTarget = "127.0.0.1:" + corp.getListenAddress().getPort();
            String site = "127.0.0.1:" + origin.getAddress().getPort();
            String target = "127.0.0.1:" + echo.port();
            try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
                s.setSoTimeout(20_000);
                assertTrue(exchange(s, "CONNECT " + corpTarget, corpTarget).startsWith("HTTP/1.1 200"));
                String blocked = exchange(s, "GET http://blocked.test/", "blocked.test");
                assertTrue(blocked.startsWith("HTTP/1.1 403"), blocked);
                assertEquals("not through " + corpTarget, body(s, blocked));
                String page = exchange(s, "GET http://" + site + "/page", site);
                assertTrue(page.startsWith("HTTP/1.1 200"), page);
                assertTrue(body(s, page).contains("uri: /page"));
                assertTrue(exchange(s, "CONNECT " + target, target).startsWith("HTTP/1.1 200"));
                TestSupport.write(s.getOutputStream(), "plain");
                assertEquals("plain", new String(s.getInputStream().readNBytes(5), StandardCharsets.UTF_8));
            }
            assertEquals(List.of("GET http://" + site + "/page " + corpTarget, "CONNECT " + target + " " + corpTarget),
                    corpSaw);
        } finally {
            origin.stop(0);
        }
    }

    /** Sends {@code requestLine} with {@code Host} and returns the response head. */
    private static String exchange(Socket s, String requestLine, String host) throws IOException {
        TestSupport.write(s.getOutputStream(), requestLine + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n");
        return TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
    }

    private static String body(Socket s, String head) throws IOException {
        String length = head.lines().filter(l -> l.toLowerCase(Locale.ROOT).startsWith("content-length:"))
                .findFirst().orElseThrow().substring("content-length:".length()).strip();
        return new String(s.getInputStream().readNBytes(Integer.parseInt(length)), StandardCharsets.UTF_8);
    }
}
