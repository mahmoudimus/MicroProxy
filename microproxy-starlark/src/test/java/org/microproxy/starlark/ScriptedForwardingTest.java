package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.List;
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

/** Scripts see a {@code CONNECT} forwarded to an intercepted HTTPS proxy ({@code ctx.forwarded_via}). */
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
}
