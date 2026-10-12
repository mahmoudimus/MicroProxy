package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http3.HeaderField;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.ActivityTracker;
import org.microproxy.ClientHello;
import org.microproxy.FlowContext;
import org.microproxy.H3TestClient;
import org.microproxy.Http3Options;
import org.microproxy.HttpProxyServer;
import org.microproxy.MasqueBridge;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * HTTP/3 inside a CONNECT-UDP flow, intercepted with {@code connectUdpInterceptQuic}: the script's
 * {@code on_client_hello}, {@code on_request} and {@code on_frame} see it as they see transparent
 * QUIC.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ScriptedMasqueQuicTest {

    private static final CertificateAuthority PROXY_CA = CertificateAuthority.generate("Scripted MASQUE Proxy CA");
    private static final CertificateAuthority ORIGIN_CA = CertificateAuthority.generate("Scripted MASQUE Origin CA");
    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();

    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();
    private final List<String> decided = new CopyOnWriteArrayList<>();

    static final String SCRIPT = """
            def on_client_hello(hello, ctx):
                log.info("QUIC in a flow for %s, ALPN %s" % (hello.sni, hello.alpn))
                return None

            def on_request(req, ctx):
                # The CONNECT-UDP request is the MASQUE client's own; the requests inside, the QUIC's.
                if ctx.transparent_quic:
                    req.headers["x-quic"] = "%s %s %s" % (ctx.transparent_quic, req.http_version, ctx.client_hello.sni)
            """;

    @AfterEach
    void tearDown() throws Exception {
        for (int i = closeables.size() - 1; i >= 0; i--) closeables.get(i).close();
    }

    @Test
    void scriptsSeeHttp3InsideAFlow() throws Exception {
        HttpsServer origin = TestSupport.httpsOrigin(ORIGIN_CA.serverContext("origin.test"), TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        ScriptedProxy script = ScriptedProxy.builder(SCRIPT + ScriptedHttp3Test.ON_FRAME,
                "masque.star").build();
        HttpProxyServer proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withSslContextSource(TLS)
                .withHttp3(true)
                .withHttp3Options(Http3Options.builder().connectUdpInterceptQuic(true).connectUdpQuicPorts().build())
                .withServerResolver((host, port) -> {
                    if (host.endsWith(".test")) return new InetSocketAddress(TestSupport.LOOPBACK, port);
                    throw new UnknownHostException(host);
                })
                .withManInTheMiddle(new CertificateAuthorityMitmManager(PROXY_CA, ORIGIN_CA.clientContext()))
                .withFiltersSource(script)
                .withFrameInterceptor(script.frameInterceptor())
                .plusActivityTracker(new ActivityTracker() {
                    @Override
                    public void transparentQuicFlowDecided(FlowContext flow, ClientHello hello, boolean intercepted,
                            String reason) {
                        decided.add(hello.sni() + " " + intercepted + " " + reason);
                    }
                })
                .start();
        closeables.add(proxy::abort);
        int port = origin.getAddress().getPort();
        try (H3TestClient inner = H3TestClient.connect(flowTo(proxy, "origin.test", port).address(), "origin.test",
                PROXY_CA.getCertificate())) {
            H3TestClient.Response r = inner.get("/quic");
            assertEquals(200, r.status());
            assertEquals(List.of("True HTTP/3 origin.test"), TestSupport.echoedHeader(r.text(), "x-quic"));
            assertEquals(List.of("stream 0"), TestSupport.echoedHeader(r.text(), "x-from-frame"));
            assertEquals("edited", r.header("x-h3-frame"));
        }
        assertEquals(List.of("origin.test true null"), decided);
    }

    /** A MASQUE client's flow to {@code host:port}, bridged to a local UDP socket. */
    private MasqueBridge flowTo(HttpProxyServer proxy, String host, int port) throws Exception {
        int listener = proxy.getListenAddress().getPort();
        H3TestClient masque = H3TestClient.connect(new InetSocketAddress(TestSupport.LOOPBACK, listener), "localhost",
                TLS.getCertificate());
        closeables.add(masque);
        H3TestClient.Tunnel tunnel = masque.open(H3TestClient.extendedConnect("connect-udp", "https",
                "localhost:" + listener, "/.well-known/masque/udp/" + host + "/" + port + "/",
                new HeaderField("capsule-protocol", "?1")));
        assertEquals(200, tunnel.status);
        MasqueBridge bridge = new MasqueBridge(masque, tunnel);
        closeables.add(bridge);
        return bridge;
    }
}
