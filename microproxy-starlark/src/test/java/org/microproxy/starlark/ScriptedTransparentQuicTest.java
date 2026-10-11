package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.tls.CertifiedKey;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.ActivityTracker;
import org.microproxy.ClientHello;
import org.microproxy.FlowContext;
import org.microproxy.H3TestClient;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Scripts deciding on, and seeing, the QUIC of the transparent QUIC listener: {@code
 * on_client_hello} relays one host and lets another be intercepted, whose HTTP/3 requests {@code
 * on_request} sees with {@code ctx.transparent_quic} and {@code on_frame} edits as they pass.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ScriptedTransparentQuicTest {

    static final String SCRIPT = """
            def on_client_hello(hello, ctx):
                if hello.sni == "skip.test" and ctx.transparent_quic and hello.alpn == ["h3"]:
                    return False
                return None

            def on_request(req, ctx):
                req.headers["x-quic"] = "%s %s %s" % (ctx.transparent_quic, req.http_version, ctx.client_hello.sni)
            """;

    private static final CertificateAuthority PROXY_CA = CertificateAuthority.generate("Scripted QUIC Proxy CA");
    private static final CertificateAuthority ORIGIN_CA = CertificateAuthority.generate("Scripted QUIC Origin CA");

    private final List<String> decided = new CopyOnWriteArrayList<>();
    private HttpsServer origin;
    private QuicServer skipped;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() throws Exception {
        origin = TestSupport.httpsOrigin(ORIGIN_CA.serverContext("origin.test", "skip.test"), TestSupport.echo());
        skipped = quicServer(origin.getAddress().getPort());
        ScriptedProxy script = ScriptedProxy.builder(SCRIPT + ScriptedHttp3Test.ON_FRAME, "quic.star").build();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(origin.getAddress().getPort())
                .withTransparentQuicPort(0)
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
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (skipped != null) skipped.close();
        if (origin != null) origin.stop(0);
    }

    /** A QUIC server for {@code skip.test} on UDP {@code port}, offering h3, that only completes handshakes. */
    private static QuicServer quicServer(int port) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        X509Certificate leaf = ORIGIN_CA.issue(keys.getPublic(), List.of("skip.test"));
        ServerConfig config = ServerConfig.builder(TlsConfig.builder()
                .certificate(new CertifiedKey(List.of(leaf, ORIGIN_CA.getCertificate()), keys.getPrivate()))
                .alpnProtocols("h3")
                .build()).build();
        QuicServer server = QuicServer.bind(new InetSocketAddress(TestSupport.LOOPBACK, port), config);
        Thread.ofVirtual().start(() -> {
            try {
                while (true) {
                    QuicConnection c = server.accept();
                    c.close(0, "");
                }
            } catch (IOException e) {
                // closed
            }
        });
        return server;
    }

    private InetSocketAddress quicAddress() {
        return new InetSocketAddress(TestSupport.LOOPBACK, proxy.getTransparentQuicAddress().getPort());
    }

    @Test
    void onClientHelloDecidesAndHooksSeeTheInterceptedHttp3() throws Exception {
        try (H3TestClient client = H3TestClient.connect(quicAddress(), "origin.test", PROXY_CA.getCertificate())) {
            H3TestClient.Response r = client.get("/quic");
            assertEquals(200, r.status());
            assertEquals(List.of("True HTTP/3 origin.test"), TestSupport.echoedHeader(r.text(), "x-quic"));
            assertEquals(List.of("stream 0"), TestSupport.echoedHeader(r.text(), "x-from-frame"));
            assertEquals("edited", r.header("x-h3-frame"));
        }
        // Relayed: the client trusts only the origin's CA, so its handshake is the real server's.
        H3TestClient.connect(quicAddress(), "skip.test", ORIGIN_CA.getCertificate()).close();
        assertEquals(List.of("origin.test true null", "skip.test false a filter declined"), decided);
    }
}
