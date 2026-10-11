package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.AioquicPeers;
import org.microproxy.H3TestClient;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Scripts on live HTTP/3: a reverse proxy serving HTTP/3, whose {@code on_request} and {@code
 * on_response} see {@code req.http_version} {@code "HTTP/3"}, and whose {@code on_frame} edits
 * the {@code h3} HEADERS and DATA frames of the client's connection as they pass. With the Java
 * HTTP/3 client, and with aioquic's when Python has it.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class ScriptedHttp3Test {

    static final String HOOKS = """
            def on_request(req, ctx):
                req.headers["x-version"] = req.http_version

            def on_response(req, res, ctx):
                res.headers["x-seen-version"] = req.http_version

            """;

    /** The README's live HTTP/3 example. */
    static final String ON_FRAME = """
            def on_frame(frame, ctx):
                if frame.protocol != "h3":
                    return None
                if frame.type == "HEADERS" and frame.direction == "from_client" and ":method" in frame.headers:
                    frame.headers["x-from-frame"] = "stream %d" % ctx.stream_id
                elif frame.type == "HEADERS" and frame.direction == "to_client" and ":status" in frame.headers:
                    frame.headers.remove("content-length")  # the DATA below changes the body's length
                    frame.headers["x-h3-frame"] = "edited"
                elif frame.type == "DATA" and frame.direction == "to_client" and frame.text != None:
                    frame.text = frame.text.replace("secret", "[redacted]")
            """;

    private static final CertificateAuthority CA = CertificateAuthority.generate("Scripted H3 CA");

    @TempDir
    Path dir;

    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() throws Exception {
        origin = TestSupport.origin(TestSupport.echo());
        ScriptedProxy script = ScriptedProxy.builder(HOOKS + ScriptedReadmeTest.inReadme(ON_FRAME), "h3.star").build();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withManInTheMiddle(new CertificateAuthorityMitmManager(CA))
                .withHttp3(true)
                .withFiltersSource(script)
                .withFrameInterceptor(script.frameInterceptor())
                .start();
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    @Test
    void scriptsSeeAndEditLiveHttp3() throws Exception {
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        try (H3TestClient client = H3TestClient.connect(address, "localhost", CA.getCertificate())) {
            H3TestClient.Response r = client.post("/form", "a secret value".getBytes(StandardCharsets.UTF_8));
            assertEquals(200, r.status());
            assertEquals("HTTP/3", r.header("x-seen-version"));
            assertEquals("edited", r.header("x-h3-frame"));
            assertNull(r.header("content-length"));
            assertEquals(List.of("HTTP/3"), TestSupport.echoedHeader(r.text(), "x-version"));
            assertEquals(List.of("stream 0"), TestSupport.echoedHeader(r.text(), "x-from-frame"));
            assertEquals("a [redacted] value", TestSupport.echoedBody(r.text()));
        }
    }

    @Test
    void scriptsSeeAndEditAnAioquicClientsHttp3() throws Exception {
        AioquicPeers.assumeAvailable();
        Path ca = AioquicPeers.certificates(dir.resolve("ca.pem"), CA.getCertificate());
        Map<String, Object> post = AioquicPeers.request("POST", "/form");
        post.put("body", "another secret here");
        List<Map<String, Object>> responses = AioquicPeers.requests(dir, proxy.getListenAddress().getPort(), ca,
                List.of(post, AioquicPeers.request("GET", "/second")), false);
        Map<String, Object> r = responses.getFirst();
        assertEquals(200L, r.get("status"));
        assertEquals("HTTP/3", AioquicPeers.field(r, "headers", "x-seen-version"));
        assertEquals("edited", AioquicPeers.field(r, "headers", "x-h3-frame"));
        String text = (String) r.get("text");
        assertEquals(List.of("HTTP/3"), TestSupport.echoedHeader(text, "x-version"));
        assertEquals(List.of("stream 0"), TestSupport.echoedHeader(text, "x-from-frame"));
        assertEquals("another [redacted] here", TestSupport.echoedBody(text));
        assertTrue(((String) responses.get(1).get("text")).contains("h:x-from-frame: stream 4"));
    }
}
