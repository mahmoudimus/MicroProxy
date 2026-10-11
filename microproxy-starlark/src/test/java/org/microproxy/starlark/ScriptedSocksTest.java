package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.SocksClient;
import org.microproxy.TestSupport;

/** Scripts see SOCKS clients ({@code ctx.socks_version}), and authenticate them with their SOCKS5 credentials. */
class ScriptedSocksTest {

    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(TestSupport.echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private static final String SCRIPT = """
            def authenticate(req, ctx):
                if ctx.socks_version == 4:
                    return "socks4-client"
                if req.headers.get("Proxy-Authorization", "") == "Basic " + base64.encode("alice:secret"):
                    return "alice"
                return False

            def on_request(req, ctx):
                if req.method != "CONNECT":
                    req.headers["X-Socks"] = str(ctx.socks_version)
                    req.headers["X-User"] = str(ctx.user)
            """;

    private String get(SocksClient c) throws Exception {
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        c.write("GET /scripted HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n");
        String response = new String(c.input().readAllBytes(), StandardCharsets.ISO_8859_1);
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        return response.substring(response.indexOf("\r\n\r\n") + 4);
    }

    @Test
    void scriptsSeeTheSocksVersionAndAuthenticateSocksClients() throws Exception {
        ScriptedProxy script = ScriptedProxy.builder(SCRIPT, "socks.star").build();
        proxy = MicroProxy.bootstrap().withPort(0).withSocksDetection(true)
                .withFiltersSource(script).withProxyAuthenticator(script).start();
        int port = origin.getAddress().getPort();
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(SocksClient.USERNAME_PASSWORD, c.greet(SocksClient.NO_AUTHENTICATION, SocksClient.USERNAME_PASSWORD));
            assertEquals(0, c.authenticate("alice", "secret"));
            assertEquals(0, c.connect("127.0.0.1", port));
            String body = get(c);
            assertEquals(List.of("5"), TestSupport.echoedHeader(body, "X-Socks"));
            assertEquals(List.of("alice"), TestSupport.echoedHeader(body, "X-User"));
        }
        try (SocksClient c = new SocksClient(proxy)) {
            c.greet(SocksClient.USERNAME_PASSWORD);
            assertEquals(1, c.authenticate("alice", "wrong"));
        }
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(90, c.socks4(SocksClient.CONNECT, "127.0.0.1", port, ""));
            String body = get(c);
            assertEquals(List.of("4"), TestSupport.echoedHeader(body, "X-Socks"));
            assertEquals(List.of("socks4-client"), TestSupport.echoedHeader(body, "X-User"));
        }
        // An HTTP client of the same listener has no SOCKS version.
        try (RawHttp http = new RawHttp(proxy.getListenAddress())) {
            RawHttp.Response response = http.send("GET", TestSupport.url(origin, "/http"),
                    "Proxy-Authorization: Basic " + java.util.Base64.getEncoder().encodeToString(
                            "alice:secret".getBytes(StandardCharsets.UTF_8)));
            assertEquals(200, response.status());
            assertEquals(List.of("None"), TestSupport.echoedHeader(response.body(), "X-Socks"));
        }
    }
}
