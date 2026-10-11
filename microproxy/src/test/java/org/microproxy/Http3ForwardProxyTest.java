package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http3.HeaderField;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.HttpRequest;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * A forward proxy serving HTTP/3 next to its TLS listener: proxy requests whose {@code :scheme}
 * and {@code :authority} name their targets, any authority (no 421), and proxy authentication
 * answered on the stream.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3ForwardProxyTest {

    private final SelfSignedSslContextSource tls = new SelfSignedSslContextSource();
    private HttpServer origin;
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    private HttpProxyServerBootstrap forwardProxy() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("fx").withSslContextSource(tls).withHttp3(true);
    }

    private H3TestClient client(String authority) throws Exception {
        H3TestClient.Options options = new H3TestClient.Options();
        options.authority = authority;
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        return H3TestClient.connect(address, "localhost", tls.getCertificate(), options);
    }

    private String originAuthority() {
        return "127.0.0.1:" + origin.getAddress().getPort();
    }

    @Test
    void proxyRequestsNameTheirTargetsWithSchemeAndAuthority() throws Exception {
        origin = TestSupport.origin(TestSupport.echo());
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                seen.add(originalRequest.method() + " " + originalRequest.uri() + " " + ctx.getHttpVersion());
                return null;
            }
        }).start();
        try (H3TestClient client = client(originAuthority())) {
            List<HeaderField> head = List.of(new HeaderField(":method", "GET"), new HeaderField(":scheme", "http"),
                    new HeaderField(":authority", originAuthority()), new HeaderField(":path", "/hello?x=1"));
            H3TestClient.Response r = client.readResponse(client.send(head, true));
            assertEquals(200, r.status());
            assertEquals("/hello?x=1", TestSupport.echoedUri(r.text()));
            assertEquals(List.of(originAuthority()), TestSupport.echoedHeader(r.text(), "host"));
            assertTrue(TestSupport.echoedHeader(r.text(), "via").getFirst().startsWith("3 fx"), r.text());
            assertNull(r.header("alt-svc"), "a forward proxy advertises nothing for its servers");
            assertEquals(List.of("GET http://" + originAuthority() + "/hello?x=1 HTTP/3.0"), seen);
        }
    }

    @Test
    void everyAuthorityIsServedWithout421() throws Exception {
        origin = TestSupport.origin(TestSupport.echo());
        proxy = forwardProxy().start();
        // The connection's SNI and :authority of the first request name the proxy; later ones other servers.
        try (H3TestClient client = client("localhost:" + proxy.getListenAddress().getPort())) {
            for (String authority : List.of(originAuthority(), "localhost:" + origin.getAddress().getPort())) {
                List<HeaderField> head = List.of(new HeaderField(":method", "GET"), new HeaderField(":scheme", "http"),
                        new HeaderField(":authority", authority), new HeaderField(":path", "/"));
                H3TestClient.Response r = client.readResponse(client.send(head, true));
                assertEquals(200, r.status(), authority);
                assertEquals(List.of(authority), TestSupport.echoedHeader(r.text(), "host"));
            }
        }
    }

    @Test
    void proxyAuthenticationIsAskedForOnTheStream() throws Exception {
        origin = TestSupport.origin(TestSupport.echo());
        proxy = forwardProxy().withProxyAuthenticator(new ProxyAuthenticator() {
            @Override
            public boolean authenticate(String userName, String password) {
                return "user".equals(userName) && "secret".equals(password);
            }

            @Override
            public String getRealm() {
                return "h3";
            }
        }).start();
        try (H3TestClient client = client(originAuthority())) {
            List<HeaderField> head = List.of(new HeaderField(":method", "GET"), new HeaderField(":scheme", "http"),
                    new HeaderField(":authority", originAuthority()), new HeaderField(":path", "/"));
            H3TestClient.Response refused = client.readResponse(client.send(head, true));
            assertEquals(407, refused.status());
            assertEquals("Basic realm=\"h3\"", refused.header("proxy-authenticate"));

            String credentials = "Basic " + Base64.getEncoder().encodeToString("user:secret".getBytes(StandardCharsets.UTF_8));
            List<HeaderField> authorized = new java.util.ArrayList<>(head);
            authorized.add(new HeaderField("proxy-authorization", credentials));
            H3TestClient.Response r = client.readResponse(client.send(authorized, true));
            assertEquals(200, r.status());
            assertEquals(List.of(), TestSupport.echoedHeader(r.text(), "proxy-authorization"),
                    "the proxy's credentials go no further");
            // Each stream authenticates on its own: the next one without credentials is refused again.
            assertEquals(407, client.readResponse(client.send(head, true)).status());
        }
    }

    @Test
    void aForwardProxyServesHttp3OnlyNextToItsTlsListener() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> MicroProxy.bootstrap().withPort(0).withHttp3(true).start());
        assertTrue(e.getMessage().contains("TLS listener"), e.getMessage());
        assertFalse(e.getMessage().isEmpty());
    }
}
