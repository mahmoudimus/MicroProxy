package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthenticationTest {

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final AtomicInteger authCalls = new AtomicInteger();
    private final AtomicReference<String> userSeenByFilters = new AtomicReference<>();

    @BeforeEach
    void setUp() {
        origin = origin(echo());
        proxy = MicroProxy.bootstrap().withPort(0)
                .withProxyAuthenticator(new ProxyAuthenticator() {
                    @Override
                    public boolean authenticate(String userName, String password) {
                        authCalls.incrementAndGet();
                        return "user".equals(userName) && "p:ss".equals(password);
                    }

                    @Override
                    public String getRealm() {
                        return "test-realm";
                    }
                })
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                        userSeenByFilters.set(ctx.getClientDetails().getUserName());
                        return null;
                    }
                })
                .start();
    }

    @AfterEach
    void tearDown() {
        proxy.abort();
        origin.stop(0);
    }

    private static String basic(String user, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void missingCredentialsGet407() {
        HttpResponse<String> response = TestSupport.get(client(proxy), url(origin, "/"));
        assertEquals(407, response.statusCode());
        assertEquals("Basic realm=\"test-realm\"", response.headers().firstValue("proxy-authenticate").orElseThrow());
    }

    @Test
    void wrongCredentialsGet407() {
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/")))
                .header("Proxy-Authorization", basic("user", "wrong")).build());
        assertEquals(407, response.statusCode());
    }

    @Test
    void validCredentialsAreAcceptedOncePerConnectionAndNotForwarded() {
        HttpClient client = client(proxy);
        for (int i = 0; i < 3; i++) {
            HttpResponse<String> response = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/" + i)))
                    .header("Proxy-Authorization", basic("user", "p:ss")).build());
            assertEquals(200, response.statusCode());
            assertTrue(echoedHeader(response.body(), "proxy-authorization").isEmpty());
        }
        assertEquals(1, authCalls.get());
        assertEquals("user", userSeenByFilters.get());
    }
}
