package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpVersion;

class UpstreamProxyManagerTest {

    @Test
    void noProxyRules() {
        NoProxyRules rules = NoProxyRules.parse("localhost, .corp.example, *.internal, 10.0.0.0/8, ::1, fd00::/8, api.test:8443");
        assertTrue(rules.matches("localhost", 80));
        assertTrue(rules.matches("corp.example", 80));
        assertTrue(rules.matches("a.b.corp.example", 443));
        assertFalse(rules.matches("notcorp.example", 80));
        assertTrue(rules.matches("svc.internal", 80));
        assertTrue(rules.matches("10.20.30.40", 80));
        assertFalse(rules.matches("11.0.0.1", 80));
        assertTrue(rules.matches("[::1]", 80));
        assertTrue(rules.matches("fd12:3456::1", 80));
        assertTrue(rules.matches("api.test", 8443));
        assertFalse(rules.matches("api.test", 443));
        assertTrue(NoProxyRules.parse("*").matches("anything", 1));
        assertFalse(NoProxyRules.parse("").matches("anything", 1));
    }

    @Test
    void proxyUrls() {
        ChainedProxy p = UpstreamProxyManager.proxy("http://us%40er:p%3Ass@proxy.corp:3128");
        assertEquals("proxy.corp", p.getChainedProxyAddress().getHostString());
        assertEquals(3128, p.getChainedProxyAddress().getPort());
        assertEquals("us@er", p.getUsername());
        assertEquals("p:ss", p.getPassword());
        assertEquals(ChainedProxyType.HTTP, p.getChainedProxyType());
        assertFalse(p.requiresEncryption());
        assertFalse(p.toString().contains("p%3Ass"), "credentials must not leak into toString");

        ChainedProxy tls = UpstreamProxyManager.proxy("https://secure.proxy");
        assertTrue(tls.requiresEncryption());
        assertEquals(443, tls.getChainedProxyAddress().getPort());
        assertEquals(ChainedProxyType.SOCKS5, UpstreamProxyManager.proxy("socks5h://s:1081").getChainedProxyType());
        assertEquals(ChainedProxyType.SOCKS4, UpstreamProxyManager.proxy("socks4a://s").getChainedProxyType());
        assertEquals(1080, UpstreamProxyManager.proxy("socks5://s").getChainedProxyAddress().getPort());
        assertEquals(80, UpstreamProxyManager.proxy("plainhost").getChainedProxyAddress().getPort());
        assertThrows(IllegalArgumentException.class, () -> UpstreamProxyManager.proxy("ftp://x"));
    }

    private static List<ChainedProxy> route(ChainedProxyManager m, HttpMethod method, String uri) {
        ArrayDeque<ChainedProxy> q = new ArrayDeque<>();
        m.lookupChainedProxies(new DefaultHttpRequest(HttpVersion.HTTP_1_1, method, uri), q, new ClientDetails());
        return List.copyOf(q);
    }

    @Test
    void environmentFollowsCurl() {
        assertNull(UpstreamProxyManager.fromEnvironment(Map.of()));
        // Upper-case HTTP_PROXY is ignored, as in curl.
        assertNull(UpstreamProxyManager.fromEnvironment(Map.of("HTTP_PROXY", "http://evil:1")));
        UpstreamProxyManager m = UpstreamProxyManager.fromEnvironment(Map.of(
                "http_proxy", "http://plain:8080", "HTTPS_PROXY", "http://secure:8443", "NO_PROXY", "skip.me"));
        assertEquals(8080, route(m, HttpMethod.GET, "http://a.example/").get(0).getChainedProxyAddress().getPort());
        assertEquals(8443, route(m, HttpMethod.CONNECT, "a.example:443").get(0).getChainedProxyAddress().getPort());
        assertEquals(8443, route(m, HttpMethod.GET, "https://a.example/").get(0).getChainedProxyAddress().getPort());
        assertSame(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION, route(m, HttpMethod.GET, "http://www.skip.me/x").get(0));
        assertSame(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION, route(m, HttpMethod.CONNECT, "skip.me:443").get(0));

        UpstreamProxyManager all = UpstreamProxyManager.fromEnvironment(Map.of("ALL_PROXY", "socks5://s:1080"));
        assertEquals(ChainedProxyType.SOCKS5, route(all, HttpMethod.CONNECT, "x:443").get(0).getChainedProxyType());
    }

    @Test
    void fallbackToDirectIsOptional() {
        UpstreamProxyManager m = new UpstreamProxyManager("http://p:1", null, null);
        assertEquals(1, route(m, HttpMethod.GET, "http://x/").size());
        assertEquals(2, route(m.withFallbackToDirect(true), HttpMethod.GET, "http://x/").size());
    }

    @Test
    void routesThroughUpstreamExceptNoProxyHosts() {
        HttpServer origin = TestSupport.origin(echo());
        List<String> upstreamSaw = new CopyOnWriteArrayList<>();
        HttpProxyServer upstream = MicroProxy.bootstrap().withPort(0)
                .withProxyAuthenticator((u, p) -> u.equals("me") && p.equals("pw"))
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                        upstreamSaw.add(req.uri());
                        return null;
                    }
                }).start();
        int upstreamPort = upstream.getListenAddress().getPort();
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0)
                .withChainProxyManager(new UpstreamProxyManager("http://me:pw@127.0.0.1:" + upstreamPort, null,
                        NoProxyRules.parse("localhost")))
                .start();
        try {
            assertEquals(200, get(client(proxy), url(origin, "/via-upstream")).statusCode());
            assertEquals(List.of(url(origin, "/via-upstream")), upstreamSaw);
            assertEquals(200, get(client(proxy), TestSupport.localhostUrl(origin, "/direct")).statusCode());
            assertEquals(1, upstreamSaw.size(), "localhost is in no_proxy");
        } finally {
            proxy.abort();
            upstream.abort();
            origin.stop(0);
        }
    }
}
