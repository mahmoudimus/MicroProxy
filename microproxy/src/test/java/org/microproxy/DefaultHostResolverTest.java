package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

class DefaultHostResolverTest {

    private final DefaultHostResolver resolver = new DefaultHostResolver();

    @Test
    void resolvesLocalhostToLoopback() throws UnknownHostException {
        InetSocketAddress address = resolver.resolve("localhost", 8080);
        assertFalse(address.isUnresolved());
        assertTrue(address.getAddress().isLoopbackAddress(), address.toString());
        assertEquals(8080, address.getPort());
        assertEquals(443, resolver.resolve("localhost", 443).getPort());
    }

    @Test
    void ipLiteralsNeedNoLookup() throws UnknownHostException {
        assertEquals("127.0.0.1", resolver.resolve("127.0.0.1", 9090).getAddress().getHostAddress());
        assertEquals(9090, resolver.resolve("127.0.0.1", 9090).getPort());
        assertTrue(resolver.resolve("::1", 80).getAddress().isLoopbackAddress());
    }

    @Test
    void unknownHostsFail() {
        // .invalid is reserved (RFC 2606) and never resolves.
        assertThrows(UnknownHostException.class, () -> resolver.resolve("no-such-host.invalid", 80));
    }

    @Test
    void proxyUsesTheConfiguredResolver() {
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "resolved"));
        List<String> lookups = new CopyOnWriteArrayList<>();
        // Maps a made-up name to the origin, so the request only works through the resolver.
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).withServerResolver((host, port) -> {
            lookups.add(host + ":" + port);
            return host.equals("origin.test") ? new InetSocketAddress(TestSupport.LOOPBACK, port)
                    : resolver.resolve(host, port);
        }).start();
        try {
            int port = origin.getAddress().getPort();
            assertEquals("resolved", TestSupport.get(TestSupport.client(proxy), "http://origin.test:" + port + "/").body());
            assertEquals(List.of("origin.test:" + port), lookups);
            assertEquals(502, TestSupport.get(TestSupport.client(proxy), "http://no-such-host.invalid/").statusCode());
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }
}
