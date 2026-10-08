package org.microproxy.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpsServer;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/** Intercepted HTTPS is cached, and served from the cache when the server goes away. */
class CachedHttpsTest {

    @Test
    void cachedPagesSurviveTheServerGoingAway() {
        CertificateAuthority originCa = CertificateAuthority.generate("Test Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Test Proxy CA");
        AtomicInteger hits = new AtomicInteger();
        HttpsServer origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), exchange -> {
            byte[] body = ("secure #" + hits.incrementAndGet()).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Cache-Control", "max-age=0");
            exchange.getResponseHeaders().set("ETag", "\"s1\"");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttpCache(HttpCache.builder().build())
                .start();
        try {
            String target = url(origin, "/page");
            assertEquals("secure #1", get(client(proxy, proxyCa.clientContext()), target).body());
            origin.stop(0);
            HttpResponse<String> offline = get(client(proxy, proxyCa.clientContext()), target);
            assertEquals(200, offline.statusCode());
            assertEquals("secure #1", offline.body());
            assertTrue(offline.headers().firstValue("cache-status").orElse("").contains("server-unreachable"));
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }
}
