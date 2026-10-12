package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.microproxy.MicroProxy;
import org.microproxy.http.HttpHeaders;

/** What the proxy learns about servers that speak HTTP/3: Alt-Svc, its expiry, and forced hosts. */
class Http3OriginsTest {

    private final AtomicLong now = new AtomicLong(1_000);

    private Http3Origins origins(String... forced) {
        DefaultHttpProxyServer server = new DefaultHttpProxyServer(
                (DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap().withPort(0).withHttp3Upstream(true));
        Http3Origins origins = new Http3Origins(server, List.of(forced));
        origins.clock = now::get;
        return origins;
    }

    private static HttpHeaders altSvc(String... values) {
        HttpHeaders h = new HttpHeaders();
        for (String v : values) h.add("Alt-Svc", v);
        return h;
    }

    @Test
    void parsesTheFirstH3AlternativeOnTheOriginsOwnHost() {
        assertEquals(new AltSvc.Http3Alternative(443, 86_400), AltSvc.http3(altSvc("h3=\":443\""), "example.com"));
        assertEquals(new AltSvc.Http3Alternative(8443, 60),
                AltSvc.http3(altSvc("h2=\":443\", h3-29=\":9443\", h3=\":8443\"; ma=60; persist=1"), "example.com"));
        assertEquals(new AltSvc.Http3Alternative(443, 5),
                AltSvc.http3(altSvc("h3=\"EXAMPLE.com:443\"; ma=\"5\""), "example.com"), "same host, any case, quoted ma");
        assertEquals(new AltSvc.Http3Alternative(443, 86_400), AltSvc.http3(altSvc("h3=\"[::1]:443\""), "[::1]"));
        assertNull(AltSvc.http3(altSvc("h3=\"other.example:443\""), "example.com"), "another host is never used");
        assertNull(AltSvc.http3(altSvc("h3=\":0\"", "h3=\":70000\"", "h3=\":x\"", "h3=\":443\"; ma=-1"), "example.com"));
        assertNull(AltSvc.http3(altSvc("h2=\":443\""), "example.com"));
        assertSame(AltSvc.CLEAR, AltSvc.http3(altSvc("clear"), "example.com"));
    }

    @Test
    void remembersAnAdvertisementUntilItsMaxAge() {
        Http3Origins origins = origins();
        assertEquals(-1, origins.http3Port("example.com:443"));
        origins.learn("example.com:443", altSvc("h3=\":8443\"; ma=60"));
        assertEquals(8443, origins.http3Port("example.com:443"));
        assertEquals(8443, origins.http3Port("EXAMPLE.COM:443"), "origins compare case-insensitively");
        assertEquals(-1, origins.http3Port("example.com:8443"), "per origin: the port is part of it");
        now.addAndGet(TimeUnit.SECONDS.toNanos(59));
        assertEquals(8443, origins.http3Port("example.com:443"));
        now.addAndGet(TimeUnit.SECONDS.toNanos(2));
        assertEquals(-1, origins.http3Port("example.com:443"), "expired");
    }

    @Test
    void clearAndAZeroMaxAgeForgetIt() {
        Http3Origins origins = origins();
        origins.learn("example.com:443", altSvc("h3=\":443\""));
        assertEquals(443, origins.http3Port("example.com:443"));
        origins.learn("example.com:443", altSvc("clear"));
        assertEquals(-1, origins.http3Port("example.com:443"));
        origins.learn("example.com:443", altSvc("h3=\":443\""));
        origins.learn("example.com:443", altSvc("h3=\":443\"; ma=0"));
        assertEquals(-1, origins.http3Port("example.com:443"));
        origins.learn("example.com:443", altSvc("h2=\":443\""));
        assertEquals(-1, origins.http3Port("example.com:443"), "an advertisement without h3 teaches nothing");
    }

    @Test
    void forcedHostsUseTheirOwnPortWithoutAnAdvertisement() {
        Http3Origins origins = origins("\\.example\\.com:", "^api\\.");
        assertEquals(443, origins.http3Port("www.example.com:443"));
        assertEquals(8443, origins.http3Port("api.test:8443"));
        assertEquals(-1, origins.http3Port("example.org:443"));
    }
}
