package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;

/**
 * The name rules of HTTP/2 connection coalescing ({@link Http2Coalescing}): which names a server's
 * certificate covers, as the JDK's HTTPS hostname verification decides, and what an ORIGIN frame's
 * entries and an exchange's authority are compared as.
 */
class Http2CoalescingNamesTest {

    private static final CertificateAuthority CA = CertificateAuthority.generate("Coalescing Names CA");

    private static X509Certificate certificate(String... names) throws Exception {
        return CA.issue(KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic(), List.of(names));
    }

    @Test
    void exactNamesMatchCaseInsensitively() {
        assertTrue(Http2Coalescing.matchesName("a.example.com", "a.example.com"));
        assertTrue(Http2Coalescing.matchesName("A.Example.COM", "a.example.com"));
        assertTrue(Http2Coalescing.matchesName("a.example.com.", "a.example.com"));
        assertFalse(Http2Coalescing.matchesName("a.example.com", "b.example.com"));
        assertFalse(Http2Coalescing.matchesName("example.com", "a.example.com"));
        assertFalse(Http2Coalescing.matchesName("", "a.example.com"));
    }

    @Test
    void wildcardsMatchOneLeftMostLabel() {
        assertTrue(Http2Coalescing.matchesName("*.example.com", "a.example.com"));
        assertTrue(Http2Coalescing.matchesName("*.example.com", "A.EXAMPLE.com"));
        // Within the label only: not deeper names, nor the parent itself.
        assertFalse(Http2Coalescing.matchesName("*.example.com", "a.b.example.com"));
        assertFalse(Http2Coalescing.matchesName("*.example.com", "example.com"));
        assertFalse(Http2Coalescing.matchesName("*.example.com", ".example.com"));
        // Part of the label, as RFC 6125 and the JDK allow.
        assertTrue(Http2Coalescing.matchesName("w*.example.com", "www.example.com"));
        assertTrue(Http2Coalescing.matchesName("*w.example.com", "aw.example.com"));
        assertFalse(Http2Coalescing.matchesName("w*.example.com", "api.example.com"));
        // Nowhere but the left-most label, once, and never right above a top-level domain or in an A-label.
        assertFalse(Http2Coalescing.matchesName("a.*.example.com", "a.b.example.com"));
        assertFalse(Http2Coalescing.matchesName("*.*.example.com", "a.b.example.com"));
        assertFalse(Http2Coalescing.matchesName("*.com", "example.com"));
        assertFalse(Http2Coalescing.matchesName("*", "example"));
        assertFalse(Http2Coalescing.matchesName("xn--*.example.com", "xn--a.example.com"));
    }

    @Test
    void certificatesCoverTheirDnsAndIpNames() throws Exception {
        X509Certificate cert = certificate("a.example.com", "*.cdn.example.com", "192.0.2.7", "2001:db8::1");
        assertTrue(Http2Coalescing.certificateCovers(cert, "a.example.com"));
        assertTrue(Http2Coalescing.certificateCovers(cert, "img.cdn.example.com"));
        assertFalse(Http2Coalescing.certificateCovers(cert, "b.example.com"));
        assertTrue(Http2Coalescing.certificateCovers(cert, "192.0.2.7"));
        assertTrue(Http2Coalescing.certificateCovers(cert, "2001:db8:0:0:0:0:0:1"));
        assertFalse(Http2Coalescing.certificateCovers(cert, "192.0.2.8"));
        // An address is never matched against DNS names, nor a name against addresses.
        assertFalse(Http2Coalescing.certificateCovers(certificate("example.com"), "192.0.2.7"));
    }

    @Test
    void originEntriesAreHttpsOriginsAndAuthoritiesCompareNormalized() {
        assertEquals("b.example.com:443", Http2Coalescing.originAuthority("https://b.example.com"));
        assertEquals("b.example.com:443", Http2Coalescing.originAuthority("HTTPS://B.Example.com:443"));
        assertEquals("b.example.com:8443", Http2Coalescing.originAuthority("https://b.example.com:8443"));
        assertEquals("[2001:db8::1]:443", Http2Coalescing.originAuthority("https://[2001:db8::1]"));
        assertNull(Http2Coalescing.originAuthority("http://b.example.com"));
        assertNull(Http2Coalescing.originAuthority("https://b.example.com/"));
        assertNull(Http2Coalescing.originAuthority("https://user@b.example.com"));
        assertNull(Http2Coalescing.originAuthority("https://"));
        assertNull(Http2Coalescing.originAuthority("b.example.com"));
        assertNull(Http2Coalescing.originAuthority("https://b.example.com:99999"));

        assertEquals("a.example.com:443", Http2Coalescing.authority("A.EXAMPLE.com"));
        assertEquals("a.example.com:8443", Http2Coalescing.authority("a.example.com.:8443"));
        assertEquals(new Http2Origins.Key("TLS|direct", "a.example.com:443"),
                new Http2Origins.Key("TLS|direct", "A.Example.com:443"));
    }

    @Test
    void onlyNamesThatSniCanCarryAreCoalesced() {
        Http2Coalescing.TlsContext none = () -> null;
        Http2Coalescing.Request request = Http2Coalescing.Request.of(new HostAndPort("B.Example.com", 443), none, null);
        assertNotNull(request);
        assertEquals("b.example.com:443", request.authority());
        assertEquals("b.example.com", request.host());
        assertNull(Http2Coalescing.Request.of(new HostAndPort("192.0.2.7", 443), none, null));
        assertNull(Http2Coalescing.Request.of(new HostAndPort("2001:db8::1", 443), none, null));
    }
}
