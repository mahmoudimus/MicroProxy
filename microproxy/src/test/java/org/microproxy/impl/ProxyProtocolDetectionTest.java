package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.microproxy.MicroProxy;
import org.microproxy.ProxyProtocolMode;

/** PROXY protocol signature detection, trusted sources and the mode's configuration. */
class ProxyProtocolDetectionTest {

    private static ProxyProtocol.Start start(String s) {
        return ProxyProtocol.start(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    @Test
    void signaturesAreToldApartByTheirFirstDifferentByte() {
        assertEquals(ProxyProtocol.Start.V1, start("PROXY TCP4 1.2.3.4"));
        assertEquals(ProxyProtocol.Start.V1, start("PROXY "));
        assertEquals(ProxyProtocol.Start.V2, start("\r\n\r\n\0\r\nQUIT\n!\u0011"));
        for (String partial : List.of("P", "PR", "PROX", "PROXY", "\r", "\r\n\r\n\0", "\r\n\r\n\0\r\nQUIT")) {
            assertEquals(ProxyProtocol.Start.PARTIAL, start(partial), partial);
        }
        for (String other : List.of("G", "GET / HTTP/1.1", "POST", "PRI * HTTP/2.0", "PROPFIND", "PROXYX",
                "\r\nGET", "\u0016\u0003\u0001", "\u0005\u0001\u0000")) {
            assertEquals(ProxyProtocol.Start.OTHER, start(other), other);
        }
    }

    @Test
    void headerLengthIsKnownOnceItsEndOrLengthFieldIs() throws Exception {
        byte[] v1 = "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\nGET".getBytes(StandardCharsets.US_ASCII);
        assertEquals(32, ProxyProtocol.headerLength(ProxyProtocol.Start.V1, v1));
        assertEquals(-1, ProxyProtocol.headerLength(ProxyProtocol.Start.V1, "PROXY TCP4".getBytes(StandardCharsets.US_ASCII)));
        byte[] tooLong = ("PROXY " + "x".repeat(200)).getBytes(StandardCharsets.US_ASCII);
        assertThrows(ProtocolException.class, () -> ProxyProtocol.headerLength(ProxyProtocol.Start.V1, tooLong));
        byte[] v2 = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x01, 0x02};
        assertEquals(16 + 258, ProxyProtocol.headerLength(ProxyProtocol.Start.V2, v2));
        assertEquals(-1, ProxyProtocol.headerLength(ProxyProtocol.Start.V2, java.util.Arrays.copyOf(v2, 15)));
    }

    @Test
    void trustedSourcesMatchAddressesAndRanges() {
        ProxyProtocol.TrustedSources trusted = ProxyProtocol.TrustedSources.parse(
                List.of("10.0.0.0/8", " 192.0.2.10 ", "2001:db8::/32", "::ffff:198.51.100.0/120", ""));
        assertEquals(List.of("10.0.0.0/8", "192.0.2.10", "2001:db8::/32", "::ffff:198.51.100.0/120"), trusted.entries());
        assertTrue(trusted.trusts(new InetSocketAddress("10.200.3.4", 1)));
        assertTrue(trusted.trusts(new InetSocketAddress("192.0.2.10", 1)));
        assertFalse(trusted.trusts(new InetSocketAddress("192.0.2.11", 1)));
        assertFalse(trusted.trusts(new InetSocketAddress("11.0.0.1", 1)));
        assertTrue(trusted.trusts(new InetSocketAddress("2001:db8:1::5", 1)));
        assertFalse(trusted.trusts(new InetSocketAddress("2001:db9::5", 1)));
        // An IPv4-mapped range matches IPv4 peers, and IPv4-mapped peers match IPv4 ranges.
        assertTrue(trusted.trusts(new InetSocketAddress("198.51.100.77", 1)));
        assertFalse(trusted.trusts(new InetSocketAddress("198.51.101.1", 1)));
        assertFalse(trusted.trusts(InetSocketAddress.createUnresolved("10.0.0.1", 1)));
        assertTrue(ProxyProtocol.TrustedSources.ALL.trusts(new InetSocketAddress("203.0.113.1", 1)));
        assertTrue(ProxyProtocol.TrustedSources.parse(List.of("0.0.0.0/0")).trusts(new InetSocketAddress("8.8.8.8", 1)));
        assertFalse(ProxyProtocol.TrustedSources.parse(List.of("0.0.0.0/0")).trusts(new InetSocketAddress("::2", 1)));
    }

    @Test
    void trustedSourcesAreParsedStrictly() {
        for (String bad : List.of("example.com", "localhost", "10.0.0.0/33", "10.0.0.0/", "10.0.0.0/x", "256.1.1.1",
                "1.2.3", "fe80::1%eth0", "2001:db8::/129", "::ffff:10.0.0.0/64", "zz:1", "10.0.0.0/-1")) {
            assertThrows(IllegalArgumentException.class, () -> ProxyProtocol.TrustedSources.parse(List.of(bad)), bad);
        }
    }

    @Test
    void modesParseFromConfigurationValues() {
        assertEquals(ProxyProtocolMode.REQUIRED, ProxyProtocolMode.parse("true"));
        assertEquals(ProxyProtocolMode.REQUIRED, ProxyProtocolMode.parse(" Required "));
        assertEquals(ProxyProtocolMode.OPTIONAL, ProxyProtocolMode.parse("OPTIONAL"));
        assertEquals(ProxyProtocolMode.OFF, ProxyProtocolMode.parse("false"));
        assertEquals(ProxyProtocolMode.OFF, ProxyProtocolMode.parse("off"));
        assertThrows(IllegalArgumentException.class, () -> ProxyProtocolMode.parse("maybe"));
    }

    @Test
    void propertiesSetTheModeAndTrustedSources() {
        Properties p = new Properties();
        p.setProperty("allow_proxy_protocol", "optional");
        p.setProperty("proxy_protocol_trusted_sources", "10.0.0.0/8, 192.0.2.1");
        DefaultHttpProxyServerBootstrap b = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertEquals(ProxyProtocolMode.OPTIONAL, b.proxyProtocolMode);
        assertEquals(List.of("10.0.0.0/8", "192.0.2.1"), b.proxyProtocolTrustedSources.entries());
        assertEquals(ProxyProtocolMode.OPTIONAL, b.copy().proxyProtocolMode);
        assertEquals(b.proxyProtocolTrustedSources, b.copy().proxyProtocolTrustedSources);

        p.setProperty("allow_proxy_protocol", "true");
        p.remove("proxy_protocol_trusted_sources");
        assertEquals(ProxyProtocolMode.REQUIRED, DefaultHttpProxyServerBootstrap.fromProperties(p).proxyProtocolMode);
        p.setProperty("allow_proxy_protocol", "sometimes");
        assertThrows(IllegalArgumentException.class, () -> DefaultHttpProxyServerBootstrap.fromProperties(p));
        p.setProperty("allow_proxy_protocol", "optional");
        p.setProperty("proxy_protocol_trusted_sources", "lb.example.com");
        assertThrows(IllegalArgumentException.class, () -> DefaultHttpProxyServerBootstrap.fromProperties(p));
    }

    @Test
    void theBooleanSetterMapsToRequiredOrOff() {
        DefaultHttpProxyServerBootstrap b = (DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap();
        assertEquals(ProxyProtocolMode.OFF, b.proxyProtocolMode);
        b.withAcceptProxyProtocol(true);
        assertEquals(ProxyProtocolMode.REQUIRED, b.proxyProtocolMode);
        b.withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL);
        assertEquals(ProxyProtocolMode.OPTIONAL, b.proxyProtocolMode);
        b.withAcceptProxyProtocol(false);
        assertEquals(ProxyProtocolMode.OFF, b.proxyProtocolMode);
    }
}
