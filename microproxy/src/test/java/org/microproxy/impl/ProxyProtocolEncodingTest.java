package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** PROXY protocol v1 header encoding (LittleProxy ProxyToServerConnectionBugTest, TCP6 cases). */
class ProxyProtocolEncodingTest {

    private static String encode(String source, int sourcePort, String destination, int destinationPort)
            throws Exception {
        return new String(ProxyProtocol.encodeV1(
                new InetSocketAddress(InetAddress.getByName(source), sourcePort),
                new InetSocketAddress(InetAddress.getByName(destination), destinationPort)), StandardCharsets.US_ASCII);
    }

    @Test
    void ipv4AddressesGiveTcp4() throws Exception {
        assertEquals("PROXY TCP4 192.0.2.1 198.51.100.2 51234 443\r\n", encode("192.0.2.1", 51234, "198.51.100.2", 443));
    }

    @Test
    void ipv6AddressesGiveTcp6() throws Exception {
        assertEquals("PROXY TCP6 2001:db8:0:0:0:0:0:1 2001:db8:0:0:0:0:0:2 12345 443\r\n",
                encode("2001:db8::1", 12345, "2001:db8::2", 443));
    }

    @Test
    void mixedFamiliesUseTcp6WithAMappedAddress() throws Exception {
        // LittleProxy skips the header for mixed families; MicroProxy maps the IPv4 side instead.
        assertEquals("PROXY TCP6 ::ffff:192.0.2.1 2001:db8:0:0:0:0:0:2 1 2\r\n", encode("192.0.2.1", 1, "2001:db8::2", 2));
    }

    @Test
    void scopeIdsAreDropped() throws Exception {
        assertEquals("PROXY TCP6 fe80:0:0:0:0:0:0:1 fe80:0:0:0:0:0:0:2 1 2\r\n", encode("fe80::1%1", 1, "fe80::2%1", 2));
    }

    @Test
    void unknownAddressesGiveUnknown() {
        assertEquals("PROXY UNKNOWN\r\n", new String(ProxyProtocol.encodeV1(null, null), StandardCharsets.US_ASCII));
        assertEquals("PROXY UNKNOWN\r\n", new String(ProxyProtocol.encodeV1(
                InetSocketAddress.createUnresolved("client", 1), new InetSocketAddress(InetAddress.getLoopbackAddress(), 2)),
                StandardCharsets.US_ASCII));
    }

    @Test
    void tcp6HeaderRoundTrips() throws Exception {
        byte[] encoded = (encode("2001:db8::1", 12345, "2001:db8::2", 443) + "GET").getBytes(StandardCharsets.US_ASCII);
        ByteReader in = new ByteReader(new ByteArrayInputStream(encoded), 1024);
        ProxyProtocol.Header header = ProxyProtocol.read(in);
        assertEquals(new InetSocketAddress(InetAddress.getByName("2001:db8::1"), 12345), header.source());
        assertEquals(new InetSocketAddress(InetAddress.getByName("2001:db8::2"), 443), header.destination());
    }
}
