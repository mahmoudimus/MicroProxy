package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** CONNECT-UDP's URI templates (RFC 9298 section 2): the well-known one, custom ones, and what they refuse. */
class ConnectUdpTemplateTest {

    private static final ConnectUdpTemplate WELL_KNOWN = ConnectUdpTemplate.parse(ConnectUdpTemplate.DEFAULT);

    @Test
    void theWellKnownTemplateNamesHostAndPortInThePath() {
        assertEquals(new HostAndPort("192.0.2.6", 443), WELL_KNOWN.match("/.well-known/masque/udp/192.0.2.6/443/"));
        assertEquals(new HostAndPort("example.com", 53), WELL_KNOWN.match("/.well-known/masque/udp/Example.com/53/"));
        // An IPv6 address's colons are percent-encoded (RFC 9298 section 2).
        assertEquals(new HostAndPort("2001:db8::42", 443),
                WELL_KNOWN.match("/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"));
        // An absolute-form request target is matched by its path.
        assertEquals(new HostAndPort("192.0.2.6", 443),
                WELL_KNOWN.match("https://proxy.example/.well-known/masque/udp/192.0.2.6/443/"));
    }

    @Test
    void invalidTargetsDoNotMatch() {
        assertNull(WELL_KNOWN.match("/.well-known/masque/udp/192.0.2.6/0/"));
        assertNull(WELL_KNOWN.match("/.well-known/masque/udp/192.0.2.6/65536/"));
        assertNull(WELL_KNOWN.match("/.well-known/masque/udp/192.0.2.6/https/"));
        assertNull(WELL_KNOWN.match("/.well-known/masque/udp//443/"));
        assertNull(WELL_KNOWN.match("/.well-known/masque/udp/a%2Fb/443/"), "no slash in a host");
        assertNull(WELL_KNOWN.match("/.well-known/masque/udp/192.0.2.6/443"), "the trailing slash is the template's");
        assertNull(WELL_KNOWN.match("/.well-known/masque/udp/192.0.2.6/443/extra"));
        assertNull(WELL_KNOWN.match("/other/192.0.2.6/443/"));
    }

    @Test
    void aCustomTemplateMayNameTheTargetInTheQueryInAnyOrder() {
        ConnectUdpTemplate query = ConnectUdpTemplate.parse("https://proxy.example:4443/masque?p={target_port}&h={target_host}");
        assertEquals(new HostAndPort("198.51.100.1", 5353), query.match("/masque?p=5353&h=198.51.100.1"));
        assertNull(query.match("/masque?h=198.51.100.1&p=5353"), "the template's order");
        assertEquals("https://proxy.example:4443/masque?p={target_port}&h={target_host}", query.toString());
    }

    @Test
    void aTemplateNeedsBothVariablesOnceAndAPath() {
        assertThrows(IllegalArgumentException.class, () -> ConnectUdpTemplate.parse("/udp/{target_host}/"));
        assertThrows(IllegalArgumentException.class,
                () -> ConnectUdpTemplate.parse("/udp/{target_host}/{target_port}/{target_port}/"));
        assertThrows(IllegalArgumentException.class, () -> ConnectUdpTemplate.parse("udp/{target_host}/{target_port}"));
    }
}
