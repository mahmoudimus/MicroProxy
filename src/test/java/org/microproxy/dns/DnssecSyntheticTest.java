package org.microproxy.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.dns.DnsTestSupport.a;
import static org.microproxy.dns.DnsTestSupport.nsec;
import static org.microproxy.dns.DnsTestSupport.response;

import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A small signed hierarchy built in the test: the root and {@code test.} are signed; {@code
 * unsigned.test.} is an unsigned delegation; {@code *.wild.test.} is a signed wildcard.
 */
class DnssecSyntheticTest {

    private static final long NOW = Instant.parse("2026-06-01T00:00:00Z").getEpochSecond();
    private static final long INCEPTION = NOW - 3600;
    private static final long EXPIRATION = NOW + 3600;

    private final DnsTestSupport.Zone root = DnsTestSupport.zone(".");
    private final DnsTestSupport.Zone test = DnsTestSupport.zone("test.");
    private final Map<String, byte[]> responses = new HashMap<>();

    @BeforeEach
    void buildZones() {
        put(".", DnsRecord.DNSKEY, signed(root, List.of(root.dnskey())), List.of());
        put("test.", DnsRecord.DS, signed(root, List.of(test.ds())), List.of());
        put("test.", DnsRecord.DNSKEY, signed(test, List.of(test.dnskey())), List.of());
        put("a.test.", DnsRecord.A, signed(test, List.of(a("a.test.", 192, 0, 2, 1))), List.of());
        put("a.test.", DnsRecord.DS, List.of(),
                signed(test, List.of(nsec("a.test.", "b.test.", DnsRecord.A, DnsRecord.RRSIG, DnsRecord.NSEC))));
        // A wildcard answer: the RRSIG covers *.wild.test. (2 labels) and an NSEC proves that
        // x.wild.test. itself does not exist.
        DnsRecord wild = a("x.wild.test.", 192, 0, 2, 2);
        put("x.wild.test.", DnsRecord.A,
                List.of(wild, test.sign(List.of(wild), INCEPTION, EXPIRATION, 2)),
                signed(test, List.of(nsec("*.wild.test.", "zz.test.", DnsRecord.A, DnsRecord.RRSIG, DnsRecord.NSEC))));
        // An unsigned delegation: the parent proves there is no DS with an NSEC listing NS.
        put("host.unsigned.test.", DnsRecord.A, List.of(a("host.unsigned.test.", 192, 0, 2, 3)), List.of());
        put("unsigned.test.", DnsRecord.DS, List.of(),
                signed(test, List.of(nsec("unsigned.test.", "wild.test.", DnsRecord.NS, DnsRecord.RRSIG, DnsRecord.NSEC))));
        responses.put(DnsTestSupport.key(DnsName.parse("missing.test."), DnsRecord.A),
                response(DnsName.parse("missing.test."), DnsRecord.A, 3, List.of(), List.of()));
        responses.put(DnsTestSupport.key(DnsName.parse("missing.test."), DnsRecord.AAAA),
                response(DnsName.parse("missing.test."), DnsRecord.AAAA, 3, List.of(), List.of()));
    }

    private List<DnsRecord> signed(DnsTestSupport.Zone zone, List<DnsRecord> rrset) {
        return DnsTestSupport.with(rrset, zone.sign(rrset, INCEPTION, EXPIRATION));
    }

    private void put(String name, int type, List<DnsRecord> answer, List<DnsRecord> authority) {
        DnsName n = DnsName.parse(name);
        responses.put(DnsTestSupport.key(n, type), response(n, type, 0, answer, authority));
    }

    private DnssecHostResolver resolver(DnssecHostResolver.Policy policy, long nowEpochSecond) {
        return DnssecHostResolver.builder()
                .transport(DnsTestSupport.replay(responses))
                .trustAnchors(List.of(root.trustAnchor()))
                .policy(policy)
                .clock(Clock.fixed(Instant.ofEpochSecond(nowEpochSecond), ZoneOffset.UTC))
                .build();
    }

    private DnssecHostResolver resolver() {
        return resolver(DnssecHostResolver.Policy.REJECT_BOGUS, NOW);
    }

    @Test
    void signedRecordIsSecure() throws Exception {
        DnssecHostResolver.Resolution r = resolver().lookup("a.test");
        assertTrue(r.secure());
        assertEquals("192.0.2.1", r.addresses().get(0).getHostAddress());
    }

    @Test
    void wildcardAnswerWithProofIsSecure() throws Exception {
        DnssecHostResolver.Resolution r = resolver().lookup("x.wild.test");
        assertTrue(r.secure());
        assertEquals("192.0.2.2", r.addresses().get(0).getHostAddress());
    }

    @Test
    void wildcardAnswerWithoutProofIsBogus() {
        DnsRecord wild = a("x.wild.test.", 192, 0, 2, 2);
        put("x.wild.test.", DnsRecord.A, List.of(wild, test.sign(List.of(wild), INCEPTION, EXPIRATION, 2)), List.of());
        assertThrows(DnssecValidationException.class, () -> resolver().lookup("x.wild.test"));
    }

    @Test
    void provablyUnsignedDelegationIsInsecure() throws Exception {
        DnssecHostResolver.Resolution r = resolver().lookup("host.unsigned.test");
        assertFalse(r.secure());
        assertEquals("192.0.2.3", r.addresses().get(0).getHostAddress());
        assertThrows(DnssecValidationException.class,
                () -> resolver(DnssecHostResolver.Policy.REQUIRE_SECURE, NOW).lookup("host.unsigned.test"));
    }

    @Test
    void unsignedDelegationWithoutProofIsBogus() {
        put("unsigned.test.", DnsRecord.DS, List.of(), List.of());
        assertThrows(DnssecValidationException.class, () -> resolver().lookup("host.unsigned.test"));
    }

    @Test
    void unsignedProofIsBogus() {
        // The NSEC claiming "no DS here" is not signed, so it proves nothing.
        put("unsigned.test.", DnsRecord.DS, List.of(),
                List.of(nsec("unsigned.test.", "wild.test.", DnsRecord.NS, DnsRecord.RRSIG, DnsRecord.NSEC)));
        assertThrows(DnssecValidationException.class, () -> resolver().lookup("host.unsigned.test"));
    }

    @Test
    void strippedSignatureIsBogus() {
        put("a.test.", DnsRecord.A, List.of(a("a.test.", 192, 0, 2, 1)), List.of());
        assertThrows(DnssecValidationException.class, () -> resolver().lookup("a.test"));
    }

    @Test
    void forgedRecordIsBogus() {
        DnsRecord real = a("a.test.", 192, 0, 2, 1);
        DnsRecord sig = test.sign(List.of(real), INCEPTION, EXPIRATION);
        put("a.test.", DnsRecord.A, List.of(a("a.test.", 203, 0, 113, 66), sig), List.of());
        assertThrows(DnssecValidationException.class, () -> resolver().lookup("a.test"));
    }

    @Test
    void keyNotMatchingDsIsBogus() {
        DnsTestSupport.Zone impostor = DnsTestSupport.zone("test.");
        put("test.", DnsRecord.DNSKEY, signed(impostor, List.of(impostor.dnskey())), List.of());
        put("a.test.", DnsRecord.A, signed(impostor, List.of(a("a.test.", 192, 0, 2, 1))), List.of());
        assertThrows(DnssecValidationException.class, () -> resolver().lookup("a.test"));
    }

    @Test
    void expiredSignaturesAreBogus() {
        assertThrows(DnssecValidationException.class,
                () -> resolver(DnssecHostResolver.Policy.REJECT_BOGUS, EXPIRATION + 10).lookup("a.test"));
        assertThrows(DnssecValidationException.class,
                () -> resolver(DnssecHostResolver.Policy.REJECT_BOGUS, INCEPTION - 10).lookup("a.test"));
    }

    @Test
    void untrustedRootIsBogus() {
        DnssecHostResolver resolver = DnssecHostResolver.builder()
                .transport(DnsTestSupport.replay(responses))
                .trustAnchors(List.of(DnsTestSupport.zone(".").trustAnchor()))
                .clock(Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC))
                .build();
        assertThrows(DnssecValidationException.class, () -> resolver.lookup("a.test"));
    }

    @Test
    void proxyConnectsOnlyToValidatedAddresses() throws Exception {
        com.sun.net.httpserver.HttpServer origin = org.microproxy.TestSupport.origin(
                org.microproxy.TestSupport.fixed(200, "validated"));
        int port = origin.getAddress().getPort();
        put("local.test.", DnsRecord.A, signed(test, List.of(a("local.test.", 127, 0, 0, 1))), List.of());
        org.microproxy.HttpProxyServer proxy = org.microproxy.MicroProxy.bootstrap().withPort(0)
                .withServerResolver(resolver()).start();
        try {
            var client = org.microproxy.TestSupport.client(proxy);
            var ok = org.microproxy.TestSupport.get(client, "http://local.test:" + port + "/");
            assertEquals("validated", ok.body());

            DnsRecord real = a("forged.test.", 192, 0, 2, 9);
            put("forged.test.", DnsRecord.A,
                    List.of(a("forged.test.", 127, 0, 0, 1), test.sign(List.of(real), INCEPTION, EXPIRATION)), List.of());
            assertEquals(502, org.microproxy.TestSupport.get(client, "http://forged.test:" + port + "/").statusCode());
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }

    @Test
    void nonexistentNamesAndLiteralsResolveSensibly() throws Exception {
        UnknownHostException e = assertThrows(UnknownHostException.class, () -> resolver().lookup("missing.test"));
        assertFalse(e instanceof DnssecValidationException);
        assertEquals("127.0.0.1", resolver().resolve("127.0.0.1", 80).getAddress().getHostAddress());
        assertTrue(resolver().resolve("localhost", 80).getAddress().isLoopbackAddress());
    }
}
