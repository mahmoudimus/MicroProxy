package org.microproxy.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.dns.DnsTestSupport.a;

import java.lang.reflect.Field;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Controlled, locally signed data exercises resource limits without querying a DNS server. */
class DnssecResourceLimitsTest {
    private static final long NOW = Instant.parse("2026-06-01T00:00:00Z").toEpochMilli();
    private final DnsTestSupport.Zone root = DnsTestSupport.zone(".");
    private final DnsTestSupport.Zone zone = DnsTestSupport.zone("test.");
    private final Map<String, byte[]> responses = new HashMap<>();
    private final MutableClock clock = new MutableClock(NOW);

    @BeforeEach
    void hierarchy() {
        put(".", DnsRecord.DNSKEY, signed(root, List.of(root.dnskey())), List.of());
        put("test.", DnsRecord.DS, signed(root, List.of(zone.ds())), List.of());
        put("test.", DnsRecord.DNSKEY, signed(zone, List.of(zone.dnskey())), List.of());
    }

    @Test
    void signatureFanoutExhaustsValidationBeforeAcceptingALateSignature() {
        DnsRecord address = a("a.test.", 192, 0, 2, 1);
        put("a.test.", DnsRecord.A, withInvalidSignatures(List.of(address), 64), List.of());
        assertBudgetExceeded(() -> resolver().lookup("a.test"));
    }

    @Test
    void aliasesShareOneAggregateSignatureBudget() {
        List<DnsRecord> answer = new ArrayList<>();
        for (int i = 0; i < 9; i++) {
            DnsRecord record = i == 8 ? a("n8.test.", 192, 0, 2, 1)
                    : new DnsRecord(DnsName.parse("n" + i + ".test."), DnsRecord.CNAME, 1, 300,
                            DnsName.parse("n" + (i + 1) + ".test.").toWire());
            answer.addAll(withInvalidSignatures(List.of(record), 7));
        }
        put("n0.test.", DnsRecord.A, answer, List.of());
        assertBudgetExceeded(() -> resolver().lookup("n0.test"));
    }

    @Test
    void wildcardNsec3RejectsExcessiveIterations() {
        DnsRecord address = a("x.wild.test.", 192, 0, 2, 1);
        put("x.wild.test.", DnsRecord.A,
                List.of(address, zone.sign(List.of(address), NOW / 1000 - 3600, NOW / 1000 + 3600, 2)),
                signed(zone, List.of(nsec3(151))));
        DnssecValidationException failure = assertThrows(DnssecValidationException.class,
                () -> resolver().lookup("x.wild.test"));
        assertTrue(failure.getMessage().contains("NSEC3"), failure.getMessage());
    }

    @Test
    void excessiveNsec3IterationsCannotDowngradeToUnsigned() {
        put("host.unsigned.test.", DnsRecord.A, List.of(a("host.unsigned.test.", 192, 0, 2, 1)), List.of());
        put("unsigned.test.", DnsRecord.DS, List.of(), signed(zone, List.of(nsec3(151))));
        assertThrows(DnssecValidationException.class, () -> resolver().lookup("host.unsigned.test"));
    }

    @Test
    void cacheActivityEvictsExpiredAnswersForOtherNames() throws Exception {
        for (String name : List.of("first.test.", "second.test.")) {
            put(name, DnsRecord.A, signed(zone, List.of(a(name, 192, 0, 2, 1))), List.of());
        }
        DnssecHostResolver resolver = resolver();
        resolver.lookup("first.test");
        clock.millis += 301_000;
        resolver.lookup("second.test");
        assertEquals(1, cacheSize(resolver, "cache"));
    }

    @Test
    void zoneKeyCacheEvictsExpiredOtherZones() throws Exception {
        DnssecValidator validator = validator();
        validator.walk(DnsName.parse("test."));
        DnsTestSupport.Zone other = DnsTestSupport.zone("other.");
        put("other.", DnsRecord.DS, signed(root, List.of(other.ds())), List.of());
        put("other.", DnsRecord.DNSKEY, signed(other, List.of(other.dnskey())), List.of());
        clock.millis += 301_000;
        validator.walk(DnsName.parse("other."));
        assertEquals(2, cacheSize(validator, "zoneKeys"));
    }

    @Test
    void delegationCachesEvictExpiredOtherNames() throws Exception {
        for (boolean insecure : List.of(false, true)) {
            DnssecValidator validator = validator();
            for (String name : List.of("first.test.", "second.test.")) {
                DnsRecord proof = DnsTestSupport.nsec(name, "z.test.",
                        insecure ? DnsRecord.NS : DnsRecord.A, DnsRecord.NSEC, DnsRecord.RRSIG);
                put(name, DnsRecord.DS, List.of(), signed(zone, List.of(proof)));
            }
            validator.walk(DnsName.parse("first.test."));
            clock.millis += 301_000;
            validator.walk(DnsName.parse("second.test."));
            assertEquals(1, cacheSize(validator, insecure ? "insecureCuts" : "notCuts"));
        }
    }

    @Test
    void signatureAndDsDigestCostsHaveAnExactAggregateBoundary() throws Exception {
        put("a.test.", DnsRecord.A, signed(zone, List.of(a("a.test.", 192, 0, 2, 1))), List.of());
        // Root DS digest + root signature + parent DS signature + child DS digest + child
        // DNSKEY signature + answer signature = 8 + 128 + 128 + 8 + 128 + 128.
        assertTrue(builder().maxValidationWork(528).build().lookup("a.test").secure());
        assertBudgetExceeded(() -> builder().maxValidationWork(527).build().lookup("a.test"));
    }

    @Test
    void unsuccessfulDsDigestsAlsoConsumeWork() {
        DnsRecord ds = zone.ds();
        byte[] digest = ds.rdata().clone();
        digest[digest.length - 1] ^= 1;
        DnsRecord wrong = new DnsRecord(ds.name(), ds.type(), 1, ds.ttl(), digest);
        put("test.", DnsRecord.DS, signed(root, List.of(wrong, wrong, wrong, ds)), List.of());
        put("a.test.", DnsRecord.A, signed(zone, List.of(a("a.test.", 192, 0, 2, 1))), List.of());
        assertBudgetExceeded(() -> builder().maxValidationWork(528).build().lookup("a.test"));
    }

    @Test
    void wildcardNsec3HashRoundsConsumeWorkAtAllowedIterationLimit() throws Exception {
        DnsRecord address = a("x.wild.test.", 192, 0, 2, 1);
        put("x.wild.test.", DnsRecord.A,
                List.of(address, zone.sign(List.of(address), NOW / 1000 - 3600, NOW / 1000 + 3600, 2)),
                signed(zone, List.of(nsec3(150))));
        assertTrue(builder().maxValidationWork(807).build().lookup("x.wild.test").secure());
        assertBudgetExceeded(() -> builder().maxValidationWork(806).build().lookup("x.wild.test"));
    }

    @Test
    void exactNsec3DelegationHashConsumesWork() throws Exception {
        DnsName child = DnsName.parse("unsigned.test.");
        put("host.unsigned.test.", DnsRecord.A, List.of(a("host.unsigned.test.", 192, 0, 2, 1)), List.of());
        put(child.toString(), DnsRecord.DS, List.of(), signed(zone, List.of(nsec3(150, child, false))));
        assertFalse(builder().maxValidationWork(679).build().lookup("host.unsigned.test").secure());
        assertBudgetExceeded(() -> builder().maxValidationWork(678).build().lookup("host.unsigned.test"));
    }

    @Test
    void closestEncloserAndNextCloserNsec3HashesConsumeWork() throws Exception {
        put("host.unsigned.test.", DnsRecord.A, List.of(a("host.unsigned.test.", 192, 0, 2, 1)), List.of());
        put("unsigned.test.", DnsRecord.DS, List.of(),
                signed(zone, List.of(nsec3(150, DnsName.parse("test."), true))));
        assertFalse(builder().maxValidationWork(981).build().lookup("host.unsigned.test").secure());
        assertBudgetExceeded(() -> builder().maxValidationWork(980).build().lookup("host.unsigned.test"));
    }

    @Test
    void addressFamilyFallbackRetainsTheAliasWorkBudget() throws Exception {
        DnsRecord alias = new DnsRecord(DnsName.parse("alias.test."), DnsRecord.CNAME, 1, 300,
                DnsName.parse("empty.test.").toWire());
        put("alias.test.", DnsRecord.A, signed(zone, List.of(alias)), List.of());
        put("empty.test.", DnsRecord.A, List.of(), List.of());
        byte[] ipv6 = new byte[16];
        ipv6[15] = 1;
        DnsRecord address = new DnsRecord(alias.name(), DnsRecord.AAAA, 1, 300, ipv6);
        put("alias.test.", DnsRecord.AAAA, signed(zone, List.of(address)), List.of());
        assertTrue(builder().maxValidationWork(656).build().lookup("alias.test").secure());
        assertBudgetExceeded(() -> builder().maxValidationWork(655).build().lookup("alias.test"));
    }

    @Test
    void resolverCapacityAndZeroTtlRequireFreshValidatedQueries() throws Exception {
        for (String name : List.of("first.test.", "second.test.", "third.test.")) {
            put(name, DnsRecord.A, signed(zone, List.of(a(name, 192, 0, 2, 1))), List.of());
        }
        DnssecHostResolver resolver = builder().cacheCapacity(2).build();
        resolver.lookup("first.test");
        resolver.lookup("second.test");
        resolver.lookup("third.test");
        assertEquals(2, cacheSize(resolver, "cache"));
        // An evicted name must be checked again, so a later forged response is rejected.
        put("first.test.", DnsRecord.DS, List.of(), signed(zone,
                List.of(DnsTestSupport.nsec("first.test.", "z.test.", DnsRecord.A, DnsRecord.NSEC))));
        put("first.test.", DnsRecord.A, List.of(a("first.test.", 203, 0, 113, 1)), List.of());
        assertThrows(DnssecValidationException.class, () -> resolver.lookup("first.test"));

        DnsRecord zeroTtl = new DnsRecord(DnsName.parse("zero.test."), DnsRecord.A, 1, 0,
                new byte[] {(byte) 192, 0, 2, 1});
        put("zero.test.", DnsRecord.A, signed(zone, List.of(zeroTtl)), List.of());
        resolver.lookup("zero.test");
        put("zero.test.", DnsRecord.DS, List.of(), signed(zone,
                List.of(DnsTestSupport.nsec("zero.test.", "zz.test.", DnsRecord.A, DnsRecord.NSEC))));
        put("zero.test.", DnsRecord.A, List.of(zeroTtl), List.of());
        assertThrows(DnssecValidationException.class, () -> resolver.lookup("zero.test"));
    }

    @Test
    void allValidatorFactCachesRespectConfiguredCapacity() throws Exception {
        DnssecValidator validator = new DnssecValidator(DnsTestSupport.replay(responses), List.of(root.ds()),
                clock, 8192, 2);
        for (int i = 0; i < 4; i++) {
            DnsTestSupport.Zone other = DnsTestSupport.zone("zone" + i + ".");
            put(other.name().toString(), DnsRecord.DS, signed(root, List.of(other.ds())), List.of());
            put(other.name().toString(), DnsRecord.DNSKEY, signed(other, List.of(other.dnskey())), List.of());
            validator.walk(other.name());
            for (boolean insecure : List.of(false, true)) {
                String name = insecure ? "unsigned" + i + ".test." : "n" + i + ".test.";
                DnsRecord proof = DnsTestSupport.nsec(name, "z.test.",
                        insecure ? DnsRecord.NS : DnsRecord.A, DnsRecord.NSEC, DnsRecord.RRSIG);
                put(name, DnsRecord.DS, List.of(), signed(zone, List.of(proof)));
                validator.walk(DnsName.parse(name));
            }
        }
        assertEquals(2, cacheSize(validator, "zoneKeys"));
        assertEquals(2, cacheSize(validator, "insecureCuts"));
        assertEquals(2, cacheSize(validator, "notCuts"));
    }

    @Test
    void concurrentResolutionsHaveIndependentBudgets() throws Exception {
        put("a.test.", DnsRecord.A, signed(zone, List.of(a("a.test.", 192, 0, 2, 1))), List.of());
        DnssecHostResolver resolver = builder().cacheCapacity(0).maxValidationWork(528).build();
        try (var executor = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var tasks = new ArrayList<java.util.concurrent.Callable<Boolean>>();
            for (int i = 0; i < 8; i++) tasks.add(() -> resolver.lookup("a.test").secure());
            for (var result : executor.invokeAll(tasks)) assertTrue(result.get());
        }
        assertEquals(0, cacheSize(resolver, "cache"));
    }

    private void assertBudgetExceeded(org.junit.jupiter.api.function.Executable lookup) {
        DnssecValidationException failure = assertThrows(DnssecValidationException.class, lookup);
        assertTrue(failure.getMessage().contains("work budget"), failure.getMessage());
    }

    private List<DnsRecord> withInvalidSignatures(List<DnsRecord> records, int count) {
        DnsRecord signature = zone.sign(records, NOW / 1000 - 3600, NOW / 1000 + 3600);
        byte[] bad = signature.rdata().clone();
        bad[bad.length - 1] ^= 1;
        DnsRecord invalid = new DnsRecord(signature.name(), signature.type(), 1, signature.ttl(), bad);
        List<DnsRecord> answer = new ArrayList<>(records);
        for (int i = 0; i < count; i++) answer.add(invalid);
        answer.add(signature);
        return answer;
    }

    private DnsRecord nsec3(int iterations) {
        byte[] next = new byte[20];
        java.util.Arrays.fill(next, (byte) 0xff);
        byte[] params = new byte[] {1, 1, (byte) (iterations >> 8), (byte) iterations, 0, 20};
        return new DnsRecord(DnsName.parse("00000000000000000000000000000000.test."), DnsRecord.NSEC3,
                1, 300, DnsRecord.concat(params, next, DnsTestSupport.bitmap(DnsRecord.NS)));
    }

    private DnsRecord nsec3(int iterations, DnsName exactOwner, boolean wrapToSelf) {
        byte[] hash = DnssecCrypto.nsec3Hash(exactOwner, new byte[0], iterations);
        byte[] next = wrapToSelf ? hash : new byte[20];
        byte[] params = new byte[] {1, 1, (byte) (iterations >> 8), (byte) iterations, 0, 20};
        return new DnsRecord(DnsName.parse(DnssecCrypto.base32HexEncode(hash) + ".test."), DnsRecord.NSEC3,
                1, 300, DnsRecord.concat(params, next, DnsTestSupport.bitmap(DnsRecord.NS)));
    }

    private List<DnsRecord> signed(DnsTestSupport.Zone signer, List<DnsRecord> records) {
        return DnsTestSupport.with(records, signer.sign(records, NOW / 1000 - 3600, NOW / 1000 + 3600));
    }

    private void put(String name, int type, List<DnsRecord> answer, List<DnsRecord> authority) {
        DnsName owner = DnsName.parse(name);
        responses.put(DnsTestSupport.key(owner, type), DnsTestSupport.response(owner, type, 0, answer, authority));
    }

    private DnssecHostResolver resolver() {
        return builder().build();
    }

    private DnssecHostResolver.Builder builder() {
        return DnssecHostResolver.builder().transport(DnsTestSupport.replay(responses))
                .trustAnchors(List.of(root.trustAnchor())).clock(clock);
    }

    private DnssecValidator validator() {
        return new DnssecValidator(DnsTestSupport.replay(responses), List.of(root.ds()), clock);
    }

    private static int cacheSize(Object owner, String name) throws Exception {
        Field field = owner.getClass().getDeclaredField(name);
        field.setAccessible(true);
        Object cache = field.get(owner);
        if (cache instanceof Map<?, ?> map) return map.size();
        return cacheSize(cache, "entries");
    }

    static final class MutableClock extends Clock {
        volatile long millis;
        MutableClock(long millis) { this.millis = millis; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return Instant.ofEpochMilli(millis); }
        @Override public long millis() { return millis; }
    }
}
