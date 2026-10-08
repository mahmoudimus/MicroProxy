package org.microproxy.dns;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Replays real DNS responses recorded by {@link DnssecLiveTest}, with the clock fixed at the
 * recording time so signatures remain valid. Then tampers with them.
 */
class DnssecRecordedTest {

    private static DnsTestSupport.Fixtures fixtures;

    @BeforeAll
    static void load() throws Exception {
        fixtures = DnsTestSupport.load(Path.of("src/test/resources/dns/recorded.txt"));
    }

    private static DnssecHostResolver resolver(Map<String, byte[]> responses, long epochSecond) {
        return DnssecHostResolver.builder()
                .transport(DnsTestSupport.replay(responses))
                .clock(Clock.fixed(Instant.ofEpochSecond(epochSecond), ZoneOffset.UTC))
                .build();
    }

    @Test
    void recordedRealWorldAnswersValidate() throws Exception {
        DnssecLiveTest.RecordedExpectations.check(resolver(fixtures.responses(), fixtures.recordedAtEpochSecond()));
    }

    @Test
    void signaturesExpire() {
        // Root DNSKEY signatures last about two weeks; a year later everything is bogus.
        long later = fixtures.recordedAtEpochSecond() + 365L * 86_400;
        assertThrows(DnssecValidationException.class,
                () -> resolver(fixtures.responses(), later).lookup("example.com"));
    }

    @Test
    void tamperedAddressIsBogus() {
        Map<String, byte[]> tampered = new HashMap<>(fixtures.responses());
        String key = DnsTestSupport.key(DnsName.parse("example.com"), DnsRecord.A);
        byte[] response = tampered.get(key).clone();
        DnsMessage message = DnsMessage.parse(response);
        byte[] address = message.answer.stream().filter(r -> r.type() == DnsRecord.A).findFirst().orElseThrow().rdata();
        int at = indexOf(response, address);
        response[at + 3] ^= 1;
        tampered.put(key, response);
        assertThrows(DnssecValidationException.class,
                () -> resolver(tampered, fixtures.recordedAtEpochSecond()).lookup("example.com"));
    }

    @Test
    void strippedSignaturesAreBogus() {
        Map<String, byte[]> stripped = new HashMap<>(fixtures.responses());
        DnsName name = DnsName.parse("example.com");
        String key = DnsTestSupport.key(name, DnsRecord.A);
        DnsMessage message = DnsMessage.parse(stripped.get(key));
        List<DnsRecord> unsigned = message.answer.stream().filter(r -> r.type() == DnsRecord.A).toList();
        stripped.put(key, DnsTestSupport.response(name, DnsRecord.A, 0, unsigned, List.of()));
        assertThrows(DnssecValidationException.class,
                () -> resolver(stripped, fixtures.recordedAtEpochSecond()).lookup("example.com"));
    }

    @Test
    void strippedDenialOfDsIsBogus() {
        // Without the NSEC3 opt-out proof from .com, google.com's lack of DS cannot be trusted.
        Map<String, byte[]> stripped = new HashMap<>(fixtures.responses());
        DnsName name = DnsName.parse("google.com");
        stripped.put(DnsTestSupport.key(name, DnsRecord.DS),
                DnsTestSupport.response(name, DnsRecord.DS, 0, List.of(), List.of()));
        assertThrows(DnssecValidationException.class,
                () -> resolver(stripped, fixtures.recordedAtEpochSecond()).lookup("google.com"));
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = haystack.length - needle.length; i >= 0; i--) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        throw new IllegalArgumentException("not found");
    }
}
