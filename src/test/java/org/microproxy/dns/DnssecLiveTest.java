package org.microproxy.dns;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Validates real domains over DNS over HTTPS. Opt-in with {@code -Dmicroproxy.dns.live=true};
 * with {@code -Dmicroproxy.dns.record=true} it also rewrites the fixtures replayed by {@link
 * DnssecRecordedTest}.
 */
@EnabledIfSystemProperty(named = "microproxy.dns.live", matches = "true")
class DnssecLiveTest {

    static final String DOH = System.getProperty("microproxy.dns.doh", "https://cloudflare-dns.com/dns-query");

    @Test
    void realWorldDomains() throws Exception {
        Map<String, byte[]> recorded = new ConcurrentHashMap<>();
        long recordedAt = Instant.now().getEpochSecond();
        DnssecHostResolver resolver = DnssecHostResolver.builder()
                .transport(DnsTestSupport.recording(DnsTransport.https(URI.create(DOH), Duration.ofSeconds(10)), recorded))
                .build();
        RecordedExpectations.check(resolver);
        if (Boolean.getBoolean("microproxy.dns.record")) {
            DnsTestSupport.save(Path.of("src/test/resources/dns/recorded.txt"), recordedAt, recorded);
        }
    }

    /** Expected outcomes shared by the live and the replay test. */
    static final class RecordedExpectations {
        static void check(DnssecHostResolver resolver) throws Exception {
            // Signed: ECDSA P-256 (.com, example.com) under the RSA-signed root.
            assertTrue(resolver.lookup("example.com").secure());
            // Signed with NSEC "black lies" for the non-delegation www label.
            assertTrue(resolver.lookup("www.cloudflare.com").secure());
            // Signed with Ed25519.
            assertTrue(resolver.lookup("ed25519.nl").secure());
            // Signed, NSEC3 in .nl.
            assertTrue(resolver.lookup("www.sidn.nl").secure());
            // Unsigned zone, proven by an NSEC3 opt-out span in .com.
            assertFalse(resolver.lookup("google.com").secure());
            // Deliberately broken zone.
            assertThrows(DnssecValidationException.class, () -> resolver.lookup("dnssec-failed.org"));
            // Nonexistent name.
            UnknownHostException e = assertThrows(UnknownHostException.class,
                    () -> resolver.lookup("no-such-name-q7x.example.com"));
            assertFalse(e instanceof DnssecValidationException);
        }
    }
}
