package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.tls.BrowserProfiles;
import io.github.mahmoudimus.quic.tls.Grease;
import io.github.mahmoudimus.quic.tls.HelloContext;
import io.github.mahmoudimus.quic.tls.ProfileExtensions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.microproxy.ClientHello;
import org.microproxy.extras.TlsFingerprints;
import org.junit.jupiter.api.Test;

/**
 * The Chrome 156 profile's hellos, read by the proxy's own ClientHello parser, have the JA4 of
 * a real Chrome 156 (captured 2026-10-27 from 156.0.8078.48, and the same as impersonator
 * 1.11.0's {@code macChrome} profile sent through {@code Tls.clientHandshake}).
 */
class Chrome156FingerprintTest {

    /**
     * The JA3 string of Chrome 156's hellos (captured, quic/src/test/resources/fingerprints/chrome-156),
     * its extensions in numeric order ({@link #unshuffledJa3}): that of a new connection, and of
     * one that resumes a session, which adds pre_shared_key (41).
     */
    static final String CHROME_156_JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
            + "0-5-10-11-13-16-18-23-27-35-43-45-51-17613-51764-65037-65281,4588-29-23-24,0";
    static final String CHROME_156_RESUMED_JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
            + "0-5-10-11-13-16-18-23-27-35-41-43-45-51-17613-51764-65037-65281,4588-29-23-24,0";

    @Test
    void ja4IsChrome156s() throws Exception {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 50; i++) {
            byte[] hello = BrowserProfiles.chrome156().encode(new HelloContext("example.com", List.of("h2", "http/1.1"),
                    Map.of(ProfileExtensions.X25519_MLKEM768, new byte[1216], 0x001d, new byte[32]),
                    Grease.random(random), random));
            assertEquals("t13d1517h2_8daaf6152771_cb7bf5808d99", TlsFingerprints.ja4(TlsClientHello.parse(hello)));
        }
    }

    @Test
    void quicJa4IsChrome156sOverHttp3() throws Exception {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 20; i++) {
            byte[] hello = BrowserProfiles.chrome156Quic().encode(new HelloContext("quic.test", List.of("h3"),
                    Map.of(ProfileExtensions.X25519_MLKEM768, new byte[1216], 0x001d, new byte[32]),
                    Grease.random(random), random, Map.of(ProfileExtensions.QUIC_TRANSPORT_PARAMETERS, new byte[] {1, 2, 3})));
            // captured from Chrome 156.0.8078.48 over HTTP/3 (quic/src/test/resources/fingerprints/chrome-156-quic)
            assertEquals("q13d0312h3_55b375c5d22e_178839b6cec1", TlsFingerprints.ja4(TlsClientHello.parse(hello), true));
        }
    }
    @Test
    void ja3IsChrome156sUpToItsExtensionShuffle() throws Exception {
        // Chrome shuffles its extensions per connection, and so its JA3 hash: every one of its
        // hellos has a JA3 of its own, the same once the extension list is put in order
        String chrome = CHROME_156_JA3;
        SecureRandom random = new SecureRandom();
        Set<String> hashes = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            byte[] hello = BrowserProfiles.chrome156().encode(new HelloContext("example.com", List.of("h2", "http/1.1"),
                    Map.of(ProfileExtensions.X25519_MLKEM768, new byte[1216], 0x001d, new byte[32]),
                    Grease.random(random), random));
            ClientHello parsed = TlsClientHello.parse(hello);
            assertEquals(chrome, unshuffledJa3(parsed));
            hashes.add(TlsFingerprints.ja3(parsed));
        }
        assertTrue(hashes.size() > 150, hashes.size() + " JA3 hashes in 200 hellos");
    }

    /** The JA3 string with its extension list in numeric order, so that a shuffle drops out. */
    static String unshuffledJa3(ClientHello hello) {
        String[] fields = TlsFingerprints.ja3String(hello).split(",", -1);
        fields[2] = String.join("-", Arrays.stream(fields[2].split("-")).mapToInt(Integer::parseInt).sorted()
                .mapToObj(Integer::toString).toList());
        return String.join(",", fields);
    }
}
