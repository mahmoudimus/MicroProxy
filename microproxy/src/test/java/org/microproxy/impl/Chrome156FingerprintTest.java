package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.mahmoudimus.quic.tls.BrowserProfiles;
import io.github.mahmoudimus.quic.tls.Grease;
import io.github.mahmoudimus.quic.tls.HelloContext;
import io.github.mahmoudimus.quic.tls.ProfileExtensions;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import org.microproxy.extras.TlsFingerprints;
import org.junit.jupiter.api.Test;

/**
 * The Chrome 156 profile's hellos, read by the proxy's own ClientHello parser, have the JA4 of
 * a real Chrome 156 (captured 2026-10-27 from 156.0.8078.48, and the same as impersonator
 * 1.11.0's {@code macChrome} profile sent through {@code Tls.clientHandshake}).
 */
class Chrome156FingerprintTest {

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
}
