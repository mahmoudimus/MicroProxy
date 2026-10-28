package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.mahmoudimus.quic.tls.BrowserProfiles;
import io.github.mahmoudimus.quic.tls.Grease;
import io.github.mahmoudimus.quic.tls.HelloContext;
import io.github.mahmoudimus.quic.tls.ProfileExtensions;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import org.microproxy.ClientHello;
import org.microproxy.extras.TlsFingerprints;
import org.junit.jupiter.api.Test;

/**
 * The Firefox 159 profile's hellos, read by the proxy's own ClientHello parser, have the JA3 and
 * JA4 of a real Firefox 159.0 (captured 2026-10-28, quic/src/test/resources/fingerprints/firefox-159).
 * Firefox does not shuffle its extensions, so even the JA3 hash is the same on every connection.
 */
class Firefox159FingerprintTest {

    /** A new connection's. */
    static final String FIREFOX_159_JA4 = "t13d1517h2_8daaf6152771_3cbfd9057e0d";
    static final String FIREFOX_159_JA3 = "9d42e90b0225e779f03141ddcd699df2";
    /** A connection's that resumes a session: pre_shared_key in, session_ticket out. */
    static final String FIREFOX_159_RESUMED_JA4 = "t13d1517h2_8daaf6152771_e6dcd7ae0a9e";
    static final String FIREFOX_159_RESUMED_JA3 = "a55f6cb044839f48d371a56323ed22ef";
    /** Over HTTP/3 (fingerprints/firefox-159-quic). */
    static final String FIREFOX_159_QUIC_JA4 = "q13d0315h3_55b375c5d22e_dc5437974b47";

    @Test
    void ja3AndJa4AreFirefox159s() throws Exception {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 50; i++) {
            byte[] hello = BrowserProfiles.firefox159().encode(new HelloContext("example.com", List.of("h2", "http/1.1"),
                    Map.of(ProfileExtensions.X25519_MLKEM768, new byte[1216], 0x001d, new byte[32], 0x0017, new byte[65]),
                    Grease.random(random), random));
            ClientHello parsed = TlsClientHello.parse(hello);
            assertEquals(FIREFOX_159_JA4, TlsFingerprints.ja4(parsed));
            assertEquals(FIREFOX_159_JA3, TlsFingerprints.ja3(parsed));
        }
    }

    @Test
    void quicJa4IsFirefox159sOverHttp3() throws Exception {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 20; i++) {
            byte[] hello = BrowserProfiles.firefox159Quic().encode(new HelloContext("quic.test", List.of("h3"),
                    Map.of(ProfileExtensions.X25519_MLKEM768, new byte[1216], 0x001d, new byte[32], 0x0017, new byte[65]),
                    Grease.random(random), random, Map.of(ProfileExtensions.QUIC_TRANSPORT_PARAMETERS, new byte[] {1, 2, 3})));
            assertEquals(FIREFOX_159_QUIC_JA4, TlsFingerprints.ja4(TlsClientHello.parse(hello), true));
        }
    }
}
