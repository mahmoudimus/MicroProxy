package io.github.mahmoudimus.quic.tls;

/** ClientHello profiles of real browsers, each checked against a capture of that browser. */
public final class BrowserProfiles {

    /**
     * The Trust Anchor IDs Chrome 156 sends (draft-ietf-tls-trust-anchor-ids), the Chrome Root
     * Store's, in lexicographic order; the same 28 as uTLS's {@code chrome155TrustAnchorIDs}.
     */
    static final String[] CHROME_156_TRUST_ANCHORS = {
        "82df130201", "82df130206", "82df13020d", "82df13020e", "82df13020f", "82df130212",
        "82df130213", "82df130214", "839a648c9b2d0107", "839a648c9b2d0108", "839a648c9b2d0109",
        "839a648c9b2d010a", "839a648c9b2d010b", "839a648c9b2d010c", "839a648c9b2d010d",
        "839a648c9b2d0112", "839a648c9b2d0113", "d6790901", "d6790904", "d6790905", "d6790906",
        "d6790907", "d6790908", "d679090a", "d679090b", "d679090c", "d679090d", "d679090f",
    };

    private BrowserProfiles() {}
}
