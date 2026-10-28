package io.github.mahmoudimus.quic.tls;

import static io.github.mahmoudimus.quic.tls.ProfileExtensions.BROTLI;
import static io.github.mahmoudimus.quic.tls.ProfileExtensions.GREASE;
import static io.github.mahmoudimus.quic.tls.ProfileExtensions.X25519_MLKEM768;

import java.util.List;

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
    /**
     * Chrome 156 (BoringSSL) over TCP, as captured from 156.0.8078.48 on macOS: 16 cipher
     * suites with GREASE first; 17 extensions plus two GREASE ones, shuffled per hello;
     * X25519MLKEM768 and X25519 key shares; ML-DSA signature schemes; ALPS for h2; Brotli
     * certificate compression; Trust Anchor IDs; and a GREASE ECH. The extension list is in
     * uTLS's {@code HelloChrome_155} order, which only matters as the order shuffling starts from.
     *
     * <p>The key shares need public keys for {@code 0x11ec} (1216 bytes) and {@code 0x001d}
     * (32 bytes) in the {@link HelloContext}.
     *
     * @return the profile
     */
    public static ClientHelloProfile chrome156() {
        return new ClientHelloProfile("chrome-156",
                new int[] {
                    GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                    0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
                },
                List.of(
                        ProfileExtensions.greaseFirst(),
                        ProfileExtensions.serverName(),
                        ProfileExtensions.extendedMasterSecret(),
                        ProfileExtensions.renegotiationInfo(),
                        ProfileExtensions.supportedGroups(GREASE, X25519_MLKEM768, 0x001d, 0x0017, 0x0018),
                        ProfileExtensions.ecPointFormats(),
                        ProfileExtensions.sessionTicket(),
                        ProfileExtensions.alpn(),
                        ProfileExtensions.statusRequest(),
                        ProfileExtensions.signatureAlgorithms(GREASE, 0x0904, 0x0905, 0x0906, 0x0403, 0x0804,
                                0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601),
                        ProfileExtensions.signedCertificateTimestamp(),
                        ProfileExtensions.keyShare(GREASE, X25519_MLKEM768, 0x001d),
                        ProfileExtensions.pskKeyExchangeModes(),
                        ProfileExtensions.supportedVersions(GREASE, 0x0304, 0x0303),
                        ProfileExtensions.compressCertificate(BROTLI),
                        ProfileExtensions.applicationSettings("h2"),
                        ProfileExtensions.trustAnchors(CHROME_156_TRUST_ANCHORS),
                        ProfileExtensions.greaseEch(144, 176, 208, 240),
                        ProfileExtensions.greaseLast()),
                true, 32);
    }
}
