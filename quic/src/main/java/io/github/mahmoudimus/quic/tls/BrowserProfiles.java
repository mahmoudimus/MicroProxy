package io.github.mahmoudimus.quic.tls;

import static io.github.mahmoudimus.quic.tls.ProfileExtensions.BROTLI;
import static io.github.mahmoudimus.quic.tls.ProfileExtensions.GREASE;
import static io.github.mahmoudimus.quic.tls.ProfileExtensions.X25519_MLKEM768;
import static io.github.mahmoudimus.quic.tls.ProfileExtensions.ZLIB;
import static io.github.mahmoudimus.quic.tls.ProfileExtensions.ZSTD;

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

    /**
     * Chrome 156's ClientHello in QUIC (RFC 9001), as captured from 156.0.8078.48 on macOS over
     * HTTP/3. Unlike its TCP hello it has no GREASE at all; no extended_master_secret,
     * renegotiation_info, ec_point_formats, session_ticket, status_request or
     * signed_certificate_timestamp; TLS 1.3 suites only; an empty legacy_session_id;
     * {@code rsa_pkcs1_sha1} but no ML-DSA among its signature schemes; ALPS for its protocol
     * ({@code h3}); and the connection's {@code quic_transport_parameters}. Its 12 extensions are
     * shuffled per hello. With SNI and ALPN {@code h3} its JA4 is {@code q13d0312h3_55b375c5d22e_178839b6cec1}.
     *
     * <p>The key shares need public keys for {@code 0x11ec} and {@code 0x001d}, and the transport
     * parameters come from {@link HelloContext#supplied()} under {@link ProfileExtensions#QUIC_TRANSPORT_PARAMETERS}.
     *
     * @return the profile
     */
    public static ClientHelloProfile chrome156Quic() {
        return new ClientHelloProfile("chrome-156-quic",
                new int[] {0x1301, 0x1302, 0x1303},
                List.of(
                        ProfileExtensions.compressCertificate(BROTLI),
                        ProfileExtensions.trustAnchors(CHROME_156_TRUST_ANCHORS),
                        ProfileExtensions.applicationSettings("h3"),
                        ProfileExtensions.serverName(),
                        ProfileExtensions.keyShare(X25519_MLKEM768, 0x001d),
                        ProfileExtensions.pskKeyExchangeModes(),
                        ProfileExtensions.supportedVersions(0x0304),
                        ProfileExtensions.supplied(ProfileExtensions.QUIC_TRANSPORT_PARAMETERS),
                        ProfileExtensions.signatureAlgorithms(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                                0x0601, 0x0201),
                        ProfileExtensions.greaseEch(144, 176, 208, 240),
                        ProfileExtensions.supportedGroups(X25519_MLKEM768, 0x001d, 0x0017, 0x0018),
                        ProfileExtensions.alpn()),
                true, 0);
    }

    /**
     * Firefox 159 (NSS) over TCP, as captured from 159.0 on macOS: 15 cipher suites, ChaCha20
     * before AES-256 among the TLS 1.3 ones; 17 extensions in a fixed order and no GREASE;
     * X25519MLKEM768, X25519 and P-256 key shares; {@code delegated_credentials},
     * {@code record_size_limit} 16385, and zlib, Brotli and zstd certificate compression; and a
     * GREASE ECH sized as NSS sizes it ({@link ProfileExtensions#nssGreaseEch}). A hello that
     * resumes a session leaves out {@code session_ticket}.
     *
     * <p>The key shares need public keys for {@code 0x11ec} (1216 bytes), {@code 0x001d} (32
     * bytes) and {@code 0x0017} (65 bytes) in the {@link HelloContext}.
     *
     * @return the profile
     */
    public static ClientHelloProfile firefox159() {
        return new ClientHelloProfile("firefox-159",
                new int[] {
                    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014,
                    0x009c, 0x009d, 0x002f, 0x0035,
                },
                List.of(
                        ProfileExtensions.serverName(),
                        ProfileExtensions.extendedMasterSecret(),
                        ProfileExtensions.renegotiationInfo(),
                        ProfileExtensions.supportedGroups(X25519_MLKEM768, 0x001d, 0x0017, 0x0018, 0x0019),
                        ProfileExtensions.ecPointFormats(),
                        ProfileExtensions.sessionTicketUnlessResuming(),
                        ProfileExtensions.alpn(),
                        ProfileExtensions.statusRequest(),
                        ProfileExtensions.delegatedCredentials(0x0403, 0x0503, 0x0603, 0x0203),
                        ProfileExtensions.signedCertificateTimestamp(),
                        ProfileExtensions.keyShare(X25519_MLKEM768, 0x001d, 0x0017),
                        ProfileExtensions.supportedVersions(0x0304, 0x0303),
                        ProfileExtensions.signatureAlgorithms(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
                                0x0401, 0x0501, 0x0601, 0x0203, 0x0201),
                        ProfileExtensions.pskKeyExchangeModes(),
                        ProfileExtensions.recordSizeLimit(16_385),
                        ProfileExtensions.compressCertificate(ZLIB, BROTLI, ZSTD),
                        ProfileExtensions.nssGreaseEch()),
                false, 32);
    }

    /**
     * Firefox 159's ClientHello in QUIC (neqo over NSS), as captured from 159.0 on macOS over
     * HTTP/3: TLS 1.3 alone, its three suites with ChaCha20 before AES-256; no session id, no
     * {@code session_ticket} or {@code ec_point_formats}; the TCP hello's groups, key shares,
     * delegated credentials and record size limit; its signature schemes and certificate
     * compression algorithms in another order; shuffled per hello, except the connection's
     * {@code quic_transport_parameters} and the GREASE ECH, which stay last. With SNI and ALPN
     * {@code h3} its JA4 is {@code q13d0315h3_55b375c5d22e_dc5437974b47}.
     *
     * <p>The key shares need public keys for {@code 0x11ec}, {@code 0x001d} and {@code 0x0017}, and
     * the transport parameters come from {@link HelloContext#supplied()} under {@link
     * ProfileExtensions#QUIC_TRANSPORT_PARAMETERS}.
     *
     * @return the profile
     */
    public static ClientHelloProfile firefox159Quic() {
        return new ClientHelloProfile("firefox-159-quic",
                new int[] {0x1301, 0x1303, 0x1302},
                List.of(
                        ProfileExtensions.serverName(),
                        ProfileExtensions.keyShare(X25519_MLKEM768, 0x001d, 0x0017),
                        ProfileExtensions.extendedMasterSecret(),
                        ProfileExtensions.supportedGroups(X25519_MLKEM768, 0x001d, 0x0017, 0x0018, 0x0019),
                        ProfileExtensions.renegotiationInfo(),
                        ProfileExtensions.supportedVersions(0x0304),
                        ProfileExtensions.pskKeyExchangeModes(),
                        ProfileExtensions.statusRequest(),
                        ProfileExtensions.signatureAlgorithms(0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806,
                                0x0401, 0x0501, 0x0601, 0x0201),
                        ProfileExtensions.alpn(),
                        ProfileExtensions.delegatedCredentials(0x0403, 0x0503, 0x0603, 0x0203),
                        ProfileExtensions.compressCertificate(ZLIB, ZSTD, BROTLI),
                        ProfileExtensions.recordSizeLimit(16_385),
                        ProfileExtensions.supplied(ProfileExtensions.QUIC_TRANSPORT_PARAMETERS).pin(),
                        ProfileExtensions.nssGreaseEch().pin()),
                true, 0);
    }
}
