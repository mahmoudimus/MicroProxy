package io.github.mahmoudimus.quic.tls;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * The extensions browser profiles send, each as an {@link ExtensionSpec} whose body is encoded
 * the way the browser encodes it (RFC 8446 section 4.2 and the extensions' own specifications).
 * In the lists, {@link #GREASE} stands for the hello's GREASE value of that list.
 */
public final class ProfileExtensions {

    /** In a cipher suite, group, version or signature scheme list: the hello's GREASE value. */
    public static final int GREASE = -1;

    /** {@code application_settings} (ALPS) with the codepoint Chrome has used since 2025. */
    public static final int APPLICATION_SETTINGS = 0x44cd;

    /** {@code trust_anchors} (draft-ietf-tls-trust-anchor-ids). */
    public static final int TRUST_ANCHORS = 0xca34;

    /** {@code encrypted_client_hello} (RFC 9849). */
    public static final int ENCRYPTED_CLIENT_HELLO = 0xfe0d;

    /** {@code record_size_limit} (RFC 8449). */
    public static final int RECORD_SIZE_LIMIT = 28;

    /** {@code compress_certificate} (RFC 8879). */
    public static final int COMPRESS_CERTIFICATE = 27;

    /** The hybrid named group X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem). */
    public static final int X25519_MLKEM768 = 0x11ec;

    /** Certificate compression algorithms (RFC 8879 section 7.3). */
    public static final int ZLIB = 1, BROTLI = 2, ZSTD = 3;

    private static final byte[] EMPTY = {};

    private ProfileExtensions() {}

    /** The first GREASE extension, with an empty body, as BoringSSL sends it. */
    public static ExtensionSpec greaseFirst() {
        return new ExtensionSpec(ExtensionSpec.GREASE_FIRST, c -> EMPTY);
    }

    /** The last GREASE extension, with a one-byte body of zero, as BoringSSL sends it. */
    public static ExtensionSpec greaseLast() {
        return new ExtensionSpec(ExtensionSpec.GREASE_LAST, c -> new byte[] {0});
    }

    /** {@code server_name} with the context's host name; left out when there is none. */
    public static ExtensionSpec serverName() {
        return new ExtensionSpec(ExtensionType.SERVER_NAME,
                c -> c.serverName() == null ? null : Extensions.encodeServerName(c.serverName()));
    }

    /** {@code extended_master_secret} (RFC 7627), empty. */
    public static ExtensionSpec extendedMasterSecret() {
        return new ExtensionSpec(23, c -> EMPTY);
    }

    /** {@code renegotiation_info} (RFC 5746) of an initial handshake: an empty renegotiated_connection. */
    public static ExtensionSpec renegotiationInfo() {
        return new ExtensionSpec(0xff01, c -> new byte[] {0});
    }

    /** {@code supported_groups}: {@code groups} in order. */
    public static ExtensionSpec supportedGroups(int... groups) {
        return new ExtensionSpec(ExtensionType.SUPPORTED_GROUPS, c -> u16List(groups, c.grease().group()));
    }

    /** {@code ec_point_formats} offering only the uncompressed format. */
    public static ExtensionSpec ecPointFormats() {
        return new ExtensionSpec(11, c -> new byte[] {1, 0});
    }

    /** {@code session_ticket} (RFC 5077), empty: no ticket to resume with. */
    public static ExtensionSpec sessionTicket() {
        return new ExtensionSpec(35, c -> EMPTY);
    }

    /** {@code application_layer_protocol_negotiation} with the context's protocols; left out when there are none. */
    public static ExtensionSpec alpn() {
        return new ExtensionSpec(ExtensionType.ALPN,
                c -> c.alpnProtocols().isEmpty() ? null : protocolList(c.alpnProtocols().toArray(String[]::new)));
    }

    /** {@code status_request} for OCSP, with no responder ids and no extensions. */
    public static ExtensionSpec statusRequest() {
        return new ExtensionSpec(ExtensionType.STATUS_REQUEST, c -> new byte[] {1, 0, 0, 0, 0});
    }

    /** {@code signature_algorithms}: {@code schemes} in order. */
    public static ExtensionSpec signatureAlgorithms(int... schemes) {
        return new ExtensionSpec(ExtensionType.SIGNATURE_ALGORITHMS, c -> u16List(schemes, c.grease().signature()));
    }

    /** {@code signed_certificate_timestamp}, empty. */
    public static ExtensionSpec signedCertificateTimestamp() {
        return new ExtensionSpec(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP, c -> EMPTY);
    }

    /**
     * {@code key_share} with a share for each of {@code groups}: the GREASE group's is one zero
     * byte, the others are the context's public keys.
     *
     * @throws IllegalArgumentException from the body if the context has no key for a group
     */
    public static ExtensionSpec keyShare(int... groups) {
        return new ExtensionSpec(ExtensionType.KEY_SHARE, c -> {
            Writer w = new Writer();
            int list = w.open(2);
            for (int group : groups) {
                if (group == GREASE) {
                    w.u16(c.grease().group()).vector16(new byte[] {0});
                    continue;
                }
                byte[] key = c.keyShares().get(group);
                if (key == null) {
                    throw new IllegalArgumentException("no key share for group 0x" + Integer.toHexString(group));
                }
                w.u16(group).vector16(key);
            }
            w.close(list);
            return w.toByteArray();
        }, groups.clone());
    }

    /** {@code psk_key_exchange_modes} offering only {@code psk_dhe_ke}. */
    public static ExtensionSpec pskKeyExchangeModes() {
        return new ExtensionSpec(ExtensionType.PSK_KEY_EXCHANGE_MODES, c -> new byte[] {1, 1});
    }

    /** {@code supported_versions}: {@code versions} in order. */
    public static ExtensionSpec supportedVersions(int... versions) {
        return new ExtensionSpec(ExtensionType.SUPPORTED_VERSIONS, c -> {
            Writer w = new Writer();
            int list = w.open(1);
            for (int v : versions) w.u16(v == GREASE ? c.grease().version() : v);
            w.close(list);
            return w.toByteArray();
        });
    }

    /** {@code compress_certificate} (RFC 8879) offering {@code algorithms} in order. */
    public static ExtensionSpec compressCertificate(int... algorithms) {
        return new ExtensionSpec(COMPRESS_CERTIFICATE, c -> {
            Writer w = new Writer();
            int list = w.open(1);
            for (int a : algorithms) w.u16(a);
            w.close(list);
            return w.toByteArray();
        });
    }

    /** {@code application_settings} (ALPS) for {@code protocols}, Chrome's codepoint. */
    public static ExtensionSpec applicationSettings(String... protocols) {
        return new ExtensionSpec(APPLICATION_SETTINGS, c -> protocolList(protocols));
    }

    /** {@code trust_anchors} naming {@code hexIds}, each a hex-encoded trust anchor ID. */
    public static ExtensionSpec trustAnchors(String... hexIds) {
        byte[][] ids = new byte[hexIds.length][];
        for (int i = 0; i < hexIds.length; i++) ids[i] = HexFormat.of().parseHex(hexIds[i]);
        return new ExtensionSpec(TRUST_ANCHORS, c -> {
            Writer w = new Writer();
            int list = w.open(2);
            for (byte[] id : ids) w.vector8(id);
            w.close(list);
            return w.toByteArray();
        });
    }

    /**
     * A GREASE {@code encrypted_client_hello} (RFC 9849 section 6.2), as BoringSSL sends one when
     * it has no ECHConfig: an outer ClientHello extension for HKDF-SHA256 and AES-128-GCM, a random
     * config id, a random 32-byte {@code enc} and a random payload of one of {@code payloadLengths}.
     */
    public static ExtensionSpec greaseEch(int... payloadLengths) {
        return new ExtensionSpec(ENCRYPTED_CLIENT_HELLO, c -> {
            byte[] configId = new byte[1];
            byte[] enc = new byte[32];
            byte[] payload = new byte[payloadLengths[c.random().nextInt(payloadLengths.length)]];
            c.random().nextBytes(configId);
            c.random().nextBytes(enc);
            c.random().nextBytes(payload);
            Writer w = new Writer();
            w.u8(0).u16(0x0001).u16(0x0001).u8(configId[0] & 0xff).vector16(enc).vector16(payload);
            return w.toByteArray();
        });
    }

    private static byte[] u16List(int[] values, int grease) {
        Writer w = new Writer();
        int list = w.open(2);
        for (int v : values) w.u16(v == GREASE ? grease : v);
        w.close(list);
        return w.toByteArray();
    }

    private static byte[] protocolList(String[] protocols) {
        Writer w = new Writer();
        int list = w.open(2);
        for (String p : protocols) w.vector8(p.getBytes(StandardCharsets.US_ASCII));
        w.close(list);
        return w.toByteArray();
    }
}
