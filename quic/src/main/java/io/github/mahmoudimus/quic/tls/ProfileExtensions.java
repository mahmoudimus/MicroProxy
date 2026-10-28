package io.github.mahmoudimus.quic.tls;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

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

    /** {@code quic_transport_parameters} (RFC 9001 section 8.2). */
    public static final int QUIC_TRANSPORT_PARAMETERS = 0x39;

    /** {@code record_size_limit} (RFC 8449). */
    public static final int RECORD_SIZE_LIMIT = 28;

    /** {@code delegated_credentials} (RFC 9345). */
    public static final int DELEGATED_CREDENTIALS = 34;

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

    /**
     * {@code session_ticket} (RFC 5077), empty, left out of a hello that resumes a TLS 1.3 session,
     * as NSS (Firefox) leaves it out.
     */
    public static ExtensionSpec sessionTicketUnlessResuming() {
        return new ExtensionSpec(35, c -> c.resuming() ? null : EMPTY);
    }

    /** {@code delegated_credentials} (RFC 9345) accepting credentials signed with {@code schemes}, in order. */
    public static ExtensionSpec delegatedCredentials(int... schemes) {
        return new ExtensionSpec(DELEGATED_CREDENTIALS, c -> u16List(schemes, c.grease().signature()));
    }

    /** {@code record_size_limit} (RFC 8449) announcing {@code limit}. */
    public static ExtensionSpec recordSizeLimit(int limit) {
        return new ExtensionSpec(RECORD_SIZE_LIMIT, c -> new byte[] {(byte) (limit >>> 8), (byte) limit});
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

    /**
     * An extension whose body the connection makes itself ({@link HelloContext#supplied()}), such as
     * QUIC's {@code quic_transport_parameters}; left out when the connection supplies none.
     */
    public static ExtensionSpec supplied(int type) {
        return new ExtensionSpec(type, c -> c.supplied().get(type));
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

    /**
     * A GREASE {@code encrypted_client_hello} as NSS (Firefox) sends one when it has no ECHConfig
     * ({@code tls13_MaybeGreaseEch}): an outer ClientHello extension for HKDF-SHA256 and, at
     * random, AES-128-GCM or ChaCha20-Poly1305, a random config id and 32-byte {@code enc}, and a
     * random payload as long as the ClientHelloInner NSS would have encrypted. That is the
     * EncodedClientHelloInner made from this hello ({@code tls13_ConstructInnerExtensionsFromOuter}):
     * <ul>
     *   <li>an inner {@code encrypted_client_hello}, the {@code server_name}, and
     *       {@code supported_versions} with TLS 1.3 alone;</li>
     *   <li>the hello's other extensions that TLS 1.3 has, as one {@code ech_outer_extensions};</li>
     *   <li>the {@code pre_shared_key}, when resuming;</li>
     * </ul>
     * padded as for a configuration whose {@code maximum_name_length} is 100 ({@code
     * tls13_PadChInner}), plus the 16-byte AEAD tag.
     */
    public static ExtensionSpec nssGreaseEch() {
        return new ExtensionSpec(ENCRYPTED_CLIENT_HELLO, (ExtensionSpec.WholeHelloBody) (c, suites, others) -> {
            byte[] determinant = new byte[1];
            byte[] configId = new byte[1];
            byte[] enc = new byte[32];
            c.random().nextBytes(determinant);
            c.random().nextBytes(configId);
            c.random().nextBytes(enc);
            byte[] payload = new byte[nssGreasePayloadLength(c, suites, others)];
            c.random().nextBytes(payload);
            Writer w = new Writer();
            w.u8(0).u16(0x0001).u16((determinant[0] & 1) != 0 ? 0x0001 : 0x0003).u8(configId[0] & 0xff)
                    .vector16(enc).vector16(payload);
            return w.toByteArray();
        });
    }

    /** The extensions NSS leaves out of a ClientHelloInner, which can only negotiate TLS 1.3. */
    private static final Set<Integer> TLS12_ONLY = Set.of(23, 0xff01, 11, 35);

    /** The length of the payload of NSS's GREASE ECH for this hello: see {@link #nssGreaseEch}. */
    static int nssGreasePayloadLength(HelloContext c, int[] suites, List<HandshakeMessage.Extension> others) {
        int nameLength = c.serverName() == null ? 0 : c.serverName().length();
        int extensions = 4 + 1; // the inner encrypted_client_hello
        int compressed = 0;
        for (HandshakeMessage.Extension e : others) {
            int type = e.type();
            if (TLS12_ONLY.contains(type)) continue;
            if (type == ExtensionType.SERVER_NAME) {
                extensions += 4 + e.data().length;
            } else if (type == ExtensionType.SUPPORTED_VERSIONS) {
                extensions += 4 + 3;
            } else {
                compressed++;
            }
        }
        if (compressed > 0) extensions += 4 + 1 + 2 * compressed;
        if (c.resuming()) extensions += 4 + c.pskLength();
        // version, random, an empty legacy_session_id, the cipher suites, null compression, the extensions
        int length = 2 + 32 + 1 + 2 + 2 * suites.length + 2 + 2 + extensions;
        int namePadding = Math.max(0, 100 - nameLength);
        int rounding = 31 - ((length + namePadding - 1) % 32);
        return length + namePadding + rounding + 16;
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
