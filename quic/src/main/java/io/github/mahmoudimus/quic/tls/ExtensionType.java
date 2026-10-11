// Ported from rustls src/msgs/enums.rs (ExtensionType) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

/** The TLS extension code points the handshake knows (RFC 8446 section 4.2, RFC 9001 section 8.2). */
final class ExtensionType {

    static final int SERVER_NAME = 0;
    static final int MAX_FRAGMENT_LENGTH = 1;
    static final int STATUS_REQUEST = 5;
    static final int SUPPORTED_GROUPS = 10;
    static final int SIGNATURE_ALGORITHMS = 13;
    static final int USE_SRTP = 14;
    static final int HEARTBEAT = 15;
    static final int ALPN = 16;
    static final int SIGNED_CERTIFICATE_TIMESTAMP = 18;
    static final int CLIENT_CERTIFICATE_TYPE = 19;
    static final int SERVER_CERTIFICATE_TYPE = 20;
    static final int PADDING = 21;
    static final int PRE_SHARED_KEY = 41;
    static final int EARLY_DATA = 42;
    static final int SUPPORTED_VERSIONS = 43;
    static final int COOKIE = 44;
    static final int PSK_KEY_EXCHANGE_MODES = 45;
    static final int CERTIFICATE_AUTHORITIES = 47;
    static final int OID_FILTERS = 48;
    static final int POST_HANDSHAKE_AUTH = 49;
    static final int SIGNATURE_ALGORITHMS_CERT = 50;
    static final int KEY_SHARE = 51;
    /** {@code quic_transport_parameters} (RFC 9001 section 8.2). */
    static final int QUIC_TRANSPORT_PARAMETERS = 0x39;

    private ExtensionType() {}

    static String name(int type) {
        return switch (type) {
            case SERVER_NAME -> "server_name";
            case MAX_FRAGMENT_LENGTH -> "max_fragment_length";
            case STATUS_REQUEST -> "status_request";
            case SUPPORTED_GROUPS -> "supported_groups";
            case SIGNATURE_ALGORITHMS -> "signature_algorithms";
            case USE_SRTP -> "use_srtp";
            case HEARTBEAT -> "heartbeat";
            case ALPN -> "application_layer_protocol_negotiation";
            case SIGNED_CERTIFICATE_TIMESTAMP -> "signed_certificate_timestamp";
            case CLIENT_CERTIFICATE_TYPE -> "client_certificate_type";
            case SERVER_CERTIFICATE_TYPE -> "server_certificate_type";
            case PADDING -> "padding";
            case PRE_SHARED_KEY -> "pre_shared_key";
            case EARLY_DATA -> "early_data";
            case SUPPORTED_VERSIONS -> "supported_versions";
            case COOKIE -> "cookie";
            case PSK_KEY_EXCHANGE_MODES -> "psk_key_exchange_modes";
            case CERTIFICATE_AUTHORITIES -> "certificate_authorities";
            case OID_FILTERS -> "oid_filters";
            case POST_HANDSHAKE_AUTH -> "post_handshake_auth";
            case SIGNATURE_ALGORITHMS_CERT -> "signature_algorithms_cert";
            case KEY_SHARE -> "key_share";
            case QUIC_TRANSPORT_PARAMETERS -> "quic_transport_parameters";
            default -> "extension(" + type + ")";
        };
    }
}
