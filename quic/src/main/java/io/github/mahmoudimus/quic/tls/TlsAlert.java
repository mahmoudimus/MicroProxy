// Ported from rustls src/msgs/enums.rs (AlertDescription) and src/error/mod.rs (the alert each
// error maps to) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;

/**
 * The TLS alert descriptions (RFC 8446 section 6) the handshake raises. QUIC sends no TLS alerts:
 * an alert becomes a {@code CRYPTO_ERROR} connection error, {@code 0x0100 + alert} (RFC 9001
 * section 4.8), built by {@link QuicException#tlsAlert(int, String)}.
 */
public final class TlsAlert {

    /** A message arrived out of order or where it is not allowed (10). */
    public static final int UNEXPECTED_MESSAGE = 10;
    /** A record failed to decrypt; not used by QUIC (20). */
    public static final int BAD_RECORD_MAC = 20;
    /** No acceptable set of security parameters could be negotiated (40). */
    public static final int HANDSHAKE_FAILURE = 40;
    /** A certificate was corrupt or failed a check such as its name (42). */
    public static final int BAD_CERTIFICATE = 42;
    /** A certificate of an unsupported type (43). */
    public static final int UNSUPPORTED_CERTIFICATE = 43;
    /** A certificate was revoked (44). */
    public static final int CERTIFICATE_REVOKED = 44;
    /** A certificate has expired or is not yet valid (45). */
    public static final int CERTIFICATE_EXPIRED = 45;
    /** Some other problem with a certificate made it unacceptable (46). */
    public static final int CERTIFICATE_UNKNOWN = 46;
    /** A field was out of range or inconsistent with other fields (47). */
    public static final int ILLEGAL_PARAMETER = 47;
    /** The certificate chain does not lead to a trusted certificate authority (48). */
    public static final int UNKNOWN_CA = 48;
    /** Access was denied (49). */
    public static final int ACCESS_DENIED = 49;
    /** A message could not be decoded (50). */
    public static final int DECODE_ERROR = 50;
    /** A handshake cryptographic operation failed, such as a signature or Finished check (51). */
    public static final int DECRYPT_ERROR = 51;
    /** The peer's protocol version is recognized but not supported (70). */
    public static final int PROTOCOL_VERSION = 70;
    /** The peer's parameters are weaker than required (71). */
    public static final int INSUFFICIENT_SECURITY = 71;
    /** An internal error unrelated to the peer (80). */
    public static final int INTERNAL_ERROR = 80;
    /** A downgrade was detected (86). */
    public static final int INAPPROPRIATE_FALLBACK = 86;
    /** The user cancelled the handshake (90). */
    public static final int USER_CANCELED = 90;
    /** A message lacked an extension it must carry (109). */
    public static final int MISSING_EXTENSION = 109;
    /** A message carried an extension that was not offered or not allowed there (110). */
    public static final int UNSUPPORTED_EXTENSION = 110;
    /** The server does not recognize the server name the client asked for (112). */
    public static final int UNRECOGNIZED_NAME = 112;
    /** An OCSP response was invalid (113). */
    public static final int BAD_CERTIFICATE_STATUS_RESPONSE = 113;
    /** A PSK identity was not recognized (115). */
    public static final int UNKNOWN_PSK_IDENTITY = 115;
    /** The server required a client certificate and none was sent (116). */
    public static final int CERTIFICATE_REQUIRED = 116;
    /** No application protocol could be agreed with ALPN (120). */
    public static final int NO_APPLICATION_PROTOCOL = 120;

    private TlsAlert() {}

    /**
     * The alert's name, as RFC 8446 spells it.
     *
     * @param alert the alert description
     * @return the name, such as {@code "handshake_failure"}, or {@code "alert(N)"} for an unknown one
     */
    public static String name(int alert) {
        return switch (alert) {
            case UNEXPECTED_MESSAGE -> "unexpected_message";
            case BAD_RECORD_MAC -> "bad_record_mac";
            case HANDSHAKE_FAILURE -> "handshake_failure";
            case BAD_CERTIFICATE -> "bad_certificate";
            case UNSUPPORTED_CERTIFICATE -> "unsupported_certificate";
            case CERTIFICATE_REVOKED -> "certificate_revoked";
            case CERTIFICATE_EXPIRED -> "certificate_expired";
            case CERTIFICATE_UNKNOWN -> "certificate_unknown";
            case ILLEGAL_PARAMETER -> "illegal_parameter";
            case UNKNOWN_CA -> "unknown_ca";
            case ACCESS_DENIED -> "access_denied";
            case DECODE_ERROR -> "decode_error";
            case DECRYPT_ERROR -> "decrypt_error";
            case PROTOCOL_VERSION -> "protocol_version";
            case INSUFFICIENT_SECURITY -> "insufficient_security";
            case INTERNAL_ERROR -> "internal_error";
            case INAPPROPRIATE_FALLBACK -> "inappropriate_fallback";
            case USER_CANCELED -> "user_canceled";
            case MISSING_EXTENSION -> "missing_extension";
            case UNSUPPORTED_EXTENSION -> "unsupported_extension";
            case UNRECOGNIZED_NAME -> "unrecognized_name";
            case BAD_CERTIFICATE_STATUS_RESPONSE -> "bad_certificate_status_response";
            case UNKNOWN_PSK_IDENTITY -> "unknown_psk_identity";
            case CERTIFICATE_REQUIRED -> "certificate_required";
            case NO_APPLICATION_PROTOCOL -> "no_application_protocol";
            default -> "alert(" + alert + ")";
        };
    }

    /**
     * The alert a {@code CRYPTO_ERROR} code carries.
     *
     * @param code a QUIC transport error code
     * @return the TLS alert description, or -1 if {@code code} is not in the {@code CRYPTO_ERROR} range
     */
    public static int fromErrorCode(long code) {
        return code >= QuicException.CRYPTO_ERROR && code <= QuicException.CRYPTO_ERROR + 0xff
                ? (int) (code - QuicException.CRYPTO_ERROR)
                : -1;
    }

    /** The error for {@code alert}, with its name in front of {@code reason}. */
    static QuicException error(int alert, String reason) {
        return QuicException.tlsAlert(alert, name(alert) + ": " + reason);
    }

    static QuicException decodeError(String reason) {
        return error(DECODE_ERROR, reason);
    }

    static QuicException illegalParameter(String reason) {
        return error(ILLEGAL_PARAMETER, reason);
    }

    static QuicException unexpectedMessage(String reason) {
        return error(UNEXPECTED_MESSAGE, reason);
    }
}
