// Ported from rustls src/msgs/enums.rs and src/enums.rs (HandshakeType) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

/** TLS 1.3 handshake message types (RFC 8446 section 4). */
final class HandshakeType {

    static final int CLIENT_HELLO = 1;
    static final int SERVER_HELLO = 2;
    static final int NEW_SESSION_TICKET = 4;
    static final int END_OF_EARLY_DATA = 5;
    static final int ENCRYPTED_EXTENSIONS = 8;
    static final int CERTIFICATE = 11;
    static final int CERTIFICATE_REQUEST = 13;
    static final int CERTIFICATE_VERIFY = 15;
    static final int FINISHED = 20;
    static final int KEY_UPDATE = 24;
    /** CompressedCertificate (RFC 8879). */
    static final int COMPRESSED_CERTIFICATE = 25;
    /** The synthetic message that replaces the first ClientHello in the transcript after a retry. */
    static final int MESSAGE_HASH = 254;

    private HandshakeType() {}

    static String name(int type) {
        return switch (type) {
            case CLIENT_HELLO -> "ClientHello";
            case SERVER_HELLO -> "ServerHello";
            case NEW_SESSION_TICKET -> "NewSessionTicket";
            case END_OF_EARLY_DATA -> "EndOfEarlyData";
            case ENCRYPTED_EXTENSIONS -> "EncryptedExtensions";
            case CERTIFICATE -> "Certificate";
            case CERTIFICATE_REQUEST -> "CertificateRequest";
            case CERTIFICATE_VERIFY -> "CertificateVerify";
            case FINISHED -> "Finished";
            case KEY_UPDATE -> "KeyUpdate";
            case MESSAGE_HASH -> "message_hash";
            default -> "handshake(" + type + ")";
        };
    }
}
