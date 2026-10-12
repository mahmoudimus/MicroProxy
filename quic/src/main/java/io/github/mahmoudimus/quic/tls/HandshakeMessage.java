// Ported from rustls src/msgs/handshake.rs, src/msgs/client_hello.rs and src/msgs/server_hello.rs
// (the TLS 1.3 handshake message structures and their codecs) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A TLS 1.3 handshake message (RFC 8446 section 4). Decoding is purely structural: every length
 * is checked against its enclosing structure, and malformed input fails with a {@code
 * decode_error} alert and nothing else. Which extensions may appear, and whether they repeat, is
 * checked by the handshake that receives the message.
 */
sealed interface HandshakeMessage {

    /** The largest handshake message body the 24-bit length can describe. */
    int MAX_BODY = 0xffffff;

    /** The {@code random} of a ServerHello that is really a HelloRetryRequest (RFC 8446 section 4.1.3). */
    byte[] HELLO_RETRY_REQUEST_RANDOM = {
        (byte) 0xcf, 0x21, (byte) 0xad, 0x74, (byte) 0xe5, (byte) 0x9a, 0x61, 0x11,
        (byte) 0xbe, 0x1d, (byte) 0x8c, 0x02, 0x1e, 0x65, (byte) 0xb8, (byte) 0x91,
        (byte) 0xc2, (byte) 0xa2, 0x11, 0x16, 0x7a, (byte) 0xbb, (byte) 0x8c, 0x5e,
        0x07, (byte) 0x9e, 0x09, (byte) 0xe2, (byte) 0xc8, (byte) 0xa8, 0x33, (byte) 0x9c
    };

    /** The legacy version field of TLS 1.3 hellos, TLS 1.2's 0x0303. */
    int LEGACY_VERSION = 0x0303;

    /** TLS 1.3 in {@code supported_versions}. */
    int TLS13 = 0x0304;

    /** The handshake type. */
    int type();

    /** Writes the message body, without its four-byte header. */
    void encodeBody(Writer w);

    /** The whole message: type, 24-bit length and body. */
    default byte[] encode() {
        Writer w = new Writer();
        w.u8(type());
        int body = w.open(3);
        encodeBody(w);
        w.close(body);
        return w.toByteArray();
    }

    /**
     * Decodes a message body.
     *
     * @param type the handshake type from the message header
     * @param body the body, exactly as long as the header said
     */
    static HandshakeMessage decode(int type, byte[] body) throws QuicException {
        Reader r = new Reader(body);
        HandshakeMessage message = switch (type) {
            case HandshakeType.CLIENT_HELLO -> ClientHello.decode(r);
            case HandshakeType.SERVER_HELLO -> ServerHello.decode(r);
            case HandshakeType.ENCRYPTED_EXTENSIONS -> new EncryptedExtensions(Extension.decodeList(r, false));
            case HandshakeType.CERTIFICATE -> CertificateMessage.decode(r);
            case HandshakeType.CERTIFICATE_REQUEST -> CertificateRequest.decode(r);
            case HandshakeType.CERTIFICATE_VERIFY -> new CertificateVerify(
                    r.u16("CertificateVerify algorithm"), r.vector16(0, "CertificateVerify signature"));
            case HandshakeType.FINISHED -> new Finished(r.rest());
            case HandshakeType.NEW_SESSION_TICKET -> NewSessionTicket.decode(r);
            case HandshakeType.KEY_UPDATE -> new KeyUpdate(r.u8("KeyUpdate request"));
            default -> new Unknown(type, r.rest());
        };
        r.expectEnd(HandshakeType.name(type));
        return message;
    }

    /** One extension: its type and undecoded body. */
    record Extension(int type, byte[] data) {

        void encode(Writer w) {
            w.u16(type).vector16(data);
        }

        /**
         * Decodes an extension block, {@code Extension extensions<0..2^16-1>}.
         *
         * @param optional whether the block may be absent altogether, as in a ClientHello or
         *     ServerHello that ends after its fixed fields
         */
        static List<Extension> decodeList(Reader r, boolean optional) throws QuicException {
            List<Extension> out = new ArrayList<>();
            if (optional && !r.hasRemaining()) return out;
            Reader block = r.sub16("extensions");
            while (block.hasRemaining()) {
                int type = block.u16("extension type");
                out.add(new Extension(type, block.vector16(0, ExtensionType.name(type))));
            }
            return out;
        }

        static void encodeList(Writer w, List<Extension> extensions) {
            int block = w.open(2);
            for (Extension e : extensions) e.encode(w);
            w.close(block);
        }

        /** The body of the first extension of {@code type}, or null. */
        static byte[] find(List<Extension> extensions, int type) {
            for (Extension e : extensions) {
                if (e.type == type) return e.data;
            }
            return null;
        }
    }

    /** ClientHello (RFC 8446 section 4.1.2). */
    record ClientHello(int legacyVersion, byte[] random, byte[] sessionId, int[] cipherSuites,
            byte[] compressionMethods, List<Extension> extensions) implements HandshakeMessage {

        @Override
        public int type() {
            return HandshakeType.CLIENT_HELLO;
        }

        @Override
        public void encodeBody(Writer w) {
            w.u16(legacyVersion).bytes(random).vector8(sessionId);
            int suites = w.open(2);
            for (int s : cipherSuites) w.u16(s);
            w.close(suites);
            w.vector8(compressionMethods);
            Extension.encodeList(w, extensions);
        }

        static ClientHello decode(Reader r) throws QuicException {
            int version = r.u16("ClientHello version");
            byte[] random = r.bytes(32, "ClientHello random");
            byte[] sessionId = r.vector8(0, "legacy_session_id");
            if (sessionId.length > 32) throw TlsAlert.decodeError("legacy_session_id longer than 32 bytes");
            int[] suites = r.u16List16(1, "cipher_suites");
            byte[] compression = r.vector8(1, "legacy_compression_methods");
            List<Extension> extensions = Extension.decodeList(r, true);
            return new ClientHello(version, random, sessionId, suites, compression, extensions);
        }

        ClientHello withExtensions(List<Extension> replacement) {
            return new ClientHello(legacyVersion, random, sessionId, cipherSuites, compressionMethods, replacement);
        }
    }

    /** ServerHello, which is a HelloRetryRequest when its random is the special value (RFC 8446 section 4.1.3). */
    record ServerHello(int legacyVersion, byte[] random, byte[] sessionId, int cipherSuite,
            int compressionMethod, List<Extension> extensions) implements HandshakeMessage {

        @Override
        public int type() {
            return HandshakeType.SERVER_HELLO;
        }

        boolean isHelloRetryRequest() {
            return Arrays.equals(random, HELLO_RETRY_REQUEST_RANDOM);
        }

        @Override
        public void encodeBody(Writer w) {
            w.u16(legacyVersion).bytes(random).vector8(sessionId).u16(cipherSuite).u8(compressionMethod);
            Extension.encodeList(w, extensions);
        }

        static ServerHello decode(Reader r) throws QuicException {
            int version = r.u16("ServerHello version");
            byte[] random = r.bytes(32, "ServerHello random");
            byte[] sessionId = r.vector8(0, "legacy_session_id_echo");
            if (sessionId.length > 32) throw TlsAlert.decodeError("legacy_session_id_echo longer than 32 bytes");
            int suite = r.u16("cipher_suite");
            int compression = r.u8("legacy_compression_method");
            List<Extension> extensions = Extension.decodeList(r, true);
            return new ServerHello(version, random, sessionId, suite, compression, extensions);
        }

        ServerHello withExtensions(List<Extension> replacement) {
            return new ServerHello(legacyVersion, random, sessionId, cipherSuite, compressionMethod, replacement);
        }
    }

    /** EncryptedExtensions (RFC 8446 section 4.3.1). */
    record EncryptedExtensions(List<Extension> extensions) implements HandshakeMessage {

        @Override
        public int type() {
            return HandshakeType.ENCRYPTED_EXTENSIONS;
        }

        @Override
        public void encodeBody(Writer w) {
            Extension.encodeList(w, extensions);
        }
    }

    /** One X.509 certificate in a Certificate message, with its extensions. */
    record CertificateEntry(byte[] certificate, List<Extension> extensions) {}

    /** Certificate (RFC 8446 section 4.4.2), for X.509 certificates. */
    record CertificateMessage(byte[] context, List<CertificateEntry> entries) implements HandshakeMessage {

        @Override
        public int type() {
            return HandshakeType.CERTIFICATE;
        }

        @Override
        public void encodeBody(Writer w) {
            w.vector8(context);
            int list = w.open(3);
            for (CertificateEntry entry : entries) {
                w.vector24(entry.certificate());
                Extension.encodeList(w, entry.extensions());
            }
            w.close(list);
        }

        static CertificateMessage decode(Reader r) throws QuicException {
            byte[] context = r.vector8(0, "certificate_request_context");
            Reader list = r.sub24("certificate_list");
            List<CertificateEntry> entries = new ArrayList<>();
            while (list.hasRemaining()) {
                byte[] cert = list.vector24(1, "cert_data");
                entries.add(new CertificateEntry(cert, Extension.decodeList(list, false)));
            }
            return new CertificateMessage(context, entries);
        }
    }

    /** CertificateRequest (RFC 8446 section 4.3.2). */
    record CertificateRequest(byte[] context, List<Extension> extensions) implements HandshakeMessage {

        @Override
        public int type() {
            return HandshakeType.CERTIFICATE_REQUEST;
        }

        @Override
        public void encodeBody(Writer w) {
            w.vector8(context);
            Extension.encodeList(w, extensions);
        }

        static CertificateRequest decode(Reader r) throws QuicException {
            byte[] context = r.vector8(0, "certificate_request_context");
            return new CertificateRequest(context, Extension.decodeList(r, false));
        }
    }

    /** CertificateVerify (RFC 8446 section 4.4.3). */
    record CertificateVerify(int scheme, byte[] signature) implements HandshakeMessage {

        @Override
        public int type() {
            return HandshakeType.CERTIFICATE_VERIFY;
        }

        @Override
        public void encodeBody(Writer w) {
            w.u16(scheme).vector16(signature);
        }
    }

    /** Finished (RFC 8446 section 4.4.4). */
    record Finished(byte[] verifyData) implements HandshakeMessage {

        @Override
        public int type() {
            return HandshakeType.FINISHED;
        }

        @Override
        public void encodeBody(Writer w) {
            w.bytes(verifyData);
        }
    }

    /** NewSessionTicket (RFC 8446 section 4.6.1): decoded so it can be validated, then ignored. */
    record NewSessionTicket(long lifetime, long ageAdd, byte[] nonce, byte[] ticket, List<Extension> extensions)
            implements HandshakeMessage {

        @Override
        public int type() {
            return HandshakeType.NEW_SESSION_TICKET;
        }

        @Override
        public void encodeBody(Writer w) {
            w.u32(lifetime).u32(ageAdd).vector8(nonce).vector16(ticket);
            Extension.encodeList(w, extensions);
        }

        static NewSessionTicket decode(Reader r) throws QuicException {
            long lifetime = r.u32("ticket_lifetime");
            long ageAdd = r.u32("ticket_age_add");
            byte[] nonce = r.vector8(0, "ticket_nonce");
            byte[] ticket = r.vector16(1, "ticket");
            return new NewSessionTicket(lifetime, ageAdd, nonce, ticket, Extension.decodeList(r, false));
        }
    }

    /** KeyUpdate (RFC 8446 section 4.6.3), which QUIC forbids (RFC 9001 section 6). */
    record KeyUpdate(int requestUpdate) implements HandshakeMessage {

        @Override
        public int type() {
            return HandshakeType.KEY_UPDATE;
        }

        @Override
        public void encodeBody(Writer w) {
            w.u8(requestUpdate);
        }
    }

    /** Any other handshake type, including EndOfEarlyData, which QUIC never sends. */
    record Unknown(int type, byte[] body) implements HandshakeMessage {

        @Override
        public void encodeBody(Writer w) {
            w.bytes(body);
        }
    }
}
