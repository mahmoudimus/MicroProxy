package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateEntry;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateMessage;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateVerify;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.EncryptedExtensions;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ServerHello;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/** Malformed, inconsistent or unsolicited handshake messages, and the alert each one gets. */
class ProtocolValidationTest {

    // --- helpers ---

    static List<Extension> without(List<Extension> extensions, int type) {
        List<Extension> out = new ArrayList<>(extensions);
        out.removeIf(e -> e.type() == type);
        return out;
    }

    static List<Extension> with(List<Extension> extensions, Extension extra) {
        List<Extension> out = new ArrayList<>(extensions);
        out.add(extra);
        return out;
    }

    static List<Extension> replace(List<Extension> extensions, int type, byte[] data) {
        List<Extension> out = new ArrayList<>(extensions);
        out.replaceAll(e -> e.type() == type ? new Extension(type, data) : e);
        return out;
    }

    static List<Extensions.KeyShare> shares(byte[] data) {
        try {
            return Extensions.decodeKeyShareClient(data);
        } catch (QuicException e) {
            throw new AssertionError(e);
        }
    }

    /** Rewrites the extensions of the ClientHello in a client's Initial flight. */
    static byte[] clientHello(byte[] flight, UnaryOperator<List<Extension>> change) {
        ClientHello hello = (ClientHello) Handshakes.decode(flight);
        return hello.withExtensions(change.apply(hello.extensions())).encode();
    }

    static TlsSession newClient(TlsConfig.Builder config) {
        return TlsSession.client(config.build(), Handshakes.CLIENT_PARAMS);
    }

    static TlsSession newServer() {
        return TlsSession.server(HandshakeTest.server().build(), Handshakes.SERVER_PARAMS);
    }

    static byte[] firstClientHello(TlsConfig.Builder config) {
        return newClient(config).writeHandshake(EncryptionLevel.INITIAL);
    }

    static byte[] firstClientHello() {
        return firstClientHello(HandshakeTest.client());
    }

    static QuicException rejects(TlsSession session, EncryptionLevel level, byte[] bytes) {
        return assertThrows(QuicException.class, () -> session.readHandshake(level, ByteBuffer.wrap(bytes)));
    }

    static void assertAlert(int alert, QuicException e) {
        assertEquals(TlsAlert.name(alert), TlsAlert.name(Handshakes.alert(e)), e.getMessage());
    }

    static void serverRejects(int alert, byte[] clientHello) {
        assertAlert(alert, rejects(newServer(), EncryptionLevel.INITIAL, clientHello));
    }

    static void serverRejectsExtensions(int alert, UnaryOperator<List<Extension>> change) {
        serverRejects(alert, clientHello(firstClientHello(), change));
    }

    /** A client whose ClientHello was answered, and the server's ServerHello. */
    record Exchange(TlsSession client, TlsSession server, ServerHello serverHello) {}

    static Exchange exchange(TlsConfig.Builder clientConfig) throws QuicException {
        TlsSession client = newClient(clientConfig);
        TlsSession server = newServer();
        server.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(client.writeHandshake(EncryptionLevel.INITIAL)));
        return new Exchange(client, server, (ServerHello) Handshakes.decode(server.writeHandshake(EncryptionLevel.INITIAL)));
    }

    static void clientRejectsServerHello(int alert, UnaryOperator<ServerHello> change) throws QuicException {
        Exchange x = exchange(HandshakeTest.client());
        assertAlert(alert, rejects(x.client(), EncryptionLevel.INITIAL, change.apply(x.serverHello()).encode()));
    }

    static ServerHello hello(ServerHello sh, int version, byte[] sessionId, int suite, int compression) {
        return new ServerHello(version, sh.random(), sessionId, suite, compression, sh.extensions());
    }

    static ServerHello retry(int suite, List<Extension> extensions) {
        return new ServerHello(HandshakeMessage.LEGACY_VERSION, HandshakeMessage.HELLO_RETRY_REQUEST_RANDOM,
                new byte[0], suite, 0, extensions);
    }

    static Extension version13() {
        return new Extension(ExtensionType.SUPPORTED_VERSIONS, Extensions.encodeSupportedVersionServer(0x0304));
    }

    static Extension retryGroup(NamedGroup group) {
        return new Extension(ExtensionType.KEY_SHARE, Extensions.encodeKeyShareRetry(group.code()));
    }

    /** Rewrites one message of the server's Handshake flight. */
    static Handshakes.Tamper serverMessage(int type, UnaryOperator<HandshakeMessage> change) {
        return (fromServer, level, bytes) -> !fromServer || level != EncryptionLevel.HANDSHAKE
                ? bytes
                : Handshakes.rewrite(bytes, type, m -> change.apply(Handshakes.decode(m)).encode());
    }

    static Handshakes.Tamper encryptedExtensions(UnaryOperator<List<Extension>> change) {
        return serverMessage(HandshakeType.ENCRYPTED_EXTENSIONS,
                m -> new EncryptedExtensions(change.apply(((EncryptedExtensions) m).extensions())));
    }

    // --- the server checks the ClientHello ---

    @Test
    void duplicateExtension() {
        serverRejectsExtensions(TlsAlert.ILLEGAL_PARAMETER,
                exts -> with(exts, new Extension(ExtensionType.ALPN, Extension.find(exts, ExtensionType.ALPN))));
    }

    @Test
    void legacySessionIdIsAProtocolViolation() {
        ClientHello hello = (ClientHello) Handshakes.decode(firstClientHello());
        ClientHello withId = new ClientHello(hello.legacyVersion(), hello.random(), new byte[32], hello.cipherSuites(),
                hello.compressionMethods(), hello.extensions());
        QuicException e = rejects(newServer(), EncryptionLevel.INITIAL, withId.encode());
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());
    }

    @Test
    void tls13Required() {
        serverRejectsExtensions(TlsAlert.PROTOCOL_VERSION, exts -> without(exts, ExtensionType.SUPPORTED_VERSIONS));
        serverRejectsExtensions(TlsAlert.PROTOCOL_VERSION, exts -> replace(exts, ExtensionType.SUPPORTED_VERSIONS,
                Extensions.encodeSupportedVersionsClient(0x0303, 0x0302)));
    }

    @Test
    void legacyCompression() {
        ClientHello hello = (ClientHello) Handshakes.decode(firstClientHello());
        for (byte[] methods : List.of(new byte[] {0, 1}, new byte[] {1})) {
            serverRejects(TlsAlert.ILLEGAL_PARAMETER, new ClientHello(hello.legacyVersion(), hello.random(),
                    hello.sessionId(), hello.cipherSuites(), methods, hello.extensions()).encode());
        }
    }

    @Test
    void requiredExtensions() {
        for (int type : new int[] {ExtensionType.SIGNATURE_ALGORITHMS, ExtensionType.KEY_SHARE,
                ExtensionType.SUPPORTED_GROUPS, ExtensionType.QUIC_TRANSPORT_PARAMETERS}) {
            serverRejectsExtensions(TlsAlert.MISSING_EXTENSION, exts -> without(exts, type));
        }
    }

    @Test
    void keyShareGroupMustBeSupported() {
        serverRejectsExtensions(TlsAlert.ILLEGAL_PARAMETER, exts -> replace(exts, ExtensionType.SUPPORTED_GROUPS,
                Extensions.encodeU16List(new int[] {NamedGroup.SECP256R1.code()})));
    }

    @Test
    void duplicateKeyShares() {
        serverRejectsExtensions(TlsAlert.ILLEGAL_PARAMETER, exts -> {
            List<Extensions.KeyShare> shares =
                    shares(Extension.find(exts, ExtensionType.KEY_SHARE));
            return replace(exts, ExtensionType.KEY_SHARE,
                    Extensions.encodeKeyShareClient(List.of(shares.get(0), shares.get(0))));
        });
    }

    @Test
    void invalidKeyShares() {
        // The wrong length, an all-zero (small order) X25519 point, and a P-256 point off the curve.
        serverRejectsExtensions(TlsAlert.ILLEGAL_PARAMETER, exts -> replace(exts, ExtensionType.KEY_SHARE,
                Extensions.encodeKeyShareClient(List.of(new Extensions.KeyShare(NamedGroup.X25519.code(), new byte[31])))));
        serverRejectsExtensions(TlsAlert.ILLEGAL_PARAMETER, exts -> replace(exts, ExtensionType.KEY_SHARE,
                Extensions.encodeKeyShareClient(List.of(new Extensions.KeyShare(NamedGroup.X25519.code(), new byte[32])))));
        serverRejects(TlsAlert.ILLEGAL_PARAMETER, clientHello(
                firstClientHello(HandshakeTest.client().groups(NamedGroup.SECP256R1)), exts -> {
                    Extensions.KeyShare share = shares(
                            Extension.find(exts, ExtensionType.KEY_SHARE)).get(0);
                    byte[] point = share.keyExchange().clone();
                    point[40] ^= 1;
                    return replace(exts, ExtensionType.KEY_SHARE, Extensions.encodeKeyShareClient(
                            List.of(new Extensions.KeyShare(share.group(), point))));
                }));
    }

    @Test
    void preSharedKeyRules() {
        Extension psk = new Extension(ExtensionType.PRE_SHARED_KEY, new byte[] {0, 0});
        Extension modes = new Extension(ExtensionType.PSK_KEY_EXCHANGE_MODES, new byte[] {1, 1});
        serverRejectsExtensions(TlsAlert.ILLEGAL_PARAMETER, exts -> {
            List<Extension> out = new ArrayList<>(List.of(psk, modes));
            out.addAll(exts);
            return out;
        });
        serverRejectsExtensions(TlsAlert.MISSING_EXTENSION, exts -> with(exts, psk));
        serverRejectsExtensions(TlsAlert.DECODE_ERROR, exts -> with(exts,
                new Extension(ExtensionType.PSK_KEY_EXCHANGE_MODES, new byte[] {0})));
    }

    @Test
    void pskKeyExchangeModesAreParsedAndIgnored() throws Exception {
        TlsSession server = newServer();
        server.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(clientHello(firstClientHello(), exts ->
                with(exts, new Extension(ExtensionType.PSK_KEY_EXCHANGE_MODES, new byte[] {1, 1})))));
        assertEquals(EncryptionLevel.HANDSHAKE, server.nextSecrets().level());
    }

    @Test
    void malformedExtensionBodies() {
        serverRejectsExtensions(TlsAlert.DECODE_ERROR, exts -> replace(exts, ExtensionType.SUPPORTED_GROUPS,
                new byte[] {0, 3, 0, 0x1d, 0}));
        serverRejectsExtensions(TlsAlert.DECODE_ERROR, exts -> replace(exts, ExtensionType.SERVER_NAME,
                new byte[] {0, 5, 0, 0, 2, 'a'}));
        serverRejectsExtensions(TlsAlert.DECODE_ERROR, exts -> replace(exts, ExtensionType.ALPN, new byte[] {0, 1, 0}));
    }

    @Test
    void truncatedClientHello() {
        byte[] hello = firstClientHello();
        byte[] body = Arrays.copyOfRange(hello, 4, hello.length - 3);
        serverRejects(TlsAlert.DECODE_ERROR, new HandshakeMessage.Unknown(HandshakeType.CLIENT_HELLO, body).encode());
    }

    @Test
    void secondClientHelloMustFollowTheRetry() throws Exception {
        TlsConfig.Builder p256First = HandshakeTest.client().groups(NamedGroup.SECP256R1, NamedGroup.X25519);
        TlsSession client = newClient(p256First);
        TlsSession server = TlsSession.server(HandshakeTest.server().groups(NamedGroup.X25519).build(),
                Handshakes.SERVER_PARAMS);
        byte[] first = client.writeHandshake(EncryptionLevel.INITIAL);
        server.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(first));
        byte[] retry = server.writeHandshake(EncryptionLevel.INITIAL);
        assertEquals(true, ((ServerHello) Handshakes.decode(retry)).isHelloRetryRequest());
        // Repeating the first ClientHello ignores the request for an X25519 share.
        assertAlert(TlsAlert.ILLEGAL_PARAMETER, rejects(server, EncryptionLevel.INITIAL, first));

        // A second ClientHello for another server name, or with early data, is refused too.
        for (UnaryOperator<List<Extension>> change : List.<UnaryOperator<List<Extension>>>of(
                exts -> replace(exts, ExtensionType.SERVER_NAME, Extensions.encodeServerName("other.test")),
                exts -> with(exts, new Extension(ExtensionType.EARLY_DATA, new byte[0])))) {
            TlsSession c = newClient(p256First);
            TlsSession s = TlsSession.server(HandshakeTest.server().groups(NamedGroup.X25519).build(),
                    Handshakes.SERVER_PARAMS);
            s.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(c.writeHandshake(EncryptionLevel.INITIAL)));
            c.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(s.writeHandshake(EncryptionLevel.INITIAL)));
            byte[] second = clientHello(c.writeHandshake(EncryptionLevel.INITIAL), change);
            assertAlert(TlsAlert.ILLEGAL_PARAMETER, rejects(s, EncryptionLevel.INITIAL, second));
        }
    }

    // --- the client checks the ServerHello ---

    @Test
    void serverHelloUnsolicitedExtension() throws Exception {
        clientRejectsServerHello(TlsAlert.UNSUPPORTED_EXTENSION,
                sh -> sh.withExtensions(with(sh.extensions(), new Extension(0xff00, new byte[0]))));
        clientRejectsServerHello(TlsAlert.UNSUPPORTED_EXTENSION,
                sh -> sh.withExtensions(with(sh.extensions(), new Extension(ExtensionType.PRE_SHARED_KEY, new byte[2]))));
    }

    @Test
    void serverHelloExtensionNotAllowedThere() throws Exception {
        clientRejectsServerHello(TlsAlert.ILLEGAL_PARAMETER, sh -> sh.withExtensions(with(sh.extensions(),
                new Extension(ExtensionType.ALPN, Extensions.encodeAlpn(List.of(new byte[] {'h', '3'}))))));
    }

    @Test
    void serverHelloDuplicateExtension() throws Exception {
        clientRejectsServerHello(TlsAlert.ILLEGAL_PARAMETER,
                sh -> sh.withExtensions(with(sh.extensions(), version13())));
    }

    @Test
    void serverHelloFields() throws Exception {
        clientRejectsServerHello(TlsAlert.ILLEGAL_PARAMETER,
                sh -> hello(sh, sh.legacyVersion(), new byte[] {1}, sh.cipherSuite(), 0));
        clientRejectsServerHello(TlsAlert.ILLEGAL_PARAMETER,
                sh -> hello(sh, sh.legacyVersion(), sh.sessionId(), 0x1304, 0));
        clientRejectsServerHello(TlsAlert.ILLEGAL_PARAMETER,
                sh -> hello(sh, sh.legacyVersion(), sh.sessionId(), sh.cipherSuite(), 1));
        clientRejectsServerHello(TlsAlert.ILLEGAL_PARAMETER,
                sh -> hello(sh, 0x0304, sh.sessionId(), sh.cipherSuite(), 0));
    }

    @Test
    void serverHelloCipherSuiteNotOffered() throws Exception {
        Exchange x = exchange(HandshakeTest.client().cipherSuites(io.github.mahmoudimus.quic.CipherSuite.TLS_AES_128_GCM_SHA256));
        ServerHello sh = hello(x.serverHello(), 0x0303, new byte[0], 0x1302, 0);
        assertAlert(TlsAlert.ILLEGAL_PARAMETER, rejects(x.client(), EncryptionLevel.INITIAL, sh.encode()));
    }

    @Test
    void serverHelloVersion() throws Exception {
        clientRejectsServerHello(TlsAlert.PROTOCOL_VERSION,
                sh -> sh.withExtensions(without(sh.extensions(), ExtensionType.SUPPORTED_VERSIONS)));
        clientRejectsServerHello(TlsAlert.ILLEGAL_PARAMETER, sh -> sh.withExtensions(replace(sh.extensions(),
                ExtensionType.SUPPORTED_VERSIONS, Extensions.encodeSupportedVersionServer(0x0303))));
    }

    @Test
    void serverHelloKeyShare() throws Exception {
        clientRejectsServerHello(TlsAlert.MISSING_EXTENSION,
                sh -> sh.withExtensions(without(sh.extensions(), ExtensionType.KEY_SHARE)));
        clientRejectsServerHello(TlsAlert.ILLEGAL_PARAMETER, sh -> sh.withExtensions(replace(sh.extensions(),
                ExtensionType.KEY_SHARE, Extensions.encodeKeyShareServer(
                        new Extensions.KeyShare(NamedGroup.SECP256R1.code(), new byte[65])))));
        clientRejectsServerHello(TlsAlert.ILLEGAL_PARAMETER, sh -> sh.withExtensions(replace(sh.extensions(),
                ExtensionType.KEY_SHARE, Extensions.encodeKeyShareServer(
                        new Extensions.KeyShare(NamedGroup.X25519.code(), new byte[32])))));
    }

    @Test
    void unexpectedMessageInsteadOfServerHello() throws Exception {
        TlsSession client = newClient(HandshakeTest.client());
        assertAlert(TlsAlert.UNEXPECTED_MESSAGE, rejects(client, EncryptionLevel.INITIAL,
                new EncryptedExtensions(List.of()).encode()));
    }

    // --- HelloRetryRequest ---

    @Test
    void retryRequests() throws Exception {
        int suite = 0x1301;
        List<ServerHello> bad = List.of(
                retry(suite, List.of(version13(), retryGroup(NamedGroup.X25519))), // the group already offered
                retry(suite, List.of(version13(), new Extension(ExtensionType.KEY_SHARE,
                        Extensions.encodeKeyShareRetry(0x0019)))), // a group never offered
                retry(suite, List.of(version13())), // no change
                retry(suite, List.of(version13(), new Extension(ExtensionType.COOKIE, Extensions.encodeCookie(new byte[0])))),
                retry(0x1304, List.of(version13(), retryGroup(NamedGroup.SECP256R1))),
                retry(suite, List.of(retryGroup(NamedGroup.SECP256R1), new Extension(ExtensionType.SUPPORTED_VERSIONS,
                        Extensions.encodeSupportedVersionServer(0x0303)))));
        for (ServerHello hrr : bad) {
            TlsSession client = newClient(HandshakeTest.client());
            assertAlert(TlsAlert.ILLEGAL_PARAMETER, rejects(client, EncryptionLevel.INITIAL, hrr.encode()));
        }
        TlsSession client = newClient(HandshakeTest.client());
        assertAlert(TlsAlert.UNSUPPORTED_EXTENSION, rejects(client, EncryptionLevel.INITIAL, retry(suite,
                List.of(version13(), retryGroup(NamedGroup.SECP256R1), new Extension(0xff01, new byte[0]))).encode()));
    }

    @Test
    void retryCookieIsEchoedAndOnlyOneRetryIsAllowed() throws Exception {
        TlsSession client = newClient(HandshakeTest.client());
        byte[] first = client.writeHandshake(EncryptionLevel.INITIAL);
        byte[] cookie = {9, 8, 7};
        ServerHello hrr = retry(0x1301, List.of(version13(), retryGroup(NamedGroup.SECP256R1),
                new Extension(ExtensionType.COOKIE, Extensions.encodeCookie(cookie))));
        client.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(hrr.encode()));
        ClientHello second = (ClientHello) Handshakes.decode(client.writeHandshake(EncryptionLevel.INITIAL));
        ClientHello original = (ClientHello) Handshakes.decode(first);
        assertArrayEquals(original.random(), second.random());
        assertArrayEquals(cookie, Extensions.decodeCookie(Extension.find(second.extensions(), ExtensionType.COOKIE)));
        List<Extensions.KeyShare> shares =
                Extensions.decodeKeyShareClient(Extension.find(second.extensions(), ExtensionType.KEY_SHARE));
        assertEquals(1, shares.size());
        assertEquals(NamedGroup.SECP256R1.code(), shares.get(0).group());
        assertAlert(TlsAlert.UNEXPECTED_MESSAGE, rejects(client, EncryptionLevel.INITIAL, hrr.encode()));
    }

    @Test
    void serverHelloMustKeepTheRetryCipherSuite() throws Exception {
        TlsSession client = newClient(HandshakeTest.client());
        client.writeHandshake(EncryptionLevel.INITIAL);
        client.readHandshake(EncryptionLevel.INITIAL,
                ByteBuffer.wrap(retry(0x1302, List.of(version13(), retryGroup(NamedGroup.SECP256R1))).encode()));
        // Answer the second ClientHello from a real server that picks TLS_AES_128_GCM_SHA256.
        TlsSession server = newServer();
        server.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(client.writeHandshake(EncryptionLevel.INITIAL)));
        assertAlert(TlsAlert.ILLEGAL_PARAMETER,
                rejects(client, EncryptionLevel.INITIAL, server.writeHandshake(EncryptionLevel.INITIAL)));
    }

    // --- EncryptedExtensions, Certificate, CertificateVerify ---

    @Test
    void encryptedExtensionsChecks() {
        HandshakeTest.fails(TlsAlert.UNSUPPORTED_EXTENSION, HandshakeTest.client(), HandshakeTest.server(),
                encryptedExtensions(exts -> with(exts, new Extension(ExtensionType.EARLY_DATA, new byte[0]))));
        HandshakeTest.fails(TlsAlert.ILLEGAL_PARAMETER, HandshakeTest.client(), HandshakeTest.server(),
                encryptedExtensions(exts -> with(exts, new Extension(ExtensionType.KEY_SHARE, new byte[0]))));
        HandshakeTest.fails(TlsAlert.ILLEGAL_PARAMETER, HandshakeTest.client(), HandshakeTest.server(),
                encryptedExtensions(exts -> with(exts, exts.get(exts.size() - 1))));
        HandshakeTest.fails(TlsAlert.ILLEGAL_PARAMETER, HandshakeTest.client(), HandshakeTest.server(),
                encryptedExtensions(exts -> replace(exts, ExtensionType.ALPN,
                        Extensions.encodeAlpn(List.of(new byte[] {'h', '2'})))));
        HandshakeTest.fails(TlsAlert.DECODE_ERROR, HandshakeTest.client(), HandshakeTest.server(),
                encryptedExtensions(exts -> replace(exts, ExtensionType.SERVER_NAME, new byte[] {0})));
    }

    @Test
    void certificateChecks() {
        HandshakeTest.fails(TlsAlert.DECODE_ERROR, HandshakeTest.client(), HandshakeTest.server(),
                serverMessage(HandshakeType.CERTIFICATE, m -> new CertificateMessage(new byte[0], List.of())));
        HandshakeTest.fails(TlsAlert.BAD_CERTIFICATE, HandshakeTest.client(), HandshakeTest.server(),
                serverMessage(HandshakeType.CERTIFICATE, m -> new CertificateMessage(new byte[0],
                        List.of(new CertificateEntry(new byte[] {0x30, 0x03, 1, 2, 3}, List.of())))));
        HandshakeTest.fails(TlsAlert.ILLEGAL_PARAMETER, HandshakeTest.client(), HandshakeTest.server(),
                serverMessage(HandshakeType.CERTIFICATE, m -> new CertificateMessage(new byte[] {1},
                        ((CertificateMessage) m).entries())));
        HandshakeTest.fails(TlsAlert.UNSUPPORTED_EXTENSION, HandshakeTest.client(), HandshakeTest.server(),
                serverMessage(HandshakeType.CERTIFICATE, m -> {
                    CertificateMessage cert = (CertificateMessage) m;
                    CertificateEntry leaf = cert.entries().get(0);
                    return new CertificateMessage(cert.context(), List.of(new CertificateEntry(leaf.certificate(),
                            List.of(new Extension(ExtensionType.STATUS_REQUEST, new byte[0])))));
                }));
    }

    @Test
    void certificateVerifySchemeChecks() {
        // rsa_pkcs1 is for certificates only; a P-384 scheme does not fit a P-256 key; 0x0000 is unknown.
        for (int scheme : new int[] {SignatureScheme.RSA_PKCS1_SHA256.code(),
                SignatureScheme.ECDSA_SECP384R1_SHA384.code(), 0}) {
            HandshakeTest.fails(TlsAlert.ILLEGAL_PARAMETER, HandshakeTest.client(), HandshakeTest.server(),
                    serverMessage(HandshakeType.CERTIFICATE_VERIFY,
                            m -> new CertificateVerify(scheme, ((CertificateVerify) m).signature())));
        }
        // A scheme the client did not offer for CertificateVerify.
        HandshakeTest.fails(TlsAlert.ILLEGAL_PARAMETER,
                HandshakeTest.client().signatureSchemes(SignatureScheme.ECDSA_SECP256R1_SHA256),
                HandshakeTest.server(),
                serverMessage(HandshakeType.CERTIFICATE_VERIFY, m -> new CertificateVerify(
                        SignatureScheme.ED25519.code(), new byte[64])));
    }
}
