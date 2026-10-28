package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.EncryptedExtensions;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.KeyUpdate;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.NewSessionTicket;
import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** Client and server sessions talking to each other in memory: negotiation, retries and failures. */
class HandshakeTest {

    static final String HOST = "quic.test";

    static TlsConfig.Builder client() {
        return TlsConfig.builder().serverName(HOST).alpnProtocols("h3").trustManager(TestCerts.CA.trustManager());
    }

    static TlsConfig.Builder server() {
        return TlsConfig.builder().certificate(TestCerts.CA.issue(KeyType.P256, HOST)).alpnProtocols("h3");
    }

    static Handshakes run(TlsConfig.Builder client, TlsConfig.Builder server) throws QuicException {
        return Handshakes.run(client.build(), server.build());
    }

    static Handshakes run(TlsConfig.Builder client, TlsConfig.Builder server, Handshakes.Tamper tamper)
            throws QuicException {
        return Handshakes.run(client.build(), server.build(), new Random(5), tamper);
    }

    /** Runs a handshake that must fail with {@code alert}; returns the sessions for inspection. */
    static Handshakes fails(int alert, TlsConfig.Builder client, TlsConfig.Builder server, Handshakes.Tamper tamper) {
        Handshakes h = new Handshakes(TlsSession.client(client.build(), Handshakes.CLIENT_PARAMS),
                TlsSession.server(server.build(), Handshakes.SERVER_PARAMS), new Random(9), tamper);
        QuicException e = assertThrows(QuicException.class, h::complete);
        assertEquals(TlsAlert.name(alert), TlsAlert.name(Handshakes.alert(e)), e.getMessage());
        assertFalse(h.client.isHandshakeComplete() && h.server.isHandshakeComplete());
        return h;
    }

    static Handshakes fails(int alert, TlsConfig.Builder client, TlsConfig.Builder server) {
        return fails(alert, client, server, Handshakes.NONE);
    }

    @Test
    void defaults() throws Exception {
        Handshakes h = run(client(), server());
        h.assertAgreement();
        assertEquals(CipherSuite.TLS_AES_128_GCM_SHA256, h.client.cipherSuite());
        assertEquals(NamedGroup.X25519, h.client.negotiatedGroup());
        assertEquals(SignatureScheme.ECDSA_SECP256R1_SHA256, h.client.peerSignatureScheme());
        assertEquals(HOST, h.client.serverName());
        assertEquals(HOST, h.server.serverName());
        assertTrue(h.server.peerCertificates().isEmpty());
        assertNull(h.server.peerSignatureScheme());
        assertTrue(h.client.isClient());
        assertFalse(h.server.isClient());
        assertFalse(h.client.isHandshaking());
    }

    @Test
    void randomFragmentationManySeeds() throws Exception {
        for (int seed = 0; seed < 40; seed++) {
            Handshakes h = Handshakes.run(client().groups(NamedGroup.SECP256R1, NamedGroup.X25519).build(),
                    server().groups(NamedGroup.X25519).build(), new Random(seed), Handshakes.NONE);
            h.assertAgreement();
            assertTrue(h.client.usedHelloRetryRequest());
        }
    }

    @Test
    void secretsAppearInOrder() throws Exception {
        TlsSession client = TlsSession.client(client().build(), Handshakes.CLIENT_PARAMS);
        TlsSession server = TlsSession.server(server().build(), Handshakes.SERVER_PARAMS);
        assertNull(client.nextSecrets());
        assertTrue(client.hasHandshakeData(EncryptionLevel.INITIAL));
        server.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(client.writeHandshake(EncryptionLevel.INITIAL)));
        assertEquals(EncryptionLevel.HANDSHAKE, server.nextSecrets().level());
        assertEquals(EncryptionLevel.ONE_RTT, server.nextSecrets().level());
        assertNull(server.nextSecrets());
        assertFalse(server.isHandshakeComplete(), "server waits for the client's Finished");
        assertArrayEquals(Handshakes.CLIENT_PARAMS, server.peerTransportParameters());

        client.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(server.writeHandshake(EncryptionLevel.INITIAL)));
        assertEquals(EncryptionLevel.HANDSHAKE, client.nextSecrets().level());
        assertNull(client.nextSecrets());
        assertNull(client.peerTransportParameters());
        assertThrows(IllegalStateException.class, client::nextOneRttSecrets);
        client.readHandshake(EncryptionLevel.HANDSHAKE,
                ByteBuffer.wrap(server.writeHandshake(EncryptionLevel.HANDSHAKE)));
        assertEquals(EncryptionLevel.ONE_RTT, client.nextSecrets().level());
        assertTrue(client.isHandshakeComplete());
        assertFalse(server.hasHandshakeData(EncryptionLevel.HANDSHAKE));

        server.readHandshake(EncryptionLevel.HANDSHAKE,
                ByteBuffer.wrap(client.writeHandshake(EncryptionLevel.HANDSHAKE)));
        assertTrue(server.isHandshakeComplete());
        assertEquals(0, client.writeHandshake(EncryptionLevel.ONE_RTT).length);
    }

    // --- HelloRetryRequest ---

    @Test
    void helloRetryRequestWhenServerPrefersX25519() throws Exception {
        Handshakes h = run(client().groups(NamedGroup.SECP256R1, NamedGroup.X25519),
                server().groups(NamedGroup.X25519));
        h.assertAgreement();
        assertTrue(h.client.usedHelloRetryRequest());
        assertTrue(h.server.usedHelloRetryRequest());
        assertEquals(NamedGroup.X25519, h.client.negotiatedGroup());
    }

    @Test
    void helloRetryRequestWhenServerPrefersP256() throws Exception {
        Handshakes h = run(client().groups(NamedGroup.X25519, NamedGroup.SECP256R1),
                server().groups(NamedGroup.SECP256R1, NamedGroup.SECP384R1));
        h.assertAgreement();
        assertTrue(h.client.usedHelloRetryRequest());
        assertEquals(NamedGroup.SECP256R1, h.client.negotiatedGroup());
    }

    @Test
    void helloRetryRequestWithSha384Suite() throws Exception {
        Handshakes h = run(client().groups(NamedGroup.X25519, NamedGroup.SECP384R1)
                        .cipherSuites(CipherSuite.TLS_AES_256_GCM_SHA384),
                server().groups(NamedGroup.SECP384R1));
        h.assertAgreement();
        assertEquals(CipherSuite.TLS_AES_256_GCM_SHA384, h.client.cipherSuite());
        assertEquals(NamedGroup.SECP384R1, h.client.negotiatedGroup());
    }

    @Test
    void serverUsesAnOfferedShareInsteadOfRetrying() throws Exception {
        Handshakes h = run(client().groups(NamedGroup.SECP256R1, NamedGroup.X25519), server());
        h.assertAgreement();
        assertFalse(h.client.usedHelloRetryRequest());
        assertEquals(NamedGroup.SECP256R1, h.client.negotiatedGroup());
    }

    @Test
    void noCommonGroup() {
        fails(TlsAlert.HANDSHAKE_FAILURE, client().groups(NamedGroup.X25519), server().groups(NamedGroup.SECP384R1));
    }

    @Test
    void noCommonCipherSuite() {
        fails(TlsAlert.HANDSHAKE_FAILURE, client().cipherSuites(CipherSuite.TLS_CHACHA20_POLY1305_SHA256),
                server().cipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256));
    }

    @Test
    void serverCipherSuitePreference() throws Exception {
        Handshakes h = run(client(), server().cipherSuites(
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384));
        h.assertAgreement();
        assertEquals(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, h.client.cipherSuite());
    }

    @Test
    void noCommonSignatureScheme() {
        fails(TlsAlert.HANDSHAKE_FAILURE, client().signatureSchemes(SignatureScheme.ED25519), server());
    }

    // --- ALPN ---

    @Test
    void alpnServerPreference() throws Exception {
        Handshakes h = run(client().alpnProtocols("h3-29", "h3"), server().alpnProtocols("h3", "h3-29"));
        assertEquals("h3", h.client.negotiatedAlpn());
        assertEquals("h3", h.server.negotiatedAlpn());
    }

    @Test
    void alpnSelector() throws Exception {
        List<ClientHelloInfo> seen = new ArrayList<>();
        Handshakes h = run(client().alpnProtocols("h3", "hq-interop"), server().alpnProtocols().alpnSelector(info -> {
            seen.add(info);
            return info.alpnProtocols().get(1);
        }));
        h.assertAgreement();
        assertEquals("hq-interop", h.client.negotiatedAlpn());
        assertEquals(List.of("h3", "hq-interop"), seen.get(0).alpnProtocols());
        assertEquals(HOST, seen.get(0).serverName());
    }

    @Test
    void alpnMismatch() {
        fails(TlsAlert.NO_APPLICATION_PROTOCOL, client().alpnProtocols("h3"), server().alpnProtocols("hq-interop"));
    }

    @Test
    void alpnSelectorDeclines() {
        fails(TlsAlert.NO_APPLICATION_PROTOCOL, client(), server().alpnSelector(info -> null));
        fails(TlsAlert.NO_APPLICATION_PROTOCOL, client(), server().alpnSelector(info -> "not-offered"));
    }

    @Test
    void alpnIsRequired() {
        assertThrows(IllegalArgumentException.class,
                () -> TlsSession.client(TlsConfig.builder().serverName(HOST).build(), new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> TlsSession.server(
                TlsConfig.builder().certificate(TestCerts.CA.issue(KeyType.P256, HOST)).build(), new byte[0]));
        // A ClientHello without ALPN is refused by the server.
        Handshakes.Tamper dropAlpn = (fromServer, level, bytes) -> fromServer ? bytes
                : ProtocolValidationTest.clientHello(bytes, exts -> ProtocolValidationTest.without(exts, ExtensionType.ALPN));
        fails(TlsAlert.NO_APPLICATION_PROTOCOL, client(), server(), dropAlpn);
    }

    @Test
    void serverWithoutAlpnInEncryptedExtensions() {
        Handshakes.Tamper dropAlpn = (fromServer, level, bytes) -> !fromServer || level != EncryptionLevel.HANDSHAKE
                ? bytes
                : Handshakes.rewrite(bytes, HandshakeType.ENCRYPTED_EXTENSIONS, m -> new EncryptedExtensions(
                        ProtocolValidationTest.without(((EncryptedExtensions) Handshakes.decode(m)).extensions(),
                                ExtensionType.ALPN)).encode());
        fails(TlsAlert.NO_APPLICATION_PROTOCOL, client(), server(), dropAlpn);
    }

    // --- transport parameters ---

    @Test
    void clientWithoutTransportParameters() {
        Handshakes.Tamper drop = (fromServer, level, bytes) -> fromServer ? bytes
                : ProtocolValidationTest.clientHello(bytes,
                        exts -> ProtocolValidationTest.without(exts, ExtensionType.QUIC_TRANSPORT_PARAMETERS));
        fails(TlsAlert.MISSING_EXTENSION, client(), server(), drop);
    }

    @Test
    void serverWithoutTransportParameters() {
        Handshakes.Tamper drop = (fromServer, level, bytes) -> !fromServer || level != EncryptionLevel.HANDSHAKE
                ? bytes
                : Handshakes.rewrite(bytes, HandshakeType.ENCRYPTED_EXTENSIONS, m -> new EncryptedExtensions(
                        ProtocolValidationTest.without(((EncryptedExtensions) Handshakes.decode(m)).extensions(),
                                ExtensionType.QUIC_TRANSPORT_PARAMETERS)).encode());
        Handshakes h = fails(TlsAlert.MISSING_EXTENSION, client(), server(), drop);
        assertNull(h.client.peerTransportParameters());
    }

    @Test
    void emptyTransportParametersAreSent() throws Exception {
        TlsSession client = TlsSession.client(client().build(), new byte[0]);
        TlsSession server = TlsSession.server(server().build(), new byte[0]);
        Handshakes h = new Handshakes(client, server, new Random(3), Handshakes.NONE);
        h.complete();
        assertArrayEquals(new byte[0], client.peerTransportParameters());
        assertArrayEquals(new byte[0], server.peerTransportParameters());
    }

    // --- server names and certificates ---

    @Test
    void certificateSelectedByServerName() throws Exception {
        CertifiedKey a = TestCerts.CA.issue(KeyType.P256, "a.example");
        CertifiedKey b = TestCerts.CA.issue(KeyType.ED25519, "b.example");
        Map<String, CertifiedKey> keys = Map.of("a.example", a, "b.example", b);
        List<ClientHelloInfo> seen = new ArrayList<>();
        TlsConfig.Builder server = TlsConfig.builder().alpnProtocols("h3").certificateSelector(info -> {
            seen.add(info);
            return keys.get(info.serverName());
        });
        for (String name : List.of("a.example", "b.example")) {
            Handshakes h = run(client().serverName(name.toUpperCase()), server);
            h.assertAgreement();
            assertEquals(name, h.server.serverName());
            assertEquals(keys.get(name).chain().get(0), h.client.peerCertificates().get(0));
        }
        assertEquals("a.example", seen.get(0).serverName());
        assertTrue(seen.get(0).signatureSchemes().contains(SignatureScheme.ED25519));
        assertFalse(seen.get(0).signatureSchemes().contains(SignatureScheme.RSA_PKCS1_SHA256),
                "pkcs1 is only advertised for certificates");
        assertEquals(List.of(CipherSuite.values()), seen.get(0).cipherSuites());
        assertEquals(NamedGroup.X25519, seen.get(0).groups().get(0));
        fails(TlsAlert.UNRECOGNIZED_NAME, client().serverName("c.example"), server);
    }

    @Test
    void certificateSelectorFailure() {
        fails(TlsAlert.INTERNAL_ERROR, client(), TlsConfig.builder().alpnProtocols("h3").certificateSelector(info -> {
            throw new IllegalStateException("boom");
        }));
    }

    @Test
    void ipAddressServerName() throws Exception {
        Handshakes h = run(client().serverName("127.0.0.1"),
                TlsConfig.builder().certificate(TestCerts.CA.issue(KeyType.P256, "127.0.0.1")).alpnProtocols("h3"));
        h.assertAgreement();
        assertNull(h.server.serverName(), "no SNI for an IP address");
        fails(TlsAlert.BAD_CERTIFICATE, client().serverName("127.0.0.2"),
                TlsConfig.builder().certificate(TestCerts.CA.issue(KeyType.P256, "127.0.0.1")).alpnProtocols("h3"));
    }

    @Test
    void wildcardCertificate() throws Exception {
        TlsConfig.Builder server = TlsConfig.builder()
                .certificate(TestCerts.CA.issue(KeyType.P256, "*.wild.test")).alpnProtocols("h3");
        run(client().serverName("a.wild.test"), server).assertAgreement();
        fails(TlsAlert.BAD_CERTIFICATE, client().serverName("a.b.wild.test"), server);
        fails(TlsAlert.BAD_CERTIFICATE, client().serverName("wild.test"), server);
    }

    @Test
    void untrustedCertificate() {
        TlsConfig.Builder server = TlsConfig.builder()
                .certificate(TestCerts.OTHER_CA.issue(KeyType.P256, HOST)).alpnProtocols("h3");
        Handshakes h = fails(TlsAlert.UNKNOWN_CA, client(), server);
        assertTrue(h.client.peerCertificates().isEmpty());
        // The JDK's default trust store does not know the test CA either.
        fails(TlsAlert.UNKNOWN_CA, TlsConfig.builder().serverName(HOST).alpnProtocols("h3"), server());
    }

    @Test
    void trustAllCertificates() throws Exception {
        TlsConfig.Builder server = TlsConfig.builder()
                .certificate(TestCerts.OTHER_CA.issue(KeyType.RSA, "elsewhere.test")).alpnProtocols("h3");
        Handshakes h = run(TlsConfig.builder().alpnProtocols("h3").trustAllCertificates(true), server);
        h.assertAgreement();
        assertNull(h.client.serverName());
        assertNull(h.server.serverName());
    }

    @Test
    void hostnameMismatch() {
        fails(TlsAlert.BAD_CERTIFICATE, client().serverName("other.test"), server());
    }

    @Test
    void hostnameVerificationCanBeDisabled() throws Exception {
        run(client().serverName("other.test").verifyHostname(false), server()).assertAgreement();
        assertThrows(IllegalArgumentException.class, () -> TlsSession.client(client().serverName(null).build(), new byte[0]));
    }

    @Test
    void corruptedCertificateVerify() {
        Handshakes.Tamper corrupt = (fromServer, level, bytes) -> !fromServer || level != EncryptionLevel.HANDSHAKE
                ? bytes
                : Handshakes.rewrite(bytes, HandshakeType.CERTIFICATE_VERIFY, m -> {
                    byte[] out = m.clone();
                    out[out.length - 1] ^= 0x01;
                    return out;
                });
        fails(TlsAlert.DECRYPT_ERROR, client(), server(), corrupt);
        // Ed25519 and RSA-PSS signatures too.
        fails(TlsAlert.DECRYPT_ERROR, client(), TlsConfig.builder()
                .certificate(TestCerts.CA.issue(KeyType.ED25519, HOST)).alpnProtocols("h3"), corrupt);
        fails(TlsAlert.DECRYPT_ERROR, client(), TlsConfig.builder()
                .certificate(TestCerts.CA.issue(KeyType.RSA, HOST)).alpnProtocols("h3"), corrupt);
    }

    @Test
    void corruptedServerFinished() {
        Handshakes.Tamper corrupt = (fromServer, level, bytes) -> !fromServer || level != EncryptionLevel.HANDSHAKE
                ? bytes
                : Handshakes.rewrite(bytes, HandshakeType.FINISHED, m -> {
                    byte[] out = m.clone();
                    out[10] ^= 0x40;
                    return out;
                });
        Handshakes h = fails(TlsAlert.DECRYPT_ERROR, client(), server(), corrupt);
        for (io.github.mahmoudimus.quic.Secrets s; (s = h.client.nextSecrets()) != null; ) {
            assertEquals(EncryptionLevel.HANDSHAKE, s.level(), "no 1-RTT secrets");
        }
        assertFalse(h.clientSecrets.containsKey(EncryptionLevel.ONE_RTT), "no 1-RTT secrets");
    }

    @Test
    void corruptedClientFinished() {
        Handshakes.Tamper corrupt = (fromServer, level, bytes) -> fromServer || level != EncryptionLevel.HANDSHAKE
                ? bytes
                : Handshakes.rewrite(bytes, HandshakeType.FINISHED, m -> {
                    byte[] out = m.clone();
                    out[out.length - 1] ^= 0x01;
                    return out;
                });
        Handshakes h = fails(TlsAlert.DECRYPT_ERROR, client(), server(), corrupt);
        assertTrue(h.client.isHandshakeComplete());
        assertFalse(h.server.isHandshakeComplete());
    }

    @Test
    void truncatedFinished() {
        Handshakes.Tamper truncate = (fromServer, level, bytes) -> !fromServer || level != EncryptionLevel.HANDSHAKE
                ? bytes
                : Handshakes.rewrite(bytes, HandshakeType.FINISHED, m -> new HandshakeMessage.Finished(
                        java.util.Arrays.copyOfRange(m, 4, m.length - 1)).encode());
        fails(TlsAlert.DECRYPT_ERROR, client(), server(), truncate);
    }

    // --- message order and levels ---

    @Test
    void certificateBeforeEncryptedExtensions() {
        Handshakes.Tamper swap = (fromServer, level, bytes) -> {
            if (!fromServer || level != EncryptionLevel.HANDSHAKE) return bytes;
            List<byte[]> messages = Handshakes.messages(bytes);
            byte[] first = messages.get(0);
            messages.set(0, messages.get(1));
            messages.set(1, first);
            return Handshakes.join(messages);
        };
        fails(TlsAlert.UNEXPECTED_MESSAGE, client(), server(), swap);
    }

    @Test
    void missingCertificateVerify() {
        Handshakes.Tamper drop = (fromServer, level, bytes) -> {
            if (!fromServer || level != EncryptionLevel.HANDSHAKE) return bytes;
            List<byte[]> messages = new ArrayList<>(Handshakes.messages(bytes));
            messages.removeIf(m -> (m[0] & 0xff) == HandshakeType.CERTIFICATE_VERIFY);
            return Handshakes.join(messages);
        };
        fails(TlsAlert.UNEXPECTED_MESSAGE, client(), server(), drop);
    }

    @Test
    void serverExpectsClientHelloFirst() throws Exception {
        TlsSession server = TlsSession.server(server().build(), Handshakes.SERVER_PARAMS);
        QuicException e = assertThrows(QuicException.class, () -> server.readHandshake(EncryptionLevel.INITIAL,
                ByteBuffer.wrap(new HandshakeMessage.Finished(new byte[32]).encode())));
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, Handshakes.alert(e));
        // The session stays failed.
        assertSame(e, assertThrows(QuicException.class,
                () -> server.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.allocate(0))));
    }

    @Test
    void clientHelloAtTheWrongLevel() {
        TlsSession client = TlsSession.client(client().build(), Handshakes.CLIENT_PARAMS);
        TlsSession server = TlsSession.server(server().build(), Handshakes.SERVER_PARAMS);
        QuicException e = assertThrows(QuicException.class, () -> server.readHandshake(EncryptionLevel.HANDSHAKE,
                ByteBuffer.wrap(client.writeHandshake(EncryptionLevel.INITIAL))));
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, Handshakes.alert(e));
    }

    @Test
    void dataAfterServerHelloInTheSameFlight() throws Exception {
        TlsSession client = TlsSession.client(client().build(), Handshakes.CLIENT_PARAMS);
        TlsSession server = TlsSession.server(server().build(), Handshakes.SERVER_PARAMS);
        server.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(client.writeHandshake(EncryptionLevel.INITIAL)));
        byte[] serverHello = server.writeHandshake(EncryptionLevel.INITIAL);
        byte[] extra = Handshakes.join(List.of(serverHello, new byte[] {8, 0, 0, 2, 0, 0}));
        QuicException e = assertThrows(QuicException.class,
                () -> client.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(extra)));
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, Handshakes.alert(e));
    }

    @Test
    void initialDataAfterTheKeysChanged() throws Exception {
        TlsSession client = TlsSession.client(client().build(), Handshakes.CLIENT_PARAMS);
        TlsSession server = TlsSession.server(server().build(), Handshakes.SERVER_PARAMS);
        server.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(client.writeHandshake(EncryptionLevel.INITIAL)));
        byte[] serverHello = server.writeHandshake(EncryptionLevel.INITIAL);
        client.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(serverHello));
        QuicException e = assertThrows(QuicException.class,
                () -> client.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(serverHello)));
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, Handshakes.alert(e));
    }

    @Test
    void oversizedMessage() {
        TlsSession server = TlsSession.server(server().build(), Handshakes.SERVER_PARAMS);
        QuicException e = assertThrows(QuicException.class, () -> server.readHandshake(EncryptionLevel.INITIAL,
                ByteBuffer.wrap(new byte[] {1, 0x10, 0, 0})));
        assertEquals(QuicException.CRYPTO_BUFFER_EXCEEDED, e.code());
    }

    @Test
    void messageSizeLimitIsConfigurable() throws Exception {
        // An RSA chain makes the Certificate message about 1.4 KB.
        TlsConfig.Builder server = TlsConfig.builder()
                .certificate(TestCerts.CA.issue(KeyType.RSA, HOST)).alpnProtocols("h3");
        run(client().maxHandshakeMessageSize(4096), server).assertAgreement();
        assertThrows(IllegalArgumentException.class, () -> TlsConfig.builder().maxHandshakeMessageSize(100));
    }

    // --- after the handshake ---

    @Test
    void clientKeepsNewSessionTickets() throws Exception {
        Handshakes h = run(client(), server());
        byte[] ticket = new NewSessionTicket(7200, 1, new byte[] {0}, new byte[] {1, 2, 3}, List.of()).encode();
        Handshakes.feed(h.client, EncryptionLevel.ONE_RTT, Handshakes.join(List.of(ticket, ticket)), new Random(1));
        assertTrue(h.client.isHandshakeComplete());
        assertEquals(java.time.Duration.ofHours(2), h.client.pollNewTicket().lifetime());
        assertEquals(HOST, h.client.pollNewTicket().serverName());
        assertNull(h.client.pollNewTicket());
    }

    @Test
    void keyUpdateMessageIsRefused() throws Exception {
        Handshakes h = run(client(), server());
        QuicException e = assertThrows(QuicException.class, () -> h.client.readHandshake(EncryptionLevel.ONE_RTT,
                ByteBuffer.wrap(new KeyUpdate(0).encode())));
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, Handshakes.alert(e));
    }

    @Test
    void serverRefusesPostHandshakeMessages() throws Exception {
        Handshakes h = run(client(), server());
        byte[] ticket = new NewSessionTicket(1, 1, new byte[0], new byte[] {1}, List.of()).encode();
        QuicException e = assertThrows(QuicException.class,
                () -> h.server.readHandshake(EncryptionLevel.ONE_RTT, ByteBuffer.wrap(ticket)));
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, Handshakes.alert(e));
    }

    @Test
    void exporterDependsOnLabelAndContext() throws Exception {
        Handshakes h = run(client(), server());
        byte[] a = h.client.exportKeyingMaterial("EXPORTER-a", null, 16);
        assertArrayEquals(a, h.server.exportKeyingMaterial("EXPORTER-a", new byte[0], 16));
        assertFalse(java.util.Arrays.equals(a, h.client.exportKeyingMaterial("EXPORTER-b", null, 16)));
        assertFalse(java.util.Arrays.equals(a, h.client.exportKeyingMaterial("EXPORTER-a", new byte[] {1}, 16)));
        TlsSession fresh = TlsSession.client(client().build(), new byte[0]);
        assertThrows(IllegalStateException.class, () -> fresh.exportKeyingMaterial("x", null, 16));
    }

    // --- client authentication ---

    @Test
    void clientCertificateRequired() throws Exception {
        CertifiedKey clientKey = TestCerts.CA.issue(KeyType.P384, "client.test");
        Handshakes h = run(client().clientCertificate(clientKey),
                server().clientAuth(ClientAuth.REQUIRE).clientTrustManager(TestCerts.CA.trustManager()));
        h.assertAgreement();
        assertEquals(clientKey.chain(), h.server.peerCertificates());
        assertEquals(SignatureScheme.ECDSA_SECP384R1_SHA384, h.server.peerSignatureScheme());
    }

    @Test
    void clientCertificateWithEveryKeyType() throws Exception {
        for (KeyType type : KeyType.values()) {
            CertifiedKey clientKey = TestCerts.CA.issue(type, "client.test");
            // P-521 is not among the default schemes: both sides take the defaults and it
            SignatureScheme[] withP521 = {SignatureScheme.ECDSA_SECP256R1_SHA256, SignatureScheme.ECDSA_SECP384R1_SHA384,
                SignatureScheme.ECDSA_SECP521R1_SHA512, SignatureScheme.RSA_PSS_RSAE_SHA256,
                SignatureScheme.RSA_PSS_RSAE_SHA384, SignatureScheme.RSA_PSS_RSAE_SHA512, SignatureScheme.ED25519};
            TlsConfig.Builder client = type == KeyType.P521 ? client().signatureSchemes(withP521) : client();
            TlsConfig.Builder server = type == KeyType.P521 ? server().signatureSchemes(withP521) : server();
            Handshakes h = run(client.clientCertificate(clientKey),
                    server.clientAuth(ClientAuth.REQUIRE).clientTrustManager(TestCerts.CA.trustManager()));
            h.assertAgreement();
            assertEquals(clientKey.chain().get(0), h.server.peerCertificates().get(0));
        }
    }

    @Test
    void clientCertificateMissing() {
        fails(TlsAlert.CERTIFICATE_REQUIRED, client(),
                server().clientAuth(ClientAuth.REQUIRE).clientTrustManager(TestCerts.CA.trustManager()));
    }

    @Test
    void clientCertificateOptional() throws Exception {
        Handshakes h = run(client(), server().clientAuth(ClientAuth.REQUEST).clientTrustManager(TestCerts.CA.trustManager()));
        h.assertAgreement();
        assertTrue(h.server.peerCertificates().isEmpty());
    }

    @Test
    void clientCertificateUntrusted() {
        fails(TlsAlert.UNKNOWN_CA, client().clientCertificate(TestCerts.OTHER_CA.issue(KeyType.P256, "client.test")),
                server().clientAuth(ClientAuth.REQUEST).clientTrustManager(TestCerts.CA.trustManager()));
    }

    @Test
    void clientCertificateVerifyCorrupted() {
        Handshakes.Tamper corrupt = (fromServer, level, bytes) -> fromServer || level != EncryptionLevel.HANDSHAKE
                ? bytes
                : Handshakes.rewrite(bytes, HandshakeType.CERTIFICATE_VERIFY, m -> {
                    byte[] out = m.clone();
                    out[out.length - 2] ^= 0x01;
                    return out;
                });
        fails(TlsAlert.DECRYPT_ERROR, client().clientCertificate(TestCerts.CA.issue(KeyType.ED25519, "client.test")),
                server().clientAuth(ClientAuth.REQUIRE).clientTrustManager(TestCerts.CA.trustManager()), corrupt);
    }

    @Test
    void configValidation() {
        assertThrows(IllegalArgumentException.class, () -> TlsConfig.builder().cipherSuites());
        assertThrows(IllegalArgumentException.class, () -> TlsConfig.builder().groups(NamedGroup.X25519, NamedGroup.X25519));
        assertThrows(IllegalArgumentException.class,
                () -> TlsConfig.builder().signatureSchemes(SignatureScheme.RSA_PKCS1_SHA256));
        assertThrows(IllegalArgumentException.class, () -> TlsConfig.builder().alpnProtocols(""));
        assertThrows(IllegalArgumentException.class,
                () -> TlsSession.server(TlsConfig.builder().alpnProtocols("h3").build(), new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new CertifiedKey(List.of(),
                TestCerts.keyPair(KeyType.P256).getPrivate()));
    }
}
