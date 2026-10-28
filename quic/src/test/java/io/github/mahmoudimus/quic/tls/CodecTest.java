package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateEntry;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateMessage;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateRequest;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.NewSessionTicket;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Unknown;
import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The codec, extension payloads, host name matching and key exchange validation. */
class CodecTest {

    private static final long DECODE_ERROR = QuicException.CRYPTO_ERROR + TlsAlert.DECODE_ERROR;

    @Test
    void readerFailsWithDecodeError() {
        Reader r = new Reader(new byte[] {0, 5, 1, 2});
        QuicException e = assertThrows(QuicException.class, () -> r.vector16(0, "thing"));
        assertEquals(DECODE_ERROR, e.code());
        assertEquals(DECODE_ERROR, assertThrows(QuicException.class,
                () -> new Reader(new byte[] {1}).expectEnd("x")).code());
        assertEquals(DECODE_ERROR, assertThrows(QuicException.class,
                () -> new Reader(new byte[] {0, 3, 0, 1, 2}).u16List16(1, "list")).code());
        assertEquals(DECODE_ERROR, assertThrows(QuicException.class,
                () -> new Reader(new byte[] {0, 0}).u16List16(1, "list")).code());
    }

    @Test
    void writerLengthPrefixes() throws Exception {
        Writer w = new Writer();
        int outer = w.open(3);
        w.vector8(new byte[] {1, 2}).u32(0xfffffffeL);
        w.close(outer);
        byte[] out = w.toByteArray();
        assertArrayEquals(new byte[] {0, 0, 7, 2, 1, 2, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe}, out);
        Reader r = new Reader(out);
        Reader sub = r.sub24("outer");
        assertArrayEquals(new byte[] {1, 2}, sub.vector8(1, "v"));
        assertEquals(0xfffffffeL, sub.u32("n"));
        assertThrows(IllegalArgumentException.class, () -> new Writer().vector8(new byte[256]));
    }

    @Test
    void messageRoundTrips() throws Exception {
        List<HandshakeMessage> messages = List.of(
                new CertificateRequest(new byte[0], List.of(new Extension(ExtensionType.SIGNATURE_ALGORITHMS,
                        Extensions.encodeU16List(new int[] {0x0403})))),
                new CertificateMessage(new byte[] {7}, List.of(new CertificateEntry(new byte[] {1, 2, 3},
                        List.of(new Extension(5, new byte[] {9}))))),
                new NewSessionTicket(1, 2, new byte[0], new byte[] {1}, List.of()),
                new HandshakeMessage.KeyUpdate(0),
                new Unknown(HandshakeType.END_OF_EARLY_DATA, new byte[0]));
        for (HandshakeMessage m : messages) {
            byte[] encoded = m.encode();
            HandshakeMessage decoded = HandshakeMessage.decode(encoded[0] & 0xff,
                    Arrays.copyOfRange(encoded, 4, encoded.length));
            assertEquals(m.getClass(), decoded.getClass());
            assertArrayEquals(encoded, decoded.encode());
        }
        assertInstanceOf(Unknown.class, HandshakeMessage.decode(99, new byte[] {1}));
        // An empty cert_data is malformed.
        assertEquals(DECODE_ERROR, assertThrows(QuicException.class, () -> HandshakeMessage.decode(
                HandshakeType.CERTIFICATE, new byte[] {0, 0, 0, 5, 0, 0, 0, 0, 0})).code());
    }

    @Test
    void serverNamePayload() throws Exception {
        assertEquals("example.com", Extensions.decodeServerName(Extensions.encodeServerName("Example.COM.")));
        assertNull(Extensions.decodeServerName(Extensions.encodeServerName("192.0.2.1")));
        // Two host names, a name with a space and an empty list are malformed.
        byte[] two = {0, 8, 0, 0, 1, 'a', 0, 0, 1, 'b'};
        assertEquals(DECODE_ERROR, assertThrows(QuicException.class, () -> Extensions.decodeServerName(two)).code());
        assertEquals(DECODE_ERROR, assertThrows(QuicException.class,
                () -> Extensions.decodeServerName(Extensions.encodeServerName("a b"))).code());
        assertEquals(DECODE_ERROR, assertThrows(QuicException.class,
                () -> Extensions.decodeServerName(new byte[] {0, 0})).code());
        // Other name types are skipped.
        assertNull(Extensions.decodeServerName(new byte[] {0, 4, 1, 0, 1, 'x'}));
    }

    @Test
    void duplicateExtensions() {
        QuicException e = assertThrows(QuicException.class, () -> Extensions.checkNoDuplicates(
                List.of(new Extension(1, new byte[0]), new Extension(2, new byte[0]), new Extension(1, new byte[0])),
                "test"));
        assertEquals(QuicException.CRYPTO_ERROR + TlsAlert.ILLEGAL_PARAMETER, e.code());
    }

    @Test
    void hostnameMatching() {
        assertTrue(HostnameChecker.matchesPattern("example.com", "example.com"));
        assertTrue(HostnameChecker.matchesPattern("*.example.com", "www.example.com"));
        assertFalse(HostnameChecker.matchesPattern("*.example.com", "example.com"));
        assertFalse(HostnameChecker.matchesPattern("*.example.com", "a.b.example.com"));
        assertFalse(HostnameChecker.matchesPattern("*.com", "example.com"));
        assertFalse(HostnameChecker.matchesPattern("w*.example.com", "www.example.com"));
        X509Certificate cert = TestCerts.CA.issue(KeyType.P256, "host.test", "::1").chain().get(0);
        assertTrue(HostnameChecker.matches(cert, "HOST.test."));
        assertTrue(HostnameChecker.matches(cert, "[::1]"));
        assertTrue(HostnameChecker.matches(cert, "0:0:0:0:0:0:0:1"));
        assertFalse(HostnameChecker.matches(cert, "127.0.0.1"));
        assertFalse(HostnameChecker.matches(cert, "other.test"));
    }

    @Test
    void keyShareValidation() throws Exception {
        SecureRandom random = new SecureRandom();
        for (NamedGroup group : NamedGroup.values()) {
            // a key encapsulation is not symmetric; HybridKeyExchangeTest covers X25519MLKEM768
            if (group == NamedGroup.X25519_MLKEM768) continue;
            KeyExchange a = KeyExchange.generate(group, random);
            KeyExchange b = KeyExchange.generate(group, random);
            assertEquals(group.publicKeyLength(), a.publicKey().length);
            assertArrayEquals(a.agree(b.publicKey()), b.agree(a.publicKey()));
            QuicException e = assertThrows(QuicException.class, () -> a.agree(new byte[group.publicKeyLength() + 1]));
            assertEquals(QuicException.CRYPTO_ERROR + TlsAlert.ILLEGAL_PARAMETER, e.code());
        }
        KeyExchange p256 = KeyExchange.generate(NamedGroup.SECP256R1, random);
        byte[] compressedTag = p256.publicKey();
        compressedTag[0] = 2;
        assertThrows(QuicException.class, () -> p256.agree(compressedTag));
        byte[] offCurve = KeyExchange.generate(NamedGroup.SECP256R1, random).publicKey();
        offCurve[64] ^= 1;
        assertThrows(QuicException.class, () -> p256.agree(offCurve));
    }

    @Test
    void signatureSchemesFitKeys() {
        assertTrue(SignatureScheme.ECDSA_SECP256R1_SHA256.compatibleWith(TestCerts.keyPair(KeyType.P256).getPublic()));
        assertFalse(SignatureScheme.ECDSA_SECP384R1_SHA384.compatibleWith(TestCerts.keyPair(KeyType.P256).getPublic()));
        assertTrue(SignatureScheme.RSA_PSS_RSAE_SHA512.compatibleWith(TestCerts.keyPair(KeyType.RSA).getPrivate()));
        assertFalse(SignatureScheme.ED25519.compatibleWith(TestCerts.keyPair(KeyType.RSA).getPrivate()));
        assertTrue(SignatureScheme.ED25519.compatibleWith(TestCerts.keyPair(KeyType.ED25519).getPrivate()));
        assertFalse(SignatureScheme.RSA_PKCS1_SHA256.allowedInCertificateVerify());
        assertEquals(SignatureScheme.RSA_PSS_RSAE_SHA384, SignatureScheme.forCode(0x0805));
        assertNull(SignatureScheme.forCode(0x0201));
        assertEquals(NamedGroup.SECP384R1, NamedGroup.forCode(0x18));
    }

    @Test
    void alertNames() {
        assertEquals("no_application_protocol", TlsAlert.name(TlsAlert.NO_APPLICATION_PROTOCOL));
        assertEquals(TlsAlert.MISSING_EXTENSION, TlsAlert.fromErrorCode(0x16d));
        assertEquals(-1, TlsAlert.fromErrorCode(QuicException.PROTOCOL_VIOLATION));
        assertEquals("alert(255)", TlsAlert.name(255));
    }
}
