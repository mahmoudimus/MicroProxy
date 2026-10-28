package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.Secrets;
import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Full handshakes for every cipher suite, group and CertificateVerify signature scheme. */
class HandshakeMatrixTest {

    static KeyType keyType(SignatureScheme scheme) {
        return switch (scheme) {
            case ECDSA_SECP256R1_SHA256 -> KeyType.P256;
            case ECDSA_SECP384R1_SHA384 -> KeyType.P384;
            case ECDSA_SECP521R1_SHA512 -> KeyType.P521;
            case ED25519 -> KeyType.ED25519;
            default -> KeyType.RSA;
        };
    }

    static Stream<Arguments> combinations() {
        List<Arguments> out = new ArrayList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            for (NamedGroup group : NamedGroup.values()) {
                for (SignatureScheme scheme : SignatureScheme.values()) {
                    if (scheme.allowedInCertificateVerify()) out.add(Arguments.of(suite, group, scheme));
                }
            }
        }
        return out.stream();
    }

    @ParameterizedTest(name = "{0} {1} {2}")
    @MethodSource("combinations")
    void handshake(CipherSuite suite, NamedGroup group, SignatureScheme scheme) throws Exception {
        TlsConfig client = TlsConfig.builder()
                .serverName("quic.test")
                .alpnProtocols("h3")
                .trustManager(TestCerts.CA.trustManager())
                .cipherSuites(suite)
                .groups(group)
                .signatureSchemes(scheme)
                .build();
        TlsConfig server = TlsConfig.builder()
                // every group, so the one the client offers is accepted (the hybrid is not a default),
                // and the scheme under test (P-521 is not a default)
                .groups(NamedGroup.values())
                .signatureSchemes(scheme)
                .certificate(TestCerts.CA.issue(keyType(scheme), "quic.test"))
                .alpnProtocols("h3")
                .build();
        Random random = new Random(31L * suite.ordinal() + 7L * group.ordinal() + scheme.ordinal());
        Handshakes h = Handshakes.run(client, server, random, Handshakes.NONE);
        h.assertAgreement();
        assertEquals(suite, h.client.cipherSuite());
        assertEquals(group, h.client.negotiatedGroup());
        assertEquals(scheme, h.client.peerSignatureScheme());
        assertEquals("h3", h.server.negotiatedAlpn());
        assertEquals("quic.test", h.server.serverName());
        assertFalse(h.client.usedHelloRetryRequest());
        assertEquals(2, h.client.peerCertificates().size());

        // Key updates: both sides derive the same next generations with "quic ku".
        Secrets oneRtt = h.clientSecrets.get(EncryptionLevel.ONE_RTT);
        for (int generation = 0; generation < 3; generation++) {
            Secrets c = h.client.nextOneRttSecrets();
            Secrets s = h.server.nextOneRttSecrets();
            assertArrayEquals(c.client(), s.client());
            assertArrayEquals(c.server(), s.server());
            assertArrayEquals(suite.hkdf().expandLabel(oneRtt.client(), "quic ku", new byte[0],
                    suite.hkdf().hashLength()), c.client());
            oneRtt = c;
        }
    }
}
