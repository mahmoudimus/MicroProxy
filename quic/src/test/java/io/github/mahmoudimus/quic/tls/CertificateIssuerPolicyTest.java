package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicException;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CertificateIssuerPolicyTest {
    static AlgorithmConstraints signatureKeyCompatibility() {
        return new AlgorithmConstraints() {
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) { return true; }
            public boolean permits(Set<CryptoPrimitive> primitives, Key key) { return true; }
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
                return !algorithm.equalsIgnoreCase("SHA256withECDSA") || key instanceof ECPublicKey;
            }
        };
    }

    @Test
    void actualIssuerMayFollowAnUnrelatedAdjacentLeaf() throws Exception {
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        CertifiedKey unrelated = TestCerts.CA.issue(TestCerts.KeyType.RSA, "unrelated.test");
        TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, signatureKeyCompatibility());
        assertDoesNotThrow(() -> policy.certificates(List.of(leaf.chain().get(0), unrelated.chain().get(0), TestCerts.CA.certificate)));
    }

    @Test
    void omittedIssuerContextFailsExplicitlyInsteadOfSubstitutingTheSubjectKey() throws Exception {
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, null);
        assertThrows(QuicException.class, () -> policy.certificates(List.of(leaf.chain().get(0))));
    }

    @Test
    void anIssuerNameMatchRequiresVerificationWithTheCandidateKey() throws Exception {
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        // Same subject DN as the CA, but a different key and not self-signed.
        CertifiedKey wrong = TestCerts.CA.issue(TestCerts.KeyType.P384, "Test CA");
        String previous = Security.getProperty("jdk.tls.disabledAlgorithms");
        try {
            Security.setProperty("jdk.tls.disabledAlgorithms", "");
            TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, null);
            assertThrows(QuicException.class, () -> policy.certificates(List.of(leaf.chain().get(0), wrong.chain().get(0))));
        } finally {
            Security.setProperty("jdk.tls.disabledAlgorithms", previous);
        }
    }
    @Test
    void duplicateIssuerCandidatesCannotCauseUnboundedSignatureWork() throws Exception {
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        CertifiedKey wrong = TestCerts.CA.issue(TestCerts.KeyType.P384, "Test CA");
        List<java.security.cert.X509Certificate> chain = new java.util.ArrayList<>();
        chain.add(leaf.chain().get(0));
        for (int i = 0; i < 17; i++) chain.add(wrong.chain().get(0));
        chain.add(TestCerts.CA.certificate);
        TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, null);
        QuicException failure = assertThrows(QuicException.class, () -> policy.certificates(chain));
        assertTrue(failure.getMessage().contains("issuer verification budget"));
    }

}
