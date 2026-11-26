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
        QuicException failure = assertThrows(QuicException.class, () -> policy.certificates(List.of(leaf.chain().get(0))));
        // No path to an accepted issuer: a certificate path failure, for callers that classify it.
        assertTrue(failure.getCause() instanceof java.security.cert.CertPathBuilderException, String.valueOf(failure.getCause()));
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
        // A bound on the work, not a verdict on trust.
        assertTrue(failure.getCause() == null, String.valueOf(failure.getCause()));
    }

    @Test
    void theCheckedPathEndsAtAnAcceptedIssuerAndIgnoresAnUnverifiableCrossSignedCopyAfterIt() throws Exception {
        // As flex.cybersource.com sends it: leaf, then the accepted root re-issued by a root the
        // trust manager no longer carries (SSL.com TLS ECC Root CA 2022 signed by Comodo AAA).
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        java.security.cert.X509Certificate crossSigned = TestCerts.CA.crossSignedBy(TestCerts.OTHER_CA);
        List<java.security.cert.X509Certificate> chain = List.of(leaf.chain().get(0), crossSigned);
        TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, signatureKeyCompatibility(),
                new java.security.cert.X509Certificate[] {TestCerts.CA.certificate});
        assertDoesNotThrow(() -> policy.certificates(chain));
        // The trust manager accepts the same chain: it stops at the accepted root as well.
        assertDoesNotThrow(() -> TestCerts.CA.trustManager().checkServerTrusted(
                chain.toArray(java.security.cert.X509Certificate[]::new), "ECDHE_RSA"));
    }

    @Test
    void aPathCertificateWithoutAVerifiableIssuerIsStillRejectedWhenAnAcceptedIssuerExists() throws Exception {
        CertifiedKey foreign = TestCerts.OTHER_CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, signatureKeyCompatibility(),
                new java.security.cert.X509Certificate[] {TestCerts.CA.certificate});
        QuicException failure = assertThrows(QuicException.class,
                () -> policy.certificates(List.of(foreign.chain().get(0))));
        assertTrue(failure.getCause() instanceof java.security.cert.CertPathBuilderException, String.valueOf(failure.getCause()));
    }

    /** Constraints that refuse {@code denied} as a signature-verifying key, and permit the rest. */
    private static AlgorithmConstraints denyingVerificationBy(java.security.PublicKey denied) {
        return new AlgorithmConstraints() {
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) { return true; }
            public boolean permits(Set<CryptoPrimitive> primitives, Key key) { return true; }
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
                return !denied.equals(key);
            }
        };
    }

    @Test
    void aSelfSignedTwinCannotHideTheCrossSignedCopyThePathUses() throws Exception {
        // leaf <- Test CA (self-signed, not accepted) <- Test CA cross-signed by the accepted
        // root: the JDK validates through the cross-signed copy, so its edge is checked.
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        java.security.cert.X509Certificate cross = TestCerts.CA.crossSignedBy(TestCerts.OTHER_CA);
        List<java.security.cert.X509Certificate> chain = List.of(leaf.chain().get(0), TestCerts.CA.certificate, cross);
        assertDoesNotThrow(() -> TestCerts.OTHER_CA.trustManager().checkServerTrusted(
                chain.toArray(java.security.cert.X509Certificate[]::new), "ECDHE_RSA"));
        TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, denyingVerificationBy(TestCerts.OTHER_CA.key.getPublic()),
                new java.security.cert.X509Certificate[] {TestCerts.OTHER_CA.certificate});
        assertThrows(QuicException.class, () -> policy.certificates(chain));
    }

    @Test
    void anIntermediateEdgeOnTheWayToAnAcceptedIssuerIsChecked() throws Exception {
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        java.security.cert.X509Certificate cross = TestCerts.CA.crossSignedBy(TestCerts.OTHER_CA);
        TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, denyingVerificationBy(TestCerts.CA.key.getPublic()),
                new java.security.cert.X509Certificate[] {TestCerts.OTHER_CA.certificate});
        assertThrows(QuicException.class, () -> policy.certificates(List.of(leaf.chain().get(0), cross)));
    }

    @Test
    void aCycleOfCrossSignaturesEndsAndIsLeftToTheTrustManager() throws Exception {
        // Test CA signed by Untrusted CA and Untrusted CA signed by Test CA: a loop, no anchor.
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        List<java.security.cert.X509Certificate> chain = List.of(leaf.chain().get(0),
                TestCerts.CA.crossSignedBy(TestCerts.OTHER_CA), TestCerts.OTHER_CA.crossSignedBy(TestCerts.CA));
        TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, signatureKeyCompatibility(),
                new java.security.cert.X509Certificate[0]);
        assertDoesNotThrow(() -> policy.certificates(chain));
    }

    @Test
    void aChainCopyOfAnAcceptedIssuerIsCheckedBecauseTheJdkMayBuildThroughIt() throws Exception {
        // Out of order, so PKIX builds rather than truncating: the JDK may go leaf <- cross <-
        // Untrusted CA even though Test CA itself is accepted. The cross edge is checked.
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.RSA, "leaf.test");
        java.security.cert.X509Certificate unrelated = TestCerts.CA.issue(TestCerts.KeyType.P256, "unrelated.test").chain().get(0);
        java.security.cert.X509Certificate cross = TestCerts.CA.crossSignedBy(TestCerts.OTHER_CA);
        TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, denyingVerificationBy(TestCerts.OTHER_CA.key.getPublic()),
                new java.security.cert.X509Certificate[] {TestCerts.CA.certificate, TestCerts.OTHER_CA.certificate});
        assertThrows(QuicException.class, () -> policy.certificates(List.of(leaf.chain().get(0), unrelated, cross)));
    }
}
