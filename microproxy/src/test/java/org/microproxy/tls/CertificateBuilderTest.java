package org.microproxy.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CertificateBuilderTest {

    @Test
    void issuedCertificateValidatesAgainstCa() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Unit CA");
        KeyPair leafKeys = CertificateAuthority.newEcKeyPair();
        X509Certificate leaf = ca.issue(leafKeys.getPublic(), List.of("example.com", "*.example.com", "192.0.2.1"));

        assertEquals(-1, leaf.getBasicConstraints());
        assertEquals(0, ca.getCertificate().getBasicConstraints());
        assertEquals(List.of("1.3.6.1.5.5.7.3.1"), leaf.getExtendedKeyUsage());
        Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
        assertEquals(3, sans.size());
        assertTrue(sans.contains(List.of(2, "*.example.com")));
        assertTrue(sans.contains(List.of(7, "192.0.2.1")));

        var path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(leaf));
        PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(ca.getCertificate(), null)));
        params.setRevocationEnabled(false);
        CertPathValidator.getInstance("PKIX").validate(path, params);
    }

    @Test
    void rsaKeysAreSupported() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair rsa = gen.generateKeyPair();
        X509Certificate cert = new CertificateBuilder().subject("rsa.test", null).publicKey(rsa.getPublic())
                .addSubjectAltName("rsa.test").sign(rsa.getPrivate());
        cert.verify(rsa.getPublic());
        assertEquals("SHA256withRSA", cert.getSigAlgName());
    }

    @Test
    void caRoundTripsThroughPkcs12(@TempDir Path dir) throws Exception {
        Path store = dir.resolve("ca.p12");
        CertificateAuthority created = CertificateAuthority.loadOrCreate(store, "pw".toCharArray(), "Saved CA");
        CertificateAuthority loaded = CertificateAuthority.loadOrCreate(store, "pw".toCharArray(), "ignored");
        assertEquals(created.getCertificate(), loaded.getCertificate());
        assertTrue(loaded.getCertificatePem().startsWith("-----BEGIN CERTIFICATE-----\n"));
    }
}
