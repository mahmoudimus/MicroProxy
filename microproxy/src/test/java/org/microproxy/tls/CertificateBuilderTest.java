package org.microproxy.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
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

    /**
     * A CA made elsewhere (here by openssl) whose Subject Key Identifier is RFC 5280 method 1, the SHA-1 of the key's
     * BIT STRING. The issued certificate's Authority Key Identifier must equal it: the JDK's PKIX path builder finds
     * the issuer by that identifier, and with any other value fails with "Path does not chain with any of the trust
     * anchors" although the signature verifies.
     */
    @Test
    void issuedCertificateNamesAnExternalCaByItsOwnKeyIdentifier() throws Exception {
        X509Certificate caCert;
        try (InputStream in = resource("external-ca.pem")) {
            caCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        PrivateKey caKey;
        try (InputStream in = resource("external-ca.key.pem")) {
            String pem = new String(in.readAllBytes(), StandardCharsets.US_ASCII)
                    .replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
            caKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
        }
        CertificateAuthority ca = new CertificateAuthority(caKey, caCert);
        X509Certificate leaf = ca.issue(CertificateAuthority.newEcKeyPair().getPublic(), List.of("example.com"));

        assertTrue(Arrays.equals(keyIdentifier(caCert, "2.5.29.14"), keyIdentifier(leaf, "2.5.29.35")),
                "the Authority Key Identifier must be the CA's Subject Key Identifier");
        var path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(leaf));
        PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(caCert, null)));
        params.setRevocationEnabled(false);
        CertPathValidator.getInstance("PKIX").validate(path, params);
        // what TLS clients do: build the path from the leaf alone with the JDK's trust manager
        java.security.KeyStore trust = java.security.KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("ca", caCert);
        javax.net.ssl.TrustManagerFactory factory = javax.net.ssl.TrustManagerFactory.getInstance("PKIX");
        factory.init(trust);
        ((javax.net.ssl.X509TrustManager) factory.getTrustManagers()[0])
                .checkServerTrusted(new X509Certificate[] {leaf}, "ECDHE_ECDSA");
    }

    private static InputStream resource(String name) {
        InputStream in = CertificateBuilderTest.class.getResourceAsStream(name);
        if (in == null) throw new IllegalStateException("missing test resource " + name);
        return in;
    }

    /** The key identifier in a Subject (2.5.29.14) or Authority (2.5.29.35, [0]) Key Identifier extension. */
    private static byte[] keyIdentifier(X509Certificate cert, String oid) {
        byte[] ext = cert.getExtensionValue(oid);
        if (ext == null) throw new AssertionError(oid + " missing");
        // OCTET STRING { OCTET STRING keyId } or OCTET STRING { SEQUENCE { [0] keyId ... } }
        int i = 2; // outer OCTET STRING header, short form for these sizes
        if (oid.equals("2.5.29.35")) i += 2; // SEQUENCE header
        int length = ext[i + 1];
        return Arrays.copyOfRange(ext, i + 2, i + 2 + length);
    }
}
