package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.mahmoudimus.quic.QuicException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PssCertificatePolicyTest {
    @Test
    void tlsPolicyChecksThePssCertificateMessageDigest() throws Exception {
        assertRejected("SHA-256", "SHA-384", false);
    }

    @Test
    void tlsPolicyChecksThePssCertificateMgf1Digest() throws Exception {
        assertRejected("SHA-384", "SHA-256", false);
    }

    @Test
    void callerConstraintsCheckThePssCertificateMessageDigest() throws Exception {
        assertRejected("SHA-256", "SHA-384", true);
    }

    @Test
    void callerConstraintsCheckThePssCertificateMgf1Digest() throws Exception {
        assertRejected("SHA-384", "SHA-256", true);
    }

    private static void assertRejected(String digest, String mgfDigest, boolean custom) throws Exception {
        X509Certificate certificate = certificate(digest, mgfDigest);
        certificate.verify(certificate.getPublicKey());
        String previous = Security.getProperty("jdk.tls.disabledAlgorithms");
        try {
            Security.setProperty("jdk.tls.disabledAlgorithms", custom ? "" : "SHA-256");
            TlsAcceptancePolicy policy = new TlsAcceptancePolicy(null, custom ? denySha256() : null);
            assertThrows(QuicException.class, () -> policy.certificates(List.of(certificate)));
        } finally {
            Security.setProperty("jdk.tls.disabledAlgorithms", previous);
        }
    }

    private static AlgorithmConstraints denySha256() {
        return new AlgorithmConstraints() {
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
                return !primitives.contains(CryptoPrimitive.MESSAGE_DIGEST)
                        || !algorithm.replace("-", "").equalsIgnoreCase("SHA256");
            }
            public boolean permits(Set<CryptoPrimitive> primitives, Key key) { return true; }
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
                return permits(primitives, algorithm, parameters);
            }
        };
    }

    /** A real RSA-PSS self-signed certificate using the existing test certificate's DER fields. */
    private static X509Certificate certificate(String digest, String mgfDigest) throws Exception {
        CertifiedKey key = TestCerts.CA.issue(TestCerts.KeyType.RSA, "pss.test");
        PSSParameterSpec spec = new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(mgfDigest), 32, 1);
        AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS");
        params.init(spec);
        byte[] algorithm = sequence(HexFormat.of().parseHex("06092a864886f70d01010a"), params.getEncoded());
        List<byte[]> fields = children(key.chain().get(0).getTBSCertificate());
        fields.set(2, algorithm);
        fields.set(3, fields.get(5)); // self-issued: issuer equals subject
        byte[] tbs = sequence(fields.toArray(byte[][]::new));
        Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(spec);
        signer.initSign(key.privateKey());
        signer.update(tbs);
        byte[] signature = signer.sign();
        byte[] bits = new byte[signature.length + 1];
        System.arraycopy(signature, 0, bits, 1, signature.length);
        byte[] der = sequence(tbs, algorithm, TestCerts.tlv(0x03, bits));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    private static byte[] sequence(byte[]... fields) {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        for (byte[] field : fields) content.writeBytes(field);
        return TestCerts.tlv(0x30, content.toByteArray());
    }

    /** Split an existing, valid test DER sequence without depending on internal JDK ASN.1 APIs. */
    private static List<byte[]> children(byte[] encoded) {
        int cursor = 1;
        int length = encoded[cursor++] & 0xff;
        if ((length & 0x80) != 0) cursor += length & 0x7f;
        List<byte[]> fields = new ArrayList<>();
        while (cursor < encoded.length) {
            int start = cursor++;
            length = encoded[cursor++] & 0xff;
            if ((length & 0x80) != 0) {
                int octets = length & 0x7f;
                length = 0;
                for (int i = 0; i < octets; i++) length = (length << 8) | (encoded[cursor++] & 0xff);
            }
            cursor += length;
            fields.add(Arrays.copyOfRange(encoded, start, cursor));
        }
        return fields;
    }
}
