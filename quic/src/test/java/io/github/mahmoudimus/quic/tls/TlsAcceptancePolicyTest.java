package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicException;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;
import org.junit.jupiter.api.Test;

class TlsAcceptancePolicyTest {
    private static void withPolicy(String property, Checked action) throws Exception {
        String previous = Security.getProperty("jdk.tls.disabledAlgorithms");
        try {
            Security.setProperty("jdk.tls.disabledAlgorithms", property);
            action.run();
        } finally { Security.setProperty("jdk.tls.disabledAlgorithms", previous); }
    }
    private interface Checked { void run() throws Exception; }
    private static TlsAcceptancePolicy policy() throws QuicException { return new TlsAcceptancePolicy(null, null); }

    @Test
    void suiteWildcardsRejectStaticRsaWhileAllowingEcdhe() throws Exception {
        withPolicy("TLS_RSA_*", () -> {
            TlsAcceptancePolicy p = policy();
            assertThrows(QuicException.class, () -> p.suite(Tls12CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256));
            p.suite(Tls12CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        });
    }
    @Test
    void cipherKeySizeChecksUseTheNegotiatedKeyLength() throws Exception {
        withPolicy("AES keySize < 256", () -> {
            assertThrows(QuicException.class, () -> policy().suite(CipherSuite.TLS_AES_128_GCM_SHA256));
            policy().suite(CipherSuite.TLS_AES_256_GCM_SHA384);
        });
    }
    @Test
    void pssDigestRestrictionsApplyDespiteTheGenericJcaAlgorithmName() throws Exception {
        withPolicy("SHA-256", () -> assertThrows(QuicException.class,
                () -> policy().signature(SignatureScheme.RSA_PSS_RSAE_SHA256, TestCerts.keyPair(TestCerts.KeyType.RSA).getPublic())));
    }
    @Test
    void handshakeUsageDoesNotDisableTheSameCertificateSignature() throws Exception {
        withPolicy("ecdsa_secp256r1_sha256 usage HandshakeSignature", () -> {
            policy().certificates(TestCerts.CA.issue(TestCerts.KeyType.P256, "tls.test").chain());
            assertThrows(QuicException.class, () -> policy().signature(SignatureScheme.ECDSA_SECP256R1_SHA256,
                    TestCerts.keyPair(TestCerts.KeyType.P256).getPublic()));
        });
    }
    @Test
    void anUninterpretableKeySizeRestrictionFailsClosed() throws Exception {
        withPolicy("SHA256 keySize < 128", () -> assertThrows(QuicException.class, TlsAcceptancePolicyTest::policy));
    }
    @Test
    void aKeyWithUnknownSizeCannotBypassAKeySizeRestriction() throws Exception {
        PublicKey key = new PublicKey() {
            public String getAlgorithm() { return "RSA"; }
            public String getFormat() { return "unknown"; }
            public byte[] getEncoded() { return new byte[0]; }
        };
        withPolicy("RSA keySize < 4096", () -> assertThrows(QuicException.class,
                () -> policy().signature(SignatureScheme.RSA_PKCS1_SHA256, key)));
    }
    @Test
    void namedSignatureConstraintsAreNotLostThroughJcaAliasConversion() throws Exception {
        AlgorithmConstraints constraints = new AlgorithmConstraints() {
            public boolean permits(Set<CryptoPrimitive> p, String a, AlgorithmParameters params) {
                return !a.equalsIgnoreCase("ECDSA_SECP256R1_SHA256");
            }
            public boolean permits(Set<CryptoPrimitive> p, Key key) { return true; }
            public boolean permits(Set<CryptoPrimitive> p, String a, Key key, AlgorithmParameters params) { return permits(p, a, params); }
        };
        withPolicy("", () -> assertThrows(QuicException.class, () -> new TlsAcceptancePolicy(null, constraints)
                .signature(SignatureScheme.ECDSA_SECP256R1_SHA256, TestCerts.keyPair(TestCerts.KeyType.P256).getPublic())));
    }
    @Test
    void compositeBulkCipherRestrictionsCannotBeLostDuringDecomposition() throws Exception {
        withPolicy("AES_128_GCM", () -> assertThrows(QuicException.class,
                () -> policy().suite(CipherSuite.TLS_AES_128_GCM_SHA256)));
    }
    @Test
    void disabledDelegationSignaturesAreRejectedBeforeCertificateVerify() throws Exception {
        CertifiedKey leaf = TestCerts.CA.issue(TestCerts.KeyType.P256, true, "dc.test");
        KeyPair credentialKey = TestCerts.keyPair(TestCerts.KeyType.P256);
        java.time.Instant now = java.time.Instant.now();
        long validTime = java.time.Duration.between(leaf.chain().get(0).getNotBefore().toInstant(), now.plusSeconds(3600)).toSeconds();
        DelegatedCredential unsigned = new DelegatedCredential(validTime, 0x0403, credentialKey.getPublic().getEncoded(), 0x0203, new byte[0]);
        byte[] signed = Signatures.sign(SignatureScheme.ECDSA_SHA1, leaf.privateKey(),
                unsigned.signedContent(leaf.chain().get(0).getEncoded()), new SecureRandom());
        DelegatedCredential dc = new DelegatedCredential(validTime, 0x0403, credentialKey.getPublic().getEncoded(), 0x0203, signed);
        // First establish this is a valid credential, independent of the acceptance policy.
        assertArrayEquals(credentialKey.getPublic().getEncoded(), dc.verify(leaf.chain().get(0), 0x0403, now).getEncoded());
        withPolicy("ecdsa_sha1 usage HandshakeSignature", () -> {
            TlsClientConnection.Config config = new TlsClientConnection.Config(BrowserProfiles.firefox159(),
                    TestCerts.CA.trustManager(), null, ClientSessionStore.NONE, java.util.Map.of(), CertificateDecompressor.ZLIB,
                    new SecureRandom(), java.time.InstantSource.system(), 65536);
            TlsClientConnection c = new TlsClientConnection(config, java.io.InputStream.nullInputStream(),
                    java.io.OutputStream.nullOutputStream(), "dc.test", "dc.test", java.util.List.of(), null);
            set(c, "policy", policy());
            set(c, "delegatedCredential", dc);
            set(c, "hello", new HandshakeMessage.ClientHello(0x0303, new byte[32], new byte[0], new int[] {0x1301},
                    new byte[] {0}, java.util.List.of(new HandshakeMessage.Extension(ExtensionType.SIGNATURE_ALGORITHMS,
                    Extensions.encodeU16List(new int[] {0x0403})))));
            Transcript transcript = new Transcript();
            transcript.start(CipherSuite.TLS_AES_128_GCM_SHA256);
            set(c, "transcript", transcript);
            byte[] cvSignature = Signatures.sign(SignatureScheme.ECDSA_SECP256R1_SHA256, credentialKey.getPrivate(),
                    Signatures.content(true, transcript.hash()), new SecureRandom());
            HandshakeMessage.CertificateVerify verify = new HandshakeMessage.CertificateVerify(0x0403, cvSignature);
            Class<?> messageClass = Class.forName(TlsClientConnection.class.getName() + "$Message");
            var constructor = messageClass.getDeclaredConstructor(int.class, HandshakeMessage.class, byte[].class, byte[].class);
            constructor.setAccessible(true);
            byte[] raw = verify.encode();
            Object message = constructor.newInstance(HandshakeType.CERTIFICATE_VERIFY, verify, java.util.Arrays.copyOfRange(raw, 4, raw.length), raw);
            var method = TlsClientConnection.class.getDeclaredMethod("onCertificateVerify", messageClass, java.security.cert.X509Certificate.class);
            method.setAccessible(true);
            var failure = assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> method.invoke(c, message, leaf.chain().get(0)));
            assertInstanceOf(QuicException.class, failure.getCause());
            assertTrue(failure.getCause().getMessage().contains("disabledAlgorithms"));
        });
    }
    private static void set(Object target, String field, Object value) throws Exception {
        var f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }
    @Test
    void digestConstraintsReceiveTheDigestPrimitive() throws Exception {
        AlgorithmConstraints constraints = denyPrimitive(CryptoPrimitive.MESSAGE_DIGEST, "SHA-256");
        withPolicy("", () -> assertThrows(QuicException.class,
                () -> new TlsAcceptancePolicy(null, constraints).suite(CipherSuite.TLS_AES_128_GCM_SHA256)));
    }
    @Test
    void groupConstraintsReceiveTheJcaAgreementAlgorithm() throws Exception {
        AlgorithmConstraints constraints = denyPrimitive(CryptoPrimitive.KEY_AGREEMENT, "ECDH");
        withPolicy("", () -> assertThrows(QuicException.class,
                () -> new TlsAcceptancePolicy(null, constraints).group(NamedGroup.SECP256R1,
                        KeyExchange.generate(NamedGroup.SECP256R1, new SecureRandom()).publicKey())));
    }
    @Test
    void unknownHybridKeySizeSemanticsFailClosed() throws Exception {
        withPolicy("ML-KEM keySize < 512", () -> assertThrows(QuicException.class,
                () -> policy().group(NamedGroup.X25519_MLKEM768, new byte[1120])));
    }
    @Test
    void anIncompleteIncludeRestrictionFailsClosed() throws Exception {
        withPolicy("include", () -> assertThrows(QuicException.class, TlsAcceptancePolicyTest::policy));
    }
    private static AlgorithmConstraints denyPrimitive(CryptoPrimitive primitive, String algorithm) {
        return new AlgorithmConstraints() {
            public boolean permits(Set<CryptoPrimitive> p, String a, AlgorithmParameters params) {
                return !p.contains(primitive) || !a.equalsIgnoreCase(algorithm);
            }
            public boolean permits(Set<CryptoPrimitive> p, Key key) { return true; }
            public boolean permits(Set<CryptoPrimitive> p, String a, Key key, AlgorithmParameters params) {
                return permits(p, a, params);
            }
        };
    }
    @Test
    void staticRsaResumptionRetainsEncryptionKeyRestrictions() throws Exception {
        AlgorithmConstraints constraints = new AlgorithmConstraints() {
            public boolean permits(Set<CryptoPrimitive> p, String a, AlgorithmParameters params) { return true; }
            public boolean permits(Set<CryptoPrimitive> p, Key key) {
                return !p.contains(CryptoPrimitive.PUBLIC_KEY_ENCRYPTION);
            }
            public boolean permits(Set<CryptoPrimitive> p, String a, Key key, AlgorithmParameters params) {
                return permits(p, key);
            }
        };
        TlsAcceptancePolicy.Evidence evidence = new TlsAcceptancePolicy.Evidence(null, null, null,
                TestCerts.keyPair(TestCerts.KeyType.RSA).getPublic());
        withPolicy("", () -> assertThrows(QuicException.class,
                () -> new TlsAcceptancePolicy(null, constraints).evidence(evidence)));
    }

    @Test
    void includesAreAppliedAndCyclesAreRejected() throws Exception {
        String name = "microproxy.test.disabledAlgorithms";
        String previous = Security.getProperty(name);
        try {
            Security.setProperty(name, "X25519");
            withPolicy("include " + name, () -> assertThrows(QuicException.class,
                    () -> policy().group(NamedGroup.X25519, KeyExchange.generate(NamedGroup.X25519, new SecureRandom()).publicKey())));
            Security.setProperty(name, "include jdk.tls.disabledAlgorithms");
            withPolicy("include " + name, () -> assertThrows(QuicException.class, TlsAcceptancePolicyTest::policy));
        } finally { Security.setProperty(name, previous != null ? previous : ""); }
    }
}
