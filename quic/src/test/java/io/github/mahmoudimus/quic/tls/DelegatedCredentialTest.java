package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** Delegated credentials (RFC 9345) checked as NSS checks them. */
class DelegatedCredentialTest {

    /** The schemes Firefox 159 offers for delegated credentials. */
    private static final int[] FIREFOX = {0x0403, 0x0503, 0x0603, 0x0203};

    private static final CertifiedKey DELEGATING = TestCerts.CA.issue(KeyType.P256, true, "dc.test");
    private static final CertifiedKey PLAIN = TestCerts.CA.issue(KeyType.P256, "dc.test");
    private static final KeyPair CREDENTIAL_KEY = p256();

    private static KeyPair p256() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A credential for {@code leaf}, valid until {@code until}, signed by {@code signer} with ECDSA P-256 SHA-256. */
    private static DelegatedCredential credential(X509Certificate leaf, PrivateKey signer, Instant until, int expected,
            PublicKey key) throws Exception {
        long validTime = Duration.between(leaf.getNotBefore().toInstant(), until).toSeconds();
        DelegatedCredential unsigned = new DelegatedCredential(validTime, expected, key.getEncoded(), 0x0403, new byte[0]);
        byte[] signature = Signatures.sign(SignatureScheme.ECDSA_SECP256R1_SHA256, signer,
                unsigned.signedContent(leaf.getEncoded()), new SecureRandom());
        return new DelegatedCredential(validTime, expected, key.getEncoded(), 0x0403, signature);
    }

    private static DelegatedCredential valid() throws Exception {
        return credential(DELEGATING.chain().get(0), DELEGATING.privateKey(), Instant.now().plus(Duration.ofDays(1)),
                0x0403, CREDENTIAL_KEY.getPublic());
    }

    private static int alert(Executable e) {
        return TlsAlert.fromErrorCode(assertThrows(QuicException.class, e::run).code());
    }

    @FunctionalInterface
    private interface Executable {
        void run() throws Exception;
    }

    @Test
    void aValidCredentialGivesItsKeyForTheCertificateVerify() throws Exception {
        DelegatedCredential dc = valid();
        dc.checkOffered(FIREFOX);
        PublicKey key = dc.verify(DELEGATING.chain().get(0), 0x0403, Instant.now());
        assertArrayEquals(CREDENTIAL_KEY.getPublic().getEncoded(), key.getEncoded());
    }

    @Test
    void itRoundTripsThroughItsWireForm() throws Exception {
        DelegatedCredential dc = valid();
        Writer w = new Writer();
        w.u32(dc.validTime()).u16(dc.expectedCertVerifyAlgorithm()).vector24(dc.publicKeyInfo()).u16(dc.algorithm())
                .vector16(dc.signature());
        DelegatedCredential decoded = DelegatedCredential.decode(w.toByteArray());
        assertEquals(dc.validTime(), decoded.validTime());
        assertArrayEquals(dc.signature(), decoded.signature());
        decoded.verify(DELEGATING.chain().get(0), 0x0403, Instant.now());
    }

    @Test
    void schemesTheClientDidNotOfferAreRefused() throws Exception {
        DelegatedCredential dc = valid();
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, alert(() -> dc.checkOffered(new int[] {0x0503})));
        DelegatedCredential rsae = new DelegatedCredential(dc.validTime(), 0x0804, dc.publicKeyInfo(), 0x0403, dc.signature());
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, alert(() -> rsae.checkOffered(new int[] {0x0804, 0x0403})));
    }

    @Test
    void theCertificateVerifyMustUseTheCredentialsScheme() throws Exception {
        DelegatedCredential dc = valid();
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, alert(() -> dc.verify(DELEGATING.chain().get(0), 0x0503, Instant.now())));
    }

    @Test
    void aCredentialSignedByAnotherKeyIsRefused() throws Exception {
        DelegatedCredential forged = credential(DELEGATING.chain().get(0), p256().getPrivate(),
                Instant.now().plus(Duration.ofDays(1)), 0x0403, CREDENTIAL_KEY.getPublic());
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, alert(() -> forged.verify(DELEGATING.chain().get(0), 0x0403, Instant.now())));
    }

    @Test
    void aCertificateWithoutDelegationUsageIsRefused() throws Exception {
        DelegatedCredential dc = credential(PLAIN.chain().get(0), PLAIN.privateKey(), Instant.now().plus(Duration.ofDays(1)),
                0x0403, CREDENTIAL_KEY.getPublic());
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, alert(() -> dc.verify(PLAIN.chain().get(0), 0x0403, Instant.now())));
    }

    @Test
    void anExpiredCredentialAndOneValidForOverSevenDaysAreRefused() throws Exception {
        X509Certificate leaf = DELEGATING.chain().get(0);
        DelegatedCredential expired = credential(leaf, DELEGATING.privateKey(), Instant.now().minus(Duration.ofHours(1)),
                0x0403, CREDENTIAL_KEY.getPublic());
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, alert(() -> expired.verify(leaf, 0x0403, Instant.now())));
        DelegatedCredential tooLong = credential(leaf, DELEGATING.privateKey(), Instant.now().plus(Duration.ofDays(8)),
                0x0403, CREDENTIAL_KEY.getPublic());
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, alert(() -> tooLong.verify(leaf, 0x0403, Instant.now())));
    }
}
