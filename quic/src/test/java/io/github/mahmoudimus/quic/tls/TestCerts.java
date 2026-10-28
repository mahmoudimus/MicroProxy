package io.github.mahmoudimus.quic.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Test certificates made at runtime with nothing but the JDK, adapted from MicroProxy's {@code
 * org.microproxy.tls.CertificateBuilder} and {@code Der}, which this self-contained module cannot
 * depend on. Authorities have P-256 keys and sign with ECDSA; leaves can have P-256, P-384, P-521, RSA
 * or Ed25519 keys.
 */
public final class TestCerts {

    /** The key types a leaf can have. */
    public enum KeyType {
        P256, P384, P521, RSA, ED25519
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<KeyType, KeyPair> KEYS = new ConcurrentHashMap<>();

    /** The authority the tests trust. */
    public static final Authority CA = new Authority("Test CA");
    /** An authority nobody trusts. */
    public static final Authority OTHER_CA = new Authority("Untrusted CA");

    private TestCerts() {}

    /** A key pair of each type, made once: RSA key generation is slow. */
    public static KeyPair keyPair(KeyType type) {
        return KEYS.computeIfAbsent(type, TestCerts::generate);
    }

    private static KeyPair generate(KeyType type) {
        return generate(type, RANDOM);
    }

    private static KeyPair generate(KeyType type, SecureRandom random) {
        try {
            return switch (type) {
                case P256 -> ec("secp256r1", random);
                case P384 -> ec("secp384r1", random);
                case P521 -> ec("secp521r1", random);
                case RSA -> {
                    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                    gen.initialize(2048, random);
                    yield gen.generateKeyPair();
                }
                case ED25519 -> {
                    KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
                    gen.initialize(java.security.spec.NamedParameterSpec.ED25519, random);
                    yield gen.generateKeyPair();
                }
            };
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair ec(String curve, SecureRandom random) throws GeneralSecurityException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec(curve), random);
        return gen.generateKeyPair();
    }

    /**
     * A deterministic random source: the same seed gives the same bytes in every run, which makes
     * keys, signatures and anything else drawn from it reproducible. For tests only.
     *
     * @param seed the seed
     * @return a seeded generator
     */
    public static SecureRandom seededRandom(long seed) {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(seed); // before any output, this replaces the system seed
            return random;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * An authority whose keys, serial numbers, signatures and validity come from a seed, so that its
     * certificates are byte for byte the same in every run.
     *
     * @param name the authority's common name
     * @param seed the seed
     * @return the authority
     */
    public static Authority seeded(String name, long seed) {
        return new Authority(name, seededRandom(seed), Instant.parse("2025-01-01T00:00:00Z"));
    }

    public static X509TrustManager trustManager(X509Certificate... anchors) {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            for (int i = 0; i < anchors.length; i++) store.setCertificateEntry("ca" + i, anchors[i]);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(store);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager x509) return x509;
            }
            throw new IllegalStateException("no X509TrustManager");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A certificate authority with a P-256 key. */
    public static final class Authority {
        public final KeyPair key;
        public final X509Certificate certificate;
        /** The seeded source of a deterministic authority, or null. */
        private final SecureRandom random;
        /** The fixed start of validity of a deterministic authority, or null for a day ago. */
        private final Instant validFrom;
        private final Map<KeyType, KeyPair> leafKeys = new ConcurrentHashMap<>();

        Authority(String name) {
            this(name, null, null);
        }

        private Authority(String name, SecureRandom random, Instant validFrom) {
            this.random = random;
            this.validFrom = validFrom;
            key = random != null ? generate(KeyType.P256, random) : generate(KeyType.P256);
            certificate = sign(name, key.getPublic(), key.getPrivate(), null, true, List.of());
        }

        public X509TrustManager trustManager() {
            return TestCerts.trustManager(certificate);
        }

        /** A leaf for {@code names} (DNS names or IP literals) with the shared key of {@code type}. */
        public CertifiedKey issue(KeyType type, String... names) {
            return issue(type, false, names);
        }

        /**
         * A leaf as {@link #issue(KeyType, String...)}, with the DelegationUsage extension when
         * {@code delegation}: one that may sign delegated credentials (RFC 9345 section 4.2).
         */
        public CertifiedKey issue(KeyType type, boolean delegation, String... names) {
            KeyPair pair = random != null ? leafKeys.computeIfAbsent(type, t -> generate(t, random)) : keyPair(type);
            X509Certificate leaf = sign(names.length > 0 ? names[0] : "leaf", pair.getPublic(), key.getPrivate(),
                    certificate, false, List.of(names), delegation);
            return CertifiedKey.of(pair.getPrivate(), leaf, certificate);
        }

        private X509Certificate sign(String cn, PublicKey subjectKey, PrivateKey signingKey, X509Certificate issuer,
                boolean ca, List<String> sans) {
            return sign(cn, subjectKey, signingKey, issuer, ca, sans, false);
        }

        private X509Certificate sign(String cn, PublicKey subjectKey, PrivateKey signingKey, X509Certificate issuer,
                boolean ca, List<String> sans, boolean delegation) {
            try {
                byte[] algorithm = sequence(oid("1.2.840.10045.4.3.2"));
                byte[] subject = name(cn);
                byte[] issuerName = issuer != null ? issuer.getSubjectX500Principal().getEncoded() : subject;
                List<byte[]> extensions = new ArrayList<>();
                extensions.add(extension("2.5.29.19", true,
                        ca ? sequence(bool(true), integer(BigInteger.ZERO)) : sequence()));
                // a leaf signs; an RSA leaf may also take an RSA-encrypted premaster (TLS 1.2 key transport)
                extensions.add(extension("2.5.29.15", true, ca
                        ? bitString(new byte[] {(byte) 0x86}, 1)
                        : "RSA".equals(subjectKey.getAlgorithm())
                                ? bitString(new byte[] {(byte) 0xa0}, 5)
                                : bitString(new byte[] {(byte) 0x80}, 7)));
                if (!ca) {
                    extensions.add(extension("2.5.29.37", false,
                            sequence(oid("1.3.6.1.5.5.7.3.1"), oid("1.3.6.1.5.5.7.3.2"))));
                }
                if (!sans.isEmpty()) {
                    List<byte[]> names = new ArrayList<>();
                    for (String san : sans) {
                        names.add(HostnameChecker.isIpLiteral(san)
                                ? tlv(0x87, InetAddress.getByName(san).getAddress())
                                : tlv(0x82, san.getBytes(StandardCharsets.US_ASCII)));
                    }
                    extensions.add(extension("2.5.29.17", false, sequence(names.toArray(byte[][]::new))));
                }
                if (delegation) extensions.add(extension(DelegatedCredential.DELEGATION_USAGE_OID, false, new byte[] {0x05, 0x00}));
                extensions.add(extension("2.5.29.14", false, tlv(0x04, keyId(subjectKey))));
                PublicKey authorityKey = issuer != null ? issuer.getPublicKey() : subjectKey;
                extensions.add(extension("2.5.29.35", false, sequence(tlv(0x80, keyId(authorityKey)))));
                Instant from = validFrom != null ? validFrom : Instant.now().minusSeconds(86_400);
                Instant until = validFrom != null ? Instant.parse("2045-01-01T00:00:00Z") : from.plusSeconds(366L * 86_400);
                byte[] tbs = sequence(
                        tlv(0xa0, integer(BigInteger.TWO)),
                        integer(new BigInteger(63, random != null ? random : RANDOM).add(BigInteger.ONE)),
                        algorithm,
                        issuerName,
                        sequence(time(from), time(until)),
                        subject,
                        subjectKey.getEncoded(),
                        tlv(0xa3, sequence(extensions.toArray(byte[][]::new))));
                Signature signature = Signature.getInstance("SHA256withECDSA");
                if (random != null) {
                    signature.initSign(signingKey, random);
                } else {
                    signature.initSign(signingKey);
                }
                signature.update(tbs);
                byte[] der = sequence(tbs, algorithm, bitString(signature.sign(), 0));
                return (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(der));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // --- the DER encodings an X.509 certificate needs ---

    static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 6);
        out.write(tag);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else {
            int bytes = len > 0xffffff ? 4 : len > 0xffff ? 3 : len > 0xff ? 2 : 1;
            out.write(0x80 | bytes);
            for (int i = bytes - 1; i >= 0; i--) out.write(len >>> (8 * i));
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] sequence(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return tlv(0x30, out.toByteArray());
    }

    private static byte[] integer(BigInteger value) {
        return tlv(0x02, value.toByteArray());
    }

    private static byte[] bool(boolean value) {
        return tlv(0x01, new byte[] {(byte) (value ? 0xff : 0)});
    }

    private static byte[] bitString(byte[] value, int unusedBits) {
        byte[] content = new byte[value.length + 1];
        content[0] = (byte) unusedBits;
        System.arraycopy(value, 0, content, 1, value.length);
        return tlv(0x03, content);
    }

    private static byte[] oid(String dotted) {
        String[] arcs = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        base128(out, Long.parseLong(arcs[0]) * 40 + Long.parseLong(arcs[1]));
        for (int i = 2; i < arcs.length; i++) base128(out, Long.parseLong(arcs[i]));
        return tlv(0x06, out.toByteArray());
    }

    private static void base128(ByteArrayOutputStream out, long value) {
        int groups = 1;
        for (long v = value >>> 7; v != 0; v >>>= 7) groups++;
        for (int i = groups - 1; i >= 0; i--) {
            int b = (int) ((value >>> (7 * i)) & 0x7f);
            out.write(i == 0 ? b : b | 0x80);
        }
    }

    private static byte[] name(String commonName) {
        byte[] cn = sequence(oid("2.5.4.3"), tlv(0x0c, commonName.getBytes(StandardCharsets.UTF_8)));
        return sequence(tlv(0x31, cn));
    }

    private static byte[] extension(String oid, boolean critical, byte[] value) {
        return critical
                ? sequence(oid(oid), bool(true), tlv(0x04, value))
                : sequence(oid(oid), tlv(0x04, value));
    }

    private static byte[] time(Instant instant) {
        String utc = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").format(instant.atZone(ZoneOffset.UTC));
        return tlv(0x17, utc.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] keyId(PublicKey key) throws GeneralSecurityException {
        return Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(key.getEncoded()), 20);
    }
}
