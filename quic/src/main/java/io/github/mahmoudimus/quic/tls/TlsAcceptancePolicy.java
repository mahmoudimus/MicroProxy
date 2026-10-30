package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicException;
import java.math.BigInteger;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.XECKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPoint;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.interfaces.DHKey;

/**
 * Acceptance is independent of the captured ClientHello. Supported disabledAlgorithms syntax:
 * names, TLS suite wildcards, keySize predicates, includes and HandshakeSignature usage, including
 * conjunctions. Other syntax fails closed. No internal JDK APIs are used.
 */
final class TlsAcceptancePolicy {
    private static final Set<CryptoPrimitive> SIGNATURE = Set.of(CryptoPrimitive.SIGNATURE);
    private static final int MAX_ISSUER_VERIFICATIONS = 16;
    private static final Set<CryptoPrimitive> AGREEMENT = Set.of(CryptoPrimitive.KEY_AGREEMENT);
    private static final Pattern KEY_SIZE = Pattern.compile(
            "keySize\\s*(<=|>=|==|!=|<|>)\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
    private final Set<String> enabled;
    private final AlgorithmConstraints constraints;
    private final List<X509Certificate> acceptedIssuers;
    private final List<Rule> rules = new ArrayList<>();

    /** Missing evidence in old/QUIC tickets forces a full TCP handshake. */
    record Evidence(NamedGroup group, byte[] share, SignatureScheme signature, PublicKey signatureKey) {
        Evidence {
            share = share != null ? share.clone() : null;
        }

        @Override
        public byte[] share() {
            return share != null ? share.clone() : null;
        }
    }

    TlsAcceptancePolicy(String[] enabled, AlgorithmConstraints constraints) throws QuicException {
        this(enabled, constraints, new X509Certificate[0]);
    }

    TlsAcceptancePolicy(String[] enabled, AlgorithmConstraints constraints, X509Certificate[] acceptedIssuers)
            throws QuicException {
        this.enabled = enabled == null ? null : Set.copyOf(Arrays.asList(enabled));
        this.constraints = constraints;
        this.acceptedIssuers = acceptedIssuers != null
                ? List.copyOf(Arrays.asList(acceptedIssuers.clone())) : List.of();
        readProperty("jdk.tls.disabledAlgorithms", new HashSet<>());
    }

    private void readProperty(String property, Set<String> active) throws QuicException {
        if (!active.add(property)) throw rejected("cyclic disabledAlgorithms include: " + property);
        String value = Security.getProperty(property);
        if (value == null) throw rejected("missing disabledAlgorithms property: " + property);
        for (String entry : value.split(",", -1)) {
            String text = entry.trim();
            if (text.isEmpty()) {
                if (!value.isBlank()) throw rejected("empty disabledAlgorithms restriction");
                continue;
            }
            if (text.regionMatches(true, 0, "include ", 0, 8)) {
                String include = text.substring(8).trim();
                if (!include.matches("[A-Za-z0-9._]+")) {
                    throw rejected("unsupported disabledAlgorithms include: " + text);
                }
                readProperty(include, active);
                continue;
            }
            String[] parts = text.split("\\s+", 2);
            String algorithm = parts[0];
            if (algorithm.equalsIgnoreCase("include")) {
                throw rejected("incomplete disabledAlgorithms include: " + text);
            }
            if (!algorithm.matches("[A-Za-z0-9._/*+\\-]+")
                    || (algorithm.contains("*") && !algorithm.toUpperCase(Locale.ROOT).startsWith("TLS_"))) {
                throw rejected("unsupported disabledAlgorithms algorithm: " + text);
            }
            List<Condition> conditions = new ArrayList<>();
            if (parts.length == 2) {
                for (String condition : parts[1].split("\\s*&\\s*", -1)) {
                    Matcher size = KEY_SIZE.matcher(condition.trim());
                    if (size.matches()) {
                        int bits;
                        try {
                            bits = Integer.parseInt(size.group(2));
                        } catch (NumberFormatException e) {
                            throw rejected("invalid disabledAlgorithms key size: " + text);
                        }
                        if (!Set.of("RSA", "RSASSAPSS", "DSA", "DH", "DIFFIEHELLMAN", "EC", "XDH", "X25519", "X448",
                                "EDDSA", "ED25519", "ED448", "AES", "CHACHA20",
                                "SECP256R1", "SECP384R1", "SECP521R1").contains(canonical(algorithm))) {
                            throw rejected("unsupported disabledAlgorithms keySize algorithm: " + text);
                        }
                        conditions.add(new Condition(size.group(1), bits, false));
                    } else if (condition.trim().equalsIgnoreCase("usage HandshakeSignature")) {
                        conditions.add(new Condition(null, 0, true));
                    } else {
                        throw rejected("unsupported disabledAlgorithms restriction: " + text);
                    }
                }
            }
            rules.add(new Rule(algorithm, List.copyOf(conditions)));
        }
        active.remove(property);
    }

    void protocol(String protocol) throws QuicException {
        algorithm(AGREEMENT, protocol, null, null, false);
    }

    void suite(CipherSuite suite) throws QuicException {
        protocol("TLSv1.3");
        cipher(suite.name(), suite.aead(), suite.keyLength());
    }

    void suite(Tls12CipherSuite suite) throws QuicException {
        protocol("TLSv1.2");
        if (suite.bulk.cbc()) throw rejected("CBC cipher suites are not accepted: " + suite);
        String cipher = suite.bulk == Tls12CipherSuite.Bulk.CHACHA20_POLY1305
                ? "ChaCha20-Poly1305" : "AES/GCM/NoPadding";
        cipher(suite.name(), cipher, suite.bulk.keyLength);
    }

    private void cipher(String suite, String cipher, int length) throws QuicException {
        if (enabled != null && !enabled.contains(suite)) throw rejected("cipher suite is not enabled: " + suite);
        algorithm(AGREEMENT, suite, null, null, false);
        String keyAlgorithm = cipher.startsWith("AES") ? "AES" : "ChaCha20";
        Set<CryptoPrimitive> primitive = Set.of(cipher.startsWith("AES")
                ? CryptoPrimitive.BLOCK_CIPHER : CryptoPrimitive.STREAM_CIPHER);
        // The negotiated length is known now. Caller Key predicates wait for the real key install.
        checkRules(keyAlgorithm, length * 8, false);
        algorithm(primitive, cipher, null, null, false);
        algorithm(primitive, bulkName(cipher, length), null, null, false);
        for (String component : suite.substring(4).split("_WITH_|_")) {
            if (component.matches("SHA\\d+")) {
                Set<CryptoPrimitive> digest = Set.of(CryptoPrimitive.MESSAGE_DIGEST);
                algorithm(digest, component, null, null, false);
                algorithm(digest, component.replace("SHA", "SHA-"), null, null, false);
                algorithm(Set.of(CryptoPrimitive.MAC), "Hmac" + component, null, null, false);
            } else if (!component.matches("\\d+")) {
                algorithm(AGREEMENT, component, null, null, false);
            }
        }
    }

    /** Called on every record-key installation, including each TLS 1.3 key update. */
    void trafficKey(String suiteName, String transformation, Key key) throws QuicException {
        Set<CryptoPrimitive> primitive = Set.of(transformation.startsWith("AES")
                ? CryptoPrimitive.BLOCK_CIPHER : CryptoPrimitive.STREAM_CIPHER);
        algorithm(primitive, suiteName, key, null, false);
        algorithm(primitive, transformation, key, null, false);
        algorithm(primitive, bulkName(transformation, keySize(key) / 8), key, null, false);
    }

    private static String bulkName(String transformation, int keyLength) {
        return transformation.startsWith("AES") ? "AES_" + keyLength * 8 + "_GCM" : "CHACHA20_POLY1305";
    }

    void group(NamedGroup group, byte[] share) throws QuicException {
        if (group == null) throw rejected("unknown key exchange group");
        String name = group.curve() != null ? group.curve() : group == NamedGroup.X25519 ? "X25519" : "X25519MLKEM768";
        int bits = switch (group) {
            case SECP256R1 -> 256;
            case SECP384R1 -> 384;
            case SECP521R1 -> 521;
            case X25519, X25519_MLKEM768 -> 255;
        };
        checkRules(name, bits, false);
        if (group == NamedGroup.X25519_MLKEM768) {
            checkRules("X25519", 255, false);
            checkRules("XDH", 255, false);
            checkRules("ML-KEM", 768, false);
            checkRules("ML-KEM-768", 768, false);
            // JDK 21 cannot expose the ML-KEM half as a JCA Key. Retain all key restrictions.
            if (constraints != null) {
                throw rejected("AlgorithmConstraints cannot be fully applied to the hybrid group on this runtime");
            }
            return;
        }
        PublicKey key = decodeGroupKey(group, share);
        AlgorithmParameters params = null;
        if (group.curve() != null) {
            try {
                params = AlgorithmParameters.getInstance("EC");
                params.init(EcCurves.forName(group.curve()));
            } catch (GeneralSecurityException e) {
                throw rejected("cannot inspect group parameters");
            }
        }
        algorithm(AGREEMENT, name, key, params, false);
        // The JDK's bare ECDH deny entry means static ECDH suites. Caller constraints must also
        // see the actual JCA algorithm used for this ephemeral exchange.
        constrained(AGREEMENT, group.curve() != null ? "ECDH" : "XDH", key, params);
    }

    private static PublicKey decodeGroupKey(NamedGroup group, byte[] share) throws QuicException {
        try {
            if (share == null || share.length != group.publicKeyLength()) {
                throw rejected("invalid " + group + " key share");
            }
            if (group == NamedGroup.X25519) {
                byte[] big = share.clone();
                big[31] &= 0x7f;
                for (int i = 0; i < 16; i++) {
                    byte temporary = big[i];
                    big[i] = big[31 - i];
                    big[31 - i] = temporary;
                }
                return KeyFactory.getInstance("XDH").generatePublic(
                        new XECPublicKeySpec(NamedParameterSpec.X25519, new BigInteger(1, big)));
            }
            if (share[0] != 4) throw rejected("invalid " + group + " key share");
            int n = (share.length - 1) / 2;
            ECPoint point = new ECPoint(new BigInteger(1, Arrays.copyOfRange(share, 1, n + 1)),
                    new BigInteger(1, Arrays.copyOfRange(share, n + 1, share.length)));
            return KeyFactory.getInstance("EC").generatePublic(
                    new ECPublicKeySpec(point, EcCurves.forName(group.curve())));
        } catch (GeneralSecurityException | RuntimeException e) {
            throw rejected("cannot apply policy to " + group + " key share");
        }
    }

    void signature(SignatureScheme scheme, Key key) throws QuicException {
        if (scheme == null || key == null) throw rejected("missing authentication metadata");
        algorithm(SIGNATURE, scheme.name(), key, null, true);
        AlgorithmParameters params = null;
        if (scheme.pssHash() != null) {
            try {
                params = AlgorithmParameters.getInstance("RSASSA-PSS");
                String hash = scheme.pssHash();
                int size = hash.equals("SHA-256") ? 32 : hash.equals("SHA-384") ? 48 : 64;
                params.init(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), size, 1));
                algorithm(Set.of(CryptoPrimitive.MESSAGE_DIGEST), hash, null, null, true);
            } catch (GeneralSecurityException e) {
                throw rejected("cannot inspect PSS parameters");
            }
        }
        algorithm(SIGNATURE, scheme.jcaAlgorithm(), key, params, true);
    }

    void certificates(List<X509Certificate> chain) throws QuicException {
        if (chain.isEmpty()) throw rejected("missing peer certificates");
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            key(SIGNATURE, cert.getPublicKey(), false);
            // An accepted anchor's own certificate signature does not establish the chain.
            // Its public key is still constrained when it verifies a child's signature.
            if (acceptedIssuers.contains(cert)) continue;
            AlgorithmParameters params = null;
            if (cert.getSigAlgParams() != null) {
                try {
                    params = AlgorithmParameters.getInstance(cert.getSigAlgName());
                    params.init(cert.getSigAlgParams());
                } catch (GeneralSecurityException | java.io.IOException e) {
                    throw rejected("cannot inspect certificate signature parameters");
                }
            }
            if ("1.2.840.113549.1.1.10".equals(cert.getSigAlgOID())) {
                pssCertificateParameters(params);
            }
            algorithm(SIGNATURE, cert.getSigAlgName(), null, params, false);
            PublicKey issuer = verifiedIssuerKey(cert, chain);
            algorithm(SIGNATURE, cert.getSigAlgName(), issuer, params, false);
        }
    }

    /** Direct signer lookup only: no network, AIA fetches or certification-path search. */
    private PublicKey verifiedIssuerKey(X509Certificate certificate, List<X509Certificate> chain) throws QuicException {
        List<X509Certificate> candidates = new ArrayList<>(chain);
        candidates.addAll(acceptedIssuers);
        int attempts = 0;
        for (X509Certificate candidate : candidates) {
            if (!certificate.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) continue;
            if (attempts >= MAX_ISSUER_VERIFICATIONS) {
                throw rejected("certificate issuer verification budget exceeded");
            }
            attempts++;
            try {
                PublicKey issuerKey = candidate.getPublicKey();
                certificate.verify(issuerKey);
                return issuerKey;
            } catch (GeneralSecurityException | RuntimeException e) {
                // A matching name is insufficient; try another candidate within the same bound.
            }
        }
        throw rejected("cannot establish the certificate issuer key from the supplied chain and accepted issuers");
    }

    private void pssCertificateParameters(AlgorithmParameters parameters) throws QuicException {
        if (parameters == null) throw rejected("missing RSA-PSS certificate parameters");
        try {
            PSSParameterSpec pss = parameters.getParameterSpec(PSSParameterSpec.class);
            if (!"MGF1".equalsIgnoreCase(pss.getMGFAlgorithm())
                    || !(pss.getMGFParameters() instanceof MGF1ParameterSpec mgf)
                    || pss.getTrailerField() != 1) {
                throw rejected("unsupported RSA-PSS certificate parameters");
            }
            digest(pss.getDigestAlgorithm());
            algorithm(SIGNATURE, pss.getMGFAlgorithm(), null, null, false);
            digest(mgf.getDigestAlgorithm());
        } catch (GeneralSecurityException e) {
            throw rejected("cannot inspect RSA-PSS certificate parameters");
        }
    }

    private void digest(String name) throws QuicException {
        Set<CryptoPrimitive> primitive = Set.of(CryptoPrimitive.MESSAGE_DIGEST);
        algorithm(primitive, name, null, null, false);
        algorithm(primitive, canonical(name), null, null, false);
    }

    void rsaEncryptionKey(Key key) throws QuicException {
        if (key == null || !(key instanceof RSAKey) || !"RSA".equals(key.getAlgorithm())) {
            throw rejected("unsupported RSA premaster-encryption key");
        }
        Set<CryptoPrimitive> primitive = Set.of(CryptoPrimitive.PUBLIC_KEY_ENCRYPTION);
        algorithm(primitive, "RSA", key, null, false);
        algorithm(primitive, "RSA/ECB/PKCS1Padding", key, null, false);
    }

    void evidence(Evidence evidence) throws QuicException {
        if (evidence == null) throw rejected("session has no policy authentication metadata");
        if (evidence.group() != null) group(evidence.group(), evidence.share());
        if (evidence.signature() != null) signature(evidence.signature(), evidence.signatureKey());
        if (evidence.group() == null && evidence.signature() == null) {
            // Static RSA sessions authenticate through the premaster-encryption key.
            rsaEncryptionKey(evidence.signatureKey());
        }
    }

    private void algorithm(Set<CryptoPrimitive> primitive, String algorithm, Key key,
            AlgorithmParameters params, boolean handshakeSignature) throws QuicException {
        checkRules(algorithm, key != null ? keySize(key) : -1, handshakeSignature);
        if (key != null) key(primitive, key, handshakeSignature);
        constrained(primitive, algorithm, key, params);
    }

    private void constrained(Set<CryptoPrimitive> primitive, String algorithm, Key key,
            AlgorithmParameters params) throws QuicException {
        try {
            if (constraints != null && (!constraints.permits(primitive, algorithm, params)
                    || (key != null && !constraints.permits(primitive, algorithm, key, params)))) {
                throw rejected("AlgorithmConstraints reject " + algorithm);
            }
        } catch (RuntimeException e) {
            throw rejected("cannot apply AlgorithmConstraints to " + algorithm + ": " + e.getMessage());
        }
    }

    private void key(Set<CryptoPrimitive> primitive, Key key, boolean handshakeSignature) throws QuicException {
        int bits = keySize(key);
        if (bits < 0) {
            for (Rule rule : rules) {
                if (rule.matches(key.getAlgorithm()) && rule.conditions().stream().anyMatch(c -> !c.handshakeOnly())) {
                    throw rejected("cannot determine key size for " + key.getAlgorithm());
                }
            }
        }
        checkRules(key.getAlgorithm(), bits, handshakeSignature);
        if (key instanceof ECKey ec) {
            String curve = EcCurves.nameOf(ec.getParams());
            if (curve == null) throw rejected("cannot identify EC key curve");
            checkRules(curve, keySize(key), handshakeSignature);
        }
        if (key instanceof XECKey xec && xec.getParams() instanceof NamedParameterSpec named) {
            checkRules(named.getName(), bits, handshakeSignature);
        }
        if (key instanceof EdECKey ed) {
            checkRules(ed.getParams().getName(), bits, handshakeSignature);
        }
        if (constraints != null && !constraints.permits(primitive, key)) {
            throw rejected("AlgorithmConstraints reject " + key.getAlgorithm() + " key");
        }
    }

    private static int keySize(Key key) {
        if (key instanceof RSAKey rsa) return rsa.getModulus().bitLength();
        if (key instanceof ECKey ec) return ec.getParams().getOrder().bitLength();
        if (key instanceof DHKey dh) return dh.getParams().getP().bitLength();
        if (key instanceof XECKey) return 255;
        if (key instanceof EdECKey ed) return ed.getParams().getName().equalsIgnoreCase("Ed448") ? 448 : 255;
        if (key instanceof javax.crypto.SecretKey && key.getEncoded() != null) return key.getEncoded().length * 8;
        return -1;
    }

    private void checkRules(String algorithm, int bits, boolean handshakeSignature) throws QuicException {
        for (Rule rule : rules) {
            if (!rule.matches(algorithm)) continue;
            boolean denied = true;
            for (Condition condition : rule.conditions()) {
                if (condition.handshakeOnly()) {
                    denied &= handshakeSignature;
                } else if (bits < 0) {
                    denied = false; // checked when the corresponding key is available
                } else {
                    denied &= condition.matches(bits);
                }
            }
            if (denied) throw rejected("jdk.tls.disabledAlgorithms rejects " + algorithm);
        }
    }

    private record Condition(String operator, int bits, boolean handshakeOnly) {
        boolean matches(int size) {
            return switch (operator) {
                case "<" -> size < bits;
                case "<=" -> size <= bits;
                case ">" -> size > bits;
                case ">=" -> size >= bits;
                case "==" -> size == bits;
                case "!=" -> size != bits;
                default -> true;
            };
        }
    }

    private record Rule(String algorithm, List<Condition> conditions) {
        boolean matches(String candidate) {
            if (algorithm.contains("*")) {
                String regex = Arrays.stream(algorithm.split("\\*", -1))
                        .map(Pattern::quote).collect(java.util.stream.Collectors.joining(".*"));
                return Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(candidate).matches();
            }
            String wanted = canonical(algorithm);
            if (wanted.equals(canonical(candidate))) return true;
            for (String part : candidate.replaceAll("(?i)SHA-", "SHA").split("(?i)with|and|[/_]")) {
                if (wanted.equals(canonical(part))) return true;
            }
            return false;
        }
    }

    private static String canonical(String algorithm) {
        return algorithm.toUpperCase(Locale.ROOT).replace("-", "");
    }

    private static QuicException rejected(String message) {
        return TlsAlert.error(TlsAlert.HANDSHAKE_FAILURE, message);
    }
}
