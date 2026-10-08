package org.microproxy.dns;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/** DNSSEC signature algorithms (RFC 8624) and DS digests mapped onto the JDK's providers. */
final class DnssecCrypto {

    private DnssecCrypto() {}

    static boolean supportsAlgorithm(int algorithm) {
        return switch (algorithm) {
            case 5, 7, 8, 10, 13, 14, 15, 16 -> true;
            default -> false;
        };
    }

    static boolean supportsDigest(int digestType) {
        return digestType == 1 || digestType == 2 || digestType == 4;
    }

    /** The digest of a DNSKEY for comparison with a DS record (RFC 4034 section 5.1.4). */
    static byte[] dsDigest(int digestType, DnsName owner, byte[] dnskeyRdata) throws GeneralSecurityException {
        String algorithm = switch (digestType) {
            case 1 -> "SHA-1";
            case 2 -> "SHA-256";
            case 4 -> "SHA-384";
            default -> throw new GeneralSecurityException("unsupported DS digest " + digestType);
        };
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(owner.toCanonicalWire());
        md.update(dnskeyRdata);
        return md.digest();
    }

    /** Verifies {@code signature} over {@code data} with a DNSKEY's public key material. */
    static boolean verify(int algorithm, byte[] publicKey, byte[] data, byte[] signature) {
        try {
            String jca = switch (algorithm) {
                case 5, 7 -> "SHA1withRSA";
                case 8 -> "SHA256withRSA";
                case 10 -> "SHA512withRSA";
                case 13 -> "SHA256withECDSAinP1363Format";
                case 14 -> "SHA384withECDSAinP1363Format";
                case 15 -> "Ed25519";
                case 16 -> "Ed448";
                default -> throw new GeneralSecurityException("unsupported algorithm " + algorithm);
            };
            Signature verifier = Signature.getInstance(jca);
            verifier.initVerify(publicKey(algorithm, publicKey));
            verifier.update(data);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    static PublicKey publicKey(int algorithm, byte[] key) throws GeneralSecurityException {
        return switch (algorithm) {
            case 5, 7, 8, 10 -> rsa(key);
            case 13 -> ec(key, "secp256r1", 32);
            case 14 -> ec(key, "secp384r1", 48);
            // Wrap the raw key in a SubjectPublicKeyInfo header (RFC 8410).
            case 15 -> edwards("Ed25519", "302a300506032b6570032100", key, 32);
            case 16 -> edwards("Ed448", "3043300506032b6571033a00", key, 57);
            default -> throw new GeneralSecurityException("unsupported algorithm " + algorithm);
        };
    }

    /** RFC 3110: exponent length (1 or 3 bytes), exponent, modulus. */
    private static PublicKey rsa(byte[] key) throws GeneralSecurityException {
        int expLen = key[0] & 0xff;
        int offset = 1;
        if (expLen == 0) {
            expLen = ((key[1] & 0xff) << 8) | (key[2] & 0xff);
            offset = 3;
        }
        BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(key, offset, offset + expLen));
        BigInteger modulus = new BigInteger(1, Arrays.copyOfRange(key, offset + expLen, key.length));
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    /** RFC 6605: the uncompressed point X || Y. */
    private static PublicKey ec(byte[] key, String curve, int size) throws GeneralSecurityException {
        if (key.length != size * 2) throw new GeneralSecurityException("bad EC key length");
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curve));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(new BigInteger(1, Arrays.copyOfRange(key, 0, size)),
                new BigInteger(1, Arrays.copyOfRange(key, size, size * 2)));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
    }

    private static PublicKey edwards(String algorithm, String spkiPrefixHex, byte[] key, int size)
            throws GeneralSecurityException {
        if (key.length != size) throw new GeneralSecurityException("bad EdDSA key length");
        byte[] prefix = HexFormat.of().parseHex(spkiPrefixHex);
        byte[] spki = DnsRecord.concat(prefix, key);
        return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(spki));
    }

    /** RFC 5155 section 5: iterated, salted SHA-1 of the canonical owner name. */
    static byte[] nsec3Hash(DnsName name, byte[] salt, int iterations) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(name.toCanonicalWire());
            sha1.update(salt);
            byte[] h = sha1.digest();
            for (int i = 0; i < iterations; i++) {
                sha1.update(h);
                sha1.update(salt);
                h = sha1.digest();
            }
            return h;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Decodes base32hex without padding (RFC 4648 section 7), as used in NSEC3 owner names. */
    static byte[] base32HexDecode(byte[] label) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (byte b : label) {
            int c = Character.toUpperCase((char) (b & 0xff));
            int v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'A' && c <= 'V') v = c - 'A' + 10;
            else return null;
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    /** Base32hex encoding without padding, lowercase. */
    static String base32HexEncode(byte[] data) {
        String alphabet = "0123456789abcdefghijklmnopqrstuv";
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(alphabet.charAt((buffer >> (bits - 5)) & 0x1f));
                bits -= 5;
            }
        }
        if (bits > 0) sb.append(alphabet.charAt((buffer << (5 - bits)) & 0x1f));
        return sb.toString();
    }

    static int compareUnsigned(byte[] a, byte[] b) {
        return Arrays.compareUnsigned(a, b);
    }
}
