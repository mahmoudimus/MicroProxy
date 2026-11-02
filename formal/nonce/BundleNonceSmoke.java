// Independent production nonce execution smoke for the minimized bundle.
//
// This file is a test harness, not production code. It is compiled into a
// dedicated temporary directory and run against the actual minimized bundle
// only: the bundle contains the byte-checked 37-class Dafny runtime, and there
// is no external runtime jar on the execution classpath. It first *executes*
// PacketKey.nonce,
// PacketKey.seal and PacketKey.open, then independently recomputes the nonce
// with the frozen pre-adoption clone/XOR algorithm and the ciphertext with a
// separate JCE Cipher instance. Class.forName is used only afterwards to assert
// the loaded class origins. No test/reference class may be present in the
// bundle.
package nonceadoption;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.crypto.PacketKey;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.ZipFile;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Executes the adopted nonce path and compares it with independent oracles. */
public final class BundleNonceSmoke {
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH = 16;
    private static final int HEADER_LENGTH = 20;
    private static final int PAYLOAD_LENGTH = 64;
    private static final long[] PACKET_NUMBERS = {0L, 1L, -1L};
    private static final byte[] IV = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b
    };
    private static final String[] FORBIDDEN_BUNDLE_ENTRIES = {
        "io/github/mahmoudimus/nonce/ReferenceNonce.class",
        "io/github/mahmoudimus/nonce/GeneratedNonceTest.class",
        "io/github/mahmoudimus/nonce/bench/NonceBenchmark.class",
        "io/github/mahmoudimus/nonce/packetbench/PacketKeyBenchmark.class"
    };
    // Fixed ciphertext digests produced by the independent manual oracle in
    // record mode. They depend only on the suite keystream, IV, header,
    // plaintext and packet number, never on the generated class.
    private static final String[][] EXPECTED_CIPHERTEXT = {
        {"TLS_AES_128_GCM_SHA256", "0", "29e281acfb6f5c679a5de4f933538bcce76b8fdac872596412735a473b476467"},
        {"TLS_AES_128_GCM_SHA256", "1", "0aa0d9210091eb00e8ec3e2827d4c207299b1748ccec1c28702d4066a018d0a2"},
        {"TLS_AES_128_GCM_SHA256", "-1", "777109a49fae39d4df0b4e39bd65fc18a0a8898fb62bde879960ccb6f18b91d5"},
        {"TLS_AES_256_GCM_SHA384", "0", "f994d5d9f395b9180f300047a274c7525d1ddc186c57d529504ae6956c8369ee"},
        {"TLS_AES_256_GCM_SHA384", "1", "9d0f51d8fccf47e68fb0959ac776d141c7bb32d21898ffd992564c19d3d25875"},
        {"TLS_AES_256_GCM_SHA384", "-1", "51847a86d413252d394444794b0bbd9099c6202a3f6ee458907ad46718dd2d8b"},
        {"TLS_CHACHA20_POLY1305_SHA256", "0", "c97bce4ef824ce2228c578a5e59577961c98f25851280a983d9a0da60b7d15f5"},
        {"TLS_CHACHA20_POLY1305_SHA256", "1", "0369d7668124e2f79e2d37f79fc742a5a223c774179519272ee6ea18855a9502"},
        {"TLS_CHACHA20_POLY1305_SHA256", "-1", "81cb50b45ad6c8ccc61a48a5bcb92631f78abdf11e35b5bf4223f369f4fd5aae"}
    };

    private BundleNonceSmoke() {}

    /** Frozen pre-adoption clone/XOR nonce, independent of the generated class. */
    private static byte[] referenceNonce(long packetNumber) {
        byte[] nonce = IV.clone();
        for (int i = 0; i < 8; i++) {
            nonce[NONCE_LENGTH - 1 - i] ^= (byte) (packetNumber >>> (8 * i));
        }
        return nonce;
    }

    private static byte[] key(CipherSuite suite) {
        byte[] key = new byte[suite.keyLength()];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (0x40 + 11 * i);
        }
        return key;
    }

    private static byte[] header() {
        byte[] header = new byte[HEADER_LENGTH];
        for (int i = 0; i < header.length; i++) {
            header[i] = (byte) (0x90 + i);
        }
        return header;
    }

    private static byte[] plaintext() {
        byte[] plaintext = new byte[PAYLOAD_LENGTH];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (0xa5 ^ i);
        }
        return plaintext;
    }

    /** Independent seal: reference nonce plus a separate JCE Cipher instance. */
    private static byte[] manualSeal(CipherSuite suite, long packetNumber) throws Exception {
        Cipher cipher = Cipher.getInstance(suite.aead());
        byte[] nonce = referenceNonce(packetNumber);
        if (suite.aes()) {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key(suite), "AES"),
                    new GCMParameterSpec(TAG_LENGTH * 8, nonce));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key(suite), "ChaCha20"),
                    new IvParameterSpec(nonce));
        }
        cipher.updateAAD(header());
        return cipher.doFinal(plaintext());
    }

    private static String digest(byte[] value) throws Exception {
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static String expectedCiphertext(CipherSuite suite, long packetNumber) {
        for (String[] row : EXPECTED_CIPHERTEXT) {
            if (row[0].equals(suite.name()) && Long.parseLong(row[1]) == packetNumber) {
                return row[2];
            }
        }
        throw new AssertionError("No fixed ciphertext digest for " + suite + " " + packetNumber);
    }

    private static void origin(Class<?> type, Path expected, String label) throws Exception {
        Path actual = Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI())
                .toRealPath();
        if (!actual.equals(expected.toRealPath())) {
            throw new AssertionError(label + " origin " + actual + " is not " + expected);
        }
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("bundle harness-dir record");
        }
        Path bundle = Path.of(args[0]).toRealPath();
        Path harness = Path.of(args[1]).toRealPath();
        boolean record = Boolean.parseBoolean(args[2]);

        List<String> rows = new ArrayList<>();
        int covered = 0;
        for (CipherSuite suite : CipherSuite.values()) {
            PacketKey packetKey = PacketKey.of(suite, key(suite), IV);
            for (long packetNumber : PACKET_NUMBERS) {
                // 1) Execute the adopted production path.
                byte[] nonce = packetKey.nonce(packetNumber);
                byte[] expectedNonce = referenceNonce(packetNumber);
                if (!Arrays.equals(expectedNonce, nonce)) {
                    throw new AssertionError("nonce mismatch for " + suite + " " + packetNumber);
                }
                byte[] header = header();
                byte[] plaintext = plaintext();
                byte[] packet = new byte[HEADER_LENGTH + PAYLOAD_LENGTH + TAG_LENGTH];
                System.arraycopy(header, 0, packet, 0, HEADER_LENGTH);
                System.arraycopy(plaintext, 0, packet, HEADER_LENGTH, PAYLOAD_LENGTH);
                int end = packetKey.seal(packetNumber, packet, 0, HEADER_LENGTH,
                        HEADER_LENGTH + PAYLOAD_LENGTH);
                byte[] ciphertext = Arrays.copyOfRange(packet, HEADER_LENGTH, end);
                byte[] expectedCiphertext = manualSeal(suite, packetNumber);
                if (!Arrays.equals(expectedCiphertext, ciphertext)) {
                    throw new AssertionError("seal ciphertext mismatch for " + suite + " " + packetNumber);
                }
                String ciphertextDigest = digest(ciphertext);
                if (record) {
                    System.out.println("RECORD " + suite.name() + " " + packetNumber + " " + ciphertextDigest);
                } else if (!expectedCiphertext(suite, packetNumber).equals(ciphertextDigest)) {
                    throw new AssertionError("fixed ciphertext digest mismatch for " + suite
                            + " " + packetNumber + ": " + ciphertextDigest);
                }
                int opened = packetKey.open(packetNumber, packet, 0, HEADER_LENGTH, end);
                if (opened != HEADER_LENGTH + PAYLOAD_LENGTH
                        || !Arrays.equals(plaintext,
                                Arrays.copyOfRange(packet, HEADER_LENGTH, opened))) {
                    throw new AssertionError("open round trip failed for " + suite + " " + packetNumber);
                }
                rows.add("{\"suite\":\"" + suite + "\",\"packet_number\":" + packetNumber
                        + ",\"nonce\":\"" + HexFormat.of().formatHex(nonce)
                        + "\",\"ciphertext_sha256\":\"" + ciphertextDigest + "\"}");
                covered++;
            }
        }
        if (covered != 9) {
            throw new AssertionError("expected 9 nonce seal/open cases, covered " + covered);
        }

        // 2) Only after the production calls, assert the loaded origins.
        origin(PacketKey.class, bundle, "PacketKey");
        origin(Class.forName(
                "io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default"),
                bundle, "VerifiedNonce");
        // The Dafny runtime must come from the same actual bundle, not an
        // external fallback jar. bundle_checks separately proves those 37
        // bundled classes are byte-identical to the pinned Maven runtime.
        origin(dafny.Helpers.class, bundle, "DafnyRuntime");
        origin(BundleNonceSmoke.class, harness, "nonce harness");

        if (record) {
            System.out.println("RECORD-COMPLETE cases=" + covered);
            return;
        }
        // 3) The production bundle must not contain test/reference/benchmark classes.
        try (ZipFile jar = new ZipFile(bundle.toFile())) {
            for (String entry : FORBIDDEN_BUNDLE_ENTRIES) {
                if (jar.getEntry(entry) != null) {
                    throw new AssertionError("test/reference class in production bundle: " + entry);
                }
            }
        }
        System.out.println("{\"schema\":\"microproxy.nonce-bundle-smoke/v1\",\"cases\":" + covered
                + ",\"passed\":" + covered
                + ",\"origins\":{\"PacketKey\":\"" + jsonEscape(bundle.toString())
                + "\",\"VerifiedNonce\":\"" + jsonEscape(bundle.toString())
                + "\",\"DafnyRuntime\":\"" + jsonEscape(bundle.toString())
                + "\",\"harness\":\"" + jsonEscape(harness.toString()) + "\"}"
                + ",\"cases_detail\":[" + String.join(",", rows) + "]}");
    }
}
