package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/**
 * Regression coverage for the generated-Java HKDF adoption. Published vectors are from RFC 5869
 * appendix A and RFC 9001 appendix A; the SHA-384 extension fixture is the independently computed
 * value already used by the formal replay. The independent {@link Mac} oracle below detects
 * boundary/adapter regressions over a finite corpus; it is not a proof of the JCE provider or of
 * all Java inputs.
 */
class HkdfGeneratedAdoptionTest {
    private static final byte[] EMPTY = new byte[0];

    private static byte[] hex(String text) {
        return HexFormat.of().parseHex(text.replace(" ", ""));
    }

    @Test
    void rfc5869AppendixA() {
        byte[] ikm = repeated(0x0b, 22);
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        byte[] prk = Hkdf.SHA256.extract(salt, ikm);
        assertArrayEquals(hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk);
        assertArrayEquals(hex("3cb25f25faacd57a90434f64d0362f2a"
                + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865"), Hkdf.SHA256.expand(prk, info, 42));

        byte[] longPrk = Hkdf.SHA256.extract(range(0x60, 80), range(0, 80));
        assertArrayEquals(hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"), longPrk);
        assertArrayEquals(hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                + "cc30c58179ec3e87c14c01d5c1f3434f1d87"), Hkdf.SHA256.expand(longPrk, range(0xb0, 80), 82));

        byte[] emptyPrk = Hkdf.SHA256.extract(EMPTY, repeated(0x0b, 22));
        assertArrayEquals(hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
                emptyPrk);
        assertArrayEquals(hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                + "9d201395faa4b61a96c8"), Hkdf.SHA256.expand(emptyPrk, EMPTY, 42));
    }

    @Test
    void sha384ExtractAndExpandFixture() {
        byte[] ikm = repeated(0x0b, 22);
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        byte[] prk = Hkdf.SHA384.extract(salt, ikm);
        assertArrayEquals(hex("704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8de"
                + "c70ee9a7e1f3e293ef68eceb072a5ade"), prk);
        assertArrayEquals(hex("9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f7"
                + "48b6457763e4f0204fc5"), Hkdf.SHA384.expand(prk, info, 42));
    }

    @Test
    void rfc9001InitialSecretsAndKeySchedule() {
        byte[] initial = Hkdf.SHA256.extract(hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
                hex("8394c8f03e515708"));
        assertArrayEquals(hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"), initial);

        String[][] sides = {
            {"client in", "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
                "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c",
                "9f50449e04a0e810283a1e9933adedd2"},
            {"server in", "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
                "cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e",
                "c206b8d9b9f0f37644430b490eeaa314"}
        };
        for (String[] side : sides) {
            byte[] secret = Hkdf.SHA256.expandLabel(initial, side[0], EMPTY, 32);
            assertArrayEquals(hex(side[1]), secret);
            assertArrayEquals(hex(side[2]), Hkdf.SHA256.expandLabel(secret, "quic key", EMPTY, 16));
            assertArrayEquals(hex(side[3]), Hkdf.SHA256.expandLabel(secret, "quic iv", EMPTY, 12));
            assertArrayEquals(hex(side[4]), Hkdf.SHA256.expandLabel(secret, "quic hp", EMPTY, 16));
        }

        byte[] chacha = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        assertArrayEquals(hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
                Hkdf.SHA256.expandLabel(chacha, "quic key", EMPTY, 32));
        assertArrayEquals(hex("e0459b3474bdd0e44a41c144"),
                Hkdf.SHA256.expandLabel(chacha, "quic iv", EMPTY, 12));
        assertArrayEquals(hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
                Hkdf.SHA256.expandLabel(chacha, "quic hp", EMPTY, 32));
        assertArrayEquals(hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"),
                Hkdf.SHA256.expandLabel(chacha, "quic ku", EMPTY, 32));
    }

    @Test
    void labelSerializationAndBounds() {
        assertArrayEquals(hex("00200f746c73313320636c69656e7420696e00"),
                Hkdf.labelInfo("client in", EMPTY, 32));
        assertArrayEquals(hex("00200f746c7331332073657276657220696e00"),
                Hkdf.labelInfo("server in", EMPTY, 32));
        assertArrayEquals(hex("00100e746c7331332071756963206b657900"),
                Hkdf.labelInfo("quic key", EMPTY, 16));
        assertArrayEquals(hex("000c0d746c733133207175696320697600"),
                Hkdf.labelInfo("quic iv", EMPTY, 12));
        assertArrayEquals(hex("00100d746c733133207175696320687000"),
                Hkdf.labelInfo("quic hp", EMPTY, 16));
        // Empty suffix labels and the historical unsigned length/context octets stay accepted.
        assertArrayEquals(hex("000006746c7331332000"), Hkdf.labelInfo("", EMPTY, 0));
        assertArrayEquals(hex("010009746c73313320007f3f0180"),
                Hkdf.labelInfo("\0\177?", hex("80"), 256));

        String maxLabel = "a".repeat(249);
        byte[] maxContext = range(0x80, 255);
        assertArrayEquals(referenceLabel(maxLabel, maxContext, 65535),
                Hkdf.labelInfo(maxLabel, maxContext, 65535));
        assertArrayEquals(Hkdf.SHA256.expand(new byte[] {1}, referenceLabel(maxLabel, maxContext, 1), 1),
                Hkdf.SHA256.expandLabel(new byte[] {1}, maxLabel, maxContext, 1));

        assertThrows(IllegalArgumentException.class, () -> Hkdf.labelInfo("a".repeat(250), EMPTY, 0));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.labelInfo("", new byte[256], 0));
        for (int length : new int[] {-1, Integer.MIN_VALUE, 65536, Integer.MAX_VALUE}) {
            assertThrows(IllegalArgumentException.class,
                    () -> Hkdf.labelInfo("", EMPTY, length), "label length " + length);
            assertThrows(IllegalArgumentException.class,
                    () -> Hkdf.SHA256.expandLabel(new byte[] {1}, "key", EMPTY, length),
                    "expandLabel length " + length);
        }
    }

    @Test
    void unicodeLabelsNeverAliasAsciiEncoding() {
        String[] rejected = {"\u0080", "caf\u00e9", "\u0100", "\u0161", "\uff7f", "\u8000",
            "\uffff", "\ud800", "\udc00", "traffic upd\ud83d\udd10", "caf?\ud800"};
        for (String label : rejected) {
            assertThrows(IllegalArgumentException.class, () -> Hkdf.labelInfo(label, EMPTY, 0), label);
            assertThrows(IllegalArgumentException.class,
                    () -> Hkdf.SHA256.expandLabel(new byte[] {1}, label, EMPTY, 16), label);
            assertThrows(IllegalArgumentException.class,
                    () -> Hkdf.SHA384.expandLabel(new byte[] {1}, label, EMPTY, 16), label);
        }
        assertArrayEquals(referenceLabel("\0a\177?", EMPTY, 1), Hkdf.labelInfo("\0a\177?", EMPTY, 1));
    }

    @Test
    void lengthAndKeyLimitsPreserveHistoricalErrors() {
        for (Hkdf hkdf : new Hkdf[] {Hkdf.SHA256, Hkdf.SHA384}) {
            int hashLength = hkdf.hashLength();
            assertTrue(hashLength == 32 || hashLength == 48);
            for (int length : new int[] {-1, Integer.MIN_VALUE,
                    255 * hashLength + 1, Integer.MAX_VALUE}) {
                IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                        () -> hkdf.expand(new byte[] {1}, EMPTY, length));
                assertEquals("HKDF output length " + length, error.getMessage());
                // The historical order rejects length before the empty/null PRK.
                assertEquals("HKDF output length " + length, assertThrows(IllegalArgumentException.class,
                        () -> hkdf.expand(EMPTY, EMPTY, length)).getMessage());
                assertEquals("HKDF output length " + length, assertThrows(IllegalArgumentException.class,
                        () -> hkdf.expand(null, EMPTY, length)).getMessage());
            }
            for (int length : new int[] {0, 1, hashLength}) {
                IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                        () -> hkdf.expand(EMPTY, EMPTY, length));
                assertEquals("Empty key", error.getMessage());
            }
            assertEquals("Missing argument", assertThrows(IllegalArgumentException.class,
                    () -> hkdf.expand(null, EMPTY, 16)).getMessage());
        }
    }

    @Test
    void zeroLengthOutputsAreFreshAndDoNotCallTheProvider() {
        byte[] prk = {(byte) 0xff};
        byte[] a = Hkdf.SHA256.expand(prk, EMPTY, 0);
        byte[] b = Hkdf.SHA256.expand(prk, EMPTY, 0);
        byte[] c = Hkdf.SHA256.expandLabel(prk, "", EMPTY, 0);
        byte[] d = Hkdf.SHA256.expandLabel(prk, "", EMPTY, 0);
        assertEquals(0, a.length);
        assertEquals(0, c.length);
        assertNotSame(a, b);
        assertNotSame(c, d);
        assertNotSame(a, c);
    }

    @Test
    void shortAndLongPrksMatchIndependentHmacOracle() throws Exception {
        for (String algorithm : new String[] {"HmacSHA256", "HmacSHA384"}) {
            Hkdf hkdf = algorithm.equals("HmacSHA256") ? Hkdf.SHA256 : Hkdf.SHA384;
            for (int size : new int[] {1, hkdf.hashLength() - 1, hkdf.hashLength(),
                    hkdf.hashLength() + 1, 257}) {
                byte[] prk = range(0x80, size);
                byte[] info = range(0xf0, 33);
                assertArrayEquals(referenceExpand(algorithm, prk, info, 97),
                        hkdf.expand(prk, info, 97), algorithm + " PRK size " + size);
            }
            int maximum = 255 * hkdf.hashLength();
            byte[] prk = range(0x80, 257);
            assertArrayEquals(referenceExpand(algorithm, prk, range(0x80, 256), maximum),
                    hkdf.expand(prk, range(0x80, 256), maximum), algorithm + " maximum output");
            assertArrayEquals(referenceExpand(algorithm, prk,
                    referenceLabel("max", range(0x80, 255), maximum), maximum),
                    hkdf.expandLabel(prk, "max", range(0x80, 255), maximum));
        }
    }

    @Test
    void deterministicRandomDifferential() throws Exception {
        for (String algorithm : new String[] {"HmacSHA256", "HmacSHA384"}) {
            Hkdf hkdf = algorithm.equals("HmacSHA256") ? Hkdf.SHA256 : Hkdf.SHA384;
            int hashLength = hkdf.hashLength();
            java.util.Random random = new java.util.Random(0x58699001L + hashLength);
            for (int i = 0; i < 150; i++) {
                byte[] salt = randomBytes(random, i % 9 == 0 ? 0 : random.nextInt(260));
                byte[] ikm = randomBytes(random, i % 13 == 0 ? 0 : random.nextInt(300));
                byte[] info = randomBytes(random, random.nextInt(260));
                byte[] prk = randomBytes(random, 1 + random.nextInt(260));
                int length = i % 11 == 0 ? 0 : random.nextInt(4 * hashLength + 2);
                assertArrayEquals(referenceExtract(algorithm, salt, ikm), hkdf.extract(salt, ikm));
                assertArrayEquals(referenceExpand(algorithm, prk, info, length),
                        hkdf.expand(prk, info, length));
                StringBuilder label = new StringBuilder();
                for (int c = random.nextInt(250); c > 0; c--) {
                    label.append((char) random.nextInt(128));
                }
                byte[] context = randomBytes(random, random.nextInt(256));
                String text = label.toString();
                assertArrayEquals(referenceLabel(text, context, length),
                        Hkdf.labelInfo(text, context, length));
                assertArrayEquals(referenceExpand(algorithm, prk, referenceLabel(text, context, length), length),
                        hkdf.expandLabel(prk, text, context, length));
            }
        }
    }

    @Test
    void inputsArePreservedAndResultsAreUnaliased() {
        for (Hkdf hkdf : new Hkdf[] {Hkdf.SHA256, Hkdf.SHA384}) {
            byte[] salt = range(0x80, 65);
            byte[] ikm = range(0xf0, 129);
            byte[] info = range(0xc0, 57);
            byte[] originalSalt = salt.clone();
            byte[] originalIkm = ikm.clone();
            byte[] originalInfo = info.clone();
            byte[] prk = hkdf.extract(salt, ikm);
            byte[] originalPrk = prk.clone();
            byte[] out = hkdf.expand(prk, info, 97);
            byte[] expected = out.clone();
            byte[] labeled = hkdf.expandLabel(prk, "key", info, 97);
            byte[] expectedLabeled = labeled.clone();

            assertArrayEquals(originalSalt, salt);
            assertArrayEquals(originalIkm, ikm);
            assertArrayEquals(originalInfo, info);
            assertArrayEquals(originalPrk, prk);
            out[0] ^= 1;
            labeled[0] ^= 1;
            assertArrayEquals(expected, hkdf.expand(prk, info, 97));
            assertArrayEquals(expectedLabeled, hkdf.expandLabel(prk, "key", info, 97));
            salt[0] ^= 1;
            ikm[0] ^= 1;
            info[0] ^= 1;
            prk[0] ^= 1;
            assertArrayEquals(expected, hkdf.expand(originalPrk, originalInfo, 97));
            assertArrayEquals(expectedLabeled, hkdf.expandLabel(originalPrk, "key", originalInfo, 97));
            assertNotSame(out, salt);
            assertNotSame(out, ikm);
            assertNotSame(out, info);
            assertNotSame(out, prk);
            assertNotSame(out, labeled);
        }
    }

    @Test
    void nullCompatibilityAndNullChecks() {
        // The previous JCE implementation passed null doFinal/update inputs through as empty.
        assertArrayEquals(Hkdf.SHA256.extract(EMPTY, EMPTY), Hkdf.SHA256.extract(EMPTY, null));
        assertArrayEquals(Hkdf.SHA256.expand(new byte[] {1}, EMPTY, 32),
                Hkdf.SHA256.expand(new byte[] {1}, null, 32));

        assertThrows(NullPointerException.class, () -> Hkdf.SHA256.extract(null, EMPTY));
        assertThrows(NullPointerException.class, () -> Hkdf.labelInfo(null, EMPTY, 0));
        assertThrows(NullPointerException.class, () -> Hkdf.labelInfo("", null, 0));
        assertThrows(IllegalArgumentException.class,
                () -> Hkdf.SHA256.expandLabel(null, "key", EMPTY, 16));
        assertThrows(IllegalArgumentException.class,
                () -> Hkdf.SHA256.expandLabel(null, "", EMPTY, 16));
        assertThrows(NullPointerException.class,
                () -> Hkdf.SHA256.expandLabel(new byte[] {1}, null, EMPTY, 16));
        assertThrows(NullPointerException.class,
                () -> Hkdf.SHA256.expandLabel(new byte[] {1}, "key", null, 16));
    }

    @Test
    void repeatedAndConcurrentCallsHaveNoSharedMacState() throws Exception {
        for (Hkdf hkdf : new Hkdf[] {Hkdf.SHA256, Hkdf.SHA384}) {
            String algorithm = hkdf == Hkdf.SHA256 ? "HmacSHA256" : "HmacSHA384";
            byte[] prk = range(0x80, 33);
            byte[] first = hkdf.expandLabel(prk, "key", range(1, 17), 65);
            for (int i = 0; i < 32; i++) {
                assertArrayEquals(first, hkdf.expandLabel(prk, "key", range(1, 17), 65));
            }

            List<Callable<byte[]>> jobs = new ArrayList<>();
            for (int i = 0; i < 64; i++) {
                final int id = i;
                jobs.add(() -> hkdf.expandLabel(range(0x80 + id, 33), "key" + id, range(id, 17), 65));
            }
            try (var executor = Executors.newFixedThreadPool(4)) {
                var results = executor.invokeAll(jobs);
                for (int i = 0; i < results.size(); i++) {
                    assertArrayEquals(referenceExpand(algorithm, range(0x80 + i, 33),
                            referenceLabel("key" + i, range(i, 17), 65), 65), results.get(i).get());
                }
            }
        }
    }

    @Test
    void oneHundredTwentyEightRandomConcurrentCallsMatchReference() throws Exception {
        List<Callable<byte[]>> jobs = new ArrayList<>();
        java.util.Random random = new java.util.Random(0x128_5869L);
        byte[][] prks = new byte[128][];
        byte[][] infos = new byte[128][];
        for (int i = 0; i < 128; i++) {
            prks[i] = randomBytes(random, 1 + random.nextInt(64));
            infos[i] = randomBytes(random, random.nextInt(32));
            final int id = i;
            jobs.add(() -> Hkdf.SHA256.expand(prks[id], infos[id], 1 + (id % 96)));
        }
        try (var executor = Executors.newFixedThreadPool(8)) {
            var results = executor.invokeAll(jobs);
            for (int i = 0; i < results.size(); i++) {
                assertArrayEquals(referenceExpand("HmacSHA256", prks[i], infos[i], 1 + (i % 96)),
                        results.get(i).get());
            }
        }
    }

    /**
     * Independent JCE HMAC oracle used only by these finite checks. It reuses one Mac per expand,
     * relying on the provider's tested doFinal reset. Production does not: the generated kernel
     * asks JdkHmac for a fresh Mac on every block, so provider reset state is not carried between
     * feedback blocks.
     */
    private static byte[] referenceExtract(String algorithm, byte[] salt, byte[] ikm) throws Exception {
        int hashLength = algorithm.equals("HmacSHA256") ? 32 : 48;
        return referenceHmac(algorithm, salt.length == 0 ? new byte[hashLength] : salt, ikm);
    }

    private static byte[] referenceExpand(String algorithm, byte[] prk, byte[] info, int length)
            throws Exception {
        Mac mac = newMac(algorithm, prk);
        ByteArrayOutputStream output = new ByteArrayOutputStream(length);
        byte[] previous = EMPTY;
        for (int counter = 1; output.size() < length; counter++) {
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter);
            previous = mac.doFinal();
            output.write(previous, 0, Math.min(previous.length, length - output.size()));
        }
        return output.toByteArray();
    }

    private static byte[] referenceHmac(String algorithm, byte[] key, byte[] input) throws Exception {
        return newMac(algorithm, key).doFinal(input);
    }

    private static Mac newMac(String algorithm, byte[] key) throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac;
    }

    private static byte[] referenceLabel(String label, byte[] context, int length) {
        byte[] fullLabel = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
        return ByteBuffer.allocate(2 + 1 + fullLabel.length + 1 + context.length)
                .putShort((short) length).put((byte) fullLabel.length).put(fullLabel)
                .put((byte) context.length).put(context).array();
    }

    private static byte[] range(int start, int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) (start + i);
        }
        return result;
    }

    private static byte[] repeated(int value, int length) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
    }

    private static byte[] randomBytes(java.util.Random random, int length) {
        byte[] result = new byte[length];
        random.nextBytes(result);
        return result;
    }
}
