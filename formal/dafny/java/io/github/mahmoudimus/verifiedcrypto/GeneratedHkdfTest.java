package io.github.mahmoudimus.verifiedcrypto;

import VerifiedHkdf.BytesResult;
import VerifiedHkdf.__default;
import dafny.DafnySequence;
import io.github.mahmoudimus.quic.Hkdf;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Standalone integration tests for the Dafny-generated RFC 5869/8446 implementation and its Java
 * boundary. This is verification of a standard algorithm, not a new cryptographic construction.
 * Published vectors: https://www.rfc-editor.org/rfc/rfc5869#appendix-A and
 * https://www.rfc-editor.org/rfc/rfc9001#appendix-A. The SHA-384/512 fixture extensions were computed
 * independently with Python's hashlib/hmac; they are not attributed to RFC 5869.
 */
public final class GeneratedHkdfTest {
    private static final byte[] EMPTY = new byte[0];
    private static int cases;
    private static int assertions;
    private static final List<String> failures = new ArrayList<>();

    private record Variant(String algorithm, DafnyHkdf actual, Hkdf canonical, String prk,
                           String okm, String emptyIkm) {}

    private static final Variant[] VARIANTS = {
        new Variant("HmacSHA256", DafnyHkdf.SHA256, Hkdf.SHA256,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"),
        new Variant("HmacSHA384", DafnyHkdf.SHA384, Hkdf.SHA384,
            "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade",
            "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5",
            "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc"),
        new Variant("HmacSHA512", DafnyHkdf.SHA512, null,
            "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
            "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47")
    };

    private GeneratedHkdfTest() {}

    public static void main(String[] args) throws Exception {
        // Each name identifies the realistic boundary or algorithm break that it detects.
        run("RFC5869_A2_long_inputs_and_multiple_blocks", GeneratedHkdfTest::rfc5869Long);
        run("RFC5869_A3_empty_salt_and_info", GeneratedHkdfTest::rfc5869Empty);
        run("RFC9001_A1_label_wire_encoding", GeneratedHkdfTest::rfc9001LabelInfo);
        run("RFC9001_A1_client_and_server_keys", GeneratedHkdfTest::rfc9001Secrets);
        run("RFC9001_A5_chacha_key_update", GeneratedHkdfTest::rfc9001Chacha);
        run("label_unsigned_length_and_context_octets", GeneratedHkdfTest::labelBounds);
        run("labels_reject_UTF16_truncation_and_ASCII_replacement_aliases", GeneratedHkdfTest::unicodeLabels);
        run("generated_invalid_hash_is_a_failure_result", GeneratedHkdfTest::invalidHashResults);
        run("generated_length_rejection_precedes_empty_key", GeneratedHkdfTest::failurePrecedence);
        run("provider_rejects_BigInteger_hash_aliases", GeneratedHkdfTest::providerInvalidHashes);
        for (Variant v : VARIANTS) {
            run(v.algorithm + "_fixed_extract_and_expand_answers", () -> fixedAnswers(v));
            run(v.algorithm + "_empty_IKM_and_default_salt", () -> emptyIkm(v));
            run(v.algorithm + "_all_256_byte_values_survive_provider_boundary", () -> highBits(v));
            run(v.algorithm + "_nonempty_short_and_long_PRKs", () -> prkLengths(v));
            run(v.algorithm + "_255_blocks_including_unsigned_counters", () -> maxOutput(v));
            run(v.algorithm + "_fresh_zero_length_results", () -> zeroOutput(v));
            run(v.algorithm + "_invalid_lengths_and_empty_keys", () -> invalidLengths(v));
            run(v.algorithm + "_inputs_unchanged_and_outputs_unaliased", () -> ownership(v));
            run(v.algorithm + "_nulls_fail_at_Java_boundary", () -> nulls(v));
            run(v.algorithm + "_deterministic_differential", () -> differential(v));
            run(v.algorithm + "_shared_facade_has_no_cross_call_Mac_state", () -> concurrent(v));
        }
        if (!failures.isEmpty()) {
            failures.forEach(System.err::println);
            throw new AssertionError(failures.size() + " of " + cases + " cases failed (" + assertions + " assertions)");
        }
        List<String> providers = new ArrayList<>();
        for (Variant v : VARIANTS) {
            providers.add(v.algorithm + "=" + Mac.getInstance(v.algorithm).getProvider().getName());
        }
        System.out.println("PASS GeneratedHkdfTest: " + cases + " cases, " + assertions
            + " assertions; providers: " + String.join(", ", providers));
    }

    private static void fixedAnswers(Variant v) {
        byte[] prk = v.actual.extract(range(0, 13), repeated(0x0b, 22));
        eq(hex(v.prk), prk);
        eq(hex(v.okm), v.actual.expand(prk, range(0xf0, 10), 42));
        check(prk.length == v.actual.hashLength(), "hash length disagrees with extract");
    }

    private static void rfc5869Long() {
        byte[] prk = DafnyHkdf.SHA256.extract(range(0x60, 80), range(0, 80));
        eq(hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"), prk);
        eq(hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            + "cc30c58179ec3e87c14c01d5c1f3434f1d87"),
            DafnyHkdf.SHA256.expand(prk, range(0xb0, 80), 82));
    }

    private static void rfc5869Empty() {
        byte[] prk = DafnyHkdf.SHA256.extract(EMPTY, repeated(0x0b, 22));
        eq(hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"), prk);
        eq(hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
            DafnyHkdf.SHA256.expand(prk, EMPTY, 42));
    }

    private static void rfc9001LabelInfo() {
        eq(hex("00200f746c73313320636c69656e7420696e00"), DafnyHkdf.labelInfo("client in", EMPTY, 32));
        eq(hex("00200f746c7331332073657276657220696e00"), DafnyHkdf.labelInfo("server in", EMPTY, 32));
        eq(hex("00100e746c7331332071756963206b657900"), DafnyHkdf.labelInfo("quic key", EMPTY, 16));
        eq(hex("000c0d746c733133207175696320697600"), DafnyHkdf.labelInfo("quic iv", EMPTY, 12));
        eq(hex("00100d746c733133207175696320687000"), DafnyHkdf.labelInfo("quic hp", EMPTY, 16));
    }

    private static void rfc9001Secrets() {
        byte[] initial = DafnyHkdf.SHA256.extract(hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
            hex("8394c8f03e515708"));
        eq(hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"), initial);
        String[][] sides = {
            {"client in", "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
                "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
            {"server in", "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
                "cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e", "c206b8d9b9f0f37644430b490eeaa314"}
        };
        for (String[] side : sides) {
            byte[] secret = DafnyHkdf.SHA256.expandLabel(initial, side[0], EMPTY, 32);
            eq(hex(side[1]), secret);
            eq(hex(side[2]), DafnyHkdf.SHA256.expandLabel(secret, "quic key", EMPTY, 16));
            eq(hex(side[3]), DafnyHkdf.SHA256.expandLabel(secret, "quic iv", EMPTY, 12));
            eq(hex(side[4]), DafnyHkdf.SHA256.expandLabel(secret, "quic hp", EMPTY, 16));
        }
    }

    private static void rfc9001Chacha() {
        byte[] secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        eq(hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
            DafnyHkdf.SHA256.expandLabel(secret, "quic key", EMPTY, 32));
        eq(hex("e0459b3474bdd0e44a41c144"), DafnyHkdf.SHA256.expandLabel(secret, "quic iv", EMPTY, 12));
        eq(hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
            DafnyHkdf.SHA256.expandLabel(secret, "quic hp", EMPTY, 32));
        eq(hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"),
            DafnyHkdf.SHA256.expandLabel(secret, "quic ku", EMPTY, 32));
    }

    private static void emptyIkm(Variant v) {
        eq(hex(v.emptyIkm), v.actual.extract(EMPTY, EMPTY));
        eq(v.actual.extract(new byte[v.actual.hashLength()], EMPTY), v.actual.extract(EMPTY, EMPTY));
    }

    private static void highBits(Variant v) throws Exception {
        byte[] allBytes = range(0, 256);
        byte[] key = range(0x80, 257);
        eq(jceHmac(v.algorithm, key, allBytes), bytes(JdkHmac.compute(
            BigInteger.valueOf(v.actual.hashLength()), DafnySequence.fromBytes(key), DafnySequence.fromBytes(allBytes))));
        eq(jceHmac(v.algorithm, key, allBytes), v.actual.extract(key, allBytes));
        eq(referenceExpand(v.algorithm, key, allBytes, 3 * v.actual.hashLength() + 1),
            v.actual.expand(key, allBytes, 3 * v.actual.hashLength() + 1));
    }

    private static void prkLengths(Variant v) throws Exception {
        for (int size : new int[] {1, v.actual.hashLength() - 1, v.actual.hashLength(),
                v.actual.hashLength() + 1, 257}) {
            byte[] prk = range(0x80, size);
            eq(referenceExpand(v.algorithm, prk, range(0xf0, 33), 97),
                v.actual.expand(prk, range(0xf0, 33), 97));
        }
    }

    private static void maxOutput(Variant v) throws Exception {
        byte[] prk = range(0x80, 257);
        int length = 255 * v.actual.hashLength();
        eq(referenceExpand(v.algorithm, prk, range(0x80, 256), length),
            v.actual.expand(prk, range(0x80, 256), length));
        eq(referenceExpand(v.algorithm, prk, referenceLabel("max", range(0x80, 255), length), length),
            v.actual.expandLabel(prk, "max", range(0x80, 255), length));
    }

    private static void zeroOutput(Variant v) {
        byte[] prk = {(byte) 0xff};
        byte[] a = v.actual.expand(prk, EMPTY, 0);
        byte[] b = v.actual.expand(prk, EMPTY, 0);
        byte[] c = v.actual.expandLabel(prk, "", EMPTY, 0);
        byte[] d = v.actual.expandLabel(prk, "", EMPTY, 0);
        eq(EMPTY, a);
        eq(EMPTY, c);
        check(a != EMPTY && b != EMPTY && c != EMPTY && d != EMPTY && a != b && c != d && a != c,
            "zero-length results must be fresh arrays");
    }

    private static void invalidLengths(Variant v) {
        for (int length : new int[] {-1, Integer.MIN_VALUE, 255 * v.actual.hashLength() + 1, Integer.MAX_VALUE}) {
            expect(IllegalArgumentException.class, () -> v.actual.expand(new byte[] {1}, EMPTY, length));
            expect(IllegalArgumentException.class, () -> v.actual.expandLabel(new byte[] {1}, "key", EMPTY, length));
        }
        for (int length : new int[] {0, 1, v.actual.hashLength()}) {
            expect(IllegalArgumentException.class, () -> v.actual.expand(EMPTY, EMPTY, length));
            expect(IllegalArgumentException.class, () -> v.actual.expandLabel(EMPTY, "key", EMPTY, length));
        }
    }

    private static void labelBounds() {
        eq(hex("000006746c7331332000"), DafnyHkdf.labelInfo("", EMPTY, 0));
        eq(hex("010009746c73313320007f3f0180"), DafnyHkdf.labelInfo("\0\177?", hex("80"), 256));
        String maxLabel = "a".repeat(249);
        byte[] context = range(0x80, 255);
        eq(referenceLabel(maxLabel, context, 65535), DafnyHkdf.labelInfo(maxLabel, context, 65535));
        expect(IllegalArgumentException.class, () -> DafnyHkdf.labelInfo("a".repeat(250), EMPTY, 0));
        expect(IllegalArgumentException.class, () -> DafnyHkdf.labelInfo("", new byte[256], 0));
        for (int length : new int[] {-1, Integer.MIN_VALUE, 65536, Integer.MAX_VALUE}) {
            expect(IllegalArgumentException.class, () -> DafnyHkdf.labelInfo("", EMPTY, length));
        }
        for (Variant v : VARIANTS) {
            eq(v.actual.expand(new byte[] {1}, referenceLabel(maxLabel, context, 1), 1),
                v.actual.expandLabel(new byte[] {1}, maxLabel, context, 1));
            expect(IllegalArgumentException.class, () -> v.actual.expandLabel(new byte[] {1}, "a".repeat(250), EMPTY, 0));
            expect(IllegalArgumentException.class, () -> v.actual.expandLabel(new byte[] {1}, "", new byte[256], 0));
        }
    }

    private static void unicodeLabels() {
        // U+0100/U+0161/U+FF7F catch narrowing to byte before validating; surrogates catch
        // replacement by '?' and code-point conversion that discards individual UTF-16 units.
        for (String label : new String[] {"\u0080", "caf\u00e9", "\u0100", "\u0161", "\uff7f",
                "\u8000", "\uffff", "\ud800", "\udc00", "traffic upd\ud83d\udd10", "caf?\ud800"}) {
            expect(IllegalArgumentException.class, () -> DafnyHkdf.labelInfo(label, EMPTY, 0));
            for (Variant v : VARIANTS) {
                expect(IllegalArgumentException.class, () -> v.actual.expandLabel(new byte[] {1}, label, EMPTY, 16));
            }
        }
        eq(referenceLabel("\0a\177?", EMPTY, 1), DafnyHkdf.labelInfo("\0a\177?", EMPTY, 1));
    }

    private static void ownership(Variant v) {
        byte[] salt = range(0x80, 65), ikm = range(0xf0, 129), info = range(0xc0, 57);
        byte[] originalSalt = salt.clone(), originalIkm = ikm.clone(), originalInfo = info.clone();
        byte[] prk = v.actual.extract(salt, ikm), originalPrk = prk.clone();
        byte[] out = v.actual.expand(prk, info, 97), expected = out.clone();
        byte[] labeled = v.actual.expandLabel(prk, "key", info, 97), expectedLabeled = labeled.clone();
        byte[] encoded = DafnyHkdf.labelInfo("key", info, 97), expectedEncoded = encoded.clone();
        eq(originalSalt, salt); eq(originalIkm, ikm); eq(originalInfo, info); eq(originalPrk, prk);
        out[0] ^= 1; labeled[0] ^= 1; encoded[0] ^= 1;
        eq(expected, v.actual.expand(prk, info, 97));
        eq(expectedLabeled, v.actual.expandLabel(prk, "key", info, 97));
        eq(expectedEncoded, DafnyHkdf.labelInfo("key", info, 97));
        eq(originalPrk, v.actual.extract(salt, ikm));
        salt[0] ^= 1; ikm[0] ^= 1; info[0] ^= 1; prk[0] ^= 1;
        eq(expected, v.actual.expand(originalPrk, originalInfo, 97));
        eq(expectedLabeled, v.actual.expandLabel(originalPrk, "key", originalInfo, 97));
        check(out != salt && out != ikm && out != info && out != prk && out != labeled,
            "result aliases an input or another operation");
    }

    private static void nulls(Variant v) {
        expect(NullPointerException.class, () -> v.actual.extract(null, EMPTY));
        expect(NullPointerException.class, () -> v.actual.extract(EMPTY, null));
        expect(NullPointerException.class, () -> v.actual.expand(null, EMPTY, 0));
        expect(NullPointerException.class, () -> v.actual.expand(new byte[] {1}, null, 0));
        expect(NullPointerException.class, () -> v.actual.expandLabel(null, "", EMPTY, 0));
        expect(NullPointerException.class, () -> v.actual.expandLabel(new byte[] {1}, null, EMPTY, 0));
        expect(NullPointerException.class, () -> v.actual.expandLabel(new byte[] {1}, "", null, 0));
        expect(NullPointerException.class, () -> DafnyHkdf.labelInfo(null, EMPTY, 0));
        expect(NullPointerException.class, () -> DafnyHkdf.labelInfo("", null, 0));
    }

    private static void invalidHashResults() {
        var empty = DafnySequence.fromBytes(EMPTY);
        var label = DafnySequence.of(new short[0]);
        for (BigInteger hash : new BigInteger[] {BigInteger.valueOf(-1), BigInteger.ZERO,
                BigInteger.valueOf(31), BigInteger.valueOf(33), BigInteger.valueOf(65),
                BigInteger.ONE.shiftLeft(32).add(BigInteger.valueOf(32))}) {
            invalidHash(__default.Extract(hash, empty, empty));
            invalidHash(__default.Expand(hash, empty, empty, BigInteger.valueOf(-1)));
            invalidHash(__default.ExpandLabel(hash, empty, label, empty, BigInteger.valueOf(-1)));
        }
    }

    private static void invalidHash(BytesResult result) {
        check(result.is_Failure() && result.dtor_reason().is_InvalidHash(), "unsupported hash did not return InvalidHash");
    }

    private static void failurePrecedence() {
        var empty = DafnySequence.fromBytes(EMPTY);
        for (int hash : new int[] {32, 48, 64}) {
            BytesResult badLength = __default.Expand(BigInteger.valueOf(hash), empty, empty, BigInteger.valueOf(-1));
            check(badLength.is_Failure() && badLength.dtor_reason().is_InvalidLength(), "length/key failure order changed");
            BytesResult badKey = __default.Expand(BigInteger.valueOf(hash), empty, empty, BigInteger.ZERO);
            check(badKey.is_Failure() && badKey.dtor_reason().is_InvalidKey(), "empty PRK accepted for zero output");
        }
    }

    private static void providerInvalidHashes() {
        var key = DafnySequence.fromBytes(new byte[] {1});
        var empty = DafnySequence.fromBytes(EMPTY);
        for (BigInteger hash : new BigInteger[] {BigInteger.ZERO, BigInteger.valueOf(-32), BigInteger.valueOf(31),
                BigInteger.ONE.shiftLeft(32).add(BigInteger.valueOf(32)), BigInteger.ONE.shiftLeft(200)}) {
            expect(IllegalArgumentException.class, () -> JdkHmac.compute(hash, key, empty));
        }
        expect(NullPointerException.class, () -> JdkHmac.compute(null, key, empty));
        expect(NullPointerException.class, () -> JdkHmac.compute(BigInteger.valueOf(32), null, empty));
        expect(NullPointerException.class, () -> JdkHmac.compute(BigInteger.valueOf(32), key, null));
    }

    private static void differential(Variant v) throws Exception {
        Random random = new Random(0x58699001L + v.actual.hashLength());
        for (int i = 0; i < 200; i++) {
            byte[] salt = randomBytes(random, i % 9 == 0 ? 0 : random.nextInt(260));
            byte[] ikm = randomBytes(random, i % 13 == 0 ? 0 : random.nextInt(300));
            byte[] info = randomBytes(random, random.nextInt(260));
            byte[] prk = randomBytes(random, 1 + random.nextInt(260));
            int length = i % 11 == 0 ? 0 : random.nextInt(4 * v.actual.hashLength() + 2);
            byte[] expectedExtract = v.canonical == null
                ? jceHmac(v.algorithm, salt.length == 0 ? new byte[v.actual.hashLength()] : salt, ikm)
                : v.canonical.extract(salt, ikm);
            eq(expectedExtract, v.actual.extract(salt, ikm));
            eq(v.canonical == null ? referenceExpand(v.algorithm, prk, info, length)
                : v.canonical.expand(prk, info, length), v.actual.expand(prk, info, length));
            StringBuilder label = new StringBuilder();
            for (int c = random.nextInt(250); c > 0; c--) label.append((char) random.nextInt(128));
            byte[] context = randomBytes(random, random.nextInt(256));
            String text = label.toString();
            eq(referenceLabel(text, context, length), DafnyHkdf.labelInfo(text, context, length));
            eq(v.canonical == null ? referenceExpand(v.algorithm, prk, referenceLabel(text, context, length), length)
                : v.canonical.expandLabel(prk, text, context, length), v.actual.expandLabel(prk, text, context, length));
        }
    }

    private static void concurrent(Variant v) throws Exception {
        try (var executor = Executors.newFixedThreadPool(4)) {
            var jobs = new ArrayList<java.util.concurrent.Callable<byte[]>>();
            for (int i = 0; i < 24; i++) {
                final int id = i;
                jobs.add(() -> v.actual.expandLabel(range(0x80 + id, 33), "key" + id, range(id, 17), 65));
            }
            var results = executor.invokeAll(jobs);
            for (int i = 0; i < results.size(); i++) {
                eq(referenceExpand(v.algorithm, range(0x80 + i, 33), referenceLabel("key" + i, range(i, 17), 65), 65),
                    results.get(i).get());
            }
        }
    }

    /** Independent iterative oracle used only for SHA-512 and boundary cases, never the adapter. */
    private static byte[] referenceExpand(String algorithm, byte[] prk, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(prk, algorithm));
        ByteBuffer output = ByteBuffer.allocate(length);
        byte[] previous = EMPTY;
        for (int counter = 1; output.hasRemaining(); counter++) {
            mac.update(previous);
            mac.update(info);
            previous = mac.doFinal(new byte[] {(byte) counter});
            output.put(previous, 0, Math.min(previous.length, output.remaining()));
        }
        return output.array();
    }

    private static byte[] jceHmac(String algorithm, byte[] key, byte[] input) throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(input);
    }

    /** Test-only ByteBuffer oracle, independent of Dafny's sequence concatenation. */
    private static byte[] referenceLabel(String label, byte[] context, int length) {
        byte[] fullLabel = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
        return ByteBuffer.allocate(2 + 1 + fullLabel.length + 1 + context.length)
            .putShort((short) length).put((byte) fullLabel.length).put(fullLabel)
            .put((byte) context.length).put(context).array();
    }

    private static byte[] bytes(DafnySequence<? extends Byte> sequence) {
        byte[] result = new byte[sequence.length()];
        for (int i = 0; i < result.length; i++) result[i] = sequence.select(i);
        return result;
    }

    private static byte[] range(int start, int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) result[i] = (byte) (start + i);
        return result;
    }

    private static byte[] repeated(int value, int length) {
        byte[] result = new byte[length]; Arrays.fill(result, (byte) value); return result;
    }

    private static byte[] randomBytes(Random random, int length) {
        byte[] result = new byte[length]; random.nextBytes(result); return result;
    }

    private static byte[] hex(String text) { return HexFormat.of().parseHex(text); }

    private static void eq(byte[] expected, byte[] actual) {
        check(Arrays.equals(expected, actual), "byte result mismatch (expected length " + expected.length
            + ", actual length " + actual.length + ")");
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private static void expect(Class<? extends Throwable> type, Checked action) {
        assertions++;
        try { action.run(); } catch (Throwable error) {
            if (type.isInstance(error)) return;
            throw new AssertionError("expected " + type.getSimpleName() + ", got " + error.getClass().getSimpleName(), error);
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }

    private static void run(String name, Checked action) {
        cases++;
        try { action.run(); } catch (Throwable error) {
            failures.add("FAIL " + name + ": " + error.getClass().getSimpleName() + ": " + error.getMessage());
        }
    }

    @FunctionalInterface
    private interface Checked { void run() throws Exception; }
}
