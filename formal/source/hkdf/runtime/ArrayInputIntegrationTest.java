import dafny.DafnySequence;
import io.github.mahmoudimus.quic.Hkdf;
import io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult;
import io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default;
import io.github.mahmoudimus.verifiedcrypto.JdkHmac;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class ArrayInputIntegrationTest {
    private static int assertions;
    private static int cases;

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private static byte[] data(int length, int offset) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) result[i] = (byte)(i * 37 + offset);
        return result;
    }

    private static byte[] mac(int hashLength, byte[] key, byte[] input) throws Exception {
        String algorithm = "HmacSHA" + (hashLength * 8);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(input);
    }

    private static byte[] expand(int hashLength, byte[] key, byte[] info, int length) throws Exception {
        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int copied = 0;
        for (int counter = 1; copied < length; counter++) {
            byte[] input = new byte[previous.length + info.length + 1];
            System.arraycopy(previous, 0, input, 0, previous.length);
            System.arraycopy(info, 0, input, previous.length, info.length);
            input[input.length - 1] = (byte)counter;
            previous = mac(hashLength, key, input);
            int take = Math.min(previous.length, length - copied);
            System.arraycopy(previous, 0, output, copied, take);
            copied += take;
        }
        return output;
    }

    private static byte[] success(BytesResult result) {
        check(result.is_Success(), "unexpected generated failure");
        return JdkHmac.bytes(result.dtor_bytes());
    }

    private static byte[] label(String suffix, byte[] context, int length) {
        byte[] label = ("tls13 " + suffix).getBytes(StandardCharsets.US_ASCII);
        return ByteBuffer.allocate(4 + label.length + context.length).putShort((short)length)
                .put((byte)label.length).put(label).put((byte)context.length).put(context).array();
    }

    private interface Attempt { void run() throws Exception; }

    private static void failure(Class<? extends Throwable> type, String message, Attempt attempt) throws Exception {
        try {
            attempt.run();
        } catch (Throwable error) {
            check(error.getClass() == type, "wrong exception class: " + error);
            check(message.equals(error.getMessage()), "wrong exception message: " + error.getMessage());
            cases++;
            return;
        }
        throw new AssertionError("expected exception " + type.getName());
    }

    private static void snapshots() {
        for (int length : new int[] {0, 1, 32, 48, 64, 255, 256, 1024}) {
            byte[] input = data(length, 11);
            byte[] expected = input.clone();
            DafnySequence<? extends Byte> one = __default.CopyInput(input);
            DafnySequence<? extends Byte> two = __default.CopyInput(input);
            byte[] first = JdkHmac.bytes(one);
            check(first != input, "snapshot input alias");
            Arrays.fill(input, (byte)0xA5);
            check(Arrays.equals(JdkHmac.bytes(one), expected), "input mutation changed snapshot");
            Arrays.fill(first, (byte)0x5A);
            check(Arrays.equals(JdkHmac.bytes(one), expected), "returned copy mutation changed snapshot");
            check(Arrays.equals(JdkHmac.bytes(two), expected), "independent snapshot changed");
            cases++;
        }
    }

    private static void generatedPaths() throws Exception {
        for (int hash : new int[] {32, 48, 64}) {
            BigInteger h = BigInteger.valueOf(hash);
            for (int saltLength : new int[] {0, 1, 13}) for (int inputLength : new int[] {0, 1, 65}) {
                byte[] salt = data(saltLength, 9);
                byte[] input = data(inputLength, 17);
                byte[] expected = mac(hash, salt.length == 0 ? new byte[hash] : salt, input);
                check(Arrays.equals(success(__default.ExtractArrays(h, salt, input)), expected), "raw extract oracle mismatch");
                check(Arrays.equals(salt, data(saltLength, 9)) && Arrays.equals(input, data(inputLength, 17)), "extract changed caller buffers");
                cases++;
            }
            for (int keyLength : new int[] {1, 32}) for (int infoLength : new int[] {0, 19}) {
                byte[] key = data(keyLength, 13);
                byte[] info = data(infoLength, 21);
                for (int length : new int[] {0, 1, hash, 255 * hash}) {
                    check(Arrays.equals(success(__default.ExpandArrays(h, key, info, BigInteger.valueOf(length))), expand(hash, key, info, length)), "raw expand oracle mismatch");
                    check(Arrays.equals(key, data(keyLength, 13)) && Arrays.equals(info, data(infoLength, 21)), "expand changed caller buffers");
                    cases++;
                }
            }
            for (int length : new int[] {-1, 255 * hash + 1}) {
                BytesResult rejected = __default.ExpandArrays(h, new byte[0], new byte[0], BigInteger.valueOf(length));
                check(rejected.is_Failure() && rejected.dtor_reason().is_InvalidLength(), "length must precede empty-key validation");
                cases++;
            }
            BytesResult empty = __default.ExpandArrays(h, new byte[0], new byte[0], BigInteger.ZERO);
            check(empty.is_Failure() && empty.dtor_reason().is_InvalidKey(), "zero output does not admit empty PRK");
            cases++;
        }
        for (int hash : new int[] {-1, 0, 31, 47, 65, Integer.MAX_VALUE}) {
            BytesResult bad = __default.ExpandArrays(BigInteger.valueOf(hash), new byte[0], new byte[0], BigInteger.valueOf(-1));
            check(bad.is_Failure() && bad.dtor_reason().is_InvalidHash(), "hash must precede other kernel errors");
            cases++;
        }
    }

    private static void facade() throws Exception {
        for (Hkdf hkdf : new Hkdf[] {Hkdf.SHA256, Hkdf.SHA384}) {
            int hash = hkdf.hashLength();
            byte[] shared = data(37, 7);
            byte[] expected = mac(hash, shared, shared);
            check(Arrays.equals(hkdf.extract(shared, shared), expected), "aliased extract mismatch");
            check(Arrays.equals(hkdf.extract(new byte[0], null), mac(hash, new byte[hash], new byte[0])), "null IKM compatibility");
            byte[] expanded = hkdf.expand(shared, shared, 37);
            check(Arrays.equals(expanded, expand(hash, shared, shared, 37)), "aliased expand mismatch");
            expanded[0] ^= 1;
            check(Arrays.equals(hkdf.expand(shared, shared, 37), expand(hash, shared, shared, 37)), "output mutation persisted across calls");
            check(Arrays.equals(hkdf.expand(shared, null, 17), expand(hash, shared, new byte[0], 17)), "null info compatibility");
            check(Arrays.equals(shared, data(37, 7)), "facade changed aliased caller buffer");
            cases += 6;
            for (String suffix : new String[] {"", "quic key", "a".repeat(249)}) for (int contextLength : new int[] {0, 1, 255}) {
                byte[] context = data(contextLength, 1);
                check(Arrays.equals(hkdf.expandLabel(shared, suffix, context, 17), expand(hash, shared, label(suffix, context, 17), 17)), "TLS label oracle mismatch");
                cases++;
            }
            failure(NullPointerException.class, "salt", () -> hkdf.extract(null, null));
            failure(IllegalArgumentException.class, "HKDF output length -1", () -> hkdf.expand(null, null, -1));
            failure(IllegalArgumentException.class, "Missing argument", () -> hkdf.expand(null, null, 0));
            failure(IllegalArgumentException.class, "Empty key", () -> hkdf.expand(new byte[0], null, 0));
            failure(NullPointerException.class, "label", () -> hkdf.expandLabel(null, null, null, 0));
            failure(NullPointerException.class, "context", () -> hkdf.expandLabel(null, "key", null, 0));
            failure(IllegalArgumentException.class, "HKDF label length out of range", () -> hkdf.expandLabel(null, "\u0100", new byte[256], -1));
            failure(IllegalArgumentException.class, "HKDF label must be ASCII", () -> hkdf.expandLabel(null, "\u0100", new byte[0], 0));
            failure(IllegalArgumentException.class, "HKDF label must be ASCII", () -> hkdf.expandLabel(shared, "\ud800", new byte[0], 17));
            failure(IllegalArgumentException.class, "HKDF label length out of range", () -> hkdf.expandLabel(shared, "a".repeat(250), new byte[0], 17));
            failure(IllegalArgumentException.class, "Missing argument", () -> hkdf.expandLabel(null, "key", new byte[0], 0));
        }
    }

    public static void main(String[] args) throws Exception {
        snapshots();
        generatedPaths();
        facade();
        System.out.println("HKDF-ARRAY-INTEGRATION-PASS cases=" + cases + " assertions=" + assertions);
    }
}
