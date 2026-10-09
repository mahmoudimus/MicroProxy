package org.microproxy.starlark.stdlib;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.ParamType;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.NoneType;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkList;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;

/**
 * {@code @stdlib//jhashlib}: the JDK's message digests and MACs for {@code hashlib.star} and
 * {@code hmac.star} (starlarky built these on BouncyCastle). BLAKE2 and SHAKE are not in the JDK and
 * are not available.
 */
@StarlarkBuiltin(name = "jhashlib", doc = "Message digests and HMAC on the JDK (used by @stdlib//hashlib and @stdlib//hmac).")
public final class HashlibModule implements StarlarkValue {

    static final HashlibModule INSTANCE = new HashlibModule();

    /** Python name, JDK algorithm, block size. */
    private record Algorithm(String name, String jdk, int blockSize) {}

    private static final Map<String, Algorithm> ALGORITHMS = Map.ofEntries(
            entry("md5", "MD5", 64),
            entry("sha1", "SHA-1", 64),
            entry("sha224", "SHA-224", 64),
            entry("sha256", "SHA-256", 64),
            entry("sha384", "SHA-384", 128),
            entry("sha512", "SHA-512", 128),
            entry("sha512_224", "SHA-512/224", 128),
            entry("sha512_256", "SHA-512/256", 128),
            entry("sha3_224", "SHA3-224", 144),
            entry("sha3_256", "SHA3-256", 136),
            entry("sha3_384", "SHA3-384", 104),
            entry("sha3_512", "SHA3-512", 72));

    private static final List<String> UNAVAILABLE = List.of("blake2b", "blake2s", "shake_128", "shake_256");

    private static Map.Entry<String, Algorithm> entry(String name, String jdk, int blockSize) {
        return Map.entry(name, new Algorithm(name, jdk, blockSize));
    }

    private HashlibModule() {}

    private static Algorithm algorithm(String name) throws EvalException {
        Algorithm a = ALGORITHMS.get(name);
        if (a != null) {
            return a;
        }
        if (UNAVAILABLE.contains(name)) {
            throw Starlark.errorf("unsupported hash type %s (MicroProxy's hashlib uses the JDK's digests, which have no BLAKE2 or SHAKE)", name);
        }
        throw Starlark.errorf("unsupported hash type %s", name);
    }

    static byte[] bytes(Object data, String what) throws EvalException {
        if (data instanceof StarlarkBytes b) {
            return b.toByteArray();
        }
        if (data instanceof String) {
            // as CPython: str must be encoded first
            throw Starlark.errorf("TypeError: Strings must be encoded before hashing");
        }
        throw Starlark.errorf("TypeError: object supporting the buffer API required for %s, not %s", what, Starlark.type(data));
    }

    /**
     * Lists the supported Python hash algorithm names in sorted order.
     *
     * @param thread the calling thread that owns the result list
     * @return the supported algorithm names
     */
    @StarlarkMethod(name = "algorithms", doc = "The names new() accepts.", useStarlarkThread = true)
    public StarlarkList<String> algorithms(StarlarkThread thread) {
        return StarlarkList.copyOf(thread.mutability(), new java.util.TreeSet<>(ALGORITHMS.keySet()));
    }

    /**
     * Creates a hash object initialized with supplied bytes.
     *
     * @param name the Python hash algorithm name
     * @param data the initial Starlark bytes
     * @param thread the calling thread that owns the hash object
     * @return a mutable hash object
     * @throws EvalException if the algorithm is unavailable or data is not bytes
     */
    @StarlarkMethod(name = "new", doc = "A new hash object for algorithm name (hashlib's names), fed data.",
            parameters = {@Param(name = "name"), @Param(name = "data", defaultValue = "b''")},
            useStarlarkThread = true)
    public HashObject newHash(String name, Object data, StarlarkThread thread) throws EvalException {
        Algorithm a = algorithm(name);
        try {
            HashObject h = new HashObject(a, MessageDigest.getInstance(a.jdk()), thread.mutability());
            h.digest.update(bytes(data, "data"));
            return h;
        } catch (GeneralSecurityException e) {
            throw Starlark.errorf("unsupported hash type %s (%s)", name, e.getMessage());
        }
    }

    /**
     * Creates a keyed HMAC object, optionally initialized with message bytes.
     *
     * @param key the Starlark bytes used as the HMAC key
     * @param msg the initial Starlark bytes, or {@code None} for an empty message
     * @param digestmod the Python digest algorithm name
     * @param thread the calling thread that owns the HMAC object
     * @return a mutable HMAC object
     * @throws EvalException if the algorithm or key is unsupported or an input is not bytes
     */
    @StarlarkMethod(name = "hmac", doc = "A new HMAC object keyed with key, for digest algorithm name, fed msg.",
            parameters = {
                @Param(name = "key"),
                @Param(name = "msg", defaultValue = "None"),
                @Param(name = "digestmod"),
            },
            useStarlarkThread = true)
    public HmacObject hmac(Object key, Object msg, String digestmod, StarlarkThread thread) throws EvalException {
        Algorithm a = algorithm(digestmod);
        if (a.name().startsWith("sha512_")) {
            throw Starlark.errorf("unsupported hash type %s for HMAC", digestmod);
        }
        String jdk = "Hmac" + a.jdk().replace("-", "");
        try {
            Mac mac = Mac.getInstance(jdk);
            byte[] k = bytes(key, "key");
            // An empty key is allowed in HMAC but not in SecretKeySpec; HMAC pads keys with zeros,
            // so a single zero byte is the same key.
            mac.init(new SecretKeySpec(k.length == 0 ? new byte[1] : k, jdk));
            HmacObject h = new HmacObject(a, mac, thread.mutability());
            if (msg != Starlark.NONE) {
                mac.update(bytes(msg, "msg"));
            }
            return h;
        } catch (GeneralSecurityException e) {
            throw Starlark.errorf("unsupported hash type %s for HMAC (%s)", digestmod, e.getMessage());
        }
    }

    /**
     * Compares like-typed byte strings or ASCII strings with the JDK digest comparison.
     *
     * @param a the first Starlark bytes or ASCII string
     * @param b the second value, of the same type as {@code a}
     * @return whether the byte representations are equal
     * @throws EvalException if the types differ, are unsupported or contain non-ASCII text
     */
    @StarlarkMethod(name = "compare_digest", doc = "Compares two str or bytes values in constant time.",
            parameters = {@Param(name = "a"), @Param(name = "b")})
    public boolean compareDigest(Object a, Object b) throws EvalException {
        byte[] x;
        byte[] y;
        if (a instanceof String s && b instanceof String t) {
            if (!s.chars().allMatch(c -> c < 128) || !t.chars().allMatch(c -> c < 128)) {
                throw Starlark.errorf("TypeError: comparing strings with non-ASCII characters is not supported");
            }
            x = s.getBytes(StandardCharsets.US_ASCII);
            y = t.getBytes(StandardCharsets.US_ASCII);
        } else if (a instanceof StarlarkBytes && b instanceof StarlarkBytes) {
            x = ((StarlarkBytes) a).toByteArray();
            y = ((StarlarkBytes) b).toByteArray();
        } else {
            throw Starlark.errorf("TypeError: unsupported operand types(s) or combination of types: '%s' and '%s'",
                    Starlark.type(a), Starlark.type(b));
        }
        return MessageDigest.isEqual(x, y);
    }

    /**
     * Derives a key using PBKDF2 with the requested HMAC digest.
     *
     * @param hashName the Python digest algorithm name
     * @param password the password as Starlark bytes
     * @param salt the salt as Starlark bytes
     * @param iterations the positive iteration count
     * @param dklen the positive key length in bytes, or {@code None} for the digest size
     * @param thread the calling interpreter thread supplying ownership and the deadline
     * @return the derived key as immutable bytes
     * @throws EvalException if arguments are invalid, the digest is unsupported or the deadline expires
     */
    @StarlarkMethod(name = "pbkdf2_hmac", doc = "PBKDF2 with HMAC (RFC 8018), as hashlib.pbkdf2_hmac.",
            parameters = {
                @Param(name = "hash_name"),
                @Param(name = "password"),
                @Param(name = "salt"),
                @Param(name = "iterations", allowedTypes = {@ParamType(type = StarlarkInt.class)}),
                @Param(name = "dklen", defaultValue = "None",
                        allowedTypes = {@ParamType(type = StarlarkInt.class), @ParamType(type = NoneType.class)}),
            },
            useStarlarkThread = true)
    public StarlarkBytes pbkdf2Hmac(String hashName, Object password, Object salt, StarlarkInt iterations,
            Object dklen, StarlarkThread thread) throws EvalException {
        int rounds = iterations.toInt("iterations");
        if (rounds < 1) {
            throw Starlark.errorf("ValueError: iteration value must be greater than 0.");
        }
        HmacObject prf = hmac(password, Starlark.NONE, hashName, thread);
        int hLen = prf.mac.getMacLength();
        int length = dklen == Starlark.NONE ? hLen : ((StarlarkInt) dklen).toInt("dklen");
        if (length < 1) {
            throw Starlark.errorf("ValueError: key length must be greater than 0.");
        }
        byte[] s = bytes(salt, "salt");
        byte[] out = new byte[length];
        long deadline = thread.getExpirationMs();
        int blocks = (length + hLen - 1) / hLen;
        for (int block = 1; block <= blocks; block++) {
            prf.mac.reset();
            prf.mac.update(s);
            prf.mac.update(new byte[] {(byte) (block >>> 24), (byte) (block >>> 16), (byte) (block >>> 8), (byte) block});
            byte[] u = prf.mac.doFinal();
            byte[] t = u.clone();
            for (int i = 1; i < rounds; i++) {
                if ((i & 0x3FF) == 0 && System.currentTimeMillis() > deadline) {
                    throw Starlark.errorf("pbkdf2_hmac ran past the deadline");
                }
                u = prf.mac.doFinal(u);
                for (int j = 0; j < t.length; j++) {
                    t[j] ^= u[j];
                }
            }
            System.arraycopy(t, 0, out, (block - 1) * hLen, Math.min(hLen, length - (block - 1) * hLen));
        }
        return StarlarkBytes.immutableOf(out);
    }

    /** A hashlib hash object. */
    @StarlarkBuiltin(name = "hash", doc = "A hashlib hash object.")
    public static final class HashObject implements StarlarkValue {
        private final Algorithm algorithm;
        private final MessageDigest digest;
        private final Mutability mutability;

        HashObject(Algorithm algorithm, MessageDigest digest, Mutability mutability) {
            this.algorithm = algorithm;
            this.digest = digest;
            this.mutability = mutability;
        }

        @Override
        public boolean isImmutable() {
            return mutability.isFrozen();
        }

        /**
         * Returns the hash algorithm name.
         *
         * @return the Python algorithm name
         */
        @StarlarkMethod(name = "name", structField = true, doc = "The algorithm's name.")
        public String name() {
            return algorithm.name();
        }

        /**
         * Returns the size of this hash result.
         *
         * @return the output length in bytes
         */
        @StarlarkMethod(name = "digest_size", structField = true, doc = "The digest's size in bytes.")
        public int digestSize() {
            return digest.getDigestLength();
        }

        /**
         * Returns the underlying digest algorithm block size.
         *
         * @return the block size in bytes
         */
        @StarlarkMethod(name = "block_size", structField = true, doc = "The algorithm's block size in bytes.")
        public int blockSize() {
            return algorithm.blockSize();
        }

        /**
         * Feeds additional bytes into this hash object.
         *
         * @param data the Starlark bytes to append
         * @throws EvalException if the object is frozen or the input is not bytes
         */
        @StarlarkMethod(name = "update", doc = "Feeds data (bytes).", parameters = {@Param(name = "data")})
        public void update(Object data) throws EvalException {
            if (mutability.isFrozen()) throw Starlark.errorf("trying to mutate a frozen %s value", name());
            digest.update(bytes(data, "data"));
        }

        /**
         * Computes the hash of bytes fed so far without changing this object.
         *
         * @return the result as immutable bytes
         * @throws EvalException if the JDK provider cannot copy its state
         */
        @StarlarkMethod(name = "digest", doc = "The digest of the data so far, as bytes.")
        public StarlarkBytes digest() throws EvalException {
            return StarlarkBytes.immutableOf(snapshot().digest());
        }

        /**
         * Computes the hash as hexadecimal without changing this object.
         *
         * @return the lowercase hexadecimal result
         * @throws EvalException if the JDK provider cannot copy its state
         */
        @StarlarkMethod(name = "hexdigest", doc = "The digest of the data so far, as hex.")
        public String hexdigest() throws EvalException {
            return HexFormat.of().formatHex(snapshot().digest());
        }

        /**
         * Copies the accumulated state into an independent hash object.
         *
         * @param thread the calling thread that owns the copy
         * @return a mutable copy of this object
         * @throws EvalException if the JDK provider cannot copy its state
         */
        @StarlarkMethod(name = "copy", doc = "A copy of this hash object.", useStarlarkThread = true)
        public HashObject copy(StarlarkThread thread) throws EvalException {
            return new HashObject(algorithm, snapshot(), thread.mutability());
        }

        private MessageDigest snapshot() throws EvalException {
            try {
                return (MessageDigest) digest.clone();
            } catch (CloneNotSupportedException e) {
                throw Starlark.errorf("%s cannot be copied", algorithm.name());
            }
        }

        @Override
        public void repr(Printer printer, StarlarkSemantics semantics) {
            printer.append("<" + algorithm.name() + " _hashlib.HASH object>");
        }
    }

    /** An hmac HMAC object. */
    @StarlarkBuiltin(name = "HMAC", doc = "An hmac.HMAC object.")
    public static final class HmacObject implements StarlarkValue {
        private final Algorithm algorithm;
        private final Mac mac;
        private final Mutability mutability;

        HmacObject(Algorithm algorithm, Mac mac, Mutability mutability) {
            this.algorithm = algorithm;
            this.mac = mac;
            this.mutability = mutability;
        }

        @Override
        public boolean isImmutable() {
            return mutability.isFrozen();
        }

        /**
         * Returns the HMAC algorithm name.
         *
         * @return {@code hmac-} followed by the digest name
         */
        @StarlarkMethod(name = "name", structField = true, doc = "hmac-<digest name>.")
        public String name() {
            return "hmac-" + algorithm.name();
        }

        /**
         * Returns the size of this HMAC result.
         *
         * @return the output length in bytes
         */
        @StarlarkMethod(name = "digest_size", structField = true, doc = "The MAC's size in bytes.")
        public int digestSize() {
            return mac.getMacLength();
        }

        /**
         * Returns the underlying digest algorithm block size.
         *
         * @return the block size in bytes
         */
        @StarlarkMethod(name = "block_size", structField = true, doc = "The digest's block size in bytes.")
        public int blockSize() {
            return algorithm.blockSize();
        }

        /**
         * Feeds additional bytes into this HMAC object.
         *
         * @param msg the Starlark bytes to append
         * @throws EvalException if the object is frozen or the input is not bytes
         */
        @StarlarkMethod(name = "update", doc = "Feeds msg (bytes).", parameters = {@Param(name = "msg")})
        public void update(Object msg) throws EvalException {
            if (mutability.isFrozen()) throw Starlark.errorf("trying to mutate a frozen %s value", name());
            mac.update(bytes(msg, "msg"));
        }

        /**
         * Computes the HMAC of bytes fed so far without changing this object.
         *
         * @return the result as immutable bytes
         * @throws EvalException if the JDK provider cannot copy its state
         */
        @StarlarkMethod(name = "digest", doc = "The MAC of the data so far, as bytes.")
        public StarlarkBytes digest() throws EvalException {
            return StarlarkBytes.immutableOf(snapshot().doFinal());
        }

        /**
         * Computes the HMAC as hexadecimal without changing this object.
         *
         * @return the lowercase hexadecimal result
         * @throws EvalException if the JDK provider cannot copy its state
         */
        @StarlarkMethod(name = "hexdigest", doc = "The MAC of the data so far, as hex.")
        public String hexdigest() throws EvalException {
            return HexFormat.of().formatHex(snapshot().doFinal());
        }

        /**
         * Copies the accumulated state into an independent HMAC object.
         *
         * @param thread the calling thread that owns the copy
         * @return a mutable copy of this object
         * @throws EvalException if the JDK provider cannot copy its state
         */
        @StarlarkMethod(name = "copy", doc = "A copy of this HMAC object.", useStarlarkThread = true)
        public HmacObject copy(StarlarkThread thread) throws EvalException {
            return new HmacObject(algorithm, snapshot(), thread.mutability());
        }

        private Mac snapshot() throws EvalException {
            try {
                return (Mac) mac.clone();
            } catch (CloneNotSupportedException e) {
                throw Starlark.errorf("%s cannot be copied", name());
            }
        }

        @Override
        public void repr(Printer printer, StarlarkSemantics semantics) {
            printer.append("<hmac.HMAC object (" + algorithm.name() + ")>");
        }
    }
}
