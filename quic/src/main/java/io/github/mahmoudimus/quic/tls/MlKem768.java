// Ported from Go src/crypto/internal/fips140/mlkem/mlkem768.go and field.go (BSD-3-Clause,
// Copyright 2023 The Go Authors): the field arithmetic with Barrett reduction, the NTT,
// compression, sampling, K-PKE and the ML-KEM key generation, encapsulation and decapsulation
// with implicit rejection, for the ML-KEM-768 parameter set only.
package io.github.mahmoudimus.quic.tls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * ML-KEM-768 (NIST FIPS 203), the post-quantum key encapsulation in the hybrid TLS group
 * X25519MLKEM768. Variable names follow FIPS 203, so the code can be read against it.
 * Operations on secret data are constant time: no branches or table lookups on secrets.
 */
final class MlKem768 {

    static final int ENCAPSULATION_KEY_SIZE = 1184;
    static final int CIPHERTEXT_SIZE = 1088;
    static final int SHARED_KEY_SIZE = 32;
    static final int SEED_SIZE = 64;

    private static final int N = 256;
    private static final int Q = 3329;
    private static final int K = 3;
    private static final int ENCODING_SIZE_12 = N * 12 / 8;
    private static final int ENCODING_SIZE_10 = N * 10 / 8;
    private static final int ENCODING_SIZE_4 = N * 4 / 8;
    private static final int ENCODING_SIZE_1 = N / 8;
    private static final long BARRETT_MULTIPLIER = 5039; // 2^24 / q
    private static final int BARRETT_SHIFT = 24;

    private static final int[] GAMMAS = {
        17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409, 1920, 2662,
        667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626, 1651, 1678, 2789, 540,
        1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733,
        2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780,
        2090, 1239, 1645, 1684, 1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594,
        735, 2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607,
        1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
    };

    private static final int[] ZETAS = {
        1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476,
        3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277,
        2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617,
        1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756,
        2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
        1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
        1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
    };

    private MlKem768() {}

    /** A shared key and the ciphertext that carries it. */
    record Encapsulation(byte[] sharedKey, byte[] ciphertext) {}

    /** The public half: t, ρ and H(ek), with the matrix A expanded from ρ. */
    private record EncryptionKey(int[][] t, int[][] a, byte[] rho, byte[] h) {

        byte[] encode() {
            byte[] out = new byte[ENCAPSULATION_KEY_SIZE];
            for (int i = 0; i < K; i++) polyByteEncode(t[i], out, i * ENCODING_SIZE_12);
            System.arraycopy(rho, 0, out, K * ENCODING_SIZE_12, 32);
            return out;
        }
    }

    /** A decapsulation key, kept as its seed (d, z) and the expanded keys. */
    static final class DecapsulationKey {

        private final byte[] z;
        private final int[][] s;
        private final EncryptionKey ek;
        private final byte[] encoded;

        private DecapsulationKey(byte[] d, byte[] z) {
            this.z = z.clone();
            // ML-KEM.KeyGen_internal (FIPS 203 algorithm 16) with K-PKE.KeyGen (algorithm 13)
            byte[] g = sha3_512(d, new byte[] {K});
            byte[] rho = Arrays.copyOf(g, 32);
            byte[] sigma = Arrays.copyOfRange(g, 32, 64);
            int[][] a = expandA(rho);
            int n = 0;
            s = new int[K][];
            for (int i = 0; i < K; i++) s[i] = ntt(samplePolyCbd(sigma, n++));
            int[][] e = new int[K][];
            for (int i = 0; i < K; i++) e[i] = ntt(samplePolyCbd(sigma, n++));
            int[][] t = new int[K][];
            for (int i = 0; i < K; i++) {
                t[i] = e[i];
                for (int j = 0; j < K; j++) t[i] = polyAdd(t[i], nttMul(a[i * K + j], s[j]));
            }
            EncryptionKey partial = new EncryptionKey(t, a, rho, null);
            this.encoded = partial.encode();
            this.ek = new EncryptionKey(t, a, rho, sha3_256(encoded));
        }

        /**
         * The key for a 64-byte seed, d then z (FIPS 203 section 7.1, the seed format).
         *
         * @throws IllegalArgumentException if the seed is not 64 bytes
         */
        static DecapsulationKey fromSeed(byte[] seed) {
            if (seed.length != SEED_SIZE) throw new IllegalArgumentException("ML-KEM seed of " + seed.length + " bytes");
            return new DecapsulationKey(Arrays.copyOf(seed, 32), Arrays.copyOfRange(seed, 32, 64));
        }

        /** A new key from {@code random}. */
        static DecapsulationKey generate(SecureRandom random) {
            byte[] seed = new byte[SEED_SIZE];
            random.nextBytes(seed);
            return fromSeed(seed);
        }

        /** {@return the encapsulation key, 1184 bytes} */
        byte[] encapsulationKey() {
            return encoded.clone();
        }

        /**
         * ML-KEM.Decaps (FIPS 203 algorithm 18): the shared key, or, for a ciphertext that does not
         * re-encrypt to itself, the implicit rejection key J(z || c), chosen in constant time.
         *
         * @throws IllegalArgumentException if the ciphertext is not 1088 bytes
         */
        byte[] decapsulate(byte[] c) {
            if (c.length != CIPHERTEXT_SIZE) {
                throw new IllegalArgumentException("ML-KEM-768 ciphertext of " + c.length + " bytes");
            }
            byte[] m = pkeDecrypt(s, c);
            byte[] g = sha3_512(m, ek.h());
            byte[] kPrime = Arrays.copyOf(g, SHARED_KEY_SIZE);
            byte[] r = Arrays.copyOfRange(g, 32, 64);
            byte[] kBar = new byte[SHARED_KEY_SIZE];
            Shake.shake256().update(z).update(c).read(kBar);
            byte[] c1 = pkeEncrypt(ek, m, r);
            int diff = 0;
            for (int i = 0; i < c.length; i++) diff |= (c[i] ^ c1[i]) & 0xff;
            // 0xff when the ciphertexts are equal, 0 otherwise, without branching on it
            int equal = ((diff - 1) >> 31) & 0xff;
            byte[] out = new byte[SHARED_KEY_SIZE];
            for (int i = 0; i < out.length; i++) out[i] = (byte) ((kPrime[i] & equal) | (kBar[i] & ~equal));
            return out;
        }
    }

    /** ML-KEM.Encaps (FIPS 203 algorithm 17) with a random message. */
    static Encapsulation encapsulate(byte[] encapsulationKey, SecureRandom random) {
        byte[] m = new byte[32];
        random.nextBytes(m);
        return encapsulate(encapsulationKey, m);
    }

    /**
     * ML-KEM.Encaps_internal (FIPS 203 algorithm 17) with a given 32-byte message, for test
     * vectors.
     *
     * @throws IllegalArgumentException if the key is not 1184 bytes or fails the modulus check
     */
    static Encapsulation encapsulate(byte[] encapsulationKey, byte[] m) {
        EncryptionKey ek = parseEncapsulationKey(encapsulationKey);
        byte[] g = sha3_512(m, ek.h());
        byte[] key = Arrays.copyOf(g, SHARED_KEY_SIZE);
        byte[] r = Arrays.copyOfRange(g, 32, 64);
        return new Encapsulation(key, pkeEncrypt(ek, m, r));
    }

    private static EncryptionKey parseEncapsulationKey(byte[] b) {
        if (b.length != ENCAPSULATION_KEY_SIZE) {
            throw new IllegalArgumentException("ML-KEM-768 encapsulation key of " + b.length + " bytes");
        }
        int[][] t = new int[K][];
        for (int i = 0; i < K; i++) t[i] = polyByteDecode(b, i * ENCODING_SIZE_12);
        byte[] rho = Arrays.copyOfRange(b, K * ENCODING_SIZE_12, ENCAPSULATION_KEY_SIZE);
        return new EncryptionKey(t, expandA(rho), rho, sha3_256(b));
    }

    private static int[][] expandA(byte[] rho) {
        int[][] a = new int[K * K][];
        for (int i = 0; i < K; i++) {
            for (int j = 0; j < K; j++) a[i * K + j] = sampleNtt(rho, j, i);
        }
        return a;
    }

    /** K-PKE.Encrypt (FIPS 203 algorithm 14). */
    private static byte[] pkeEncrypt(EncryptionKey ex, byte[] m, byte[] rnd) {
        int n = 0;
        int[][] r = new int[K][];
        for (int i = 0; i < K; i++) r[i] = ntt(samplePolyCbd(rnd, n++));
        int[][] e1 = new int[K][];
        for (int i = 0; i < K; i++) e1[i] = samplePolyCbd(rnd, n++);
        int[] e2 = samplePolyCbd(rnd, n);
        byte[] c = new byte[CIPHERTEXT_SIZE];
        for (int i = 0; i < K; i++) {
            int[] uHat = new int[N];
            for (int j = 0; j < K; j++) uHat = polyAdd(uHat, nttMul(ex.a()[j * K + i], r[j]));
            int[] u = polyAdd(e1[i], inverseNtt(uHat));
            ringCompressAndEncode10(u, c, i * ENCODING_SIZE_10);
        }
        int[] mu = ringDecodeAndDecompress1(m);
        int[] vNtt = new int[N];
        for (int i = 0; i < K; i++) vNtt = polyAdd(vNtt, nttMul(ex.t()[i], r[i]));
        int[] v = polyAdd(polyAdd(inverseNtt(vNtt), e2), mu);
        ringCompressAndEncode4(v, c, K * ENCODING_SIZE_10);
        return c;
    }

    /** K-PKE.Decrypt (FIPS 203 algorithm 15). */
    private static byte[] pkeDecrypt(int[][] s, byte[] c) {
        int[] mask = new int[N];
        for (int i = 0; i < K; i++) {
            int[] u = ringDecodeAndDecompress10(c, i * ENCODING_SIZE_10);
            mask = polyAdd(mask, nttMul(s[i], ntt(u)));
        }
        int[] v = ringDecodeAndDecompress4(c, K * ENCODING_SIZE_10);
        int[] w = polySub(v, inverseNtt(mask));
        return ringCompressAndEncode1(w);
    }

    // --- field arithmetic mod q, on values in [0, q) ---

    private static int reduceOnce(int a) {
        int x = (a - Q) & 0xffff;
        return (x + (x >>> 15) * Q) & 0xffff;
    }

    private static int add(int a, int b) {
        return reduceOnce((a + b) & 0xffff);
    }

    private static int sub(int a, int b) {
        return reduceOnce((a - b + Q) & 0xffff);
    }

    /** Barrett reduction of a product below 2^24. */
    private static int reduce(long a) {
        long quotient = (a * BARRETT_MULTIPLIER) >>> BARRETT_SHIFT;
        return reduceOnce((int) (a - quotient * Q) & 0xffff);
    }

    private static int mul(int a, int b) {
        return reduce((long) a * b);
    }

    private static int mulSub(int a, int b, int c) {
        return reduce((long) a * ((b - c + Q) & 0xffff));
    }

    private static int addMul(int a, int b, int c, int d) {
        return reduce((long) a * b + (long) c * d);
    }

    /** Compress_d (FIPS 203 equation 4.7): round(2^d / q * x) mod 2^d, without division. */
    private static int compress(int x, int d) {
        long dividend = (long) x << d;
        long quotient = (dividend * BARRETT_MULTIPLIER) >>> BARRETT_SHIFT;
        long remainder = dividend - quotient * Q;
        quotient += ((Q / 2 - remainder) >>> 63) & 1;
        quotient += ((Q + Q / 2 - remainder) >>> 63) & 1;
        return (int) (quotient & ((1 << d) - 1));
    }

    /** Decompress_d (FIPS 203 equation 4.8): round(q / 2^d * y). */
    private static int decompress(int y, int d) {
        int dividend = y * Q;
        int quotient = dividend >>> d;
        quotient += (dividend >>> (d - 1)) & 1;
        return quotient;
    }

    private static int[] polyAdd(int[] a, int[] b) {
        int[] s = new int[N];
        for (int i = 0; i < N; i++) s[i] = add(a[i], b[i]);
        return s;
    }

    private static int[] polySub(int[] a, int[] b) {
        int[] s = new int[N];
        for (int i = 0; i < N; i++) s[i] = sub(a[i], b[i]);
        return s;
    }

    // --- encodings ---

    /** ByteEncode_12 (FIPS 203 algorithm 5). */
    private static void polyByteEncode(int[] f, byte[] out, int at) {
        for (int i = 0; i < N; i += 2) {
            int x = f[i] | (f[i + 1] << 12);
            out[at++] = (byte) x;
            out[at++] = (byte) (x >>> 8);
            out[at++] = (byte) (x >>> 16);
        }
    }

    /** ByteDecode_12 (FIPS 203 algorithm 6), with the modulus check of section 7.2. */
    private static int[] polyByteDecode(byte[] b, int at) {
        int[] f = new int[N];
        for (int i = 0; i < N; i += 2) {
            int d = (b[at] & 0xff) | ((b[at + 1] & 0xff) << 8) | ((b[at + 2] & 0xff) << 16);
            at += 3;
            f[i] = d & 0xfff;
            f[i + 1] = d >>> 12;
            if (f[i] >= Q || f[i + 1] >= Q) {
                throw new IllegalArgumentException("ML-KEM-768 encapsulation key fails the modulus check");
            }
        }
        return f;
    }

    private static byte[] ringCompressAndEncode1(int[] f) {
        byte[] b = new byte[ENCODING_SIZE_1];
        for (int i = 0; i < N; i++) b[i / 8] |= (byte) (compress(f[i], 1) << (i % 8));
        return b;
    }

    private static int[] ringDecodeAndDecompress1(byte[] b) {
        int[] f = new int[N];
        for (int i = 0; i < N; i++) f[i] = ((b[i / 8] >>> (i % 8)) & 1) * ((Q + 1) / 2);
        return f;
    }

    private static void ringCompressAndEncode4(int[] f, byte[] out, int at) {
        for (int i = 0; i < N; i += 2) out[at + i / 2] = (byte) (compress(f[i], 4) | (compress(f[i + 1], 4) << 4));
    }

    private static int[] ringDecodeAndDecompress4(byte[] b, int at) {
        int[] f = new int[N];
        for (int i = 0; i < N; i += 2) {
            int x = b[at + i / 2] & 0xff;
            f[i] = decompress(x & 0xf, 4);
            f[i + 1] = decompress(x >>> 4, 4);
        }
        return f;
    }

    private static void ringCompressAndEncode10(int[] f, byte[] out, int at) {
        for (int i = 0; i < N; i += 4) {
            long x = compress(f[i], 10)
                    | ((long) compress(f[i + 1], 10) << 10)
                    | ((long) compress(f[i + 2], 10) << 20)
                    | ((long) compress(f[i + 3], 10) << 30);
            for (int j = 0; j < 5; j++) out[at++] = (byte) (x >>> (8 * j));
        }
    }

    private static int[] ringDecodeAndDecompress10(byte[] b, int at) {
        int[] f = new int[N];
        for (int i = 0; i < N; i += 4) {
            long x = 0;
            for (int j = 0; j < 5; j++) x |= (b[at++] & 0xffL) << (8 * j);
            for (int j = 0; j < 4; j++) f[i + j] = decompress((int) ((x >>> (10 * j)) & 0x3ff), 10);
        }
        return f;
    }

    // --- sampling ---

    /** SamplePolyCBD_2 (FIPS 203 algorithm 8) of PRF_2(s, b). */
    private static int[] samplePolyCbd(byte[] s, int b) {
        byte[] buf = new byte[128];
        Shake.shake256().update(s).update(new byte[] {(byte) b}).read(buf);
        int[] f = new int[N];
        for (int i = 0; i < N; i += 2) {
            int x = buf[i / 2] & 0xff;
            f[i] = sub((x & 1) + ((x >>> 1) & 1), ((x >>> 2) & 1) + ((x >>> 3) & 1));
            f[i + 1] = sub(((x >>> 4) & 1) + ((x >>> 5) & 1), ((x >>> 6) & 1) + ((x >>> 7) & 1));
        }
        return f;
    }

    /** SampleNTT (FIPS 203 algorithm 7) of XOF(ρ, i, j), by rejection of 12-bit values. */
    private static int[] sampleNtt(byte[] rho, int i, int j) {
        Shake xof = Shake.shake128().update(rho).update(new byte[] {(byte) i, (byte) j});
        int[] a = new int[N];
        byte[] buf = new byte[24];
        int off = buf.length;
        int n = 0;
        while (n < N) {
            if (off >= buf.length) {
                xof.read(buf);
                off = 0;
            }
            int d1 = ((buf[off] & 0xff) | ((buf[off + 1] & 0xff) << 8)) & 0xfff;
            int d2 = ((buf[off + 1] & 0xff) | ((buf[off + 2] & 0xff) << 8)) >>> 4;
            off += 3;
            if (d1 < Q) a[n++] = d1;
            if (n < N && d2 < Q) a[n++] = d2;
        }
        return a;
    }

    // --- NTT ---

    /** NTT (FIPS 203 algorithm 9). */
    private static int[] ntt(int[] in) {
        int[] f = in.clone();
        int k = 1;
        for (int len = 128; len >= 2; len /= 2) {
            for (int start = 0; start < N; start += 2 * len) {
                int zeta = ZETAS[k++];
                for (int j = start; j < start + len; j++) {
                    int t = mul(zeta, f[j + len]);
                    f[j + len] = sub(f[j], t);
                    f[j] = add(f[j], t);
                }
            }
        }
        return f;
    }

    /** NTT^-1 (FIPS 203 algorithm 10). */
    private static int[] inverseNtt(int[] in) {
        int[] f = in.clone();
        int k = 127;
        for (int len = 2; len <= 128; len *= 2) {
            for (int start = 0; start < N; start += 2 * len) {
                int zeta = ZETAS[k--];
                for (int j = start; j < start + len; j++) {
                    int t = f[j];
                    f[j] = add(t, f[j + len]);
                    f[j + len] = mulSub(zeta, f[j + len], t);
                }
            }
        }
        for (int i = 0; i < N; i++) f[i] = mul(f[i], 3303); // 128^-1 mod q
        return f;
    }

    /** MultiplyNTTs (FIPS 203 algorithm 11). */
    private static int[] nttMul(int[] f, int[] g) {
        int[] h = new int[N];
        for (int i = 0; i < N; i += 2) {
            int a0 = f[i];
            int a1 = f[i + 1];
            int b0 = g[i];
            int b1 = g[i + 1];
            h[i] = addMul(a0, b0, mul(a1, b1), GAMMAS[i / 2]);
            h[i + 1] = addMul(a0, b1, a1, b0);
        }
        return h;
    }

    // --- hashes ---

    private static byte[] sha3_256(byte[] data) {
        return digest("SHA3-256", data, null);
    }

    private static byte[] sha3_512(byte[] a, byte[] b) {
        return digest("SHA3-512", a, b);
    }

    private static byte[] digest(String algorithm, byte[] a, byte[] b) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(a);
            if (b != null) md.update(b);
            return md.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(algorithm + " is part of every Java 21 runtime", e);
        }
    }
}
