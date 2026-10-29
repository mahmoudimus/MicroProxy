package io.github.mahmoudimus.quic.tls;

import dafny.DafnySequence;
import dafny.TypeDescriptor;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/** Finite exact-artifact checks. These are not a production Java refinement proof. */
public final class polynomial_java {
    private static final int Q = 3329;
    private static int assertions;
    private static int cases;
    private static int products;

    private static DafnySequence<BigInteger> seq(int[] a) {
        BigInteger[] out = new BigInteger[a.length];
        for (int i = 0; i < a.length; i++) out[i] = BigInteger.valueOf(a[i]);
        return DafnySequence.of(TypeDescriptor.BIG_INTEGER, out);
    }

    private static int[] ints(DafnySequence<? extends BigInteger> a) {
        int[] out = new int[a.length()];
        for (int i = 0; i < a.length(); i++) out[i] = a.select(i).intValueExact();
        return out;
    }

    private static int mod(long a) { return (int) Math.floorMod(a, Q); }
    private static int pow(int a, int e) {
        int p = 1;
        for (int i = 0; i < e; i++) p = mod((long) p * a);
        return p;
    }
    private static int gamma(int i) { return pow(17, 2 * (Integer.reverse(i) >>> 25) + 1); }

    private static void equal(int[] actual, int[] expected, String label) {
        assertions++;
        if (!Arrays.equals(actual, expected)) throw new AssertionError(label);
        if (actual.length != 256) throw new AssertionError(label + " length");
        for (int x : actual) {
            assertions++;
            if (x < 0 || x >= Q) throw new AssertionError(label + " canonical");
        }
    }

    // Direct polynomial remainder evaluation, independent of the butterfly loops.
    private static int[] mathematicalNtt(int[] f) {
        int[] result = new int[256];
        for (int i = 0; i < 128; i++) {
            int r = gamma(i);
            for (int parity = 0; parity < 2; parity++) {
                int acc = 0;
                for (int j = 127; j >= 0; j--) acc = mod(f[2*j+parity] + (long) r*acc);
                result[2*i+parity] = acc;
            }
        }
        return result;
    }

    // Schoolbook convolution with X^256 == -1.
    private static int[] negacyclic(int[] f, int[] g) {
        long[] raw = new long[256];
        for (int i = 0; i < 256; i++) for (int j = 0; j < 256; j++) {
            long v = (long) f[i]*g[j];
            if (i+j < 256) raw[i+j] += v; else raw[i+j-256] -= v;
        }
        int[] out = new int[256];
        for (int i = 0; i < 256; i++) out[i] = mod(raw[i]);
        return out;
    }

    private static Method method(String name, boolean binary) throws Exception {
        Method m = binary ? MlKem768.class.getDeclaredMethod(name, int[].class, int[].class)
                          : MlKem768.class.getDeclaredMethod(name, int[].class);
        m.setAccessible(true);
        return m;
    }

    private static void test(int[] f, int[] g, boolean product) throws Exception {
        var sf = seq(f);
        var sg = seq(g);
        int[] before = f.clone();
        int[] beforeG = g.clone();
        var nf = VerifiedPolynomial.__default.Ntt(sf);
        equal(ints(nf), mathematicalNtt(f), "mathematical NTT");
        equal(ints(nf), (int[]) method("ntt", false).invoke(null, (Object) f), "production NTT");
        equal(ints(VerifiedPolynomial.__default.InverseNtt(nf)), f, "inverse round-trip");
        var inv = VerifiedPolynomial.__default.InverseNtt(sf);
        equal(ints(inv), (int[]) method("inverseNtt", false).invoke(null, (Object) f), "production inverse");
        equal(ints(VerifiedPolynomial.__default.Ntt(inv)), f, "right inverse");
        equal(f, before, "input ownership");
        if (product) {
            int[] add = new int[256], sub = new int[256];
            for (int i = 0; i < 256; i++) { add[i] = mod(f[i]+g[i]); sub[i] = mod(f[i]-g[i]); }
            equal(ints(VerifiedPolynomial.__default.Add(sf,sg)), add, "addition");
            equal(ints(VerifiedPolynomial.__default.Sub(sf,sg)), sub, "subtraction");
            equal(ints(VerifiedPolynomial.__default.NttMul(sf,sg)),
                  (int[]) method("nttMul", true).invoke(null, f, g), "production NTT product");
            var ng = VerifiedPolynomial.__default.Ntt(sg);
            equal(ints(VerifiedPolynomial.__default.InverseNtt(VerifiedPolynomial.__default.NttMul(nf,ng))),
                  negacyclic(f,g), "negacyclic product");
            products++;
        }
        equal(g, beforeG, "second input ownership");
        cases++;
    }

    public static void main(String[] args) throws Exception {
        Random random = new Random(0x2033329L);
        for (int c = 0; c < 32; c++) {
            int[] f = new int[256], g = new int[256];
            for (int i = 0; i < 256; i++) {
                f[i] = c == 0 ? 0 : c == 1 ? Q-1 : random.nextInt(Q);
                g[i] = c == 0 ? Q-1 : c == 1 ? 1 : random.nextInt(Q);
            }
            test(f, g, true);
        }
        for (int i = 0; i < 256; i++) {
            int[] basis = new int[256];
            basis[i] = Q-1;
            test(basis, new int[256], false);
        }
        System.out.println("POLYNOMIAL_CHECKS cases=" + cases + " product_cases=" + products + " assertions=" + assertions);
    }
}
