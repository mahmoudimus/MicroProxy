package io.github.mahmoudimus.quic.tls;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Random;

/** Finite exact-artifact checks. These are not a production Java refinement proof. */
public final class native_polynomial_test {
    private static final int Q = 3329;
    private static int assertions;
    private static int cases;
    private static int products;

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
        var sf = f;
        var sg = g;
        int[] before = f.clone();
        int[] beforeG = g.clone();
        var nf = NativePolynomial.__default.Ntt(sf);
        equal(nf, mathematicalNtt(f), "mathematical NTT");
        equal(nf, (int[]) method("ntt", false).invoke(null, (Object) f), "production NTT");
        equal(NativePolynomial.__default.InverseNtt(nf), f, "inverse round-trip");
        var inv = NativePolynomial.__default.InverseNtt(sf);
        equal(inv, (int[]) method("inverseNtt", false).invoke(null, (Object) f), "production inverse");
        equal(NativePolynomial.__default.Ntt(inv), f, "right inverse");
        equal(f, before, "input ownership");
        if (product) {
            int[] add = new int[256], sub = new int[256];
            for (int i = 0; i < 256; i++) { add[i] = mod(f[i]+g[i]); sub[i] = mod(f[i]-g[i]); }
            equal(NativePolynomial.__default.Add(sf,sg), add, "addition");
            equal(NativePolynomial.__default.Sub(sf,sg), sub, "subtraction");
            equal(NativePolynomial.__default.NttMul(sf,sg),
                  (int[]) method("nttMul", true).invoke(null, f, g), "production NTT product");
            var ng = NativePolynomial.__default.Ntt(sg);
            equal(NativePolynomial.__default.InverseNtt(NativePolynomial.__default.NttMul(nf,ng)),
                  negacyclic(f,g), "negacyclic product");
            products++;
        }
        equal(g, beforeG, "second input ownership");
        if (nf == f || inv == f || inv == nf) throw new AssertionError("fresh outputs");
        int[] aliased = NativePolynomial.__default.NttMul(f,f);
        equal(aliased, (int[]) method("nttMul", true).invoke(null, f, f), "aliased operands");
        equal(f, before, "aliased input ownership");
        if (aliased == f) throw new AssertionError("fresh aliased output");
        cases++;
    }

    private static void fieldChecks() {
        for (int a = 0; a < 6658; a++) {
            assertions++;
            if (NativeField.__default.ReduceOnce(a) != a%Q) throw new AssertionError("reduceOnce " + a);
        }
        for (int a = 0; a <= 22154496; a++) {
            assertions++;
            if (NativeField.__default.Reduce(a) != a%Q) throw new AssertionError("reduce " + a);
        }
        int[] edges = {0,1,1664,3327,3328};
        for (int a : edges) for (int b : edges) {
            assertions += 3;
            if (NativeField.__default.Add(a,b) != mod(a+b)) throw new AssertionError("field add");
            if (NativeField.__default.Sub(a,b) != mod(a-b)) throw new AssertionError("field sub");
            if (NativeField.__default.Mul(a,b) != mod((long)a*b)) throw new AssertionError("field mul");
            for (int c : edges) {
                assertions++;
                if (NativeField.__default.MulSub(a,b,c) != mod((long)a*(b-c))) throw new AssertionError("field mulsub");
                for (int d : edges) {
                    assertions++;
                    if (NativeField.__default.AddMul(a,b,c,d) != mod((long)a*b+(long)c*d)) throw new AssertionError("field addmul");
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        fieldChecks();
        for (int length : new int[]{0,1,255,256,257,4096}) {
            int[] secret = new int[length]; Arrays.fill(secret, Integer.MIN_VALUE);
            NativePolynomial.__default.Wipe(secret);
            for (int value : secret) { assertions++; if (value != 0) throw new AssertionError("wipe"); }
        }
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
        System.out.println("NATIVE_POLYNOMIAL_CHECKS cases=" + cases + " product_cases=" + products + " assertions=" + assertions);
    }
}
