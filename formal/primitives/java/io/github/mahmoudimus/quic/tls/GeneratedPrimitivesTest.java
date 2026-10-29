package io.github.mahmoudimus.quic.tls;

import dafny.DafnySequence;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/** Standalone finite tests of the exact generated artifact, not a Java refinement proof. */
public final class GeneratedPrimitivesTest {
    private static int assertions;
    private static int states;
    private static int fieldCases;
    private static int oneBitStates;
    private static int rotationCases;
    private static final int Q = 3329;
    private static final int MAX = 22154496;

    private static void check(boolean value, String message) {
        assertions++;
        if (!value) throw new AssertionError(message);
    }

    private static BigInteger n(long x) { return BigInteger.valueOf(x); }

    private static long[] words(DafnySequence<? extends Long> s) {
        long[] a = new long[s.length()];
        for (int i = 0; i < a.length; i++) a[i] = s.select(i);
        return a;
    }

    private static void constantsAndCoordinates() {
        var constants = VerifiedKeccak.__default.Constants();
        int lfsr = 1;
        check(constants.length() == 24, "round constant count");
        for (int round = 0; round < 24; round++) {
            long expected = 0;
            for (int j = 0; j < 7; j++) {
                if ((lfsr & 1) != 0) expected ^= 1L << ((1 << j) - 1);
                lfsr = ((lfsr << 1) ^ ((lfsr & 128) == 0 ? 0 : 0x171)) & 255;
            }
            check(constants.select(round) == expected, "FIPS round constant " + round);
        }
        int[] offsets = new int[25];
        boolean[] seen = new boolean[25];
        seen[0] = true;
        int x = 1, y = 0;
        for (int t = 0; t < 24; t++) {
            int at = x + 5*y;
            check(!seen[at], "rho coordinate reused");
            seen[at] = true;
            offsets[at] = ((t+1)*(t+2)/2)%64;
            int nextY = (2*x+3*y)%5;
            x = y;
            y = nextY;
        }
        var actual = VerifiedKeccak.__default.Offsets();
        for (int i = 0; i < 25; i++) {
            check(seen[i], "rho omitted lane");
            check(actual.select(i).intValueExact() == offsets[i], "rho offset " + i);
        }
        long[] coordinates = new long[25];
        for (int i = 0; i < 25; i++) coordinates[i] = i;
        long[] pi = words(VerifiedKeccak.__default.Pi(DafnySequence.of(coordinates)));
        // Forward coordinate relation, independent of the spec's inverse lookup.
        for (int sx = 0; sx < 5; sx++) for (int sy = 0; sy < 5; sy++) {
            check(pi[sy + 5*((2*sx+3*sy)%5)] == coordinates[sx+5*sy], "pi axes");
        }
        for (int bit = 0; bit < 64; bit++) for (int shift = 0; shift < 64; shift++) {
            long v = 1L << bit;
            check(VerifiedKeccak.__default.Rotate(v, n(shift)) == Long.rotateLeft(v, shift), "rotation");
            rotationCases++;
        }
    }

    private static void permutation(long[] input) {
        long[] copy = input.clone();
        var immutable = DafnySequence.of(input);
        long[] actual = words(VerifiedKeccak.__default.Permute(immutable));
        long[] expected = copy.clone();
        Shake.keccak(expected);
        check(Arrays.equals(expected, actual), "canonical permutation state " + states);
        check(Arrays.equals(input, copy), "input array changed");
        check(Arrays.equals(words(immutable), copy), "input sequence changed");
        states++;
    }

    private static void permutations() {
        // XKCP KeccakF-1600-IntermediateValues.txt, all-zero input, final lanes.
        // Pinned reference: 5585d0213203c0c5b2dfdf3b34f5da9275abc3e7.
        String[] kat = ("F1258F7940E1DDE7 84D5CCF933C0478A D598261EA65AA9EE BD1547306F80494D 8B284E056253D057 "
            + "FF97A42D7F8E6FD4 90FEE5A0A44647C4 8C5BDA0CD6192E76 AD30A6F71B19059C 30935AB7D08FFC64 "
            + "EB5AA93F2317D635 A9A6E6260D712103 81A57C16DBCF555F 43B831CD0347C826 01F22F1A11A5569F "
            + "05E5635A21D9AE61 64BEFEF28CC970F2 613670957BC46611 B87C5A554FD00ECB 8C3EE88A1CCF32C8 "
            + "940C7922AE3A2614 1841F924A2C509E4 16F53526E70465C2 75F644E97F30A13B EAF1FF7B5CECA249").split(" ");
        long[] zero = words(VerifiedKeccak.__default.Permute(DafnySequence.of(new long[25])));
        for (int i = 0; i < 25; i++) check(zero[i] == Long.parseUnsignedLong(kat[i], 16), "XKCP zero KAT");
        permutation(new long[25]);
        long[] ones = new long[25];
        Arrays.fill(ones, -1L);
        permutation(ones);
        for (int lane = 0; lane < 25; lane++) for (int bit = 0; bit < 64; bit++) {
            long[] a = new long[25];
            a[lane] = 1L << bit;
            permutation(a);
            oneBitStates++;
        }
        Random random = new Random(0x202203L);
        for (int i = 0; i < 96; i++) {
            long[] a = new long[25];
            for (int j = 0; j < 25; j++) a[j] = random.nextLong();
            permutation(a);
        }
    }

    private static Method canonical(String name, Class<?>... args) throws Exception {
        Method m = MlKem768.class.getDeclaredMethod(name, args);
        m.setAccessible(true);
        return m;
    }

    private static void field() throws Exception {
        Method once = canonical("reduceOnce", int.class);
        Method reduce = canonical("reduce", long.class);
        Method add = canonical("add", int.class, int.class);
        Method sub = canonical("sub", int.class, int.class);
        Method mul = canonical("mul", int.class, int.class);
        Method mulSub = canonical("mulSub", int.class, int.class, int.class);
        Method addMul = canonical("addMul", int.class, int.class, int.class, int.class);
        for (int a = 0; a < 2*Q; a++) {
            int actual = VerifiedField.__default.ReduceOnce(n(a)).intValueExact();
            check(actual == a%Q && actual == (int)once.invoke(null, a), "reduceOnce " + a);
            fieldCases++;
        }
        int[] edges = {0, 1, Q-1, Q, Q+1, 2*Q-1, (1<<24)-1, 1<<24, (1<<24)+1, MAX-1, MAX};
        for (int a : edges) compareReduce(reduce, a);
        Random random = new Random(0x203202L);
        for (int i = 0; i < 4096; i++) {
            compareReduce(reduce, random.nextInt(MAX+1));
            int a = random.nextInt(Q), b = random.nextInt(Q), c = random.nextInt(Q), d = random.nextInt(Q);
            compare(VerifiedField.__default.Add(n(a), n(b)), add, Math.floorMod(a+b, Q), a, b);
            compare(VerifiedField.__default.Sub(n(a), n(b)), sub, Math.floorMod(a-b, Q), a, b);
            compare(VerifiedField.__default.Mul(n(a), n(b)), mul, (a*b)%Q, a, b);
            compare(VerifiedField.__default.MulSub(n(a), n(b), n(c)), mulSub, Math.floorMod(a*(b-c), Q), a, b, c);
            compare(VerifiedField.__default.AddMul(n(a), n(b), n(c), n(d)), addMul, (a*b+c*d)%Q, a, b, c, d);
        }
        // Maximum-domain caller witnesses; canonical coefficients at both extremes.
        compare(VerifiedField.__default.MulSub(n(Q-1), n(Q-1), n(0)), mulSub,
                Math.floorMod((Q-1)*(Q-1), Q), Q-1, Q-1, 0);
        compare(VerifiedField.__default.AddMul(n(Q-1), n(Q-1), n(Q-1), n(Q-1)), addMul,
                (2*(Q-1)*(Q-1))%Q, Q-1, Q-1, Q-1, Q-1);
    }

    private static void compareReduce(Method reference, int a) throws Exception {
        int actual = VerifiedField.__default.Reduce(n(a)).intValueExact();
        check(actual == a%Q && actual == (int)reference.invoke(null, (long)a), "wide Barrett " + a);
        fieldCases++;
    }

    private static void compare(BigInteger actual, Method reference, int expected, Object... args) throws Exception {
        int value = actual.intValueExact();
        check(value == expected && value == (int)reference.invoke(null, args), "field " + reference.getName());
        fieldCases++;
    }

    public static void main(String[] args) throws Exception {
        constantsAndCoordinates();
        permutations();
        field();
        System.out.println("PASS GeneratedPrimitivesTest {\"one_bit_states\":" + oneBitStates + ",\"keccak_states\":" + states
            + ",\"rotation_cases\":" + rotationCases + ",\"field_cases\":" + fieldCases + ",\"assertions\":" + assertions + "}");
    }
}
