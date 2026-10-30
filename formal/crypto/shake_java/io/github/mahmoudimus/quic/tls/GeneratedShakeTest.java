package io.github.mahmoudimus.quic.tls;

import SpongeSpec.ReadResult;
import SpongeSpec.State;
import SpongeSpec.UpdateResult;
import dafny.DafnySequence;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

/** Finite generated-code tests. Dafny separately checks the universal contracts. */
public final class GeneratedShakeTest {
    private static int assertions, vectors, partitions, slices, wordCases;
    private static final DafnySequence<Byte> EMPTY = DafnySequence.of(new byte[0]);
    private static BigInteger n(long x) { return BigInteger.valueOf(x); }
    private static void check(boolean ok, String message) {
        assertions++;
        if (!ok) throw new AssertionError(message);
    }
    private static byte[] bytes(DafnySequence<? extends Byte> value) {
        byte[] out = new byte[value.length()];
        for (int i = 0; i < out.length; i++) out[i] = value.select(i);
        return out;
    }
    private static void eq(byte[] a, byte[] b, String message) { check(Arrays.equals(a,b), message); }
    private static byte[] canonical(int rate, byte[] data, int length) {
        byte[] out = new byte[length];
        (rate == 168 ? Shake.shake128() : Shake.shake256()).update(data).read(out);
        return out;
    }
    private static State updated(UpdateResult r) {
        check(r.is_Updated(), "valid update rejected");
        return r.dtor_state();
    }
    private static void vector(int rate, byte[] input, byte[] expected) {
        byte[] original = input.clone();
        var data = DafnySequence.of(input.clone());
        eq(expected,bytes(VerifiedShake.__default.Xof(n(rate),data,n(expected.length))),"hashlib value");
        eq(expected,canonical(rate,input,expected.length),"canonical Java value");
        State state = updated(VerifiedShake.__default.Update(VerifiedShake.__default.New(n(rate)),EMPTY));
        for (int at = 0; at < input.length;) {
            int count = Math.min(1+at%23,input.length-at);
            state = updated(VerifiedShake.__default.UpdateSlice(state,data,n(at),n(count)));
            at += count;
            state = updated(VerifiedShake.__default.Update(state,EMPTY));
        }
        ReadResult zero = VerifiedShake.__default.Read(state,n(0));
        check(zero.dtor_bytes().length() == 0 && zero.dtor_state().dtor_squeezing(),"zero read phase");
        state = zero.dtor_state();
        check(VerifiedShake.__default.Update(state,EMPTY).is_InputAfterOutput(),"input after zero output");
        check(VerifiedShake.__default.UpdateSlice(state,data,n(-1),n(-1)).is_InputAfterOutput(),"phase precedence");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (out.size() < expected.length) {
            int count = Math.min(1+out.size()%37,expected.length-out.size());
            ReadResult next = VerifiedShake.__default.Read(state,n(count));
            out.writeBytes(bytes(next.dtor_bytes()));
            state = next.dtor_state();
            zero = VerifiedShake.__default.Read(state,n(0));
            check(zero.dtor_state().equals(state),"zero read advanced state");
            state = zero.dtor_state();
        }
        eq(expected,out.toByteArray(),"partition law");
        eq(original,input,"input modified");
        vectors++;
        partitions++;
    }
    private static void slices() {
        byte[] input = {(byte)128,(byte)255,0,127};
        var data = DafnySequence.of(input.clone());
        int[][] bad = {{-1,0},{0,-1},{5,0},{1,4},{4,1},{Integer.MAX_VALUE,Integer.MAX_VALUE},{0,Integer.MAX_VALUE}};
        int[][] good = {{0,0},{0,4},{4,0},{1,3},{2,1}};
        for (int rate : new int[] {136,168}) {
            State initial = VerifiedShake.__default.New(n(rate));
            for (int[] p : bad) {
                check(VerifiedShake.__default.UpdateSlice(initial,data,n(p[0]),n(p[1])).is_InvalidSlice(),"bad slice accepted");
                eq(canonical(rate,new byte[0],32),bytes(VerifiedShake.__default.Read(initial,n(32)).dtor_bytes()),"error changed state");
                slices++;
            }
            for (int[] p : good) {
                State state = updated(VerifiedShake.__default.UpdateSlice(initial,data,n(p[0]),n(p[1])));
                byte[] expected = canonical(rate,Arrays.copyOfRange(input,p[0],p[0]+p[1]),64);
                ReadResult r = VerifiedShake.__default.Read(state,n(64));
                byte[] a = bytes(r.dtor_bytes()), b = bytes(r.dtor_bytes());
                eq(expected,a,"slice value");
                check(a != b,"output freshness");
                a[0] ^= (byte)255;
                eq(expected,b,"output alias");
                eq(expected,bytes(r.dtor_bytes()),"result alias");
                slices++;
            }
        }
    }
    private static void words() {
        Random random = new Random(0x2021600L);
        for (int test = 0; test < 512; test++) {
            long w = random.nextLong();
            byte[] b = new byte[8];
            for (int j = 0; j < 8; j++) {
                b[j] = ByteLanes.__default.Octet(w,j);
                check(Byte.toUnsignedInt(b[j]) == ((w >>> (8*j)) & 255),"little-endian byte");
                wordCases++;
            }
            check(ByteLanes.__default.Pack8(b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]) == w,"rebuild word");
            for (int at = 0; at < 8; at++) for (int seen = 0; seen < 8; seen++) {
                byte v = (byte)test;
                long changed = w ^ (Byte.toUnsignedLong(v) << (8*at));
                byte expected = (byte)(b[seen] ^ (at == seen ? v : 0));
                check(ByteLanes.__default.Octet(changed,seen) == expected,"xor changed another byte");
                wordCases++;
            }
        }
    }
    public static void main(String[] args) throws Exception {
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            String[] f = line.split("\t",-1);
            vector(Integer.parseInt(f[0]),HexFormat.of().parseHex(f[1]),HexFormat.of().parseHex(f[2]));
        }
        slices();
        words();
        System.out.println("PASS GeneratedShakeTest {\"vectors\":"+vectors+",\"partitions\":"+partitions
                +",\"slices\":"+slices+",\"word_cases\":"+wordCases+",\"assertions\":"+assertions+"}");
    }
}
