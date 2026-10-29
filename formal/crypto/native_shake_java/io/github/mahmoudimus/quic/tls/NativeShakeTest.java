package io.github.mahmoudimus.quic.tls;

import NativeShake.Sponge;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

/** Finite native-refinement compatibility tests; universal contracts are in Dafny. */
public final class NativeShakeTest {
    private static int assertions, vectors, partitions, permutations, slices;
    private static volatile long sink;
    private static final java.lang.management.ThreadMXBean CLOCK = java.lang.management.ManagementFactory.getThreadMXBean();
    private record Timing(long wall, long cpu) {}
    private static Sponge sponge(int rate) { Sponge s = new Sponge(); s.__ctor(rate); return s; }
    private static void check(boolean value, String message) {
        assertions++;
        if (!value) throw new AssertionError(message);
    }
    private static void eq(byte[] a, byte[] b, String message) { check(Arrays.equals(a,b),message); }
    private static byte[] canonical(int rate, byte[] input, int size) {
        byte[] out = new byte[size];
        (rate == 168 ? Shake.shake128() : Shake.shake256()).update(input).read(out);
        return out;
    }
    private static void vector(int rate, byte[] input, byte[] expected) {
        Sponge s = sponge(rate);
        byte[] untouched = input.clone();
        check(s.Update(input,0,input.length) == 0,"valid one-shot update");
        byte[] out = new byte[expected.length];
        s.Read(out);
        eq(expected,out,"hashlib native output");
        byte[] oneShot = NativeShake.__default.Xof(rate,input,expected.length);
        eq(expected,oneShot,"one-shot native output with destruction");
        check(oneShot != input && oneShot != out,"one-shot output aliases caller array");
        eq(expected,canonical(rate,input,out.length),"canonical output");
        eq(input,untouched,"input changed");
        Sponge p = sponge(rate);
        for (int at = 0; at < input.length;) {
            int count = Math.min(input.length-at,1+at%23);
            check(p.Update(input,at,count) == 0,"partition update");
            check(p.Update(input,at,0) == 0,"empty update");
            at += count;
        }
        p.Read(new byte[0]);
        check(p.squeezing,"zero read initiates phase");
        check(p.Update(input,-1,-1) == 1,"phase precedence");
        ByteArrayOutputStream collected = new ByteArrayOutputStream();
        while (collected.size() < expected.length) {
            byte[] chunk = new byte[Math.min(expected.length-collected.size(),1+collected.size()%37)];
            p.Read(chunk);
            collected.writeBytes(chunk);
            long[] lanes = p.lanes().clone();
            int position = p.position;
            p.Read(new byte[0]);
            check(p.position == position && Arrays.equals(lanes,p.lanes()),"zero read advances state");
            if (chunk.length > 0) chunk[0] ^= 1;
            check(Arrays.equals(lanes,p.lanes()),"output aliases state");
        }
        eq(expected,collected.toByteArray(),"partition output");
        check(s.lanes() != p.lanes(),"instances alias");
        p.Destroy();
        check(!p.squeezing && p.position == 0,"destroy reset state");
        for (long lane : p.lanes()) check(lane == 0,"destroy left lane");
        for (long lane : p.scratch()) check(lane == 0,"destroy left scratch");
        for (long lane : p.parity()) check(lane == 0,"destroy left parity");
        eq(expected,out,"destroy changed returned bytes");
        vectors++; partitions++;
    }
    private static void boundaries() {
        byte[] input = {(byte)128,(byte)255,0,127};
        int[][] bad = {{-1,0},{0,-1},{5,0},{1,4},{4,1},{Integer.MAX_VALUE,Integer.MAX_VALUE},{0,Integer.MAX_VALUE}};
        int[][] good = {{0,0},{0,4},{4,0},{1,3},{2,1}};
        for (int rate : new int[]{136,168}) {
            Sponge s = sponge(rate);
            for (int[] p : bad) {
                long[] before = s.lanes().clone();
                check(s.Update(input,p[0],p[1]) == 2,"invalid slice accepted");
                check(s.position == 0 && !s.squeezing && Arrays.equals(before,s.lanes()),"invalid slice mutates state");
                slices++;
            }
            for (int[] p : good) {
                Sponge t = sponge(rate);
                check(t.Update(input,p[0],p[1]) == 0,"valid boundary slice rejected");
                byte[] out = new byte[97]; t.Read(out);
                eq(canonical(rate,Arrays.copyOfRange(input,p[0],p[0]+p[1]),out.length),out,"boundary slice output");
                slices++;
            }
        }
    }
    private static void permutations() {
        Random random = new Random(0x5348414b454cL);
        for (int i = 0; i < 1728; i++) {
            long[] input = new long[25];
            if (i < 1600) input[i/64] = 1L << (i%64);
            else for (int j = 0; j < 25; j++) input[j] = random.nextLong();
            long[] expected = input.clone(); Shake.keccak(expected);
            NativeKeccak.__default.Permute(input);
            check(Arrays.equals(expected,input),"permutation mismatch "+i);
            permutations++;
        }
    }
    private static Timing timed(boolean nativeCode, byte[] input, int size, int count) {
        long start = System.nanoTime();
        long cpu = CLOCK.getCurrentThreadCpuTime();
        long sum = 0;
        for (int i = 0; i < count; i++) {
            byte[] out = new byte[size];
            if (nativeCode) {
                Sponge s = sponge(136); s.Update(input,0,input.length); s.Read(out);
            } else Shake.shake256().update(input).read(out);
            sum += out[i%size];
        }
        sink = sum;
        return new Timing(System.nanoTime()-start,CLOCK.getCurrentThreadCpuTime()-cpu);
    }
    private static void benchmark() {
        Random random = new Random(203202);
        for (int[] shape : new int[][]{{34,840,1200},{128,128,2000},{4096,4096,400}}) {
            byte[] input = new byte[shape[0]]; random.nextBytes(input);
            timed(false,input,shape[1],shape[2]); timed(true,input,shape[1],shape[2]);
            long[] old = new long[7], next = new long[7], oldCpu = new long[7], nextCpu = new long[7];
            for (int i = 0; i < 7; i++) {
                Timing a,b;
                if (i%2 == 0) { a = timed(false,input,shape[1],shape[2]); b = timed(true,input,shape[1],shape[2]); }
                else { b = timed(true,input,shape[1],shape[2]); a = timed(false,input,shape[1],shape[2]); }
                old[i] = a.wall(); next[i] = b.wall(); oldCpu[i] = a.cpu(); nextCpu[i] = b.cpu();
            }
            Arrays.sort(old); Arrays.sort(next); Arrays.sort(oldCpu); Arrays.sort(nextCpu);
            System.out.println("BENCH NativeShakeTest {\"input\":"+shape[0]+",\"output\":"+shape[1]+",\"iterations\":"+shape[2]+",\"baseline_median_ns\":"+old[3]+",\"native_median_ns\":"+next[3]+",\"ratio\":"+(double)next[3]/old[3]+",\"baseline_cpu_median_ns\":"+oldCpu[3]+",\"native_cpu_median_ns\":"+nextCpu[3]+",\"cpu_ratio\":"+(double)nextCpu[3]/oldCpu[3]+"}");
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--benchmark")) { benchmark(); return; }
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            String[] f = line.split("\t",-1);
            vector(Integer.parseInt(f[0]),HexFormat.of().parseHex(f[1]),HexFormat.of().parseHex(f[2]));
        }
        boundaries(); permutations();
        System.out.println("PASS NativeShakeTest {\"vectors\":"+vectors+",\"partitions\":"+partitions+",\"permutations\":"+permutations+",\"slices\":"+slices+",\"assertions\":"+assertions+"}");
    }
}
