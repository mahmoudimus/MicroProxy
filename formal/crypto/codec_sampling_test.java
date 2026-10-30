package io.github.mahmoudimus.quic.tls;

import dafny.DafnySequence;
import dafny.TypeDescriptor;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/** Finite checks of the exact generated artifact; not a universal Java refinement. */
public final class codec_sampling_test {
    private static int assertions, scalars, encodings, malformed, cbd, feeds, javaSamples;
    private static BigInteger n(int x) { return BigInteger.valueOf(x); }
    private static void check(boolean p, String label) {
        assertions++;
        if (!p) throw new AssertionError(label);
    }
    private static DafnySequence<? extends BigInteger> seq(int[] a) {
        BigInteger[] b = new BigInteger[a.length];
        for (int i = 0; i < a.length; i++) b[i] = n(a[i]);
        return DafnySequence.of(TypeDescriptor.BIG_INTEGER,b);
    }
    private static int[] ints(DafnySequence<? extends BigInteger> a) {
        int[] b = new int[a.length()];
        for (int i = 0; i < b.length; i++) b[i] = a.select(i).intValueExact();
        return b;
    }
    private static byte[] bytes(DafnySequence<? extends Byte> a) {
        byte[] b = new byte[a.length()];
        for (int i = 0; i < b.length; i++) b[i] = a.select(i);
        return b;
    }
    private static Method method(String name, Class<?>... args) throws Exception {
        Method m = MlKem768.class.getDeclaredMethod(name,args);
        m.setAccessible(true);
        return m;
    }
    private static int compress(int x, int d) { return ((2*(1<<d)*x+3329)/6658)% (1<<d); }
    private static int decompress(int x, int d) { return (2*3329*x+(1<<d))/(2*(1<<d)); }
    private static byte[] bitEncode(int[] f, int d) {
        byte[] b = new byte[32*d];
        for (int i = 0; i < 256; i++) for (int j = 0; j < d; j++) {
            int k = i*d+j;
            b[k/8] |= (byte) (((f[i]>>>j)&1)<<(k%8));
        }
        return b;
    }
    private static int[] bitDecode(byte[] b, int d) {
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) for (int j = 0; j < d; j++) {
            int k = i*d+j;
            f[i] |= ((b[k/8]>>>(k%8))&1)<<j;
        }
        return f;
    }
    private static void scalars() throws Exception {
        Method c = method("compress",int.class,int.class), e = method("decompress",int.class,int.class);
        for (int d = 1; d <= 11; d++) {
            for (int x = 0; x < 3329; x++) {
                int actual = VerifiedCodec.__default.Compress(n(x),n(d)).intValueExact();
                check(actual == compress(x,d),"FIPS compression");
                check(actual == (int)c.invoke(null,x,d),"Java compression");
                int y = VerifiedCodec.__default.Decompress(n(actual),n(d)).intValueExact();
                int delta = Math.floorMod(x-y,3329);
                check(Math.min(delta,3329-delta) <= (3329+(1<<d))/(2*(1<<d)),"circular error");
                scalars++;
            }
            for (int x = 0; x < (1<<d); x++) {
                int actual = VerifiedCodec.__default.Decompress(n(x),n(d)).intValueExact();
                check(actual == decompress(x,d),"FIPS decompression ties");
                check(actual == (int)e.invoke(null,x,d),"Java decompression");
                scalars++;
            }
        }
    }
    private static void encoding(int[] f, int d) {
        var input = seq(f);
        int[] snapshot = f.clone();
        byte[] b = bytes(VerifiedCodec.__default.Encode(input,n(d)));
        check(Arrays.equals(b,bitEncode(f,d)),"little endian byte equation");
        var decoded = VerifiedCodec.__default.Decode(DafnySequence.of(b),n(d));
        check(decoded.is_Decoded(),"raw decode accepted");
        check(Arrays.equals(ints(decoded.dtor_words()),f),"raw round trip");
        check(Arrays.equals(ints(input),snapshot) && Arrays.equals(f,snapshot),"input ownership");
        encodings++;
    }
    private static void codecs() throws Exception {
        Random random = new Random(0x203c0decL);
        for (int d : new int[] {1,4,10,12}) {
            encoding(new int[256],d);
            for (int i = 0; i < 256; i++) for (int j = 0; j < d; j++) {
                int[] f = new int[256]; f[i] = 1<<j; encoding(f,d);
            }
            for (int trial = 0; trial < 32; trial++) {
                int[] f = new int[256];
                for (int i = 0; i < 256; i++) f[i] = random.nextInt(d == 12 ? 3329 : 1<<d);
                encoding(f,d);
            }
            for (int trial = 0; trial < 32; trial++) {
                int[] f = new int[256], c = new int[256];
                for (int i = 0; i < 256; i++) { f[i] = random.nextInt(3329); c[i] = d == 12 ? f[i] : compress(f[i],d); }
                byte[] b = bytes(VerifiedCodec.__default.CompressAndEncode(seq(f),n(d)));
                check(Arrays.equals(b,bitEncode(c,d)),"combined encoding");
                byte[] old = new byte[b.length];
                if (d == 12) method("polyByteEncode",int[].class,byte[].class,int.class).invoke(null,f,old,0);
                else if (d == 1) old = (byte[])method("ringCompressAndEncode1",int[].class).invoke(null,(Object)f);
                else method("ringCompressAndEncode"+d,int[].class,byte[].class,int.class).invoke(null,f,old,0);
                check(Arrays.equals(b,old),"canonical Java encoding");
                int[] decoded = ints(VerifiedCodec.__default.DecodeAndDecompress(DafnySequence.of(b),n(d)).dtor_words());
                int[] expected = bitDecode(b,d);
                if (d != 12) for (int i = 0; i < 256; i++) expected[i] = decompress(expected[i],d);
                check(Arrays.equals(decoded,expected),"combined decode");
                int[] oldDecoded;
                if (d == 12) oldDecoded = (int[])method("polyByteDecode",byte[].class,int.class).invoke(null,b,0);
                else if (d == 1) oldDecoded = (int[])method("ringDecodeAndDecompress1",byte[].class).invoke(null,(Object)b);
                else oldDecoded = (int[])method("ringDecodeAndDecompress"+d,byte[].class,int.class).invoke(null,b,0);
                check(Arrays.equals(decoded,oldDecoded),"canonical Java decoding");
            }
            for (int length : new int[] {0,1,32*d-1,32*d+1,1000}) {
                var r = VerifiedCodec.__default.Decode(DafnySequence.of(new byte[length]),n(d));
                check(r.is_InvalidLength(),"length rejection"); malformed++;
            }
        }
        for (int d : new int[] {Integer.MIN_VALUE,-1,0,2,3,5,8,11,13,Integer.MAX_VALUE}) {
            check(VerifiedCodec.__default.Decode(DafnySequence.of(new byte[0]),n(d)).is_InvalidWidth(),"width rejection"); malformed++;
        }
        for (int i = 0; i < 256; i++) {
            int[] f = new int[256]; f[i] = 3329;
            check(VerifiedCodec.__default.Decode(DafnySequence.of(bitEncode(f,12)),n(12)).is_ModulusError(),"modulus at every position"); malformed++;
        }
        for (int x = 3329; x < 4096; x++) for (int i = 0; i < 2; i++) {
            int[] f = new int[256]; f[i] = x;
            check(VerifiedCodec.__default.Decode(DafnySequence.of(bitEncode(f,12)),n(12)).is_ModulusError(),"every noncanonical 12-bit value"); malformed++;
        }
    }
    private static int[] cbdReference(byte[] b) {
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) {
            int sum = 0;
            for (int j = 0; j < 4; j++) { int k = 4*i+j; sum += ((b[k/8]>>>(k%8))&1)*(j<2 ? 1 : -1); }
            f[i] = Math.floorMod(sum,3329);
        }
        return f;
    }
    private static void cbd(byte[] b) {
        byte[] copy = b.clone();
        var input = DafnySequence.of(b);
        check(Arrays.equals(ints(VerifiedSampling.__default.Cbd2(input)),cbdReference(b)),"CBD bit sums");
        check(Arrays.equals(copy,b) && Arrays.equals(bytes(input),copy),"CBD ownership");
        cbd++;
    }
    private static byte[] pair(int x, int y) {
        return new byte[] {(byte)x,(byte)((x>>>8)|(y<<4)),(byte)(y>>>4)};
    }
    private static SamplingSpec.FeedResult feed(int[] current, byte[] b) {
        var r = VerifiedSampling.__default.Feed(seq(current),DafnySequence.of(b));
        ArrayList<Integer> values = new ArrayList<>(); for (int x: current) values.add(x);
        int off = 0;
        while (off < b.length && values.size() < 256) {
            int x = (b[off]&255)+256*(b[off+1]&15), y = ((b[off+1]&255)>>>4)+16*(b[off+2]&255);
            off += 3;
            if (x < 3329) values.add(x);
            if (values.size() < 256 && y < 3329) values.add(y);
        }
        int[] expected = values.stream().mapToInt(Integer::intValue).toArray();
        check(Arrays.equals(ints(r.dtor_coeffs()),expected),"Feed rejection order/cap");
        check(r.dtor_consumed().intValueExact() == off,"Feed byte consumption");
        check(r.is_Full() == (values.size()==256) && r.is_NeedMore() == (values.size()<256),"Feed status");
        feeds++;
        return r;
    }
    private static void sampling() throws Exception {
        for (int x = 0; x < 256; x++) { byte[] b = new byte[128]; Arrays.fill(b,(byte)x); cbd(b); }
        Random random = new Random(0x2035aL);
        for (int trial = 0; trial < 128; trial++) { byte[] b = new byte[128]; random.nextBytes(b); cbd(b); }
        for (int x = 0; x < 4096; x++) for (int prefix : new int[] {0,254,255,256}) feed(new int[prefix],pair(x,4095-x));
        for (int len : new int[] {0,3,24,168,768,4098}) {
            byte[] b = new byte[len]; Arrays.fill(b,(byte)255); feed(new int[0],b);
            Arrays.fill(b,(byte)0); feed(new int[0],b);
            random.nextBytes(b); feed(new int[17],b);
        }
        check(VerifiedSampling.__default.Feed(seq(new int[]{-1}),DafnySequence.of(new byte[0])).is_InvalidPrefix(),"negative prefix");
        check(VerifiedSampling.__default.Feed(seq(new int[]{3329}),DafnySequence.of(new byte[0])).is_InvalidPrefix(),"modulus prefix");
        check(VerifiedSampling.__default.Feed(seq(new int[257]),DafnySequence.of(new byte[0])).is_InvalidPrefix(),"long prefix");
        for (int length : new int[]{1,2,4,5,167}) check(VerifiedSampling.__default.Feed(seq(new int[0]),DafnySequence.of(new byte[length])).is_InvalidBlockLength(),"block length");
        Method oldCbd = method("samplePolyCbd",byte[].class,int.class), oldNtt = method("sampleNtt",byte[].class,int.class,int.class);
        for (int trial = 0; trial < 16; trial++) {
            byte[] seed = new byte[32]; random.nextBytes(seed);
            for (int nonce : new int[]{0,1,127,128,255}) {
                byte[] b = new byte[128]; Shake.shake256().update(seed).update(new byte[]{(byte)nonce}).read(b);
                check(Arrays.equals(ints(VerifiedSampling.__default.Cbd2(DafnySequence.of(b))),(int[])oldCbd.invoke(null,seed,nonce)),"Java PRF/CBD bytes"); javaSamples++;
            }
            for (int i = 0; i < 3; i++) for (int j = 0; j < 3; j++) {
                Shake shake = Shake.shake128().update(seed).update(new byte[]{(byte)i,(byte)j});
                int[] f = new int[0];
                while (f.length < 256) { byte[] b = new byte[24]; shake.read(b); f = ints(feed(f,b).dtor_coeffs()); }
                check(Arrays.equals(f,(int[])oldNtt.invoke(null,seed,i,j)),"Java XOF/NTT sample"); javaSamples++;
            }
        }
    }
    public static void main(String[] args) throws Exception {
        scalars(); codecs(); sampling();
        System.out.printf("PASS codec_sampling_test {\"scalars\":%d,\"encodings\":%d,\"malformed\":%d,\"cbd\":%d,\"feeds\":%d,\"java_samples\":%d,\"assertions\":%d}%n",scalars,encodings,malformed,cbd,feeds,javaSamples,assertions);
    }
}
