package io.github.mahmoudimus.quic.tls;

import dafny.DafnySequence;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import KemSpec.Result;
import KemSpec.SecretKey;
import KemSpec.Encapsulation;

/** Finite checks of exact generated Java, separate from universal Dafny proofs. */
public final class kem_test {
    private static int assertions, rounds, malformed, selections;
    private static void check(boolean value, String label) {
        assertions++;
        if (!value) throw new AssertionError(label);
    }
    private static DafnySequence<? extends Byte> seq(byte[] b) { return DafnySequence.of(b); }
    private static byte[] bytes(DafnySequence<? extends Byte> s) {
        byte[] b = new byte[s.length()];
        for (int i = 0; i < b.length; i++) b[i] = s.select(i);
        return b;
    }
    private static <T> T success(Result<T> r) {
        check(r.is_Success(), "unexpected KEM failure: "+r);
        return r.dtor_value();
    }
    private static void equal(byte[] a, byte[] b, String label) { check(Arrays.equals(a,b),label); }
    private static byte[] fallback(byte[] seed, byte[] c) {
        byte[] key = new byte[32];
        Shake.shake256().update(Arrays.copyOfRange(seed,32,64)).update(c).read(key);
        return key;
    }
    private static void errors(byte[] ek, SecretKey dk) {
        for (int n : new int[] {0,1,31,32,63,65,127}) {
            var r = VerifiedMlKem.__default.KeyGen(seq(new byte[n]));
            check(r.is_Failure() && r.dtor_reason().is_InvalidSeedLength(),"seed length "+n); malformed++;
        }
        for (int n : new int[] {0,1,32,1088,1183,1185}) {
            var r = VerifiedMlKem.__default.Encaps(seq(new byte[n]),seq(new byte[0]));
            check(r.is_Failure() && r.dtor_reason().is_InvalidKeyLength(),"key precedence "+n); malformed++;
        }
        for (int n : new int[] {0,1,31,33,64}) {
            var r = VerifiedMlKem.__default.Encaps(seq(ek),seq(new byte[n]));
            check(r.is_Failure() && r.dtor_reason().is_InvalidMessageLength(),"message length "+n); malformed++;
        }
        for (int n : new int[] {0,1,32,1087,1089,2400}) {
            var r = VerifiedMlKem.__default.Decaps(dk,seq(new byte[n]));
            check(r.is_Failure() && r.dtor_reason().is_InvalidCiphertextLength(),"cipher length "+n);
            var s = VerifiedMlKem.__default.DecapsFromSeed(seq(new byte[0]),seq(new byte[n]));
            check(s.is_Failure() && s.dtor_reason().is_InvalidCiphertextLength(),"cipher/seed precedence "+n);
            malformed++;
        }
        for (int poly = 0; poly < 3; poly++) for (int q : new int[] {3329,4095}) {
            byte[] bad = ek.clone();
            bad[384*poly] = (byte)q;
            bad[384*poly+1] = (byte)((bad[384*poly+1]&0xf0)|(q>>>8));
            var r = VerifiedMlKem.__default.Encaps(seq(bad),seq(new byte[0]));
            check(r.is_Failure() && r.dtor_reason().is_ModulusError(),"modulus precedence "+poly+":"+q); malformed++;
        }
    }
    private static void sampleLimits() {
        byte[] allRejected = new byte[840]; Arrays.fill(allRejected,(byte)255);
        var rejected = VerifiedMlKem.__default.SamplePrefix(seq(allRejected));
        check(rejected.is_Failure() && rejected.dtor_reason().is_RejectionLimit(),"uniform sampling limit");
        var accepted = success(VerifiedMlKem.__default.SamplePrefix(seq(new byte[840])));
        check(accepted.length() == 256,"sample limit accepted length");
        for (int i = 0; i < 256; i++) check(accepted.select(i).equals(BigInteger.ZERO),"sample zero coefficient");
        // Only 255 accepted values before the cap must produce the same failure.
        byte[] shortPrefix = allRejected.clone();
        Arrays.fill(shortPrefix,0,381,(byte)0);
        shortPrefix[381] = 0; shortPrefix[382] = (byte)240; shortPrefix[383] = (byte)255;
        var shortResult = VerifiedMlKem.__default.SamplePrefix(seq(shortPrefix));
        check(shortResult.is_Failure() && shortResult.dtor_reason().is_RejectionLimit(),"255 coefficient prefix limit");
        // The second coefficient of the final allowed group supplies coefficient 256.
        shortPrefix[837] = (byte)255; shortPrefix[838] = 15; shortPrefix[839] = 0;
        var last = success(VerifiedMlKem.__default.SamplePrefix(seq(shortPrefix)));
        check(last.length() == 256 && last.select(255).equals(BigInteger.ZERO),"last allowed iteration accepted");
    }
    private static void selectors() {
        byte[] c = new byte[1088], other = new byte[1088], a = new byte[32], b = new byte[32];
        for (int j = 0; j < 32; j++) { a[j] = (byte)(j*7+128); b[j] = (byte)~a[j]; }
        equal(bytes(VerifiedMlKem.__default.Select(seq(c),seq(other),seq(a),seq(b))),a,"selector equal"); selections++;
        for (int i = 0; i < 1088; i++) for (int bit : new int[] {1,128,255}) {
            other[i] = (byte)bit;
            equal(bytes(VerifiedMlKem.__default.Select(seq(c),seq(other),seq(a),seq(b))),b,"selector mismatch "+i+":"+bit);
            other[i] = 0; selections++;
        }
    }
    private static void accumulated(int count) throws Exception {
        Shake source = Shake.shake128(), output = Shake.shake128();
        for (int i = 0; i < count; i++) {
            byte[] seed = new byte[64], m = new byte[32], randomCipher = new byte[1088];
            source.read(seed);
            SecretKey dk = success(VerifiedMlKem.__default.KeyGen(seq(seed)));
            byte[] ek = bytes(dk.dtor_ek().dtor_encoded());
            var original = MlKem768.DecapsulationKey.fromSeed(seed);
            equal(ek,original.encapsulationKey(),"canonical ek "+i);
            equal(bytes(dk.dtor_seed()),seed,"retained seed "+i);
            byte[] serialized = bytes(VerifiedMlKem.__default.SerializeSecret(dk));
            check(serialized.length == 2400,"expanded key length");
            equal(Arrays.copyOfRange(serialized,1152,2336),ek,"expanded ek "+i);
            equal(Arrays.copyOfRange(serialized,2336,2368),MessageDigest.getInstance("SHA3-256").digest(ek),"expanded H(ek) "+i);
            equal(Arrays.copyOfRange(serialized,2368,2400),Arrays.copyOfRange(seed,32,64),"expanded z "+i);
            output.update(ek);
            source.read(m);
            Encapsulation enc = success(VerifiedMlKem.__default.Encaps(seq(ek),seq(m)));
            byte[] c = bytes(enc.dtor_ciphertext()), k = bytes(enc.dtor_key());
            var canonical = MlKem768.encapsulate(ek,m);
            equal(c,canonical.ciphertext(),"canonical cipher "+i);
            equal(k,canonical.sharedKey(),"canonical shared key "+i);
            output.update(c).update(k);
            byte[] dec = bytes(success(VerifiedMlKem.__default.Decaps(dk,seq(c))));
            equal(dec,k,"honest finite fixture "+i);
            source.read(randomCipher);
            byte[] rejected = bytes(success(VerifiedMlKem.__default.Decaps(dk,seq(randomCipher))));
            equal(rejected,original.decapsulate(randomCipher),"canonical rejection "+i);
            equal(rejected,fallback(seed,randomCipher),"J(z||c) rejection fixture "+i);
            output.update(rejected);
            if (i == 0) {
                errors(ek,dk);
                equal(bytes(success(VerifiedMlKem.__default.DecapsFromSeed(seq(seed),seq(c)))),k,"seed decapsulation");
                for (int at : new int[] {0,319,320,959,960,1087}) {
                    byte[] changed = c.clone(); changed[at] ^= (byte)0x80;
                    byte[] actual = bytes(success(VerifiedMlKem.__default.Decaps(dk,seq(changed))));
                    equal(actual,original.decapsulate(changed),"tamper canonical "+at);
                    equal(actual,fallback(seed,changed),"tamper J(z||c) "+at);
                }
                byte[] changedSeed = seed.clone(); changedSeed[32] ^= 1;
                SecretKey changed = success(VerifiedMlKem.__default.KeyGen(seq(changedSeed)));
                equal(bytes(changed.dtor_ek().dtor_encoded()),ek,"z does not change ek");
                equal(bytes(success(VerifiedMlKem.__default.Decaps(changed,seq(c)))),k,"z does not change accepted key");
                byte[] changedReject = bytes(success(VerifiedMlKem.__default.Decaps(changed,seq(randomCipher))));
                equal(changedReject,fallback(changedSeed,randomCipher),"z changes fallback input");
                check(!Arrays.equals(changedReject,rejected),"finite distinct-z fixture");
            }
            rounds++;
        }
        byte[] digest = new byte[32]; output.read(digest);
        String actual = HexFormat.of().formatHex(digest);
        if (count == 100) check(actual.equals("1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"),"Go accumulated100 known answer: "+actual);
        System.out.println("accumulated "+count+" "+actual);
    }
    public static void main(String[] args) throws Exception {
        sampleLimits(); selectors(); accumulated(args.length == 0 ? 100 : Integer.parseInt(args[0]));
        System.out.println("PASS kem_test {\"assertions\":"+assertions+",\"rounds\":"+rounds+",\"malformed\":"+malformed+",\"selections\":"+selections+"}");
    }
}
