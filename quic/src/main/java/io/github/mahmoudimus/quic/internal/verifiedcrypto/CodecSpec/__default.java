// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static java.math.BigInteger Pow2(java.math.BigInteger d) {
    return ((java.math.BigInteger)(java.lang.Object)((dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, java.math.BigInteger.ONE, java.math.BigInteger.valueOf(2L), java.math.BigInteger.valueOf(4L), java.math.BigInteger.valueOf(8L), java.math.BigInteger.valueOf(16L), java.math.BigInteger.valueOf(32L), java.math.BigInteger.valueOf(64L), java.math.BigInteger.valueOf(128L), java.math.BigInteger.valueOf(256L), java.math.BigInteger.valueOf(512L), java.math.BigInteger.valueOf(1024L), java.math.BigInteger.valueOf(2048L), java.math.BigInteger.valueOf(4096L))).select(dafny.Helpers.toInt((d)))));
  }
  public static boolean Width(java.math.BigInteger d) {
    return (((java.util.Objects.equals(d, java.math.BigInteger.ONE)) || (java.util.Objects.equals(d, java.math.BigInteger.valueOf(4L)))) || (java.util.Objects.equals(d, java.math.BigInteger.valueOf(10L)))) || (java.util.Objects.equals(d, java.math.BigInteger.valueOf(12L)));
  }
  public static boolean Canonical(dafny.DafnySequence<? extends java.math.BigInteger> f) {
    return (java.util.Objects.equals(java.math.BigInteger.valueOf((f).length()), __default.N())) && (((java.util.function.Function<dafny.DafnySequence<? extends java.math.BigInteger>, Boolean>)(_0_f) -> dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, __default.N()), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _1_i = (java.math.BigInteger)_forall_var_0;
      return !(((_1_i).signum() != -1) && ((_1_i).compareTo(__default.N()) < 0)) || (((((java.math.BigInteger)(java.lang.Object)((_0_f).select(dafny.Helpers.toInt((_1_i)))))).signum() != -1) && ((((java.math.BigInteger)(java.lang.Object)((_0_f).select(dafny.Helpers.toInt((_1_i)))))).compareTo(__default.Q()) < 0));
    }))).apply(f));
  }
  public static boolean Words(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger d)
  {
    return ((__default.Width(d)) && (java.util.Objects.equals(java.math.BigInteger.valueOf((f).length()), __default.N()))) && (((dafny.Function2<dafny.DafnySequence<? extends java.math.BigInteger>, java.math.BigInteger, Boolean>)(_0_f, _1_d) -> dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, __default.N()), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _2_i = (java.math.BigInteger)_forall_var_0;
      return !(((_2_i).signum() != -1) && ((_2_i).compareTo(__default.N()) < 0)) || (((((java.math.BigInteger)(java.lang.Object)((_0_f).select(dafny.Helpers.toInt((_2_i)))))).signum() != -1) && ((((java.math.BigInteger)(java.lang.Object)((_0_f).select(dafny.Helpers.toInt((_2_i)))))).compareTo(((java.util.Objects.equals(_1_d, java.math.BigInteger.valueOf(12L))) ? (__default.Q()) : (__default.Pow2(_1_d)))) < 0));
    }))).apply(f, d));
  }
  public static java.math.BigInteger Compress(java.math.BigInteger x, java.math.BigInteger d)
  {
    return dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(((__default.Pow2(d)).multiply(x)).add(dafny.DafnyEuclidean.EuclideanDivision(__default.Q(), java.math.BigInteger.valueOf(2L))), __default.Q()), __default.Pow2(d));
  }
  public static java.math.BigInteger Decompress(java.math.BigInteger y, java.math.BigInteger d)
  {
    return dafny.DafnyEuclidean.EuclideanDivision(((__default.Q()).multiply(y)).add(dafny.DafnyEuclidean.EuclideanDivision(__default.Pow2(d), java.math.BigInteger.valueOf(2L))), __default.Pow2(d));
  }
  public static java.math.BigInteger GroupWords(java.math.BigInteger d) {
    if (java.util.Objects.equals(d, java.math.BigInteger.ONE)) {
      return java.math.BigInteger.valueOf(8L);
    } else if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(10L))) {
      return java.math.BigInteger.valueOf(4L);
    } else {
      return java.math.BigInteger.valueOf(2L);
    }
  }
  public static java.math.BigInteger GroupBytes(java.math.BigInteger d) {
    if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(10L))) {
      return java.math.BigInteger.valueOf(5L);
    } else if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(12L))) {
      return java.math.BigInteger.valueOf(3L);
    } else {
      return java.math.BigInteger.ONE;
    }
  }
  public static java.math.BigInteger BytePower(java.math.BigInteger j) {
    return ((java.math.BigInteger)(java.lang.Object)((dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, java.math.BigInteger.ONE, java.math.BigInteger.valueOf(256L), java.math.BigInteger.valueOf(65536L), java.math.BigInteger.valueOf(16777216L), java.math.BigInteger.valueOf(4294967296L))).select(dafny.Helpers.toInt((j)))));
  }
  public static java.math.BigInteger WordPower(java.math.BigInteger d, java.math.BigInteger j)
  {
    if (java.util.Objects.equals(d, java.math.BigInteger.ONE)) {
      return ((java.math.BigInteger)(java.lang.Object)((dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, java.math.BigInteger.ONE, java.math.BigInteger.valueOf(2L), java.math.BigInteger.valueOf(4L), java.math.BigInteger.valueOf(8L), java.math.BigInteger.valueOf(16L), java.math.BigInteger.valueOf(32L), java.math.BigInteger.valueOf(64L), java.math.BigInteger.valueOf(128L))).select(dafny.Helpers.toInt((j)))));
    } else if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(4L))) {
      return ((java.math.BigInteger)(java.lang.Object)((dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, java.math.BigInteger.ONE, java.math.BigInteger.valueOf(16L))).select(dafny.Helpers.toInt((j)))));
    } else if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(10L))) {
      return ((java.math.BigInteger)(java.lang.Object)((dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, java.math.BigInteger.ONE, java.math.BigInteger.valueOf(1024L), java.math.BigInteger.valueOf(1048576L), java.math.BigInteger.valueOf(1073741824L))).select(dafny.Helpers.toInt((j)))));
    } else {
      return ((java.math.BigInteger)(java.lang.Object)((dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, java.math.BigInteger.ONE, java.math.BigInteger.valueOf(4096L))).select(dafny.Helpers.toInt((j)))));
    }
  }
  public static java.math.BigInteger GroupValue(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger d, java.math.BigInteger g)
  {
    java.math.BigInteger _0_k = (g).multiply(__default.GroupWords(d));
    if (java.util.Objects.equals(d, java.math.BigInteger.ONE)) {
      return (((((((((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_0_k)))))).add((java.math.BigInteger.valueOf(2L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.ONE))))))))).add((java.math.BigInteger.valueOf(4L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(2L)))))))))).add((java.math.BigInteger.valueOf(8L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(3L)))))))))).add((java.math.BigInteger.valueOf(16L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(4L)))))))))).add((java.math.BigInteger.valueOf(32L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(5L)))))))))).add((java.math.BigInteger.valueOf(64L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(6L)))))))))).add((java.math.BigInteger.valueOf(128L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(7L)))))))));
    } else if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(4L))) {
      return (((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_0_k)))))).add((java.math.BigInteger.valueOf(16L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.ONE))))))));
    } else if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(10L))) {
      return (((((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_0_k)))))).add((java.math.BigInteger.valueOf(1024L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.ONE))))))))).add((java.math.BigInteger.valueOf(1048576L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(2L)))))))))).add((java.math.BigInteger.valueOf(1073741824L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(3L)))))))));
    } else {
      return (((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_0_k)))))).add((java.math.BigInteger.valueOf(4096L)).multiply(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.ONE))))))));
    }
  }
  public static byte EncodedByte(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger d, java.math.BigInteger i)
  {
    return (dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(__default.GroupValue(f, d, dafny.DafnyEuclidean.EuclideanDivision(i, __default.GroupBytes(d))), __default.BytePower(dafny.DafnyEuclidean.EuclideanModulus(i, __default.GroupBytes(d)))), java.math.BigInteger.valueOf(256L))).byteValue();
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Encoded(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger d)
  {
    return dafny.DafnySequence.Create(dafny.TypeDescriptor.BYTE, (java.math.BigInteger.valueOf(32L)).multiply(d), ((dafny.Function2<dafny.DafnySequence<? extends java.math.BigInteger>, java.math.BigInteger, java.util.function.Function<java.math.BigInteger, java.lang.Byte>>)(_0_f, _1_d) -> ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_2_i_boxed0) -> {
      java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
      return __default.EncodedByte(_0_f, _1_d, _2_i);
    })).apply(f, d));
  }
  public static java.math.BigInteger ByteGroup(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger d, java.math.BigInteger g)
  {
    java.math.BigInteger _0_k = (g).multiply(__default.GroupBytes(d));
    if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(10L))) {
      return ((((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((_0_k))))))).add((java.math.BigInteger.valueOf(256L)).multiply(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.ONE)))))))))).add((java.math.BigInteger.valueOf(65536L)).multiply(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(2L))))))))))).add((java.math.BigInteger.valueOf(16777216L)).multiply(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(3L))))))))))).add((java.math.BigInteger.valueOf(4294967296L)).multiply(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(4L))))))))));
    } else if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(12L))) {
      return ((dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((_0_k))))))).add((java.math.BigInteger.valueOf(256L)).multiply(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.ONE)))))))))).add((java.math.BigInteger.valueOf(65536L)).multiply(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_0_k).add(java.math.BigInteger.valueOf(2L))))))))));
    } else {
      return dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((_0_k))))));
    }
  }
  public static java.math.BigInteger DecodedWord(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger d, java.math.BigInteger i)
  {
    return dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(__default.ByteGroup(b, d, dafny.DafnyEuclidean.EuclideanDivision(i, __default.GroupWords(d))), __default.WordPower(d, dafny.DafnyEuclidean.EuclideanModulus(i, __default.GroupWords(d)))), __default.Pow2(d));
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> DecodedWords(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger d)
  {
    return dafny.DafnySequence.Create(dafny.TypeDescriptor.BIG_INTEGER, __default.N(), ((dafny.Function2<dafny.DafnySequence<? extends java.lang.Byte>, java.math.BigInteger, java.util.function.Function<java.math.BigInteger, java.math.BigInteger>>)(_0_b, _1_d) -> ((java.util.function.Function<java.math.BigInteger, java.math.BigInteger>)(_2_i_boxed0) -> {
      java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
      return __default.DecodedWord(_0_b, _1_d, _2_i);
    })).apply(b, d));
  }
  public static DecodeResult Decode(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger d)
  {
    if (!(__default.Width(d))) {
      return io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.create_InvalidWidth();
    } else if (!java.util.Objects.equals(java.math.BigInteger.valueOf((b).length()), (java.math.BigInteger.valueOf(32L)).multiply(d))) {
      return io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.create_InvalidLength();
    } else if ((java.util.Objects.equals(d, java.math.BigInteger.valueOf(12L))) && (!(__default.Canonical(__default.DecodedWords(b, d))))) {
      return io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.create_ModulusError();
    } else {
      return io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.create_Decoded(__default.DecodedWords(b, d));
    }
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> CompressedWords(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger d)
  {
    if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(12L))) {
      return f;
    } else {
      return dafny.DafnySequence.Create(dafny.TypeDescriptor.BIG_INTEGER, __default.N(), ((dafny.Function2<dafny.DafnySequence<? extends java.math.BigInteger>, java.math.BigInteger, java.util.function.Function<java.math.BigInteger, java.math.BigInteger>>)(_0_f, _1_d) -> ((java.util.function.Function<java.math.BigInteger, java.math.BigInteger>)(_2_i_boxed0) -> {
        java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
        return __default.Compress(((java.math.BigInteger)(java.lang.Object)((_0_f).select(dafny.Helpers.toInt((_2_i))))), _1_d);
      })).apply(f, d));
    }
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> ExpandedWords(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger d)
  {
    if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(12L))) {
      return f;
    } else {
      return dafny.DafnySequence.Create(dafny.TypeDescriptor.BIG_INTEGER, __default.N(), ((dafny.Function2<dafny.DafnySequence<? extends java.math.BigInteger>, java.math.BigInteger, java.util.function.Function<java.math.BigInteger, java.math.BigInteger>>)(_0_f, _1_d) -> ((java.util.function.Function<java.math.BigInteger, java.math.BigInteger>)(_2_i_boxed0) -> {
        java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
        return __default.Decompress(((java.math.BigInteger)(java.lang.Object)((_0_f).select(dafny.Helpers.toInt((_2_i))))), _1_d);
      })).apply(f, d));
    }
  }
  public static java.math.BigInteger Distance(java.math.BigInteger a, java.math.BigInteger b)
  {
    java.math.BigInteger _0_e = dafny.DafnyEuclidean.EuclideanModulus((a).subtract(b), __default.Q());
    if ((_0_e).compareTo(dafny.DafnyEuclidean.EuclideanDivision(__default.Q(), java.math.BigInteger.valueOf(2L))) <= 0) {
      return _0_e;
    } else {
      return (__default.Q()).subtract(_0_e);
    }
  }
  public static boolean ErrorAtScale(java.math.BigInteger x, java.math.BigInteger p)
  {
    java.math.BigInteger _0_c = dafny.DafnyEuclidean.EuclideanDivision(((p).multiply(x)).add(dafny.DafnyEuclidean.EuclideanDivision(__default.Q(), java.math.BigInteger.valueOf(2L))), __default.Q());
    java.math.BigInteger _1_y = dafny.DafnyEuclidean.EuclideanModulus(_0_c, p);
    java.math.BigInteger _2_r = dafny.DafnyEuclidean.EuclideanDivision(((__default.Q()).multiply(_1_y)).add(dafny.DafnyEuclidean.EuclideanDivision(p, java.math.BigInteger.valueOf(2L))), p);
    java.math.BigInteger _3_signed = ((java.util.Objects.equals(_0_c, p)) ? (((_2_r).subtract(x)).add(__default.Q())) : ((_2_r).subtract(x)));
    return (((java.math.BigInteger.ZERO).subtract(dafny.DafnyEuclidean.EuclideanDivision((__default.Q()).add(p), (java.math.BigInteger.valueOf(2L)).multiply(p)))).compareTo(_3_signed) <= 0) && ((_3_signed).compareTo(dafny.DafnyEuclidean.EuclideanDivision((__default.Q()).add(p), (java.math.BigInteger.valueOf(2L)).multiply(p))) <= 0);
  }
  public static java.math.BigInteger N()
  {
    return java.math.BigInteger.valueOf(256L);
  }
  public static java.math.BigInteger Q()
  {
    return java.math.BigInteger.valueOf(3329L);
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec._default";
  }
}
