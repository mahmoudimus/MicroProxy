// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static boolean Prefix(dafny.DafnySequence<? extends java.math.BigInteger> f) {
    return ((java.math.BigInteger.valueOf((f).length())).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N()) <= 0) && (((java.util.function.Function<dafny.DafnySequence<? extends java.math.BigInteger>, Boolean>)(_0_f) -> dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_f).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _1_i = (java.math.BigInteger)_forall_var_0;
      return !(((_1_i).signum() != -1) && ((_1_i).compareTo(java.math.BigInteger.valueOf((_0_f).length())) < 0)) || (((((java.math.BigInteger)(java.lang.Object)((_0_f).select(dafny.Helpers.toInt((_1_i)))))).signum() != -1) && ((((java.math.BigInteger)(java.lang.Object)((_0_f).select(dafny.Helpers.toInt((_1_i)))))).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Q()) < 0));
    }))).apply(f));
  }
  public static java.math.BigInteger Bit(byte x, java.math.BigInteger j)
  {
    return dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(dafny.Helpers.unsignedToBigInteger(x), io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Pow2(j)), java.math.BigInteger.valueOf(2L));
  }
  public static java.math.BigInteger CbdWord(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger i)
  {
    byte _0_x = ((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanDivision(i, java.math.BigInteger.valueOf(2L)))))));
    java.math.BigInteger _1_j = (java.math.BigInteger.valueOf(4L)).multiply(dafny.DafnyEuclidean.EuclideanModulus(i, java.math.BigInteger.valueOf(2L)));
    return dafny.DafnyEuclidean.EuclideanModulus((((__default.Bit(_0_x, _1_j)).add(__default.Bit(_0_x, (_1_j).add(java.math.BigInteger.ONE)))).subtract(__default.Bit(_0_x, (_1_j).add(java.math.BigInteger.valueOf(2L))))).subtract(__default.Bit(_0_x, (_1_j).add(java.math.BigInteger.valueOf(3L)))), io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Q());
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Cbd2(dafny.DafnySequence<? extends java.lang.Byte> b) {
    return dafny.DafnySequence.Create(dafny.TypeDescriptor.BIG_INTEGER, io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N(), ((java.util.function.Function<dafny.DafnySequence<? extends java.lang.Byte>, java.util.function.Function<java.math.BigInteger, java.math.BigInteger>>)(_0_b) -> ((java.util.function.Function<java.math.BigInteger, java.math.BigInteger>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return __default.CbdWord(_0_b, _1_i);
    })).apply(b));
  }
  public static java.math.BigInteger First(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger off)
  {
    return (dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((off))))))).add((java.math.BigInteger.valueOf(256L)).multiply(dafny.DafnyEuclidean.EuclideanModulus(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((off).add(java.math.BigInteger.ONE))))))), java.math.BigInteger.valueOf(16L))));
  }
  public static java.math.BigInteger Second(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger off)
  {
    return (dafny.DafnyEuclidean.EuclideanDivision(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((off).add(java.math.BigInteger.ONE))))))), java.math.BigInteger.valueOf(16L))).add((java.math.BigInteger.valueOf(16L)).multiply(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((off).add(java.math.BigInteger.valueOf(2L))))))))));
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Accept(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger x)
  {
    if (((java.math.BigInteger.valueOf((f).length())).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N()) < 0) && ((x).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Q()) < 0)) {
      return dafny.DafnySequence.<java.math.BigInteger>concatenate(f, dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, x));
    } else {
      return f;
    }
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Pair(dafny.DafnySequence<? extends java.math.BigInteger> f, dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger off)
  {
    return __default.Accept(__default.Accept(f, __default.First(b, off)), __default.Second(b, off));
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> AcceptedPair(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger off)
  {
    return dafny.DafnySequence.<java.math.BigInteger>concatenate((((__default.First(b, off)).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Q()) < 0) ? (dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, __default.First(b, off))) : (dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER))), (((__default.Second(b, off)).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Q()) < 0) ? (dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, __default.Second(b, off))) : (dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER))));
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Accepted(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger off)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> _0___accumulator = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(off, java.math.BigInteger.valueOf((b).length()))) {
        return dafny.DafnySequence.<java.math.BigInteger>concatenate(_0___accumulator, dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER));
      } else {
        _0___accumulator = dafny.DafnySequence.<java.math.BigInteger>concatenate(_0___accumulator, __default.AcceptedPair(b, off));
        dafny.DafnySequence<? extends java.lang.Byte> _in0 = b;
        java.math.BigInteger _in1 = (off).add(java.math.BigInteger.valueOf(3L));
        b = _in0;
        off = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Limit(dafny.DafnySequence<? extends java.math.BigInteger> f) {
    if ((java.math.BigInteger.valueOf((f).length())).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N()) <= 0) {
      return f;
    } else {
      return (f).take(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N());
    }
  }
  public static FeedResult Run(dafny.DafnySequence<? extends java.math.BigInteger> f, dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger off)
  {
    TAIL_CALL_START: while (true) {
      if (java.util.Objects.equals(java.math.BigInteger.valueOf((f).length()), io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N())) {
        return io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.create_Full(f, off);
      } else if (java.util.Objects.equals(off, java.math.BigInteger.valueOf((b).length()))) {
        return io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.create_NeedMore(f, off);
      } else {
        dafny.DafnySequence<? extends java.math.BigInteger> _in0 = __default.Pair(f, b, off);
        dafny.DafnySequence<? extends java.lang.Byte> _in1 = b;
        java.math.BigInteger _in2 = (off).add(java.math.BigInteger.valueOf(3L));
        f = _in0;
        b = _in1;
        off = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static FeedResult Feed(dafny.DafnySequence<? extends java.math.BigInteger> f, dafny.DafnySequence<? extends java.lang.Byte> b)
  {
    if (!(__default.Prefix(f))) {
      return io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.create_InvalidPrefix();
    } else if ((dafny.DafnyEuclidean.EuclideanModulus(java.math.BigInteger.valueOf((b).length()), java.math.BigInteger.valueOf(3L))).signum() != 0) {
      return io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.create_InvalidBlockLength();
    } else {
      return __default.Run(f, b, java.math.BigInteger.ZERO);
    }
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec._default";
  }
}
