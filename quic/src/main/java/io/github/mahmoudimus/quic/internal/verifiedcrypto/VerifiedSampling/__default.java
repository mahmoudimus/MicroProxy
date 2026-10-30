// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedSampling;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Cbd2(dafny.DafnySequence<? extends java.lang.Byte> b)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> f = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    if(true) {
      java.math.BigInteger[] _0_a;
      java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N()), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
      _0_a = _nw0;
      java.math.BigInteger _hi0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N();
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        java.math.BigInteger _2_x = java.math.BigInteger.ZERO;
        _2_x = dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanDivision(_1_i, java.math.BigInteger.valueOf(2L))))))));
        java.math.BigInteger _3_j = java.math.BigInteger.ZERO;
        _3_j = (java.math.BigInteger.valueOf(4L)).multiply(dafny.DafnyEuclidean.EuclideanModulus(_1_i, java.math.BigInteger.valueOf(2L)));
        java.math.BigInteger _4_low = java.math.BigInteger.ZERO;
        _4_low = (dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(_2_x, io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Pow2(_3_j)), java.math.BigInteger.valueOf(2L))).add(dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(_2_x, io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Pow2((_3_j).add(java.math.BigInteger.ONE))), java.math.BigInteger.valueOf(2L)));
        java.math.BigInteger _5_high = java.math.BigInteger.ZERO;
        _5_high = (dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(_2_x, io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Pow2((_3_j).add(java.math.BigInteger.valueOf(2L)))), java.math.BigInteger.valueOf(2L))).add(dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(_2_x, io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Pow2((_3_j).add(java.math.BigInteger.valueOf(3L)))), java.math.BigInteger.valueOf(2L)));
        (_0_a)[dafny.Helpers.toInt(((_1_i)).intValue())] = dafny.DafnyEuclidean.EuclideanModulus((_4_low).subtract(_5_high), java.math.BigInteger.valueOf(3329L));
      }
      f = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
    }
    return f;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult Feed(dafny.DafnySequence<? extends java.math.BigInteger> current, dafny.DafnySequence<? extends java.lang.Byte> b)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.Default();
    if (!(io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.__default.Prefix(current))) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.create_InvalidPrefix();
      return r;
    }
    if ((dafny.DafnyEuclidean.EuclideanModulus(java.math.BigInteger.valueOf((b).length()), java.math.BigInteger.valueOf(3L))).signum() != 0) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.create_InvalidBlockLength();
      return r;
    }
    dafny.DafnySequence<? extends java.math.BigInteger> _0_f;
    _0_f = current;
    java.math.BigInteger _1_off = java.math.BigInteger.ZERO;
    _1_off = java.math.BigInteger.ZERO;
    while (((java.math.BigInteger.valueOf((_0_f).length())).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N()) < 0) && ((_1_off).compareTo(java.math.BigInteger.valueOf((b).length())) < 0)) {
      dafny.DafnySequence<? extends java.math.BigInteger> _2_before;
      _2_before = _0_f;
      java.math.BigInteger _3_x = java.math.BigInteger.ZERO;
      _3_x = (dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt((_1_off))))))).add((java.math.BigInteger.valueOf(256L)).multiply(dafny.DafnyEuclidean.EuclideanModulus(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_1_off).add(java.math.BigInteger.ONE))))))), java.math.BigInteger.valueOf(16L))));
      java.math.BigInteger _4_y = java.math.BigInteger.ZERO;
      _4_y = (dafny.DafnyEuclidean.EuclideanDivision(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_1_off).add(java.math.BigInteger.ONE))))))), java.math.BigInteger.valueOf(16L))).add((java.math.BigInteger.valueOf(16L)).multiply(dafny.Helpers.unsignedToBigInteger(((byte)(java.lang.Object)((b).select(dafny.Helpers.toInt(((_1_off).add(java.math.BigInteger.valueOf(2L))))))))));
      if ((_3_x).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Q()) < 0) {
        _0_f = dafny.DafnySequence.<java.math.BigInteger>concatenate(_0_f, dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, _3_x));
      }
      if (((java.math.BigInteger.valueOf((_0_f).length())).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N()) < 0) && ((_4_y).compareTo(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Q()) < 0)) {
        _0_f = dafny.DafnySequence.<java.math.BigInteger>concatenate(_0_f, dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, _4_y));
      }
      _1_off = (_1_off).add(java.math.BigInteger.valueOf(3L));
    }
    if (java.util.Objects.equals(java.math.BigInteger.valueOf((_0_f).length()), io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N())) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.create_Full(_0_f, _1_off);
      return r;
    }
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.create_NeedMore(_0_f, _1_off);
    return r;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedSampling._default";
  }
}
