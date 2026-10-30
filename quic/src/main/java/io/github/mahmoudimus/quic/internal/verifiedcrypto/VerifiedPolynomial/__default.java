// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedPolynomial;

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
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedSampling.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolynomialRing.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Add(dafny.DafnySequence<? extends java.math.BigInteger> f, dafny.DafnySequence<? extends java.math.BigInteger> g)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> r = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    if(true) {
      java.math.BigInteger[] _0_a;
      java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(256L)), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
      _0_a = _nw0;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(256L);
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.Add(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_1_i))))), ((java.math.BigInteger)(java.lang.Object)((g).select(dafny.Helpers.toInt((_1_i))))));
        (_0_a)[dafny.Helpers.toInt(((_1_i)).intValue())] = _out0;
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Sub(dafny.DafnySequence<? extends java.math.BigInteger> f, dafny.DafnySequence<? extends java.math.BigInteger> g)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> r = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    if(true) {
      java.math.BigInteger[] _0_a;
      java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(256L)), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
      _0_a = _nw0;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(256L);
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.Sub(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_1_i))))), ((java.math.BigInteger)(java.lang.Object)((g).select(dafny.Helpers.toInt((_1_i))))));
        (_0_a)[dafny.Helpers.toInt(((_1_i)).intValue())] = _out0;
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> ForwardStage(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger s)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> r = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    if(true) {
      java.math.BigInteger[] _0_a;
      java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(256L)), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
      _0_a = _nw0;
      java.math.BigInteger _1_l = java.math.BigInteger.ZERO;
      _1_l = io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.__default.Len(s);
      dafny.DafnySequence<? extends java.math.BigInteger> _2_roots;
      _2_roots = io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.__default.Zetas();
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(256L);
      for (java.math.BigInteger _3_i = java.math.BigInteger.ZERO; _3_i.compareTo(_hi0) < 0; _3_i = _3_i.add(java.math.BigInteger.ONE)) {
        java.math.BigInteger _4_z = java.math.BigInteger.ZERO;
        _4_z = ((java.math.BigInteger)(java.lang.Object)((_2_roots).select(dafny.Helpers.toInt(((dafny.DafnyEuclidean.EuclideanDivision(java.math.BigInteger.valueOf(128L), _1_l)).add(dafny.DafnyEuclidean.EuclideanDivision(_3_i, (java.math.BigInteger.valueOf(2L)).multiply(_1_l))))))));
        if ((dafny.DafnyEuclidean.EuclideanModulus(_3_i, (java.math.BigInteger.valueOf(2L)).multiply(_1_l))).compareTo(_1_l) < 0) {
          java.math.BigInteger _5_t = java.math.BigInteger.ZERO;
          java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
          _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.Mul(_4_z, ((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_3_i).add(_1_l)))))));
          _5_t = _out0;
          java.math.BigInteger _out1 = java.math.BigInteger.ZERO;
          _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.Add(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_3_i))))), _5_t);
          (_0_a)[dafny.Helpers.toInt(((_3_i)).intValue())] = _out1;
        } else {
          java.math.BigInteger _6_t = java.math.BigInteger.ZERO;
          java.math.BigInteger _out2 = java.math.BigInteger.ZERO;
          _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.Mul(_4_z, ((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_3_i))))));
          _6_t = _out2;
          java.math.BigInteger _out3 = java.math.BigInteger.ZERO;
          _out3 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.Sub(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_3_i).subtract(_1_l)))))), _6_t);
          (_0_a)[dafny.Helpers.toInt(((_3_i)).intValue())] = _out3;
        }
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Ntt(dafny.DafnySequence<? extends java.math.BigInteger> f)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> r = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    if(true) {
      r = f;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(7L);
      for (java.math.BigInteger _0_s = java.math.BigInteger.ZERO; _0_s.compareTo(_hi0) < 0; _0_s = _0_s.add(java.math.BigInteger.ONE)) {
        dafny.DafnySequence<? extends java.math.BigInteger> _out0;
        _out0 = __default.ForwardStage(r, _0_s);
        r = _out0;
      }
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> InverseStage(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger s)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> r = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    if(true) {
      java.math.BigInteger[] _0_a;
      java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(256L)), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
      _0_a = _nw0;
      java.math.BigInteger _1_l = java.math.BigInteger.ZERO;
      _1_l = io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.__default.Len((java.math.BigInteger.valueOf(6L)).subtract(s));
      dafny.DafnySequence<? extends java.math.BigInteger> _2_roots;
      _2_roots = io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.__default.Zetas();
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(256L);
      for (java.math.BigInteger _3_i = java.math.BigInteger.ZERO; _3_i.compareTo(_hi0) < 0; _3_i = _3_i.add(java.math.BigInteger.ONE)) {
        java.math.BigInteger _4_z = java.math.BigInteger.ZERO;
        _4_z = ((java.math.BigInteger)(java.lang.Object)((_2_roots).select(dafny.Helpers.toInt((((dafny.DafnyEuclidean.EuclideanDivision(java.math.BigInteger.valueOf(256L), _1_l)).subtract(java.math.BigInteger.ONE)).subtract(dafny.DafnyEuclidean.EuclideanDivision(_3_i, (java.math.BigInteger.valueOf(2L)).multiply(_1_l))))))));
        if ((dafny.DafnyEuclidean.EuclideanModulus(_3_i, (java.math.BigInteger.valueOf(2L)).multiply(_1_l))).compareTo(_1_l) < 0) {
          java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
          _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.Add(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_3_i))))), ((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_3_i).add(_1_l)))))));
          (_0_a)[dafny.Helpers.toInt(((_3_i)).intValue())] = _out0;
        } else {
          java.math.BigInteger _out1 = java.math.BigInteger.ZERO;
          _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.MulSub(_4_z, ((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_3_i))))), ((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((_3_i).subtract(_1_l)))))));
          (_0_a)[dafny.Helpers.toInt(((_3_i)).intValue())] = _out1;
        }
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Scale(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger scalar)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> r = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    if(true) {
      java.math.BigInteger[] _0_a;
      java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(256L)), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
      _0_a = _nw0;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(256L);
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.Mul(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_1_i))))), scalar);
        (_0_a)[dafny.Helpers.toInt(((_1_i)).intValue())] = _out0;
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> InverseNtt(dafny.DafnySequence<? extends java.math.BigInteger> f)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> r = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    if(true) {
      r = f;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(7L);
      for (java.math.BigInteger _0_s = java.math.BigInteger.ZERO; _0_s.compareTo(_hi0) < 0; _0_s = _0_s.add(java.math.BigInteger.ONE)) {
        dafny.DafnySequence<? extends java.math.BigInteger> _out0;
        _out0 = __default.InverseStage(r, _0_s);
        r = _out0;
      }
      dafny.DafnySequence<? extends java.math.BigInteger> _out1;
      _out1 = __default.Scale(r, java.math.BigInteger.valueOf(3303L));
      r = _out1;
    }
    return r;
  }
  public static dafny.Tuple2 BaseCase(java.math.BigInteger a0, java.math.BigInteger a1, java.math.BigInteger b0, java.math.BigInteger b1, java.math.BigInteger gamma)
  {
    java.math.BigInteger c0 = java.math.BigInteger.ZERO;
    java.math.BigInteger c1 = java.math.BigInteger.ZERO;
    if(true) {
      java.math.BigInteger _0_t = java.math.BigInteger.ZERO;
      java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
      _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.Mul(a1, b1);
      _0_t = _out0;
      java.math.BigInteger _out1 = java.math.BigInteger.ZERO;
      _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.AddMul(a0, b0, _0_t, gamma);
      c0 = _out1;
      java.math.BigInteger _out2 = java.math.BigInteger.ZERO;
      _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.__default.AddMul(a0, b1, a1, b0);
      c1 = _out2;
    }
    return new dafny.Tuple2<>(c0, c1);
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> NttMul(dafny.DafnySequence<? extends java.math.BigInteger> f, dafny.DafnySequence<? extends java.math.BigInteger> g)
  {
    dafny.DafnySequence<? extends java.math.BigInteger> r = dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER);
    if(true) {
      java.math.BigInteger[] _0_a;
      java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(256L)), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
      _0_a = _nw0;
      dafny.DafnySequence<? extends java.math.BigInteger> _1_gammas;
      _1_gammas = io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.__default.Gammas();
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(128L);
      for (java.math.BigInteger _2_i = java.math.BigInteger.ZERO; _2_i.compareTo(_hi0) < 0; _2_i = _2_i.add(java.math.BigInteger.ONE)) {
        java.math.BigInteger _3_c0 = java.math.BigInteger.ZERO;
        java.math.BigInteger _4_c1 = java.math.BigInteger.ZERO;
        java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
        java.math.BigInteger _out1 = java.math.BigInteger.ZERO;
        dafny.Tuple2<java.math.BigInteger, java.math.BigInteger> _outcollector0 = __default.BaseCase(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf(2L)).multiply(_2_i)))))), ((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((((java.math.BigInteger.valueOf(2L)).multiply(_2_i)).add(java.math.BigInteger.ONE)))))), ((java.math.BigInteger)(java.lang.Object)((g).select(dafny.Helpers.toInt(((java.math.BigInteger.valueOf(2L)).multiply(_2_i)))))), ((java.math.BigInteger)(java.lang.Object)((g).select(dafny.Helpers.toInt((((java.math.BigInteger.valueOf(2L)).multiply(_2_i)).add(java.math.BigInteger.ONE)))))), ((java.math.BigInteger)(java.lang.Object)((_1_gammas).select(dafny.Helpers.toInt((_2_i))))));
        _out0 = (java.math.BigInteger) (Object) _outcollector0.dtor__0();
        _out1 = (java.math.BigInteger) (Object) _outcollector0.dtor__1();
        _3_c0 = _out0;
        _4_c1 = _out1;
        java.math.BigInteger _index0 = (java.math.BigInteger.valueOf(2L)).multiply(_2_i);
        java.math.BigInteger _index1 = ((java.math.BigInteger.valueOf(2L)).multiply(_2_i)).add(java.math.BigInteger.ONE);
        java.math.BigInteger _rhs0 = _3_c0;
        java.math.BigInteger _rhs1 = _4_c1;
        java.math.BigInteger[] _lhs0 = _0_a;
        java.math.BigInteger _lhs1 = (java.math.BigInteger.valueOf(2L)).multiply(_2_i);
        java.math.BigInteger[] _lhs2 = _0_a;
        java.math.BigInteger _lhs3 = ((java.math.BigInteger.valueOf(2L)).multiply(_2_i)).add(java.math.BigInteger.ONE);
        _lhs0[dafny.Helpers.toInt((_lhs1).intValue())] = _rhs0;
        _lhs2[dafny.Helpers.toInt((_lhs3).intValue())] = _rhs1;
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
    }
    return r;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedPolynomial._default";
  }
}
