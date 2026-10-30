// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedKeccak;

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
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedPolynomial.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static long Rotate(long v, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return v;
    } else {
      return (long) (long) (((long) (long) (((long) dafny.Helpers.bv64ShiftLeft(v, (n).byteValue())))) | ((long) dafny.Helpers.bv64ShiftRight(v, ((java.math.BigInteger.valueOf(64L)).subtract(n)).byteValue())));
    }
  }
  public static dafny.DafnySequence<? extends java.lang.Long> Constants() {
    return dafny.DafnySequence.<java.lang.Long> of((long) 1L, (long) 32898L, (long) -9223372036854742902L, (long) -9223372034707259392L, (long) 32907L, (long) 2147483649L, (long) -9223372034707259263L, (long) -9223372036854743031L, (long) 138L, (long) 136L, (long) 2147516425L, (long) 2147483658L, (long) 2147516555L, (long) -9223372036854775669L, (long) -9223372036854742903L, (long) -9223372036854743037L, (long) -9223372036854743038L, (long) -9223372036854775680L, (long) 32778L, (long) -9223372034707292150L, (long) -9223372034707259263L, (long) -9223372036854742912L, (long) 2147483649L, (long) -9223372034707259384L);
  }
  public static dafny.DafnySequence<? extends java.math.BigInteger> Offsets() {
    return dafny.DafnySequence.<java.math.BigInteger> of(_System.nat._typeDescriptor(), java.math.BigInteger.ZERO, java.math.BigInteger.ONE, java.math.BigInteger.valueOf(62L), java.math.BigInteger.valueOf(28L), java.math.BigInteger.valueOf(27L), java.math.BigInteger.valueOf(36L), java.math.BigInteger.valueOf(44L), java.math.BigInteger.valueOf(6L), java.math.BigInteger.valueOf(55L), java.math.BigInteger.valueOf(20L), java.math.BigInteger.valueOf(3L), java.math.BigInteger.valueOf(10L), java.math.BigInteger.valueOf(43L), java.math.BigInteger.valueOf(25L), java.math.BigInteger.valueOf(39L), java.math.BigInteger.valueOf(41L), java.math.BigInteger.valueOf(45L), java.math.BigInteger.valueOf(15L), java.math.BigInteger.valueOf(21L), java.math.BigInteger.valueOf(8L), java.math.BigInteger.valueOf(18L), java.math.BigInteger.valueOf(2L), java.math.BigInteger.valueOf(61L), java.math.BigInteger.valueOf(56L), java.math.BigInteger.valueOf(14L));
  }
  public static dafny.DafnySequence<? extends java.lang.Long> Theta(dafny.DafnySequence<? extends java.lang.Long> a)
  {
    dafny.DafnySequence<? extends java.lang.Long> r = dafny.DafnySequence.<java.lang.Long> empty(dafny.TypeDescriptor.LONG);
    if(true) {
      long[] _0_c;
      long[] _nw0 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(5L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
      _0_c = _nw0;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(5L);
      for (java.math.BigInteger _1_x = java.math.BigInteger.ZERO; _1_x.compareTo(_hi0) < 0; _1_x = _1_x.add(java.math.BigInteger.ONE)) {
        (_0_c)[dafny.Helpers.toInt(((_1_x)).intValue())] = (long) (long) (((long) (long) (((long) (long) (((long) (long) ((((long)(java.lang.Object)((a).select(dafny.Helpers.toInt((_1_x)))))) ^ (((long)(java.lang.Object)((a).select(dafny.Helpers.toInt(((_1_x).add(java.math.BigInteger.valueOf(5L)))))))))) ^ (((long)(java.lang.Object)((a).select(dafny.Helpers.toInt(((_1_x).add(java.math.BigInteger.valueOf(10L)))))))))) ^ (((long)(java.lang.Object)((a).select(dafny.Helpers.toInt(((_1_x).add(java.math.BigInteger.valueOf(15L)))))))))) ^ (((long)(java.lang.Object)((a).select(dafny.Helpers.toInt(((_1_x).add(java.math.BigInteger.valueOf(20L)))))))));
      }
      long[] _2_b;
      long[] _nw1 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(25L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
      _2_b = _nw1;
      java.math.BigInteger _hi1 = java.math.BigInteger.valueOf(25L);
      for (java.math.BigInteger _3_i = java.math.BigInteger.ZERO; _3_i.compareTo(_hi1) < 0; _3_i = _3_i.add(java.math.BigInteger.ONE)) {
        long _4_value;
        _4_value = (long) (long) (((long) (long) ((((long)(java.lang.Object)((a).select(dafny.Helpers.toInt((_3_i)))))) ^ ((_0_c)[(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanModulus((dafny.DafnyEuclidean.EuclideanModulus(_3_i, java.math.BigInteger.valueOf(5L))).add(java.math.BigInteger.valueOf(4L)), java.math.BigInteger.valueOf(5L)))))]))) ^ (__default.Rotate((_0_c)[(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanModulus((dafny.DafnyEuclidean.EuclideanModulus(_3_i, java.math.BigInteger.valueOf(5L))).add(java.math.BigInteger.ONE), java.math.BigInteger.valueOf(5L)))))], java.math.BigInteger.ONE)));
        (_2_b)[dafny.Helpers.toInt(((_3_i)).intValue())] = _4_value;
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.LONG, (_2_b), 0, java.lang.reflect.Array.getLength(_2_b));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Long> Rho(dafny.DafnySequence<? extends java.lang.Long> a)
  {
    dafny.DafnySequence<? extends java.lang.Long> r = dafny.DafnySequence.<java.lang.Long> empty(dafny.TypeDescriptor.LONG);
    if(true) {
      dafny.DafnySequence<? extends java.math.BigInteger> _0_offsets;
      _0_offsets = __default.Offsets();
      long[] _1_b;
      long[] _nw0 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(25L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
      _1_b = _nw0;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(25L);
      for (java.math.BigInteger _2_i = java.math.BigInteger.ZERO; _2_i.compareTo(_hi0) < 0; _2_i = _2_i.add(java.math.BigInteger.ONE)) {
        (_1_b)[dafny.Helpers.toInt(((_2_i)).intValue())] = __default.Rotate(((long)(java.lang.Object)((a).select(dafny.Helpers.toInt((_2_i))))), ((java.math.BigInteger)(java.lang.Object)((_0_offsets).select(dafny.Helpers.toInt((_2_i))))));
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.LONG, (_1_b), 0, java.lang.reflect.Array.getLength(_1_b));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Long> Pi(dafny.DafnySequence<? extends java.lang.Long> a)
  {
    dafny.DafnySequence<? extends java.lang.Long> r = dafny.DafnySequence.<java.lang.Long> empty(dafny.TypeDescriptor.LONG);
    if(true) {
      long[] _0_b;
      long[] _nw0 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(25L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
      _0_b = _nw0;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(25L);
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        (_0_b)[dafny.Helpers.toInt(((_1_i)).intValue())] = ((long)(java.lang.Object)((a).select(dafny.Helpers.toInt(((dafny.DafnyEuclidean.EuclideanModulus((dafny.DafnyEuclidean.EuclideanModulus(_1_i, java.math.BigInteger.valueOf(5L))).add((java.math.BigInteger.valueOf(3L)).multiply(dafny.DafnyEuclidean.EuclideanDivision(_1_i, java.math.BigInteger.valueOf(5L)))), java.math.BigInteger.valueOf(5L))).add((java.math.BigInteger.valueOf(5L)).multiply(dafny.DafnyEuclidean.EuclideanModulus(_1_i, java.math.BigInteger.valueOf(5L)))))))));
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.LONG, (_0_b), 0, java.lang.reflect.Array.getLength(_0_b));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Long> Chi(dafny.DafnySequence<? extends java.lang.Long> a)
  {
    dafny.DafnySequence<? extends java.lang.Long> r = dafny.DafnySequence.<java.lang.Long> empty(dafny.TypeDescriptor.LONG);
    if(true) {
      long[] _0_b;
      long[] _nw0 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(25L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
      _0_b = _nw0;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(25L);
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        java.math.BigInteger _2_row = java.math.BigInteger.ZERO;
        _2_row = (java.math.BigInteger.valueOf(5L)).multiply(dafny.DafnyEuclidean.EuclideanDivision(_1_i, java.math.BigInteger.valueOf(5L)));
        java.math.BigInteger _3_x = java.math.BigInteger.ZERO;
        _3_x = dafny.DafnyEuclidean.EuclideanModulus(_1_i, java.math.BigInteger.valueOf(5L));
        (_0_b)[dafny.Helpers.toInt(((_1_i)).intValue())] = (long) (long) ((((long)(java.lang.Object)((a).select(dafny.Helpers.toInt((_1_i)))))) ^ ((long) (long) (((long) (long) (((long) ~(((long)(java.lang.Object)((a).select(dafny.Helpers.toInt(((_2_row).add(dafny.DafnyEuclidean.EuclideanModulus((_3_x).add(java.math.BigInteger.ONE), java.math.BigInteger.valueOf(5L)))))))))))) & (((long)(java.lang.Object)((a).select(dafny.Helpers.toInt(((_2_row).add(dafny.DafnyEuclidean.EuclideanModulus((_3_x).add(java.math.BigInteger.valueOf(2L)), java.math.BigInteger.valueOf(5L))))))))))));
      }
      r = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.LONG, (_0_b), 0, java.lang.reflect.Array.getLength(_0_b));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Long> Iota(dafny.DafnySequence<? extends java.lang.Long> a, long rc)
  {
    dafny.DafnySequence<? extends java.lang.Long> r = dafny.DafnySequence.<java.lang.Long> empty(dafny.TypeDescriptor.LONG);
    if(true) {
      r = dafny.DafnySequence.<java.lang.Long>update(a, dafny.Helpers.toInt((java.math.BigInteger.ZERO)), (long) (long) ((((long)(java.lang.Object)((a).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))) ^ (rc)));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Long> Round(dafny.DafnySequence<? extends java.lang.Long> a, long rc)
  {
    dafny.DafnySequence<? extends java.lang.Long> r = dafny.DafnySequence.<java.lang.Long> empty(dafny.TypeDescriptor.LONG);
    if(true) {
      dafny.DafnySequence<? extends java.lang.Long> _0_t;
      dafny.DafnySequence<? extends java.lang.Long> _out0;
      _out0 = __default.Theta(a);
      _0_t = _out0;
      dafny.DafnySequence<? extends java.lang.Long> _1_u;
      dafny.DafnySequence<? extends java.lang.Long> _out1;
      _out1 = __default.Rho(_0_t);
      _1_u = _out1;
      dafny.DafnySequence<? extends java.lang.Long> _2_v;
      dafny.DafnySequence<? extends java.lang.Long> _out2;
      _out2 = __default.Pi(_1_u);
      _2_v = _out2;
      dafny.DafnySequence<? extends java.lang.Long> _3_w;
      dafny.DafnySequence<? extends java.lang.Long> _out3;
      _out3 = __default.Chi(_2_v);
      _3_w = _out3;
      dafny.DafnySequence<? extends java.lang.Long> _out4;
      _out4 = __default.Iota(_3_w, rc);
      r = _out4;
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Long> Permute(dafny.DafnySequence<? extends java.lang.Long> a)
  {
    dafny.DafnySequence<? extends java.lang.Long> r = dafny.DafnySequence.<java.lang.Long> empty(dafny.TypeDescriptor.LONG);
    if(true) {
      dafny.DafnySequence<? extends java.lang.Long> _0_constants;
      _0_constants = __default.Constants();
      r = a;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf(24L);
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        dafny.DafnySequence<? extends java.lang.Long> _out0;
        _out0 = __default.Round(r, ((long)(java.lang.Object)((_0_constants).select(dafny.Helpers.toInt((_1_i))))));
        r = _out0;
      }
    }
    return r;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedKeccak._default";
  }
}
