// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static java.math.BigInteger ReduceOnce(java.math.BigInteger a)
  {
    java.math.BigInteger r = java.math.BigInteger.ZERO;
    if(true) {
      java.math.BigInteger _0_x = java.math.BigInteger.ZERO;
      _0_x = dafny.DafnyEuclidean.EuclideanModulus((a).subtract(__default.Q()), java.math.BigInteger.valueOf(65536L));
      r = dafny.DafnyEuclidean.EuclideanModulus((_0_x).add((dafny.DafnyEuclidean.EuclideanDivision(_0_x, java.math.BigInteger.valueOf(32768L))).multiply(__default.Q())), java.math.BigInteger.valueOf(65536L));
    }
    return r;
  }
  public static java.math.BigInteger Reduce(java.math.BigInteger a)
  {
    java.math.BigInteger r = java.math.BigInteger.ZERO;
    if(true) {
      java.math.BigInteger _0_quotient = java.math.BigInteger.ZERO;
      _0_quotient = dafny.DafnyEuclidean.EuclideanDivision((a).multiply(java.math.BigInteger.valueOf(5039L)), java.math.BigInteger.valueOf(16777216L));
      java.math.BigInteger _1_remainder = java.math.BigInteger.ZERO;
      _1_remainder = (a).subtract((_0_quotient).multiply(__default.Q()));
      java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
      _out0 = __default.ReduceOnce(dafny.DafnyEuclidean.EuclideanModulus(_1_remainder, java.math.BigInteger.valueOf(65536L)));
      r = _out0;
    }
    return r;
  }
  public static java.math.BigInteger Add(java.math.BigInteger a, java.math.BigInteger b)
  {
    java.math.BigInteger r = java.math.BigInteger.ZERO;
    if(true) {
      java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
      _out0 = __default.ReduceOnce(dafny.DafnyEuclidean.EuclideanModulus((a).add(b), java.math.BigInteger.valueOf(65536L)));
      r = _out0;
    }
    return r;
  }
  public static java.math.BigInteger Sub(java.math.BigInteger a, java.math.BigInteger b)
  {
    java.math.BigInteger r = java.math.BigInteger.ZERO;
    if(true) {
      java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
      _out0 = __default.ReduceOnce(dafny.DafnyEuclidean.EuclideanModulus(((a).subtract(b)).add(__default.Q()), java.math.BigInteger.valueOf(65536L)));
      r = _out0;
    }
    return r;
  }
  public static java.math.BigInteger Mul(java.math.BigInteger a, java.math.BigInteger b)
  {
    java.math.BigInteger r = java.math.BigInteger.ZERO;
    if(true) {
      java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
      _out0 = __default.Reduce((a).multiply(b));
      r = _out0;
    }
    return r;
  }
  public static java.math.BigInteger MulSub(java.math.BigInteger a, java.math.BigInteger b, java.math.BigInteger c)
  {
    java.math.BigInteger r = java.math.BigInteger.ZERO;
    if(true) {
      java.math.BigInteger _0_adjusted = java.math.BigInteger.ZERO;
      _0_adjusted = dafny.DafnyEuclidean.EuclideanModulus(((b).subtract(c)).add(__default.Q()), java.math.BigInteger.valueOf(65536L));
      java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
      _out0 = __default.Reduce((a).multiply(_0_adjusted));
      r = _out0;
    }
    return r;
  }
  public static java.math.BigInteger AddMul(java.math.BigInteger a, java.math.BigInteger b, java.math.BigInteger c, java.math.BigInteger d)
  {
    java.math.BigInteger r = java.math.BigInteger.ZERO;
    if(true) {
      java.math.BigInteger _out0 = java.math.BigInteger.ZERO;
      _out0 = __default.Reduce(((a).multiply(b)).add((c).multiply(d)));
      r = _out0;
    }
    return r;
  }
  public static java.math.BigInteger Q()
  {
    return java.math.BigInteger.valueOf(3329L);
  }
  public static java.math.BigInteger MaxReduce()
  {
    return java.math.BigInteger.valueOf(22154496L);
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField._default";
  }
}
