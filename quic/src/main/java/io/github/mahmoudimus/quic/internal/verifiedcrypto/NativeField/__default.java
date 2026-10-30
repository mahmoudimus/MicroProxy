// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static int ReduceOnce(int a)
  {
    int r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      int _0_biased;
      _0_biased = (int) (((int) ((a) + (32768))) - (__default.Q()));
      long _1_atLeastQ;
      _1_atLeastQ = (long) (long) (((long) dafny.Helpers.bv64ShiftRight(((long) (_0_biased)), ((byte) (15)))) & ((long) 1L));
      r = (int) ((a) - ((int) ((((int) (_1_atLeastQ))) * (__default.Q()))));
    }
    return r;
  }
  public static int Reduce(int a)
  {
    int r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      long _0_product;
      _0_product = (long) (long) ((((long) (a))) * ((long) 5039L));
      long _1_shifted;
      _1_shifted = (long) dafny.Helpers.bv64ShiftRight((_0_product), ((byte) (24)));
      int _2_quotient;
      _2_quotient = ((int) (_1_shifted));
      int _3_remainder;
      _3_remainder = (int) ((a) - ((int) ((_2_quotient) * (__default.Q()))));
      int _out0;
      _out0 = __default.ReduceOnce(_3_remainder);
      r = _out0;
    }
    return r;
  }
  public static int Add(int a, int b)
  {
    int r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      int _out0;
      _out0 = __default.ReduceOnce((int) ((a) + (b)));
      r = _out0;
    }
    return r;
  }
  public static int Sub(int a, int b)
  {
    int r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      int _out0;
      _out0 = __default.ReduceOnce((int) (((int) ((a) + (__default.Q()))) - (b)));
      r = _out0;
    }
    return r;
  }
  public static int Mul(int a, int b)
  {
    int r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      int _out0;
      _out0 = __default.Reduce((int) ((a) * (b)));
      r = _out0;
    }
    return r;
  }
  public static int MulSub(int a, int b, int c)
  {
    int r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      int _0_adjusted;
      _0_adjusted = (int) (((int) ((b) + (__default.Q()))) - (c));
      int _out0;
      _out0 = __default.Reduce((int) ((a) * (_0_adjusted)));
      r = _out0;
    }
    return r;
  }
  public static int AddMul(int a, int b, int c, int d)
  {
    int r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      int _out0;
      _out0 = __default.Reduce((int) (((int) ((a) * (b))) + ((int) ((c) * (d)))));
      r = _out0;
    }
    return r;
  }
  public static int Q()
  {
    return 3329;
  }
  public static int MaxReduce()
  {
    return 22154496;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField._default";
  }
}
