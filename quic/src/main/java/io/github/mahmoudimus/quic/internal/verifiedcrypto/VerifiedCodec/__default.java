// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static java.math.BigInteger Compress(java.math.BigInteger x, java.math.BigInteger d)
  {
    java.math.BigInteger r = java.math.BigInteger.ZERO;
    if(true) {
      r = dafny.DafnyEuclidean.EuclideanModulus(dafny.DafnyEuclidean.EuclideanDivision(((io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Pow2(d)).multiply(x)).add(java.math.BigInteger.valueOf(1664L)), java.math.BigInteger.valueOf(3329L)), io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Pow2(d));
    }
    return r;
  }
  public static java.math.BigInteger Decompress(java.math.BigInteger y, java.math.BigInteger d)
  {
    java.math.BigInteger r = java.math.BigInteger.ZERO;
    if(true) {
      r = dafny.DafnyEuclidean.EuclideanDivision(((java.math.BigInteger.valueOf(3329L)).multiply(y)).add(dafny.DafnyEuclidean.EuclideanDivision(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Pow2(d), java.math.BigInteger.valueOf(2L))), io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Pow2(d));
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Encode(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger d)
  {
    dafny.DafnySequence<? extends java.lang.Byte> b = dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE);
    if(true) {
      byte[] _0_a;
      byte[] _nw0 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked(((java.math.BigInteger.valueOf(32L)).multiply(d)), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      _0_a = _nw0;
      java.math.BigInteger _hi0 = (java.math.BigInteger.valueOf(32L)).multiply(d);
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        (_0_a)[dafny.Helpers.toInt(((_1_i)).intValue())] = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.EncodedByte(f, d, _1_i);
      }
      b = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BYTE, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
    }
    return b;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult Decode(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger d)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult r = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.Default();
    if (!(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Width(d))) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.create_InvalidWidth();
      return r;
    }
    if (!java.util.Objects.equals(java.math.BigInteger.valueOf((b).length()), (java.math.BigInteger.valueOf(32L)).multiply(d))) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.create_InvalidLength();
      return r;
    }
    java.math.BigInteger[] _0_a;
    java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N()), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
    _0_a = _nw0;
    java.math.BigInteger _hi0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N();
    for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
      (_0_a)[dafny.Helpers.toInt(((_1_i)).intValue())] = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.DecodedWord(b, d, _1_i);
    }
    dafny.DafnySequence<? extends java.math.BigInteger> _2_f;
    _2_f = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
    if ((java.util.Objects.equals(d, java.math.BigInteger.valueOf(12L))) && (!(io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.Canonical(_2_f)))) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.create_ModulusError();
      return r;
    }
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.create_Decoded(_2_f);
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> CompressAndEncode(dafny.DafnySequence<? extends java.math.BigInteger> f, java.math.BigInteger d)
  {
    dafny.DafnySequence<? extends java.lang.Byte> b = dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE);
    if(true) {
      if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(12L))) {
        dafny.DafnySequence<? extends java.lang.Byte> _out0;
        _out0 = __default.Encode(f, d);
        b = _out0;
        return b;
      }
      java.math.BigInteger[] _0_a;
      java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N()), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
      _0_a = _nw0;
      java.math.BigInteger _hi0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N();
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        java.math.BigInteger _out1 = java.math.BigInteger.ZERO;
        _out1 = __default.Compress(((java.math.BigInteger)(java.lang.Object)((f).select(dafny.Helpers.toInt((_1_i))))), d);
        (_0_a)[dafny.Helpers.toInt(((_1_i)).intValue())] = _out1;
      }
      dafny.DafnySequence<? extends java.math.BigInteger> _2_f1;
      _2_f1 = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_0_a), 0, java.lang.reflect.Array.getLength(_0_a));
      dafny.DafnySequence<? extends java.lang.Byte> _out2;
      _out2 = __default.Encode(_2_f1, d);
      b = _out2;
    }
    return b;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult DecodeAndDecompress(dafny.DafnySequence<? extends java.lang.Byte> b, java.math.BigInteger d)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult r = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.Default();
    io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult _0_raw;
    io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult _out0;
    _out0 = __default.Decode(b, d);
    _0_raw = _out0;
    if (!((_0_raw).is_Decoded())) {
      r = _0_raw;
      return r;
    }
    if (java.util.Objects.equals(d, java.math.BigInteger.valueOf(12L))) {
      r = _0_raw;
      return r;
    }
    java.math.BigInteger[] _1_a;
    java.math.BigInteger[] _nw0 = (java.math.BigInteger[]) dafny.TypeDescriptor.BIG_INTEGER.fillThenReturnArray(dafny.TypeDescriptor.BIG_INTEGER.newArray(dafny.Helpers.toIntChecked((io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N()), "Java arrays may be no larger than the maximum 32-bit signed int")), java.math.BigInteger.ZERO);
    _1_a = _nw0;
    java.math.BigInteger _hi0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.__default.N();
    for (java.math.BigInteger _2_i = java.math.BigInteger.ZERO; _2_i.compareTo(_hi0) < 0; _2_i = _2_i.add(java.math.BigInteger.ONE)) {
      java.math.BigInteger _out1 = java.math.BigInteger.ZERO;
      _out1 = __default.Decompress(((java.math.BigInteger)(java.lang.Object)(((_0_raw).dtor_words()).select(dafny.Helpers.toInt((_2_i))))), d);
      (_1_a)[dafny.Helpers.toInt(((_2_i)).intValue())] = _out1;
    }
    dafny.DafnySequence<? extends java.math.BigInteger> _3_f;
    _3_f = dafny.DafnySequence.fromRawArrayRange(dafny.TypeDescriptor.BIG_INTEGER, (_1_a), 0, java.lang.reflect.Array.getLength(_1_a));
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.DecodeResult.create_Decoded(_3_f);
    return r;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec._default";
  }
}
