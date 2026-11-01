// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf;


@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static boolean ValidHash(java.math.BigInteger hashLen) {
    return (dafny.DafnySet.<java.math.BigInteger> of(java.math.BigInteger.valueOf(32L), java.math.BigInteger.valueOf(48L), java.math.BigInteger.valueOf(64L))).<java.math.BigInteger>contains(hashLen);
  }
  public static BytesResult Extract(java.math.BigInteger hashLen, dafny.DafnySequence<? extends java.lang.Byte> salt, dafny.DafnySequence<? extends java.lang.Byte> ikm)
  {
    BytesResult r = BytesResult.Default();
    if(true) {
      if (!(__default.ValidHash(hashLen))) {
        r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Failure(io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.FailureKind.create_InvalidHash());
        return r;
      }
      dafny.DafnySequence<? extends java.lang.Byte> _0_key;
      _0_key = salt;
      if ((java.math.BigInteger.valueOf((_0_key).length())).signum() == 0) {
        _0_key = dafny.DafnySequence.Create(dafny.TypeDescriptor.BYTE, hashLen, ((java.util.function.Function<java.math.BigInteger, java.lang.Byte>)(_1_i_boxed0) -> {
          java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
          return (byte) 0;
        }));
      }
      r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Success(io.github.mahmoudimus.verifiedcrypto.JdkHmac.compute(hashLen, _0_key, ikm));
    }
    return r;
  }
  public static BytesResult Expand(java.math.BigInteger hashLen, dafny.DafnySequence<? extends java.lang.Byte> prk, dafny.DafnySequence<? extends java.lang.Byte> info, java.math.BigInteger length)
  {
    BytesResult r = BytesResult.Default();
    if(true) {
      if (!(__default.ValidHash(hashLen))) {
        r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Failure(io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.FailureKind.create_InvalidHash());
        return r;
      }
      if (((length).signum() == -1) || ((length).compareTo((java.math.BigInteger.valueOf(255L)).multiply(hashLen)) > 0)) {
        r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Failure(io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.FailureKind.create_InvalidLength());
        return r;
      }
      if ((java.math.BigInteger.valueOf((prk).length())).signum() == 0) {
        r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Failure(io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.FailureKind.create_InvalidKey());
        return r;
      }
      java.math.BigInteger _0_n = java.math.BigInteger.ZERO;
      _0_n = dafny.DafnyEuclidean.EuclideanDivision(((length).add(hashLen)).subtract(java.math.BigInteger.ONE), hashLen);
      java.math.BigInteger _1_i = java.math.BigInteger.ZERO;
      _1_i = java.math.BigInteger.ZERO;
      dafny.DafnySequence<? extends java.lang.Byte> _2_previous;
      _2_previous = dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE);
      dafny.DafnySequence<? extends java.lang.Byte> _3_output;
      _3_output = dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE);
      while ((_1_i).compareTo(_0_n) < 0) {
        java.math.BigInteger _4_counter = java.math.BigInteger.ZERO;
        _4_counter = (_1_i).add(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends java.lang.Byte> _5_next;
        _5_next = io.github.mahmoudimus.verifiedcrypto.JdkHmac.compute(hashLen, prk, dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(_2_previous, info), dafny.DafnySequence.<java.lang.Byte> of((_4_counter).byteValue())));
        _3_output = dafny.DafnySequence.<java.lang.Byte>concatenate(_3_output, _5_next);
        _2_previous = _5_next;
        _1_i = (_1_i).add(java.math.BigInteger.ONE);
      }
      r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Success((_3_output).take(length));
    }
    return r;
  }
  public static BytesResult LabelInfo(dafny.DafnySequence<? extends java.lang.Short> labelUnits, dafny.DafnySequence<? extends java.lang.Byte> context, java.math.BigInteger length)
  {
    BytesResult r = BytesResult.Default();
    if(true) {
      if (((((length).signum() == -1) || ((length).compareTo(java.math.BigInteger.valueOf(65535L)) > 0)) || ((java.math.BigInteger.valueOf((labelUnits).length())).compareTo(java.math.BigInteger.valueOf(249L)) > 0)) || ((java.math.BigInteger.valueOf((context).length())).compareTo(java.math.BigInteger.valueOf(255L)) > 0)) {
        r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Failure(io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.FailureKind.create_InvalidLength());
        return r;
      }
      dafny.DafnySequence<? extends java.lang.Byte> _0_ascii;
      _0_ascii = dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE);
      java.math.BigInteger _1_i = java.math.BigInteger.ZERO;
      _1_i = java.math.BigInteger.ZERO;
      while ((_1_i).compareTo(java.math.BigInteger.valueOf((labelUnits).length())) < 0) {
        if (java.lang.Integer.compareUnsigned(((short)(java.lang.Object)((labelUnits).select(dafny.Helpers.toInt((_1_i))))), (short) 127) > 0) {
          r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Failure(io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.FailureKind.create_InvalidLabel());
          return r;
        }
        _0_ascii = dafny.DafnySequence.<java.lang.Byte>concatenate(_0_ascii, dafny.DafnySequence.<java.lang.Byte> of(((byte) (((short)(java.lang.Object)((labelUnits).select(dafny.Helpers.toInt((_1_i)))))))));
        _1_i = (_1_i).add(java.math.BigInteger.ONE);
      }
      dafny.DafnySequence<? extends java.lang.Byte> _2_header;
      _2_header = dafny.DafnySequence.<java.lang.Byte> of((dafny.DafnyEuclidean.EuclideanDivision(length, java.math.BigInteger.valueOf(256L))).byteValue(), (dafny.DafnyEuclidean.EuclideanModulus(length, java.math.BigInteger.valueOf(256L))).byteValue(), ((java.math.BigInteger.valueOf(6L)).add(java.math.BigInteger.valueOf((labelUnits).length()))).byteValue());
      dafny.DafnySequence<? extends java.lang.Byte> _3_prefix;
      _3_prefix = dafny.DafnySequence.<java.lang.Byte> of((byte) 116, (byte) 108, (byte) 115, (byte) 49, (byte) 51, (byte) 32);
      dafny.DafnySequence<? extends java.lang.Byte> _4_serialized;
      _4_serialized = dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(dafny.DafnySequence.<java.lang.Byte>concatenate(_2_header, _3_prefix), _0_ascii), dafny.DafnySequence.<java.lang.Byte> of((byte) (context).cardinalityInt())), context);
      r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Success(_4_serialized);
    }
    return r;
  }
  public static BytesResult ExpandLabel(java.math.BigInteger hashLen, dafny.DafnySequence<? extends java.lang.Byte> secret, dafny.DafnySequence<? extends java.lang.Short> labelUnits, dafny.DafnySequence<? extends java.lang.Byte> context, java.math.BigInteger length)
  {
    BytesResult r = BytesResult.Default();
    if(true) {
      if (!(__default.ValidHash(hashLen))) {
        r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Failure(io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.FailureKind.create_InvalidHash());
        return r;
      }
      BytesResult _0_encoded;
      BytesResult _out0;
      _out0 = __default.LabelInfo(labelUnits, context, length);
      _0_encoded = _out0;
      BytesResult _source0 = _0_encoded;
      if (_source0.is_Success()) {
        dafny.DafnySequence<? extends java.lang.Byte> _1___mcc_h0 = ((io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult_Success)_source0)._bytes;
        dafny.DafnySequence<? extends java.lang.Byte> _2_info = _1___mcc_h0;
        BytesResult _out1;
        _out1 = __default.Expand(hashLen, secret, _2_info, length);
        r = _out1;
      } else {
        FailureKind _3___mcc_h1 = ((io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult_Failure)_source0)._reason;
        FailureKind _4_reason = _3___mcc_h1;
        r = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Failure(_4_reason);
      }
    }
    return r;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf._default";
  }
}
