// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedShake;

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
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedKeccak.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State New(java.math.BigInteger rate)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.Default();
    if(true) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.create(dafny.DafnySequence.Create(dafny.TypeDescriptor.LONG, java.math.BigInteger.valueOf(25L), ((java.util.function.Function<java.math.BigInteger, java.lang.Long>)(_0_i_boxed0) -> {
  java.math.BigInteger _0_i = ((java.math.BigInteger)(java.lang.Object)(_0_i_boxed0));
  return (long) 0L;
})), rate, java.math.BigInteger.ZERO, false);
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Long> XorByte(dafny.DafnySequence<? extends java.lang.Long> lanes, java.math.BigInteger at, byte value)
  {
    dafny.DafnySequence<? extends java.lang.Long> r = dafny.DafnySequence.<java.lang.Long> empty(dafny.TypeDescriptor.LONG);
    if(true) {
      r = dafny.DafnySequence.<java.lang.Long>update(lanes, dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanDivision(at, java.math.BigInteger.valueOf(8L)))), (long) (long) ((((long)(java.lang.Object)((lanes).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanDivision(at, java.math.BigInteger.valueOf(8L)))))))) ^ ((long) (long) (((long) dafny.Helpers.bv64ShiftLeft((long) java.lang.Byte.toUnsignedLong(value), ((java.math.BigInteger.valueOf(8L)).multiply(dafny.DafnyEuclidean.EuclideanModulus(at, java.math.BigInteger.valueOf(8L)))).byteValue()))))));
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State AbsorbOne(io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State s, byte value)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.Default();
    if(true) {
      dafny.DafnySequence<? extends java.lang.Long> _0_lanes;
      dafny.DafnySequence<? extends java.lang.Long> _out0;
      _out0 = __default.XorByte((s).dtor_lanes(), (s).dtor_position(), value);
      _0_lanes = _out0;
      if (java.util.Objects.equals(((s).dtor_position()).add(java.math.BigInteger.ONE), (s).dtor_rate())) {
        dafny.DafnySequence<? extends java.lang.Long> _out1;
        _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedKeccak.__default.Permute(_0_lanes);
        _0_lanes = _out1;
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.create(_0_lanes, (s).dtor_rate(), java.math.BigInteger.ZERO, false);
      } else {
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.create(_0_lanes, (s).dtor_rate(), ((s).dtor_position()).add(java.math.BigInteger.ONE), false);
      }
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State Pad(io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State s)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.Default();
    if(true) {
      dafny.DafnySequence<? extends java.lang.Long> _0_lanes;
      dafny.DafnySequence<? extends java.lang.Long> _out0;
      _out0 = __default.XorByte((s).dtor_lanes(), (s).dtor_position(), (byte) 31);
      _0_lanes = _out0;
      dafny.DafnySequence<? extends java.lang.Long> _out1;
      _out1 = __default.XorByte(_0_lanes, ((s).dtor_rate()).subtract(java.math.BigInteger.ONE), (byte) 128);
      _0_lanes = _out1;
      dafny.DafnySequence<? extends java.lang.Long> _out2;
      _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedKeccak.__default.Permute(_0_lanes);
      _0_lanes = _out2;
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.create(_0_lanes, (s).dtor_rate(), java.math.BigInteger.ZERO, true);
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult Update(io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State s, dafny.DafnySequence<? extends java.lang.Byte> input)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult.Default();
    if(true) {
      if ((s).dtor_squeezing()) {
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult.create_InputAfterOutput();
        return r;
      }
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State _0_current;
      _0_current = s;
      java.math.BigInteger _hi0 = java.math.BigInteger.valueOf((input).length());
      for (java.math.BigInteger _1_i = java.math.BigInteger.ZERO; _1_i.compareTo(_hi0) < 0; _1_i = _1_i.add(java.math.BigInteger.ONE)) {
        io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State _out0;
        _out0 = __default.AbsorbOne(_0_current, ((byte)(java.lang.Object)((input).select(dafny.Helpers.toInt((_1_i))))));
        _0_current = _out0;
      }
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult.create_Updated(_0_current);
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult Next(io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State s)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult.Default();
    if(true) {
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State _0_ready;
      _0_ready = s;
      if (java.util.Objects.equals((_0_ready).dtor_position(), (_0_ready).dtor_rate())) {
        dafny.DafnySequence<? extends java.lang.Long> _1_lanes;
        dafny.DafnySequence<? extends java.lang.Long> _out0;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedKeccak.__default.Permute((_0_ready).dtor_lanes());
        _1_lanes = _out0;
        _0_ready = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.create(_1_lanes, (s).dtor_rate(), java.math.BigInteger.ZERO, true);
      }
      byte _2_value;
      _2_value = ((byte) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(((long)(java.lang.Object)(((_0_ready).dtor_lanes()).select(dafny.Helpers.toInt((dafny.DafnyEuclidean.EuclideanDivision((_0_ready).dtor_position(), java.math.BigInteger.valueOf(8L))))))), ((java.math.BigInteger.valueOf(8L)).multiply(dafny.DafnyEuclidean.EuclideanModulus((_0_ready).dtor_position(), java.math.BigInteger.valueOf(8L)))).byteValue())) & ((long) 255L))));
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult.create(io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.create((_0_ready).dtor_lanes(), (s).dtor_rate(), ((_0_ready).dtor_position()).add(java.math.BigInteger.ONE), true), dafny.DafnySequence.<java.lang.Byte> of(_2_value));
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult UpdateSlice(io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State s, dafny.DafnySequence<? extends java.lang.Byte> input, java.math.BigInteger offset, java.math.BigInteger length)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult.Default();
    if(true) {
      if ((s).dtor_squeezing()) {
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult.create_InputAfterOutput();
        return r;
      }
      if (((((offset).signum() == -1) || ((offset).compareTo(java.math.BigInteger.valueOf((input).length())) > 0)) || ((length).signum() == -1)) || ((length).compareTo((java.math.BigInteger.valueOf((input).length())).subtract(offset)) > 0)) {
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult.create_InvalidSlice();
        return r;
      }
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult _out0;
      _out0 = __default.Update(s, (input).subsequence(dafny.Helpers.toInt((offset)), dafny.Helpers.toInt(((offset).add(length)))));
      r = _out0;
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult Read(io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State s, java.math.BigInteger length)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult.Default();
    if(true) {
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State _0_initial;
      _0_initial = s;
      if (!((_0_initial).dtor_squeezing())) {
        io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State _out0;
        _out0 = __default.Pad(_0_initial);
        _0_initial = _out0;
      }
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State _1_current;
      _1_current = _0_initial;
      dafny.DafnySequence<? extends java.lang.Byte> _2_bytes;
      _2_bytes = dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE);
      java.math.BigInteger _hi0 = length;
      for (java.math.BigInteger _3_i = java.math.BigInteger.ZERO; _3_i.compareTo(_hi0) < 0; _3_i = _3_i.add(java.math.BigInteger.ONE)) {
        io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult _4_next;
        io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult _out1;
        _out1 = __default.Next(_1_current);
        _4_next = _out1;
        _1_current = (_4_next).dtor_state();
        _2_bytes = dafny.DafnySequence.<java.lang.Byte>concatenate(_2_bytes, (_4_next).dtor_bytes());
      }
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult.create(_1_current, _2_bytes);
    }
    return r;
  }
  public static dafny.DafnySequence<? extends java.lang.Byte> Xof(java.math.BigInteger rate, dafny.DafnySequence<? extends java.lang.Byte> input, java.math.BigInteger length)
  {
    dafny.DafnySequence<? extends java.lang.Byte> r = dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE);
    if(true) {
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State _0_state;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State _out0;
      _out0 = __default.New(rate);
      _0_state = _out0;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult _1_updated;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult _out1;
      _out1 = __default.Update(_0_state, input);
      _1_updated = _out1;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult _2_output;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult _out2;
      _out2 = __default.Read((_1_updated).dtor_state(), length);
      _2_output = _out2;
      r = (_2_output).dtor_bytes();
    }
    return r;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedShake._default";
  }
}
