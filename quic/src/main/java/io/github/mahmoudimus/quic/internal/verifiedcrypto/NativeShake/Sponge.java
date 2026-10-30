// Class Sponge
// Dafny class Sponge compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake;

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

@SuppressWarnings({"unchecked", "deprecation"})
public class Sponge {
  public Sponge() {
    this.position = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    this.squeezing = false;
    this._lanes = new long[0];
    this._offsets = new int[0];
    this._sources = new int[0];
    this._scratch = new long[0];
    this._parity = new long[0];
    this._rate = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
  }
  public int position;
  public boolean squeezing;
  public void __ctor(int r)
  {
    int[] _0_table;
    int[] _out0;
    _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default.NewOffsets();
    _0_table = _out0;
    int[] _1_indexTable;
    int[] _out1;
    _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default.NewSources();
    _1_indexTable = _out1;
    long[] _nw0 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(25L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
    (this)._lanes = _nw0;
    long[] _nw1 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(25L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
    (this)._scratch = _nw1;
    long[] _nw2 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(5L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
    (this)._parity = _nw2;
    (this)._offsets = _0_table;
    (this)._sources = _1_indexTable;
    (this)._rate = r;
    (this).position = 0;
    (this).squeezing = false;
    int _hi0 = 25;
    for (int _2_i = 0; _2_i < _hi0; _2_i++) {
      ((this).lanes())[dafny.Helpers.toInt((_2_i))] = (long) 0L;
    }
  }
  public void XorByte(int at, byte value)
  {
    int _0_j;
    _0_j = dafny.DafnyEuclidean.EuclideanDivision(at, 8);
    long _1_updated;
    _1_updated = __default.XorWord(((this).lanes())[(_0_j)], at, value);
    io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default.SetLane((this).lanes(), _0_j, _1_updated);
  }
  public void Permute()
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default.PermuteScratch((this).lanes(), (this).scratch(), (this).parity(), (this).offsets(), (this).sources());
  }
  public void AbsorbOne(byte value)
  {
    (this).XorByte(this.position, value);
    if (((int) ((this.position) + (1))) == ((this).rate())) {
      (this).Permute();
      (this).position = 0;
    } else {
      (this).position = (int) ((this.position) + (1));
    }
  }
  public int Update(byte[] input, int offset, int length)
  {
    int status = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      if (this.squeezing) {
        status = 1;
        return status;
      }
      int _0_size;
      _0_size = (input).length;
      if ((((java.lang.Integer.signum((offset)) == -1) || ((offset) > (_0_size))) || (java.lang.Integer.signum((length)) == -1)) || ((length) > ((int) ((_0_size) - (offset))))) {
        status = 2;
        return status;
      }
      int _hi0 = length;
      for (int _1_i = 0; _1_i < _hi0; _1_i++) {
        (this).AbsorbOne((input)[((int) ((offset) + (_1_i)))]);
      }
      status = 0;
    }
    return status;
  }
  public void Start()
  {
    if (!(this.squeezing)) {
      (this).XorByte(this.position, (byte) 31);
      (this).XorByte((int) (((this).rate()) - (1)), (byte) 128);
      (this).Permute();
      (this).position = 0;
      (this).squeezing = true;
    }
  }
  public byte Next()
  {
    byte value = (byte) 0;
    if(true) {
      if ((this.position) == ((this).rate())) {
        (this).Permute();
        (this).position = 0;
      }
      value = ((byte) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(((this).lanes())[(dafny.DafnyEuclidean.EuclideanDivision(this.position, 8))], ((byte) ((int) ((8) * (dafny.DafnyEuclidean.EuclideanModulus(this.position, 8))))))) & ((long) 255L))));
      (this).position = (int) ((this.position) + (1));
    }
    return value;
  }
  public void Read(byte[] output)
  {
    (this).Start();
    int _0_length;
    _0_length = (output).length;
    int _hi0 = _0_length;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      byte _out0;
      _out0 = (this).Next();
      (output)[dafny.Helpers.toInt((_1_i))] = _out0;
    }
  }
  public void Destroy()
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default.Wipe((this).lanes());
    io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default.Wipe((this).scratch());
    io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default.Wipe((this).parity());
    (this).position = 0;
    (this).squeezing = false;
  }
  public long[] _lanes;
  public long[] lanes()
  {
    return this._lanes;
  }
  public int[] _offsets;
  public int[] offsets()
  {
    return this._offsets;
  }
  public int[] _sources;
  public int[] sources()
  {
    return this._sources;
  }
  public long[] _scratch;
  public long[] scratch()
  {
    return this._scratch;
  }
  public long[] _parity;
  public long[] parity()
  {
    return this._parity;
  }
  public int _rate;
  public int rate()
  {
    return this._rate;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge";
  }
}
