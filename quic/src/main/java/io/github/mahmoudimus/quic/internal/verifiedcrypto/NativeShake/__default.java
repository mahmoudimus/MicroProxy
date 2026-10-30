// Class __default
// Dafny class __default compiled into Java
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
public class __default {
  public __default() {
  }
  public static long XorWord(long word, int at, byte value)
  {
    return (long) (long) ((word) ^ ((long) (long) (((long) dafny.Helpers.bv64ShiftLeft((long) java.lang.Byte.toUnsignedLong(value), ((byte) ((int) ((8) * (dafny.DafnyEuclidean.EuclideanModulus(at, 8))))))))));
  }
  public static byte[] Xof(int rate, byte[] input, int length)
  {
    byte[] output = new byte[0];
    if(true) {
      Sponge _0_sponge;
      Sponge _nw0 = new Sponge();
      _nw0.__ctor(rate);
      _0_sponge = _nw0;
      int _1_size;
      _1_size = (input).length;
      int _2_status;
      int _out0;
      _out0 = (_0_sponge).Update(input, 0, _1_size);
      _2_status = _out0;
      byte[] _nw1 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked((length), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      output = _nw1;
      (_0_sponge).Read(output);
      (_0_sponge).Destroy();
    }
    return output;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake._default";
  }
}
