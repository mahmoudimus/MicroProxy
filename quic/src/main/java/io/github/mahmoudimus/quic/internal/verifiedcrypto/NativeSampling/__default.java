// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling;

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

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static boolean IsPrefix(int[] a)
  {
    boolean ok = false;
    int _0_size;
    _0_size = (a).length;
    if ((_0_size) > (256)) {
      ok = false;
      return ok;
    }
    int _hi0 = _0_size;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      if ((java.lang.Integer.signum(((a)[(_1_i)])) == -1) || (((a)[(_1_i)]) >= (3329))) {
        ok = false;
        return ok;
      }
    }
    ok = true;
    return ok;
  }
  public static int[] Cbd2(byte[] b)
  {
    int[] f = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      f = _nw0;
      int _hi0 = 256;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        long _1_x;
        _1_x = (long) java.lang.Byte.toUnsignedLong((b)[(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.PublicDiv(_0_i, 2))]);
        int _2_j;
        _2_j = (int) ((4) * (io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.PublicMod(_0_i, 2)));
        int _3_low;
        _3_low = (int) ((io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.Extract(_1_x, _2_j, 1)) + (io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.Extract(_1_x, (int) ((_2_j) + (1)), 1)));
        int _4_high;
        _4_high = (int) ((io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.Extract(_1_x, (int) ((_2_j) + (2)), 1)) + (io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.Extract(_1_x, (int) ((_2_j) + (3)), 1)));
        int _out0;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default.ReduceOnce((int) (((int) ((3329) + (_3_low))) - (_4_high)));
        (f)[dafny.Helpers.toInt((_0_i))] = _out0;
      }
    }
    return f;
  }
  public static FeedResult Feed(int[] current, byte[] b)
  {
    FeedResult r = FeedResult.Default();
    boolean _0_valid;
    boolean _out0;
    _out0 = __default.IsPrefix(current);
    _0_valid = _out0;
    if (!(_0_valid)) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.FeedResult.create_InvalidPrefix();
      return r;
    }
    int _1_size;
    _1_size = (b).length;
    if (java.lang.Integer.signum((io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.PublicMod(_1_size, 3))) != 0) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.FeedResult.create_InvalidBlockLength();
      return r;
    }
    int[] _2_a;
    int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
    _2_a = _nw0;
    int _3_used;
    _3_used = (current).length;
    int _hi0 = _3_used;
    for (int _4_i = 0; _4_i < _hi0; _4_i++) {
      (_2_a)[dafny.Helpers.toInt((_4_i))] = (current)[(_4_i)];
    }
    int _5_off;
    _5_off = 0;
    while (((_3_used) < (256)) && ((_5_off) < (_1_size))) {
      int _6_x;
      _6_x = (int) ((java.lang.Byte.toUnsignedInt((b)[(_5_off)])) + ((int) ((256) * (io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.Extract((long) java.lang.Byte.toUnsignedLong((b)[((int) ((_5_off) + (1)))]), 0, 4)))));
      int _7_y;
      _7_y = (int) ((io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.Extract((long) java.lang.Byte.toUnsignedLong((b)[((int) ((_5_off) + (1)))]), 4, 4)) + ((int) ((16) * (java.lang.Byte.toUnsignedInt((b)[((int) ((_5_off) + (2)))])))));
      if ((_6_x) < (3329)) {
        (_2_a)[dafny.Helpers.toInt((_3_used))] = _6_x;
        _3_used = (int) ((_3_used) + (1));
      }
      if (((_3_used) < (256)) && ((_7_y) < (3329))) {
        (_2_a)[dafny.Helpers.toInt((_3_used))] = _7_y;
        _3_used = (int) ((_3_used) + (1));
      }
      _5_off = (int) ((_5_off) + (3));
    }
    if ((_3_used) == (256)) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.FeedResult.create_Full(_2_a, _5_off);
      return r;
    }
    int[] _8_partial;
    int[] _nw1 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((_3_used), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
    _8_partial = _nw1;
    int _hi1 = _3_used;
    for (int _9_i = 0; _9_i < _hi1; _9_i++) {
      (_8_partial)[dafny.Helpers.toInt((_9_i))] = (_2_a)[(_9_i)];
    }
    io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.Wipe(_2_a);
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.FeedResult.create_NeedMore(_8_partial, _5_off);
    return r;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling._default";
  }
}
