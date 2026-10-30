// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak;

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

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static long Rotate(long v, int n)
  {
    if (java.lang.Integer.signum((n)) == 0) {
      return v;
    } else {
      return (long) (long) (((long) (long) (((long) dafny.Helpers.bv64ShiftLeft(v, ((byte) (n)))))) | ((long) dafny.Helpers.bv64ShiftRight(v, ((byte) ((int) ((64) - (n)))))));
    }
  }
  public static long Constant(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return (long) 1L;
    } else if ((i) == (1)) {
      return (long) 32898L;
    } else if ((i) == (2)) {
      return (long) -9223372036854742902L;
    } else if ((i) == (3)) {
      return (long) -9223372034707259392L;
    } else if ((i) == (4)) {
      return (long) 32907L;
    } else if ((i) == (5)) {
      return (long) 2147483649L;
    } else if ((i) == (6)) {
      return (long) -9223372034707259263L;
    } else if ((i) == (7)) {
      return (long) -9223372036854743031L;
    } else if ((i) == (8)) {
      return (long) 138L;
    } else if ((i) == (9)) {
      return (long) 136L;
    } else if ((i) == (10)) {
      return (long) 2147516425L;
    } else if ((i) == (11)) {
      return (long) 2147483658L;
    } else if ((i) == (12)) {
      return (long) 2147516555L;
    } else if ((i) == (13)) {
      return (long) -9223372036854775669L;
    } else if ((i) == (14)) {
      return (long) -9223372036854742903L;
    } else if ((i) == (15)) {
      return (long) -9223372036854743037L;
    } else if ((i) == (16)) {
      return (long) -9223372036854743038L;
    } else if ((i) == (17)) {
      return (long) -9223372036854775680L;
    } else if ((i) == (18)) {
      return (long) 32778L;
    } else if ((i) == (19)) {
      return (long) -9223372034707292150L;
    } else if ((i) == (20)) {
      return (long) -9223372034707259263L;
    } else if ((i) == (21)) {
      return (long) -9223372036854742912L;
    } else if ((i) == (22)) {
      return (long) 2147483649L;
    } else {
      return (long) -9223372034707259384L;
    }
  }
  public static int Offset(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 0;
    } else if ((i) == (1)) {
      return 1;
    } else if ((i) == (2)) {
      return 62;
    } else if ((i) == (3)) {
      return 28;
    } else if ((i) == (4)) {
      return 27;
    } else if ((i) == (5)) {
      return 36;
    } else if ((i) == (6)) {
      return 44;
    } else if ((i) == (7)) {
      return 6;
    } else if ((i) == (8)) {
      return 55;
    } else if ((i) == (9)) {
      return 20;
    } else if ((i) == (10)) {
      return 3;
    } else if ((i) == (11)) {
      return 10;
    } else if ((i) == (12)) {
      return 43;
    } else if ((i) == (13)) {
      return 25;
    } else if ((i) == (14)) {
      return 39;
    } else if ((i) == (15)) {
      return 41;
    } else if ((i) == (16)) {
      return 45;
    } else if ((i) == (17)) {
      return 15;
    } else if ((i) == (18)) {
      return 21;
    } else if ((i) == (19)) {
      return 8;
    } else if ((i) == (20)) {
      return 18;
    } else if ((i) == (21)) {
      return 2;
    } else if ((i) == (22)) {
      return 61;
    } else if ((i) == (23)) {
      return 56;
    } else {
      return 14;
    }
  }
  public static int[] NewOffsets()
  {
    int[] r = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(25L)), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      r = _nw0;
      int _hi0 = 25;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        (r)[dafny.Helpers.toInt((_0_i))] = __default.Offset(_0_i);
      }
    }
    return r;
  }
  public static int Source(int i) {
    if (java.lang.Integer.signum((i)) == 0) {
      return 0;
    } else if ((i) == (1)) {
      return 6;
    } else if ((i) == (2)) {
      return 12;
    } else if ((i) == (3)) {
      return 18;
    } else if ((i) == (4)) {
      return 24;
    } else if ((i) == (5)) {
      return 3;
    } else if ((i) == (6)) {
      return 9;
    } else if ((i) == (7)) {
      return 10;
    } else if ((i) == (8)) {
      return 16;
    } else if ((i) == (9)) {
      return 22;
    } else if ((i) == (10)) {
      return 1;
    } else if ((i) == (11)) {
      return 7;
    } else if ((i) == (12)) {
      return 13;
    } else if ((i) == (13)) {
      return 19;
    } else if ((i) == (14)) {
      return 20;
    } else if ((i) == (15)) {
      return 4;
    } else if ((i) == (16)) {
      return 5;
    } else if ((i) == (17)) {
      return 11;
    } else if ((i) == (18)) {
      return 17;
    } else if ((i) == (19)) {
      return 23;
    } else if ((i) == (20)) {
      return 2;
    } else if ((i) == (21)) {
      return 8;
    } else if ((i) == (22)) {
      return 14;
    } else if ((i) == (23)) {
      return 15;
    } else {
      return 21;
    }
  }
  public static int[] NewSources()
  {
    int[] r = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(25L)), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      r = _nw0;
      int _hi0 = 25;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        (r)[dafny.Helpers.toInt((_0_i))] = __default.Source(_0_i);
      }
    }
    return r;
  }
  public static void SetLane(long[] a, int index, long value)
  {
    (a)[dafny.Helpers.toInt((index))] = value;
  }
  public static void Iota(long[] a, long rc)
  {
    long _0_value;
    _0_value = (long) (long) (((a)[(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))]) ^ (rc));
    __default.SetLane(a, 0, _0_value);
  }
  public static void Theta(long[] a, long[] c)
  {
    int _hi0 = 5;
    for (int _0_x = 0; _0_x < _hi0; _0_x++) {
      (c)[dafny.Helpers.toInt((_0_x))] = (long) (long) (((long) (long) (((long) (long) (((long) (long) (((a)[(_0_x)]) ^ ((a)[((int) ((_0_x) + (5)))]))) ^ ((a)[((int) ((_0_x) + (10)))]))) ^ ((a)[((int) ((_0_x) + (15)))]))) ^ ((a)[((int) ((_0_x) + (20)))]));
    }
    int _hi1 = 5;
    for (int _1_x = 0; _1_x < _hi1; _1_x++) {
      long _2_d;
      _2_d = (long) (long) (((c)[(dafny.DafnyEuclidean.EuclideanModulus((int) ((_1_x) + (4)), 5))]) ^ (__default.Rotate((c)[(dafny.DafnyEuclidean.EuclideanModulus((int) ((_1_x) + (1)), 5))], 1)));
      int _hi2 = 5;
      for (int _3_y = 0; _3_y < _hi2; _3_y++) {
        int _4_i;
        _4_i = (int) ((_1_x) + ((int) ((5) * (_3_y))));
        (a)[dafny.Helpers.toInt((_4_i))] = (long) (long) (((a)[(_4_i)]) ^ (_2_d));
      }
    }
  }
  public static void RhoPi(long[] a, long[] b, int[] offsets, int[] sources)
  {
    int _hi0 = 25;
    for (int _0_i = 0; _0_i < _hi0; _0_i++) {
      int _1_j;
      _1_j = (sources)[(_0_i)];
      (b)[dafny.Helpers.toInt((_0_i))] = __default.Rotate((a)[(_1_j)], (offsets)[(_1_j)]);
    }
  }
  public static void Chi(long[] a, long[] b)
  {
    int _hi0 = 25;
    for (int _0_i = 0; _0_i < _hi0; _0_i++) {
      int _1_row;
      _1_row = (int) ((5) * (dafny.DafnyEuclidean.EuclideanDivision(_0_i, 5)));
      int _2_x;
      _2_x = dafny.DafnyEuclidean.EuclideanModulus(_0_i, 5);
      (a)[dafny.Helpers.toInt((_0_i))] = (long) (long) (((b)[(_0_i)]) ^ ((long) (long) (((long) (long) (((long) ~((b)[((int) ((_1_row) + (dafny.DafnyEuclidean.EuclideanModulus((int) ((_2_x) + (1)), 5))))])))) & ((b)[((int) ((_1_row) + (dafny.DafnyEuclidean.EuclideanModulus((int) ((_2_x) + (2)), 5))))]))));
    }
  }
  public static void Round(long[] a, long[] b, long[] c, int[] offsets, int[] sources, long rc)
  {
    __default.Theta(a, c);
    __default.RhoPi(a, b, offsets, sources);
    __default.Chi(a, b);
    __default.Iota(a, rc);
  }
  public static void PermuteScratch(long[] a, long[] b, long[] c, int[] offsets, int[] sources)
  {
    int _hi0 = 24;
    for (int _0_i = 0; _0_i < _hi0; _0_i++) {
      __default.Round(a, b, c, offsets, sources, __default.Constant(_0_i));
    }
  }
  public static void Permute(long[] a)
  {
    long[] _0_b;
    long[] _nw0 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(25L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
    _0_b = _nw0;
    long[] _1_c;
    long[] _nw1 = (long[]) dafny.TypeDescriptor.LONG.fillThenReturnArray(dafny.TypeDescriptor.LONG.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(5L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (long) 0);
    _1_c = _nw1;
    int[] _2_offsets;
    int[] _out0;
    _out0 = __default.NewOffsets();
    _2_offsets = _out0;
    int[] _3_sources;
    int[] _out1;
    _out1 = __default.NewSources();
    _3_sources = _out1;
    __default.PermuteScratch(a, _0_b, _1_c, _2_offsets, _3_sources);
    __default.Wipe(_0_b);
    __default.Wipe(_1_c);
  }
  public static void Wipe(long[] a)
  {
    int _0_length;
    _0_length = (a).length;
    int _hi0 = _0_length;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      (a)[dafny.Helpers.toInt((_1_i))] = (long) 0L;
    }
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak._default";
  }
}
