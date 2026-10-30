// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static void Wipe(int[] a)
  {
    int _0_size;
    _0_size = (a).length;
    int _hi0 = _0_size;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      (a)[dafny.Helpers.toInt((_1_i))] = 0;
    }
  }
  public static boolean Width(int d) {
    return ((((d) == (1)) || ((d) == (4))) || ((d) == (10))) || ((d) == (12));
  }
  public static int Pow2(int d) {
    if (java.lang.Integer.signum((d)) == 0) {
      return 1;
    } else if ((d) == (1)) {
      return 2;
    } else if ((d) == (2)) {
      return 4;
    } else if ((d) == (3)) {
      return 8;
    } else if ((d) == (4)) {
      return 16;
    } else if ((d) == (5)) {
      return 32;
    } else if ((d) == (6)) {
      return 64;
    } else if ((d) == (7)) {
      return 128;
    } else if ((d) == (8)) {
      return 256;
    } else if ((d) == (9)) {
      return 512;
    } else if ((d) == (10)) {
      return 1024;
    } else if ((d) == (11)) {
      return 2048;
    } else {
      return 4096;
    }
  }
  public static int GroupWords(int d) {
    if ((d) == (1)) {
      return 8;
    } else if ((d) == (10)) {
      return 4;
    } else {
      return 2;
    }
  }
  public static int GroupBytes(int d) {
    if ((d) == (10)) {
      return 5;
    } else if ((d) == (12)) {
      return 3;
    } else {
      return 1;
    }
  }
  public static long BytePower(int j) {
    if (java.lang.Integer.signum((j)) == 0) {
      return (long) 1L;
    } else if ((j) == (1)) {
      return (long) 256L;
    } else if ((j) == (2)) {
      return (long) 65536L;
    } else if ((j) == (3)) {
      return (long) 16777216L;
    } else {
      return (long) 4294967296L;
    }
  }
  public static long WordPower(int d, int j)
  {
    if ((d) == (1)) {
      return ((long) (__default.Pow2(j)));
    } else if ((d) == (4)) {
      if (java.lang.Integer.signum((j)) == 0) {
        return (long) 1L;
      } else {
        return (long) 16L;
      }
    } else if ((d) == (10)) {
      if (java.lang.Integer.signum((j)) == 0) {
        return (long) 1L;
      } else if ((j) == (1)) {
        return (long) 1024L;
      } else if ((j) == (2)) {
        return (long) 1048576L;
      } else {
        return (long) 1073741824L;
      }
    } else {
      if (java.lang.Integer.signum((j)) == 0) {
        return (long) 1L;
      } else {
        return (long) 4096L;
      }
    }
  }
  public static int Extract(long value, int shift, int bits)
  {
    long _0_word = (value);
    long _1_shifted = (long) dafny.Helpers.bv64ShiftRight(_0_word, ((byte) (shift)));
    long _2_masked = (long) (long) ((_1_shifted) & (((long) ((int) ((__default.Pow2(bits)) - (1))))));
    return ((int) (_2_masked));
  }
  public static int Shift(long value, int shift)
  {
    long _0_word = (value);
    return ((int) ((long) dafny.Helpers.bv64ShiftRight(_0_word, ((byte) (shift)))));
  }
  public static int PublicDiv(int value, int divisor)
  {
    return dafny.DafnyEuclidean.EuclideanDivision(value, divisor);
  }
  public static int PublicMod(int value, int divisor)
  {
    return dafny.DafnyEuclidean.EuclideanModulus(value, divisor);
  }
  public static int Compress(int x, int d)
  {
    int r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      int _0_p;
      _0_p = __default.Pow2(d);
      int _1_dividend;
      _1_dividend = (int) (((int) ((_0_p) * (x))) + (1664));
      long _2_product;
      _2_product = (long) (long) ((((long) (_1_dividend))) * ((long) 5039L));
      int _3_quotient;
      _3_quotient = ((int) ((long) dafny.Helpers.bv64ShiftRight((_2_product), ((byte) (24)))));
      int _4_remainder;
      _4_remainder = (int) ((_1_dividend) - ((int) ((_3_quotient) * (3329))));
      int _5_biased;
      _5_biased = (int) (((int) ((_4_remainder) + (32768))) - (3329));
      int _6_correction;
      _6_correction = ((int) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(((long) (_5_biased)), ((byte) (15)))) & ((long) 1L))));
      int _7_rounded;
      _7_rounded = (int) ((_3_quotient) + (_6_correction));
      r = __default.Extract(((long) (_7_rounded)), 0, d);
    }
    return r;
  }
  public static long DecompressionScale(int d) {
    if ((d) == (1)) {
      return (long) 8388608L;
    } else if ((d) == (2)) {
      return (long) 4194304L;
    } else if ((d) == (3)) {
      return (long) 2097152L;
    } else if ((d) == (4)) {
      return (long) 1048576L;
    } else if ((d) == (5)) {
      return (long) 524288L;
    } else if ((d) == (6)) {
      return (long) 262144L;
    } else if ((d) == (7)) {
      return (long) 131072L;
    } else if ((d) == (8)) {
      return (long) 65536L;
    } else if ((d) == (9)) {
      return (long) 32768L;
    } else if ((d) == (10)) {
      return (long) 16384L;
    } else {
      return (long) 8192L;
    }
  }
  public static int Decompress(int y, int d)
  {
    int r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness;
    if(true) {
      int _0_p;
      _0_p = __default.Pow2(d);
      int _1_dividend;
      _1_dividend = (int) (((int) ((3329) * (y))) + (__default.PublicDiv(_0_p, 2)));
      long _2_scale;
      _2_scale = __default.DecompressionScale(d);
      long _3_product;
      _3_product = (long) (long) ((((long) (_1_dividend))) * (_2_scale));
      r = ((int) ((long) dafny.Helpers.bv64ShiftRight((_3_product), ((byte) (24)))));
    }
    return r;
  }
  public static long GroupValue(int[] f, int d, int g)
  {
    int _0_k = (int) ((g) * (__default.GroupWords(d)));
    if ((d) == (1)) {
      return (long) (long) (((long) (long) (((long) (long) (((long) (long) (((long) (long) (((long) (long) (((long) (long) ((((long) ((f)[(_0_k)]))) + ((long) (long) (((long) 2L) * (((long) ((f)[((int) ((_0_k) + (1)))]))))))) + ((long) (long) (((long) 4L) * (((long) ((f)[((int) ((_0_k) + (2)))]))))))) + ((long) (long) (((long) 8L) * (((long) ((f)[((int) ((_0_k) + (3)))]))))))) + ((long) (long) (((long) 16L) * (((long) ((f)[((int) ((_0_k) + (4)))]))))))) + ((long) (long) (((long) 32L) * (((long) ((f)[((int) ((_0_k) + (5)))]))))))) + ((long) (long) (((long) 64L) * (((long) ((f)[((int) ((_0_k) + (6)))]))))))) + ((long) (long) (((long) 128L) * (((long) ((f)[((int) ((_0_k) + (7)))]))))));
    } else if ((d) == (4)) {
      return (long) (long) ((((long) ((f)[(_0_k)]))) + ((long) (long) (((long) 16L) * (((long) ((f)[((int) ((_0_k) + (1)))]))))));
    } else if ((d) == (10)) {
      return (long) (long) (((long) (long) (((long) (long) ((((long) ((f)[(_0_k)]))) + ((long) (long) (((long) 1024L) * (((long) ((f)[((int) ((_0_k) + (1)))]))))))) + ((long) (long) (((long) 1048576L) * (((long) ((f)[((int) ((_0_k) + (2)))]))))))) + ((long) (long) (((long) 1073741824L) * (((long) ((f)[((int) ((_0_k) + (3)))]))))));
    } else {
      return (long) (long) ((((long) ((f)[(_0_k)]))) + ((long) (long) (((long) 4096L) * (((long) ((f)[((int) ((_0_k) + (1)))]))))));
    }
  }
  public static byte EncodeTenByte(int a, int b, int c, int d, int at)
  {
    return ((byte) (((java.lang.Integer.signum((at)) == 0) ? (__default.Extract(((long) (a)), 0, 8)) : ((((at) == (1)) ? ((int) ((__default.Shift(((long) (a)), 8)) + ((int) ((4) * (__default.Extract(((long) (b)), 0, 6)))))) : ((((at) == (2)) ? ((int) ((__default.Shift(((long) (b)), 6)) + ((int) ((16) * (__default.Extract(((long) (c)), 0, 4)))))) : ((((at) == (3)) ? ((int) ((__default.Shift(((long) (c)), 4)) + ((int) ((64) * (__default.Extract(((long) (d)), 0, 2)))))) : (__default.Shift(((long) (d)), 2)))))))))));
  }
  public static byte EncodeTwelveByte(int a, int b, int at)
  {
    return ((byte) (((java.lang.Integer.signum((at)) == 0) ? (__default.Extract(((long) (a)), 0, 8)) : ((((at) == (1)) ? ((int) ((__default.Shift(((long) (a)), 8)) + ((int) ((16) * (__default.Extract(((long) (b)), 0, 4)))))) : (__default.Shift(((long) (b)), 4)))))));
  }
  public static int DecodeTenWord(int a, int b, int c, int d, int e, int at)
  {
    if (java.lang.Integer.signum((at)) == 0) {
      return (int) ((a) + ((int) ((256) * (__default.Extract(((long) (b)), 0, 2)))));
    } else if ((at) == (1)) {
      return (int) ((__default.Shift(((long) (b)), 2)) + ((int) ((64) * (__default.Extract(((long) (c)), 0, 4)))));
    } else if ((at) == (2)) {
      return (int) ((__default.Shift(((long) (c)), 4)) + ((int) ((16) * (__default.Extract(((long) (d)), 0, 6)))));
    } else {
      return (int) ((__default.Shift(((long) (d)), 6)) + ((int) ((4) * (e))));
    }
  }
  public static int DecodeTwelveWord(int a, int b, int c, int at)
  {
    if (java.lang.Integer.signum((at)) == 0) {
      return (int) ((a) + ((int) ((256) * (__default.Extract(((long) (b)), 0, 4)))));
    } else {
      return (int) ((__default.Shift(((long) (b)), 4)) + ((int) ((16) * (c))));
    }
  }
  public static byte EncodedByte(int[] f, int d, int i)
  {
    int _0_group = __default.PublicDiv(i, __default.GroupBytes(d));
    int _1_at = __default.PublicMod(i, __default.GroupBytes(d));
    int _2_k = (int) ((_0_group) * (__default.GroupWords(d)));
    if (((d) == (1)) || ((d) == (4))) {
      return ((byte) (__default.GroupValue(f, d, _0_group)));
    } else if ((d) == (10)) {
      return __default.EncodeTenByte((f)[(_2_k)], (f)[((int) ((_2_k) + (1)))], (f)[((int) ((_2_k) + (2)))], (f)[((int) ((_2_k) + (3)))], _1_at);
    } else {
      return __default.EncodeTwelveByte((f)[(_2_k)], (f)[((int) ((_2_k) + (1)))], _1_at);
    }
  }
  public static byte[] Encode(int[] f, int d)
  {
    byte[] b = new byte[0];
    if(true) {
      byte[] _nw0 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked(((int) ((32) * (d))), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      b = _nw0;
      int _hi0 = (int) ((32) * (d));
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        (b)[dafny.Helpers.toInt((_0_i))] = __default.EncodedByte(f, d, _0_i);
      }
    }
    return b;
  }
  public static long ByteGroup(byte[] b, int d, int g)
  {
    int _0_k = (int) ((g) * (__default.GroupBytes(d)));
    if ((d) == (10)) {
      return (long) (long) (((long) (long) (((long) (long) (((long) (long) (((long) java.lang.Byte.toUnsignedLong((b)[(_0_k)])) + ((long) (long) (((long) 256L) * ((long) java.lang.Byte.toUnsignedLong((b)[((int) ((_0_k) + (1)))])))))) + ((long) (long) (((long) 65536L) * ((long) java.lang.Byte.toUnsignedLong((b)[((int) ((_0_k) + (2)))])))))) + ((long) (long) (((long) 16777216L) * ((long) java.lang.Byte.toUnsignedLong((b)[((int) ((_0_k) + (3)))])))))) + ((long) (long) (((long) 4294967296L) * ((long) java.lang.Byte.toUnsignedLong((b)[((int) ((_0_k) + (4)))])))));
    } else if ((d) == (12)) {
      return (long) (long) (((long) (long) (((long) java.lang.Byte.toUnsignedLong((b)[(_0_k)])) + ((long) (long) (((long) 256L) * ((long) java.lang.Byte.toUnsignedLong((b)[((int) ((_0_k) + (1)))])))))) + ((long) (long) (((long) 65536L) * ((long) java.lang.Byte.toUnsignedLong((b)[((int) ((_0_k) + (2)))])))));
    } else {
      return (long) java.lang.Byte.toUnsignedLong((b)[(_0_k)]);
    }
  }
  public static int DecodedWord(byte[] b, int d, int i)
  {
    int _0_group = __default.PublicDiv(i, __default.GroupWords(d));
    int _1_at = __default.PublicMod(i, __default.GroupWords(d));
    int _2_k = (int) ((_0_group) * (__default.GroupBytes(d)));
    if (((d) == (1)) || ((d) == (4))) {
      return __default.Extract((long) java.lang.Byte.toUnsignedLong((b)[(_2_k)]), (int) ((d) * (_1_at)), d);
    } else if ((d) == (10)) {
      return __default.DecodeTenWord(java.lang.Byte.toUnsignedInt((b)[(_2_k)]), java.lang.Byte.toUnsignedInt((b)[((int) ((_2_k) + (1)))]), java.lang.Byte.toUnsignedInt((b)[((int) ((_2_k) + (2)))]), java.lang.Byte.toUnsignedInt((b)[((int) ((_2_k) + (3)))]), java.lang.Byte.toUnsignedInt((b)[((int) ((_2_k) + (4)))]), _1_at);
    } else {
      return __default.DecodeTwelveWord(java.lang.Byte.toUnsignedInt((b)[(_2_k)]), java.lang.Byte.toUnsignedInt((b)[((int) ((_2_k) + (1)))]), java.lang.Byte.toUnsignedInt((b)[((int) ((_2_k) + (2)))]), _1_at);
    }
  }
  public static boolean IsCanonical(int[] a)
  {
    boolean ok = false;
    int _hi0 = 256;
    for (int _0_i = 0; _0_i < _hi0; _0_i++) {
      if ((java.lang.Integer.signum(((a)[(_0_i)])) == -1) || (((a)[(_0_i)]) >= (3329))) {
        ok = false;
        return ok;
      }
    }
    ok = true;
    return ok;
  }
  public static DecodeResult Decode(byte[] b, int d)
  {
    DecodeResult r = DecodeResult.Default();
    if (!(__default.Width(d))) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult.create_InvalidWidth();
      return r;
    }
    if (((b).length) != ((int) ((32) * (d)))) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult.create_InvalidLength();
      return r;
    }
    int[] _0_a;
    int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
    _0_a = _nw0;
    int _hi0 = 256;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      (_0_a)[dafny.Helpers.toInt((_1_i))] = __default.DecodedWord(b, d, _1_i);
    }
    boolean _2_valid;
    boolean _out0;
    _out0 = __default.IsCanonical(_0_a);
    _2_valid = _out0;
    if (((d) == (12)) && (!(_2_valid))) {
      __default.Wipe(_0_a);
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult.create_ModulusError();
      return r;
    }
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult.create_Decoded(_0_a);
    return r;
  }
  public static byte[] CompressAndEncode(int[] f, int d)
  {
    byte[] b = new byte[0];
    if(true) {
      if ((d) == (12)) {
        byte[] _out0;
        _out0 = __default.Encode(f, d);
        b = _out0;
        return b;
      }
      int[] _0_a;
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      _0_a = _nw0;
      int _hi0 = 256;
      for (int _1_i = 0; _1_i < _hi0; _1_i++) {
        int _out1;
        _out1 = __default.Compress((f)[(_1_i)], d);
        (_0_a)[dafny.Helpers.toInt((_1_i))] = _out1;
      }
      byte[] _out2;
      _out2 = __default.Encode(_0_a, d);
      b = _out2;
      __default.Wipe(_0_a);
    }
    return b;
  }
  public static DecodeResult DecodeAndDecompress(byte[] b, int d)
  {
    DecodeResult r = DecodeResult.Default();
    DecodeResult _0_raw;
    DecodeResult _out0;
    _out0 = __default.Decode(b, d);
    _0_raw = _out0;
    if (!((_0_raw).is_Decoded())) {
      r = _0_raw;
      return r;
    }
    if ((d) == (12)) {
      r = _0_raw;
      return r;
    }
    int[] _1_a;
    int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
    _1_a = _nw0;
    int _hi0 = 256;
    for (int _2_i = 0; _2_i < _hi0; _2_i++) {
      int _out1;
      _out1 = __default.Decompress(((_0_raw).dtor_words())[(_2_i)], d);
      (_1_a)[dafny.Helpers.toInt((_2_i))] = _out1;
    }
    __default.Wipe((_0_raw).dtor_words());
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult.create_Decoded(_1_a);
    return r;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec._default";
  }
}
