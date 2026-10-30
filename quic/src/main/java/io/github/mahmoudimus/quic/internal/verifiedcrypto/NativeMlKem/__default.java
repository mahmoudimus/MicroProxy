// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem;

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

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static void WipeBytes(byte[] a)
  {
    int _0_n;
    _0_n = (a).length;
    int _hi0 = _0_n;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      (a)[dafny.Helpers.toInt((_1_i))] = (byte) 0;
    }
  }
  public static void WipeInts(int[] a)
  {
    int _0_n;
    _0_n = (a).length;
    int _hi0 = _0_n;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      (a)[dafny.Helpers.toInt((_1_i))] = 0;
    }
  }
  public static void WipePolys(int[][] a)
  {
    int _0_n;
    _0_n = (a).length;
    int _hi0 = _0_n;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      __default.WipeInts((a)[(_1_i)]);
    }
  }
  public static byte[] Slice(byte[] a, int start, int length)
  {
    byte[] b = new byte[0];
    if(true) {
      byte[] _nw0 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked((length), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      b = _nw0;
      int _hi0 = length;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        (b)[dafny.Helpers.toInt((_0_i))] = (a)[(dafny.Helpers.toInt((long) (long) ((((long) (start))) + (((long) (_0_i))))))];
      }
    }
    return b;
  }
  public static byte[] Join(byte[] a, byte[] b)
  {
    byte[] c = new byte[0];
    if(true) {
      int _0_n;
      _0_n = (a).length;
      int _1_m;
      _1_m = (b).length;
      byte[] _nw0 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked(((int) ((_0_n) + (_1_m))), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      c = _nw0;
      int _hi0 = _0_n;
      for (int _2_i = 0; _2_i < _hi0; _2_i++) {
        (c)[dafny.Helpers.toInt((_2_i))] = (a)[(_2_i)];
      }
      int _hi1 = _1_m;
      for (int _3_i = 0; _3_i < _hi1; _3_i++) {
        int _index0 = (int) ((_0_n) + (_3_i));
        (c)[dafny.Helpers.toInt(_index0)] = (b)[(_3_i)];
      }
    }
    return c;
  }
  public static byte[] Tag(byte[] a, byte tag)
  {
    byte[] b = new byte[0];
    if(true) {
      int _0_n;
      _0_n = (a).length;
      byte[] _nw0 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked(((int) ((_0_n) + (1))), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      b = _nw0;
      int _hi0 = _0_n;
      for (int _1_i = 0; _1_i < _hi0; _1_i++) {
        (b)[dafny.Helpers.toInt((_1_i))] = (a)[(_1_i)];
      }
      (b)[dafny.Helpers.toInt((_0_n))] = tag;
    }
    return b;
  }
  public static byte[] Select(byte[] c, byte[] expected, byte[] candidate, byte[] fallback)
  {
    byte[] r = new byte[0];
    if(true) {
      byte _0_diff;
      _0_diff = (byte) 0;
      int _hi0 = 1088;
      for (int _1_i = 0; _1_i < _hi0; _1_i++) {
        _0_diff = (byte) (byte) ((byte)((_0_diff) | ((byte) (byte) ((byte)(((c)[(_1_i)]) ^ ((expected)[(_1_i)]))))));
      }
      byte _2_mask;
      _2_mask = ((byte) ((long) dafny.Helpers.bv64ShiftRight((long) (long) (((long) (long) (((long) java.lang.Byte.toUnsignedLong(_0_diff)) - ((long) 1L)))), (byte) 56)));
      byte[] _nw0 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked((32), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      r = _nw0;
      int _hi1 = 32;
      for (int _3_i = 0; _3_i < _hi1; _3_i++) {
        (r)[dafny.Helpers.toInt((_3_i))] = (byte) (byte) ((byte)(((byte) (byte) ((byte)(((candidate)[(_3_i)]) & (_2_mask)))) | ((byte) (byte) ((byte)(((fallback)[(_3_i)]) & ((byte) (byte) (((byte) ~(_2_mask)))))))));
      }
    }
    return r;
  }
  public static void CopyInto(byte[] a, byte[] b, int start)
  {
    int _0_n;
    _0_n = (a).length;
    int _hi0 = _0_n;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      int _index0 = (int) ((start) + (_1_i));
      (b)[dafny.Helpers.toInt(_index0)] = (a)[(_1_i)];
    }
  }
  public static int[] Noise(byte[] seed, int nonce)
  {
    int[] r = new int[0];
    if(true) {
      byte[] _0_input;
      byte[] _out0;
      _out0 = __default.Tag(seed, ((byte) (nonce)));
      _0_input = _out0;
      byte[] _1_bytes;
      byte[] _out1;
      _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.__default.Xof(136, _0_input, 128);
      _1_bytes = _out1;
      int[] _out2;
      _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.__default.Cbd2(_1_bytes);
      r = _out2;
      __default.WipeBytes(_0_input);
      __default.WipeBytes(_1_bytes);
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[]> SamplePrefix(byte[] bytes)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[]> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[]>Default(dafny.TypeDescriptor.INT_ARRAY);
    int[] _0_empty;
    int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((0), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
    _0_empty = _nw0;
    io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.FeedResult _1_sample;
    io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.FeedResult _out0;
    _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.__default.Feed(_0_empty, bytes);
    _1_sample = _out0;
    if ((_1_sample).is_Full()) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[]>create_Success(dafny.TypeDescriptor.INT_ARRAY, (_1_sample).dtor_coeffs());
      return r;
    }
    __default.WipeInts((_1_sample).dtor_coeffs());
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[]>create_Failure(dafny.TypeDescriptor.INT_ARRAY, io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_RejectionLimit());
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[]> Sample(byte[] rho, int i, int j)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[]> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[]>Default(dafny.TypeDescriptor.INT_ARRAY);
    if(true) {
      byte[] _0_first;
      byte[] _out0;
      _out0 = __default.Tag(rho, ((byte) (j)));
      _0_first = _out0;
      byte[] _1_input;
      byte[] _out1;
      _out1 = __default.Tag(_0_first, ((byte) (i)));
      _1_input = _out1;
      byte[] _2_bytes;
      byte[] _out2;
      _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.__default.Xof(168, _1_input, 840);
      _2_bytes = _out2;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[]> _out3;
      _out3 = __default.SamplePrefix(_2_bytes);
      r = _out3;
      __default.WipeBytes(_0_first);
      __default.WipeBytes(_1_input);
      __default.WipeBytes(_2_bytes);
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> ExpandMatrix(byte[] rho)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[][]>Default(((dafny.TypeDescriptor<int[][]>)(dafny.TypeDescriptor.INT_ARRAY).arrayType()));
    int[] _0_empty;
    int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((0), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
    _0_empty = _nw0;
    int[][] _1_a;
    java.util.function.Function<java.math.BigInteger, int[]> _init0 = ((java.util.function.Function<int[], java.util.function.Function<java.math.BigInteger, int[]>>)(_2_empty) -> ((java.util.function.Function<java.math.BigInteger, int[]>)(_3_i_boxed0) -> {
      java.math.BigInteger _3_i = ((java.math.BigInteger)(java.lang.Object)(_3_i_boxed0));
      return _2_empty;
    })).apply(_0_empty);
    int[][] _nw1 = (int[][]) dafny.TypeDescriptor.INT_ARRAY.newArray(dafny.Helpers.toIntChecked((9), "Java arrays may be no larger than the maximum 32-bit signed int"));
    for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw1))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
      _nw1[dafny.Helpers.toInt(_i0_0)] = ((int[])(java.lang.Object)(_init0.apply(_i0_0)));
    }
    _1_a = _nw1;
    int _hi0 = 9;
    for (int _4_k = 0; _4_k < _hi0; _4_k++) {
      io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[]> _5_sample;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[]> _out0;
      _out0 = __default.Sample(rho, dafny.DafnyEuclidean.EuclideanDivision(_4_k, 3), dafny.DafnyEuclidean.EuclideanModulus(_4_k, 3));
      _5_sample = _out0;
      if ((_5_sample).is_Failure()) {
        __default.WipePolys(_1_a);
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[][]>create_Failure(((dafny.TypeDescriptor<int[][]>)(dafny.TypeDescriptor.INT_ARRAY).arrayType()), io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_RejectionLimit());
        return r;
      }
      (_1_a)[dafny.Helpers.toInt((_4_k))] = (_5_sample).dtor_value();
    }
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[][]>create_Success(((dafny.TypeDescriptor<int[][]>)(dafny.TypeDescriptor.INT_ARRAY).arrayType()), _1_a);
    return r;
  }
  public static int[] Expand(byte[] bytes, int d)
  {
    int[] f = new int[0];
    if(true) {
      io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult _0_decoded;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult _out0;
      _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.DecodeAndDecompress(bytes, d);
      _0_decoded = _out0;
      f = (_0_decoded).dtor_words();
    }
    return f;
  }
  public static byte[] EncodeVector(int[][] a, int d)
  {
    byte[] r = new byte[0];
    if(true) {
      byte[] _nw0 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked(((int) ((96) * (d))), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      r = _nw0;
      int _hi0 = 3;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        byte[] _1_bytes;
        byte[] _out0;
        _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.CompressAndEncode((a)[(_0_i)], d);
        _1_bytes = _out0;
        __default.CopyInto(_1_bytes, r, (int) (((int) ((_0_i) * (32))) * (d)));
        __default.WipeBytes(_1_bytes);
      }
    }
    return r;
  }
  public static int[][] NoiseVector(byte[] seed, int start, boolean ntt)
  {
    int[][] a = new int[0][];
    if(true) {
      int[] _0_empty;
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((0), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      _0_empty = _nw0;
      java.util.function.Function<java.math.BigInteger, int[]> _init0 = ((java.util.function.Function<int[], java.util.function.Function<java.math.BigInteger, int[]>>)(_1_empty) -> ((java.util.function.Function<java.math.BigInteger, int[]>)(_2_i_boxed0) -> {
        java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
        return _1_empty;
      })).apply(_0_empty);
      int[][] _nw1 = (int[][]) dafny.TypeDescriptor.INT_ARRAY.newArray(dafny.Helpers.toIntChecked((3), "Java arrays may be no larger than the maximum 32-bit signed int"));
      for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw1))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
        _nw1[dafny.Helpers.toInt(_i0_0)] = ((int[])(java.lang.Object)(_init0.apply(_i0_0)));
      }
      a = _nw1;
      int _hi0 = 3;
      for (int _3_i = 0; _3_i < _hi0; _3_i++) {
        int[] _4_f;
        int[] _out0;
        _out0 = __default.Noise(seed, (int) ((start) + (_3_i)));
        _4_f = _out0;
        if (ntt) {
          int[] _5_transformed;
          int[] _out1;
          _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.Ntt(_4_f);
          _5_transformed = _out1;
          __default.WipeInts(_4_f);
          _4_f = _5_transformed;
        }
        (a)[dafny.Helpers.toInt((_3_i))] = _4_f;
      }
    }
    return a;
  }
  public static int[][] Row(int[][] a, int i, boolean transposed)
  {
    int[][] r = new int[0][];
    if(true) {
      int[] _0_first;
      _0_first = (a)[(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))];
      java.util.function.Function<java.math.BigInteger, int[]> _init0 = ((java.util.function.Function<int[], java.util.function.Function<java.math.BigInteger, int[]>>)(_1_first) -> ((java.util.function.Function<java.math.BigInteger, int[]>)(_2_j_boxed0) -> {
        java.math.BigInteger _2_j = ((java.math.BigInteger)(java.lang.Object)(_2_j_boxed0));
        return _1_first;
      })).apply(_0_first);
      int[][] _nw0 = (int[][]) dafny.TypeDescriptor.INT_ARRAY.newArray(dafny.Helpers.toIntChecked((3), "Java arrays may be no larger than the maximum 32-bit signed int"));
      for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw0))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
        _nw0[dafny.Helpers.toInt(_i0_0)] = ((int[])(java.lang.Object)(_init0.apply(_i0_0)));
      }
      r = _nw0;
      int _hi0 = 3;
      for (int _3_j = 0; _3_j < _hi0; _3_j++) {
        (r)[dafny.Helpers.toInt((_3_j))] = (a)[(((transposed) ? ((int) (((int) ((3) * (_3_j))) + (i))) : ((int) (((int) ((3) * (i))) + (_3_j)))))];
      }
    }
    return r;
  }
  public static void CopyInts(int[] a, int[] b)
  {
    int _0_n;
    _0_n = (a).length;
    int _hi0 = _0_n;
    for (int _1_i = 0; _1_i < _hi0; _1_i++) {
      (b)[dafny.Helpers.toInt((_1_i))] = (a)[(_1_i)];
    }
  }
  public static int[] DotStep(int[] accumulator, int[] a, int[] b)
  {
    int[] r = new int[0];
    if(true) {
      int[] _0_term;
      int[] _out0;
      _out0 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.NttMul(a, b);
      _0_term = _out0;
      int[] _out1;
      _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.Add(accumulator, _0_term);
      r = _out1;
      __default.WipeInts(_0_term);
    }
    return r;
  }
  public static int[] Dot(int[][] a, int[][] b)
  {
    int[] r = new int[0];
    if(true) {
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((256), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      r = _nw0;
      int _hi0 = 256;
      for (int _0_i = 0; _0_i < _hi0; _0_i++) {
        (r)[dafny.Helpers.toInt((_0_i))] = 0;
      }
      int _hi1 = 3;
      for (int _1_i = 0; _1_i < _hi1; _1_i++) {
        int[] _2_next;
        int[] _out0;
        _out0 = __default.DotStep(r, (a)[(_1_i)], (b)[(_1_i)]);
        _2_next = _out0;
        __default.CopyInts(_2_next, r);
        __default.WipeInts(_2_next);
      }
    }
    return r;
  }
  public static int[] RowProduct(int[][] a, int[][] b, int[] e, int i, boolean transposed, boolean inverse)
  {
    int[] r = new int[0];
    if(true) {
      int[][] _0_row;
      int[][] _out0;
      _out0 = __default.Row(a, i, transposed);
      _0_row = _out0;
      int[] _1_product;
      int[] _out1;
      _out1 = __default.Dot(_0_row, b);
      _1_product = _out1;
      if (inverse) {
        int[] _2_transformed;
        int[] _out2;
        _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.InverseNtt(_1_product);
        _2_transformed = _out2;
        __default.WipeInts(_1_product);
        _1_product = _2_transformed;
      }
      int[] _out3;
      _out3 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.Add(_1_product, e);
      r = _out3;
      __default.WipeInts(_1_product);
    }
    return r;
  }
  public static int[][] MatrixProduct(int[][] a, int[][] b, int[][] e, boolean transposed, boolean inverse)
  {
    int[][] r = new int[0][];
    if(true) {
      int[] _0_empty;
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((0), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      _0_empty = _nw0;
      java.util.function.Function<java.math.BigInteger, int[]> _init0 = ((java.util.function.Function<int[], java.util.function.Function<java.math.BigInteger, int[]>>)(_1_empty) -> ((java.util.function.Function<java.math.BigInteger, int[]>)(_2_i_boxed0) -> {
        java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
        return _1_empty;
      })).apply(_0_empty);
      int[][] _nw1 = (int[][]) dafny.TypeDescriptor.INT_ARRAY.newArray(dafny.Helpers.toIntChecked((3), "Java arrays may be no larger than the maximum 32-bit signed int"));
      for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw1))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
        _nw1[dafny.Helpers.toInt(_i0_0)] = ((int[])(java.lang.Object)(_init0.apply(_i0_0)));
      }
      r = _nw1;
      int _hi0 = 3;
      for (int _3_i = 0; _3_i < _hi0; _3_i++) {
        int[] _out0;
        _out0 = __default.RowProduct(a, b, (e)[(_3_i)], _3_i, transposed, inverse);
        (r)[dafny.Helpers.toInt((_3_i))] = _out0;
      }
    }
    return r;
  }
  public static dafny.Tuple2 KeyMaterial(int[][] a, byte[] sigma)
  {
    int[][] secret = new int[0][];
    int[][] t = new int[0][];
    if(true) {
      int[][] _out0;
      _out0 = __default.NoiseVector(sigma, 0, true);
      secret = _out0;
      int[][] _0_error;
      int[][] _out1;
      _out1 = __default.NoiseVector(sigma, 3, true);
      _0_error = _out1;
      int[][] _out2;
      _out2 = __default.MatrixProduct(a, secret, _0_error, false, false);
      t = _out2;
      __default.WipePolys(_0_error);
    }
    return new dafny.Tuple2<>(secret, t);
  }
  public static dafny.Tuple2 EncodePublic(int[][] t, byte[] rho)
  {
    byte[] encoded = new byte[0];
    byte[] hash = new byte[0];
    if(true) {
      byte[] _0_prefix;
      byte[] _out0;
      _out0 = __default.EncodeVector(t, 12);
      _0_prefix = _out0;
      byte[] _out1;
      _out1 = __default.Join(_0_prefix, rho);
      encoded = _out1;
      __default.WipeBytes(_0_prefix);
      byte[] _out2;
      _out2 = io.github.mahmoudimus.verifiedcrypto.native_kem_hash.sha3_256(encoded);
      hash = _out2;
    }
    return new dafny.Tuple2<>(encoded, hash);
  }
  public static SecretKey AssembleKey(byte[] retained, int[][] secret, int[][] a, int[][] t, byte[] rho, byte[] encoded, byte[] hash)
  {
    SecretKey dk = null;
    if(true) {
      PublicKey _0_ek;
      PublicKey _nw0 = new PublicKey();
      _nw0.__ctor(a, t, rho, encoded, hash);
      _0_ek = _nw0;
      SecretKey _nw1 = new SecretKey();
      _nw1.__ctor(retained, secret, _0_ek);
      dk = _nw1;
    }
    return dk;
  }
  public static SecretKey BuildKey(byte[] seed, int[][] a, byte[] rho, byte[] sigma)
  {
    SecretKey dk = null;
    if(true) {
      int[][] _0_secret;
      int[][] _1_t;
      int[][] _out0;
      int[][] _out1;
      dafny.Tuple2<int[][], int[][]> _outcollector0 = __default.KeyMaterial(a, sigma);
      _out0 = (int[][]) (Object) _outcollector0.dtor__0();
      _out1 = (int[][]) (Object) _outcollector0.dtor__1();
      _0_secret = _out0;
      _1_t = _out1;
      byte[] _2_encoded;
      byte[] _3_hash;
      byte[] _out2;
      byte[] _out3;
      dafny.Tuple2<byte[], byte[]> _outcollector1 = __default.EncodePublic(_1_t, rho);
      _out2 = (byte[]) (Object) _outcollector1.dtor__0();
      _out3 = (byte[]) (Object) _outcollector1.dtor__1();
      _2_encoded = _out2;
      _3_hash = _out3;
      byte[] _4_retained;
      byte[] _out4;
      _out4 = __default.Slice(seed, 0, 64);
      _4_retained = _out4;
      SecretKey _out5;
      _out5 = __default.AssembleKey(_4_retained, _0_secret, a, _1_t, rho, _2_encoded, _3_hash);
      dk = _out5;
    }
    return dk;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<SecretKey> KeyGen(byte[] seed)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<SecretKey> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<SecretKey>Default(((dafny.TypeDescriptor<SecretKey>)(java.lang.Object)dafny.TypeDescriptor.reference(SecretKey.class)));
    if (!java.util.Objects.equals(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength((seed))), java.math.BigInteger.valueOf(64L))) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<SecretKey>create_Failure(((dafny.TypeDescriptor<SecretKey>)(java.lang.Object)dafny.TypeDescriptor.reference(SecretKey.class)), io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_InvalidSeedLength());
      return r;
    }
    byte[] _0_d;
    byte[] _out0;
    _out0 = __default.Slice(seed, 0, 32);
    _0_d = _out0;
    byte[] _1_tagged;
    byte[] _out1;
    _out1 = __default.Tag(_0_d, (byte) 3);
    _1_tagged = _out1;
    byte[] _2_g;
    byte[] _out2;
    _out2 = io.github.mahmoudimus.verifiedcrypto.native_kem_hash.sha3_512(_1_tagged);
    _2_g = _out2;
    byte[] _3_rho;
    byte[] _out3;
    _out3 = __default.Slice(_2_g, 0, 32);
    _3_rho = _out3;
    byte[] _4_sigma;
    byte[] _out4;
    _out4 = __default.Slice(_2_g, 32, 32);
    _4_sigma = _out4;
    __default.WipeBytes(_0_d);
    __default.WipeBytes(_1_tagged);
    __default.WipeBytes(_2_g);
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> _5_expanded;
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> _out5;
    _out5 = __default.ExpandMatrix(_3_rho);
    _5_expanded = _out5;
    if ((_5_expanded).is_Failure()) {
      __default.WipeBytes(_3_rho);
      __default.WipeBytes(_4_sigma);
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<SecretKey>create_Failure(((dafny.TypeDescriptor<SecretKey>)(java.lang.Object)dafny.TypeDescriptor.reference(SecretKey.class)), io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_RejectionLimit());
      return r;
    }
    int[][] _6_a;
    _6_a = (_5_expanded).dtor_value();
    SecretKey _7_dk;
    SecretKey _out6;
    _out6 = __default.BuildKey(seed, _6_a, _3_rho, _4_sigma);
    _7_dk = _out6;
    __default.WipeBytePreservingKey(_4_sigma);
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<SecretKey>create_Success(((dafny.TypeDescriptor<SecretKey>)(java.lang.Object)dafny.TypeDescriptor.reference(SecretKey.class)), _7_dk);
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult DecodeKeyPart(byte[] bytes, int i)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult f = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult.Default();
    if(true) {
      byte[] _0_part;
      byte[] _out0;
      _out0 = __default.Slice(bytes, (int) ((384) * (i)), 384);
      _0_part = _out0;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult _out1;
      _out1 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.Decode(_0_part, 12);
      f = _out1;
      __default.WipeBytes(_0_part);
    }
    return f;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> ParseWords(byte[] bytes)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[][]>Default(((dafny.TypeDescriptor<int[][]>)(dafny.TypeDescriptor.INT_ARRAY).arrayType()));
    int[] _0_empty;
    int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((0), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
    _0_empty = _nw0;
    int[][] _1_t;
    java.util.function.Function<java.math.BigInteger, int[]> _init0 = ((java.util.function.Function<int[], java.util.function.Function<java.math.BigInteger, int[]>>)(_2_empty) -> ((java.util.function.Function<java.math.BigInteger, int[]>)(_3_i_boxed0) -> {
      java.math.BigInteger _3_i = ((java.math.BigInteger)(java.lang.Object)(_3_i_boxed0));
      return _2_empty;
    })).apply(_0_empty);
    int[][] _nw1 = (int[][]) dafny.TypeDescriptor.INT_ARRAY.newArray(dafny.Helpers.toIntChecked((3), "Java arrays may be no larger than the maximum 32-bit signed int"));
    for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw1))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
      _nw1[dafny.Helpers.toInt(_i0_0)] = ((int[])(java.lang.Object)(_init0.apply(_i0_0)));
    }
    _1_t = _nw1;
    boolean _4_failed;
    _4_failed = false;
    int _5_i;
    _5_i = 0;
    while (((_5_i) < (3)) && (!(_4_failed))) {
      io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult _6_f;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult _out0;
      _out0 = __default.DecodeKeyPart(bytes, _5_i);
      _6_f = _out0;
      if (!((_6_f).is_Decoded())) {
        _4_failed = true;
      } else {
        (_1_t)[dafny.Helpers.toInt((_5_i))] = (_6_f).dtor_words();
        _5_i = (int) ((_5_i) + (1));
      }
    }
    if (_4_failed) {
      __default.WipePolys(_1_t);
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[][]>create_Failure(((dafny.TypeDescriptor<int[][]>)(dafny.TypeDescriptor.INT_ARRAY).arrayType()), io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_ModulusError());
      return r;
    }
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<int[][]>create_Success(((dafny.TypeDescriptor<int[][]>)(dafny.TypeDescriptor.INT_ARRAY).arrayType()), _1_t);
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<PublicKey> Parse(byte[] bytes)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<PublicKey> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<PublicKey>Default(((dafny.TypeDescriptor<PublicKey>)(java.lang.Object)dafny.TypeDescriptor.reference(PublicKey.class)));
    if (!java.util.Objects.equals(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength((bytes))), java.math.BigInteger.valueOf(1184L))) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<PublicKey>create_Failure(((dafny.TypeDescriptor<PublicKey>)(java.lang.Object)dafny.TypeDescriptor.reference(PublicKey.class)), io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_InvalidKeyLength());
      return r;
    }
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> _0_words;
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> _out0;
    _out0 = __default.ParseWords(bytes);
    _0_words = _out0;
    if ((_0_words).is_Failure()) {
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<PublicKey>create_Failure(((dafny.TypeDescriptor<PublicKey>)(java.lang.Object)dafny.TypeDescriptor.reference(PublicKey.class)), io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_ModulusError());
      return r;
    }
    int[][] _1_t;
    _1_t = (_0_words).dtor_value();
    byte[] _2_rho;
    byte[] _out1;
    _out1 = __default.Slice(bytes, 1152, 32);
    _2_rho = _out1;
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> _3_a;
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<int[][]> _out2;
    _out2 = __default.ExpandMatrix(_2_rho);
    _3_a = _out2;
    if ((_3_a).is_Failure()) {
      __default.WipePolys(_1_t);
      __default.WipeBytes(_2_rho);
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<PublicKey>create_Failure(((dafny.TypeDescriptor<PublicKey>)(java.lang.Object)dafny.TypeDescriptor.reference(PublicKey.class)), io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_RejectionLimit());
      return r;
    }
    byte[] _4_encoded;
    byte[] _out3;
    _out3 = __default.Slice(bytes, 0, 1184);
    _4_encoded = _out3;
    byte[] _5_hash;
    byte[] _out4;
    _out4 = io.github.mahmoudimus.verifiedcrypto.native_kem_hash.sha3_256(bytes);
    _5_hash = _out4;
    PublicKey _6_ek;
    PublicKey _nw0 = new PublicKey();
    _nw0.__ctor((_3_a).dtor_value(), _1_t, _2_rho, _4_encoded, _5_hash);
    _6_ek = _nw0;
    r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<PublicKey>create_Success(((dafny.TypeDescriptor<PublicKey>)(java.lang.Object)dafny.TypeDescriptor.reference(PublicKey.class)), _6_ek);
    return r;
  }
  public static byte[] EncryptU(int[][] a, int[][] y, byte[] coins)
  {
    byte[] c1 = new byte[0];
    if(true) {
      int[][] _0_e1;
      int[][] _out0;
      _out0 = __default.NoiseVector(coins, 3, false);
      _0_e1 = _out0;
      int[][] _1_u;
      int[][] _out1;
      _out1 = __default.MatrixProduct(a, y, _0_e1, true, true);
      _1_u = _out1;
      byte[] _out2;
      _out2 = __default.EncodeVector(_1_u, 10);
      c1 = _out2;
      __default.WipePolys(_0_e1);
      __default.WipePolys(_1_u);
    }
    return c1;
  }
  public static byte[] EncryptV(int[][] t, int[][] y, byte[] m, byte[] coins)
  {
    byte[] c2 = new byte[0];
    if(true) {
      int[] _0_e2;
      int[] _out0;
      _out0 = __default.Noise(coins, 6);
      _0_e2 = _out0;
      int[] _1_mu;
      int[] _out1;
      _out1 = __default.Expand(m, 1);
      _1_mu = _out1;
      int[] _2_product;
      int[] _out2;
      _out2 = __default.Dot(t, y);
      _2_product = _out2;
      int[] _3_inverse;
      int[] _out3;
      _out3 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.InverseNtt(_2_product);
      _3_inverse = _out3;
      int[] _4_noisy;
      int[] _out4;
      _out4 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.Add(_3_inverse, _0_e2);
      _4_noisy = _out4;
      int[] _5_v;
      int[] _out5;
      _out5 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.Add(_4_noisy, _1_mu);
      _5_v = _out5;
      byte[] _out6;
      _out6 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.CompressAndEncode(_5_v, 4);
      c2 = _out6;
      __default.WipeInts(_0_e2);
      __default.WipeInts(_1_mu);
      __default.WipeInts(_2_product);
      __default.WipeInts(_3_inverse);
      __default.WipeInts(_4_noisy);
      __default.WipeInts(_5_v);
    }
    return c2;
  }
  public static byte[] Encrypt(PublicKey ek, byte[] m, byte[] coins)
  {
    byte[] ciphertext = new byte[0];
    if(true) {
      int[][] _0_y;
      int[][] _out0;
      _out0 = __default.NoiseVector(coins, 0, true);
      _0_y = _out0;
      byte[] _1_c1;
      byte[] _out1;
      _out1 = __default.EncryptU((ek).matrix(), _0_y, coins);
      _1_c1 = _out1;
      byte[] _2_c2;
      byte[] _out2;
      _out2 = __default.EncryptV((ek).t(), _0_y, m, coins);
      _2_c2 = _out2;
      byte[] _out3;
      _out3 = __default.Join(_1_c1, _2_c2);
      ciphertext = _out3;
      __default.WipePolys(_0_y);
      __default.WipeBytes(_1_c1);
      __default.WipeBytes(_2_c2);
    }
    return ciphertext;
  }
  public static int[] CipherPart(byte[] c, int i)
  {
    int[] r = new int[0];
    if(true) {
      byte[] _0_part;
      byte[] _out0;
      _out0 = __default.Slice(c, (int) ((320) * (i)), 320);
      _0_part = _out0;
      int[] _1_f;
      int[] _out1;
      _out1 = __default.Expand(_0_part, 10);
      _1_f = _out1;
      int[] _out2;
      _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.Ntt(_1_f);
      r = _out2;
      __default.WipeBytes(_0_part);
      __default.WipeInts(_1_f);
    }
    return r;
  }
  public static int[][] DecodeCipherU(byte[] c)
  {
    int[][] u = new int[0][];
    if(true) {
      int[] _0_empty;
      int[] _nw0 = (int[]) io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().fillThenReturnArray(io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I._typeDescriptor().newArray(dafny.Helpers.toIntChecked((0), "Java arrays may be no larger than the maximum 32-bit signed int")), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.I.Witness);
      _0_empty = _nw0;
      java.util.function.Function<java.math.BigInteger, int[]> _init0 = ((java.util.function.Function<int[], java.util.function.Function<java.math.BigInteger, int[]>>)(_1_empty) -> ((java.util.function.Function<java.math.BigInteger, int[]>)(_2_i_boxed0) -> {
        java.math.BigInteger _2_i = ((java.math.BigInteger)(java.lang.Object)(_2_i_boxed0));
        return _1_empty;
      })).apply(_0_empty);
      int[][] _nw1 = (int[][]) dafny.TypeDescriptor.INT_ARRAY.newArray(dafny.Helpers.toIntChecked((3), "Java arrays may be no larger than the maximum 32-bit signed int"));
      for (java.math.BigInteger _i0_0 = java.math.BigInteger.ZERO; _i0_0.compareTo(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength(_nw1))) < 0; _i0_0 = _i0_0.add(java.math.BigInteger.ONE)) {
        _nw1[dafny.Helpers.toInt(_i0_0)] = ((int[])(java.lang.Object)(_init0.apply(_i0_0)));
      }
      u = _nw1;
      int _hi0 = 3;
      for (int _3_i = 0; _3_i < _hi0; _3_i++) {
        int[] _out0;
        _out0 = __default.CipherPart(c, _3_i);
        (u)[dafny.Helpers.toInt((_3_i))] = _out0;
      }
    }
    return u;
  }
  public static int[] DecryptMask(int[][] secret, byte[] ciphertext)
  {
    int[] mask = new int[0];
    if(true) {
      int[][] _0_u;
      int[][] _out0;
      _out0 = __default.DecodeCipherU(ciphertext);
      _0_u = _out0;
      int[] _1_product;
      int[] _out1;
      _out1 = __default.Dot(secret, _0_u);
      _1_product = _out1;
      int[] _out2;
      _out2 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.InverseNtt(_1_product);
      mask = _out2;
      __default.WipePolys(_0_u);
      __default.WipeInts(_1_product);
    }
    return mask;
  }
  public static byte[] Decrypt(int[][] secret, byte[] ciphertext)
  {
    byte[] m = new byte[0];
    if(true) {
      int[] _0_mask;
      int[] _out0;
      _out0 = __default.DecryptMask(secret, ciphertext);
      _0_mask = _out0;
      byte[] _1_last;
      byte[] _out1;
      _out1 = __default.Slice(ciphertext, 960, 128);
      _1_last = _out1;
      int[] _2_v;
      int[] _out2;
      _out2 = __default.Expand(_1_last, 4);
      _2_v = _out2;
      int[] _3_w;
      int[] _out3;
      _out3 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.__default.Sub(_2_v, _0_mask);
      _3_w = _out3;
      byte[] _out4;
      _out4 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default.CompressAndEncode(_3_w, 1);
      m = _out4;
      __default.WipeInts(_0_mask);
      __default.WipeBytes(_1_last);
      __default.WipeInts(_2_v);
      __default.WipeInts(_3_w);
    }
    return m;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<Encapsulation> Encaps(byte[] bytes, byte[] m)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<Encapsulation> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<Encapsulation>Default(Encapsulation._typeDescriptor());
    if(true) {
      io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<PublicKey> _0_parsed;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<PublicKey> _out0;
      _out0 = __default.Parse(bytes);
      _0_parsed = _out0;
      if ((_0_parsed).is_Failure()) {
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<Encapsulation>create_Failure(Encapsulation._typeDescriptor(), (_0_parsed).dtor_reason());
        return r;
      }
      PublicKey _1_ek;
      _1_ek = (_0_parsed).dtor_value();
      if (!java.util.Objects.equals(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength((m))), java.math.BigInteger.valueOf(32L))) {
        (_1_ek).Destroy();
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<Encapsulation>create_Failure(Encapsulation._typeDescriptor(), io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_InvalidMessageLength());
        return r;
      }
      byte[] _2_input;
      byte[] _out1;
      _out1 = __default.Join(m, (_1_ek).hash());
      _2_input = _out1;
      byte[] _3_g;
      byte[] _out2;
      _out2 = io.github.mahmoudimus.verifiedcrypto.native_kem_hash.sha3_512(_2_input);
      _3_g = _out2;
      byte[] _4_coins;
      byte[] _out3;
      _out3 = __default.Slice(_3_g, 32, 32);
      _4_coins = _out3;
      byte[] _5_ciphertext;
      byte[] _out4;
      _out4 = __default.Encrypt(_1_ek, m, _4_coins);
      _5_ciphertext = _out4;
      byte[] _6_key;
      byte[] _out5;
      _out5 = __default.Slice(_3_g, 0, 32);
      _6_key = _out5;
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<Encapsulation>create_Success(Encapsulation._typeDescriptor(), io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.Encapsulation.create(_6_key, _5_ciphertext));
      (_1_ek).Destroy();
      __default.WipeBytes(_2_input);
      __default.WipeBytes(_3_g);
      __default.WipeBytes(_4_coins);
    }
    return r;
  }
  public static void WipeBytePreservingKey(byte[] a)
  {
    __default.WipeBytes(a);
  }
  public static void WipeDecapsBuffers(byte[] m, byte[] input, byte[] g, byte[] z, byte[] rejectionInput, byte[] fallback, byte[] coins, byte[] expected, byte[] candidate)
  {
    __default.WipeBytes(m);
    __default.WipeBytes(input);
    __default.WipeBytes(g);
    __default.WipeBytes(z);
    __default.WipeBytes(rejectionInput);
    __default.WipeBytes(fallback);
    __default.WipeBytes(coins);
    __default.WipeBytes(expected);
    __default.WipeBytes(candidate);
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<byte[]> Decaps(SecretKey dk, byte[] ciphertext)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<byte[]> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<byte[]>Default(dafny.TypeDescriptor.BYTE_ARRAY);
    if(true) {
      if (!java.util.Objects.equals(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength((ciphertext))), java.math.BigInteger.valueOf(1088L))) {
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<byte[]>create_Failure(dafny.TypeDescriptor.BYTE_ARRAY, io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_InvalidCiphertextLength());
        return r;
      }
      byte[] _0_m;
      byte[] _out0;
      _out0 = __default.Decrypt((dk).s(), ciphertext);
      _0_m = _out0;
      byte[] _1_input;
      byte[] _out1;
      _out1 = __default.Join(_0_m, ((dk).ek()).hash());
      _1_input = _out1;
      byte[] _2_g;
      byte[] _out2;
      _out2 = io.github.mahmoudimus.verifiedcrypto.native_kem_hash.sha3_512(_1_input);
      _2_g = _out2;
      byte[] _3_z;
      byte[] _out3;
      _out3 = __default.Slice((dk).seed(), 32, 32);
      _3_z = _out3;
      byte[] _4_rejectionInput;
      byte[] _out4;
      _out4 = __default.Join(_3_z, ciphertext);
      _4_rejectionInput = _out4;
      byte[] _5_fallback;
      byte[] _out5;
      _out5 = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.__default.Xof(136, _4_rejectionInput, 32);
      _5_fallback = _out5;
      byte[] _6_coins;
      byte[] _out6;
      _out6 = __default.Slice(_2_g, 32, 32);
      _6_coins = _out6;
      byte[] _7_expected;
      byte[] _out7;
      _out7 = __default.Encrypt((dk).ek(), _0_m, _6_coins);
      _7_expected = _out7;
      byte[] _8_candidate;
      byte[] _out8;
      _out8 = __default.Slice(_2_g, 0, 32);
      _8_candidate = _out8;
      byte[] _9_key;
      byte[] _out9;
      _out9 = __default.Select(ciphertext, _7_expected, _8_candidate, _5_fallback);
      _9_key = _out9;
      r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<byte[]>create_Success(dafny.TypeDescriptor.BYTE_ARRAY, _9_key);
      __default.WipeDecapsBuffers(_0_m, _1_input, _2_g, _3_z, _4_rejectionInput, _5_fallback, _6_coins, _7_expected, _8_candidate);
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<byte[]> DecapsAndDestroy(SecretKey dk, byte[] ciphertext)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<byte[]> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<byte[]>Default(dafny.TypeDescriptor.BYTE_ARRAY);
    if(true) {
      io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<byte[]> _out0;
      _out0 = __default.Decaps(dk, ciphertext);
      r = _out0;
      (dk).Destroy();
    }
    return r;
  }
  public static io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<byte[]> DecapsFromSeed(byte[] seed, byte[] ciphertext)
  {
    io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<byte[]> r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<byte[]>Default(dafny.TypeDescriptor.BYTE_ARRAY);
    if(true) {
      if (!java.util.Objects.equals(java.math.BigInteger.valueOf(java.lang.reflect.Array.getLength((ciphertext))), java.math.BigInteger.valueOf(1088L))) {
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<byte[]>create_Failure(dafny.TypeDescriptor.BYTE_ARRAY, io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_InvalidCiphertextLength());
        return r;
      }
      io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<SecretKey> _0_generated;
      io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<SecretKey> _out0;
      _out0 = __default.KeyGen(seed);
      _0_generated = _out0;
      if ((_0_generated).is_Failure()) {
        r = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<byte[]>create_Failure(dafny.TypeDescriptor.BYTE_ARRAY, (_0_generated).dtor_reason());
        return r;
      }
      SecretKey _1_dk;
      _1_dk = (_0_generated).dtor_value();
      io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result<byte[]> _out1;
      _out1 = __default.DecapsAndDestroy(_1_dk, ciphertext);
      r = _out1;
    }
    return r;
  }
  public static byte[] SerializeSecret(SecretKey dk)
  {
    byte[] r = new byte[0];
    if(true) {
      byte[] _0_secret;
      byte[] _out0;
      _out0 = __default.EncodeVector((dk).s(), 12);
      _0_secret = _out0;
      byte[] _1_z;
      byte[] _out1;
      _out1 = __default.Slice((dk).seed(), 32, 32);
      _1_z = _out1;
      byte[] _nw0 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked((2400), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      r = _nw0;
      __default.CopyInto(_0_secret, r, 0);
      __default.CopyInto(((dk).ek()).encoded(), r, 1152);
      __default.CopyInto(((dk).ek()).hash(), r, 2336);
      __default.CopyInto(_1_z, r, 2368);
      __default.WipeBytes(_0_secret);
      __default.WipeBytes(_1_z);
    }
    return r;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem._default";
  }
}
