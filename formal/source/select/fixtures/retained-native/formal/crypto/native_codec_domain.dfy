include "NativeCodec.dfy"

module NativeCodecPublicDomain {
  import C = NativeCodec
  import S = CodecSpec
  import V = VerifiedCodec
  import T = NativeTypes
  method WipeAllValues(a: array<T.I>)
    requires T.JavaLength(a.Length)
    modifies a
  {
    C.Wipe(a);
    assert forall i: int :: 0 <= i < a.Length ==> a[i] == 0;
  }
  method Scalars(x: T.I, y: T.I, d: T.I)
    requires 0 <= x < 3329 && 1 <= d <= 11 && 0 <= y as int < S.Pow2(d as int)
  {
    var c := C.Compress(x,d);
    assert c as int == S.Compress(x as int,d as int);
    var e := C.Decompress(y,d);
    assert e as int == S.Decompress(y as int,d as int);
    V.CompressionError(x as int,d as int);
  }
  method Lossless(f: array<T.I>, d: T.I)
    requires S.Words(T.Ints(f),d as int)
  {
    ghost var before := T.Ints(f);
    var b := C.Encode(f,d);
    V.RoundTrip(before,d as int);
    var r := C.Decode(b,d);
    assert C.Model(r) == S.Decoded(before);
    assert fresh(b) && fresh(r.words) && T.Ints(f) == before;
  }
  method TotalDecode(b: array<bv8>, d: T.I)
    requires T.JavaLength(b.Length)
  {
    ghost var before := T.Bytes(b);
    var r := C.Decode(b,d);
    assert C.Model(r) == S.Decode(before,d as int);
    if !S.Width(d as int) { assert r.InvalidWidth?; }
    else if b.Length != 32*(d as int) { assert r.InvalidLength?; }
    var e := C.DecodeAndDecompress(b,d);
    assert e.Decoded? ==> T.Canonical(e.words) && fresh(e.words);
    assert T.Bytes(b) == before;
  }
  method Compressed(f: array<T.I>, d: T.I)
    requires T.Canonical(f) && S.Width(d as int)
  {
    ghost var before := T.Ints(f);
    var b := C.CompressAndEncode(f,d);
    V.RoundTrip(S.CompressedWords(before,d as int),d as int);
    var r := C.DecodeAndDecompress(b,d);
    assert C.Model(r) == S.Decoded(S.ExpandedWords(S.CompressedWords(before,d as int),d as int));
    assert fresh(b) && fresh(r.words) && T.Ints(f) == before;
  }
}
