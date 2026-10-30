include "Codec.dfy"

module CodecPublicDomain {
  import C = VerifiedCodec
  import S = CodecSpec

  method Scalars(x: int, y: int, d: int)
    requires 0 <= x < 3329 && 1 <= d <= 11 && 0 <= y < S.Pow2(d)
  {
    var c := C.Compress(x,d);
    assert c == ((2*S.Pow2(d)*x+3329)/6658)%S.Pow2(d);
    var e := C.Decompress(y,d);
    assert e == (3329*y+S.Pow2(d)/2)/S.Pow2(d);
    C.CompressionError(x,d);
  }
  method Lossless(f: seq<int>, d: int)
    requires S.Words(f,d)
  {
    var b := C.Encode(f,d);
    C.RoundTrip(f,d);
    var r := C.Decode(b,d);
    assert r == S.Decoded(f);
  }
  method CanonicalRoundTrip12(f: seq<int>)
    requires |f| == 256 && forall i | 0 <= i < 256 :: 0 <= f[i] < 3329
  { Lossless(f,12); }
  method TotalDecode(b: seq<bv8>, d: int)
  {
    var r := C.Decode(b,d);
    assert r == S.Decode(b,d);
    if !S.Width(d) { assert r.InvalidWidth?; }
    else if |b| != 32*d { assert r.InvalidLength?; }
    var e := C.DecodeAndDecompress(b,d);
    assert e.Decoded? ==> S.Canonical(e.words);
  }
  method Compressed(f: seq<int>, d: int)
    requires S.Canonical(f) && S.Width(d)
  {
    var b := C.CompressAndEncode(f,d);
    C.RoundTrip(S.CompressedWords(f,d),d);
    var r := C.DecodeAndDecompress(b,d);
    assert r == S.Decoded(S.ExpandedWords(S.CompressedWords(f,d),d));
  }
}
