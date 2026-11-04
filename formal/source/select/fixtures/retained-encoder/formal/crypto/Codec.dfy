// FIPS 203 equations 4.7/4.8 and algorithms 3--6, q=3329, n=256.
// Grouped little-endian formulas follow the existing Go-derived MlKem768.java
// (Go Authors, BSD-3-Clause). Contracts and proofs are new standards-based work.
module CodecSpec {
  const Q: int := 3329
  const N: int := 256

  function Pow2(d: nat): int
    requires d <= 12
    ensures 1 <= Pow2(d) <= 4096
  { [1,2,4,8,16,32,64,128,256,512,1024,2048,4096][d] }

  predicate Width(d: int) { d == 1 || d == 4 || d == 10 || d == 12 }
  predicate Canonical(f: seq<int>) {
    |f| == N && forall i | 0 <= i < N :: 0 <= f[i] < Q
  }
  predicate Words(f: seq<int>, d: int) {
    Width(d) && |f| == N &&
    forall i | 0 <= i < N :: 0 <= f[i] < (if d == 12 then Q else Pow2(d))
  }

  // floor(t+1/2), including upward half ties. Q is odd, so compression
  // itself has no half tie for integral x; decompression does have ties.
  function Compress(x: int, d: int): int
    requires 0 <= x < Q && 1 <= d <= 11
    ensures 0 <= Compress(x,d) < Pow2(d)
  { ((Pow2(d)*x + Q/2)/Q) % Pow2(d) }

  function Decompress(y: int, d: int): int
    requires 1 <= d <= 11 && 0 <= y < Pow2(d)
    ensures 0 <= Decompress(y,d) < Q
  { (Q*y + Pow2(d)/2)/Pow2(d) }

  function GroupWords(d: int): int requires Width(d)
  { if d == 1 then 8 else if d == 10 then 4 else 2 }
  function GroupBytes(d: int): int requires Width(d)
  { if d == 10 then 5 else if d == 12 then 3 else 1 }
  function BytePower(j: nat): int requires j <= 4
  { [1,256,65536,16777216,4294967296][j] }
  function WordPower(d: int, j: nat): int
    requires Width(d) && j < GroupWords(d)
  {
    if d == 1 then [1,2,4,8,16,32,64,128][j]
    else if d == 4 then [1,16][j]
    else if d == 10 then [1,1024,1048576,1073741824][j]
    else [1,4096][j]
  }

  // Each group is sum(f[g*GroupWords+j] * 2^(d*j)); its bytes are
  // floor(group / 2^(8*j)) mod 256. These are the exact little-endian
  // equations of ByteEncode, with no compression hidden in ByteEncode.
  opaque function GroupValue(f: seq<int>, d: int, g: int): int
    requires Words(f,d) && 0 <= g < N/GroupWords(d)
  {
    var k := g*GroupWords(d);
    if d == 1 then f[k]+2*f[k+1]+4*f[k+2]+8*f[k+3]+16*f[k+4]+32*f[k+5]+64*f[k+6]+128*f[k+7]
    else if d == 4 then f[k]+16*f[k+1]
    else if d == 10 then f[k]+1024*f[k+1]+1048576*f[k+2]+1073741824*f[k+3]
    else f[k]+4096*f[k+1]
  }
  opaque function EncodedByte(f: seq<int>, d: int, i: int): bv8
    requires Words(f,d) && 0 <= i < 32*d
    ensures EncodedByte(f,d,i) as int == (GroupValue(f,d,i/GroupBytes(d))/BytePower(i%GroupBytes(d)))%256
  { ((GroupValue(f,d,i/GroupBytes(d))/BytePower(i%GroupBytes(d)))%256) as bv8 }
  opaque function Encoded(f: seq<int>, d: int): seq<bv8>
    requires Words(f,d)
    ensures |Encoded(f,d)| == 32*d
  { seq(32*d, i requires 0 <= i < 32*d => EncodedByte(f,d,i)) }

  opaque function ByteGroup(b: seq<bv8>, d: int, g: int): int
    requires Width(d) && |b| == 32*d && 0 <= g < N/GroupWords(d)
  {
    var k := g*GroupBytes(d);
    if d == 10 then (b[k] as int)+256*(b[k+1] as int)+65536*(b[k+2] as int)+16777216*(b[k+3] as int)+4294967296*(b[k+4] as int)
    else if d == 12 then (b[k] as int)+256*(b[k+1] as int)+65536*(b[k+2] as int)
    else b[k] as int
  }
  opaque function DecodedWord(b: seq<bv8>, d: int, i: int): int
    requires Width(d) && |b| == 32*d && 0 <= i < N
  { (ByteGroup(b,d,i/GroupWords(d))/WordPower(d,i%GroupWords(d)))%Pow2(d) }
  opaque function DecodedWords(b: seq<bv8>, d: int): seq<int>
    requires Width(d) && |b| == 32*d
    ensures |DecodedWords(b,d)| == N
  { seq(N, i requires 0 <= i < N => DecodedWord(b,d,i)) }

  datatype DecodeResult = InvalidWidth | InvalidLength | ModulusError | Decoded(words: seq<int>)
  function Decode(b: seq<bv8>, d: int): DecodeResult
    ensures Decode(b,d).Decoded? ==> Words(Decode(b,d).words,d)
  {
    reveal DecodedWords, DecodedWord;
    if !Width(d) then InvalidWidth
    else if |b| != 32*d then InvalidLength
    else if d == 12 && !Canonical(DecodedWords(b,d)) then ModulusError
    else Decoded(DecodedWords(b,d))
  }

  function CompressedWords(f: seq<int>, d: int): seq<int>
    requires Canonical(f) && Width(d)
    ensures Words(CompressedWords(f,d),d)
  { if d == 12 then f else seq(N, i requires 0 <= i < N => Compress(f[i],d)) }
  function ExpandedWords(f: seq<int>, d: int): seq<int>
    requires Words(f,d)
    ensures Canonical(ExpandedWords(f,d))
  { if d == 12 then f else seq(N, i requires 0 <= i < N => Decompress(f[i],d)) }

  // Circular coefficient distance: compression may round q-1 to zero.
  function Distance(a: int, b: int): int
    requires 0 <= a < Q && 0 <= b < Q
  {
    var e := (a-b)%Q;
    if e <= Q/2 then e else Q-e
  }
  predicate ErrorAtScale(x: int, p: int)
    requires 0 <= x < Q && p > 0
  {
    var c := (p*x+Q/2)/Q;
    var y := c%p;
    var r := (Q*y+p/2)/p;
    var signed := if c == p then r-x+Q else r-x;
    -((Q+p)/(2*p)) <= signed <= (Q+p)/(2*p)
  }
}

module VerifiedCodec {
  import S = CodecSpec

  method Compress(x: int, d: int) returns (r: int)
    requires 0 <= x < S.Q && 1 <= d <= 11
    ensures 0 <= r < S.Pow2(d) && r == S.Compress(x,d)
    ensures r == ((2*S.Pow2(d)*x + S.Q)/(2*S.Q))%S.Pow2(d)
  { r := ((S.Pow2(d)*x + 1664)/3329)%S.Pow2(d); }

  method Decompress(y: int, d: int) returns (r: int)
    requires 1 <= d <= 11 && 0 <= y < S.Pow2(d)
    ensures 0 <= r < S.Q && r == S.Decompress(y,d)
  { r := (3329*y + S.Pow2(d)/2)/S.Pow2(d); }

  method Encode(f: seq<int>, d: int) returns (b: seq<bv8>)
    requires S.Words(f,d)
    ensures |b| == 32*d && b == S.Encoded(f,d)
  {
    reveal S.Encoded;
    var a := new bv8[32*d];
    for i := 0 to 32*d
      invariant forall j | 0 <= j < i :: a[j] == S.EncodedByte(f,d,j)
    { a[i] := S.EncodedByte(f,d,i); }
    b := a[..];
  }

  method Decode(b: seq<bv8>, d: int) returns (r: S.DecodeResult)
    ensures r == S.Decode(b,d)
    ensures r.Decoded? ==> S.Words(r.words,d)
  {
    reveal S.DecodedWords, S.DecodedWord;
    if !S.Width(d) { return S.InvalidWidth; }
    if |b| != 32*d { return S.InvalidLength; }
    var a := new int[S.N];
    for i := 0 to S.N
      invariant forall j | 0 <= j < i :: a[j] == S.DecodedWord(b,d,j)
    { a[i] := S.DecodedWord(b,d,i); }
    var f := a[..];
    assert f == S.DecodedWords(b,d);
    if d == 12 && !S.Canonical(f) { return S.ModulusError; }
    return S.Decoded(f);
  }

  lemma GroupBound(f: seq<int>, d: int, g: int)
    requires S.Words(f,d) && 0 <= g < S.N/S.GroupWords(d)
    ensures 0 <= S.GroupValue(f,d,g) < (if d == 10 then 1099511627776 else if d == 12 then 16777216 else 256)
  {
    reveal S.GroupValue;
    var k := g*S.GroupWords(d);
    if d == 1 {
      assert forall j | k <= j < k+8 :: 0 <= f[j] < 2;
    } else if d == 4 {
      assert forall j | k <= j < k+2 :: 0 <= f[j] < 16;
    } else if d == 10 {
      assert forall j | k <= j < k+4 :: 0 <= f[j] < 1024;
    } else {
      assert forall j | k <= j < k+2 :: 0 <= f[j] < 4096;
    }
  }

  lemma ReconstructBytes(w: int, d: int)
    requires S.Width(d)
    requires 0 <= w < (if d == 10 then 1099511627776 else if d == 12 then 16777216 else 256)
    ensures d == 10 ==> w%256+256*((w/256)%256)+65536*((w/65536)%256)+16777216*((w/16777216)%256)+4294967296*((w/4294967296)%256) == w
    ensures d == 12 ==> w%256+256*((w/256)%256)+65536*((w/65536)%256) == w
    ensures d == 1 || d == 4 ==> w%256 == w
  {
    assert w/65536 == (w/256)/256;
    assert w/16777216 == (w/65536)/256;
    assert w/4294967296 == (w/16777216)/256;
  }

  lemma {:isolate_assertions} GroupRoundTrip(f: seq<int>, d: int, g: int)
    requires S.Words(f,d) && 0 <= g < S.N/S.GroupWords(d)
    ensures S.ByteGroup(S.Encoded(f,d),d,g) == S.GroupValue(f,d,g)
  {
    reveal S.Encoded, S.ByteGroup;
    GroupBound(f,d,g);
    var w := S.GroupValue(f,d,g);
    var b := S.Encoded(f,d);
    var k := g*S.GroupBytes(d);
    ReconstructBytes(w,d);
    if d == 10 {
      assert b[k] as int == w%256;
      assert b[k+1] as int == (w/256)%256;
      assert b[k+2] as int == (w/65536)%256;
      assert b[k+3] as int == (w/16777216)%256;
      assert b[k+4] as int == (w/4294967296)%256;
      assert w%256+256*((w/256)%256)+65536*((w/65536)%256)+16777216*((w/16777216)%256)+4294967296*((w/4294967296)%256) == w;
    } else if d == 12 {
      assert b[k] as int == w%256;
      assert b[k+1] as int == (w/256)%256;
      assert b[k+2] as int == (w/65536)%256;
      assert w%256+256*((w/256)%256)+65536*((w/65536)%256) == w;
    } else {
      assert b[k] as int == w;
    }
  }

  lemma {:isolate_assertions} GroupCoefficient(f: seq<int>, d: int, g: int, j: int)
    requires S.Words(f,d) && 0 <= g < S.N/S.GroupWords(d) && 0 <= j < S.GroupWords(d)
    ensures (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[g*S.GroupWords(d)+j]
  {
    reveal S.GroupValue;
    var k := g*S.GroupWords(d);
    if d == 1 {
      assert forall h | k <= h < k+8 :: 0 <= f[h] < 2;
      if j == 0 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 1 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 2 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 3 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 4 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 5 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 6 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 7 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
    }
    else if d == 4 {
      assert forall h | k <= h < k+2 :: 0 <= f[h] < 16;
      if j == 0 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 1 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
    }
    else if d == 10 {
      assert forall h | k <= h < k+4 :: 0 <= f[h] < 1024;
      if j == 0 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 1 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 2 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 3 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
    }
    else if d == 12 {
      assert forall h | k <= h < k+2 :: 0 <= f[h] < 4096;
      if j == 0 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
      else if j == 1 { assert (S.GroupValue(f,d,g)/S.WordPower(d,j))%S.Pow2(d) == f[k+j]; }
    }
  }

  lemma WordRoundTrip(f: seq<int>, d: int, i: int)
    requires S.Words(f,d) && 0 <= i < S.N
    ensures S.DecodedWord(S.Encoded(f,d),d,i) == f[i]
  {
    reveal S.DecodedWord;
    GroupRoundTrip(f,d,i/S.GroupWords(d));
    GroupCoefficient(f,d,i/S.GroupWords(d),i%S.GroupWords(d));
  }

  lemma RoundTrip(f: seq<int>, d: int)
    requires S.Words(f,d)
    ensures S.Decode(S.Encoded(f,d),d) == S.Decoded(f)
  {
    reveal S.DecodedWords;
    forall i | 0 <= i < S.N
      ensures S.DecodedWord(S.Encoded(f,d),d,i) == f[i]
    { WordRoundTrip(f,d,i); }
    assert S.DecodedWords(S.Encoded(f,d),d) == f;
  }

  lemma {:isolate_assertions} CompressionError(x: int, d: int)
    requires 0 <= x < S.Q && 1 <= d <= 11
    ensures S.Distance(x,S.Decompress(S.Compress(x,d),d)) <= (S.Q+S.Pow2(d))/(2*S.Pow2(d))
  {
    var p := S.Pow2(d);
    if d == 1 { assert S.ErrorAtScale(x,2); }
    else if d == 2 { assert S.ErrorAtScale(x,4); }
    else if d == 3 { assert S.ErrorAtScale(x,8); }
    else if d == 4 { assert S.ErrorAtScale(x,16); }
    else if d == 5 { assert S.ErrorAtScale(x,32); }
    else if d == 6 { assert S.ErrorAtScale(x,64); }
    else if d == 7 { assert S.ErrorAtScale(x,128); }
    else if d == 8 { assert S.ErrorAtScale(x,256); }
    else if d == 9 { assert S.ErrorAtScale(x,512); }
    else if d == 10 { assert S.ErrorAtScale(x,1024); }
    else { assert S.ErrorAtScale(x,2048); }
    assert S.ErrorAtScale(x,p);
    var c := (p*x+1664)/3329;
    var r := S.Decompress(S.Compress(x,d),d);
    assert 0 <= c <= p;
    var e := if c == p then r-x+S.Q else r-x;
    assert -832 <= e <= 832;
    assert (x-r)%S.Q == (-e)%S.Q;
    if e >= 0 {} else {}
  }

  method CompressAndEncode(f: seq<int>, d: int) returns (b: seq<bv8>)
    requires S.Canonical(f) && S.Width(d)
    ensures b == S.Encoded(S.CompressedWords(f,d),d) && |b| == 32*d
  {
    if d == 12 { b := Encode(f,d); return; }
    var a := new int[S.N];
    for i := 0 to S.N
      invariant forall j | 0 <= j < i :: a[j] == S.Compress(f[j],d)
    { a[i] := Compress(f[i],d); }
    var f1 := a[..];
    assert f1 == S.CompressedWords(f,d);
    b := Encode(f1,d);
  }

  method DecodeAndDecompress(b: seq<bv8>, d: int) returns (r: S.DecodeResult)
    ensures r.Decoded? <==> S.Decode(b,d).Decoded?
    ensures r.Decoded? ==> S.Canonical(r.words) && r.words == S.ExpandedWords(S.Decode(b,d).words,d)
    ensures !r.Decoded? ==> r == S.Decode(b,d)
  {
    var raw := Decode(b,d);
    if !raw.Decoded? { return raw; }
    if d == 12 { return raw; }
    var a := new int[S.N];
    for i := 0 to S.N
      invariant forall j | 0 <= j < i :: a[j] == S.Decompress(raw.words[j],d)
    { a[i] := Decompress(raw.words[i],d); }
    var f := a[..];
    assert f == S.ExpandedWords(raw.words,d);
    return S.Decoded(f);
  }
}
