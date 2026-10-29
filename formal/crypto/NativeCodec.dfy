include "NativeTypes.dfy"
include "Codec.dfy"

module NativeCodec {
  import T = NativeTypes
  import S = CodecSpec
  datatype DecodeResult = InvalidWidth | InvalidLength | ModulusError | Decoded(words: array<T.I>)
  ghost function Model(r: DecodeResult): S.DecodeResult
    reads if r.Decoded? then {r.words} else {}
  {
    if r.InvalidWidth? then S.InvalidWidth else if r.InvalidLength? then S.InvalidLength
    else if r.ModulusError? then S.ModulusError else S.Decoded(T.Ints(r.words))
  }
  // Source-level clearing of owned temporary arrays. Physical JVM/JIT erasure
  // remains an external runtime obligation, not a timing or erasure theorem.
  method Wipe(a: array<T.I>)
    requires T.JavaLength(a.Length)
    modifies a
    ensures forall i: int :: 0 <= i < a.Length ==> a[i] == 0
  {
    var size: T.I := a.Length as T.I;
    for i: T.I := 0 to size
      modifies a
      invariant forall j: int :: 0 <= j < i as int ==> a[j] == 0
    { a[i] := 0; }
  }
  function Width(d: T.I): bool ensures Width(d) == S.Width(d as int)
  { d == 1 || d == 4 || d == 10 || d == 12 }
  function Pow2(d: T.I): T.I
    requires 0 <= d <= 12
    ensures Pow2(d) as int == S.Pow2(d as int)
  {
    if d == 0 then 1 else if d == 1 then 2 else if d == 2 then 4
    else if d == 3 then 8 else if d == 4 then 16 else if d == 5 then 32
    else if d == 6 then 64 else if d == 7 then 128 else if d == 8 then 256
    else if d == 9 then 512 else if d == 10 then 1024 else if d == 11 then 2048 else 4096
  }
  function GroupWords(d: T.I): T.I
    requires Width(d)
    ensures GroupWords(d) as int == S.GroupWords(d as int)
  { if d == 1 then 8 else if d == 10 then 4 else 2 }
  function GroupBytes(d: T.I): T.I
    requires Width(d)
    ensures GroupBytes(d) as int == S.GroupBytes(d as int)
  { if d == 10 then 5 else if d == 12 then 3 else 1 }
  function BytePower(j: T.I): T.L
    requires 0 <= j <= 4
    ensures BytePower(j) as int == S.BytePower(j as int)
    ensures 1 <= BytePower(j) <= 4294967296
  { if j == 0 then 1 else if j == 1 then 256 else if j == 2 then 65536 else if j == 3 then 16777216 else 4294967296 }
  function WordPower(d: T.I, j: T.I): T.L
    requires Width(d) && 0 <= j < GroupWords(d)
    ensures WordPower(d,j) as int == S.WordPower(d as int,j as int)
    ensures 1 <= WordPower(d,j) <= 1073741824
  {
    if d == 1 then Pow2(j) as T.L
    else if d == 4 then (if j == 0 then 1 else 16)
    else if d == 10 then (if j == 0 then 1 else if j == 1 then 1024 else if j == 2 then 1048576 else 1073741824)
    else (if j == 0 then 1 else 4096)
  }
  method Compress(x: T.I, d: T.I) returns (r: T.I)
    requires 0 <= x < 3329 && 1 <= d <= 11
    ensures 0 <= r as int < S.Pow2(d as int) && r as int == S.Compress(x as int,d as int)
  { var p := Pow2(d); r := ((p*x + 1664)/3329)%p; }
  method Decompress(y: T.I, d: T.I) returns (r: T.I)
    requires 1 <= d <= 11 && 0 <= y as int < S.Pow2(d as int)
    ensures 0 <= r < 3329 && r as int == S.Decompress(y as int,d as int)
  { var p := Pow2(d); r := (3329*y + p/2)/p; }
  function {:isolate_assertions} GroupValue(f: array<T.I>, d: T.I, g: T.I): T.L
    requires S.Words(T.Ints(f),d as int) && 0 <= g as int < 256/S.GroupWords(d as int)
    reads f
    ensures GroupValue(f,d,g) as int == S.GroupValue(T.Ints(f),d as int,g as int)
    ensures 0 <= GroupValue(f,d,g) < 1099511627776
  {
    reveal S.GroupValue;
    var k := g*GroupWords(d);
    if d == 1 then (f[k] as T.L)+2*(f[k+1] as T.L)+4*(f[k+2] as T.L)+8*(f[k+3] as T.L)+16*(f[k+4] as T.L)+32*(f[k+5] as T.L)+64*(f[k+6] as T.L)+128*(f[k+7] as T.L)
    else if d == 4 then (f[k] as T.L)+16*(f[k+1] as T.L)
    else if d == 10 then (f[k] as T.L)+1024*(f[k+1] as T.L)+1048576*(f[k+2] as T.L)+1073741824*(f[k+3] as T.L)
    else (f[k] as T.L)+4096*(f[k+1] as T.L)
  }
  function EncodedByte(f: array<T.I>, d: T.I, i: T.I): bv8
    requires S.Words(T.Ints(f),d as int) && 0 <= i < 32*d
    reads f
    ensures EncodedByte(f,d,i) == S.EncodedByte(T.Ints(f),d as int,i as int)
  {
    reveal S.EncodedByte;
    ((GroupValue(f,d,i/GroupBytes(d))/BytePower(i%GroupBytes(d)))%256) as bv8
  }
  method Encode(f: array<T.I>, d: T.I) returns (b: array<bv8>)
    requires S.Words(T.Ints(f),d as int)
    ensures fresh(b) && T.Bytes(b) == S.Encoded(T.Ints(f),d as int) && b.Length == 32*(d as int)
    ensures T.Ints(f) == old(T.Ints(f))
  {
    reveal S.Encoded;
    b := new bv8[32*d];
    for i: T.I := 0 to 32*d
      modifies b
      invariant forall j: int :: 0 <= j < i as int ==> b[j] == S.EncodedByte(T.Ints(f),d as int,j)
    { b[i] := EncodedByte(f,d,i); }
  }
  function ByteGroup(b: array<bv8>, d: T.I, g: T.I): T.L
    requires Width(d) && b.Length == 32*(d as int) && 0 <= g < 256/GroupWords(d)
    reads b
    ensures ByteGroup(b,d,g) as int == S.ByteGroup(T.Bytes(b),d as int,g as int)
    ensures 0 <= ByteGroup(b,d,g) < 1099511627776
  {
    reveal S.ByteGroup;
    var k := g*GroupBytes(d);
    if d == 10 then (b[k] as T.L)+256*(b[k+1] as T.L)+65536*(b[k+2] as T.L)+16777216*(b[k+3] as T.L)+4294967296*(b[k+4] as T.L)
    else if d == 12 then (b[k] as T.L)+256*(b[k+1] as T.L)+65536*(b[k+2] as T.L)
    else b[k] as T.L
  }
  function DecodedWord(b: array<bv8>, d: T.I, i: T.I): T.I
    requires Width(d) && b.Length == 32*(d as int) && 0 <= i < 256
    reads b
    ensures DecodedWord(b,d,i) as int == S.DecodedWord(T.Bytes(b),d as int,i as int)
    ensures 0 <= DecodedWord(b,d,i) as int < S.Pow2(d as int)
  {
    reveal S.DecodedWord;
    ((ByteGroup(b,d,i/GroupWords(d))/WordPower(d,i%GroupWords(d)))%(Pow2(d) as T.L)) as T.I
  }
  method IsCanonical(a: array<T.I>) returns (ok: bool)
    requires a.Length == 256
    ensures ok == S.Canonical(T.Ints(a)) && ok == T.Canonical(a)
  {
    for i: T.I := 0 to 256
      invariant forall j: int :: 0 <= j < i as int ==> 0 <= a[j] as int < 3329
    {
      if a[i] < 0 || a[i] >= 3329 {
        assert T.Ints(a)[i as int] == a[i] as int;
        return false;
      }
    }
    return true;
  }
  method Decode(b: array<bv8>, d: T.I) returns (r: DecodeResult)
    requires T.JavaLength(b.Length)
    ensures Model(r) == S.Decode(T.Bytes(b),d as int)
    ensures r.Decoded? ==> S.Words(T.Ints(r.words),d as int) && fresh(r.words)
    ensures T.Bytes(b) == old(T.Bytes(b))
  {
    reveal S.DecodedWords, S.DecodedWord;
    if !Width(d) { return InvalidWidth; }
    if (b.Length as T.I) != 32*d { return InvalidLength; }
    var a := new T.I[256 as T.I];
    for i: T.I := 0 to 256
      modifies a
      invariant forall j: int :: 0 <= j < i as int ==> a[j] as int == S.DecodedWord(T.Bytes(b),d as int,j)
    {
      a[i] := DecodedWord(b,d,i);
    }
    assert T.Ints(a) == S.DecodedWords(T.Bytes(b),d as int);
    var valid := IsCanonical(a);
    if d == 12 && !valid { Wipe(a); return ModulusError; }
    return Decoded(a);
  }
  method CompressAndEncode(f: array<T.I>, d: T.I) returns (b: array<bv8>)
    requires T.Canonical(f) && Width(d)
    ensures fresh(b) && T.Bytes(b) == S.Encoded(S.CompressedWords(T.Ints(f),d as int),d as int)
    ensures b.Length == 32*(d as int) && T.Ints(f) == old(T.Ints(f))
  {
    if d == 12 { b := Encode(f,d); return; }
    var a := new T.I[256 as T.I];
    for i: T.I := 0 to 256
      modifies a
      invariant forall j: int :: 0 <= j < i as int ==> a[j] as int == S.Compress(T.Ints(f)[j],d as int)
    { a[i] := Compress(f[i],d); }
    assert T.Ints(a) == S.CompressedWords(T.Ints(f),d as int);
    b := Encode(a,d);
    Wipe(a);
  }
  method DecodeAndDecompress(b: array<bv8>, d: T.I) returns (r: DecodeResult)
    requires T.JavaLength(b.Length)
    ensures r.Decoded? <==> S.Decode(T.Bytes(b),d as int).Decoded?
    ensures r.Decoded? ==> T.Canonical(r.words) && fresh(r.words) && T.Ints(r.words) == S.ExpandedWords(S.Decode(T.Bytes(b),d as int).words,d as int)
    ensures !r.Decoded? ==> Model(r) == S.Decode(T.Bytes(b),d as int)
    ensures T.Bytes(b) == old(T.Bytes(b))
  {
    var raw := Decode(b,d);
    if !raw.Decoded? { return raw; }
    if d == 12 {
      assert forall j: int :: 0 <= j < 256 ==> raw.words[j] as int == T.Ints(raw.words)[j];
      return raw;
    }
    var a := new T.I[256 as T.I];
    for i: T.I := 0 to 256
      modifies a
      invariant forall j: int :: 0 <= j < i as int ==> a[j] as int == S.Decompress(T.Ints(raw.words)[j],d as int)
    {
      assert raw.words[i] as int == T.Ints(raw.words)[i as int];
      a[i] := Decompress(raw.words[i],d);
    }
    assert T.Ints(a) == S.ExpandedWords(T.Ints(raw.words),d as int);
    Wipe(raw.words);
    return Decoded(a);
  }
}
