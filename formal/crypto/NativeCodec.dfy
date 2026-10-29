include "NativeTypes.dfy"
include "NativeField.dfy"
include "Codec.dfy"

module NativeCodec {
  import T = NativeTypes
  import S = CodecSpec
  import F = NativeField
  import V = VerifiedCodec
  import A = VerifiedField
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
  opaque function Pow2(d: T.I): T.I
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
  ghost function Power(k: int): int
    requires 0 <= k <= 32
    ensures 1 <= Power(k) <= 4294967296
  { [1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536,131072,262144,524288,1048576,2097152,4194304,8388608,16777216,33554432,67108864,134217728,268435456,536870912,1073741824,2147483648,4294967296][k] }

  lemma {:isolate_assertions} ShiftRight(word: bv64, shift: T.I)
    requires word < 4096 && 0 <= shift <= 12
    ensures (word >> shift) as int == (word as int)/Power(shift as int)
  {
    if shift == 0 { assert (word >> 0) as int == (word as int)/1; }
    else if shift == 1 { assert (word >> 1) as int == (word as int)/2; }
    else if shift == 2 { assert (word >> 2) as int == (word as int)/4; }
    else if shift == 3 { assert (word >> 3) as int == (word as int)/8; }
    else if shift == 4 { assert (word >> 4) as int == (word as int)/16; }
    else if shift == 5 { assert (word >> 5) as int == (word as int)/32; }
    else if shift == 6 { assert (word >> 6) as int == (word as int)/64; }
    else if shift == 7 { assert (word >> 7) as int == (word as int)/128; }
    else if shift == 8 { assert (word >> 8) as int == (word as int)/256; }
    else if shift == 9 { assert (word >> 9) as int == (word as int)/512; }
    else if shift == 10 { assert (word >> 10) as int == (word as int)/1024; }
    else if shift == 11 { assert (word >> 11) as int == (word as int)/2048; }
    else if shift == 12 { assert (word >> 12) as int == (word as int)/4096; }
  }
  lemma Low1(word: bv64)
    requires word < 4096
    ensures (word & 1) as int == (word as int)%2
  {}
  lemma Low2(word: bv64)
    requires word < 4096
    ensures (word & 3) as int == (word as int)%4
  {}
  lemma Low3(word: bv64)
    requires word < 4096
    ensures (word & 7) as int == (word as int)%8
  {}
  lemma Low4(word: bv64)
    requires word < 4096
    ensures (word & 15) as int == (word as int)%16
  {}
  lemma Low5(word: bv64)
    requires word < 4096
    ensures (word & 31) as int == (word as int)%32
  {}
  lemma Low6(word: bv64)
    requires word < 4096
    ensures (word & 63) as int == (word as int)%64
  {}
  lemma Low7(word: bv64)
    requires word < 4096
    ensures (word & 127) as int == (word as int)%128
  {}
  lemma Low8(word: bv64)
    requires word < 4096
    ensures (word & 255) as int == (word as int)%256
  {}
  lemma Low9(word: bv64)
    requires word < 4096
    ensures (word & 511) as int == (word as int)%512
  {}
  lemma Low10(word: bv64)
    requires word < 4096
    ensures (word & 1023) as int == (word as int)%1024
  {}
  lemma Low11(word: bv64)
    requires word < 4096
    ensures (word & 2047) as int == (word as int)%2048
  {}
  lemma Low12(word: bv64)
    requires word < 4096
    ensures (word & 4095) as int == (word as int)%4096
  {}
  lemma {:isolate_assertions} LowBits(word: bv64, bits: T.I)
    requires word < 4096 && 1 <= bits <= 12
    ensures (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int)
  {
    if bits == 1 { Low1(word); assert Pow2(bits) == 2; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 2 { Low2(word); assert Pow2(bits) == 4; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 3 { Low3(word); assert Pow2(bits) == 8; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 4 { Low4(word); assert Pow2(bits) == 16; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 5 { Low5(word); assert Pow2(bits) == 32; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 6 { Low6(word); assert Pow2(bits) == 64; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 7 { Low7(word); assert Pow2(bits) == 128; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 8 { Low8(word); assert Pow2(bits) == 256; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 9 { Low9(word); assert Pow2(bits) == 512; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 10 { Low10(word); assert Pow2(bits) == 1024; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 11 { Low11(word); assert Pow2(bits) == 2048; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
    else if bits == 12 { Low12(word); assert Pow2(bits) == 4096; assert (word & ((Pow2(bits)-1) as bv64)) as int == (word as int)%S.Pow2(bits as int); }
  }
  // Payload extraction has no division/remainder. Both counts are public,
  // proved small enough that JVM shift masking cannot change their meaning.
  opaque function {:isolate_assertions} Extract(value: T.L, shift: T.I, bits: T.I): T.I
    requires 0 <= value < 4096 && 0 <= shift <= 12 && 1 <= bits <= 12
    ensures Extract(value,shift,bits) as int == ((value as int)/Power(shift as int))%S.Pow2(bits as int)
    ensures 0 <= Extract(value,shift,bits) as int < S.Pow2(bits as int)
  {
    var word: bv64 := value as bv64;
    assert word as int == value as int;
    assert word < 4096;
    ShiftRight(word,shift);
    var shifted := word >> shift;
    assert shifted as int == (value as int)/Power(shift as int);
    assert shifted < 4096;
    LowBits(shifted,bits);
    var masked := shifted & ((Pow2(bits)-1) as bv64);
    assert masked as int == (shifted as int)%S.Pow2(bits as int);
    masked as T.I
  }
  opaque function {:isolate_assertions} Shift(value: T.L, shift: T.I): T.I
    requires 0 <= value < 4096 && 0 <= shift <= 12
    ensures Shift(value,shift) as int == (value as int)/Power(shift as int)
    ensures 0 <= Shift(value,shift) < 4096
  {
    var word: bv64 := value as bv64;
    assert word as int == value as int;
    assert word < 4096;
    ShiftRight(word,shift);
    (word >> shift) as T.I
  }
  // Division is restricted to explicit, nonnegative public metadata helpers.
  function PublicDiv(value: T.I, divisor: T.I): T.I
    requires 0 <= value && 1 <= divisor <= 8
    ensures PublicDiv(value,divisor) as int == (value as int)/(divisor as int)
    ensures 0 <= PublicDiv(value,divisor) <= value
  { value/divisor }
  function PublicMod(value: T.I, divisor: T.I): T.I
    requires 0 <= value && 1 <= divisor <= 8
    ensures PublicMod(value,divisor) as int == (value as int)%(divisor as int)
    ensures 0 <= PublicMod(value,divisor) < divisor
  { value%divisor }
  lemma CompressionPowerBound(d: int)
    requires 1 <= d <= 11
    ensures S.Pow2(d) <= 2048
  {}
  lemma CompressionQuotientBound(dividend: int)
    requires 0 <= dividend <= 6817408
    ensures 0 <= dividend/3329 <= 2048
  {}
  method {:isolate_assertions} Compress(x: T.I, d: T.I) returns (r: T.I)
    requires 0 <= x < 3329 && 1 <= d <= 11
    ensures 0 <= r as int < S.Pow2(d as int) && r as int == S.Compress(x as int,d as int)
  {
    var p := Pow2(d);
    CompressionPowerBound(d as int);
    A.ProductBound(p as int,x as int,2048,3328);
    var dividend: T.I := p*x + 1664;
    assert dividend as int == S.Pow2(d as int)*(x as int)+S.Q/2;
    CompressionQuotientBound(dividend as int);
    var product: T.L := (dividend as T.L)*5039;
    assert product as int == (dividend as int)*5039;
    F.NativeShift24(product);
    var quotient: T.I := ((product as bv64) >> (24 as T.I)) as T.I;
    F.BarrettBounds(dividend as int);
    var remainder: T.I := dividend-quotient*3329;
    var biased: T.I := remainder+32768-3329;
    var correction: T.I := (((biased as bv64) >> (15 as T.I)) & 1) as T.I;
    ghost var small := remainder < 3329;
    if small {
      assert 0 <= biased < 32768;
      assert (biased as bv64) < 32768;
      assert correction == 0;
    } else {
      assert 32768 <= biased < 65536;
      assert 32768 <= (biased as bv64) < 65536;
      assert correction == 1;
    }
    var rounded: T.I := quotient+correction;
    assert rounded as int == (dividend as int)/3329;
    assert 0 <= rounded as int <= 2048;
    r := Extract(rounded as T.L,0,d);
    assert r as int == (rounded as int)%S.Pow2(d as int);
  }
  function DecompressionScale(d: T.I): T.L
    requires 1 <= d <= 11
    ensures 8192 <= DecompressionScale(d) <= 8388608
    ensures (DecompressionScale(d) as int)*S.Pow2(d as int) == 16777216
  { if d == 1 then 8388608 else if d == 2 then 4194304 else if d == 3 then 2097152 else if d == 4 then 1048576 else if d == 5 then 524288 else if d == 6 then 262144 else if d == 7 then 131072 else if d == 8 then 65536 else if d == 9 then 32768 else if d == 10 then 16384 else 8192 }
  lemma ScaleDivision(value: int, d: T.I)
    requires 0 <= value && 1 <= d <= 11
    ensures (value*(DecompressionScale(d) as int))/16777216 == value/S.Pow2(d as int)
  {
    if d == 1 { assert (value*8388608)/16777216 == value/2; }
    else if d == 2 { assert (value*4194304)/16777216 == value/4; }
    else if d == 3 { assert (value*2097152)/16777216 == value/8; }
    else if d == 4 { assert (value*1048576)/16777216 == value/16; }
    else if d == 5 { assert (value*524288)/16777216 == value/32; }
    else if d == 6 { assert (value*262144)/16777216 == value/64; }
    else if d == 7 { assert (value*131072)/16777216 == value/128; }
    else if d == 8 { assert (value*65536)/16777216 == value/256; }
    else if d == 9 { assert (value*32768)/16777216 == value/512; }
    else if d == 10 { assert (value*16384)/16777216 == value/1024; }
    else if d == 11 { assert (value*8192)/16777216 == value/2048; }
  }
  method {:isolate_assertions} Decompress(y: T.I, d: T.I) returns (r: T.I)
    requires 1 <= d <= 11 && 0 <= y as int < S.Pow2(d as int)
    ensures 0 <= r < 3329 && r as int == S.Decompress(y as int,d as int)
  {
    var p := Pow2(d);
    var dividend: T.I := 3329*y + PublicDiv(p,2);
    assert dividend as int == 3329*(y as int)+S.Pow2(d as int)/2;
    var scale := DecompressionScale(d);
    var product: T.L := (dividend as T.L)*scale;
    assert 0 <= product < 137438953472;
    F.NativeShift24(product);
    r := ((product as bv64) >> (24 as T.I)) as T.I;
    ScaleDivision(dividend as int,d);
    assert r as int == (dividend as int)/S.Pow2(d as int);
  }
  function {:isolate_assertions} GroupValue(f: array<T.I>, d: T.I, g: T.I): T.L
    requires S.Words(T.Ints(f),d as int) && 0 <= g as int < 256/S.GroupWords(d as int)
    reads f
    ensures GroupValue(f,d,g) as int == S.GroupValue(T.Ints(f),d as int,g as int)
    ensures 0 <= GroupValue(f,d,g) < 1099511627776
    ensures d == 1 || d == 4 ==> GroupValue(f,d,g) < 256
  {
    reveal S.GroupValue;
    var k := g*GroupWords(d);
    if d == 1 then (f[k] as T.L)+2*(f[k+1] as T.L)+4*(f[k+2] as T.L)+8*(f[k+3] as T.L)+16*(f[k+4] as T.L)+32*(f[k+5] as T.L)+64*(f[k+6] as T.L)+128*(f[k+7] as T.L)
    else if d == 4 then (f[k] as T.L)+16*(f[k+1] as T.L)
    else if d == 10 then (f[k] as T.L)+1024*(f[k+1] as T.L)+1048576*(f[k+2] as T.L)+1073741824*(f[k+3] as T.L)
    else (f[k] as T.L)+4096*(f[k+1] as T.L)
  }
  lemma EncodeTen(a: int, b: int, c: int, d: int, at: int)
    requires 0 <= a < 1024 && 0 <= b < 1024 && 0 <= c < 1024 && 0 <= d < 1024 && 0 <= at < 5
    ensures ((a+1024*b+1048576*c+1073741824*d)/S.BytePower(at))%256 ==
      (if at == 0 then a%256 else if at == 1 then a/256+4*(b%64)
       else if at == 2 then b/64+16*(c%16) else if at == 3 then c/16+64*(d%4) else d/4)
  {
    if at == 0 {} else if at == 1 {} else if at == 2 {} else if at == 3 {} else {}
  }
  lemma EncodeTwelve(a: int, b: int, at: int)
    requires 0 <= a < 4096 && 0 <= b < 4096 && 0 <= at < 3
    ensures ((a+4096*b)/S.BytePower(at))%256 ==
      (if at == 0 then a%256 else if at == 1 then a/256+16*(b%16) else b/16)
  { if at == 0 {} else if at == 1 {} else {} }
  lemma DecodeTen(a: int, b: int, c: int, d: int, e: int, at: int)
    requires 0 <= a < 256 && 0 <= b < 256 && 0 <= c < 256 && 0 <= d < 256 && 0 <= e < 256 && 0 <= at < 4
    ensures ((a+256*b+65536*c+16777216*d+4294967296*e)/S.WordPower(10,at))%1024 ==
      (if at == 0 then a+256*(b%4) else if at == 1 then b/4+64*(c%16)
       else if at == 2 then c/16+16*(d%64) else d/64+4*e)
  { if at == 0 {} else if at == 1 {} else if at == 2 {} else {} }
  lemma DecodeTwelve(a: int, b: int, c: int, at: int)
    requires 0 <= a < 256 && 0 <= b < 256 && 0 <= c < 256 && 0 <= at < 2
    ensures ((a+256*b+65536*c)/S.WordPower(12,at))%4096 ==
      (if at == 0 then a+256*(b%16) else b/16+16*c)
  { if at == 0 {} else {} }
  opaque function {:isolate_assertions} EncodeTenByte(a: T.I, b: T.I, c: T.I, d: T.I, at: T.I): bv8
    requires 0 <= a < 1024 && 0 <= b < 1024 && 0 <= c < 1024 && 0 <= d < 1024 && 0 <= at < 5
    ensures EncodeTenByte(a,b,c,d,at) as int == ((a as int)+1024*(b as int)+1048576*(c as int)+1073741824*(d as int))/S.BytePower(at as int)%256
  {
    EncodeTen(a as int,b as int,c as int,d as int,at as int);
    (if at == 0 then Extract(a as T.L,0,8)
     else if at == 1 then Shift(a as T.L,8)+4*Extract(b as T.L,0,6)
     else if at == 2 then Shift(b as T.L,6)+16*Extract(c as T.L,0,4)
     else if at == 3 then Shift(c as T.L,4)+64*Extract(d as T.L,0,2)
     else Shift(d as T.L,2)) as bv8
  }
  opaque function {:isolate_assertions} EncodeTwelveByte(a: T.I, b: T.I, at: T.I): bv8
    requires 0 <= a < 4096 && 0 <= b < 4096 && 0 <= at < 3
    ensures EncodeTwelveByte(a,b,at) as int == ((a as int)+4096*(b as int))/S.BytePower(at as int)%256
  {
    EncodeTwelve(a as int,b as int,at as int);
    (if at == 0 then Extract(a as T.L,0,8)
     else if at == 1 then Shift(a as T.L,8)+16*Extract(b as T.L,0,4)
     else Shift(b as T.L,4)) as bv8
  }
  opaque function {:isolate_assertions} DecodeTenWord(a: T.I, b: T.I, c: T.I, d: T.I, e: T.I, at: T.I): T.I
    requires 0 <= a < 256 && 0 <= b < 256 && 0 <= c < 256 && 0 <= d < 256 && 0 <= e < 256 && 0 <= at < 4
    ensures DecodeTenWord(a,b,c,d,e,at) as int == ((a as int)+256*(b as int)+65536*(c as int)+16777216*(d as int)+4294967296*(e as int))/S.WordPower(10,at as int)%1024
    ensures 0 <= DecodeTenWord(a,b,c,d,e,at) < 1024
  {
    DecodeTen(a as int,b as int,c as int,d as int,e as int,at as int);
    if at == 0 then (a as T.I)+256*Extract(b as T.L,0,2)
    else if at == 1 then Shift(b as T.L,2)+64*Extract(c as T.L,0,4)
    else if at == 2 then Shift(c as T.L,4)+16*Extract(d as T.L,0,6)
    else Shift(d as T.L,6)+4*(e as T.I)
  }
  opaque function {:isolate_assertions} DecodeTwelveWord(a: T.I, b: T.I, c: T.I, at: T.I): T.I
    requires 0 <= a < 256 && 0 <= b < 256 && 0 <= c < 256 && 0 <= at < 2
    ensures DecodeTwelveWord(a,b,c,at) as int == ((a as int)+256*(b as int)+65536*(c as int))/S.WordPower(12,at as int)%4096
    ensures 0 <= DecodeTwelveWord(a,b,c,at) < 4096
  {
    DecodeTwelve(a as int,b as int,c as int,at as int);
    if at == 0 then (a as T.I)+256*Extract(b as T.L,0,4)
    else Shift(b as T.L,4)+16*(c as T.I)
  }
  opaque function {:isolate_assertions} EncodedByte(f: array<T.I>, d: T.I, i: T.I): bv8
    requires S.Words(T.Ints(f),d as int) && 0 <= i < 32*d
    reads f
    ensures EncodedByte(f,d,i) == S.EncodedByte(T.Ints(f),d as int,i as int)
  {
    var group := PublicDiv(i,GroupBytes(d));
    var at := PublicMod(i,GroupBytes(d));
    var k := group*GroupWords(d);
    assert forall j: int :: 0 <= j < 256 ==> T.Ints(f)[j] == f[j] as int;
    assert forall j: int :: 0 <= j < 256 ==> 0 <= f[j] as int < (if d == 12 then 3329 else S.Pow2(d as int));
    reveal S.EncodedByte, S.GroupValue;
    if d == 1 || d == 4 then GroupValue(f,d,group) as bv8
    else if d == 10 then EncodeTenByte(f[k],f[k+1],f[k+2],f[k+3],at)
    else EncodeTwelveByte(f[k],f[k+1],at)
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
  opaque function {:isolate_assertions} DecodedWord(b: array<bv8>, d: T.I, i: T.I): T.I
    requires Width(d) && b.Length == 32*(d as int) && 0 <= i < 256
    reads b
    ensures DecodedWord(b,d,i) as int == S.DecodedWord(T.Bytes(b),d as int,i as int)
    ensures 0 <= DecodedWord(b,d,i) as int < S.Pow2(d as int)
  {
    var group := PublicDiv(i,GroupWords(d));
    var at := PublicMod(i,GroupWords(d));
    var k := group*GroupBytes(d);
    assert Power((d as int)*(at as int)) == S.WordPower(d as int,at as int);
    reveal S.DecodedWord, S.ByteGroup;
    if d == 1 || d == 4 then Extract(b[k] as T.L,d*at,d)
    else if d == 10 then DecodeTenWord(b[k] as T.I,b[k+1] as T.I,b[k+2] as T.I,b[k+3] as T.I,b[k+4] as T.I,at)
    else DecodeTwelveWord(b[k] as T.I,b[k+1] as T.I,b[k+2] as T.I,at)
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
