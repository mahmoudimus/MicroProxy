include "KemSpec.dfy"
include "NativeJdkHash.dfy"
include "NativeSampling.dfy"
include "NativeShake.dfy"
include "NativePolynomial.dfy"

// Composition formulas adapted from Go crypto/internal/fips140/mlkem via
// MlKem768.java (Copyright 2023 The Go Authors, BSD-3-Clause). Native ownership,
// byte/int refinement, failure cleanup and Dafny proofs are new work.
module NativeMlKem {
  import T = NativeTypes
  import S = KemSpec
  import P = PolySpec
  import C = CodecSpec
  import NC = NativeCodec
  import NS = NativeSampling
  import SX = SpongeSpec
  import X = NativeShake
  import H = NativeJdkHash
  import J = JdkHash
  import NP = NativePolynomial

  ghost function {:opaque} Polys(a: array<array<T.I>>): seq<seq<int>>
    reads a, set i: int | 0 <= i < a.Length :: a[i]
    ensures |Polys(a)| == a.Length
    ensures forall i | 0 <= i < a.Length :: Polys(a)[i] == T.Ints(a[i])
  { seq(a.Length,i requires 0 <= i < a.Length reads PolyObjects(a) => T.Ints(a[i])) }
  ghost function PolyObjects(a: array<array<T.I>>): set<object>
    reads a
  { {a} + set i: int | 0 <= i < a.Length :: a[i] as object }
  ghost predicate Vec(a: array<array<T.I>>, n: nat)
    reads PolyObjects(a)
    ensures Vec(a,n) == S.Vec(Polys(a),n)
  { VecEquation(a,n); a.Length == n && forall i | 0 <= i < n :: T.Canonical(a[i]) }
  lemma NativeCanonical(a: array<T.I>)
    ensures T.Canonical(a) == P.Canonical(T.Ints(a))
  {
    forall j | 0 <= j < a.Length
      ensures T.Ints(a)[j] == a[j] as int
    {}
  }
  lemma VecEquation(a: array<array<T.I>>, n: nat)
    ensures (a.Length == n && forall i | 0 <= i < n :: T.Canonical(a[i])) == S.Vec(Polys(a),n)
  {
    if a.Length == n {
      forall i | 0 <= i < n
        ensures T.Canonical(a[i]) == P.Canonical(Polys(a)[i])
      { NativeCanonical(a[i]); assert Polys(a)[i] == T.Ints(a[i]); }
    }
  }
  ghost predicate Distinct(a: array<array<T.I>>)
    reads a
  { forall i,j | 0 <= i < j < a.Length :: a[i] != a[j] }
  ghost predicate ZeroBytes(a: array<bv8>) reads a
  { forall i | 0 <= i < a.Length :: a[i] == 0 }
  ghost predicate ZeroInts(a: array<T.I>) reads a
  { forall i | 0 <= i < a.Length :: a[i] == 0 }

  class PublicKey {
    const matrix: array<array<T.I>>
    const t: array<array<T.I>>
    const rho: array<bv8>
    const encoded: array<bv8>
    const hash: array<bv8>
    var destroyed: bool

    ghost function Repr(): set<object>
      reads this,matrix,t
    { {this,rho,encoded,hash}+PolyObjects(matrix)+PolyObjects(t) }
    ghost function Model(): S.PublicKey
      reads Repr()
    { S.PublicKey(Polys(matrix),Polys(t),rho[..],encoded[..],hash[..]) }
    ghost predicate Valid()
      reads Repr()
    {
      !destroyed && S.ValidPublic(Model()) && Vec(matrix,9) && Vec(t,3) && Distinct(matrix) && Distinct(t) &&
      PolyObjects(matrix) !! PolyObjects(t) && rho != encoded && rho != hash && encoded != hash
    }
    constructor(a: array<array<T.I>>, words: array<array<T.I>>, seed: array<bv8>, bytes: array<bv8>, digest: array<bv8>)
      requires S.ValidPublic(S.PublicKey(Polys(a),Polys(words),seed[..],bytes[..],digest[..]))
      requires Distinct(a) && Distinct(words) && PolyObjects(a) !! PolyObjects(words)
      requires seed != bytes && seed != digest && bytes != digest
      ensures Valid()
      ensures Model() == old(S.PublicKey(Polys(a),Polys(words),seed[..],bytes[..],digest[..]))
      ensures matrix == a && t == words && rho == seed && encoded == bytes && hash == digest
      ensures Repr() == {this,seed,bytes,digest}+PolyObjects(a)+PolyObjects(words)
    {
      matrix := a; t := words; rho := seed; encoded := bytes; hash := digest; destroyed := false;
    }
    method Destroy()
      requires Valid()
      modifies Repr()
      ensures destroyed
      ensures forall i | 0 <= i < matrix.Length :: ZeroInts(matrix[i])
      ensures forall i | 0 <= i < t.Length :: ZeroInts(t[i])
      ensures ZeroBytes(rho) && ZeroBytes(encoded) && ZeroBytes(hash)
    {
      WipePolys(matrix); WipePolys(t);
      WipeBytes(rho); WipeBytes(encoded); WipeBytes(hash);
      destroyed := true;
    }
  }
  class SecretKey {
    const seed: array<bv8>
    const s: array<array<T.I>>
    const ek: PublicKey
    var destroyed: bool
    ghost function Repr(): set<object>
      reads this,s,ek,ek.matrix,ek.t
    { {this,seed}+PolyObjects(s)+ek.Repr() }
    ghost function Model(): S.SecretKey
      reads Repr()
    { S.SecretKey(seed[..],Polys(s),ek.Model()) }
    ghost predicate Valid()
      reads Repr()
    { !destroyed && seed.Length == 64 && Vec(s,3) && Distinct(s) && ek.Valid() &&
      {seed} !! ek.Repr() && PolyObjects(s) !! ek.Repr() }
    constructor(bytes: array<bv8>, words: array<array<T.I>>, publicKey: PublicKey)
      requires bytes.Length == 64 && Vec(words,3) && Distinct(words) && publicKey.Valid()
      requires {bytes} !! publicKey.Repr() && PolyObjects(words) !! publicKey.Repr()
      ensures Valid() && S.ValidSecret(Model())
      ensures Model() == old(S.SecretKey(bytes[..],Polys(words),publicKey.Model()))
      ensures seed == bytes && s == words && ek == publicKey
      ensures Repr() == {this,bytes}+PolyObjects(words)+publicKey.Repr()
    { seed := bytes; s := words; ek := publicKey; destroyed := false; }
    method Destroy()
      requires Valid()
      modifies Repr()
      ensures destroyed && ZeroBytes(seed) && ek.destroyed
      ensures ZeroBytes(ek.rho) && ZeroBytes(ek.encoded) && ZeroBytes(ek.hash)
      ensures forall i | 0 <= i < s.Length :: ZeroInts(s[i])
      ensures forall i | 0 <= i < ek.matrix.Length :: ZeroInts(ek.matrix[i])
      ensures forall i | 0 <= i < ek.t.Length :: ZeroInts(ek.t[i])
    {
      WipeBytes(seed); WipePolys(s); ek.Destroy(); destroyed := true;
    }
  }

  // These postconditions establish source writes to every array element.
  // JVM/compiler/JIT retention, register copies, caches and provider internals
  // require a separate physical-erasure assumption and are not proved here.
  method WipeBytes(a: array<bv8>)
    requires T.JavaLength(a.Length)
    modifies a
    ensures ZeroBytes(a)
  {
    var n: T.I := a.Length as T.I;
    for i: T.I := 0 to n
      modifies a
      invariant forall j: int :: 0 <= j < i as int ==> a[j] == 0
    { a[i] := 0; }
  }
  method WipeInts(a: array<T.I>)
    requires T.JavaLength(a.Length)
    modifies a
    ensures ZeroInts(a)
  {
    var n: T.I := a.Length as T.I;
    for i: T.I := 0 to n
      modifies a
      invariant forall j: int :: 0 <= j < i as int ==> a[j] == 0
    { a[i] := 0; }
  }
  method WipePolys(a: array<array<T.I>>)
    requires T.JavaLength(a.Length)
    requires forall i | 0 <= i < a.Length :: T.JavaLength(a[i].Length)
    modifies PolyObjects(a)
    ensures a[..] == old(a[..])
    ensures forall i | 0 <= i < a.Length :: ZeroInts(a[i])
  {
    var n: T.I := a.Length as T.I;
    for i: T.I := 0 to n
      modifies PolyObjects(a)
      invariant forall j: int :: 0 <= j < i as int ==> ZeroInts(a[j])
      invariant forall j: int :: 0 <= j < a.Length ==> T.JavaLength(a[j].Length)
      invariant a[..] == old(a[..])
    { WipeInts(a[i]); }
  }
  method Slice(a: array<bv8>, start: T.I, length: T.I) returns(b: array<bv8>)
    requires T.JavaLength(a.Length)
    requires 0 <= start && 0 <= length && start as int + length as int <= a.Length
    ensures fresh(b) && b[..] == a[start as int..start as int+length as int]
    ensures b.Length == length as int
  {
    b := new bv8[length];
    for i: T.I := 0 to length
      modifies b
      invariant forall j: int :: 0 <= j < i as int ==> b[j] == a[start as int+j]
    { b[i] := a[(start as T.L)+(i as T.L)]; }
  }
  method Join(a: array<bv8>, b: array<bv8>) returns(c: array<bv8>)
    requires T.JavaLength(a.Length+b.Length)
    ensures fresh(c) && c[..] == a[..]+b[..]
    ensures c.Length == a.Length+b.Length
  {
    var n: T.I := a.Length as T.I;
    var m: T.I := b.Length as T.I;
    c := new bv8[n+m];
    for i: T.I := 0 to n
      modifies c
      invariant forall j: int :: 0 <= j < i as int ==> c[j] == a[j]
    { c[i] := a[i]; }
    for i: T.I := 0 to m
      modifies c
      invariant c[..n as int] == a[..]
      invariant forall j: int :: 0 <= j < i as int ==> c[n as int+j] == b[j]
    { c[n+i] := b[i]; }
  }
  method Tag(a: array<bv8>, tag: bv8) returns(b: array<bv8>)
    requires a.Length < 2147483647
    ensures fresh(b) && b[..] == a[..]+[tag]
    ensures b.Length == a.Length+1
  {
    var n: T.I := a.Length as T.I;
    b := new bv8[n+1];
    for i: T.I := 0 to n
      modifies b
      invariant forall j: int :: 0 <= j < i as int ==> b[j] == a[j]
    { b[i] := a[i]; }
    b[n] := tag;
  }

  method Select(c: array<bv8>, expected: array<bv8>, candidate: array<bv8>, fallback: array<bv8>) returns(r: array<bv8>)
    requires c.Length == 1088 && expected.Length == 1088 && candidate.Length == 32 && fallback.Length == 32
    ensures fresh(r) && r.Length == 32
    ensures r[..] == (if c[..] == expected[..] then candidate[..] else fallback[..])
  {
    var diff: bv8 := 0;
    for i: T.I := 0 to 1088
      invariant diff == 0 <==> c[..i as int] == expected[..i as int]
    {
      ghost var before := diff;
      diff := diff | (c[i] ^ expected[i]);
      assert diff == 0 <==> before == 0 && c[i] == expected[i];
      assert c[..i as int+1] == c[..i as int]+[c[i]];
      assert expected[..i as int+1] == expected[..i as int]+[expected[i]];
    }
    // The pinned runtime's bv64 shift branches only on its public distance;
    // bv8/bv16/bv32 right-shift helpers branch on the payload sign.
    var mask := (((diff as bv64)-1) >> 56) as bv8;
    assert mask == (if diff == 0 then 255 else 0);
    r := new bv8[32 as T.I];
    for i: T.I := 0 to 32
      modifies r
      invariant forall j: int :: 0 <= j < i as int ==> r[j] == (if c[..] == expected[..] then candidate[j] else fallback[j])
    { r[i] := (candidate[i] & mask) | (fallback[i] & !mask); }
  }
  method CopyInto(a: array<bv8>, b: array<bv8>, start: T.I)
    requires a != b && T.JavaLength(b.Length)
    requires 0 <= start && start as int+a.Length <= b.Length
    modifies b
    ensures b[start as int..start as int+a.Length] == a[..]
    ensures forall i | 0 <= i < b.Length && (i < start as int || start as int+a.Length <= i) :: b[i] == old(b[i])
  {
    var n: T.I := a.Length as T.I;
    for i: T.I := 0 to n
      modifies b
      invariant forall j: int :: 0 <= j < i as int ==> b[start as int+j] == a[j]
      invariant forall j: int :: 0 <= j < b.Length && (j < start as int || start as int+n as int <= j) ==> b[j] == old(b[j])
    { b[start+i] := a[i]; }
  }
  ghost function ModelSample(r: S.Result<array<T.I>>): S.Result<seq<int>>
    reads if r.Success? then {r.value} else {}
  { if r.Success? then S.Success(T.Ints(r.value)) else S.Failure(r.reason) }
  ghost function ModelMatrix(r: S.Result<array<array<T.I>>>): S.Result<seq<seq<int>>>
    reads if r.Success? then PolyObjects(r.value) else {}
  { if r.Success? then S.Success(Polys(r.value)) else S.Failure(r.reason) }
  ghost function ModelPublic(r: S.Result<PublicKey>): S.Result<S.PublicKey>
    reads if r.Success? then r.value.Repr() else {}
  { if r.Success? then S.Success(r.value.Model()) else S.Failure(r.reason) }
  ghost function ModelSecret(r: S.Result<SecretKey>): S.Result<S.SecretKey>
    reads if r.Success? then r.value.Repr() else {}
  { if r.Success? then S.Success(r.value.Model()) else S.Failure(r.reason) }
  ghost function ModelBytes(r: S.Result<array<bv8>>): S.Result<seq<bv8>>
    reads if r.Success? then {r.value} else {}
  { if r.Success? then S.Success(r.value[..]) else S.Failure(r.reason) }
  datatype Encapsulation = Encapsulation(key: array<bv8>, ciphertext: array<bv8>)
  ghost function ModelEncapsulation(r: S.Result<Encapsulation>): S.Result<S.Encapsulation>
    reads if r.Success? then {r.value.key,r.value.ciphertext} else {}
  { if r.Success? then S.Success(S.Encapsulation(r.value.key[..],r.value.ciphertext[..])) else S.Failure(r.reason) }

  method Noise(seed: array<bv8>, nonce: T.I) returns(r: array<T.I>)
    requires seed.Length == 32 && 0 <= nonce < 256
    ensures fresh(r) && T.Canonical(r) && T.Ints(r) == S.Noise(seed[..],nonce as int)
  {
    var input := Tag(seed,nonce as bv8);
    var bytes := X.Xof(136,input,128);
    r := NS.Cbd2(bytes);
    WipeBytes(input); WipeBytes(bytes);
    assert ZeroBytes(input) && ZeroBytes(bytes);
  }
  method SamplePrefix(bytes: array<bv8>) returns(r: S.Result<array<T.I>>)
    requires bytes.Length == 840
    ensures ModelSample(r) == S.SamplePrefix(bytes[..])
    ensures r.Success? ==> fresh(r.value) && T.Canonical(r.value)
  {
    var empty := new T.I[0 as T.I];
    var sample := NS.Feed(empty,bytes);
    assert sample.Full? || sample.NeedMore?;
    if sample.Full? { NativeCanonical(sample.coeffs); return S.Success(sample.coeffs); }
    WipeInts(sample.coeffs);
    assert ZeroInts(sample.coeffs);
    return S.Failure(S.RejectionLimit);
  }
  method Sample(rho: array<bv8>, i: T.I, j: T.I) returns(r: S.Result<array<T.I>>)
    requires rho.Length == 32 && 0 <= i < 3 && 0 <= j < 3
    ensures ModelSample(r) == S.Sample(rho[..],i as int,j as int)
    ensures r.Success? ==> fresh(r.value) && T.Canonical(r.value)
  {
    var first := Tag(rho,j as bv8);
    var input := Tag(first,i as bv8);
    assert input[..] == rho[..]+[j as bv8,i as bv8];
    var bytes := X.Xof(168,input,840);
    r := SamplePrefix(bytes);
    assert ModelSample(r) == S.Sample(rho[..],i as int,j as int);
    WipeBytes(first); WipeBytes(input); WipeBytes(bytes);
    assert ZeroBytes(first) && ZeroBytes(input) && ZeroBytes(bytes);
  }
  method {:isolate_assertions} ExpandMatrix(rho: array<bv8>) returns(r: S.Result<array<array<T.I>>>)
    requires rho.Length == 32
    ensures r.Success? <==> S.MatrixReady(rho[..])
    ensures r.Success? ==> Vec(r.value,9) && Distinct(r.value) && Polys(r.value) == S.Matrix(rho[..])
    ensures r.Success? ==> fresh(PolyObjects(r.value))
    ensures r.Failure? ==> r.reason == S.RejectionLimit
  {
    var empty := new T.I[0 as T.I];
    var a := new array<T.I>[9 as T.I](i => empty);
    for k: T.I := 0 to 9
      modifies PolyObjects(a)
      invariant fresh(PolyObjects(a))
      invariant forall h: int :: 0 <= h < k as int ==> S.Sample(rho[..],h/3,h%3) == S.Success(T.Ints(a[h]))
      invariant forall h: int :: 0 <= h < k as int ==> T.Canonical(a[h])
      invariant forall h: int :: k as int <= h < 9 ==> a[h] == empty
      invariant forall h,l: int :: 0 <= h < l < k as int ==> a[h] != a[l]
      invariant empty.Length == 0
    {
      var sample := Sample(rho,k/3,k%3);
      if sample.Failure? {
        assert !S.MatrixReady(rho[..]);
        WipePolys(a);
        assert forall h | 0 <= h < a.Length :: ZeroInts(a[h]);
        return S.Failure(S.RejectionLimit);
      }
      a[k] := sample.value;
    }
    assert S.MatrixReady(rho[..]);
    assert Polys(a) == S.Matrix(rho[..]);
    return S.Success(a);
  }
  method Expand(bytes: array<bv8>, d: T.I) returns(f: array<T.I>)
    requires (d == 1 || d == 4 || d == 10) && bytes.Length == 32*(d as int)
    ensures fresh(f) && T.Canonical(f) && T.Ints(f) == S.Expanded(bytes[..],d as int)
  {
    var decoded := NC.DecodeAndDecompress(bytes,d);
    assert decoded.Decoded?;
    f := decoded.words;
  }
  method {:isolate_assertions} EncodeVector(a: array<array<T.I>>, d: T.I) returns(r: array<bv8>)
    requires Vec(a,3) && C.Width(d as int)
    ensures fresh(r) && r[..] == S.EncodedVector(Polys(a),d as int,3) && r.Length == 96*(d as int)
  {
    ghost var model := Polys(a);
    r := new bv8[96*d];
    ByteOutsidePolys(r,a);
    for i: T.I := 0 to 3
      modifies r
      invariant Polys(a) == model
      invariant r[..(i as int)*32*(d as int)] == S.EncodedVector(model,d as int,i as int)
    {
      assert T.Ints(a[i]) == model[i as int];
      var bytes := NC.CompressAndEncode(a[i],d);
      ghost var part := bytes[..];
      ByteOutsidePolys(bytes,a);
      CopyInto(bytes,r,i*32*d);
      assert r[..((i as int)+1)*32*(d as int)] == S.EncodedVector(model,d as int,i as int)+part;
      assert S.EncodedVector(model,d as int,(i as int)+1) == S.EncodedVector(model,d as int,i as int)+part;
      WipeBytes(bytes);
    }
  }
  method {:isolate_assertions} NoiseVector(seed: array<bv8>, start: T.I, ntt: bool) returns(a: array<array<T.I>>)
    requires seed.Length == 32 && 0 <= start <= 253
    ensures fresh(PolyObjects(a)) && Vec(a,3) && Distinct(a)
    ensures Polys(a) == S.NoiseVector(seed[..],start as int,ntt)
  {
    ghost var model := S.NoiseVector(seed[..],start as int,ntt);
    var empty := new T.I[0 as T.I];
    a := new array<T.I>[3 as T.I](i => empty);
    for i: T.I := 0 to 3
      modifies a
      invariant fresh(PolyObjects(a))
      invariant forall j: int :: 0 <= j < i as int ==> T.Canonical(a[j])
      invariant forall j: int :: 0 <= j < i as int ==> T.Ints(a[j]) == model[j]
      invariant forall j,k: int :: 0 <= j < k < i as int ==> a[j] != a[k]
    {
      var f := Noise(seed,start+i);
      if ntt {
        var transformed := NP.Ntt(f);
        WipeInts(f);
        f := transformed;
      }
      assert T.Ints(f) == model[i as int];
      a[i] := f;
    }
  }
  // A fresh reference view; its coefficient arrays remain borrowed and are
  // never wiped or changed through the view.
  method Row(a: array<array<T.I>>, i: T.I, transposed: bool) returns(r: array<array<T.I>>)
    requires Vec(a,9) && 0 <= i < 3
    ensures fresh(r) && Vec(r,3) && Polys(r) == S.Row(Polys(a),i as int,transposed)
    ensures forall j | 0 <= j < 3 :: r[j] == a[if transposed then 3*j+i as int else 3*(i as int)+j]
  {
    var first := a[0];
    r := new array<T.I>[3 as T.I](j => first);
    for j: T.I := 0 to 3
      modifies r
      invariant forall k: int :: 0 <= k < j as int ==> r[k] == a[if transposed then 3*k+i as int else 3*(i as int)+k]
    { r[j] := a[if transposed then 3*j+i else 3*i+j]; }
  }
  method CopyInts(a: array<T.I>, b: array<T.I>)
    requires a != b && a.Length == b.Length && T.JavaLength(a.Length)
    modifies b
    ensures T.Ints(b) == T.Ints(a) && b[..] == a[..]
    ensures T.Canonical(a) ==> T.Canonical(b)
  {
    var n: T.I := a.Length as T.I;
    for i: T.I := 0 to n
      modifies b
      invariant forall j: int :: 0 <= j < i as int ==> b[j] == a[j]
    { b[i] := a[i]; }
  }
  method {:isolate_assertions} DotStep(accumulator: array<T.I>, a: array<T.I>, b: array<T.I>) returns(r: array<T.I>)
    requires T.Canonical(accumulator) && T.Canonical(a) && T.Canonical(b)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == P.Add(T.Ints(accumulator),P.NttMul(T.Ints(a),T.Ints(b)))
  {
    var term := NP.NttMul(a,b);
    r := NP.Add(accumulator,term);
    WipeInts(term);
  }
  method {:isolate_assertions} Dot(a: array<array<T.I>>, b: array<array<T.I>>) returns(r: array<T.I>)
    requires Vec(a,3) && Vec(b,3)
    ensures fresh(r) && T.Canonical(r) && T.Ints(r) == S.Dot(Polys(a),Polys(b),3)
  {
    ghost var modelA := Polys(a);
    ghost var modelB := Polys(b);
    r := new T.I[256 as T.I];
    assert r !in PolyObjects(a)+PolyObjects(b);
    for i: T.I := 0 to 256
      modifies r
      invariant forall j: int :: 0 <= j < i as int ==> r[j] == 0
    { r[i] := 0; }
    for i: T.I := 0 to 3
      modifies r
      invariant fresh(r) && T.Canonical(r)
      invariant Polys(a) == modelA && Polys(b) == modelB
      invariant T.Ints(r) == S.Dot(modelA,modelB,i as int)
    {
      var next := DotStep(r,a[i],b[i]);
      CopyInts(next,r); WipeInts(next);
    }
  }
  ghost function RowProducts(a: seq<seq<int>>, b: seq<seq<int>>, e: seq<seq<int>>, transposed: bool, inverse: bool): seq<seq<int>>
    requires S.Vec(a,9) && S.Vec(b,3) && S.Vec(e,3)
    ensures S.Vec(RowProducts(a,b,e,transposed,inverse),3)
  {
    seq(3,i requires 0 <= i < 3 => P.Add(
      if inverse then P.InverseNtt(S.Dot(S.Row(a,i,transposed),b,3)) else S.Dot(S.Row(a,i,transposed),b,3),e[i]))
  }
  method RowProduct(a: array<array<T.I>>, b: array<array<T.I>>, e: array<T.I>, i: T.I, transposed: bool, inverse: bool) returns(r: array<T.I>)
    requires Vec(a,9) && Vec(b,3) && T.Canonical(e) && 0 <= i < 3
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == P.Add(if inverse then P.InverseNtt(S.Dot(S.Row(Polys(a),i as int,transposed),Polys(b),3)) else S.Dot(S.Row(Polys(a),i as int,transposed),Polys(b),3),T.Ints(e))
  {
    var row := Row(a,i,transposed);
    var product := Dot(row,b);
    if inverse {
      var transformed := NP.InverseNtt(product);
      WipeInts(product); product := transformed;
    }
    r := NP.Add(product,e);
    WipeInts(product);
  }
  method {:isolate_assertions} MatrixProduct(a: array<array<T.I>>, b: array<array<T.I>>, e: array<array<T.I>>, transposed: bool, inverse: bool) returns(r: array<array<T.I>>)
    requires Vec(a,9) && Vec(b,3) && Vec(e,3)
    ensures fresh(PolyObjects(r)) && Vec(r,3) && Distinct(r)
    ensures Polys(r) == RowProducts(Polys(a),Polys(b),Polys(e),transposed,inverse)
  {
    var empty := new T.I[0 as T.I];
    r := new array<T.I>[3 as T.I](i => empty);
    ghost var model := RowProducts(Polys(a),Polys(b),Polys(e),transposed,inverse);
    for i: T.I := 0 to 3
      modifies r
      invariant fresh(PolyObjects(r))
      invariant forall j: int :: 0 <= j < i as int ==> T.Canonical(r[j])
      invariant forall j: int :: 0 <= j < i as int ==> T.Ints(r[j]) == model[j]
      invariant forall j,k: int :: 0 <= j < k < i as int ==> r[j] != r[k]
    {
      r[i] := RowProduct(a,b,e[i],i,transposed,inverse);
      assert T.Ints(r[i]) == model[i as int];
    }
  }
  lemma ByteOutsidePolys(bytes: array<bv8>, words: array<array<T.I>>)
    requires bytes.Length != words.Length
    requires forall i | 0 <= i < words.Length :: bytes.Length != words[i].Length
    ensures bytes !in PolyObjects(words)
  {}
  lemma SeedOutsidePublic(bytes: array<bv8>, ek: PublicKey)
    requires bytes.Length == 64 && ek.Valid()
    ensures bytes !in ek.Repr()
  {
    ByteOutsidePolys(bytes,ek.matrix);
    ByteOutsidePolys(bytes,ek.t);
  }
  lemma PublicDisjoint(words: array<array<T.I>>, ek: PublicKey)
    requires Vec(words,3) && ek.Valid() && ek !in PolyObjects(words)
    requires PolyObjects(words) !! PolyObjects(ek.matrix)
    requires PolyObjects(words) !! PolyObjects(ek.t)
    ensures PolyObjects(words) !! ek.Repr()
  {
    ByteOutsidePolys(ek.rho,words);
    ByteOutsidePolys(ek.encoded,words);
    ByteOutsidePolys(ek.hash,words);
  }
  lemma KeyGenEquation(seed: seq<bv8>, rho: seq<bv8>, sigma: seq<bv8>, a: seq<seq<int>>, secret: seq<seq<int>>, t: seq<seq<int>>)
    requires |seed| == 64 && |rho| == 32 && |sigma| == 32
    requires J.G(seed[..32]+[3 as bv8]) == rho+sigma
    requires S.MatrixReady(rho) && a == S.Matrix(rho)
    requires secret == S.NoiseVector(sigma,0,true) && t == S.KeyT(a,sigma)
    ensures S.KeyGen(seed) == S.Success(S.SecretKey(seed,secret,S.PublicKey(a,t,rho,S.PublicBytes(t,rho),J.H(S.PublicBytes(t,rho)))))
  {}
  lemma PublicValidity(a: seq<seq<int>>, t: seq<seq<int>>, rho: seq<bv8>, encoded: seq<bv8>, hash: seq<bv8>)
    requires S.Vec(a,9) && S.Vec(t,3) && |rho| == 32
    requires S.MatrixReady(rho) && a == S.Matrix(rho)
    requires encoded == S.PublicBytes(t,rho) && hash == J.H(encoded)
    ensures S.ValidPublic(S.PublicKey(a,t,rho,encoded,hash))
  {}
  ghost function BuiltKey(seed: seq<bv8>, a: seq<seq<int>>, rho: seq<bv8>, sigma: seq<bv8>): S.SecretKey
    requires |seed| == 64 && |rho| == 32 && |sigma| == 32
    requires S.MatrixReady(rho) && a == S.Matrix(rho)
    ensures S.ValidSecret(BuiltKey(seed,a,rho,sigma))
  {
    var t := S.KeyT(a,sigma);
    var encoded := S.PublicBytes(t,rho);
    S.SecretKey(seed,S.NoiseVector(sigma,0,true),S.PublicKey(a,t,rho,encoded,J.H(encoded)))
  }
  lemma BuiltKeyEquation(seed: seq<bv8>, a: seq<seq<int>>, rho: seq<bv8>, sigma: seq<bv8>, secret: seq<seq<int>>, t: seq<seq<int>>, encoded: seq<bv8>, hash: seq<bv8>)
    requires |seed| == 64 && |rho| == 32 && |sigma| == 32
    requires S.MatrixReady(rho) && a == S.Matrix(rho)
    requires secret == S.NoiseVector(sigma,0,true) && t == S.KeyT(a,sigma)
    requires encoded == S.PublicBytes(t,rho) && hash == J.H(encoded)
    ensures S.SecretKey(seed,secret,S.PublicKey(a,t,rho,encoded,hash)) == BuiltKey(seed,a,rho,sigma)
  {}
  method {:isolate_assertions} KeyMaterial(a: array<array<T.I>>, sigma: array<bv8>) returns(secret: array<array<T.I>>, t: array<array<T.I>>)
    requires Vec(a,9) && sigma.Length == 32
    ensures Vec(secret,3) && Vec(t,3) && Distinct(secret) && Distinct(t)
    ensures fresh(PolyObjects(secret)+PolyObjects(t)) && PolyObjects(secret) !! PolyObjects(t)
    ensures Polys(secret) == S.NoiseVector(sigma[..],0,true) && Polys(t) == S.KeyT(Polys(a),sigma[..])
  {
    secret := NoiseVector(sigma,0,true);
    ghost var secretObjects := PolyObjects(secret);
    var error := NoiseVector(sigma,3,true);
    t := MatrixProduct(a,secret,error,false,false);
    assert Polys(t) == S.KeyT(Polys(a),sigma[..]);
    ghost var secretModel := Polys(secret);
    ghost var tModel := Polys(t);
    assert PolyObjects(error) !! (PolyObjects(a)+PolyObjects(secret)+PolyObjects(t)+{sigma});
    WipePolys(error);
    assert Polys(secret) == secretModel && Polys(t) == tModel;
    assert fresh(PolyObjects(secret)) && fresh(PolyObjects(t));
  }
  method {:isolate_assertions} EncodePublic(t: array<array<T.I>>, rho: array<bv8>) returns(encoded: array<bv8>, hash: array<bv8>)
    requires Vec(t,3) && rho.Length == 32
    ensures fresh({encoded,hash}) && encoded != hash
    ensures encoded.Length == 1184 && hash.Length == 32
    ensures encoded[..] == S.PublicBytes(Polys(t),rho[..]) && hash[..] == J.H(encoded[..])
  {
    var prefix := EncodeVector(t,12);
    encoded := Join(prefix,rho);
    ByteOutsidePolys(prefix,t);
    WipeBytes(prefix);
    hash := H.Hash(encoded);
  }
  // Internal ownership transfer of already validated, disjoint arrays.
  method {:isolate_assertions} AssembleKey(retained: array<bv8>, secret: array<array<T.I>>, a: array<array<T.I>>, t: array<array<T.I>>, rho: array<bv8>, encoded: array<bv8>, hash: array<bv8>) returns(dk: SecretKey)
    requires retained.Length == 64 && Vec(secret,3) && Vec(a,9) && Vec(t,3)
    requires Distinct(secret) && Distinct(a) && Distinct(t)
    requires PolyObjects(secret) !! PolyObjects(a) && PolyObjects(secret) !! PolyObjects(t) && PolyObjects(a) !! PolyObjects(t)
    requires S.ValidPublic(S.PublicKey(Polys(a),Polys(t),rho[..],encoded[..],hash[..]))
    requires rho != encoded && rho != hash && encoded != hash
    ensures dk.Valid() && fresh({dk,dk.ek})
    ensures dk.Model() == old(S.SecretKey(retained[..],Polys(secret),S.PublicKey(Polys(a),Polys(t),rho[..],encoded[..],hash[..])))
    ensures dk.seed == retained && dk.s == secret && dk.ek.matrix == a && dk.ek.t == t
    ensures dk.ek.rho == rho && dk.ek.encoded == encoded && dk.ek.hash == hash
    ensures dk.Repr() == {dk,dk.ek,retained,rho,encoded,hash}+PolyObjects(secret)+PolyObjects(a)+PolyObjects(t)
  {
    var ek := new PublicKey(a,t,rho,encoded,hash);
    assert ek !in PolyObjects(secret);
    PublicDisjoint(secret,ek);
    SeedOutsidePublic(retained,ek);
    dk := new SecretKey(retained,secret,ek);
  }
  // a and rho were allocated by KeyGen; the remaining key objects are fresh.
  method {:isolate_assertions} BuildKey(seed: array<bv8>, a: array<array<T.I>>, rho: array<bv8>, sigma: array<bv8>) returns(dk: SecretKey, ghost allocatedObjects: set<object>)
    requires seed.Length == 64 && rho.Length == 32 && sigma.Length == 32 && rho != sigma
    requires Vec(a,9) && Distinct(a) && S.MatrixReady(rho[..]) && Polys(a) == S.Matrix(rho[..])
    ensures dk.Valid() && dk.Model() == BuiltKey(seed[..],Polys(a),rho[..],sigma[..])
    ensures dk.ek.matrix == a && dk.ek.rho == rho
    ensures fresh(dk.Repr()-(PolyObjects(a)+{rho}))
    ensures fresh(PolyObjects(dk.s)+PolyObjects(dk.ek.t)+{dk,dk.ek,dk.seed,dk.ek.encoded,dk.ek.hash})
    ensures {seed,sigma} !! dk.Repr()
    ensures fresh(allocatedObjects) && dk.Repr() <= allocatedObjects+PolyObjects(a)+{rho}
  {
    ghost var borrowed: set<object> := {seed,sigma};
    assert forall obj: object | obj in borrowed :: old(allocated(obj));
    ghost var inputObjects := PolyObjects(a);
    var secret,t := KeyMaterial(a,sigma);
    ghost var materialObjects := PolyObjects(secret)+PolyObjects(t);
    assert fresh(materialObjects) && materialObjects !! inputObjects;
    var encoded,hash := EncodePublic(t,rho);
    assert fresh({encoded,hash});
    var retained := Slice(seed,0,64);
    assert fresh(retained);
    BuiltKeyEquation(seed[..],Polys(a),rho[..],sigma[..],Polys(secret),Polys(t),encoded[..],hash[..]);
    PublicValidity(Polys(a),Polys(t),rho[..],encoded[..],hash[..]);
    dk := AssembleKey(retained,secret,a,t,rho,encoded,hash);
    assert fresh({dk,dk.ek});
    ghost var created: set<object> := materialObjects;
    FreshSetUnion(created,{encoded,hash}); created := created+{encoded,hash};
    FreshSetUnion(created,{retained}); created := created+{retained};
    FreshSetUnion(created,{dk,dk.ek}); created := created+{dk,dk.ek};
    assert fresh(created);
    assert dk.Repr()-(PolyObjects(a)+{rho}) <= created;
    FreshSubset(dk.Repr()-(PolyObjects(a)+{rho}),created);
    ByteOutsidePolys(seed,a); ByteOutsidePolys(sigma,a);
    FreshDisjoint(created,borrowed);
    assert {seed,sigma} !! (PolyObjects(a)+{rho});
    assert dk.Repr() <= created+PolyObjects(a)+{rho};
    allocatedObjects := created;
  }
  method {:isolate_assertions} KeyGen(seed: array<bv8>) returns(r: S.Result<SecretKey>)
    ensures ModelSecret(r) == S.KeyGen(seed[..])
    ensures r.Success? ==> r.value.Valid() && fresh(r.value.Repr())
  {
    if seed.Length != 64 { return S.Failure(S.InvalidSeedLength); }
    var d := Slice(seed,0,32);
    var tagged := Tag(d,3);
    var g := H.Expand(tagged);
    var rho := Slice(g,0,32); var sigma := Slice(g,32,32);
    ghost var sigmaModel := sigma[..];
    assert J.G(seed[..32]+[3 as bv8]) == rho[..]+sigmaModel;
    WipeBytes(d); WipeBytes(tagged); WipeBytes(g);
    assert ZeroBytes(d) && ZeroBytes(tagged) && ZeroBytes(g);
    var expanded := ExpandMatrix(rho);
    if expanded.Failure? {
      assert S.KeyGen(seed[..]) == S.Failure(S.RejectionLimit);
      WipeBytes(rho); WipeBytes(sigma);
      assert ZeroBytes(rho) && ZeroBytes(sigma);
      return S.Failure(S.RejectionLimit);
    }
    var a := expanded.value;
    ghost var transferred := PolyObjects(a)+{rho};
    assert fresh(transferred);
    var dk, created := BuildKey(seed,a,rho,sigma);
    assert fresh(created);
    assert dk.Repr() <= created+transferred;
    FreshSetUnion(created,transferred);
    FreshSubset(dk.Repr(),created+transferred);
    assert fresh(dk.Repr());
    ghost var model := dk.Model();
    WipeBytePreservingKey(sigma,dk);
    assert ZeroBytes(sigma) && dk.Model() == model && dk.Valid();
    KeyGenEquation(seed[..],rho[..],sigmaModel,Polys(a),Polys(dk.s),Polys(dk.ek.t));
    assert S.Success(dk.Model()) == S.KeyGen(seed[..]);
    return S.Success(dk);
  }
  method {:isolate_assertions} DecodeKeyPart(bytes: array<bv8>, i: T.I) returns(f: NC.DecodeResult)
    requires bytes.Length == 1184 && 0 <= i < 3
    ensures NC.Model(f) == C.Decode(bytes[384*(i as int)..384*((i as int)+1)],12)
    ensures f.Decoded? ==> fresh(f.words) && T.Canonical(f.words)
  {
    var part := Slice(bytes,384*i,384);
    f := NC.Decode(part,12);
    ghost var model := NC.Model(f);
    if f.Decoded? {
      NativeCanonical(f.words);
      assert f.words.Length == 256;
      assert part as object != f.words as object;
    }
    WipeBytes(part);
    assert NC.Model(f) == model;
  }
  ghost predicate KeyDecoded(bytes: seq<bv8>) {
    |bytes| == 1184 && forall j | 0 <= j < 3 :: C.Decode(bytes[384*j..384*(j+1)],12).Decoded?
  }
  ghost function CheckedWords(bytes: seq<bv8>): S.Result<seq<seq<int>>>
    requires |bytes| == 1184
  { if KeyDecoded(bytes) then S.Success(S.KeyWords(bytes)) else S.Failure(S.ModulusError) }
  method {:isolate_assertions} ParseWords(bytes: array<bv8>) returns(r: S.Result<array<array<T.I>>>)
    requires bytes.Length == 1184
    ensures ModelMatrix(r) == CheckedWords(bytes[..])
    ensures r.Success? ==> Vec(r.value,3) && Distinct(r.value) && fresh(PolyObjects(r.value))
  {
    ghost var model := bytes[..];
    var empty := new T.I[0 as T.I];
    var t := new array<T.I>[3 as T.I](i => empty);
    var failed := false;
    var i: T.I := 0;
    while i < 3 && !failed
      modifies t
      invariant 0 <= i <= 3
      invariant fresh(PolyObjects(t))
      invariant failed ==> !KeyDecoded(model)
      invariant forall j: int :: 0 <= j < i as int ==> T.Canonical(t[j])
      invariant forall j: int :: 0 <= j < i as int ==> C.Decode(model[384*j..384*(j+1)],12) == C.Decoded(T.Ints(t[j]))
      invariant forall j: int :: i as int <= j < 3 ==> t[j] == empty
      invariant forall j,k: int :: 0 <= j < k < i as int ==> t[j] != t[k]
      decreases 3-i, if failed then 0 else 1
    {
      var f := DecodeKeyPart(bytes,i);
      if !f.Decoded? {
        assert !C.Decode(model[384*(i as int)..384*((i as int)+1)],12).Decoded?;
        failed := true;
      } else {
        t[i] := f.words;
        i := i+1;
      }
    }
    if failed {
      WipePolys(t);
      assert forall j | 0 <= j < 3 :: ZeroInts(t[j]);
      return S.Failure(S.ModulusError);
    }
    forall j | 0 <= j < 3
      ensures C.Decode(model[384*j..384*(j+1)],12).Decoded?
    { assert C.Decode(model[384*j..384*(j+1)],12) == C.Decoded(T.Ints(t[j])); }
    assert KeyDecoded(model);
    assert Polys(t) == S.KeyWords(model);
    return S.Success(t);
  }
  lemma ParseEquation(bytes: seq<bv8>, rho: seq<bv8>, a: seq<seq<int>>, t: seq<seq<int>>)
    requires KeyDecoded(bytes) && rho == bytes[1152..]
    requires S.MatrixReady(rho) && a == S.Matrix(rho) && t == S.KeyWords(bytes)
    ensures S.Parse(bytes) == S.Success(S.PublicKey(a,t,rho,bytes,J.H(bytes)))
    ensures S.ValidPublic(S.PublicKey(a,t,rho,bytes,J.H(bytes)))
  { S.CheckedKeyEncoding(bytes); }
  lemma ParseMatrixFailure(bytes: seq<bv8>)
    requires KeyDecoded(bytes) && !S.MatrixReady(bytes[1152..])
    ensures S.Parse(bytes) == S.Failure(S.RejectionLimit)
  {}
  method {:isolate_assertions} Parse(bytes: array<bv8>) returns(r: S.Result<PublicKey>)
    ensures ModelPublic(r) == S.Parse(bytes[..])
    ensures r.Success? ==> r.value.Valid() && fresh(r.value.Repr())
  {
    if bytes.Length != 1184 { return S.Failure(S.InvalidKeyLength); }
    ghost var model := bytes[..];
    var words := ParseWords(bytes);
    if words.Failure? { return S.Failure(S.ModulusError); }
    var t := words.value;
    ghost var tObjects := PolyObjects(t);
    assert fresh(tObjects);
    assert KeyDecoded(model) && Polys(t) == S.KeyWords(model);
    var rho := Slice(bytes,1152,32);
    assert rho[..] == model[1152..];
    var a := ExpandMatrix(rho);
    if a.Failure? {
      ParseMatrixFailure(model);
      WipePolys(t); WipeBytes(rho);
      assert ZeroBytes(rho) && forall j | 0 <= j < 3 :: ZeroInts(t[j]);
      return S.Failure(S.RejectionLimit);
    }
    ghost var aObjects := PolyObjects(a.value);
    assert fresh(aObjects) && aObjects !! tObjects;
    var encoded := Slice(bytes,0,1184);
    var hash := H.Hash(bytes);
    ParseEquation(model,rho[..],Polys(a.value),Polys(t));
    var ek := new PublicKey(a.value,t,rho,encoded,hash);
    assert ek.Model() == S.PublicKey(Polys(a.value),Polys(t),rho[..],model,J.H(model));
    ghost var created: set<object> := {ek,rho,encoded,hash}+aObjects+tObjects;
    forall obj: object | obj in created
      ensures !old(allocated(obj))
    { if obj in aObjects {} else if obj in tObjects {} else {
      assert obj == ek || obj == rho || obj == encoded || obj == hash;
    } }
    assert ek.Repr() == created;
    return S.Success(ek);
  }
  method {:isolate_assertions} EncryptU(a: array<array<T.I>>, y: array<array<T.I>>, coins: array<bv8>) returns(c1: array<bv8>)
    requires Vec(a,9) && Vec(y,3) && coins.Length == 32
    requires Polys(y) == S.NoiseVector(coins[..],0,true)
    ensures fresh(c1) && c1.Length == 960
    ensures c1[..] == S.EncodedVector(S.U(Polys(a),coins[..]),10,3)
  {
    ghost var model := S.EncodedVector(S.U(Polys(a),coins[..]),10,3);
    var e1 := NoiseVector(coins,3,false);
    var u := MatrixProduct(a,y,e1,true,true);
    assert Polys(u) == S.U(Polys(a),coins[..]);
    c1 := EncodeVector(u,10);
    assert c1[..] == model;
    assert (PolyObjects(e1)+PolyObjects(u)) !! (PolyObjects(a)+PolyObjects(y)+{coins,c1});
    WipePolys(e1); WipePolys(u);
    assert c1[..] == model;
  }
  method {:isolate_assertions} EncryptV(t: array<array<T.I>>, y: array<array<T.I>>, m: array<bv8>, coins: array<bv8>) returns(c2: array<bv8>)
    requires Vec(t,3) && Vec(y,3) && m.Length == 32 && coins.Length == 32
    requires Polys(y) == S.NoiseVector(coins[..],0,true)
    ensures fresh(c2) && c2.Length == 128
    ensures c2[..] == C.Encoded(C.CompressedWords(S.V(Polys(t),m[..],coins[..]),4),4)
  {
    ghost var model := C.Encoded(C.CompressedWords(S.V(Polys(t),m[..],coins[..]),4),4);
    var e2 := Noise(coins,6);
    var mu := Expand(m,1);
    var product := Dot(t,y);
    var inverse := NP.InverseNtt(product);
    var noisy := NP.Add(inverse,e2);
    var v := NP.Add(noisy,mu);
    assert T.Ints(v) == S.V(Polys(t),m[..],coins[..]);
    c2 := NC.CompressAndEncode(v,4);
    assert c2[..] == model;
    assert {e2,mu,product,inverse,noisy,v} !! (PolyObjects(t)+PolyObjects(y)+{m,coins,c2});
    WipeInts(e2); WipeInts(mu); WipeInts(product); WipeInts(inverse); WipeInts(noisy); WipeInts(v);
    assert unchanged(old(PolyObjects(t)));
    PreservePolys(t);
    assert c2[..] == model;
  }
  method {:isolate_assertions} Encrypt(ek: PublicKey, m: array<bv8>, coins: array<bv8>) returns(ciphertext: array<bv8>)
    requires ek.Valid() && m.Length == 32 && coins.Length == 32
    ensures fresh(ciphertext) && ciphertext.Length == 1088
    ensures ciphertext[..] == S.Encrypt(ek.Model(),m[..],coins[..])
  {
    ghost var model := S.Encrypt(ek.Model(),m[..],coins[..]);
    var y := NoiseVector(coins,0,true);
    var c1 := EncryptU(ek.matrix,y,coins);
    var c2 := EncryptV(ek.t,y,m,coins);
    ciphertext := Join(c1,c2);
    assert ciphertext[..] == model;
    assert (PolyObjects(y)+{c1,c2}) !! (ek.Repr()+{m,coins,ciphertext});
    WipePolys(y); WipeBytes(c1); WipeBytes(c2);
    assert unchanged(old(ek.Repr()));
    PreservePublic(ek);
    assert ciphertext[..] == model;
  }
  ghost function CipherU(c: seq<bv8>): seq<seq<int>>
    requires |c| == 1088
    ensures S.Vec(CipherU(c),3)
  { seq(3,i requires 0 <= i < 3 => P.Ntt(S.Expanded(c[320*i..320*(i+1)],10))) }
  method {:isolate_assertions} CipherPart(c: array<bv8>, i: T.I) returns(r: array<T.I>)
    requires c.Length == 1088 && 0 <= i < 3
    ensures fresh(r) && T.Canonical(r) && T.Ints(r) == CipherU(c[..])[i as int]
  {
    var part := Slice(c,320*i,320);
    var f := Expand(part,10);
    r := NP.Ntt(f);
    assert T.Ints(r) == CipherU(c[..])[i as int];
    WipeBytes(part); WipeInts(f);
  }
  method {:isolate_assertions} DecodeCipherU(c: array<bv8>) returns(u: array<array<T.I>>)
    requires c.Length == 1088
    ensures fresh(PolyObjects(u)) && Vec(u,3) && Polys(u) == CipherU(c[..])
  {
    ghost var model := CipherU(c[..]);
    var empty := new T.I[0 as T.I];
    u := new array<T.I>[3 as T.I](i => empty);
    for i: T.I := 0 to 3
      modifies u
      invariant fresh(PolyObjects(u))
      invariant forall j: int :: 0 <= j < i as int ==> T.Canonical(u[j])
      invariant forall j: int :: 0 <= j < i as int ==> T.Ints(u[j]) == model[j]
    { u[i] := CipherPart(c,i); }
  }
  lemma DecryptEquation(s: seq<seq<int>>, c: seq<bv8>, w: seq<int>, m: seq<bv8>)
    requires S.Vec(s,3) && |c| == 1088
    requires w == P.Sub(S.Expanded(c[960..],4),P.InverseNtt(S.Dot(s,CipherU(c),3)))
    requires m == C.Encoded(C.CompressedWords(w,1),1)
    ensures m == S.Decrypt(s,c)
  {}
  method {:isolate_assertions} DecryptMask(secret: array<array<T.I>>, ciphertext: array<bv8>) returns(mask: array<T.I>)
    requires Vec(secret,3) && ciphertext.Length == 1088
    ensures fresh(mask) && T.Canonical(mask)
    ensures T.Ints(mask) == P.InverseNtt(S.Dot(Polys(secret),CipherU(ciphertext[..]),3))
  {
    ghost var model := P.InverseNtt(S.Dot(Polys(secret),CipherU(ciphertext[..]),3));
    var u := DecodeCipherU(ciphertext);
    ghost var uObjects := PolyObjects(u);
    assert fresh(uObjects);
    var product := Dot(secret,u);
    mask := NP.InverseNtt(product);
    assert T.Ints(mask) == model;
    assert uObjects !! (PolyObjects(secret)+{ciphertext as object,mask});
    assert product !in PolyObjects(secret) && product as object != ciphertext as object && product != mask;
    WipePolys(u); WipeInts(product);
    assert T.Ints(mask) == model;
  }
  method {:isolate_assertions} Decrypt(secret: array<array<T.I>>, ciphertext: array<bv8>) returns(m: array<bv8>)
    requires Vec(secret,3) && ciphertext.Length == 1088
    ensures fresh(m) && m.Length == 32 && m[..] == S.Decrypt(Polys(secret),ciphertext[..])
  {
    ghost var model := S.Decrypt(Polys(secret),ciphertext[..]);
    ghost var sModel := Polys(secret);
    ghost var cModel := ciphertext[..];
    var mask := DecryptMask(secret,ciphertext);
    var last := Slice(ciphertext,960,128);
    assert last[..] == cModel[960..];
    var v := Expand(last,4);
    var w := NP.Sub(v,mask);
    m := NC.CompressAndEncode(w,1);
    assert T.Ints(w) == P.Sub(S.Expanded(cModel[960..],4),P.InverseNtt(S.Dot(sModel,CipherU(cModel),3)));
    DecryptEquation(sModel,cModel,T.Ints(w),m[..]);
    assert m[..] == model;
    assert {mask as object,last,v,w} !! (PolyObjects(secret)+{ciphertext,m});
    WipeInts(mask); WipeBytes(last); WipeInts(v); WipeInts(w);
    assert m[..] == model;
  }
  lemma EncapsEquation(bytes: seq<bv8>, m: seq<bv8>, ek: S.PublicKey, g: seq<bv8>, key: seq<bv8>, ciphertext: seq<bv8>)
    requires S.Parse(bytes) == S.Success(ek) && |m| == 32
    requires g == J.G(m+ek.hash) && key == g[..32]
    requires ciphertext == S.Encrypt(ek,m,g[32..])
    ensures S.Success(S.Encapsulation(key,ciphertext)) == S.Encaps(bytes,m)
  {}
  lemma DecapsEquation(dk: S.SecretKey, c: seq<bv8>, m: seq<bv8>, g: seq<bv8>, fallback: seq<bv8>, expected: seq<bv8>, key: seq<bv8>)
    requires S.ValidSecret(dk) && |c| == 1088
    requires m == S.Decrypt(dk.s,c) && g == J.G(m+dk.ek.hash)
    requires fallback == SX.Xof(136,dk.seed[32..]+c,32)
    requires expected == S.Encrypt(dk.ek,m,g[32..])
    requires key == (if c == expected then g[..32] else fallback)
    ensures S.Success(key) == S.Decaps(dk,c)
  {}
  method {:isolate_assertions} Encaps(bytes: array<bv8>, m: array<bv8>) returns(r: S.Result<Encapsulation>)
    ensures ModelEncapsulation(r) == S.Encaps(bytes[..],m[..])
    ensures r.Success? ==> fresh(r.value.key) && fresh(r.value.ciphertext)
    ensures r.Success? ==> r.value.key.Length == 32 && r.value.ciphertext.Length == 1088 && r.value.key != r.value.ciphertext
  {
    ghost var specification := S.Encaps(bytes[..],m[..]);
    var parsed := Parse(bytes);
    if parsed.Failure? {
      assert specification == S.Failure(parsed.reason);
      return S.Failure(parsed.reason);
    }
    var ek := parsed.value;
    if m.Length != 32 {
      assert specification == S.Failure(S.InvalidMessageLength);
      ek.Destroy(); return S.Failure(S.InvalidMessageLength);
    }
    var input := Join(m,ek.hash);
    var g := H.Expand(input);
    var coins := Slice(g,32,32);
    assert coins[..] == g[32..64];
    assert g.Length == 64 && g[32..64] == g[32..];
    assert coins[..] == g[32..];
    ghost var ekModel := ek.Model();
    ghost var mModel := m[..];
    ghost var coinsModel := coins[..];
    var ciphertext := Encrypt(ek,m,coins);
    assert ciphertext[..] == S.Encrypt(ekModel,mModel,coinsModel);
    assert ek.Model() == ekModel && m[..] == mModel && g[32..] == coinsModel;
    var key := Slice(g,0,32);
    assert ciphertext[..] == S.Encrypt(ek.Model(),m[..],g[32..]);
    EncapsEquation(bytes[..],m[..],ek.Model(),g[..],key[..],ciphertext[..]);
    assert S.Success(S.Encapsulation(key[..],ciphertext[..])) == S.Encaps(bytes[..],m[..]);
    r := S.Success(Encapsulation(key,ciphertext));
    assert ModelEncapsulation(r) == specification;
    ghost var outputModel := ModelEncapsulation(r);
    assert ek.Repr() !! {bytes,m,key,ciphertext};
    ek.Destroy(); WipeBytes(input); WipeBytes(g); WipeBytes(coins);
    assert ModelEncapsulation(r) == outputModel;
    assert specification == S.Encaps(bytes[..],m[..]);
  }
  lemma CollectedBuffers(a: object, b: object, c: object, d: object, e: object, f: object, g: object, h: object, i: object)
    ensures {a}+{b}+{c}+{d}+{e}+{f}+{g}+{h}+{i} == {a,b,c,d,e,f,g,h,i}
  {}
  lemma AllocatedSet(a: set<object>)
    ensures forall obj: object | obj in a :: allocated(obj)
  {}
  twostate lemma FreshDisjoint(new created: set<object>, new prior: set<object>)
    requires fresh(created)
    requires forall obj: object | obj in prior :: old(allocated(obj))
    ensures created !! prior
  {}
  twostate lemma FreshSubset(new a: set<object>, new b: set<object>)
    requires a <= b && fresh(b)
    ensures fresh(a)
  {}
  twostate lemma FreshSetUnion(new a: set<object>, new b: set<object>)
    requires fresh(a) && fresh(b)
    ensures fresh(a+b)
  {}
  twostate lemma PreservePublic(ek: PublicKey)
    requires old(ek.Valid()) && unchanged(old(ek.Repr()))
    ensures ek.Valid() && ek.Model() == old(ek.Model()) && ek.Repr() == old(ek.Repr())
  {
    PreservePolys(ek.matrix); PreservePolys(ek.t);
    assert ek.rho[..] == old(ek.rho[..]);
    assert ek.encoded[..] == old(ek.encoded[..]);
    assert ek.hash[..] == old(ek.hash[..]);
  }
  twostate lemma PreservePolys(a: array<array<T.I>>)
    requires unchanged(old(PolyObjects(a)))
    ensures Polys(a) == old(Polys(a))
    ensures PolyObjects(a) == old(PolyObjects(a))
  {
    assert a[..] == old(a[..]);
    forall i | 0 <= i < a.Length
      ensures Polys(a)[i] == old(Polys(a))[i]
    {
      assert a[i] == old(a[i]);
      assert a[i][..] == old(a[i][..]);
      assert T.Ints(a[i]) == old(T.Ints(a[i]));
    }
  }
  twostate lemma PreserveSecret(dk: SecretKey)
    requires old(dk.Valid()) && unchanged(old(dk.Repr()))
    ensures dk.Valid() && dk.Model() == old(dk.Model()) && dk.Repr() == old(dk.Repr())
  {
    PreservePolys(dk.s); PreservePolys(dk.ek.matrix); PreservePolys(dk.ek.t);
    assert dk.seed[..] == old(dk.seed[..]);
    assert dk.ek.rho[..] == old(dk.ek.rho[..]);
    assert dk.ek.encoded[..] == old(dk.ek.encoded[..]);
    assert dk.ek.hash[..] == old(dk.ek.hash[..]);
    assert dk.ek.Model() == old(dk.ek.Model());
    assert dk.Model() == old(dk.Model());
  }
  method {:isolate_assertions} WipeBytePreservingKey(a: array<bv8>, ghost dk: SecretKey)
    requires T.JavaLength(a.Length) && dk.Valid() && a !in dk.Repr()
    modifies a
    ensures ZeroBytes(a) && dk.Valid() && dk.Model() == old(dk.Model()) && dk.Repr() == old(dk.Repr())
  {
    WipeBytes(a);
    assert unchanged(old(dk.Repr()));
    PreserveSecret(dk);
  }
  method {:isolate_assertions} WipeDecapsBuffers(m: array<bv8>, input: array<bv8>, g: array<bv8>, z: array<bv8>, rejectionInput: array<bv8>, fallback: array<bv8>, coins: array<bv8>, expected: array<bv8>, candidate: array<bv8>, ghost dk: SecretKey)
    requires T.JavaLength(m.Length) && T.JavaLength(input.Length) && T.JavaLength(g.Length)
    requires T.JavaLength(z.Length) && T.JavaLength(rejectionInput.Length) && T.JavaLength(fallback.Length)
    requires T.JavaLength(coins.Length) && T.JavaLength(expected.Length) && T.JavaLength(candidate.Length)
    requires dk.Valid() && {m,input,g,z,rejectionInput,fallback,coins,expected,candidate} !! dk.Repr()
    modifies m,input,g,z,rejectionInput,fallback,coins,expected,candidate
    ensures dk.Valid() && dk.Model() == old(dk.Model())
    ensures ZeroBytes(m) && ZeroBytes(input) && ZeroBytes(g) && ZeroBytes(z) && ZeroBytes(rejectionInput)
    ensures ZeroBytes(fallback) && ZeroBytes(coins) && ZeroBytes(expected) && ZeroBytes(candidate)
  {
    WipeBytes(m); WipeBytes(input); WipeBytes(g); WipeBytes(z); WipeBytes(rejectionInput);
    WipeBytes(fallback); WipeBytes(coins); WipeBytes(expected); WipeBytes(candidate);
    assert unchanged(old(dk.Repr()));
    PreserveSecret(dk);
  }
  method {:isolate_assertions} Decaps(dk: SecretKey, ciphertext: array<bv8>) returns(r: S.Result<array<bv8>>)
    requires dk.Valid()
    ensures ModelBytes(r) == S.Decaps(dk.Model(),ciphertext[..])
    ensures r.Success? ==> fresh(r.value) && r.value.Length == 32
  {
    ghost var dkModel := dk.Model();
    ghost var cipherModel := ciphertext[..];
    ghost var borrowed := dk.Repr()+{ciphertext};
    assert forall obj: object | obj in borrowed :: old(allocated(obj));
    assert S.ValidSecret(dkModel);
    ghost var specification := S.Decaps(dkModel,cipherModel);
    if ciphertext.Length != 1088 { return S.Failure(S.InvalidCiphertextLength); }
    var m := Decrypt(dk.s,ciphertext);
    assert fresh(m);
    ghost var discarded: set<object> := {m};
    var input := Join(m,dk.ek.hash);
    assert fresh(input);
    FreshSetUnion(discarded,{input});
    discarded := discarded+{input};
    var g := H.Expand(input);
    assert fresh(g);
    FreshSetUnion(discarded,{g});
    discarded := discarded+{g};
    var z := Slice(dk.seed,32,32);
    assert fresh(z);
    FreshSetUnion(discarded,{z});
    discarded := discarded+{z};
    assert z[..] == dk.seed[32..64];
    assert dk.seed.Length == 64 && dk.seed[32..64] == dk.seed[32..];
    var rejectionInput := Join(z,ciphertext);
    assert fresh(rejectionInput);
    FreshSetUnion(discarded,{rejectionInput});
    discarded := discarded+{rejectionInput};
    assert rejectionInput[..] == dk.seed[32..]+ciphertext[..];
    var fallback := X.Xof(136,rejectionInput,32);
    assert fresh(fallback);
    FreshSetUnion(discarded,{fallback});
    discarded := discarded+{fallback};
    assert fallback[..] == SX.Xof(136,dk.seed[32..]+ciphertext[..],32);
    var coins := Slice(g,32,32);
    assert fresh(coins);
    FreshSetUnion(discarded,{coins});
    discarded := discarded+{coins};
    assert coins[..] == g[32..64];
    assert g.Length == 64 && g[32..64] == g[32..];
    assert coins[..] == g[32..];
    ghost var plainModel := m[..];
    ghost var coinsModel := coins[..];
    var expected := Encrypt(dk.ek,m,coins);
    assert fresh(expected);
    FreshSetUnion(discarded,{expected});
    discarded := discarded+{expected};
    assert expected[..] == S.Encrypt(dkModel.ek,plainModel,coinsModel);
    assert dk.Model() == dkModel && m[..] == plainModel && g[32..] == coinsModel;
    var candidate := Slice(g,0,32);
    assert fresh(candidate);
    FreshSetUnion(discarded,{candidate});
    discarded := discarded+{candidate};
    CollectedBuffers(m,input,g,z,rejectionInput,fallback,coins,expected,candidate);
    assert discarded == {m,input,g,z,rejectionInput,fallback,coins,expected,candidate};
    assert fresh(discarded);
    forall obj: object | obj in borrowed
      ensures obj !in discarded
    { assert old(allocated(obj)); }
    assert discarded !! borrowed;
    AllocatedSet(discarded);
    label BeforeSelection:
    var key := Select(ciphertext,expected,candidate,fallback);
    assert !old@BeforeSelection(allocated(key));
    assert forall obj: object | obj in discarded :: old@BeforeSelection(allocated(obj));
    assert fresh(key) && key !in discarded;
    DecapsEquation(dkModel,cipherModel,m[..],g[..],fallback[..],expected[..],key[..]);
    assert S.Success(key[..]) == S.Decaps(dk.Model(),ciphertext[..]);
    r := S.Success(key);
    assert ModelBytes(r) == specification;
    ghost var outputModel := ModelBytes(r);
    assert unchanged(old(dk.Repr()));
    PreserveSecret(dk);
    assert dk.Model() == dkModel && borrowed == dk.Repr()+{ciphertext};
    assert {m,input,g,z,rejectionInput,fallback,coins,expected,candidate} !! dk.Repr();
    WipeDecapsBuffers(m,input,g,z,rejectionInput,fallback,coins,expected,candidate,dk);
    assert ModelBytes(r) == outputModel;
    assert dk.Model() == dkModel && ciphertext[..] == cipherModel;
    assert S.ValidSecret(dk.Model());
    assert specification == S.Decaps(dk.Model(),ciphertext[..]);
  }
  method {:isolate_assertions} DecapsAndDestroy(dk: SecretKey, ciphertext: array<bv8>) returns(r: S.Result<array<bv8>>)
    requires dk.Valid() && ciphertext.Length == 1088 && ciphertext !in dk.Repr()
    modifies dk.Repr()
    ensures ModelBytes(r) == old(S.Decaps(dk.Model(),ciphertext[..]))
    ensures r.Success? && fresh(r.value) && r.value.Length == 32
    ensures dk.destroyed && ZeroBytes(dk.seed) && dk.ek.destroyed
  {
    ghost var prior := dk.Repr();
    assert forall obj: object | obj in prior :: old(allocated(obj));
    r := Decaps(dk,ciphertext);
    assert r.Success?;
    FreshDisjoint({r.value},prior);
    assert dk.Repr() == prior;
    ghost var resultModel := ModelBytes(r);
    dk.Destroy();
    assert ModelBytes(r) == resultModel;
  }
  method {:isolate_assertions} DecapsFromSeed(seed: array<bv8>, ciphertext: array<bv8>) returns(r: S.Result<array<bv8>>)
    ensures ModelBytes(r) == S.DecapsFromSeed(seed[..],ciphertext[..])
    ensures r.Success? ==> fresh(r.value) && r.value.Length == 32
  {
    if ciphertext.Length != 1088 { return S.Failure(S.InvalidCiphertextLength); }
    var generated := KeyGen(seed);
    if generated.Failure? { return S.Failure(generated.reason); }
    var dk := generated.value;
    ghost var model := dk.Model();
    FreshDisjoint(dk.Repr(),{ciphertext});
    assert S.DecapsFromSeed(seed[..],ciphertext[..]) == S.Decaps(model,ciphertext[..]);
    r := DecapsAndDestroy(dk,ciphertext);
  }
  method {:isolate_assertions} SerializeSecret(dk: SecretKey) returns(r: array<bv8>)
    requires dk.Valid()
    ensures fresh(r) && r.Length == 2400 && r[..] == S.SerializedSecret(dk.Model())
  {
    ghost var model := dk.Model();
    var secret := EncodeVector(dk.s,12);
    assert secret[..] == S.EncodedVector(model.s,12,3);
    var z := Slice(dk.seed,32,32);
    assert z[..] == model.seed[32..];
    r := new bv8[2400 as T.I];
    CopyInto(secret,r,0); CopyInto(dk.ek.encoded,r,1152); CopyInto(dk.ek.hash,r,2336); CopyInto(z,r,2368);
    assert unchanged(old(dk.Repr()));
    PreserveSecret(dk);
    assert r[..1152] == secret[..];
    assert r[1152..2336] == model.ek.encoded;
    assert r[2336..2368] == model.ek.hash;
    assert r[2368..] == z[..];
    assert r[..] == secret[..]+model.ek.encoded+model.ek.hash+z[..];
    assert r[..] == S.SerializedSecret(model);
    WipeBytes(secret); WipeBytes(z);
    assert unchanged(old(dk.Repr()));
    PreserveSecret(dk);
  }
}
