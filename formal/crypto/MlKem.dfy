include "KemSpec.dfy"

// Composition formulas adapted from Go src/crypto/internal/fips140/mlkem
// via MlKem768.java (Copyright 2023 The Go Authors, BSD-3-Clause).
// Dafny specifications, total failure contracts and proofs are new work.
module VerifiedMlKem {
  import S = KemSpec
  import P = PolySpec
  import VP = VerifiedPolynomial
  import C = CodecSpec
  import VC = VerifiedCodec
  import VS = VerifiedSampling
  import SS = SamplingSpec
  import X = VerifiedShake
  import H = JdkHash

  method Select(c: seq<bv8>, expected: seq<bv8>, candidate: seq<bv8>, fallback: seq<bv8>) returns (r: seq<bv8>)
    requires |c| == 1088 && |expected| == 1088 && |candidate| == 32 && |fallback| == 32
    ensures r == (if c == expected then candidate else fallback)
  {
    var diff: bv8 := 0;
    for i := 0 to 1088
      invariant diff == 0 <==> c[..i] == expected[..i]
    {
      ghost var before := diff;
      diff := diff | (c[i] ^ expected[i]);
      assert diff == 0 <==> before == 0 && c[i] == expected[i];
      assert c[..i+1] == c[..i]+[c[i]];
      assert expected[..i+1] == expected[..i]+[expected[i]];
    }
    var mask := (((diff as bv16)-1) >> 8) as bv8;
    assert mask == (if diff == 0 then 255 else 0);
    var a := new bv8[32];
    for i := 0 to 32
      invariant forall j | 0 <= j < i :: a[j] == (if c == expected then candidate[j] else fallback[j])
    { a[i] := (candidate[i] & mask) | (fallback[i] & !mask); }
    r := a[..];
  }

  method Noise(seed: seq<bv8>, nonce: nat) returns (r: seq<int>)
    requires |seed| == 32 && nonce < 256
    ensures P.Canonical(r) && r == S.Noise(seed,nonce)
  {
    var b := X.Xof(136,seed+[nonce as bv8],128);
    r := VS.Cbd2(b);
  }
  method NoiseVector(seed: seq<bv8>, start: nat, ntt: bool) returns (r: seq<seq<int>>)
    requires |seed| == 32 && start <= 253
    ensures S.Vec(r,3) && r == S.NoiseVector(seed,start,ntt)
  {
    r := [];
    for i := 0 to 3
      invariant S.Vec(r,i)
      invariant forall j | 0 <= j < i :: r[j] == S.NoiseVector(seed,start,ntt)[j]
    {
      var f := Noise(seed,start+i);
      if ntt { f := VP.Ntt(f); }
      r := r+[f];
    }
  }
  method SamplePrefix(b: seq<bv8>) returns (r: S.Result<seq<int>>)
    requires |b| == 840
    ensures r == S.SamplePrefix(b)
    ensures r.Success? ==> P.Canonical(r.value)
  {
    var sampled := VS.Feed([],b);
    if sampled.Full? { return S.Success(sampled.coeffs); }
    return S.Failure(S.RejectionLimit);
  }
  method Sample(rho: seq<bv8>, i: nat, j: nat) returns (r: S.Result<seq<int>>)
    requires |rho| == 32 && i < 3 && j < 3
    ensures r == S.Sample(rho,i,j)
    ensures r.Success? ==> P.Canonical(r.value)
  {
    var b := X.Xof(168,rho+[j as bv8,i as bv8],840);
    r := SamplePrefix(b);
  }
  method ExpandMatrix(rho: seq<bv8>) returns (r: S.Result<seq<seq<int>>>)
    requires |rho| == 32
    ensures r.Success? <==> S.MatrixReady(rho)
    ensures r.Success? ==> S.Vec(r.value,9) && r.value == S.Matrix(rho)
    ensures r.Failure? ==> r.reason == S.RejectionLimit
  {
    var a: seq<seq<int>> := [];
    for k := 0 to 9
      invariant S.Vec(a,k)
      invariant forall h | 0 <= h < k :: S.Sample(rho,h/3,h%3) == S.Success(a[h])
    {
      var sample := Sample(rho,k/3,k%3);
      if sample.Failure? {
        assert !S.MatrixReady(rho);
        return S.Failure(S.RejectionLimit);
      }
      a := a+[sample.value];
    }
    assert S.MatrixReady(rho);
    assert a == S.Matrix(rho);
    return S.Success(a);
  }
  method Dot(a: seq<seq<int>>, b: seq<seq<int>>) returns (r: seq<int>)
    requires S.Vec(a,3) && S.Vec(b,3)
    ensures P.Canonical(r) && r == S.Dot(a,b,3)
  {
    r := seq(256,i => 0);
    for i := 0 to 3
      invariant P.Canonical(r) && r == S.Dot(a,b,i)
    {
      var term := VP.NttMul(a[i],b[i]);
      r := VP.Add(r,term);
    }
  }
  method Row(a: seq<seq<int>>, i: nat, transposed: bool) returns (r: seq<seq<int>>)
    requires S.Vec(a,9) && i < 3
    ensures S.Vec(r,3) && r == S.Row(a,i,transposed)
  { r := seq(3,j requires 0 <= j < 3 => a[if transposed then 3*j+i else 3*i+j]); }
  method EncodeVector(a: seq<seq<int>>, d: int) returns (r: seq<bv8>)
    requires S.Vec(a,3) && C.Width(d)
    ensures r == S.EncodedVector(a,d,3) && |r| == 96*d
  {
    r := [];
    for i := 0 to 3
      invariant r == S.EncodedVector(a,d,i)
    {
      var b := VC.CompressAndEncode(a[i],d);
      r := r+b;
    }
  }
  method {:isolate_assertions} KeyGen(seed: seq<bv8>) returns (r: S.Result<S.SecretKey>)
    ensures r == S.KeyGen(seed)
    ensures r.Success? ==> S.ValidSecret(r.value)
  {
    if |seed| != 64 { return S.Failure(S.InvalidSeedLength); }
    var g := H.G(seed[..32]+[3 as bv8]);
    var rho := g[..32]; var sigma := g[32..];
    var matrix := ExpandMatrix(rho);
    if matrix.Failure? { return S.Failure(S.RejectionLimit); }
    var a := matrix.value;
    var s := NoiseVector(sigma,0,true);
    var e := NoiseVector(sigma,3,true);
    var t: seq<seq<int>> := [];
    for i := 0 to 3
      invariant S.Vec(t,i)
      invariant forall j | 0 <= j < i :: t[j] == S.KeyT(a,sigma)[j]
    {
      var row := Row(a,i,false);
      var product := Dot(row,s);
      var f := VP.Add(product,e[i]);
      t := t+[f];
    }
    assert t == S.KeyT(a,sigma);
    var prefix := EncodeVector(t,12);
    var encoded := prefix+rho;
    var ek := S.PublicKey(a,t,rho,encoded,H.H(encoded));
    return S.Success(S.SecretKey(seed,s,ek));
  }
  method Parse(b: seq<bv8>) returns (r: S.Result<S.PublicKey>)
    ensures r == S.Parse(b)
    ensures r.Success? ==> S.ValidPublic(r.value)
    ensures r.Success? ==> S.Vec(r.value.t,3) && S.Vec(r.value.matrix,9)
    ensures r.Success? ==> |r.value.hash| == 32 && r.value.hash == H.H(b)
  {
    if |b| != 1184 { return S.Failure(S.InvalidKeyLength); }
    var t: seq<seq<int>> := [];
    for i := 0 to 3
      invariant S.Vec(t,i)
      invariant forall j | 0 <= j < i :: C.Decode(b[384*j..384*(j+1)],12).Decoded?
      invariant forall j | 0 <= j < i :: C.Decode(b[384*j..384*(j+1)],12) == C.Decoded(t[j])
    {
      var f := VC.Decode(b[384*i..384*(i+1)],12);
      if !f.Decoded? {
        assert !(forall j | 0 <= j < 3 :: C.Decode(b[384*j..384*(j+1)],12).Decoded?);
        return S.Failure(S.ModulusError);
      }
      t := t+[f.words];
    }
    assert forall j | 0 <= j < 3 :: C.Decode(b[384*j..384*(j+1)],12).Decoded?;
    assert t == S.KeyWords(b);
    var rho := b[1152..];
    var a := ExpandMatrix(rho);
    if a.Failure? { return S.Failure(S.RejectionLimit); }
    return S.Success(S.PublicKey(a.value,t,rho,b,H.H(b)));
  }
  method Expand(b: seq<bv8>, d: int) returns (f: seq<int>)
    requires (d == 1 || d == 4 || d == 10) && |b| == 32*d
    ensures P.Canonical(f) && f == S.Expanded(b,d)
  {
    var decoded := VC.DecodeAndDecompress(b,d);
    assert decoded.Decoded?;
    f := decoded.words;
  }
  method Encrypt(ek: S.PublicKey, m: seq<bv8>, coins: seq<bv8>) returns (c: seq<bv8>)
    requires S.Vec(ek.matrix,9) && S.Vec(ek.t,3) && |m| == 32 && |coins| == 32
    ensures c == S.Encrypt(ek,m,coins) && |c| == 1088
  {
    var y := NoiseVector(coins,0,true);
    var e1 := NoiseVector(coins,3,false);
    var e2 := Noise(coins,6);
    var u: seq<seq<int>> := [];
    for i := 0 to 3
      invariant S.Vec(u,i)
      invariant forall j | 0 <= j < i :: u[j] == S.U(ek.matrix,coins)[j]
    {
      var row := Row(ek.matrix,i,true);
      var product := Dot(row,y);
      var inverse := VP.InverseNtt(product);
      var f := VP.Add(inverse,e1[i]);
      u := u+[f];
    }
    assert u == S.U(ek.matrix,coins);
    var c1 := EncodeVector(u,10);
    var mu := Expand(m,1);
    var product := Dot(ek.t,y);
    var v := VP.InverseNtt(product);
    v := VP.Add(v,e2);
    v := VP.Add(v,mu);
    assert v == S.V(ek.t,m,coins);
    var c2 := VC.CompressAndEncode(v,4);
    c := c1+c2;
  }
  method Decrypt(s: seq<seq<int>>, c: seq<bv8>) returns (m: seq<bv8>)
    requires S.Vec(s,3) && |c| == 1088
    ensures m == S.Decrypt(s,c) && |m| == 32
  {
    var u: seq<seq<int>> := [];
    for i := 0 to 3
      invariant S.Vec(u,i)
      invariant forall j | 0 <= j < i :: u[j] == P.Ntt(S.Expanded(c[320*j..320*(j+1)],10))
    {
      var f := Expand(c[320*i..320*(i+1)],10);
      f := VP.Ntt(f);
      u := u+[f];
    }
    assert u == seq(3,i requires 0 <= i < 3 => P.Ntt(S.Expanded(c[320*i..320*(i+1)],10)));
    var mask := Dot(s,u);
    mask := VP.InverseNtt(mask);
    var v := Expand(c[960..],4);
    var w := VP.Sub(v,mask);
    m := VC.CompressAndEncode(w,1);
  }
  method Encaps(b: seq<bv8>, m: seq<bv8>) returns (r: S.Result<S.Encapsulation>)
    ensures r == S.Encaps(b,m)
    ensures r.Success? ==> |r.value.key| == 32 && |r.value.ciphertext| == 1088
  {
    var parsed := Parse(b);
    if parsed.Failure? { return S.Failure(parsed.reason); }
    if |m| != 32 { return S.Failure(S.InvalidMessageLength); }
    var g := H.G(m+parsed.value.hash);
    var c := Encrypt(parsed.value,m,g[32..]);
    return S.Success(S.Encapsulation(g[..32],c));
  }
  method Decaps(dk: S.SecretKey, c: seq<bv8>) returns (r: S.Result<seq<bv8>>)
    requires S.ValidSecret(dk)
    ensures r == S.Decaps(dk,c)
    ensures r.Success? ==> |r.value| == 32
  {
    if |c| != 1088 { return S.Failure(S.InvalidCiphertextLength); }
    var m := Decrypt(dk.s,c);
    var g := H.G(m+dk.ek.hash);
    var fallback := X.Xof(136,dk.seed[32..]+c,32);
    var c1 := Encrypt(dk.ek,m,g[32..]);
    var key := Select(c,c1,g[..32],fallback);
    return S.Success(key);
  }
  method DecapsFromSeed(seed: seq<bv8>, c: seq<bv8>) returns (r: S.Result<seq<bv8>>)
    ensures r == S.DecapsFromSeed(seed,c)
    ensures r.Success? ==> |r.value| == 32
  {
    if |c| != 1088 { return S.Failure(S.InvalidCiphertextLength); }
    var generated := KeyGen(seed);
    if generated.Failure? { return S.Failure(generated.reason); }
    r := Decaps(generated.value,c);
  }
  method SerializeSecret(dk: S.SecretKey) returns (r: seq<bv8>)
    requires S.ValidSecret(dk)
    ensures r == S.SerializedSecret(dk) && |r| == 2400
  {
    var secret := EncodeVector(dk.s,12);
    r := secret+dk.ek.encoded+dk.ek.hash+dk.seed[32..];
  }

  lemma EncodedPart(a: seq<seq<int>>, d: int, i: nat)
    requires S.Vec(a,3) && C.Width(d) && i < 3
    ensures S.EncodedVector(a,d,3)[i*32*d..(i+1)*32*d] == C.Encoded(C.CompressedWords(a[i],d),d)
  {
    assert S.EncodedVector(a,d,1) == C.Encoded(C.CompressedWords(a[0],d),d);
    assert S.EncodedVector(a,d,2) == S.EncodedVector(a,d,1)+C.Encoded(C.CompressedWords(a[1],d),d);
    assert S.EncodedVector(a,d,3) == S.EncodedVector(a,d,2)+C.Encoded(C.CompressedWords(a[2],d),d);
    if i == 0 {} else if i == 1 {} else {}
  }
  lemma ParsePublic(ek: S.PublicKey)
    requires S.ValidPublic(ek)
    ensures S.Parse(ek.encoded) == S.Success(ek)
  {
    forall i | 0 <= i < 3
      ensures C.Decode(ek.encoded[384*i..384*(i+1)],12) == C.Decoded(ek.t[i])
    {
      EncodedPart(ek.t,12,i);
      VC.RoundTrip(ek.t[i],12);
      assert ek.encoded[384*i..384*(i+1)] == C.Encoded(ek.t[i],12);
    }
    assert S.KeyWords(ek.encoded) == ek.t;
    assert ek.encoded[1152..] == ek.rho;
  }

}
