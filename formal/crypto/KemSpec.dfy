include "Polynomial.dfy"
include "Sampling.dfy"
include "Shake.dfy"
include "JdkHash.dfy"

// FIPS 203 equations and algorithms 13--18, ML-KEM-768 only.
// High-level matrix/vector expressions are separate from the executable loops.
// Go-derived source formulas retain their attribution in MlKem.dfy.
module KemSpec {
  import P = PolySpec
  import C = CodecSpec
  import S = SamplingSpec
  import X = SpongeSpec
  import H = JdkHash
  datatype FailureKind = InvalidSeedLength | InvalidKeyLength | InvalidMessageLength |
    InvalidCiphertextLength | ModulusError | RejectionLimit
  datatype Result<T> = Failure(reason: FailureKind) | Success(value: T)
  datatype PublicKey = PublicKey(matrix: seq<seq<int>>, t: seq<seq<int>>,
    rho: seq<bv8>, encoded: seq<bv8>, hash: seq<bv8>)
  datatype SecretKey = SecretKey(seed: seq<bv8>, s: seq<seq<int>>, ek: PublicKey)
  datatype Encapsulation = Encapsulation(key: seq<bv8>, ciphertext: seq<bv8>)

  ghost predicate Vec(a: seq<seq<int>>, n: nat) {
    |a| == n && forall i | 0 <= i < n :: P.Canonical(a[i])
  }
  ghost function Zero(): seq<int>
    ensures P.Canonical(Zero())
  { seq(256,i => 0) }
  ghost function Dot(a: seq<seq<int>>, b: seq<seq<int>>, n: nat): seq<int>
    requires Vec(a,3) && Vec(b,3) && n <= 3
    ensures P.Canonical(Dot(a,b,n))
    decreases n
  { if n == 0 then Zero() else P.Add(Dot(a,b,n-1),P.NttMul(a[n-1],b[n-1])) }
  ghost function Row(a: seq<seq<int>>, i: nat, transposed: bool): seq<seq<int>>
    requires Vec(a,9) && i < 3
    ensures Vec(Row(a,i,transposed),3)
  { seq(3,j requires 0 <= j < 3 => a[if transposed then 3*j+i else 3*i+j]) }
  ghost function Noise(seed: seq<bv8>, nonce: nat): seq<int>
    requires |seed| == 32 && nonce < 256
    ensures P.Canonical(Noise(seed,nonce))
  { S.Cbd2(X.Xof(136,seed+[nonce as bv8],128)) }
  ghost function NoiseVector(seed: seq<bv8>, start: nat, ntt: bool): seq<seq<int>>
    requires |seed| == 32 && start <= 253
    ensures Vec(NoiseVector(seed,start,ntt),3)
  { seq(3,i requires 0 <= i < 3 => if ntt then P.Ntt(Noise(seed,start+i)) else Noise(seed,start+i)) }

  // Proposed bounded policy: first 840 bytes = 280 complete loop iterations.
  // Appendix B permits this minimum, but recommends avoiding a cap if possible.
  // Uniform RejectionLimit exposes no index or intermediate coefficients.
  // Immutable sequence proofs DO NOT prove destruction of intermediate secrets.
  ghost function SamplePrefix(b: seq<bv8>): Result<seq<int>>
    requires |b| == 840
    ensures SamplePrefix(b).Success? ==> P.Canonical(SamplePrefix(b).value)
  {
    var r := S.Feed([],b);
    if r.Full? then Success(r.coeffs) else Failure(RejectionLimit)
  }
  ghost function Sample(rho: seq<bv8>, i: nat, j: nat): Result<seq<int>>
    requires |rho| == 32 && i < 3 && j < 3
    ensures Sample(rho,i,j).Success? ==> P.Canonical(Sample(rho,i,j).value)
  {
    SamplePrefix(X.Xof(168,rho+[j as bv8,i as bv8],840))
  }
  ghost function MatrixReady(rho: seq<bv8>): bool
    requires |rho| == 32
  { forall k | 0 <= k < 9 :: Sample(rho,k/3,k%3).Success? }
  ghost function Matrix(rho: seq<bv8>): seq<seq<int>>
    requires |rho| == 32 && MatrixReady(rho)
    ensures Vec(Matrix(rho),9)
  { seq(9,k requires 0 <= k < 9 => Sample(rho,k/3,k%3).value) }
  ghost function EncodedVector(a: seq<seq<int>>, d: int, n: nat): seq<bv8>
    requires Vec(a,3) && C.Width(d) && n <= 3
    ensures |EncodedVector(a,d,n)| == n*32*d
    decreases n
  { if n == 0 then [] else EncodedVector(a,d,n-1)+C.Encoded(C.CompressedWords(a[n-1],d),d) }
  ghost function PublicBytes(t: seq<seq<int>>, rho: seq<bv8>): seq<bv8>
    requires Vec(t,3) && |rho| == 32
    ensures |PublicBytes(t,rho)| == 1184
  { EncodedVector(t,12,3)+rho }
  ghost predicate ValidPublic(ek: PublicKey) {
    Vec(ek.matrix,9) && Vec(ek.t,3) && |ek.rho| == 32 &&
    ek.encoded == PublicBytes(ek.t,ek.rho) && ek.hash == H.H(ek.encoded) &&
    MatrixReady(ek.rho) && ek.matrix == Matrix(ek.rho)
  }
  ghost predicate ValidSecret(dk: SecretKey) {
    |dk.seed| == 64 && Vec(dk.s,3) && ValidPublic(dk.ek)
  }
  ghost function KeyT(a: seq<seq<int>>, sigma: seq<bv8>): seq<seq<int>>
    requires Vec(a,9) && |sigma| == 32
    ensures Vec(KeyT(a,sigma),3)
  {
    var s := NoiseVector(sigma,0,true);
    var e := NoiseVector(sigma,3,true);
    seq(3,i requires 0 <= i < 3 => P.Add(Dot(Row(a,i,false),s,3),e[i]))
  }
  ghost function KeyGen(seed: seq<bv8>): Result<SecretKey>
    ensures KeyGen(seed).Success? ==> ValidSecret(KeyGen(seed).value)
  {
    if |seed| != 64 then Failure(InvalidSeedLength) else
    var g := H.G(seed[..32]+[3 as bv8]);
    var rho := g[..32]; var sigma := g[32..];
    if !MatrixReady(rho) then Failure(RejectionLimit) else
    var a := Matrix(rho); var t := KeyT(a,sigma);
    var encoded := PublicBytes(t,rho);
    Success(SecretKey(seed,NoiseVector(sigma,0,true),PublicKey(a,t,rho,encoded,H.H(encoded))))
  }
  ghost function KeyWords(b: seq<bv8>): seq<seq<int>>
    requires |b| == 1184
    requires forall i | 0 <= i < 3 :: C.Decode(b[384*i..384*(i+1)],12).Decoded?
    ensures Vec(KeyWords(b),3)
  { seq(3,i requires 0 <= i < 3 => C.Decode(b[384*i..384*(i+1)],12).words) }
  lemma {:isolate_assertions} CanonicalEncoding12(b: seq<bv8>)
    requires |b| == 384 && C.Decode(b,12).Decoded?
    ensures C.Encoded(C.Decode(b,12).words,12) == b
  {
    reveal C.DecodedWords, C.DecodedWord, C.ByteGroup, C.GroupValue, C.Encoded;
    var f := C.Decode(b,12).words;
    forall j | 0 <= j < 384
      ensures C.Encoded(f,12)[j] == b[j]
    {
      var k := j/3;
      var v := (b[3*k] as int)+256*(b[3*k+1] as int)+65536*(b[3*k+2] as int);
      assert 0 <= v < 16777216;
      assert C.ByteGroup(b,12,k) == v;
      assert f[2*k] == v%4096;
      assert 0 <= v/4096 < 4096;
      assert (v/4096)%4096 == v/4096;
      assert C.DecodedWord(b,12,2*k+1) == (v/4096)%4096;
      assert f[2*k+1] == v/4096;
      assert C.GroupValue(f,12,k) == v;
      if j%3 == 0 {
        assert v%256 == b[j] as int;
      } else if j%3 == 1 {
        assert j == 3*k+1;
        assert v/256 == (b[3*k+1] as int)+256*(b[3*k+2] as int);
        assert (v/256)%256 == b[j] as int;
      } else {
        assert (v/65536)%256 == b[j] as int;
      }
      assert C.EncodedByte(f,12,j) as int == b[j] as int;
    }
  }

  lemma CheckedKeyEncoding(b: seq<bv8>)
    requires |b| == 1184
    requires forall i | 0 <= i < 3 :: C.Decode(b[384*i..384*(i+1)],12).Decoded?
    ensures PublicBytes(KeyWords(b),b[1152..]) == b
  {
    var t := KeyWords(b);
    forall i | 0 <= i < 3
      ensures C.Encoded(C.CompressedWords(t[i],12),12) == b[384*i..384*(i+1)]
    { CanonicalEncoding12(b[384*i..384*(i+1)]); }
    assert EncodedVector(t,12,1) == b[..384];
    assert EncodedVector(t,12,2) == b[..768];
    assert EncodedVector(t,12,3) == b[..1152];
  }
  ghost function Parse(b: seq<bv8>): Result<PublicKey>
    ensures Parse(b).Success? ==> ValidPublic(Parse(b).value)
  {
    if |b| != 1184 then Failure(InvalidKeyLength) else
    if !(forall i | 0 <= i < 3 :: C.Decode(b[384*i..384*(i+1)],12).Decoded?) then Failure(ModulusError) else
    CheckedKeyEncoding(b);
    var rho := b[1152..];
    if !MatrixReady(rho) then Failure(RejectionLimit) else
    Success(PublicKey(Matrix(rho),KeyWords(b),rho,b,H.H(b)))
  }
  ghost function Expanded(b: seq<bv8>, d: int): seq<int>
    requires (d == 1 || d == 4 || d == 10) && |b| == 32*d
    ensures P.Canonical(Expanded(b,d))
  { C.ExpandedWords(C.Decode(b,d).words,d) }
  ghost function U(a: seq<seq<int>>, coins: seq<bv8>): seq<seq<int>>
    requires Vec(a,9) && |coins| == 32
    ensures Vec(U(a,coins),3)
  {
    var y := NoiseVector(coins,0,true); var e := NoiseVector(coins,3,false);
    seq(3,i requires 0 <= i < 3 => P.Add(P.InverseNtt(Dot(Row(a,i,true),y,3)),e[i]))
  }
  ghost function V(t: seq<seq<int>>, m: seq<bv8>, coins: seq<bv8>): seq<int>
    requires Vec(t,3) && |m| == 32 && |coins| == 32
    ensures P.Canonical(V(t,m,coins))
  { P.Add(P.Add(P.InverseNtt(Dot(t,NoiseVector(coins,0,true),3)),Noise(coins,6)),Expanded(m,1)) }
  ghost function Encrypt(ek: PublicKey, m: seq<bv8>, coins: seq<bv8>): seq<bv8>
    requires Vec(ek.matrix,9) && Vec(ek.t,3) && |m| == 32 && |coins| == 32
    ensures |Encrypt(ek,m,coins)| == 1088
  { EncodedVector(U(ek.matrix,coins),10,3)+C.Encoded(C.CompressedWords(V(ek.t,m,coins),4),4) }
  ghost function Decrypt(s: seq<seq<int>>, c: seq<bv8>): seq<bv8>
    requires Vec(s,3) && |c| == 1088
    ensures |Decrypt(s,c)| == 32
  {
    var u := seq(3,i requires 0 <= i < 3 => P.Ntt(Expanded(c[320*i..320*(i+1)],10)));
    var w := P.Sub(Expanded(c[960..],4),P.InverseNtt(Dot(s,u,3)));
    C.Encoded(C.CompressedWords(w,1),1)
  }
  ghost function Encaps(b: seq<bv8>, m: seq<bv8>): Result<Encapsulation> {
    var parsed := Parse(b);
    if parsed.Failure? then Failure(parsed.reason) else
    if |m| != 32 then Failure(InvalidMessageLength) else
    var g := H.G(m+parsed.value.hash);
    Success(Encapsulation(g[..32],Encrypt(parsed.value,m,g[32..])))
  }
  ghost function Decaps(dk: SecretKey, c: seq<bv8>): Result<seq<bv8>>
    requires ValidSecret(dk)
  {
    if |c| != 1088 then Failure(InvalidCiphertextLength) else
    var m := Decrypt(dk.s,c); var g := H.G(m+dk.ek.hash);
    var fallback := X.Xof(136,dk.seed[32..]+c,32);
    Success(if c == Encrypt(dk.ek,m,g[32..]) then g[..32] else fallback)
  }
  ghost function DecapsFromSeed(seed: seq<bv8>, c: seq<bv8>): Result<seq<bv8>> {
    if |c| != 1088 then Failure(InvalidCiphertextLength) else
    var generated := KeyGen(seed);
    if generated.Failure? then Failure(generated.reason) else Decaps(generated.value,c)
  }
  // FIPS 203 algorithm 16's expanded 2400-byte decapsulation-key encoding.
  ghost function SerializedSecret(dk: SecretKey): seq<bv8>
    requires ValidSecret(dk)
    ensures |SerializedSecret(dk)| == 2400
  { EncodedVector(dk.s,12,3)+dk.ek.encoded+dk.ek.hash+dk.seed[32..] }

}
