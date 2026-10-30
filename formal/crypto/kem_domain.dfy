include "MlKem.dfy"

// Arbitrary finite byte strings, not a fixed vector corpus. The total public
// entry points preserve their complete success/failure equations.
module KemDomain {
  import S = KemSpec
  import V = VerifiedMlKem
  import H = JdkHash
  import X = SpongeSpec
  import C = CodecSpec
  method EveryInput(seed: seq<bv8>, key: seq<bv8>, message: seq<bv8>, ciphertext: seq<bv8>) {
    var generated := V.KeyGen(seed);
    assert generated == S.KeyGen(seed);
    assert |seed| != 64 ==> generated == S.Failure(S.InvalidSeedLength);
    if generated.Success? {
      V.ParsePublic(generated.value.ek);
      assert S.Parse(generated.value.ek.encoded) == S.Success(generated.value.ek);
    }
    var encapsulated := V.Encaps(key,message);
    assert encapsulated == S.Encaps(key,message);
    assert |key| != 1184 ==> encapsulated == S.Failure(S.InvalidKeyLength);
    var decapsulated := V.DecapsFromSeed(seed,ciphertext);
    assert decapsulated == S.DecapsFromSeed(seed,ciphertext);
    assert |ciphertext| != 1088 ==> decapsulated == S.Failure(S.InvalidCiphertextLength);
  }
  method ModulusRejection(key: seq<bv8>, message: seq<bv8>, i: nat)
    requires |key| == 1184 && i < 3
    requires !C.Decode(key[384*i..384*(i+1)],12).Decoded?
  {
    var result := V.Encaps(key,message);
    assert result == S.Failure(S.ModulusError);
  }
  method ReencryptionEquation(dk: S.SecretKey, ciphertext: seq<bv8>)
    requires S.ValidSecret(dk) && |ciphertext| == 1088
  {
    var result := V.Decaps(dk,ciphertext);
    ghost var m := S.Decrypt(dk.s,ciphertext);
    ghost var g := H.G(m+dk.ek.hash);
    assert result.Success?;
    assert ciphertext == S.Encrypt(dk.ek,m,g[32..]) ==> result.value == g[..32];
    assert ciphertext != S.Encrypt(dk.ek,m,g[32..]) ==>
      result.value == X.Xof(136,dk.seed[32..]+ciphertext,32);
  }
  method EverySelection(c: seq<bv8>, d: seq<bv8>, a: seq<bv8>, b: seq<bv8>)
    requires |c| == 1088 && |d| == 1088 && |a| == 32 && |b| == 32
  {
    var r := V.Select(c,d,a,b);
    assert c == d ==> r == a;
    assert c != d ==> r == b;
  }
}
