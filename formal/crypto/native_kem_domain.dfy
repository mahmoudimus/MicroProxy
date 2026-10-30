include "NativeMlKem.dfy"
module NativeKemDomain {
  import T = NativeTypes
  import S = KemSpec
  import N = NativeMlKem

  // Every finite native byte input, including all invalid lengths and modulus
  // values; no value-dependent public preconditions are hidden in the harness.
  method EveryInput(seed: array<bv8>, ek: array<bv8>, message: array<bv8>, ciphertext: array<bv8>)
  {
    var generated := N.KeyGen(seed);
    assert N.ModelSecret(generated) == S.KeyGen(seed[..]);
    var parsed := N.Parse(ek);
    assert N.ModelPublic(parsed) == S.Parse(ek[..]);
    var encapsulated := N.Encaps(ek,message);
    assert N.ModelEncapsulation(encapsulated) == S.Encaps(ek[..],message[..]);
    var decapsulated := N.DecapsFromSeed(seed,ciphertext);
    assert N.ModelBytes(decapsulated) == S.DecapsFromSeed(seed[..],ciphertext[..]);
  }
  method Cached(dk: N.SecretKey, ciphertext: array<bv8>)
    requires dk.Valid()
  {
    var decoded := N.Decaps(dk,ciphertext);
    assert N.ModelBytes(decoded) == S.Decaps(dk.Model(),ciphertext[..]);
    var serialized := N.SerializeSecret(dk);
    assert serialized[..] == S.SerializedSecret(dk.Model());
  }
  method Selection(c: array<bv8>, expected: array<bv8>, candidate: array<bv8>, fallback: array<bv8>)
    requires c.Length == 1088 && expected.Length == 1088 && candidate.Length == 32 && fallback.Length == 32
  {
    var key := N.Select(c,expected,candidate,fallback);
    assert key[..] == (if c[..] == expected[..] then candidate[..] else fallback[..]);
  }
  method Destroy(dk: N.SecretKey)
    requires dk.Valid()
    modifies dk.Repr()
    ensures N.ZeroBytes(dk.seed) && dk.destroyed && dk.ek.destroyed
    ensures N.ZeroBytes(dk.ek.rho) && N.ZeroBytes(dk.ek.encoded) && N.ZeroBytes(dk.ek.hash)
    ensures forall i | 0 <= i < dk.s.Length :: N.ZeroInts(dk.s[i])
    ensures forall i | 0 <= i < dk.ek.matrix.Length :: N.ZeroInts(dk.ek.matrix[i])
    ensures forall i | 0 <= i < dk.ek.t.Length :: N.ZeroInts(dk.ek.t[i])
  { dk.Destroy(); }
}
