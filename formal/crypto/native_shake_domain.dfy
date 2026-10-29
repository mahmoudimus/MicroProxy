include "NativeShake.dfy"

// These caller domains spell out the complete native state and table bounds.
// They do not assume Valid() or use a sampled set of input/state values.
module NativeShakePublicDomain {
  import T = NativeTypes
  import V = NativeShake
  import K = NativeKeccak
  import S = SpongeSpec
  import P = KeccakSpec

  ghost function Offsets(): seq<int> {
    [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14]
  }
  ghost function Sources(): seq<int> {
    [0,6,12,18,24,3,9,10,16,22,1,7,13,19,20,4,5,11,17,23,2,8,14,15,21]
  }
  ghost predicate Legal(s: V.Sponge)
    reads s,s.lanes,s.offsets,s.sources
  {
    s.lanes.Length == 25 && s.scratch.Length == 25 && s.parity.Length == 5 &&
    s.offsets.Length == 25 && s.sources.Length == 25 &&
    s.lanes != s.scratch && s.lanes != s.parity && s.scratch != s.parity &&
    (s.offsets as object) != (s.lanes as object) &&
    (s.offsets as object) != (s.scratch as object) &&
    (s.offsets as object) != (s.parity as object) &&
    (s.sources as object) != (s.lanes as object) &&
    (s.sources as object) != (s.scratch as object) &&
    (s.sources as object) != (s.parity as object) &&
    (forall i: int :: 0 <= i < 25 ==> s.offsets[i] as int == Offsets()[i]) &&
    (forall i: int :: 0 <= i < 25 ==> s.sources[i] as int == Sources()[i]) &&
    (s.rate == 136 || s.rate == 168) && 0 <= s.position &&
    (if s.squeezing then s.position <= s.rate else s.position < s.rate)
  }

  lemma Tables()
    ensures forall i: int :: 0 <= i < 25 ==> 0 <= Offsets()[i] < 64 && Offsets()[i] == P.Offsets()[i]%64
    ensures forall i: int :: 0 <= i < 25 ==> 0 <= Sources()[i] < 25 && Sources()[i] == ((i%5)+3*(i/5))%5+5*(i%5)
  {}
  lemma Domain(s: V.Sponge)
    requires Legal(s)
    ensures s.Valid()
  { Tables(); }

  method AllRates(rate: T.I)
    requires rate == 136 || rate == 168
  {
    var s := new V.Sponge(rate);
    Tables();
    assert Legal(s);
    assert s.Valid() && s.Model() == S.Initial(rate as int);
    assert fresh(s.lanes) && fresh(s.scratch) && fresh(s.parity) && fresh(s.offsets) && fresh(s.sources);
  }

  method AllUpdates(s: V.Sponge, input: array<bv8>, offset: T.I, length: T.I)
    requires Legal(s) && 0 <= input.Length <= 2147483647
    modifies s,s.lanes,s.scratch,s.parity
  {
    Domain(s);
    ghost var before := s.Model();
    ghost var bytes := input[..];
    var status := s.Update(input,offset,length);
    assert status == (if before.squeezing then 1 else
      if offset < 0 || offset as int > input.Length || length < 0 || length as int > input.Length-offset as int then 2 else 0);
    assert status != 0 ==> s.Model() == before;
    assert status == 0 ==> s.Model() == S.Absorb(before,bytes[offset as int..offset as int+length as int]);
    assert input[..] == bytes;
  }

  method AllReads(s: V.Sponge, output: array<bv8>)
    requires Legal(s) && 0 <= output.Length <= 2147483647
    requires (output as object) != (s.offsets as object) && (output as object) != (s.sources as object)
    modifies s,s.lanes,s.scratch,s.parity,output
  {
    Domain(s);
    ghost var before := s.Model();
    s.Read(output);
    assert S.ReadResult(s.Model(),output[..]) == S.Read(before,output.Length);
    assert s.Valid() && s.squeezing;
    if output.Length == 0 {
      S.RawReadEmpty(S.Start(before));
      assert s.Model() == S.Start(before);
    }
  }

  method AllXofs(rate: T.I, input: array<bv8>, length: T.I)
    requires (rate == 136 || rate == 168) && 0 <= input.Length <= 2147483647 && 0 <= length
  {
    ghost var bytes := input[..];
    var output := V.Xof(rate,input,length);
    assert fresh(output) && output.Length == length as int;
    assert output[..] == S.Xof(rate as int,bytes,length as int) && input[..] == bytes;
  }

  // External buffers are arbitrary and may alias one another. Fresh internal
  // tables establish the Read frame preconditions; callers need no Valid input.
  method ExternalBuffers(rate: T.I, input: array<bv8>, output: array<bv8>, offset: T.I, length: T.I)
    requires rate == 136 || rate == 168
    requires 0 <= input.Length <= 2147483647 && 0 <= output.Length <= 2147483647
    modifies output
  {
    ghost var bytes := input[..];
    var s := new V.Sponge(rate);
    assert (output as object) != (s.offsets as object) && (output as object) != (s.sources as object);
    assert (input as object) != (s.offsets as object) && (input as object) != (s.sources as object);
    var status := s.Update(input,offset,length);
    assert input[..] == bytes;
    ghost var absorbed := s.Model();
    assert status == 0 ==> absorbed == S.Absorb(S.Initial(rate as int),bytes[offset as int..offset as int+length as int]);
    s.Read(output);
    assert S.ReadResult(s.Model(),output[..]) == S.Read(absorbed,output.Length);
    ghost var result := output[..];
    s.Destroy();
    assert output[..] == result;
  }

  method AllAbsorbStates(s: V.Sponge, value: bv8)
    requires Legal(s) && !s.squeezing
    modifies s,s.lanes,s.scratch,s.parity
  {
    Domain(s); ghost var before := s.Model();
    s.AbsorbOne(value);
    assert s.Model() == S.AbsorbOne(before,value) && s.Valid();
  }
  method AllStarts(s: V.Sponge)
    requires Legal(s)
    modifies s,s.lanes,s.scratch,s.parity
  {
    Domain(s); ghost var before := s.Model();
    s.Start();
    assert s.Model() == S.Start(before) && s.Valid() && s.squeezing;
  }
  method AllSqueezeStates(s: V.Sponge)
    requires Legal(s) && s.squeezing
    modifies s,s.lanes,s.scratch,s.parity
  {
    Domain(s); ghost var before := s.Model();
    var value := s.Next();
    assert S.ReadResult(s.Model(),[value]) == S.Next(before) && s.Valid();
  }
  method AllDestruction(s: V.Sponge)
    requires Legal(s)
    modifies s,s.lanes,s.scratch,s.parity
  {
    Domain(s); s.Destroy();
    assert !s.squeezing && s.position == 0 && s.Valid();
    assert forall i: int :: 0 <= i < 25 ==> s.lanes[i] == 0 && s.scratch[i] == 0;
    assert forall i: int :: 0 <= i < 5 ==> s.parity[i] == 0;
  }
  method AllPermutations(lanes: array<bv64>)
    requires lanes.Length == 25
    modifies lanes
  {
    ghost var before := lanes[..];
    K.Permute(lanes);
    assert lanes[..] == P.Iter(before,24);
  }
}
