include "../crypto/NativeShake.dfy"

// Direct executable-Dafny ownership, freshness, and frame harnesses. They call
// the real NativeShake.Xof and Sponge methods; functional sponge equations are
// proved by the included method bodies and are not reimplemented here.
//
// Claims are source-level object identity facts only. Dafny "fresh" and
// "Footprint" are not JVM addresses, and Destroy is a source-level wipe of the
// owned arrays, not a claim about physical/JIT/provider erasure.
module NativeShakeOwnership {
  import T = NativeTypes
  import V = NativeShake
  import S = SpongeSpec
  import K = KeccakSpec

  ghost function Footprint(s: V.Sponge): set<object>
    reads s
  { {s as object, s.lanes as object, s.scratch as object, s.parity as object,
      s.offsets as object, s.sources as object} }

  ghost function Identity(s: V.Sponge): (T.I, set<object>)
    reads s
  { (s.rate, Footprint(s)) }

  ghost predicate PairwiseDisjoint(s: V.Sponge)
    reads s
  {
    s.lanes != s.scratch && s.lanes != s.parity && s.scratch != s.parity &&
    (s.offsets as object) != (s.lanes as object) &&
    (s.offsets as object) != (s.scratch as object) &&
    (s.offsets as object) != (s.parity as object) &&
    (s.sources as object) != (s.lanes as object) &&
    (s.sources as object) != (s.scratch as object) &&
    (s.sources as object) != (s.parity as object) &&
    (s.offsets as object) != (s.sources as object)
  }

  // This is local disjointness and validity, not exclusive access by all Java callers.
  ghost predicate FactoryOwned(s: V.Sponge)
    reads s,s.lanes,s.offsets,s.sources
  { s.Valid() && PairwiseDisjoint(s) }

  lemma ValidFootprint(s: V.Sponge)
    requires s.Valid()
    ensures FactoryOwned(s) && |Footprint(s)| == 6
  {
    assert s.offsets[1] as int == K.Offsets()[1]%64;
    assert K.Offsets()[1] == 1;
    assert s.sources[1] as int == 6;
    assert (s.offsets as object) != (s.sources as object);
  }

  method XofOwned(rate: T.I, input: array<bv8>, length: T.I) returns(output: array<bv8>)
    requires S.ValidRate(rate as int)
    requires T.JavaLength(input.Length) && 0 <= length
    ensures fresh(output) && output.Length == length as int
    ensures (output as object) != (input as object)
    ensures output[..] == S.Xof(rate as int,old(input[..]),length as int)
    ensures input[..] == old(input[..])
  {
    ghost var bytes := input[..];
    output := V.Xof(rate,input,length);
    assert fresh(output) && output.Length == length as int;
    assert output[..] == S.Xof(rate as int,bytes,length as int);
    assert input[..] == bytes;
    assert (output as object) != (input as object);
  }

  method NewOwned(rate: T.I) returns(s: V.Sponge)
    requires S.ValidRate(rate as int)
    ensures FactoryOwned(s) && fresh(Footprint(s)) && |Footprint(s)| == 6
    ensures s.Model() == S.Initial(rate as int)
    ensures s.rate == rate
  {
    s := new V.Sponge(rate);
    ValidFootprint(s);
    assert FactoryOwned(s) && fresh(Footprint(s)) && |Footprint(s)| == 6;
  }

  // Arbitrary pre-existing external arrays are outside the fresh factory
  // footprint. The owned arrays are therefore fresh relative to them and
  // pairwise disjoint from them and from one another.
  method ExternalFootprint(rate: T.I,
      a: array<bv8>, b: array<bv8>, c: array<bv8>, d: array<bv8>)
    requires S.ValidRate(rate as int)
    requires T.JavaLength(a.Length) && T.JavaLength(b.Length) &&
             T.JavaLength(c.Length) && T.JavaLength(d.Length)
  {
    var s := new V.Sponge(rate);
    ValidFootprint(s);
    assert FactoryOwned(s) && PairwiseDisjoint(s) && fresh(Footprint(s));
    assert (a as object) !in Footprint(s) && (b as object) !in Footprint(s);
    assert (c as object) !in Footprint(s) && (d as object) !in Footprint(s);
    assert (a as object) != (s.lanes as object) && (a as object) != (s.scratch as object);
    assert (a as object) != (s.parity as object) && (a as object) != (s.offsets as object);
    assert (a as object) != (s.sources as object);
    assert (b as object) != (s.lanes as object) && (b as object) != (s.scratch as object);
    assert (b as object) != (s.parity as object) && (b as object) != (s.offsets as object);
    assert (b as object) != (s.sources as object);
  }

  // Arbitrary external buffers with distinct input and output arrays. Update
  // preserves the input, Read writes only output, both methods preserve the
  // owned footprint identity, and Destroy leaves the external output intact.
  method ExternalDistinct(rate: T.I, input: array<bv8>, output: array<bv8>)
    requires S.ValidRate(rate as int)
    requires T.JavaLength(input.Length) && T.JavaLength(output.Length)
    requires (input as object) != (output as object)
    modifies output
    ensures input[..] == old(input[..])
    ensures output[..] == S.Xof(rate as int,old(input[..]),output.Length as int)
  {
    ghost var inputBytes := input[..];
    var s := new V.Sponge(rate);
    ValidFootprint(s);
    ghost var identity := Identity(s);
    assert FactoryOwned(s) && fresh(Footprint(s));
    assert (input as object) !in Footprint(s) && (output as object) !in Footprint(s);
    var status := s.Update(input,0,input.Length as T.I);
    assert status == 0;
    assert input[..] == inputBytes;
    assert Identity(s) == identity;
    assert (input.Length as T.I) as int == input.Length;
    assert input[0..input.Length] == inputBytes;
    assert s.Model() == S.Absorb(S.Initial(rate as int),input[0..input.Length]);
    assert s.Model() == S.Absorb(S.Initial(rate as int),inputBytes);
    ghost var model := s.Model();
    assert (output as object) != (s.sources as object);
    assert (output as object) != (s.offsets as object);
    s.Read(output);
    assert Identity(s) == identity;
    assert input[..] == inputBytes;
    assert S.ReadResult(s.Model(),output[..]) == S.Read(model,output.Length);
    assert output[..] == S.Xof(rate as int,inputBytes,output.Length as int);
    ghost var result := output[..];
    s.Destroy();
    assert Identity(s) == identity;
    assert input[..] == inputBytes;
    assert output[..] == result;
  }

  // The same external array is both input and output. Update still preserves
  // its pre-read contents, Read overwrites it with the XOF, and Destroy leaves
  // that returned output intact. Alias identity comes from the fresh footprint,
  // not from a caller precondition.
  method ExternalAliased(rate: T.I, buffer: array<bv8>)
    requires S.ValidRate(rate as int)
    requires T.JavaLength(buffer.Length)
    modifies buffer
    ensures buffer[..] == S.Xof(rate as int,old(buffer[..]),buffer.Length as int)
  {
    ghost var inputBytes := buffer[..];
    var s := new V.Sponge(rate);
    ValidFootprint(s);
    ghost var identity := Identity(s);
    assert FactoryOwned(s) && fresh(Footprint(s));
    assert (buffer as object) !in Footprint(s);
    var status := s.Update(buffer,0,buffer.Length as T.I);
    assert status == 0;
    assert buffer[..] == inputBytes;
    assert Identity(s) == identity;
    assert (buffer.Length as T.I) as int == buffer.Length;
    assert buffer[0..buffer.Length] == inputBytes;
    assert s.Model() == S.Absorb(S.Initial(rate as int),buffer[0..buffer.Length]);
    assert s.Model() == S.Absorb(S.Initial(rate as int),inputBytes);
    ghost var model := s.Model();
    assert (buffer as object) != (s.sources as object);
    assert (buffer as object) != (s.offsets as object);
    s.Read(buffer);
    assert Identity(s) == identity;
    assert S.ReadResult(s.Model(),buffer[..]) == S.Read(model,buffer.Length);
    assert buffer[..] == S.Xof(rate as int,inputBytes,buffer.Length as int);
    ghost var result := buffer[..];
    s.Destroy();
    assert Identity(s) == identity;
    assert buffer[..] == result;
  }

  // Arbitrary offsets and lengths exercise the real Update status contract.
  // External input and an unused external output are untouched for every
  // status, and the owned footprint identity is preserved.
  method ExternalUpdateFrame(rate: T.I, input: array<bv8>, output: array<bv8>,
      offset: T.I, length: T.I)
    requires S.ValidRate(rate as int)
    requires T.JavaLength(input.Length) && T.JavaLength(output.Length)
    ensures input[..] == old(input[..])
    ensures output[..] == old(output[..])
  {
    ghost var inputBytes := input[..];
    ghost var outputBytes := output[..];
    var s := new V.Sponge(rate);
    ValidFootprint(s);
    ghost var identity := Identity(s);
    assert FactoryOwned(s) && fresh(Footprint(s));
    assert (input as object) !in Footprint(s) && (output as object) !in Footprint(s);
    var status := s.Update(input,offset,length);
    assert status == (if offset < 0 || offset as int > input.Length ||
                       length < 0 || length as int > input.Length-offset as int then 2 else 0);
    assert input[..] == inputBytes;
    assert output[..] == outputBytes;
    assert Identity(s) == identity;
  }

  // Every public Sponge method preserves the const-array footprint and the
  // immutable rate. The sequence also checks post-Destroy output survival.
  method AllMethodFrames(rate: T.I, input: array<bv8>, output: array<bv8>,
      at: T.I, value: bv8)
    requires S.ValidRate(rate as int)
    requires T.JavaLength(input.Length) && T.JavaLength(output.Length)
    requires (input as object) != (output as object)
    requires 0 <= at < 200
    modifies output
    ensures input[..] == old(input[..])
  {
    ghost var inputBytes := input[..];
    var s := new V.Sponge(rate);
    ValidFootprint(s);
    ghost var identity := Identity(s);
    assert FactoryOwned(s) && fresh(Footprint(s));
    assert (input as object) !in Footprint(s) && (output as object) !in Footprint(s);

    s.Permute();
    assert Identity(s) == identity;

    var status := s.Update(input,0,input.Length as T.I);
    assert status == 0;
    assert Identity(s) == identity;
    assert input[..] == inputBytes;

    s.AbsorbOne(value);
    assert Identity(s) == identity;

    s.Start();
    assert Identity(s) == identity && s.squeezing;

    ghost var beforeNext := s.Model();
    var byte := s.Next();
    assert S.ReadResult(s.Model(),[byte]) == S.Next(beforeNext);
    assert Identity(s) == identity && s.squeezing;

    ghost var model := s.Model();
    assert (output as object) != (s.sources as object);
    assert (output as object) != (s.offsets as object);
    s.Read(output);
    assert Identity(s) == identity;
    assert S.ReadResult(s.Model(),output[..]) == S.Read(model,output.Length);
    assert input[..] == inputBytes;

    ghost var result := output[..];
    s.Destroy();
    assert Identity(s) == identity;
    assert output[..] == result;
    assert input[..] == inputBytes;

    // XorByte is a public method too. It is called after Destroy so its weaker
    // precondition (lane length and byte index) is satisfied; it still preserves
    // the footprint even though this harness makes no further functional claim.
    s.XorByte(at,value);
    assert Identity(s) == identity;
  }
}
