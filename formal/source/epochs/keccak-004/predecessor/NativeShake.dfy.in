include "NativeKeccak.dfy"
include "SpongeSpec.dfy"

module NativeShake {
  import T = NativeTypes
  import S = SpongeSpec
  import K = NativeKeccak
  import P = KeccakSpec

  function XorWord(word: bv64, at: T.I, value: bv8): bv64
    requires 0 <= at < 200
    ensures XorWord(word,at,value) == word ^ ((value as bv64) << (8*((at as int)%8)))
  { word ^ ((value as bv64) << (8*(at%8))) }

  method {:isolate_assertions} Xof(rate: T.I, input: array<bv8>, length: T.I) returns(output: array<bv8>)
    requires S.ValidRate(rate as int) && T.JavaLength(input.Length) && 0 <= length
    ensures fresh(output) && output.Length == length as int
    ensures output[..] == S.Xof(rate as int,input[..],length as int)
  {
    var sponge := new Sponge(rate);
    ghost var before := sponge.Model();
    ghost var bytes := input[..];
    assert before == S.Initial(rate as int);
    var size: T.I := input.Length as T.I;
    assert size as int == input.Length;
    var status := sponge.Update(input,0,size);
    assert status == 0;
    assert input[..] == bytes;
    assert sponge.Model() == S.Absorb(before,input[0..size as int]);
    assert input[0..size as int] == input[..];
    assert sponge.Model() == S.Absorb(S.Initial(rate as int),input[..]);
    output := new bv8[length];
    sponge.Read(output);
    assert output[..] == S.Read(S.Absorb(S.Initial(rate as int),input[..]),length as int).bytes;
    assert output[..] == S.Xof(rate as int,input[..],length as int);
    ghost var result := output[..];
    sponge.Destroy();
    assert output[..] == result;
  }

  // The Java facade owns this instance exclusively. State snapshots/contracts
  // are ghost; byte/long arrays and bounded native indices are executable.
  class Sponge {
    const lanes: array<bv64>
    const scratch: array<bv64>
    const parity: array<bv64>
    const offsets: array<T.I>
    const sources: array<T.I>
    const rate: T.I
    var position: T.I
    var squeezing: bool

    ghost function Model(): S.State
      reads this,lanes
    { S.State(lanes[..],rate as int,position as int,squeezing) }
    ghost predicate Valid()
      reads this,lanes,offsets,sources
    {
      lanes.Length == 25 && scratch.Length == 25 && parity.Length == 5 && offsets.Length == 25 && sources.Length == 25 &&
      lanes != scratch && lanes != parity && scratch != parity &&
      (offsets as object) != (lanes as object) && (offsets as object) != (scratch as object) && (offsets as object) != (parity as object) &&
      (forall i: int :: 0 <= i < 25 ==> 0 <= offsets[i] < 64 && offsets[i] as int == P.Offsets()[i]%64) &&
      (sources as object) != (lanes as object) && (sources as object) != (scratch as object) && (sources as object) != (parity as object) &&
      (forall i: int :: 0 <= i < 25 ==> 0 <= sources[i] < 25 && sources[i] as int == ((i%5)+3*(i/5))%5+5*(i%5)) &&
      S.Valid(Model())
    }

    constructor(r: T.I)
      requires S.ValidRate(r as int)
      ensures Valid() && Model() == S.Initial(r as int)
      ensures fresh(lanes) && fresh(scratch) && fresh(parity) && fresh(offsets) && fresh(sources)
    {
      var table := K.NewOffsets(); var indexTable := K.NewSources();
      lanes := new bv64[25];
      scratch := new bv64[25]; parity := new bv64[5]; offsets := table; sources := indexTable;
      rate := r; position := 0; squeezing := false;
      new;
      for i: T.I := 0 to 25
        modifies lanes
        invariant forall k: int :: 0 <= k < i as int ==> lanes[k] == 0
      { lanes[i] := 0; }
    }

    method {:isolate_assertions} XorByte(at: T.I, value: bv8)
      requires lanes.Length == 25 && 0 <= at < 200
      modifies lanes
      ensures lanes[..] == S.XorByte(old(lanes[..]),at as int,value)
    {
      var j: T.I := at/8;
      ghost var before := lanes[..];
      var updated := XorWord(lanes[j],at,value);
      K.SetLane(lanes,j,updated);
      assert j as int == (at as int)/8;
      assert lanes[..] == before[(at as int)/8 := before[(at as int)/8] ^ ((value as bv64) << (8*((at as int)%8)))];
    }

    method Permute()
      requires Valid()
      modifies lanes,scratch,parity
      ensures Valid() && lanes[..] == P.Iter(old(lanes[..]),24)
    { K.PermuteScratch(lanes,scratch,parity,offsets,sources); }

    method {:isolate_assertions} AbsorbOne(value: bv8)
      requires Valid() && !squeezing
      modifies this,lanes,scratch,parity
      ensures Valid() && Model() == S.AbsorbOne(old(Model()),value)
    {
      ghost var before := Model();
      XorByte(position,value);
      if position+1 == rate {
        Permute(); position := 0;
      } else { position := position+1; }
      S.AbsorbOneEquation(before,value);
    }

    // status 0=updated, 1=input after output, 2=invalid slice. Invalid calls
    // preserve every state byte; phase errors take precedence over bounds.
    method {:isolate_assertions} Update(input: array<bv8>, offset: T.I, length: T.I) returns(status: T.I)
      requires Valid() && T.JavaLength(input.Length)
      modifies this,lanes,scratch,parity
      ensures Valid()
      ensures status == (if old(squeezing) then 1 else
        if offset < 0 || offset as int > input.Length || length < 0 || length as int > input.Length-offset as int then 2 else 0)
      ensures status != 0 ==> Model() == old(Model())
      ensures status == 0 ==> Model() == S.Absorb(old(Model()),input[offset as int..offset as int+length as int])
    {
      if squeezing { return 1; }
      var size: T.I := input.Length as T.I;
      if offset < 0 || offset > size || length < 0 || length > size-offset { return 2; }
      ghost var before := Model();
      ghost var bytes := input[offset as int..offset as int+length as int];
      S.AbsorbEmpty(before);
      for i: T.I := 0 to length
        modifies this,lanes,scratch,parity
        invariant Valid() && !squeezing
        invariant Model() == S.Absorb(before,bytes[..i as int])
      {
        S.AbsorbStep(before,bytes[..i as int],input[offset+i]);
        AbsorbOne(input[offset+i]);
        assert bytes[..i as int]+[bytes[i]] == bytes[..i as int+1];
      }
      assert bytes[..length as int] == bytes;
      assert Model() == S.Absorb(before,bytes);
      assert bytes == input[offset as int..offset as int+length as int];
      status := 0;
    }

    method {:isolate_assertions} Start()
      requires Valid()
      modifies this,lanes,scratch,parity
      ensures Valid() && squeezing && Model() == S.Start(old(Model()))
    {
      ghost var before := Model();
      if !squeezing {
        XorByte(position,0x1f); XorByte(rate-1,0x80);
        Permute();
        position := 0; squeezing := true;
        S.PadEquation(before);
      }
    }

    method {:isolate_assertions} Next() returns(value: bv8)
      requires Valid() && squeezing
      modifies this,lanes,scratch,parity
      ensures Valid() && squeezing
      ensures S.ReadResult(Model(),[value]) == S.Next(old(Model()))
    {
      ghost var before := Model();
      if position == rate { Permute(); position := 0; }
      S.ByteAtEquation(lanes[..],position as int);
      value := ((lanes[position/8] >> (8*(position%8))) & 255) as bv8;
      position := position+1;
      S.NextEquation(before);
    }

    method {:isolate_assertions} Read(output: array<bv8>)
      requires Valid() && T.JavaLength(output.Length)
      requires (output as object) != (sources as object)
      requires (output as object) != (offsets as object)
      modifies this,lanes,scratch,parity,output
      ensures Valid() && squeezing
      ensures S.ReadResult(Model(),output[..]) == S.Read(old(Model()),output.Length)
    {
      ghost var before := Model();
      Start();
      ghost var initial := Model();
      S.RawReadEmpty(initial);
      var length: T.I := output.Length as T.I;
      for i: T.I := 0 to length
        modifies this,lanes,scratch,parity,output
        invariant Valid() && squeezing
        invariant S.ReadResult(Model(),output[..i as int]) == S.RawRead(initial,i as int)
      {
        S.RawReadStep(initial,i as int);
        output[i] := Next();
      }
    }

    // Source-level erasure contract. Physical/JIT/provider erasure is a runtime
    // trust assumption; the proof does not make a machine-memory timing claim.
    method Destroy()
      requires Valid()
      modifies this,lanes,scratch,parity
      ensures Valid() && !squeezing && position == 0
      ensures forall i: int :: 0 <= i < 25 ==> lanes[i] == 0 && scratch[i] == 0
      ensures forall i: int :: 0 <= i < 5 ==> parity[i] == 0
    {
      K.Wipe(lanes); K.Wipe(scratch); K.Wipe(parity);
      position := 0; squeezing := false;
    }
  }
}
