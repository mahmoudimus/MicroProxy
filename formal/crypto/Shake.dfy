include "SpongeSpec.dfy"

module VerifiedShake {
  import S = SpongeSpec
  import K = VerifiedKeccak
  method New(rate: int) returns (r: S.State)
    requires S.ValidRate(rate)
    ensures r == S.Initial(rate) && S.Valid(r)
  { r := S.State(seq(25,i => 0 as bv64),rate,0,false); }

  method XorByte(lanes: seq<bv64>, at: int, value: bv8) returns (r: seq<bv64>)
    requires |lanes| == 25 && 0 <= at < 200
    ensures r == S.XorByte(lanes,at,value)
  { r := lanes[at/8 := lanes[at/8] ^ ((value as bv64) << (8*(at%8)))]; }

  method AbsorbOne(s: S.State, value: bv8) returns (r: S.State)
    requires S.Valid(s) && !s.squeezing
    ensures r == S.AbsorbOne(s,value) && S.Valid(r) && !r.squeezing
  {
    var lanes := XorByte(s.lanes,s.position,value);
    if s.position+1 == s.rate {
      lanes := K.Permute(lanes);
      r := S.State(lanes,s.rate,0,false);
    } else { r := S.State(lanes,s.rate,s.position+1,false); }
    S.AbsorbOneEquation(s,value);
  }
  method Pad(s: S.State) returns (r: S.State)
    requires S.Valid(s) && !s.squeezing
    ensures r == S.Pad(s) && S.Valid(r) && r.squeezing
  {
    var lanes := XorByte(s.lanes,s.position,0x1f);
    lanes := XorByte(lanes,s.rate-1,0x80);
    lanes := K.Permute(lanes);
    r := S.State(lanes,s.rate,0,true);
    S.PadEquation(s);
  }
  method {:isolate_assertions} Update(s: S.State, input: seq<bv8>) returns (r: S.UpdateResult)
    requires S.Valid(s)
    ensures r == (if s.squeezing then S.InputAfterOutput else S.Updated(S.Absorb(s,input)))
  {
    if s.squeezing { r := S.InputAfterOutput; return; }
    var current := s;
    S.AbsorbEmpty(s);
    for i := 0 to |input|
      invariant S.Valid(current) && !current.squeezing
      invariant current == S.Absorb(s,input[..i])
    {
      S.AbsorbStep(s,input[..i],input[i]);
      current := AbsorbOne(current,input[i]);
      assert input[..i]+[input[i]] == input[..i+1];
    }
    assert !s.squeezing;
    assert input[..|input|] == input;
    assert current == S.Absorb(s,input);
    r := S.Updated(current);
    assert r == S.Updated(S.Absorb(s,input));
  }
  method {:isolate_assertions} Next(s: S.State) returns (r: S.ReadResult)
    requires S.Valid(s) && s.squeezing
    ensures r == S.Next(s) && S.Valid(r.state) && r.state.squeezing
  {
    var ready := s;
    if ready.position == ready.rate {
      var lanes := K.Permute(ready.lanes);
      ready := S.State(lanes,s.rate,0,true);
    }
    S.ByteAtEquation(ready.lanes,ready.position);
    var value := ((ready.lanes[ready.position/8] >> (8*(ready.position%8))) & 255) as bv8;
    r := S.ReadResult(S.State(ready.lanes,s.rate,ready.position+1,true),[value]);
    S.NextEquation(s);
  }
  method UpdateSlice(s: S.State, input: seq<bv8>, offset: int, length: int) returns (r: S.UpdateResult)
    requires S.Valid(s)
    ensures r == S.UpdateSlice(s,input,offset,length)
  {
    if s.squeezing { r := S.InputAfterOutput; return; }
    if offset < 0 || offset > |input| || length < 0 || length > |input|-offset {
      r := S.InvalidSlice; return;
    }
    r := Update(s,input[offset..offset+length]);
  }
  method Read(s: S.State, length: nat) returns (r: S.ReadResult)
    requires S.Valid(s)
    ensures r == S.Read(s,length) && S.Valid(r.state) && r.state.squeezing
    ensures |r.bytes| == length
  {
    var initial := s;
    if !initial.squeezing { initial := Pad(initial); }
    assert initial == S.Start(s);
    var current := initial;
    var bytes: seq<bv8> := [];
    S.RawReadEmpty(initial);
    for i := 0 to length
      invariant S.Valid(current) && current.squeezing
      invariant S.ReadResult(current,bytes) == S.RawRead(initial,i)
    {
      S.RawReadStep(initial,i);
      var next := Next(current);
      current := next.state;
      bytes := bytes+next.bytes;
    }
    r := S.ReadResult(current,bytes);
  }
  method Xof(rate: int, input: seq<bv8>, length: nat) returns (r: seq<bv8>)
    requires S.ValidRate(rate)
    ensures r == S.Xof(rate,input,length) && |r| == length
  {
    var state := New(rate);
    var updated := Update(state,input);
    assert updated.Updated?;
    var output := Read(updated.state,length);
    r := output.bytes;
  }
}
