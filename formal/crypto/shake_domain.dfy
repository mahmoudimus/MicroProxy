include "Shake.dfy"
include "ByteLanes.dfy"

// Caller domains use literal FIPS202 bounds, independently of the predicates
// under test. No message, partition, lane value, or finite output is sampled.
module ShakePublicDomain {
  import V = VerifiedShake
  import S = SpongeSpec
  import B = ByteLanes
  import K = KeccakSpec

  predicate Legal(s: S.State) {
    |s.lanes| == 25 && (s.rate == 136 || s.rate == 168) &&
    0 <= s.position &&
    (if s.squeezing then s.position <= s.rate else s.position < s.rate)
  }

  method AllRates(rate: int)
    requires rate == 136 || rate == 168
  {
    var state := V.New(rate);
    assert state == S.Initial(rate) && Legal(state);
  }

  method AllUpdates(s: S.State, input: seq<bv8>)
    requires Legal(s)
  {
    var r := V.Update(s,input);
    assert r == (if s.squeezing then S.InputAfterOutput else S.Updated(S.Absorb(s,input)));
  }

  method AllSlices(s: S.State, input: seq<bv8>, offset: int, length: int)
    requires Legal(s)
  {
    var r := V.UpdateSlice(s,input,offset,length);
    assert r == S.UpdateSlice(s,input,offset,length);
    if s.squeezing { assert r.InputAfterOutput?; }
    else if offset < 0 || offset > |input| || length < 0 || length > |input|-offset {
      assert r.InvalidSlice?;
    } else { assert r == S.Updated(S.Absorb(s,input[offset..offset+length])); }
  }

  method AllReads(s: S.State, length: nat)
    requires Legal(s)
  {
    var r := V.Read(s,length);
    assert r == S.Read(s,length) && Legal(r.state) && r.state.squeezing;
    assert |r.bytes| == length;
    if length == 0 {
      S.RawReadEmpty(S.Start(s));
      assert r == S.ReadResult(S.Start(s),[]);
    }
  }

  method AllXofs(rate: int, input: seq<bv8>, length: nat)
    requires rate == 136 || rate == 168
  {
    var r := V.Xof(rate,input,length);
    assert r == S.Xof(rate,input,length) && |r| == length;
  }

  method AllAbsorbStates(s: S.State, value: bv8)
    requires Legal(s) && !s.squeezing
  {
    var a := V.AbsorbOne(s,value);
    assert a == S.AbsorbOne(s,value) && Legal(a) && !a.squeezing;
    var p := V.Pad(s);
    assert p == S.Pad(s) && Legal(p) && p.squeezing;
  }

  method AllSqueezeStates(s: S.State)
    requires Legal(s) && s.squeezing
  {
    var r := V.Next(s);
    assert r == S.Next(s) && Legal(r.state) && r.state.squeezing;
  }

  method AllLaneBytes(lanes: seq<bv64>, at: int, value: bv8)
    requires |lanes| == 25 && 0 <= at < 200
  {
    var r := V.XorByte(lanes,at,value);
    assert r == S.XorByte(lanes,at,value);
    B.SpecByteAt(lanes,at);
    B.UnpackLanesRoundtrip(lanes);
  }

  method UpdatePartitions(s: S.State, a: seq<bv8>, b: seq<bv8>)
    requires Legal(s) && !s.squeezing
  {
    var whole := V.Update(s,a+b);
    var first := V.Update(s,a);
    var second := V.Update(first.state,b);
    S.AbsorbConcat(s,a,b);
    assert whole == second;
  }

  method ReadPartitions(s: S.State, a: nat, b: nat)
    requires Legal(s)
  {
    var whole := V.Read(s,a+b);
    var first := V.Read(s,a);
    var second := V.Read(first.state,b);
    S.ReadSplit(s,a,b);
    assert whole == S.ReadResult(second.state,first.bytes+second.bytes);
  }

  method SharedPaddingOctet(s: S.State)
    requires Legal(s) && !s.squeezing && s.position == s.rate-1
  {
    var r := V.Pad(s);
    S.PadEquation(s);
    // Both XORs must reach the same octet before the permutation. Keeping
    // them explicit catches an overwrite that drops the SHAKE suffix.
    assert r == S.State(K.Iter(S.XorByte(S.XorByte(s.lanes,s.rate-1,0x1f),s.rate-1,0x80),24),s.rate,0,true);
  }
}
