include "../primitives/Keccak.dfy"

// FIPS202 byte-oriented SHAKE contract. Mathematical reference state and stream
// laws; executable code lives in Shake.dfy. No external permutation assumption.
module SpongeSpec {
  import K = KeccakSpec
  datatype State = State(lanes: seq<bv64>, rate: int, position: int, squeezing: bool)
  datatype ReadResult = ReadResult(state: State, bytes: seq<bv8>)
  datatype UpdateResult = Updated(state: State) | InputAfterOutput | InvalidSlice

  predicate ValidRate(rate: int) { rate == 136 || rate == 168 }
  predicate Valid(s: State) {
    |s.lanes| == 25 && ValidRate(s.rate) && 0 <= s.position &&
    (if s.squeezing then s.position <= s.rate else s.position < s.rate)
  }
  ghost function Initial(rate: int): State
    requires ValidRate(rate)
    ensures Valid(Initial(rate)) && !Initial(rate).squeezing
  { State(seq(25, i => 0 as bv64), rate, 0, false) }

  ghost function XorByte(lanes: seq<bv64>, at: int, value: bv8): seq<bv64>
    requires |lanes| == 25 && 0 <= at < 200
    ensures |XorByte(lanes, at, value)| == 25
  { lanes[at/8 := lanes[at/8] ^ ((value as bv64) << (8*(at%8)))] }
  ghost function {:opaque} ByteAt(lanes: seq<bv64>, at: int): bv8
    requires |lanes| == 25 && 0 <= at < 200
  { ((lanes[at/8] >> (8*(at%8))) & 255) as bv8 }
  lemma ByteAtEquation(lanes: seq<bv64>, at: int)
    requires |lanes| == 25 && 0 <= at < 200
    ensures ByteAt(lanes,at) == ((lanes[at/8] >> (8*(at%8))) & 255) as bv8
  { reveal ByteAt(); }

  ghost function {:opaque} AbsorbOne(s: State, value: bv8): State
    requires Valid(s) && !s.squeezing
    ensures Valid(AbsorbOne(s, value)) && !AbsorbOne(s, value).squeezing
    ensures AbsorbOne(s, value).rate == s.rate
  {
    var lanes := XorByte(s.lanes, s.position, value);
    if s.position+1 == s.rate then State(K.Iter(lanes, 24), s.rate, 0, false)
    else State(lanes, s.rate, s.position+1, false)
  }
  lemma AbsorbOneEquation(s: State, value: bv8)
    requires Valid(s) && !s.squeezing
    ensures AbsorbOne(s, value) ==
      (if s.position+1 == s.rate then State(K.Iter(XorByte(s.lanes,s.position,value),24),s.rate,0,false)
       else State(XorByte(s.lanes,s.position,value),s.rate,s.position+1,false))
  { reveal AbsorbOne(); }

  ghost function {:opaque} Absorb(s: State, input: seq<bv8>): State
    requires Valid(s) && !s.squeezing
    ensures Valid(Absorb(s, input)) && !Absorb(s, input).squeezing
    ensures Absorb(s, input).rate == s.rate
    decreases |input|
  {
    if |input| == 0 then s
    else AbsorbOne(Absorb(s,input[..|input|-1]),input[|input|-1])
  }
  lemma AbsorbEmpty(s: State)
    requires Valid(s) && !s.squeezing
    ensures Absorb(s,[]) == s
  { reveal Absorb(); }
  lemma AbsorbStep(s: State, input: seq<bv8>, value: bv8)
    requires Valid(s) && !s.squeezing
    ensures Absorb(s,input+[value]) == AbsorbOne(Absorb(s,input),value)
  { reveal Absorb(); }
  ghost function UpdateSlice(s: State, input: seq<bv8>, offset: int, length: int): UpdateResult
    requires Valid(s)
  {
    if s.squeezing then InputAfterOutput
    else if offset < 0 || offset > |input| || length < 0 || length > |input|-offset then InvalidSlice
    else Updated(Absorb(s,input[offset..offset+length]))
  }
  lemma {:isolate_assertions} AbsorbConcat(s: State, a: seq<bv8>, b: seq<bv8>)
    requires Valid(s) && !s.squeezing
    ensures Absorb(s,a+b) == Absorb(Absorb(s,a),b)
    decreases |b|
  {
    if |b| == 0 {
      assert b == [];
      assert a+b == a;
      AbsorbEmpty(Absorb(s,a));
    }
    else {
      var prefix := b[..|b|-1]; var value := b[|b|-1];
      assert b == prefix+[value];
      AbsorbConcat(s,a,prefix);
      AbsorbStep(s,a+prefix,value);
      AbsorbStep(Absorb(s,a),prefix,value);
      assert a+b == (a+prefix)+[value];
      calc {
        Absorb(s,a+b);
        == AbsorbOne(Absorb(s,a+prefix),value);
        == AbsorbOne(Absorb(Absorb(s,a),prefix),value);
        == Absorb(Absorb(s,a),prefix+[value]);
        == Absorb(Absorb(s,a),b);
      }
    }
  }

  ghost function {:opaque} Pad(s: State): State
    requires Valid(s) && !s.squeezing
    ensures Valid(Pad(s)) && Pad(s).squeezing && Pad(s).position == 0
    ensures Pad(s).rate == s.rate
  {
    var a := XorByte(s.lanes,s.position,0x1f);
    var b := XorByte(a,s.rate-1,0x80);
    State(K.Iter(b,24),s.rate,0,true)
  }
  lemma PadEquation(s: State)
    requires Valid(s) && !s.squeezing
    ensures Pad(s) == State(K.Iter(XorByte(XorByte(s.lanes,s.position,0x1f),s.rate-1,0x80),24),s.rate,0,true)
  { reveal Pad(); }
  ghost function Start(s: State): State
    requires Valid(s)
    ensures Valid(Start(s)) && Start(s).squeezing && Start(s).rate == s.rate
  { if s.squeezing then s else Pad(s) }

  ghost function {:opaque} Next(s: State): ReadResult
    requires Valid(s) && s.squeezing
    ensures Valid(Next(s).state) && Next(s).state.squeezing
    ensures Next(s).state.rate == s.rate && |Next(s).bytes| == 1
  {
    var ready := if s.position == s.rate then State(K.Iter(s.lanes,24),s.rate,0,true) else s;
    ReadResult(State(ready.lanes,s.rate,ready.position+1,true),[ByteAt(ready.lanes,ready.position)])
  }
  lemma NextEquation(s: State)
    requires Valid(s) && s.squeezing
    ensures Next(s) ==
      (var ready := if s.position == s.rate then State(K.Iter(s.lanes,24),s.rate,0,true) else s;
       ReadResult(State(ready.lanes,s.rate,ready.position+1,true),[ByteAt(ready.lanes,ready.position)]))
  { reveal Next(); }

  ghost function {:opaque} RawRead(s: State, length: nat): ReadResult
    requires Valid(s) && s.squeezing
    ensures Valid(RawRead(s,length).state) && RawRead(s,length).state.squeezing
    ensures RawRead(s,length).state.rate == s.rate && |RawRead(s,length).bytes| == length
    decreases length
  {
    if length == 0 then ReadResult(s,[])
    else
      var prior := RawRead(s,length-1);
      var next := Next(prior.state);
      ReadResult(next.state,prior.bytes+next.bytes)
  }
  lemma RawReadEmpty(s: State)
    requires Valid(s) && s.squeezing
    ensures RawRead(s,0) == ReadResult(s,[])
  { reveal RawRead(); }
  lemma RawReadStep(s: State, length: nat)
    requires Valid(s) && s.squeezing
    ensures RawRead(s,length+1) ==
      (var prior := RawRead(s,length); var next := Next(prior.state);
       ReadResult(next.state,prior.bytes+next.bytes))
  { reveal RawRead(); }

  ghost function Read(s: State, length: nat): ReadResult
    requires Valid(s)
    ensures Valid(Read(s,length).state) && Read(s,length).state.squeezing
    ensures Read(s,length).state.rate == s.rate && |Read(s,length).bytes| == length
  { RawRead(Start(s),length) }
  lemma RawReadSplit(s: State, a: nat, b: nat)
    requires Valid(s) && s.squeezing
    ensures RawRead(s,a+b) ==
      (var first := RawRead(s,a); var second := RawRead(first.state,b);
       ReadResult(second.state,first.bytes+second.bytes))
    decreases b
  {
    if b == 0 { RawReadEmpty(RawRead(s,a).state); }
    else {
      RawReadSplit(s,a,b-1);
      RawReadStep(s,a+b-1);
      RawReadStep(RawRead(s,a).state,b-1);
    }
  }
  lemma ReadSplit(s: State, a: nat, b: nat)
    requires Valid(s)
    ensures Read(s,a+b) ==
      (var first := Read(s,a); var second := Read(first.state,b);
       ReadResult(second.state,first.bytes+second.bytes))
  { RawReadSplit(Start(s),a,b); }
  ghost function Xof(rate: int, input: seq<bv8>, length: nat): seq<bv8>
    requires ValidRate(rate)
    ensures |Xof(rate,input,length)| == length
  { Read(Absorb(Initial(rate),input),length).bytes }
}
