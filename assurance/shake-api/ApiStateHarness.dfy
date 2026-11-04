// SHAKE public API state/status coupling.
//
// Two arbitrary valid paired NativeShake.Sponge instances with equal public
// (rate, position, squeezing) fields and arbitrary independent secret lane/
// scratch contents.  For equal public input lengths, slice arguments and
// requested output lengths, corresponding actual API calls return equal status
// and preserve equality of the public fields.  Secret bytes are never compared.
//
// Cross-run writable footprints are explicitly separated.  Within-call aliases
// admitted by the production contracts are preserved, including a Read output
// buffer shared by both runs (oa == ob) as long as it lies outside both
// instances' footprints.  Boundary/rollover facts are derived locally from the
// existing SpongeSpec equations (no closed-form position arithmetic).
include "../../formal/crypto/NativeShake.dfy"

module ShakeApiState {
  import T = NativeTypes
  import S = SpongeSpec
  import N = NativeShake

  ghost predicate SamePublic(a: S.State, b: S.State) {
    a.rate == b.rate && a.position == b.position && a.squeezing == b.squeezing
  }

  ghost function Footprint(s: N.Sponge): set<object>
    reads s, s.lanes, s.scratch, s.parity, s.offsets, s.sources
  { {s, s.lanes, s.scratch, s.parity, s.offsets, s.sources} }

  // Explicit cross-run separation: the two instances' objects/arrays are
  // disjoint, so no call on one can write the other's state or lookup tables.
  ghost predicate Separated(a: N.Sponge, b: N.Sponge)
    reads a, b, a.lanes, a.scratch, a.parity, a.offsets, a.sources,
          b.lanes, b.scratch, b.parity, b.offsets, b.sources
  { Footprint(a) !! Footprint(b) }

  // Output buffers may alias the *own* instance's arrays (the production
  // contracts admit that) but never the other instance's footprint.
  ghost predicate SeparatedWithOutputs(a: N.Sponge, b: N.Sponge,
                                       oa: array<bv8>, ob: array<bv8>)
    reads a, b, a.lanes, a.scratch, a.parity, a.offsets, a.sources,
          b.lanes, b.scratch, b.parity, b.offsets, b.sources, oa, ob
  { Separated(a, b) && oa !in Footprint(b) && ob !in Footprint(a) }

  lemma SeparatedFacts(a: N.Sponge, b: N.Sponge)
    requires Separated(a, b)
    ensures a != b
    ensures (a.lanes as object) != (b.lanes as object)
    ensures (a.lanes as object) != (b.scratch as object)
    ensures (a.lanes as object) != (b.parity as object)
    ensures (a.lanes as object) != (b.offsets as object)
    ensures (a.lanes as object) != (b.sources as object)
    ensures (b.lanes as object) != (a.scratch as object)
    ensures (b.lanes as object) != (a.parity as object)
    ensures (b.lanes as object) != (a.offsets as object)
    ensures (b.lanes as object) != (a.sources as object)
    ensures (a.scratch as object) != (b.lanes as object)
    ensures (a.scratch as object) != (b.scratch as object)
    ensures (a.scratch as object) != (b.parity as object)
    ensures (a.parity as object) != (b.lanes as object)
    ensures (a.parity as object) != (b.scratch as object)
    ensures (a.parity as object) != (b.parity as object)
  {
    assert a in Footprint(a);
    assert a.lanes as object in Footprint(a) && a.scratch as object in Footprint(a);
    assert a.parity as object in Footprint(a) && a.offsets as object in Footprint(a);
    assert a.sources as object in Footprint(a);
    assert b in Footprint(b);
    assert b.lanes as object in Footprint(b) && b.scratch as object in Footprint(b);
    assert b.parity as object in Footprint(b) && b.offsets as object in Footprint(b);
    assert b.sources as object in Footprint(b);
  }

  lemma OutputFacts(a: N.Sponge, b: N.Sponge, oa: array<bv8>, ob: array<bv8>)
    requires SeparatedWithOutputs(a, b, oa, ob)
    ensures (oa as object) != (b.lanes as object)
    ensures (oa as object) != (b.scratch as object)
    ensures (oa as object) != (b.parity as object)
    ensures (oa as object) != (b.offsets as object)
    ensures (oa as object) != (b.sources as object)
    ensures (oa as object) != (b as object)
    ensures (ob as object) != (a.lanes as object)
    ensures (ob as object) != (a.scratch as object)
    ensures (ob as object) != (a.parity as object)
    ensures (ob as object) != (a.offsets as object)
    ensures (ob as object) != (a.sources as object)
    ensures (ob as object) != (a as object)
  {
    SeparatedFacts(a, b);
    assert b.lanes as object in Footprint(b);
    assert b.scratch as object in Footprint(b);
    assert b.parity as object in Footprint(b);
    assert b.offsets as object in Footprint(b);
    assert b.sources as object in Footprint(b);
    assert b in Footprint(b);
    assert a.lanes as object in Footprint(a);
    assert a.scratch as object in Footprint(a);
    assert a.parity as object in Footprint(a);
    assert a.offsets as object in Footprint(a);
    assert a.sources as object in Footprint(a);
    assert a in Footprint(a);
  }

  // ---------------------------------------------------------------------------
  // Ghost relational lemmas over the existing SpongeSpec equations.
  // ---------------------------------------------------------------------------

  lemma AbsorbOneSamePublic(s: S.State, t: S.State, v: bv8, w: bv8)
    requires S.Valid(s) && S.Valid(t) && !s.squeezing && !t.squeezing && SamePublic(s, t)
    ensures SamePublic(S.AbsorbOne(s, v), S.AbsorbOne(t, w))
  {
    S.AbsorbOneEquation(s, v);
    S.AbsorbOneEquation(t, w);
    if s.position + 1 == s.rate {
      assert t.position + 1 == t.rate;
    } else {
      assert t.position + 1 != t.rate;
    }
  }

  lemma AbsorbSamePublicLen(s: S.State, t: S.State, a: seq<bv8>, b: seq<bv8>)
    requires S.Valid(s) && S.Valid(t) && !s.squeezing && !t.squeezing && SamePublic(s, t)
    requires |a| == |b|
    ensures SamePublic(S.Absorb(s, a), S.Absorb(t, b))
    decreases |a|
  {
    if |a| == 0 {
      assert b == [];
      S.AbsorbEmpty(s);
      S.AbsorbEmpty(t);
    } else {
      var pa := a[..|a| - 1];
      var pb := b[..|b| - 1];
      assert |pa| == |pb|;
      assert a == pa + [a[|a| - 1]] && b == pb + [b[|b| - 1]];
      AbsorbSamePublicLen(s, t, pa, pb);
      AbsorbOneSamePublic(S.Absorb(s, pa), S.Absorb(t, pb), a[|a| - 1], b[|b| - 1]);
      S.AbsorbStep(s, pa, a[|a| - 1]);
      S.AbsorbStep(t, pb, b[|b| - 1]);
    }
  }

  lemma PadSamePublic(s: S.State, t: S.State)
    requires S.Valid(s) && S.Valid(t) && !s.squeezing && !t.squeezing && SamePublic(s, t)
    ensures SamePublic(S.Pad(s), S.Pad(t))
  {
    S.PadEquation(s);
    S.PadEquation(t);
  }

  lemma StartSamePublic(s: S.State, t: S.State)
    requires S.Valid(s) && S.Valid(t) && SamePublic(s, t)
    ensures SamePublic(S.Start(s), S.Start(t))
  {
    if !s.squeezing {
      assert !t.squeezing;
      PadSamePublic(s, t);
    }
  }

  lemma NextSamePublic(s: S.State, t: S.State)
    requires S.Valid(s) && S.Valid(t) && s.squeezing && t.squeezing && SamePublic(s, t)
    ensures SamePublic(S.Next(s).state, S.Next(t).state)
  {
    S.NextEquation(s);
    S.NextEquation(t);
    if s.position == s.rate {
      assert t.position == t.rate;
    } else {
      assert t.position != t.rate;
    }
  }

  lemma RawReadSamePublic(s: S.State, t: S.State, n: nat)
    requires S.Valid(s) && S.Valid(t) && s.squeezing && t.squeezing && SamePublic(s, t)
    ensures SamePublic(S.RawRead(s, n).state, S.RawRead(t, n).state)
    decreases n
  {
    if n == 0 {
      S.RawReadEmpty(s);
      S.RawReadEmpty(t);
    } else {
      RawReadSamePublic(s, t, n - 1);
      var sa := S.RawRead(s, n - 1).state;
      var ta := S.RawRead(t, n - 1).state;
      NextSamePublic(sa, ta);
      S.RawReadStep(s, n - 1);
      S.RawReadStep(t, n - 1);
      var ns := S.Next(sa);
      var nt := S.Next(ta);
      assert S.RawRead(s, n) == S.ReadResult(ns.state, S.RawRead(s, n - 1).bytes + ns.bytes);
      assert S.RawRead(t, n) == S.ReadResult(nt.state, S.RawRead(t, n - 1).bytes + nt.bytes);
    }
  }

  lemma ReadSamePublic(s: S.State, t: S.State, n: nat)
    requires S.Valid(s) && S.Valid(t) && SamePublic(s, t)
    ensures SamePublic(S.Read(s, n).state, S.Read(t, n).state)
  {
    StartSamePublic(s, t);
    RawReadSamePublic(S.Start(s), S.Start(t), n);
  }

  // Rollover at the exact absorb boundary, from AbsorbOneEquation alone.
  lemma AbsorbRolloverPublic(s: S.State, v: bv8)
    requires S.Valid(s) && !s.squeezing && s.position + 1 == s.rate
    ensures S.Absorb(s, [v]).position == 0 && !S.Absorb(s, [v]).squeezing
    ensures S.Absorb(s, [v]).rate == s.rate
  {
    S.AbsorbEmpty(s);
    S.AbsorbStep(s, [], v);
    assert S.Absorb(s, []) == s;
    assert [] + [v] == [v];
    assert S.Absorb(s, [v]) == S.AbsorbOne(S.Absorb(s, []), v);
    assert S.Absorb(s, [v]) == S.AbsorbOne(s, v);
    S.AbsorbOneEquation(s, v);
  }

  // Next at position == rate rolls over to position 1 (from NextEquation alone).
  lemma NextRolloverPublic(s: S.State)
    requires S.Valid(s) && s.squeezing && s.position == s.rate
    ensures S.Next(s).state.position == 1 && S.Next(s).state.rate == s.rate
    ensures S.Next(s).state.squeezing
  {
    S.NextEquation(s);
  }

  // ---------------------------------------------------------------------------
  // Actual API pairs over arbitrary valid states.
  // ---------------------------------------------------------------------------

  method NewPair(rate: T.I) returns (a: N.Sponge, b: N.Sponge)
    requires S.ValidRate(rate as int)
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures Separated(a, b)
    ensures !a.Model().squeezing && a.Model().position == 0 && a.Model().rate == rate as int
    ensures fresh(a) && fresh(a.lanes) && fresh(a.scratch) && fresh(a.parity)
    ensures fresh(a.offsets) && fresh(a.sources)
    ensures fresh(b) && fresh(b.lanes) && fresh(b.scratch) && fresh(b.parity)
    ensures fresh(b.offsets) && fresh(b.sources)
  {
    a := new N.Sponge(rate);
    b := new N.Sponge(rate);
    assert SamePublic(a.Model(), b.Model());
  }

  method PairUpdate(a: N.Sponge, b: N.Sponge, ina: array<bv8>, inb: array<bv8>,
                    offset: T.I, length: T.I) returns (sa: T.I, sb: T.I)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires Separated(a, b)
    requires T.JavaLength(ina.Length) && T.JavaLength(inb.Length) && ina.Length == inb.Length
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity
    ensures sa == sb
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures sa == (if old(a.Model()).squeezing then 1 else
      if offset < 0 || offset as int > ina.Length || length < 0 ||
         length as int > ina.Length - offset as int then 2 else 0)
    ensures sa == 0 ==>
      a.Model() == S.Absorb(old(a.Model()), ina[offset as int..offset as int + length as int])
    ensures sa != 0 ==> a.Model() == old(a.Model())
    ensures a.Model().squeezing == old(a.Model()).squeezing
    ensures sa == 0 ==> !a.Model().squeezing
  {
    SeparatedFacts(a, b);
    ghost var ba := a.Model();
    ghost var bb := b.Model();
    sa := a.Update(ina, offset, length);
    sb := b.Update(inb, offset, length);
    assert sa == sb;
    if sa == 0 {
      var slicea := ina[offset as int..offset as int + length as int];
      var sliceb := inb[offset as int..offset as int + length as int];
      assert |slicea| == |sliceb|;
      assert a.Model() == S.Absorb(ba, slicea);
      assert b.Model() == S.Absorb(bb, sliceb);
      AbsorbSamePublicLen(ba, bb, slicea, sliceb);
    }
    assert SamePublic(a.Model(), b.Model());
  }

  // Status-only pairs: the two named statuses the production contract defines.
  method PairUpdateInvalid(a: N.Sponge, b: N.Sponge, ina: array<bv8>, inb: array<bv8>,
                           offset: T.I, length: T.I)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires Separated(a, b)
    requires T.JavaLength(ina.Length) && T.JavaLength(inb.Length) && ina.Length == inb.Length
    requires !a.Model().squeezing
    requires offset < 0 || offset as int > ina.Length || length < 0 ||
             length as int > ina.Length - offset as int
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures a.Model() == old(a.Model())
  {
    var sa, sb := PairUpdate(a, b, ina, inb, offset, length);
    assert sa == 2 && sb == 2;
  }

  method PairUpdateAfterOutput(a: N.Sponge, b: N.Sponge, ina: array<bv8>, inb: array<bv8>,
                               offset: T.I, length: T.I)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires Separated(a, b)
    requires T.JavaLength(ina.Length) && T.JavaLength(inb.Length) && ina.Length == inb.Length
    requires a.Model().squeezing
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures a.Model() == old(a.Model())
  {
    var sa, sb := PairUpdate(a, b, ina, inb, offset, length);
    assert sa == 1 && sb == 1;   // phase error precedes slice bounds
  }

  method PairStart(a: N.Sponge, b: N.Sponge)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires Separated(a, b)
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures a.Model().squeezing && b.Model().squeezing
    ensures a.Model() == S.Start(old(a.Model()))
  {
    SeparatedFacts(a, b);
    ghost var ba := a.Model();
    ghost var bb := b.Model();
    a.Start();
    b.Start();
    assert a.Model() == S.Start(ba);
    assert b.Model() == S.Start(bb);
    StartSamePublic(ba, bb);
  }

  method PairNext(a: N.Sponge, b: N.Sponge) returns (va: bv8, vb: bv8)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires a.Model().squeezing && b.Model().squeezing
    requires Separated(a, b)
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures a.Model() == S.Next(old(a.Model())).state
    ensures old(a.Model()).position == old(a.Model()).rate ==> a.Model().position == 1
  {
    SeparatedFacts(a, b);
    ghost var ba := a.Model();
    ghost var bb := b.Model();
    va := a.Next();
    vb := b.Next();
    var ra := S.Next(ba);
    var rb := S.Next(bb);
    assert S.ReadResult(a.Model(), [va]) == ra;
    assert S.ReadResult(b.Model(), [vb]) == rb;
    assert S.ReadResult(a.Model(), [va]).state == a.Model();
    assert S.ReadResult(b.Model(), [vb]).state == b.Model();
    assert a.Model() == ra.state;
    assert b.Model() == rb.state;
    NextSamePublic(ba, bb);
    if ba.position == ba.rate {
      NextRolloverPublic(ba);
    }
  }

  method PairRead(a: N.Sponge, b: N.Sponge, oa: array<bv8>, ob: array<bv8>)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires SeparatedWithOutputs(a, b, oa, ob)
    requires T.JavaLength(oa.Length) && T.JavaLength(ob.Length) && oa.Length == ob.Length
    requires (oa as object) != (a.sources as object) && (oa as object) != (a.offsets as object)
    requires (ob as object) != (b.sources as object) && (ob as object) != (b.offsets as object)
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity, oa, ob
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures a.Model().squeezing && b.Model().squeezing
    ensures a.Model() == S.Read(old(a.Model()), oa.Length as nat).state
    ensures old(a.Model()).squeezing == false ==>
      S.Start(old(a.Model())).position == old(a.Model()).position ||
      S.Start(old(a.Model())).position == 0
  {
    // Snapshot a's OWN state fact immediately, while its output buffer still
    // holds the bytes a.Read wrote (shared oa==ob is admitted and may be
    // overwritten by b.Read; secret output bytes are never compared).
    ghost var ba := a.Model();
    ghost var bb := b.Model();
    OutputFacts(a, b, oa, ob);
    a.Read(oa);
    ghost var ra := S.Read(ba, oa.Length as nat);
    assert S.ReadResult(a.Model(), oa[..]) == ra;
    assert S.ReadResult(a.Model(), oa[..]).state == a.Model();
    assert a.Model() == ra.state;
    // b.Read cannot touch a's lanes (ob is outside a's footprint and the
    // instances are separated), so a's state fact survives independently.
    b.Read(ob);
    ghost var rb := S.Read(bb, ob.Length as nat);
    assert S.ReadResult(b.Model(), ob[..]) == rb;
    assert S.ReadResult(b.Model(), ob[..]).state == b.Model();
    assert b.Model() == rb.state;
    assert a.Model() == ra.state;
    ReadSamePublic(ba, bb, oa.Length as nat);
  }

  // Explicit shared external output case: both runs read into the SAME buffer.
  // Only public state coupling is claimed; the buffer's secret bytes after the
  // second read are not compared with the first run's bytes.
  method PairReadSharedOutput(a: N.Sponge, b: N.Sponge, o: array<bv8>)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires Separated(a, b) && o !in Footprint(a) && o !in Footprint(b)
    requires T.JavaLength(o.Length)
    requires (o as object) != (a.sources as object) && (o as object) != (a.offsets as object)
    requires (o as object) != (b.sources as object) && (o as object) != (b.offsets as object)
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity, o
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures a.Model().squeezing && b.Model().squeezing
    ensures a.Model() == S.Read(old(a.Model()), o.Length as nat).state
  {
    ghost var ba := a.Model();
    ghost var bb := b.Model();
    SeparatedFacts(a, b);
    a.Read(o);
    ghost var ra := S.Read(ba, o.Length as nat);
    assert S.ReadResult(a.Model(), o[..]) == ra;
    assert S.ReadResult(a.Model(), o[..]).state == a.Model();
    assert a.Model() == ra.state;
    b.Read(o);
    ghost var rb := S.Read(bb, o.Length as nat);
    assert S.ReadResult(b.Model(), o[..]) == rb;
    assert S.ReadResult(b.Model(), o[..]).state == b.Model();
    assert b.Model() == rb.state;
    assert a.Model() == ra.state;
    ReadSamePublic(ba, bb, o.Length as nat);
  }

  method PairDestroy(a: N.Sponge, b: N.Sponge)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires Separated(a, b)
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures !a.Model().squeezing && a.Model().position == 0
  {
    SeparatedFacts(a, b);
    a.Destroy();
    b.Destroy();
    assert SamePublic(a.Model(), b.Model());
  }

  // Exact absorb rollover for arbitrary valid states already at rate-1.
  method PairAbsorbBoundary(a: N.Sponge, b: N.Sponge, va: bv8, vb: bv8)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires !a.Model().squeezing && a.Model().position + 1 == a.Model().rate
    requires Separated(a, b)
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures a.Model().position == 0 && !a.Model().squeezing
  {
    var ina := new bv8[1];
    var inb := new bv8[1];
    ina[0] := va;
    inb[0] := vb;
    ghost var ba := a.Model();
    var sa, sb := PairUpdate(a, b, ina, inb, 0, 1);
    assert sa == 0;
    assert a.Model() == S.Absorb(ba, ina[0..1]);
    assert ina[..] == [va];
    assert ina[0..1] == ina[..];
    assert a.Model() == S.Absorb(ba, ina[..]);
    AbsorbRolloverPublic(ba, va);
    assert a.Model().position == 0;
  }

  // Exact Next rollover for arbitrary valid squeezing states at position == rate.
  method PairNextBoundary(a: N.Sponge, b: N.Sponge) returns (va: bv8, vb: bv8)
    requires a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    requires a.Model().squeezing && a.Model().position == a.Model().rate
    requires Separated(a, b)
    modifies a, b, a.lanes, a.scratch, a.parity, b.lanes, b.scratch, b.parity
    ensures a.Valid() && b.Valid() && SamePublic(a.Model(), b.Model())
    ensures a.Model().position == 1
  {
    ghost var ba := a.Model();
    va, vb := PairNext(a, b);
    assert ba.position == ba.rate;
    assert a.Model().position == 1;
  }

  // ---------------------------------------------------------------------------
  // Composed supplementary scenario: constructor, coupled updates with invalid
  // slices, zero Read starting the phase, phase-error precedence over an
  // invalid slice, segmented reads, destroy and reuse.  Cross-run sharing of an
  // external output buffer is exercised by PairReadSharedOutput.
  // ---------------------------------------------------------------------------

  method ScenarioAbsorbPhase(rate: T.I)
    requires S.ValidRate(rate as int)
  {
    var a, b := NewPair(rate);
    var e1 := new bv8[0];
    var e2 := new bv8[0];
    var s1: T.I;
    var s2: T.I;
    assert !a.Model().squeezing && a.Model().position == 0;
    s1, s2 := PairUpdate(a, b, e1, e2, 0, 0);
    assert s1 == 0;
    var small := new bv8[3];
    s1, s2 := PairUpdate(a, b, small, small, 0, 3);
    assert s1 == s2;
    PairUpdateInvalid(a, b, small, small, 5, 1);
    PairStart(a, b);
    assert a.Model().squeezing && b.Model().squeezing;
  }

  method ScenarioReads(rate: T.I)
    requires S.ValidRate(rate as int)
  {
    var a, b := NewPair(rate);
    var r1 := new bv8[0];
    var r2 := new bv8[0];
    PairRead(a, b, r1, r2);
    assert a.Model().squeezing && b.Model().squeezing;
    var small := new bv8[3];
    PairUpdateAfterOutput(a, b, small, small, 99, 99);
    var t1 := new bv8[7];
    var t2 := new bv8[7];
    PairRead(a, b, t1, t2);
    PairRead(a, b, t1, t2);
    assert SamePublic(a.Model(), b.Model());
  }

  method ScenarioDestroyReuse(rate: T.I)
    requires S.ValidRate(rate as int)
  {
    var a, b := NewPair(rate);
    var r1 := new bv8[3];
    var r2 := new bv8[3];
    PairRead(a, b, r1, r2);
    PairDestroy(a, b);
    assert !a.Model().squeezing && a.Model().position == 0;
    var small := new bv8[3];
    var s1, s2 := PairUpdate(a, b, small, small, 0, 1);
    assert s1 == s2 && SamePublic(a.Model(), b.Model());
    PairStart(a, b);
    assert SamePublic(a.Model(), b.Model());
  }

  method ScenarioSharedOutput(rate: T.I)
    requires S.ValidRate(rate as int)
  {
    var a, b := NewPair(rate);
    var u := new bv8[5];
    PairReadSharedOutput(a, b, u);
    assert SamePublic(a.Model(), b.Model());
    var u2 := new bv8[5];
    PairReadSharedOutput(a, b, u2);
    assert SamePublic(a.Model(), b.Model());
  }
}
