// Ghost-only source observation vocabulary and its checked encoding kernel.
//
// The module is deliberately marked {:compile false}.  Dafny recognizes that
// attribute on modules and omits the module (including datatype constructors)
// from generated target code.  All functions below are ghost.  The module is
// therefore vocabulary/proof material, not a runtime observer object, class or
// execution model.
//
// Wire format (tag first, fixed width per tag):
//   1  Call(site,target,arity)                         width 4
//   2  Branch(site,taken)                              width 4
//   3  Read(site,role,address)                         width 4
//   4  Write(site,role,address)                        width 4
//   5  LoopBound(site,bound)                           width 4
//   6  Ops(add,sub,mul,div,mod,bit,shift)              width 8 (counts only)
//   7  Alloc(site,size)                                width 4
//   8  ProviderCall(site,provider,op,hashLen,keyLen,   width 8
//                    inputLen,outputLen)
//   9  LoopCheck(site,guard,iteration)                 width 4
//
// Ops is a source-level word-operation COUNT tuple.  It is not an ordered
// primitive-instruction trace and does not prove constant time.  Read/Write
// carry a required buffer-role identity in addition to the address.  LoopCheck
// records the Boolean guard result and iteration number; LoopBound separately
// records the public bound.  They are intentionally distinct constructors so a
// bool guard cannot be mistaken for an int bound.  ProviderCall carries only
// public HMAC/provider metadata (lengths and algorithm identifiers), never
// secret key/input/output bytes.
module {:compile false} SourceObservationVocabulary {
  datatype Event =
    | Call(site: int, target: int, arity: int)
    | Branch(site: int, taken: bool)
    | Read(site: int, role: int, address: int)
    | Write(site: int, role: int, address: int)
    | LoopCheck(site: int, guard: bool, iteration: int)
    | Ops(add: int, sub: int, mul: int, div: int, mod: int, bit: int, shift: int)
    | Alloc(site: int, size: int)
    | ProviderCall(site: int, provider: int, operation: int,
                   hashLen: int, keyLen: int, inputLen: int, outputLen: int)
    | LoopBound(site: int, bound: int)

  ghost function Tag(e: Event): int {
    match e
    case Call(_, _, _) => 1
    case Branch(_, _) => 2
    case Read(_, _, _) => 3
    case Write(_, _, _) => 4
    case LoopCheck(_, _, _) => 9
    case Ops(_, _, _, _, _, _, _) => 6
    case Alloc(_, _) => 7
    case ProviderCall(_, _, _, _, _, _, _) => 8
    case LoopBound(_, _) => 5
  }

  ghost function WidthOfTag(tag: int): int {
    if tag == 1 then 4
    else if tag == 2 then 4
    else if tag == 3 then 4
    else if tag == 4 then 4
    else if tag == 5 then 4
    else if tag == 6 then 8
    else if tag == 7 then 4
    else if tag == 8 then 8
    else if tag == 9 then 4
    else 0
  }

  ghost function Width(e: Event): int { WidthOfTag(Tag(e)) }

  ghost function Encode(e: Event): seq<int> {
    match e
    case Call(location, destination, count) => [1, location, destination, count]
    case Branch(site, taken) => [2, site, if taken then 1 else 0, 0]
    case Read(site, role, address) => [3, site, role, address]
    case Write(site, role, address) => [4, site, role, address]
    case LoopCheck(site, guard, iteration) =>
      [9, site, if guard then 1 else 0, iteration]
    case Ops(add, sub, mul, div, mod, bit, shift) =>
      [6, add, sub, mul, div, mod, bit, shift]
    case Alloc(site, size) => [7, site, size, 0]
    case ProviderCall(site, provider, operation, hashLen, keyLen, inputLen, outputLen) =>
      [8, site, provider, operation, hashLen, keyLen, inputLen, outputLen]
    case LoopBound(site, bound) => [5, site, bound, 0]
  }

  ghost function EncodeTrace(trace: seq<Event>): seq<int>
    decreases |trace|
  {
    if |trace| == 0 then []
    else Encode(trace[0]) + EncodeTrace(trace[1..])
  }

  datatype MaybeEvent = NoEvent | SomeEvent(event: Event)

  ghost function DecodeExact(s: seq<int>): MaybeEvent {
    if |s| == 0 then NoEvent
    else if s[0] == 1 then
      if |s| == 4 then SomeEvent(Call(s[1], s[2], s[3])) else NoEvent
    else if s[0] == 2 then
      if |s| == 4 then SomeEvent(Branch(s[1], s[2] != 0)) else NoEvent
    else if s[0] == 3 then
      if |s| == 4 then SomeEvent(Read(s[1], s[2], s[3])) else NoEvent
    else if s[0] == 4 then
      if |s| == 4 then SomeEvent(Write(s[1], s[2], s[3])) else NoEvent
    else if s[0] == 5 then
      if |s| == 4 then SomeEvent(LoopBound(s[1], s[2])) else NoEvent
    else if s[0] == 6 then
      if |s| == 8 then SomeEvent(Ops(s[1], s[2], s[3], s[4], s[5], s[6], s[7])) else NoEvent
    else if s[0] == 7 then
      if |s| == 4 then SomeEvent(Alloc(s[1], s[2])) else NoEvent
    else if s[0] == 8 then
      if |s| == 8 then
        SomeEvent(ProviderCall(s[1], s[2], s[3], s[4], s[5], s[6], s[7]))
      else NoEvent
    else if s[0] == 9 then
      if |s| == 4 then SomeEvent(LoopCheck(s[1], s[2] != 0, s[3])) else NoEvent
    else NoEvent
  }

  // Total decoder for a full encoded trace.  WidthOfTag makes the event
  // boundary explicit; a zero/unknown tag or a short prefix is rejected.  The
  // recursive call consumes at least one int, so termination is by |s|.
  datatype MaybeTrace = NoTrace | SomeTrace(events: seq<Event>)

  ghost function DecodeTrace(s: seq<int>): MaybeTrace
    decreases |s|
  {
    if |s| == 0 then SomeTrace([])
    else
      var tag := s[0];
      var w := WidthOfTag(tag);
      if w <= 0 || |s| < w then NoTrace
      else
        var head := s[..w];
        match DecodeExact(head) {
          case SomeEvent(e) =>
            match DecodeTrace(s[w..]) {
              case SomeTrace(rest) => SomeTrace([e] + rest)
              case NoTrace => NoTrace
            }
          case NoEvent => NoTrace
        }
  }

  // Every constructor has its declared fixed tag and width, and an encoded
  // event is nonempty with the tag in position zero.
  lemma EncodeShape(e: Event)
    ensures |Encode(e)| == Width(e)
    ensures Width(e) > 0
    ensures Encode(e)[0] == Tag(e)
  {
    match e
    case Call(_, _, _) => {}
    case Branch(_, _) => {}
    case Read(_, _, _) => {}
    case Write(_, _, _) => {}
    case LoopCheck(_, _, _) => {}
    case Ops(_, _, _, _, _, _, _) => {}
    case Alloc(_, _) => {}
    case ProviderCall(_, _, _, _, _, _, _) => {}
    case LoopBound(_, _) => {}
  }

  // DecodeExact is a left inverse of Encode on a single event.
  lemma DecodeExactEncode(e: Event)
    ensures DecodeExact(Encode(e)) == SomeEvent(e)
  {
    match e
    case Call(_, _, _) => {}
    case Branch(_, _) => {}
    case Read(_, _, _) => {}
    case Write(_, _, _) => {}
    case LoopCheck(_, _, _) => {}
    case Ops(_, _, _, _, _, _, _) => {}
    case Alloc(_, _) => {}
    case ProviderCall(_, _, _, _, _, _, _) => {}
    case LoopBound(_, _) => {}
  }

  // Distinct events have distinct exact encodings.  This is proved through the
  // checked decoder, not by assuming constructor/tag disjointness as an axiom.
  lemma EncodeInjective(e1: Event, e2: Event)
    ensures Encode(e1) == Encode(e2) ==> e1 == e2
  {
    if Encode(e1) == Encode(e2) {
      DecodeExactEncode(e1);
      DecodeExactEncode(e2);
      assert SomeEvent(e1) == SomeEvent(e2);
    }
  }

  lemma EncodingsDistinct(e1: Event, e2: Event)
    requires e1 != e2
    ensures Encode(e1) != Encode(e2)
  {
    if Encode(e1) == Encode(e2) {
      EncodeInjective(e1, e2);
    }
  }

  // A first event encoding cannot be a proper prefix of a different first event
  // encoding.  This is the event-boundary/prefix-unambiguity property used by
  // the trace decoder and concatenation proofs.
  lemma PrefixCancel(a: seq<int>, b: seq<int>, x: seq<int>, y: seq<int>)
    requires |a| == |b|
    requires a + x == b + y
    ensures a == b && x == y
  {
    assert a == (a + x)[..|a|];
    assert b == (b + y)[..|b|];
    assert x == (a + x)[|a|..];
    assert y == (b + y)[|b|..];
    assert a == b;
    assert x == y;
  }

  lemma EventPrefixCancel(e1: Event, e2: Event, r1: seq<int>, r2: seq<int>)
    requires Encode(e1) + r1 == Encode(e2) + r2
    ensures e1 == e2 && r1 == r2
  {
    EncodeShape(e1);
    EncodeShape(e2);
    assert |Encode(e1)| > 0 && |Encode(e2)| > 0;
    assert (Encode(e1) + r1)[0] == Encode(e1)[0];
    assert (Encode(e2) + r2)[0] == Encode(e2)[0];
    assert (Encode(e1) + r1)[0] == (Encode(e2) + r2)[0];
    assert Tag(e1) == Tag(e2);
    assert Width(e1) == Width(e2);
    assert |Encode(e1)| == |Encode(e2)|;
    PrefixCancel(Encode(e1), Encode(e2), r1, r2);
    EncodeInjective(e1, e2);
  }

  // Concatenated traces are injective: no content/label erasure can hide an
  // event while preserving the encoded trace.
  lemma EncodeTraceInjective(t1: seq<Event>, t2: seq<Event>)
    ensures EncodeTrace(t1) == EncodeTrace(t2) ==> t1 == t2
    decreases |t1| + |t2|
  {
    if EncodeTrace(t1) == EncodeTrace(t2) {
      if |t1| == 0 {
        if |t2| == 0 {
        } else {
          EncodeShape(t2[0]);
          assert |EncodeTrace(t2)| > 0;
          assert false;
        }
      } else if |t2| == 0 {
        EncodeShape(t1[0]);
        assert |EncodeTrace(t1)| > 0;
        assert false;
      } else {
        assert EncodeTrace(t1) == Encode(t1[0]) + EncodeTrace(t1[1..]);
        assert EncodeTrace(t2) == Encode(t2[0]) + EncodeTrace(t2[1..]);
        EventPrefixCancel(t1[0], t2[0], EncodeTrace(t1[1..]), EncodeTrace(t2[1..]));
        assert t1[0] == t2[0];
        assert EncodeTrace(t1[1..]) == EncodeTrace(t2[1..]);
        EncodeTraceInjective(t1[1..], t2[1..]);
        assert t1[1..] == t2[1..];
        assert t1 == [t1[0]] + t1[1..];
        assert t2 == [t2[0]] + t2[1..];
      }
    }
  }

  lemma EncodeTraceShape(trace: seq<Event>)
    ensures |EncodeTrace(trace)| == 0 <==> |trace| == 0
    decreases |trace|
  {
    if |trace| == 0 {
    } else {
      EncodeShape(trace[0]);
      EncodeTraceShape(trace[1..]);
    }
  }

  // DecodeTrace is the inverse of EncodeTrace for arbitrary event lists.
  lemma DecodeTraceEncode(trace: seq<Event>)
    ensures DecodeTrace(EncodeTrace(trace)) == SomeTrace(trace)
    decreases |trace|
  {
    if |trace| == 0 {
      assert EncodeTrace(trace) == [];
    } else {
      var e := trace[0];
      var rest := trace[1..];
      EncodeShape(e);
      DecodeExactEncode(e);
      assert EncodeTrace(trace) == Encode(e) + EncodeTrace(rest);
      assert |Encode(e)| == Width(e);
      assert Width(e) == WidthOfTag(Tag(e));
      assert Encode(e)[0] == Tag(e);
      assert (Encode(e) + EncodeTrace(rest))[0] == Tag(e);
      assert EncodeTrace(trace)[0] == Tag(e);
      assert WidthOfTag(EncodeTrace(trace)[0]) == Width(e);
      assert |EncodeTrace(trace)| == |Encode(e)| + |EncodeTrace(rest)|;
      assert |EncodeTrace(trace)| >= Width(e);
      assert EncodeTrace(trace)[..Width(e)] == Encode(e);
      assert EncodeTrace(trace)[Width(e)..] == EncodeTrace(rest);
      assert DecodeExact(EncodeTrace(trace)[..Width(e)]) == SomeEvent(e);
      DecodeTraceEncode(rest);
      assert DecodeTrace(EncodeTrace(rest)) == SomeTrace(rest);
      assert EncodeTrace(trace) == Encode(e) + EncodeTrace(rest);
      assert DecodeTrace(EncodeTrace(trace)) == SomeTrace([e] + rest);
      assert [e] + rest == trace;
    }
  }

  // Concrete distinguishability lemmas required by the observer contract.
  lemma BranchFalseDiffers(site: int)
    ensures Branch(site, false) != Branch(site, true)
    ensures Encode(Branch(site, false)) != Encode(Branch(site, true))
  {
    EncodingsDistinct(Branch(site, false), Branch(site, true));
  }

  lemma ReadRoleDistinct(site: int, role1: int, role2: int, address: int)
    requires role1 != role2
    ensures Read(site, role1, address) != Read(site, role2, address)
    ensures Encode(Read(site, role1, address)) != Encode(Read(site, role2, address))
  {
    EncodingsDistinct(Read(site, role1, address), Read(site, role2, address));
  }

  lemma ReadAddressDistinct(site: int, role: int, address1: int, address2: int)
    requires address1 != address2
    ensures Read(site, role, address1) != Read(site, role, address2)
    ensures Encode(Read(site, role, address1)) != Encode(Read(site, role, address2))
  {
    EncodingsDistinct(Read(site, role, address1), Read(site, role, address2));
  }

  lemma ReadSiteDistinct(site1: int, site2: int, role: int, address: int)
    requires site1 != site2
    ensures Read(site1, role, address) != Read(site2, role, address)
    ensures Encode(Read(site1, role, address)) != Encode(Read(site2, role, address))
  {
    EncodingsDistinct(Read(site1, role, address), Read(site2, role, address));
  }

  lemma WriteRoleDistinct(site: int, role1: int, role2: int, address: int)
    requires role1 != role2
    ensures Write(site, role1, address) != Write(site, role2, address)
    ensures Encode(Write(site, role1, address)) != Encode(Write(site, role2, address))
  {
    EncodingsDistinct(Write(site, role1, address), Write(site, role2, address));
  }

  lemma WriteAddressDistinct(site: int, role: int, address1: int, address2: int)
    requires address1 != address2
    ensures Write(site, role, address1) != Write(site, role, address2)
    ensures Encode(Write(site, role, address1)) != Encode(Write(site, role, address2))
  {
    EncodingsDistinct(Write(site, role, address1), Write(site, role, address2));
  }

  lemma WriteSiteDistinct(site1: int, site2: int, role: int, address: int)
    requires site1 != site2
    ensures Write(site1, role, address) != Write(site2, role, address)
    ensures Encode(Write(site1, role, address)) != Encode(Write(site2, role, address))
  {
    EncodingsDistinct(Write(site1, role, address), Write(site2, role, address));
  }

  lemma ReadWriteDistinct(site1: int, role1: int, address1: int,
                          site2: int, role2: int, address2: int)
    ensures Read(site1, role1, address1) != Write(site2, role2, address2)
    ensures Encode(Read(site1, role1, address1)) != Encode(Write(site2, role2, address2))
  {
    EncodingsDistinct(Read(site1, role1, address1), Write(site2, role2, address2));
  }

  lemma CallMetadataRetained(site: int, target: int, arity: int)
    ensures |Encode(Call(site, target, arity))| == 4
    ensures Encode(Call(site, target, arity))[1] == site
    ensures Encode(Call(site, target, arity))[2] == target
    ensures Encode(Call(site, target, arity))[3] == arity
  {
  }

  lemma AllocMetadataRetained(site: int, size: int)
    ensures |Encode(Alloc(site, size))| == 4
    ensures Encode(Alloc(site, size))[1] == site
    ensures Encode(Alloc(site, size))[2] == size
  {
  }

  lemma ProviderMetadataRetained(site: int, provider: int, operation: int,
                                 hashLen: int, keyLen: int,
                                 inputLen: int, outputLen: int)
    ensures |Encode(ProviderCall(site, provider, operation, hashLen, keyLen,
                                 inputLen, outputLen))| == 8
    ensures Encode(ProviderCall(site, provider, operation, hashLen, keyLen,
                                inputLen, outputLen))[1] == site
    ensures Encode(ProviderCall(site, provider, operation, hashLen, keyLen,
                                inputLen, outputLen))[2] == provider
    ensures Encode(ProviderCall(site, provider, operation, hashLen, keyLen,
                                inputLen, outputLen))[3] == operation
    ensures Encode(ProviderCall(site, provider, operation, hashLen, keyLen,
                                inputLen, outputLen))[4] == hashLen
    ensures Encode(ProviderCall(site, provider, operation, hashLen, keyLen,
                                inputLen, outputLen))[5] == keyLen
    ensures Encode(ProviderCall(site, provider, operation, hashLen, keyLen,
                                inputLen, outputLen))[6] == inputLen
    ensures Encode(ProviderCall(site, provider, operation, hashLen, keyLen,
                                inputLen, outputLen))[7] == outputLen
  {
  }

  lemma OpsCountsInjective(add1: int, sub1: int, mul1: int, div1: int,
                           mod1: int, bit1: int, shift1: int,
                           add2: int, sub2: int, mul2: int, div2: int,
                           mod2: int, bit2: int, shift2: int)
    ensures Encode(Ops(add1, sub1, mul1, div1, mod1, bit1, shift1)) ==
            Encode(Ops(add2, sub2, mul2, div2, mod2, bit2, shift2)) ==>
            add1 == add2 && sub1 == sub2 && mul1 == mul2 && div1 == div2 &&
            mod1 == mod2 && bit1 == bit2 && shift1 == shift2
  {
    if Encode(Ops(add1, sub1, mul1, div1, mod1, bit1, shift1)) ==
       Encode(Ops(add2, sub2, mul2, div2, mod2, bit2, shift2)) {
      EncodeInjective(Ops(add1, sub1, mul1, div1, mod1, bit1, shift1),
                      Ops(add2, sub2, mul2, div2, mod2, bit2, shift2));
    }
  }

  lemma LoopCheckVsBoundDistinct(site: int, guard: bool, iteration: int, bound: int)
    ensures LoopCheck(site, guard, iteration) != LoopBound(site, bound)
    ensures Encode(LoopCheck(site, guard, iteration)) != Encode(LoopBound(site, bound))
  {
    EncodingsDistinct(LoopCheck(site, guard, iteration), LoopBound(site, bound));
  }
}
