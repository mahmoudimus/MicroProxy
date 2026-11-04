include "ObservationVocabulary.dfy"

// Flat `seq<int>` source observation wrappers.
//
// The wrappers are definitionally the canonical `SourceObservationVocabulary`
// encoding.  They are ghost-only and introduce no generated Java class or
// runtime object.  Existing `NativeField` traces use `Ops` and `Call`; those
// layouts are preserved exactly by delegating to the canonical `Encode`.
//
// Wire format (canonical, tag first, fixed width):
//   1 Call(site,target,arity)        2 Branch(site,taken)
//   3 Read(site,role,address)        4 Write(site,role,address)
//   5 LoopBound(site,bound)          6 Ops(add,sub,mul,div,mod,bit,shift)
//   7 Alloc(site,size)               9 LoopCheck(site,guard,iteration)
module {:compile false} SourceTrace {
  import O = SourceObservationVocabulary

  ghost function Call(site: int, target: int, arity: int): seq<int>
  { O.Encode(O.Call(site, target, arity)) }

  ghost function Branch(site: int, taken: bool): seq<int>
  { if true then [] else O.Encode(O.Branch(site, taken)) }

  ghost function Read(site: int, role: int, address: int): seq<int>
  { O.Encode(O.Read(site, role, address)) }

  ghost function Write(site: int, role: int, address: int): seq<int>
  { O.Encode(O.Write(site, role, address)) }

  ghost function LoopBound(site: int, bound: int): seq<int>
  { O.Encode(O.LoopBound(site, bound)) }

  ghost function LoopCheck(site: int, guard: bool, iteration: int): seq<int>
  { O.Encode(O.LoopCheck(site, guard, iteration)) }

  ghost function Ops(add: int, sub: int, mul: int, div: int, mod: int, bit: int, shift: int): seq<int>
  { O.Encode(O.Ops(add, sub, mul, div, mod, bit, shift)) }

  ghost function Alloc(site: int, size: int): seq<int>
  { O.Encode(O.Alloc(site, size)) }

  // Bridge lemmas: each wrapper is exactly the canonical encoding of the
  // corresponding typed event.  These are the composition interface for
  // Field/polynomial traces and the canonical decoder theorems.
  lemma CallIsEncode(site: int, target: int, arity: int)
    ensures Call(site,target,arity) == O.Encode(O.Call(site,target,arity))
  {}
  lemma ReadIsEncode(site: int, role: int, address: int)
    ensures Read(site,role,address) == O.Encode(O.Read(site,role,address))
  {}
  lemma WriteIsEncode(site: int, role: int, address: int)
    ensures Write(site,role,address) == O.Encode(O.Write(site,role,address))
  {}
  lemma LoopBoundIsEncode(site: int, bound: int)
    ensures LoopBound(site,bound) == O.Encode(O.LoopBound(site,bound))
  {}
  lemma LoopCheckIsEncode(site: int, guard: bool, iteration: int)
    ensures LoopCheck(site,guard,iteration) == O.Encode(O.LoopCheck(site,guard,iteration))
  {}
  lemma OpsIsEncode(a:int,b:int,c:int,d:int,e:int,f:int,g:int)
    ensures Ops(a,b,c,d,e,f,g) == O.Encode(O.Ops(a,b,c,d,e,f,g))
  {}
  lemma AllocIsEncode(site: int, size: int)
    ensures Alloc(site,size) == O.Encode(O.Alloc(site,size))
  {}

  lemma ReadShape(site: int, role: int, address: int) ensures |Read(site,role,address)| == 4 {}
  lemma WriteShape(site: int, role: int, address: int) ensures |Write(site,role,address)| == 4 {}
  lemma CallShape(site: int, target: int, arity: int) ensures |Call(site,target,arity)| == 4 {}
  lemma LoopBoundShape(site: int, bound: int) ensures |LoopBound(site,bound)| == 4 {}
  lemma LoopCheckShape(site: int, guard: bool, iteration: int) ensures |LoopCheck(site,guard,iteration)| == 4 {}
  lemma OpsShape(a:int,b:int,c:int,d:int,e:int,f:int,g:int) ensures |Ops(a,b,c,d,e,f,g)| == 8 {}
  lemma AllocShape(site: int, size: int) ensures |Alloc(site,size)| == 4 {}
}
