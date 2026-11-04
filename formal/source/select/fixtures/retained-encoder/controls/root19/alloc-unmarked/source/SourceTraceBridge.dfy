include "SourceTrace.dfy"
include "vocabulary/ObservationVocabulary.dfy"
// Verified bridge for the common local markers to the canonical vocabulary.
// For/ Loop are local extensions and are not claimed as canonical events.
module SourceTraceBridge {
  import ST = SourceTrace
  import V = SourceObservationVocabulary
  lemma CallBridge(id:int,target:int,arity:int)
    ensures ST.Call(id,target,arity) == V.Encode(V.Call(id,target,arity))
  { reveal ST.Call(); }
  lemma BranchBridge(id:int,taken:bool)
    ensures ST.Branch(id,taken) == V.Encode(V.Branch(id,taken))
  { reveal ST.Branch(); }
  lemma ReadBridge(role:int,addr:int)
    ensures ST.Read(role,addr) == V.Encode(V.Read(0,role,addr))
  { reveal ST.Read(); }
  lemma WriteBridge(role:int,addr:int)
    ensures ST.Write(role,addr) == V.Encode(V.Write(0,role,addr))
  { reveal ST.Write(); }
  lemma OpsBridge(a:int,b:int,c:int,d:int,e:int,f:int,g:int)
    ensures ST.Ops(a,b,c,d,e,f,g) == V.Encode(V.Ops(a,b,c,d,e,f,g))
  { reveal ST.Ops(); }
  lemma AllocBridge(id:int,size:int)
    ensures ST.Alloc(id,size) == V.Encode(V.Alloc(id,size))
  { reveal ST.Alloc(); }
}
