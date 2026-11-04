include "../../SourceTrace.dfy"

// Actual wrapper-to-canonical-event equalities. No self-equality bridge and
// no additional assumptions: verify this file with all included definitions.
module NativeSourceTraceBridge {
  import ST = SourceTrace
  import O = SourceObservationVocabulary
  lemma CallBridge(site:int,target:int,arity:int)
    ensures ST.Call(site,target,arity) == O.Encode(O.Call(site,target,arity))
  { ST.CallIsEncode(site,target,arity); }
  lemma BranchBridge(site:int,taken:bool)
    ensures ST.Branch(site,taken) == O.Encode(O.Branch(site,taken))
  { ST.BranchIsEncode(site,taken); }
  lemma ReadBridge(site:int,role:int,address:int)
    ensures ST.Read(site,role,address) == O.Encode(O.Read(site,role,address))
  { ST.ReadIsEncode(site,role,address); }
  lemma WriteBridge(site:int,role:int,address:int)
    ensures ST.Write(site,role,address) == O.Encode(O.Write(site,role,address))
  { ST.WriteIsEncode(site,role,address); }
  lemma LoopBoundBridge(site:int,bound:int)
    ensures ST.LoopBound(site,bound) == O.Encode(O.LoopBound(site,bound))
  { ST.LoopBoundIsEncode(site,bound); }
  lemma LoopCheckBridge(site:int,guard:bool,iteration:int)
    ensures ST.LoopCheck(site,guard,iteration) == O.Encode(O.LoopCheck(site,guard,iteration))
  { ST.LoopCheckIsEncode(site,guard,iteration); }
  lemma OpsBridge(a:int,b:int,c:int,d:int,e:int,f:int,g:int)
    ensures ST.Ops(a,b,c,d,e,f,g) == O.Encode(O.Ops(a,b,c,d,e,f,g))
  { ST.OpsIsEncode(a,b,c,d,e,f,g); }
  lemma AllocBridge(site:int,size:int)
    ensures ST.Alloc(site,size) == O.Encode(O.Alloc(site,size))
  { ST.AllocIsEncode(site,size); }
}
