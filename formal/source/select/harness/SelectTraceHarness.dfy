include "../../../crypto/NativeMlKem.dfy"
module SelectTraceHarness {
  import T = NativeTypes
  import K = NativeMlKem
  import ST = SourceTrace
  method Check(c: array<bv8>, e1: array<bv8>, e2: array<bv8>,
               c1: array<bv8>, c2: array<bv8>, f1: array<bv8>, f2: array<bv8>)
    requires c.Length == 1088 && e1.Length == 1088 && e2.Length == 1088
    requires c1.Length == 32 && c2.Length == 32 && f1.Length == 32 && f2.Length == 32
  {
    var r1: array<bv8>; ghost var t1: seq<int>;
    r1, t1 := K.Select(c,e1,c1,f1);
    var r2: array<bv8>; ghost var t2: seq<int>;
    r2, t2 := K.Select(c,e2,c2,f2);
    assert t1 == t2;
    assert t1 == ST.LoopBound(0,0) + ST.LoopBound(0,1088) + K.SelectDiffPrefix(1088)
      + ST.Alloc(0,32) + ST.LoopBound(2,0) + ST.LoopBound(2,32) + K.SelectOutPrefix(32);
    assert r1[..] == (if c[..] == e1[..] then c1[..] else f1[..]);
    assert r2[..] == (if c[..] == e2[..] then c2[..] else f2[..]);
  }


  method CheckAllLegalAliases(c: array<bv8>, cand: array<bv8>)
    requires c.Length == 1088 && cand.Length == 32
  {
    ghost var cBefore := c[..];
    ghost var candBefore := cand[..];
    var r1: array<bv8>; ghost var t1: seq<int>;
    r1, t1 := K.Select(c,c,cand,cand);
    var r2: array<bv8>; ghost var t2: seq<int>;
    r2, t2 := K.Select(c,c,cand,cand);
    assert c[..] == cBefore && cand[..] == candBefore;
    assert t1 == t2;
    assert fresh(r1) && fresh(r2) && r1 != r2;
    assert r1 != c && r1 != cand && r2 != c && r2 != cand;
    assert r1[..] == cand[..] && r2[..] == cand[..];
  }
  method CheckAlias(c: array<bv8>, e1: array<bv8>, e2: array<bv8>, cand: array<bv8>, fb: array<bv8>)
    requires c.Length == 1088 && e1.Length == 1088 && e2.Length == 1088
    requires cand.Length == 32 && fb.Length == 32
  {
    // candidate and fallback aliases are permitted by the actual method domain.
    var r1: array<bv8>; ghost var t1: seq<int>;
    r1, t1 := K.Select(c,e1,cand,cand);
    var r2: array<bv8>; ghost var t2: seq<int>;
    r2, t2 := K.Select(c,e2,fb,fb);
    assert t1 == t2;
  }
}
