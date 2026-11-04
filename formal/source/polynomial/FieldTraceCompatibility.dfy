include "../../crypto/NativeField.dfy"

// Universal two-run trace harnesses over the actual NativeField methods.
// Inputs range over the complete accepted domains and are independently chosen
// for the two runs.  The trace must be equal even when every scalar input is
// different, and must have the exact propagated operation/call shape.
module NativeFieldTraceHarness {
  import T = NativeTypes
  import F = NativeField
  import ST = SourceTrace

  method CheckReduceOnce(a1: T.I, a2: T.I)
    requires 0 <= a1 < 6658 && 0 <= a2 < 6658
  {
    var r1: T.I;
    ghost var t1: seq<int>;
    r1, t1 := F.ReduceOnce(a1);
    var r2: T.I;
    ghost var t2: seq<int>;
    r2, t2 := F.ReduceOnce(a2);
    reveal ST.Ops(); reveal ST.Call();
    assert t1 == t2;
    assert t1 == ST.Ops(1,2,1,0,0,1,1);
  }

  method CheckReduce(a1: T.I, a2: T.I)
    requires 0 <= a1 <= F.MaxReduce && 0 <= a2 <= F.MaxReduce
  {
    var r1: T.I;
    ghost var t1: seq<int>;
    r1, t1 := F.Reduce(a1);
    var r2: T.I;
    ghost var t2: seq<int>;
    r2, t2 := F.Reduce(a2);
    reveal ST.Ops(); reveal ST.Call();
    assert t1 == t2;
    assert t1 == ST.Ops(0,1,2,0,0,0,1) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1);
  }

  method CheckAdd(a1: T.I, b1: T.I, a2: T.I, b2: T.I)
    requires 0 <= a1 < F.Q && 0 <= b1 < F.Q && 0 <= a2 < F.Q && 0 <= b2 < F.Q
  {
    var r1: T.I;
    ghost var t1: seq<int>;
    r1, t1 := F.Add(a1,b1);
    var r2: T.I;
    ghost var t2: seq<int>;
    r2, t2 := F.Add(a2,b2);
    reveal ST.Ops(); reveal ST.Call();
    assert t1 == t2;
    assert t1 == ST.Ops(1,0,0,0,0,0,0) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1);
  }

  method CheckSub(a1: T.I, b1: T.I, a2: T.I, b2: T.I)
    requires 0 <= a1 < F.Q && 0 <= b1 < F.Q && 0 <= a2 < F.Q && 0 <= b2 < F.Q
  {
    var r1: T.I;
    ghost var t1: seq<int>;
    r1, t1 := F.Sub(a1,b1);
    var r2: T.I;
    ghost var t2: seq<int>;
    r2, t2 := F.Sub(a2,b2);
    reveal ST.Ops(); reveal ST.Call();
    assert t1 == t2;
    assert t1 == ST.Ops(1,1,0,0,0,0,0) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1);
  }

  method CheckMul(a1: T.I, b1: T.I, a2: T.I, b2: T.I)
    requires 0 <= a1 < F.Q && 0 <= b1 < F.Q && 0 <= a2 < F.Q && 0 <= b2 < F.Q
  {
    var r1: T.I;
    ghost var t1: seq<int>;
    r1, t1 := F.Mul(a1,b1);
    var r2: T.I;
    ghost var t2: seq<int>;
    r2, t2 := F.Mul(a2,b2);
    reveal ST.Ops(); reveal ST.Call();
    assert t1 == t2;
    assert t1 == ST.Ops(0,0,1,0,0,0,0) + ST.Call(2,2,1)
      + ST.Ops(0,1,2,0,0,0,1) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1);
  }

  method CheckMulSub(a1: T.I, b1: T.I, c1: T.I, a2: T.I, b2: T.I, c2: T.I)
    requires 0 <= a1 < F.Q && 0 <= b1 < F.Q && 0 <= c1 < F.Q
    requires 0 <= a2 < F.Q && 0 <= b2 < F.Q && 0 <= c2 < F.Q
  {
    var r1: T.I;
    ghost var t1: seq<int>;
    r1, t1 := F.MulSub(a1,b1,c1);
    var r2: T.I;
    ghost var t2: seq<int>;
    r2, t2 := F.MulSub(a2,b2,c2);
    reveal ST.Ops(); reveal ST.Call();
    assert t1 == t2;
    assert t1 == ST.Ops(1,1,1,0,0,0,0) + ST.Call(3,2,1)
      + ST.Ops(0,1,2,0,0,0,1) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1);
  }

  method CheckAddMul(a1: T.I, b1: T.I, c1: T.I, d1: T.I,
                     a2: T.I, b2: T.I, c2: T.I, d2: T.I)
    requires 0 <= a1 < F.Q && 0 <= b1 < F.Q && 0 <= c1 < F.Q && 0 <= d1 < F.Q
    requires 0 <= a2 < F.Q && 0 <= b2 < F.Q && 0 <= c2 < F.Q && 0 <= d2 < F.Q
  {
    var r1: T.I;
    ghost var t1: seq<int>;
    r1, t1 := F.AddMul(a1,b1,c1,d1);
    var r2: T.I;
    ghost var t2: seq<int>;
    r2, t2 := F.AddMul(a2,b2,c2,d2);
    reveal ST.Ops(); reveal ST.Call();
    assert t1 == t2;
    assert t1 == ST.Ops(1,0,2,0,0,0,0) + ST.Call(4,2,1)
      + ST.Ops(0,1,2,0,0,0,1) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1);
  }
}
