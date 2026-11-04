include "../crypto/NativeKeccak.dfy"

module NativeKeccakTraceHarness {
  import T = NativeTypes
  import K = NativeKeccak
  import ST = SourceTrace

  method CheckSetLane(a1: array<bv64>, a2: array<bv64>, idx: T.I, v1: bv64, v2: bv64)
    requires a1.Length == 25 && a2.Length == 25 && 0 <= idx < 25
    modifies a1,a2
  {
    var r1: T.I; ghost var t1: seq<int>;
    t1 := K.SetLane(a1,idx,v1);
    ghost var t2: seq<int>;
    t2 := K.SetLane(a2,idx,v2);
    assert t1 == t2;
    assert t1 == ST.Write(0, 0, idx as int);
  }

  method CheckIota(a1: array<bv64>, a2: array<bv64>, rc1: bv64, rc2: bv64)
    requires a1.Length == 25 && a2.Length == 25
    modifies a1,a2
  {
    ghost var t1: seq<int>;
    t1 := K.Iota(a1,rc1);
    ghost var t2: seq<int>;
    t2 := K.Iota(a2,rc2);
    assert t1 == t2;
    assert t1 == ST.Read(0, 0, 0) + ST.Call(1,10,3) + ST.Write(0, 0, 0);
  }


  method CheckChi(a1: array<bv64>, b1: array<bv64>, a2: array<bv64>, b2: array<bv64>)
    requires a1.Length == 25 && b1.Length == 25 && a2.Length == 25 && b2.Length == 25
    requires a1 != b1 && a2 != b2
    modifies a1,a2
  {
    ghost var t1: seq<int>;
    t1 := K.Chi(a1,b1);
    ghost var t2: seq<int>;
    t2 := K.Chi(a2,b2);
    assert t1 == t2;
    assert t1 == ST.LoopBound(0, 0) + ST.LoopBound(0, 25) + K.ChiPrefix(25);
  }
  method CheckWipe(a1: array<bv64>, a2: array<bv64>)
    requires a1.Length == a2.Length && T.JavaLength(a1.Length)
    modifies a1,a2
  {
    ghost var t1: seq<int>;
    t1 := K.Wipe(a1);
    ghost var t2: seq<int>;
    t2 := K.Wipe(a2);
    assert t1 == t2;
    assert t1 == ST.LoopBound(0, 0) + ST.LoopBound(0, a1.Length) + K.WipePrefix(0,a1.Length);
  }
}
