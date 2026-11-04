include "../crypto/NativeKeccak.dfy"
module RotateThetaTraceHarness {
  import T = NativeTypes
  import K = NativeKeccak
  import S = KeccakSpec
  import ST = SourceTrace

  method CheckRotate(v1: bv64, v2: bv64, n: T.I)
    requires 0 <= n < 64
  {
    var r1 := K.Rotate(v1,n);
    var r2 := K.Rotate(v2,n);
    assert r1.1 == r2.1;
    assert r1.0 == S.Rotate(v1,n as int);
    assert r2.0 == S.Rotate(v2,n as int);
    assert r1.1 == K.RotateTrace(n);
  }


  method CheckRhoPi(a1: array<bv64>, b1: array<bv64>, a2: array<bv64>, b2: array<bv64>)
    requires a1.Length == 25 && b1.Length == 25 && a1 != b1
    requires a2.Length == 25 && b2.Length == 25 && a2 != b2
    modifies a1,b1,a2,b2
  {
    var o1 := new T.I[25]; var s1 := new T.I[25];
    var o2 := new T.I[25]; var s2 := new T.I[25];
    var k: T.I := 0;
    while k < 25
      modifies o1,s1,o2,s2
      invariant 0 <= k <= 25
      invariant forall i: int :: 0 <= i < k as int ==> o1[i] == K.Offset(i as T.I) && s1[i] == K.Source(i as T.I)
      invariant forall i: int :: 0 <= i < k as int ==> o2[i] == K.Offset(i as T.I) && s2[i] == K.Source(i as T.I)
    {
      o1[k] := K.Offset(k); s1[k] := K.Source(k);
      o2[k] := K.Offset(k); s2[k] := K.Source(k);
      k := k+1;
    }
    assert o1[..] == o2[..] && s1[..] == s2[..];
    ghost var t1: seq<int>;
    t1 := K.RhoPi(a1,b1,o1,s1);
    ghost var t2: seq<int>;
    t2 := K.RhoPi(a2,b2,o2,s2);
    assert t1 == t2;
    assert t1 == ST.LoopBound(0, 0) + ST.LoopBound(0, 25) + K.RhoPiPrefix(s1[..],o1[..],25);
  }
  method CheckTheta(a1: array<bv64>, c1: array<bv64>, a2: array<bv64>, c2: array<bv64>)
    requires a1.Length == 25 && c1.Length == 5 && a1 != c1
    requires a2.Length == 25 && c2.Length == 5 && a2 != c2
    modifies a1,c1,a2,c2
  {
    ghost var t1: seq<int>;
    t1 := K.Theta(a1,c1);
    ghost var t2: seq<int>;
    t2 := K.Theta(a2,c2);
    assert t1 == t2;
    assert t1 == ST.LoopBound(0, 0) + ST.LoopBound(0, 5) + K.ThetaColPrefix(5) + ST.LoopBound(2, 0) + ST.LoopBound(2, 5) + K.ThetaOuterPrefix(5);
  }
}
