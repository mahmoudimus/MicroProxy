include "../../../crypto/NativeMlKem.dfy"
module SelectObservedHarness {
  import K = NativeMlKem
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
    assert r1[..] == (if c[..] == e1[..] then c1[..] else f1[..]);
    assert r2[..] == (if c[..] == e2[..] then c2[..] else f2[..]);
  }
}
