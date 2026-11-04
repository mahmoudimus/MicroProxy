include "PolynomialControls.dfy"
module FunctionIndexHarness {
  import F = FunctionControl
  method Paired(i1: int, i2: int, a: array<int>)
    requires a.Length == 2 && i1 == 0 && i2 == 1
  {
    var r1 := F.PrivateIndexObserved(i1,a).0;
    ghost var t1 := F.PrivateIndexObserved(i1,a).1;
    var r2 := F.PrivateIndexObserved(i2,a).0;
    ghost var t2 := F.PrivateIndexObserved(i2,a).1;
    assert t1 == t2;
  }
}
