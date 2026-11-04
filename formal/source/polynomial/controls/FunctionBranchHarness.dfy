include "PolynomialControls.dfy"
module FunctionBranchHarness {
  import F = FunctionControl
  method Paired(v1: int, v2: int)
    requires v1 == 0 && v2 == 1
  {
    var r1 := F.PrivateBranchObserved(v1).0;
    ghost var t1 := F.PrivateBranchObserved(v1).1;
    var r2 := F.PrivateBranchObserved(v2).0;
    ghost var t2 := F.PrivateBranchObserved(v2).1;
    assert t1 == t2;
  }
}
