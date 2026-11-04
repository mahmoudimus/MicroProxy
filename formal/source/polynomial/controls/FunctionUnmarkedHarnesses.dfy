include "PolynomialControls.dfy"
module FunctionUnmarkedHarnesses {
  import F = FunctionControl
  method BranchPaired(v1: int, v2: int)
    requires v1 == 0 && v2 == 1
  {
    var r1 := F.PrivateBranchUnmarked(v1).0;
    ghost var t1 := F.PrivateBranchUnmarked(v1).1;
    var r2 := F.PrivateBranchUnmarked(v2).0;
    ghost var t2 := F.PrivateBranchUnmarked(v2).1;
    assert t1 == t2;
  }
  method IndexPaired(i1: int, i2: int, a: array<int>)
    requires a.Length == 2 && i1 == 0 && i2 == 1
  {
    var r1 := F.PrivateIndexUnmarked(i1,a).0;
    ghost var t1 := F.PrivateIndexUnmarked(i1,a).1;
    var r2 := F.PrivateIndexUnmarked(i2,a).0;
    ghost var t2 := F.PrivateIndexUnmarked(i2,a).1;
    assert t1 == t2;
  }
}
