include "PolynomialControls.dfy"
module UnmarkedHarnesses {
  import C = Control
  method BranchPaired(x1: int, x2: int)
    requires x1 == 0 && x2 == 1
  {
    var r1, t1 := C.SecretBranchUnmarked(x1);
    var r2, t2 := C.SecretBranchUnmarked(x2);
    assert t1 == t2;
  }
  method IndexPaired(i1: int, i2: int, a: array<int>)
    requires a.Length == 2 && i1 == 0 && i2 == 1
  {
    var r1, t1 := C.SecretIndexUnmarked(i1,a);
    var r2, t2 := C.SecretIndexUnmarked(i2,a);
    assert t1 == t2;
  }
}
