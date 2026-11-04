include "PolynomialControls.dfy"

// Two-run harnesses for the honest secret observations.  Functional
// postconditions hold, but the paired trace assertion must fail.
module ControlHarnesses {
  import C = Control

  method BranchPaired(x1: int, x2: int)
    requires x1 == 0 && x2 == 1
  {
    var r1, t1 := C.SecretBranchObserved(x1);
    var r2, t2 := C.SecretBranchObserved(x2);
    assert t1 == t2;
  }

  method IndexPaired(i1: int, i2: int, a: array<int>)
    requires a.Length == 2 && i1 == 0 && i2 == 1
  {
    var r1, t1 := C.SecretIndexObserved(i1,a);
    var r2, t2 := C.SecretIndexObserved(i2,a);
    assert t1 == t2;
  }
}
