include "PolynomialControls.dfy"
module BranchObservedHarness {
  import C = Control
  method Paired(x1: int, x2: int)
    requires x1 == 0 && x2 == 1
  {
    var r1, t1 := C.SecretBranchObserved(x1);
    var r2, t2 := C.SecretBranchObserved(x2);
    assert t1 == t2;
  }
}
