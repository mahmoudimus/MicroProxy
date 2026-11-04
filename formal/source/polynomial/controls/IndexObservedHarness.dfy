include "PolynomialControls.dfy"
module IndexObservedHarness {
  import C = Control
  method Paired(i1: int, i2: int, a: array<int>)
    requires a.Length == 2 && i1 == 0 && i2 == 1
  {
    var r1, t1 := C.SecretIndexObserved(i1,a);
    var r2, t2 := C.SecretIndexObserved(i2,a);
    assert t1 == t2;
  }
}
