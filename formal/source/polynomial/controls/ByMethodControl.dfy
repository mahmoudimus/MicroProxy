include "../../../crypto/NativePolynomial.dfy"
module ByMethodProbe {
  function Identity(v: bv64): (bv64, ghost seq<int>) {
    (v, ghost [])
  } by method {
    if v == 0 {
      return (v | v, ghost []);
    } else {
      return (v, ghost []);
    }
  }
}
