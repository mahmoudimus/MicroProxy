include "NativePolynomial.dfy"
module NativePolynomialDomain {
  import T = NativeTypes
  import P = NativePolynomial
  import S = PolySpec
  import R = PolynomialRing
  // No restrictions beyond all canonical coefficient arrays. Aliased f and g
  // are permitted. Every public operation preserves both caller inputs.
  method ArbitraryCanonical(f: array<T.I>, g: array<T.I>)
    requires T.Canonical(f) && T.Canonical(g)
  {
    ghost var originalF := T.Ints(f);
    ghost var originalG := T.Ints(g);
    var sum, sumTrace := P.Add(f,g);
    var difference, differenceTrace := P.Sub(f,g);
    var nf, nfTrace := P.Ntt(f);
    var ng, ngTrace := P.Ntt(g);
    var product, productTrace := P.NttMul(nf,ng);
    var ringProduct, ringProductTrace := P.InverseNtt(product);
    var restored, restoredTrace := P.InverseNtt(nf);
    var inverse, inverseTrace := P.InverseNtt(f);
    R.NegacyclicViaNtt(originalF,originalG);
    R.NttInverseRoundTrip(originalF);
    S.NttRoundTrip(originalF);
    assert T.Ints(ringProduct) == R.NegacyclicProduct(originalF,originalG);
    assert T.Ints(restored) == originalF;
    assert S.Representation(T.Ints(inverse)) == originalF;
    assert T.Ints(nf) == S.Representation(originalF);
    assert T.Ints(sum) == S.Add(originalF,originalG);
    assert T.Ints(difference) == S.Sub(originalF,originalG);
    assert T.Ints(f) == originalF && T.Ints(g) == originalG;
    var wt0 := P.Wipe(nf); var wt1 := P.Wipe(ng); var wt2 := P.Wipe(product);
    var wt3 := P.Wipe(sum); var wt4 := P.Wipe(difference); var wt5 := P.Wipe(restored); var wt6 := P.Wipe(inverse); var wt7 := P.Wipe(ringProduct);
  }
}
