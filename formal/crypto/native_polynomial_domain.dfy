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
    var sum := P.Add(f,g);
    var difference := P.Sub(f,g);
    var nf := P.Ntt(f);
    var ng := P.Ntt(g);
    var product := P.NttMul(nf,ng);
    var ringProduct := P.InverseNtt(product);
    var restored := P.InverseNtt(nf);
    var inverse := P.InverseNtt(f);
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
    P.Wipe(nf); P.Wipe(ng); P.Wipe(product);
    P.Wipe(sum); P.Wipe(difference); P.Wipe(restored); P.Wipe(inverse); P.Wipe(ringProduct);
  }
}
