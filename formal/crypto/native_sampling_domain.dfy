include "NativeSampling.dfy"

module NativeSamplingPublicDomain {
  import S = SamplingSpec
  import V = NativeSampling
  import T = NativeTypes
  method CbdAllBytes(b: array<bv8>)
    requires b.Length == 128
  {
    ghost var before := T.Bytes(b);
    var f := V.Cbd2(b);
    assert T.Canonical(f) && T.Ints(f) == S.Cbd2(before);
    assert fresh(f) && T.Bytes(b) == before;
  }
  method FeedAllInputs(current: array<T.I>, b: array<bv8>)
    requires T.JavaLength(current.Length) && T.JavaLength(b.Length)
  {
    ghost var initial := T.Ints(current);
    ghost var bytes := T.Bytes(b);
    var r := V.Feed(current,b);
    assert V.Model(r) == S.Feed(initial,bytes);
    if S.Prefix(initial) && b.Length%3 == 0 {
      assert r.Full? || r.NeedMore?;
      assert T.Ints(r.coeffs) == S.Limit(initial+S.Accepted(bytes,0));
      assert r.NeedMore? ==> r.consumed as int == b.Length;
      assert fresh(r.coeffs);
    } else if !S.Prefix(initial) { assert r.InvalidPrefix?; }
    else { assert r.InvalidBlockLength?; }
    assert T.Ints(current) == initial && T.Bytes(b) == bytes;
  }
}
