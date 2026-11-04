include "Sampling.dfy"

module SamplingPublicDomain {
  import S = SamplingSpec
  import V = VerifiedSampling
  import C = CodecSpec
  method CbdAllBytes(b: seq<bv8>)
    requires |b| == 128
  {
    var f := V.Cbd2(b);
    assert C.Canonical(f) && f == S.Cbd2(b);
  }
  method FeedAllInputs(current: seq<int>, b: seq<bv8>)
  {
    var r := V.Feed(current,b);
    assert r == S.Feed(current,b);
    if S.Prefix(current) && |b|%3 == 0 {
      assert r.Full? || r.NeedMore?;
      assert r.coeffs == S.Limit(current+S.Accepted(b,0));
      assert r.NeedMore? ==> r.consumed == |b|;
    } else if !S.Prefix(current) { assert r.InvalidPrefix?; }
    else { assert r.InvalidBlockLength?; }
  }
}
