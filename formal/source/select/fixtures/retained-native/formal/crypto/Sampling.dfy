include "Codec.dfy"

// FIPS 203 algorithms 7/8. Byte extraction follows Go-derived MlKem768.java
// (Go Authors, BSD-3-Clause); finite-input contracts and proofs are new work.
// Feed does not assume that a SHAKE stream ever produces 256 accepted values.
module SamplingSpec {
  import C = CodecSpec
  predicate Prefix(f: seq<int>) {
    |f| <= C.N && forall i | 0 <= i < |f| :: 0 <= f[i] < C.Q
  }
  function Bit(x: bv8, j: int): int
    requires 0 <= j < 8
    ensures 0 <= Bit(x,j) <= 1
  { ((x as int)/C.Pow2(j))%2 }
  function CbdWord(b: seq<bv8>, i: int): int
    requires |b| == 128 && 0 <= i < C.N
    ensures 0 <= CbdWord(b,i) < C.Q
  {
    var x := b[i/2]; var j := 4*(i%2);
    (Bit(x,j)+Bit(x,j+1)-Bit(x,j+2)-Bit(x,j+3))%C.Q
  }
  function Cbd2(b: seq<bv8>): seq<int>
    requires |b| == 128
    ensures C.Canonical(Cbd2(b))
  { seq(C.N, i requires 0 <= i < C.N => CbdWord(b,i)) }
  function First(b: seq<bv8>, off: int): int
    requires 0 <= off && off+3 <= |b|
    ensures 0 <= First(b,off) < 4096
  { (b[off] as int)+256*((b[off+1] as int)%16) }
  function Second(b: seq<bv8>, off: int): int
    requires 0 <= off && off+3 <= |b|
    ensures 0 <= Second(b,off) < 4096
  { (b[off+1] as int)/16+16*(b[off+2] as int) }
  function Accept(f: seq<int>, x: int): seq<int>
    requires Prefix(f) && 0 <= x < 4096
    ensures Prefix(Accept(f,x))
    ensures |f| <= |Accept(f,x)| <= |f|+1
    ensures Accept(f,x)[..|f|] == f
  { if |f| < C.N && x < C.Q then f+[x] else f }
  function Pair(f: seq<int>, b: seq<bv8>, off: int): seq<int>
    requires Prefix(f) && 0 <= off && off+3 <= |b|
    ensures Prefix(Pair(f,b,off))
    ensures |f| <= |Pair(f,b,off)| <= |f|+2
    ensures Pair(f,b,off)[..|f|] == f
  { Accept(Accept(f,First(b,off)),Second(b,off)) }

  // An independent uncapped accepted stream, preserving d1 before d2.
  // Feed returns the first 256 coefficients of current + this stream.
  function AcceptedPair(b: seq<bv8>, off: int): seq<int>
    requires 0 <= off && off+3 <= |b|
  {
    (if First(b,off) < C.Q then [First(b,off)] else []) +
    (if Second(b,off) < C.Q then [Second(b,off)] else [])
  }
  function Accepted(b: seq<bv8>, off: int): seq<int>
    requires |b|%3 == 0 && 0 <= off <= |b| && off%3 == 0
    decreases |b|-off
  { if off == |b| then [] else AcceptedPair(b,off)+Accepted(b,off+3) }
  function Limit(f: seq<int>): seq<int>
  { if |f| <= C.N then f else f[..C.N] }

  datatype FeedResult = InvalidPrefix | InvalidBlockLength |
    Full(coeffs: seq<int>, consumed: int) | NeedMore(coeffs: seq<int>, consumed: int)
  opaque function Run(f: seq<int>, b: seq<bv8>, off: int): FeedResult
    requires Prefix(f) && |b|%3 == 0 && 0 <= off <= |b| && off%3 == 0
    ensures Run(f,b,off).Full? || Run(f,b,off).NeedMore?
    ensures Prefix(Run(f,b,off).coeffs)
    ensures off <= Run(f,b,off).consumed <= |b| && Run(f,b,off).consumed%3 == 0
    ensures Run(f,b,off).Full? <==> |Run(f,b,off).coeffs| == C.N
    ensures Run(f,b,off).NeedMore? ==> Run(f,b,off).consumed == |b|
    ensures |f| <= |Run(f,b,off).coeffs|
    ensures Run(f,b,off).coeffs[..|f|] == f
    decreases |b|-off
  {
    if |f| == C.N then Full(f,off)
    else if off == |b| then NeedMore(f,off)
    else Run(Pair(f,b,off),b,off+3)
  }
  function Feed(f: seq<int>, b: seq<bv8>): FeedResult {
    if !Prefix(f) then InvalidPrefix
    else if |b|%3 != 0 then InvalidBlockLength
    else Run(f,b,0)
  }
}

module VerifiedSampling {
  import S = SamplingSpec
  import C = CodecSpec

  lemma RunStep(f: seq<int>, b: seq<bv8>, off: int)
    requires S.Prefix(f) && |f| < C.N && |b|%3 == 0 && 0 <= off < |b| && off%3 == 0
    ensures S.Run(f,b,off) == S.Run(S.Pair(f,b,off),b,off+3)
  { reveal S.Run; }
  lemma RunDone(f: seq<int>, b: seq<bv8>, off: int)
    requires S.Prefix(f) && |b|%3 == 0 && 0 <= off <= |b| && off%3 == 0
    requires |f| == C.N || off == |b|
    ensures S.Run(f,b,off) == (if |f| == C.N then S.Full(f,off) else S.NeedMore(f,off))
  { reveal S.Run; }

  lemma LimitAppend(a: seq<int>, b: seq<int>)
    ensures S.Limit(S.Limit(a)+b) == S.Limit(a+b)
  {
    if |a| >= C.N {
      assert (a+b)[..C.N] == a[..C.N];
      assert (S.Limit(a)+b)[..C.N] == a[..C.N];
    }
  }
  lemma PairOrder(f: seq<int>, b: seq<bv8>, off: int)
    requires S.Prefix(f) && 0 <= off && off+3 <= |b|
    ensures S.Pair(f,b,off) == S.Limit(f+S.AcceptedPair(b,off))
  {
    if |f| == C.N {
      assert (f+S.AcceptedPair(b,off))[..C.N] == f;
    } else if |f| == C.N-1 {
      if S.First(b,off) < C.Q && S.Second(b,off) < C.Q {
        assert (f+[S.First(b,off), S.Second(b,off)])[..C.N] == f+[S.First(b,off)];
      }
    }
  }
  lemma {:induction false} AcceptedOrder(f: seq<int>, b: seq<bv8>, off: int)
    requires S.Prefix(f) && |b|%3 == 0 && 0 <= off <= |b| && off%3 == 0
    ensures S.Run(f,b,off).coeffs == S.Limit(f+S.Accepted(b,off))
    decreases |b|-off
  {
    if |f| == C.N {
      RunDone(f,b,off);
      assert (f+S.Accepted(b,off))[..C.N] == f;
    } else if off < |b| {
      RunStep(f,b,off);
      PairOrder(f,b,off);
      AcceptedOrder(S.Pair(f,b,off),b,off+3);
      LimitAppend(f+S.AcceptedPair(b,off),S.Accepted(b,off+3));
    } else {
      RunDone(f,b,off);
    }
  }

  method Cbd2(b: seq<bv8>) returns (f: seq<int>)
    requires |b| == 128
    ensures C.Canonical(f) && f == S.Cbd2(b)
  {
    var a := new int[C.N];
    for i := 0 to C.N
      invariant forall j | 0 <= j < i :: a[j] == S.CbdWord(b,j)
    {
      var x := b[i/2] as int;
      var j := 4*(i%2);
      var low := (x/C.Pow2(j))%2 + (x/C.Pow2(j+1))%2;
      var high := (x/C.Pow2(j+2))%2 + (x/C.Pow2(j+3))%2;
      a[i] := (low-high)%3329;
    }
    f := a[..];
  }

  method Feed(current: seq<int>, b: seq<bv8>) returns (r: S.FeedResult)
    ensures r == S.Feed(current,b)
    ensures r.Full? || r.NeedMore? ==> S.Prefix(r.coeffs)
    ensures r.Full? ==> |r.coeffs| == C.N
    ensures r.NeedMore? ==> |r.coeffs| < C.N && r.consumed == |b|
    ensures r.Full? || r.NeedMore? ==> 0 <= r.consumed <= |b| && r.consumed%3 == 0
    ensures r.Full? || r.NeedMore? ==> r.coeffs == S.Limit(current+S.Accepted(b,0))
  {
    if !S.Prefix(current) { return S.InvalidPrefix; }
    if |b|%3 != 0 { return S.InvalidBlockLength; }
    AcceptedOrder(current,b,0);
    var f := current;
    var off := 0;
    while |f| < C.N && off < |b|
      invariant S.Prefix(f)
      invariant 0 <= off <= |b| && off%3 == 0
      invariant S.Run(f,b,off) == S.Feed(current,b)
      decreases |b|-off
    {
      RunStep(f,b,off);
      var before := f;
      var x := (b[off] as int)+256*((b[off+1] as int)%16);
      var y := (b[off+1] as int)/16+16*(b[off+2] as int);
      if x < C.Q {
        assert x < C.Q;
        f := f+[x];
      }
      assert S.Prefix(f);
      if |f| < C.N && y < C.Q { f := f+[y]; }
      assert |f| <= C.N;
      assert f == S.Pair(before,b,off);
      off := off+3;
      assert off <= |b|;
    }
    RunDone(f,b,off);
    if |f| == C.N { return S.Full(f,off); }
    return S.NeedMore(f,off);
  }
}
