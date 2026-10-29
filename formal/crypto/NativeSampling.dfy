include "NativeCodec.dfy"
include "Sampling.dfy"

module NativeSampling {
  import T = NativeTypes
  import C = CodecSpec
  import N = NativeCodec
  import S = SamplingSpec
  import V = VerifiedSampling

  datatype FeedResult = InvalidPrefix | InvalidBlockLength |
    Full(coeffs: array<T.I>, consumed: T.I) | NeedMore(coeffs: array<T.I>, consumed: T.I)
  ghost function Model(r: FeedResult): S.FeedResult
    reads if r.Full? || r.NeedMore? then {r.coeffs} else {}
  {
    if r.InvalidPrefix? then S.InvalidPrefix else if r.InvalidBlockLength? then S.InvalidBlockLength
    else if r.Full? then S.Full(T.Ints(r.coeffs),r.consumed as int)
    else S.NeedMore(T.Ints(r.coeffs),r.consumed as int)
  }
  method IsPrefix(a: array<T.I>) returns(ok: bool)
    requires T.JavaLength(a.Length)
    ensures ok == S.Prefix(T.Ints(a))
  {
    var size: T.I := a.Length as T.I;
    if size > 256 { return false; }
    for i: T.I := 0 to size
      invariant forall j: int :: 0 <= j < i as int ==> 0 <= a[j] < 3329
    { if a[i] < 0 || a[i] >= 3329 { assert T.Ints(a)[i as int] == a[i] as int; return false; } }
    return true;
  }
  method Cbd2(b: array<bv8>) returns(f: array<T.I>)
    requires b.Length == 128
    ensures fresh(f) && T.Canonical(f) && T.Ints(f) == S.Cbd2(T.Bytes(b))
    ensures T.Bytes(b) == old(T.Bytes(b))
  {
    f := new T.I[256 as T.I];
    for i: T.I := 0 to 256
      modifies f
      invariant forall k: int :: 0 <= k < i as int ==> f[k] as int == S.CbdWord(T.Bytes(b),k)
    {
      var x: T.I := b[i/2] as T.I;
      var j: T.I := 4*(i%2);
      var low := (x/N.Pow2(j))%2 + (x/N.Pow2(j+1))%2;
      var high := (x/N.Pow2(j+2))%2 + (x/N.Pow2(j+3))%2;
      // This numerator is 3327..3331; the runtime remainder never sees a
      // negative secret and all coefficient arithmetic is native int.
      f[i] := (3329+low-high)%3329;
      assert (3329+low-high)%3329 == (low-high)%3329;
    }
  }
  method {:isolate_assertions} Feed(current: array<T.I>, b: array<bv8>) returns(r: FeedResult)
    requires T.JavaLength(current.Length) && T.JavaLength(b.Length)
    ensures Model(r) == S.Feed(T.Ints(current),T.Bytes(b))
    ensures r.Full? || r.NeedMore? ==> fresh(r.coeffs) && S.Prefix(T.Ints(r.coeffs))
    ensures r.Full? ==> r.coeffs.Length == 256
    ensures r.NeedMore? ==> r.coeffs.Length < 256 && r.consumed as int == b.Length
    ensures r.Full? || r.NeedMore? ==> 0 <= r.consumed as int <= b.Length && r.consumed%3 == 0
    ensures r.Full? || r.NeedMore? ==> T.Ints(r.coeffs) == S.Limit(T.Ints(current)+S.Accepted(T.Bytes(b),0))
    ensures T.Ints(current) == old(T.Ints(current)) && T.Bytes(b) == old(T.Bytes(b))
  {
    var valid := IsPrefix(current);
    if !valid { return InvalidPrefix; }
    var size: T.I := b.Length as T.I;
    if size%3 != 0 { return InvalidBlockLength; }
    ghost var initial := T.Ints(current);
    ghost var bytes := T.Bytes(b);
    V.AcceptedOrder(initial,bytes,0);
    var a := new T.I[256 as T.I];
    var used: T.I := current.Length as T.I;
    for i: T.I := 0 to used
      modifies a
      invariant forall j: int :: 0 <= j < i as int ==> a[j] == current[j]
    { a[i] := current[i]; }
    assert T.Ints(a)[..used as int] == initial;
    var off: T.I := 0;
    while used < 256 && off < size
      modifies a
      invariant 0 <= used <= 256
      invariant S.Prefix(T.Ints(a)[..used as int])
      invariant 0 <= off <= size && off%3 == 0
      invariant S.Run(T.Ints(a)[..used as int],bytes,off as int) == S.Feed(initial,bytes)
      decreases size-off
    {
      ghost var before := T.Ints(a)[..used as int];
      V.RunStep(before,bytes,off as int);
      var x: T.I := (b[off] as T.I)+256*((b[off+1] as T.I)%16);
      var y: T.I := (b[off+1] as T.I)/16+16*(b[off+2] as T.I);
      assert x as int == S.First(bytes,off as int) && y as int == S.Second(bytes,off as int);
      if x < 3329 {
        assert x < 3329;
        a[used] := x; used := used+1;
        assert T.Ints(a)[..used as int] == before+[x as int];
      }
      assert T.Ints(a)[..used as int] == S.Accept(before,x as int);
      ghost var middle := T.Ints(a)[..used as int];
      if used < 256 && y < 3329 {
        a[used] := y; used := used+1;
        assert T.Ints(a)[..used as int] == middle+[y as int];
      }
      assert used <= 256;
      assert T.Ints(a)[..used as int] == S.Pair(before,bytes,off as int);
      off := off+3;
      assert off <= size;
    }
    V.RunDone(T.Ints(a)[..used as int],bytes,off as int);
    if used == 256 { return Full(a,off); }
    var partial := new T.I[used];
    for i: T.I := 0 to used
      modifies partial
      invariant forall j: int :: 0 <= j < i as int ==> partial[j] == a[j]
    { partial[i] := a[i]; }
    assert T.Ints(partial) == T.Ints(a)[..used as int];
    N.Wipe(a);
    return NeedMore(partial,off);
  }
}
