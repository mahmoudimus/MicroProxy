include "../../dafny/hkdf/Hkdf.dfy"

module HkdfArrayInputTrace {
  import opened VerifiedHkdf

  method CopyPair(a: array<bv8>, b: array<bv8>)
    requires a.Length == b.Length
  {
    var x, {:ghost} tx := CopyInput(a);
    var y, {:ghost} ty := CopyInput(b);
    assert tx == ty;
    assert x == a[..] && y == b[..];
  }

  method ExtractPair(hashLen: int, salt1: array<bv8>, ikm1: array<bv8>,
                     salt2: array<bv8>, ikm2: array<bv8>)
    requires salt1.Length == salt2.Length && ikm1.Length == ikm2.Length
  {
    var r1, {:ghost} t1 := ExtractArrays(hashLen, salt1, ikm1);
    var r2, {:ghost} t2 := ExtractArrays(hashLen, salt2, ikm2);
    assert t1 == t2;
    assert r1.Success? == r2.Success?;
    assert r1.Success? ==> |r1.bytes| == |r2.bytes|;
    assert r1.Failure? ==> r1.reason == r2.reason;
  }

  method ExpandPair(hashLen: int, prk1: array<bv8>, info1: array<bv8>,
                    prk2: array<bv8>, info2: array<bv8>, length: int)
    requires prk1.Length == prk2.Length && info1.Length == info2.Length
  {
    var r1, {:ghost} t1 := ExpandArrays(hashLen, prk1, info1, length);
    var r2, {:ghost} t2 := ExpandArrays(hashLen, prk2, info2, length);
    assert t1 == t2;
    assert r1.Success? == r2.Success?;
    assert r1.Success? ==> |r1.bytes| == |r2.bytes|;
    assert r1.Failure? ==> r1.reason == r2.reason;
  }

  method LabelPair(labelUnits: seq<bv16>, context1: array<bv8>, context2: array<bv8>, length: int)
    requires context1.Length == context2.Length
  {
    var r1, {:ghost} t1 := LabelInfoArray(labelUnits, context1, length);
    var r2, {:ghost} t2 := LabelInfoArray(labelUnits, context2, length);
    assert t1 == t2;
    assert r1.Success? == r2.Success?;
    assert r1.Success? ==> |r1.bytes| == |r2.bytes|;
    assert r1.Failure? ==> r1.reason == r2.reason;
  }

  method SnapshotAfterMutation(a: array<bv8>, i: int, value: bv8)
      returns(snapshot: seq<bv8>)
    requires 0 <= i < a.Length
    modifies a
    ensures snapshot == old(a[..])
  {
    var copy, {:ghost} trace := CopyInput(a);
    snapshot := copy;
    a[i] := value;
    assert snapshot == old(a[..]);
  }

  method AliasedSnapshots(a: array<bv8>, b: array<bv8>, i: int, value: bv8)
      returns(left: seq<bv8>, right: seq<bv8>)
    requires 0 <= i < a.Length
    modifies a
    ensures left == old(a[..]) && right == old(b[..])
  {
    var x, {:ghost} tx := CopyInput(a);
    var y, {:ghost} ty := CopyInput(b);
    left := x; right := y;
    a[i] := value;
    assert left == old(a[..]) && right == old(b[..]);
  }

  method UnrestrictedDomain(hashLen: int, a: array<bv8>, b: array<bv8>,
                            labelUnits: seq<bv16>, length: int)
  {
    var e, {:ghost} te := ExtractArrays(hashLen, a, b);
    assert e == ExtractSpec(hashLen, a[..], b[..]);
    var x, {:ghost} tx := ExpandArrays(hashLen, a, b, length);
    assert x == ExpandSpec(hashLen, a[..], b[..], length);
    var l, {:ghost} tl := LabelInfoArray(labelUnits, a, length);
    assert l == LabelInfoSpec(labelUnits, a[..], length);
  }
}
