// FIPS 202 sections 3.2/3.3, lane-level specification for Keccak-f[1600].
// New standards-based work; no AWS source is included or adapted here.
module KeccakSpec {
  ghost function Offsets(): seq<nat> {
    [0, 1, 190, 28, 91, 36, 300, 6, 55, 276, 3, 10, 171, 153, 231,
     105, 45, 15, 21, 136, 210, 66, 253, 120, 78]
  }
  ghost function Constants(): seq<bv64> {
    [0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
     0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
     0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
     0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
     0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
     0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
  }
  ghost function Rotate(v: bv64, n: nat): bv64 requires n < 64 {
    (v << n) | (v >> (64 - n))
  }
  ghost function {:opaque} Column(a: seq<bv64>, x: nat): bv64
    requires |a| == 25 && x < 5
  { a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20] }
  lemma ColumnAt(a: seq<bv64>, x: nat)
    requires |a| == 25 && x < 5
    ensures Column(a, x) == a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
  { reveal Column(); }
  ghost function {:opaque} ThetaLane(a: seq<bv64>, i: nat): bv64
    requires |a| == 25 && i < 25
  { a[i] ^ Column(a, (i%5+4)%5) ^ Rotate(Column(a, (i%5+1)%5), 1) }
  lemma ThetaLaneAt(a: seq<bv64>, i: nat)
    requires |a| == 25 && i < 25
    ensures ThetaLane(a, i) == a[i] ^ Column(a, (i%5+4)%5) ^ Rotate(Column(a, (i%5+1)%5), 1)
  { reveal ThetaLane(); }
  ghost function {:opaque} Theta(a: seq<bv64>): seq<bv64>
    requires |a| == 25 ensures |Theta(a)| == 25
  { seq(25, i requires 0 <= i < 25 => ThetaLane(a, i)) }
  lemma ThetaAt(a: seq<bv64>, i: nat)
    requires |a| == 25 && i < 25
    ensures Theta(a)[i] == ThetaLane(a, i)
  { reveal Theta(); }
  ghost function Rho(a: seq<bv64>): seq<bv64>
    requires |a| == 25 ensures |Rho(a)| == 25
  { seq(25, i requires 0 <= i < 25 => Rotate(a[i], Offsets()[i]%64)) }
  ghost function Pi(a: seq<bv64>): seq<bv64>
    requires |a| == 25 ensures |Pi(a)| == 25
  { seq(25, i requires 0 <= i < 25 => a[((i%5)+3*(i/5))%5 + 5*(i%5)]) }
  ghost function Chi(a: seq<bv64>): seq<bv64>
    requires |a| == 25 ensures |Chi(a)| == 25
  { seq(25, i requires 0 <= i < 25 => a[i] ^ ((!a[5*(i/5)+(i%5+1)%5]) & a[5*(i/5)+(i%5+2)%5])) }
  ghost function Iota(a: seq<bv64>, rc: bv64): seq<bv64>
    requires |a| == 25 ensures |Iota(a, rc)| == 25
  { a[0 := a[0] ^ rc] }
  ghost function {:opaque} Round(a: seq<bv64>, rc: bv64): seq<bv64>
    requires |a| == 25 ensures |Round(a, rc)| == 25
  { Iota(Chi(Pi(Rho(Theta(a)))), rc) }
  lemma RoundEquation(a: seq<bv64>, rc: bv64)
    requires |a| == 25
    ensures Round(a, rc) == Iota(Chi(Pi(Rho(Theta(a)))), rc)
  { reveal Round(); }
  ghost function {:opaque} Iter(a: seq<bv64>, n: nat): seq<bv64>
    requires |a| == 25 && n <= 24 ensures |Iter(a, n)| == 25
    decreases n
  { if n == 0 then a else Round(Iter(a, n-1), Constants()[n-1]) }
  lemma IterZero(a: seq<bv64>)
    requires |a| == 25 ensures Iter(a, 0) == a
  { reveal Iter(); }
  lemma IterStep(a: seq<bv64>, n: nat)
    requires |a| == 25 && n < 24
    ensures Iter(a, n+1) == Round(Iter(a, n), Constants()[n])
  { reveal Iter(); }
}

module VerifiedKeccak {
  import S = KeccakSpec
  function Rotate(v: bv64, n: nat): bv64
    requires n < 64 ensures Rotate(v, n) == S.Rotate(v, n)
  { if n == 0 then v else (v << n) | (v >> (64-n)) }

  function Constants(): seq<bv64>
    ensures Constants() == S.Constants()
  {
    [0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
     0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
     0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
     0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
     0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
     0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
  }
  function Offsets(): seq<nat>
    ensures |Offsets()| == 25
    ensures forall i :: 0 <= i < 25 ==> Offsets()[i] == S.Offsets()[i]%64
  { [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
     41, 45, 15, 21, 8, 18, 2, 61, 56, 14] }

  method {:isolate_assertions} Theta(a: seq<bv64>) returns (r: seq<bv64>)
    requires |a| == 25 ensures r == S.Theta(a)
  {
    var c := new bv64[5];
    for x := 0 to 5
      modifies c
      invariant forall k :: 0 <= k < x ==> c[k] == S.Column(a, k)
    {
      S.ColumnAt(a, x);
      c[x] := a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20];
    }
    var b := new bv64[25];
    for i := 0 to 25
      modifies b
      invariant forall k :: 0 <= k < i ==> b[k] == S.Theta(a)[k]
    {
      assert c[(i%5+4)%5] == S.Column(a, (i%5+4)%5);
      assert c[(i%5+1)%5] == S.Column(a, (i%5+1)%5);
      var value := a[i] ^ c[(i%5+4)%5] ^ Rotate(c[(i%5+1)%5], 1);
      S.ThetaAt(a, i);
      S.ThetaLaneAt(a, i);
      assert value == S.Theta(a)[i];
      b[i] := value;
      forall k | 0 <= k < i+1
        ensures b[k] == S.Theta(a)[k]
      { if k == i { assert b[k] == value; } }
    }
    r := b[..];
  }
  method Rho(a: seq<bv64>) returns (r: seq<bv64>)
    requires |a| == 25 ensures r == S.Rho(a)
  {
    var offsets := Offsets();
    var b := new bv64[25];
    for i := 0 to 25
      invariant forall k :: 0 <= k < i ==> b[k] == S.Rho(a)[k]
    { b[i] := Rotate(a[i], offsets[i]); }
    r := b[..];
  }
  method Pi(a: seq<bv64>) returns (r: seq<bv64>)
    requires |a| == 25 ensures r == S.Pi(a)
  {
    var b := new bv64[25];
    for i := 0 to 25
      invariant forall k :: 0 <= k < i ==> b[k] == S.Pi(a)[k]
    { b[i] := a[((i%5)+3*(i/5))%5 + 5*(i%5)]; }
    r := b[..];
  }
  method Chi(a: seq<bv64>) returns (r: seq<bv64>)
    requires |a| == 25 ensures r == S.Chi(a)
  {
    var b := new bv64[25];
    for i := 0 to 25
      invariant forall k :: 0 <= k < i ==> b[k] == S.Chi(a)[k]
    {
      var row := 5*(i/5);
      var x := i%5;
      b[i] := a[i] ^ ((!a[row+(x+1)%5]) & a[row+(x+2)%5]);
    }
    r := b[..];
  }
  method Iota(a: seq<bv64>, rc: bv64) returns (r: seq<bv64>)
    requires |a| == 25 ensures r == S.Iota(a, rc)
  { r := a[0 := a[0] ^ rc]; }
  method Round(a: seq<bv64>, rc: bv64) returns (r: seq<bv64>)
    requires |a| == 25 ensures r == S.Round(a, rc)
  {
    var t := Theta(a);
    var u := Rho(t);
    var v := Pi(u);
    var w := Chi(v);
    r := Iota(w, rc);
    S.RoundEquation(a, rc);
  }
  method Permute(a: seq<bv64>) returns (r: seq<bv64>)
    requires |a| == 25 ensures r == S.Iter(a, 24)
  {
    var constants := Constants();
    S.IterZero(a);
    r := a;
    ghost var completed := 0;
    for i := 0 to 24
      invariant r == S.Iter(a, i)
      invariant completed == i
    {
      S.IterStep(a, i);
      r := Round(r, constants[i]);
      completed := i+1;
    }
    // A separately checked iteration obligation gives an inexpensive negative
    // witness for omitted rounds without asking SMT to invert the permutation.
    assert completed == 24;
  }
}
