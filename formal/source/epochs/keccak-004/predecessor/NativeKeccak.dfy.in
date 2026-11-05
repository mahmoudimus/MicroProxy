include "NativeTypes.dfy"
include "../primitives/Keccak.dfy"

// Array refinement of the FIPS202 permutation. All runtime indices are native
// signed Java ints with their bounds verified; values are native bv64 longs.
module NativeKeccak {
  import T = NativeTypes
  import S = KeccakSpec
  function Rotate(v: bv64, n: T.I): bv64
    requires 0 <= n < 64
    ensures Rotate(v,n) == S.Rotate(v,n as int)
  { if n == 0 then v else (v << n) | (v >> (64-n)) }
  function Constant(i: T.I): bv64
    requires 0 <= i < 24
    ensures Constant(i) == S.Constants()[i]
  { if i == 0 then 0x0000000000000001
    else if i == 1 then 0x0000000000008082
    else if i == 2 then 0x800000000000808a
    else if i == 3 then 0x8000000080008000
    else if i == 4 then 0x000000000000808b
    else if i == 5 then 0x0000000080000001
    else if i == 6 then 0x8000000080008081
    else if i == 7 then 0x8000000000008009
    else if i == 8 then 0x000000000000008a
    else if i == 9 then 0x0000000000000088
    else if i == 10 then 0x0000000080008009
    else if i == 11 then 0x000000008000000a
    else if i == 12 then 0x000000008000808b
    else if i == 13 then 0x800000000000008b
    else if i == 14 then 0x8000000000008089
    else if i == 15 then 0x8000000000008003
    else if i == 16 then 0x8000000000008002
    else if i == 17 then 0x8000000000000080
    else if i == 18 then 0x000000000000800a
    else if i == 19 then 0x800000008000000a
    else if i == 20 then 0x8000000080008081
    else if i == 21 then 0x8000000000008080
    else if i == 22 then 0x0000000080000001
    else 0x8000000080008008 }
  function Offset(i: T.I): T.I
    requires 0 <= i < 25
    ensures 0 <= Offset(i) < 64 && Offset(i) as int == S.Offsets()[i]%64
  { if i == 0 then 0
    else if i == 1 then 1
    else if i == 2 then 62
    else if i == 3 then 28
    else if i == 4 then 27
    else if i == 5 then 36
    else if i == 6 then 44
    else if i == 7 then 6
    else if i == 8 then 55
    else if i == 9 then 20
    else if i == 10 then 3
    else if i == 11 then 10
    else if i == 12 then 43
    else if i == 13 then 25
    else if i == 14 then 39
    else if i == 15 then 41
    else if i == 16 then 45
    else if i == 17 then 15
    else if i == 18 then 21
    else if i == 19 then 8
    else if i == 20 then 18
    else if i == 21 then 2
    else if i == 22 then 61
    else if i == 23 then 56
    else 14 }

  method NewOffsets() returns(r: array<T.I>)
    ensures fresh(r) && r.Length == 25
    ensures forall i: int :: 0 <= i < 25 ==> 0 <= r[i] < 64 && r[i] as int == S.Offsets()[i]%64
  {
    r := new T.I[25];
    for i: T.I := 0 to 25
      invariant forall k: int :: 0 <= k < i as int ==> 0 <= r[k] < 64 && r[k] as int == S.Offsets()[k]%64
    { r[i] := Offset(i); }
  }

  function Source(i: T.I): T.I
    requires 0 <= i < 25
    ensures 0 <= Source(i) < 25
    ensures Source(i) as int == (((i as int)%5)+3*((i as int)/5))%5+5*((i as int)%5)
  { if i == 0 then 0
    else if i == 1 then 6
    else if i == 2 then 12
    else if i == 3 then 18
    else if i == 4 then 24
    else if i == 5 then 3
    else if i == 6 then 9
    else if i == 7 then 10
    else if i == 8 then 16
    else if i == 9 then 22
    else if i == 10 then 1
    else if i == 11 then 7
    else if i == 12 then 13
    else if i == 13 then 19
    else if i == 14 then 20
    else if i == 15 then 4
    else if i == 16 then 5
    else if i == 17 then 11
    else if i == 18 then 17
    else if i == 19 then 23
    else if i == 20 then 2
    else if i == 21 then 8
    else if i == 22 then 14
    else if i == 23 then 15
    else 21 }
  method NewSources() returns(r: array<T.I>)
    ensures fresh(r) && r.Length == 25
    ensures forall i: int :: 0 <= i < 25 ==> 0 <= r[i] < 25 && r[i] as int == ((i%5)+3*(i/5))%5+5*(i%5)
  {
    r := new T.I[25];
    for i: T.I := 0 to 25
      invariant forall k: int :: 0 <= k < i as int ==> 0 <= r[k] < 25 && r[k] as int == ((k%5)+3*(k/5))%5+5*(k%5)
    { r[i] := Source(i); }
  }
  method SetLane(a: array<bv64>, index: T.I, value: bv64)
    requires a.Length == 25 && 0 <= index < 25
    modifies a
    ensures a[..] == old(a[..])[index as int := value]
  {
    ghost var before := a[..];
    a[index] := value;
    forall j: int | 0 <= j < 25
      ensures a[j] == before[index as int := value][j]
    { if j == index as int {} }
  }

  method Iota(a: array<bv64>, rc: bv64)
    requires a.Length == 25
    modifies a
    ensures a[..] == S.Iota(old(a[..]),rc)
  { var value := a[0]^rc; SetLane(a,0,value); }

  method {:isolate_assertions} Theta(a: array<bv64>, c: array<bv64>)
    requires a.Length == 25 && c.Length == 5 && a != c
    modifies a,c
    ensures a[..] == S.Theta(old(a[..]))
  {
    ghost var start := a[..];
    for x: T.I := 0 to 5
      modifies c
      invariant forall k: int :: 0 <= k < x as int ==> c[k] == S.Column(start,k)
    {
      S.ColumnAt(start,x as int);
      c[x] := a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
    }
    for x: T.I := 0 to 5
      modifies a
      invariant forall k: int :: 0 <= k < 25 && k%5 < x as int ==> a[k] == S.Theta(start)[k]
      invariant forall k: int :: 0 <= k < 25 && x as int <= k%5 ==> a[k] == start[k]
    {
      var d := c[(x+4)%5] ^ Rotate(c[(x+1)%5],1);
      for y: T.I := 0 to 5
        modifies a
        invariant forall k: int :: 0 <= k < 25 && (k%5 < x as int || (k%5 == x as int && k/5 < y as int)) ==> a[k] == S.Theta(start)[k]
        invariant forall k: int :: 0 <= k < 25 && (x as int < k%5 || (k%5 == x as int && y as int <= k/5)) ==> a[k] == start[k]
      {
        var i: T.I := x+5*y;
        assert i%5 == x && i/5 == y;
        S.ThetaLaneAt(start,i as int); S.ThetaAt(start,i as int);
        a[i] := a[i]^d;
      }
    }
    assert a[..] == S.Theta(start);
  }
  method {:isolate_assertions} RhoPi(a: array<bv64>, b: array<bv64>, offsets: array<T.I>, sources: array<T.I>)
    requires a.Length == 25 && b.Length == 25 && a != b
    requires offsets.Length == 25 && (offsets as object) != (b as object)
    requires forall i: int :: 0 <= i < 25 ==> 0 <= offsets[i] < 64 && offsets[i] as int == S.Offsets()[i]%64
    requires sources.Length == 25
    requires (sources as object) != (b as object) && (sources as object) != (a as object)
    requires forall i: int :: 0 <= i < 25 ==> 0 <= sources[i] < 25 && sources[i] as int == ((i%5)+3*(i/5))%5+5*(i%5)
    modifies b
    ensures b[..] == S.Pi(S.Rho(a[..]))
  {
    ghost var theta := a[..];
    // A pull mapping combines rho and pi; addresses depend only on loop index.
    for i: T.I := 0 to 25
      modifies b
      invariant forall k: int :: 0 <= k < i as int ==> b[k] == S.Pi(S.Rho(theta))[k]
    {
      var j: T.I := sources[i];
      assert j as int == (((i as int)%5)+3*((i as int)/5))%5+5*((i as int)%5);
      assert 0 <= offsets[j] < 64;
      assert offsets[j] as int == S.Offsets()[j]%64;
      b[i] := Rotate(a[j],offsets[j]);
    }
    assert b[..] == S.Pi(S.Rho(theta));
  }
  method {:isolate_assertions} Chi(a: array<bv64>, b: array<bv64>)
    requires a.Length == 25 && b.Length == 25 && a != b
    modifies a
    ensures a[..] == S.Chi(b[..])
  {
    ghost var pi := b[..];
    for i: T.I := 0 to 25
      modifies a
      invariant forall k: int :: 0 <= k < i as int ==> a[k] == S.Chi(pi)[k]
    {
      var row: T.I := 5*(i/5); var x: T.I := i%5;
      a[i] := b[i] ^ ((!b[row+(x+1)%5]) & b[row+(x+2)%5]);
    }
    assert a[..] == S.Chi(pi);
  }
  method {:isolate_assertions} Round(a: array<bv64>, b: array<bv64>, c: array<bv64>, offsets: array<T.I>, sources: array<T.I>, rc: bv64)
    requires a.Length == 25 && b.Length == 25 && c.Length == 5
    requires a != b && a != c && b != c
    requires offsets.Length == 25
    requires (offsets as object) != (a as object) && (offsets as object) != (b as object) && (offsets as object) != (c as object)
    requires forall i: int :: 0 <= i < 25 ==> 0 <= offsets[i] < 64 && offsets[i] as int == S.Offsets()[i]%64
    requires sources.Length == 25
    requires (sources as object) != (b as object) && (sources as object) != (a as object)
    requires forall i: int :: 0 <= i < 25 ==> 0 <= sources[i] < 25 && sources[i] as int == ((i%5)+3*(i/5))%5+5*(i%5)
    requires (sources as object) != (c as object)
    modifies a,b,c
    ensures a[..] == S.Round(old(a[..]),rc)
  {
    ghost var start := a[..];
    Theta(a,c); RhoPi(a,b,offsets,sources); Chi(a,b); Iota(a,rc);
    S.RoundEquation(start,rc);
  }
  method {:isolate_assertions} PermuteScratch(a: array<bv64>, b: array<bv64>, c: array<bv64>, offsets: array<T.I>, sources: array<T.I>)
    requires a.Length == 25 && b.Length == 25 && c.Length == 5
    requires a != b && a != c && b != c
    requires offsets.Length == 25
    requires (offsets as object) != (a as object) && (offsets as object) != (b as object) && (offsets as object) != (c as object)
    requires forall i: int :: 0 <= i < 25 ==> 0 <= offsets[i] < 64 && offsets[i] as int == S.Offsets()[i]%64
    requires sources.Length == 25
    requires (sources as object) != (b as object) && (sources as object) != (a as object)
    requires forall i: int :: 0 <= i < 25 ==> 0 <= sources[i] < 25 && sources[i] as int == ((i%5)+3*(i/5))%5+5*(i%5)
    requires (sources as object) != (c as object)
    modifies a,b,c
    ensures a[..] == S.Iter(old(a[..]),24)
  {
    ghost var start := a[..];
    S.IterZero(start);
    ghost var completed := 0;
    for i: T.I := 0 to 24
      modifies a,b,c
      invariant a[..] == S.Iter(start,i as int)
      invariant completed == i as int
    {
      S.IterStep(start,i as int);
      Round(a,b,c,offsets,sources,Constant(i));
      completed := i as int+1;
    }
    assert completed == 24;
  }
  method {:isolate_assertions} Permute(a: array<bv64>)
    requires a.Length == 25
    modifies a
    ensures a[..] == S.Iter(old(a[..]),24)
  {
    var b := new bv64[25]; var c := new bv64[5];
    var offsets := NewOffsets(); var sources := NewSources();
    PermuteScratch(a,b,c,offsets,sources);
    Wipe(b); Wipe(c);
  }

  method Wipe(a: array<bv64>)
    requires T.JavaLength(a.Length)
    modifies a
    ensures forall i: int :: 0 <= i < a.Length ==> a[i] == 0
  {
    var length: T.I := a.Length as T.I;
    for i: T.I := 0 to length
      invariant forall k: int :: 0 <= k < i as int ==> a[k] == 0
    { a[i] := 0; }
  }
}
