include "NativeField.dfy"
include "Polynomial.dfy"

// Native-array refinement of the FIPS203 polynomial specification. Runtime
// coefficients and indices are primitive Java ints. Mathematical sequences are
// ghost snapshots only. The Go-derived butterfly formulas retain their original
// provenance; the array refinement and range proofs are new work.
module NativePolynomial {
  import T = NativeTypes
  import S = PolySpec
  import R = PolynomialRing
  import F = NativeField
  import P = VerifiedPolynomial

  function Len(s: T.I): T.I
    requires 0 <= s < 7
    ensures Len(s) as int == S.Len(s as int)
    ensures 2 <= Len(s) <= 128
  { if s == 0 then 128 else if s == 1 then 64 else if s == 2 then 32
    else if s == 3 then 16 else if s == 4 then 8 else if s == 5 then 4 else 2 }

  function ZetasChunk0(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk0(i) < 3329
    ensures ZetasChunk0(i) as int == S.Zetas()[0+(i as int)]
  {
    reveal S.Zetas();
    if i == 0 then 1
    else if i == 1 then 1729
    else if i == 2 then 2580
    else if i == 3 then 3289
    else if i == 4 then 2642
    else if i == 5 then 630
    else if i == 6 then 1897
    else if i == 7 then 848
    else if i == 8 then 1062
    else if i == 9 then 1919
    else if i == 10 then 193
    else if i == 11 then 797
    else if i == 12 then 2786
    else if i == 13 then 3260
    else if i == 14 then 569
    else 1746
  }

  function ZetasChunk1(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk1(i) < 3329
    ensures ZetasChunk1(i) as int == S.Zetas()[16+(i as int)]
  {
    reveal S.Zetas();
    if i == 0 then 296
    else if i == 1 then 2447
    else if i == 2 then 1339
    else if i == 3 then 1476
    else if i == 4 then 3046
    else if i == 5 then 56
    else if i == 6 then 2240
    else if i == 7 then 1333
    else if i == 8 then 1426
    else if i == 9 then 2094
    else if i == 10 then 535
    else if i == 11 then 2882
    else if i == 12 then 2393
    else if i == 13 then 2879
    else if i == 14 then 1974
    else 821
  }

  function ZetasChunk2(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk2(i) < 3329
    ensures ZetasChunk2(i) as int == S.Zetas()[32+(i as int)]
  {
    reveal S.Zetas();
    if i == 0 then 289
    else if i == 1 then 331
    else if i == 2 then 3253
    else if i == 3 then 1756
    else if i == 4 then 1197
    else if i == 5 then 2304
    else if i == 6 then 2277
    else if i == 7 then 2055
    else if i == 8 then 650
    else if i == 9 then 1977
    else if i == 10 then 2513
    else if i == 11 then 632
    else if i == 12 then 2865
    else if i == 13 then 33
    else if i == 14 then 1320
    else 1915
  }

  function ZetasChunk3(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk3(i) < 3329
    ensures ZetasChunk3(i) as int == S.Zetas()[48+(i as int)]
  {
    reveal S.Zetas();
    if i == 0 then 2319
    else if i == 1 then 1435
    else if i == 2 then 807
    else if i == 3 then 452
    else if i == 4 then 1438
    else if i == 5 then 2868
    else if i == 6 then 1534
    else if i == 7 then 2402
    else if i == 8 then 2647
    else if i == 9 then 2617
    else if i == 10 then 1481
    else if i == 11 then 648
    else if i == 12 then 2474
    else if i == 13 then 3110
    else if i == 14 then 1227
    else 910
  }

  function ZetasChunk4(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk4(i) < 3329
    ensures ZetasChunk4(i) as int == S.Zetas()[64+(i as int)]
  {
    reveal S.Zetas();
    if i == 0 then 17
    else if i == 1 then 2761
    else if i == 2 then 583
    else if i == 3 then 2649
    else if i == 4 then 1637
    else if i == 5 then 723
    else if i == 6 then 2288
    else if i == 7 then 1100
    else if i == 8 then 1409
    else if i == 9 then 2662
    else if i == 10 then 3281
    else if i == 11 then 233
    else if i == 12 then 756
    else if i == 13 then 2156
    else if i == 14 then 3015
    else 3050
  }

  function ZetasChunk5(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk5(i) < 3329
    ensures ZetasChunk5(i) as int == S.Zetas()[80+(i as int)]
  {
    reveal S.Zetas();
    if i == 0 then 1703
    else if i == 1 then 1651
    else if i == 2 then 2789
    else if i == 3 then 1789
    else if i == 4 then 1847
    else if i == 5 then 952
    else if i == 6 then 1461
    else if i == 7 then 2687
    else if i == 8 then 939
    else if i == 9 then 2308
    else if i == 10 then 2437
    else if i == 11 then 2388
    else if i == 12 then 733
    else if i == 13 then 2337
    else if i == 14 then 268
    else 641
  }

  function ZetasChunk6(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk6(i) < 3329
    ensures ZetasChunk6(i) as int == S.Zetas()[96+(i as int)]
  {
    reveal S.Zetas();
    if i == 0 then 1584
    else if i == 1 then 2298
    else if i == 2 then 2037
    else if i == 3 then 3220
    else if i == 4 then 375
    else if i == 5 then 2549
    else if i == 6 then 2090
    else if i == 7 then 1645
    else if i == 8 then 1063
    else if i == 9 then 319
    else if i == 10 then 2773
    else if i == 11 then 757
    else if i == 12 then 2099
    else if i == 13 then 561
    else if i == 14 then 2466
    else 2594
  }

  function ZetasChunk7(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk7(i) < 3329
    ensures ZetasChunk7(i) as int == S.Zetas()[112+(i as int)]
  {
    reveal S.Zetas();
    if i == 0 then 2804
    else if i == 1 then 1092
    else if i == 2 then 403
    else if i == 3 then 1026
    else if i == 4 then 1143
    else if i == 5 then 2150
    else if i == 6 then 2775
    else if i == 7 then 886
    else if i == 8 then 1722
    else if i == 9 then 1212
    else if i == 10 then 1874
    else if i == 11 then 1029
    else if i == 12 then 2110
    else if i == 13 then 2935
    else if i == 14 then 885
    else 2154
  }

  function ZetasValue(i: T.I): T.I
    requires 0 <= i < 128
    ensures 0 <= ZetasValue(i) < 3329
    ensures ZetasValue(i) as int == S.Zetas()[i as int]
  {
    if i < 16 then ZetasChunk0(i-0)
    else if i < 32 then ZetasChunk1(i-16)
    else if i < 48 then ZetasChunk2(i-32)
    else if i < 64 then ZetasChunk3(i-48)
    else if i < 80 then ZetasChunk4(i-64)
    else if i < 96 then ZetasChunk5(i-80)
    else if i < 112 then ZetasChunk6(i-96)
    else ZetasChunk7(i-112)
  }

  method NewZetas() returns (r: array<T.I>)
    ensures fresh(r) && r.Length == 128
    ensures T.Ints(r) == S.Zetas()
    ensures forall i: int :: 0 <= i < 128 ==> 0 <= r[i] < 3329
  {
    r := new T.I[128 as T.I];
    for i: T.I := 0 to 128
      invariant forall j: int :: 0 <= j < i as int ==> r[j] as int == S.Zetas()[j] && 0 <= r[j] < 3329
    { r[i] := ZetasValue(i); }
    assert T.Ints(r) == S.Zetas();
  }

  function GammasChunk0(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= GammasChunk0(i) < 3329
    ensures GammasChunk0(i) as int == S.Gammas()[0+(i as int)]
  {
    reveal S.Gammas();
    if i == 0 then 17
    else if i == 1 then 3312
    else if i == 2 then 2761
    else if i == 3 then 568
    else if i == 4 then 583
    else if i == 5 then 2746
    else if i == 6 then 2649
    else if i == 7 then 680
    else if i == 8 then 1637
    else if i == 9 then 1692
    else if i == 10 then 723
    else if i == 11 then 2606
    else if i == 12 then 2288
    else if i == 13 then 1041
    else if i == 14 then 1100
    else 2229
  }

  function GammasChunk1(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= GammasChunk1(i) < 3329
    ensures GammasChunk1(i) as int == S.Gammas()[16+(i as int)]
  {
    reveal S.Gammas();
    if i == 0 then 1409
    else if i == 1 then 1920
    else if i == 2 then 2662
    else if i == 3 then 667
    else if i == 4 then 3281
    else if i == 5 then 48
    else if i == 6 then 233
    else if i == 7 then 3096
    else if i == 8 then 756
    else if i == 9 then 2573
    else if i == 10 then 2156
    else if i == 11 then 1173
    else if i == 12 then 3015
    else if i == 13 then 314
    else if i == 14 then 3050
    else 279
  }

  function GammasChunk2(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= GammasChunk2(i) < 3329
    ensures GammasChunk2(i) as int == S.Gammas()[32+(i as int)]
  {
    reveal S.Gammas();
    if i == 0 then 1703
    else if i == 1 then 1626
    else if i == 2 then 1651
    else if i == 3 then 1678
    else if i == 4 then 2789
    else if i == 5 then 540
    else if i == 6 then 1789
    else if i == 7 then 1540
    else if i == 8 then 1847
    else if i == 9 then 1482
    else if i == 10 then 952
    else if i == 11 then 2377
    else if i == 12 then 1461
    else if i == 13 then 1868
    else if i == 14 then 2687
    else 642
  }

  function GammasChunk3(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= GammasChunk3(i) < 3329
    ensures GammasChunk3(i) as int == S.Gammas()[48+(i as int)]
  {
    reveal S.Gammas();
    if i == 0 then 939
    else if i == 1 then 2390
    else if i == 2 then 2308
    else if i == 3 then 1021
    else if i == 4 then 2437
    else if i == 5 then 892
    else if i == 6 then 2388
    else if i == 7 then 941
    else if i == 8 then 733
    else if i == 9 then 2596
    else if i == 10 then 2337
    else if i == 11 then 992
    else if i == 12 then 268
    else if i == 13 then 3061
    else if i == 14 then 641
    else 2688
  }

  function GammasChunk4(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= GammasChunk4(i) < 3329
    ensures GammasChunk4(i) as int == S.Gammas()[64+(i as int)]
  {
    reveal S.Gammas();
    if i == 0 then 1584
    else if i == 1 then 1745
    else if i == 2 then 2298
    else if i == 3 then 1031
    else if i == 4 then 2037
    else if i == 5 then 1292
    else if i == 6 then 3220
    else if i == 7 then 109
    else if i == 8 then 375
    else if i == 9 then 2954
    else if i == 10 then 2549
    else if i == 11 then 780
    else if i == 12 then 2090
    else if i == 13 then 1239
    else if i == 14 then 1645
    else 1684
  }

  function GammasChunk5(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= GammasChunk5(i) < 3329
    ensures GammasChunk5(i) as int == S.Gammas()[80+(i as int)]
  {
    reveal S.Gammas();
    if i == 0 then 1063
    else if i == 1 then 2266
    else if i == 2 then 319
    else if i == 3 then 3010
    else if i == 4 then 2773
    else if i == 5 then 556
    else if i == 6 then 757
    else if i == 7 then 2572
    else if i == 8 then 2099
    else if i == 9 then 1230
    else if i == 10 then 561
    else if i == 11 then 2768
    else if i == 12 then 2466
    else if i == 13 then 863
    else if i == 14 then 2594
    else 735
  }

  function GammasChunk6(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= GammasChunk6(i) < 3329
    ensures GammasChunk6(i) as int == S.Gammas()[96+(i as int)]
  {
    reveal S.Gammas();
    if i == 0 then 2804
    else if i == 1 then 525
    else if i == 2 then 1092
    else if i == 3 then 2237
    else if i == 4 then 403
    else if i == 5 then 2926
    else if i == 6 then 1026
    else if i == 7 then 2303
    else if i == 8 then 1143
    else if i == 9 then 2186
    else if i == 10 then 2150
    else if i == 11 then 1179
    else if i == 12 then 2775
    else if i == 13 then 554
    else if i == 14 then 886
    else 2443
  }

  function GammasChunk7(i: T.I): T.I
    requires 0 <= i < 16
    ensures 0 <= GammasChunk7(i) < 3329
    ensures GammasChunk7(i) as int == S.Gammas()[112+(i as int)]
  {
    reveal S.Gammas();
    if i == 0 then 1722
    else if i == 1 then 1607
    else if i == 2 then 1212
    else if i == 3 then 2117
    else if i == 4 then 1874
    else if i == 5 then 1455
    else if i == 6 then 1029
    else if i == 7 then 2300
    else if i == 8 then 2110
    else if i == 9 then 1219
    else if i == 10 then 2935
    else if i == 11 then 394
    else if i == 12 then 885
    else if i == 13 then 2444
    else if i == 14 then 2154
    else 1175
  }

  function GammasValue(i: T.I): T.I
    requires 0 <= i < 128
    ensures 0 <= GammasValue(i) < 3329
    ensures GammasValue(i) as int == S.Gammas()[i as int]
  {
    if i < 16 then GammasChunk0(i-0)
    else if i < 32 then GammasChunk1(i-16)
    else if i < 48 then GammasChunk2(i-32)
    else if i < 64 then GammasChunk3(i-48)
    else if i < 80 then GammasChunk4(i-64)
    else if i < 96 then GammasChunk5(i-80)
    else if i < 112 then GammasChunk6(i-96)
    else GammasChunk7(i-112)
  }

  method NewGammas() returns (r: array<T.I>)
    ensures fresh(r) && r.Length == 128
    ensures T.Ints(r) == S.Gammas()
    ensures forall i: int :: 0 <= i < 128 ==> 0 <= r[i] < 3329
  {
    r := new T.I[128 as T.I];
    for i: T.I := 0 to 128
      invariant forall j: int :: 0 <= j < i as int ==> r[j] as int == S.Gammas()[j] && 0 <= r[j] < 3329
    { r[i] := GammasValue(i); }
    assert T.Ints(r) == S.Gammas();
  }

  method Add(f: array<T.I>, g: array<T.I>) returns (r: array<T.I>)
    requires T.Canonical(f) && T.Canonical(g)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.Add(T.Ints(f),T.Ints(g))
  {
    r := new T.I[256 as T.I];
    for i: T.I := 0 to 256
      invariant forall j: int :: 0 <= j < i as int ==> r[j] as int == S.Add(T.Ints(f),T.Ints(g))[j]
    { r[i] := F.Add(f[i],g[i]); }
    assert T.Ints(r) == S.Add(T.Ints(f),T.Ints(g));
  }

  method Sub(f: array<T.I>, g: array<T.I>) returns (r: array<T.I>)
    requires T.Canonical(f) && T.Canonical(g)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.Sub(T.Ints(f),T.Ints(g))
  {
    r := new T.I[256 as T.I];
    for i: T.I := 0 to 256
      invariant forall j: int :: 0 <= j < i as int ==> r[j] as int == S.Sub(T.Ints(f),T.Ints(g))[j]
    { r[i] := F.Sub(f[i],g[i]); }
    assert T.Ints(r) == S.Sub(T.Ints(f),T.Ints(g));
  }

  method Copy(f: array<T.I>) returns (r: array<T.I>)
    requires T.Canonical(f)
    ensures fresh(r) && T.Canonical(r) && T.Ints(r) == T.Ints(f)
  {
    r := new T.I[256 as T.I];
    for i: T.I := 0 to 256
      invariant forall j: int :: 0 <= j < i as int ==> r[j] == f[j]
    { r[i] := f[i]; }
  }

  method {:isolate_assertions} ForwardStage(f: array<T.I>, r: array<T.I>, roots: array<T.I>, s: T.I)
    requires T.Canonical(f) && r.Length == 256 && 0 <= s < 7
    requires f != r && roots != r && T.Ints(roots) == S.Zetas()
    modifies r
    ensures T.Canonical(r) && T.Ints(r) == S.ForwardStage(T.Ints(f),s as int)
  {
    var l := Len(s);
    var blocks: T.I := 128/l;
    for block: T.I := 0 to blocks
      modifies r
      invariant forall j: int :: 0 <= j < 2*(l as int)*(block as int) ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j)
    {
      var start: T.I := 2*l*block;
      var k: T.I := 128/l+block;
      S.StageBounds((s) as int,start as int);
      S.RootTables(k as int);
      var z := roots[k];
      for offset: T.I := 0 to l
        modifies r
        invariant forall j: int :: 0 <= j < start as int ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j)
        invariant forall j: int :: start as int <= j < (start as int)+(offset as int) ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j)
        invariant forall j: int :: (start as int)+(l as int) <= j < (start as int)+(l as int)+(offset as int) ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j)
      {
        var i: T.I := start+offset;
        S.StageBounds((s) as int,i as int);
        S.StagePartner((s) as int,i as int);
        assert i/(2*l) == block && i%(2*l) == offset;
        var t := F.Mul(z,f[i+l]);
        r[i] := F.Add(f[i],t);
        r[i+l] := F.Sub(f[i],t);
      }
      assert forall j: int :: 0 <= j < 2*(l as int)*((block as int)+1) ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j);
    }
    assert T.Ints(r) == S.ForwardStage(T.Ints(f),s as int);
  }
  method {:isolate_assertions} InverseStage(f: array<T.I>, r: array<T.I>, roots: array<T.I>, s: T.I)
    requires T.Canonical(f) && r.Length == 256 && 0 <= s < 7
    requires f != r && roots != r && T.Ints(roots) == S.Zetas()
    modifies r
    ensures T.Canonical(r) && T.Ints(r) == S.InverseStage(T.Ints(f),s as int)
  {
    var l := Len(6-s);
    var blocks: T.I := 128/l;
    for block: T.I := 0 to blocks
      modifies r
      invariant forall j: int :: 0 <= j < 2*(l as int)*(block as int) ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j)
    {
      var start: T.I := 2*l*block;
      var k: T.I := 256/l-1-block;
      S.StageBounds((6-s) as int,start as int);
      S.RootTables(k as int);
      var z := roots[k];
      for offset: T.I := 0 to l
        modifies r
        invariant forall j: int :: 0 <= j < start as int ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j)
        invariant forall j: int :: start as int <= j < (start as int)+(offset as int) ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j)
        invariant forall j: int :: (start as int)+(l as int) <= j < (start as int)+(l as int)+(offset as int) ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j)
      {
        var i: T.I := start+offset;
        S.StageBounds((6-s) as int,i as int);
        S.StagePartner((6-s) as int,i as int);
        assert i/(2*l) == block && i%(2*l) == offset;
        r[i] := F.Add(f[i],f[i+l]);
        r[i+l] := F.MulSub(z,f[i+l],f[i]);
      }
      assert forall j: int :: 0 <= j < 2*(l as int)*((block as int)+1) ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j);
    }
    assert T.Ints(r) == S.InverseStage(T.Ints(f),s as int);
  }
  method Scale(a: array<T.I>, scalar: T.I)
    requires T.Canonical(a) && 0 <= scalar < 3329
    modifies a
    ensures T.Canonical(a) && T.Ints(a) == S.Scale(old(T.Ints(a)),scalar as int)
  {
    ghost var before := T.Ints(a);
    for i: T.I := 0 to 256
      invariant forall j: int :: 0 <= j < i as int ==> a[j] as int == S.Scale(before,scalar as int)[j]
      invariant forall j: int :: i as int <= j < 256 ==> a[j] as int == before[j]
    { a[i] := F.Mul(a[i],scalar); }
    assert T.Ints(a) == S.Scale(before,scalar as int);
  }

  method Ntt(f: array<T.I>) returns (r: array<T.I>)
    requires T.Canonical(f)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.Ntt(T.Ints(f))
    ensures T.Ints(r) == S.Representation(T.Ints(f))
  {
    ghost var before := T.Ints(f);
    r := Copy(f);
    var scratch := new T.I[256 as T.I];
    var roots := NewZetas();
    ghost var a,b := r,scratch;
    S.NttPrefixZero(before);
    for s: T.I := 0 to 7
      modifies a,b
      invariant (r == a && scratch == b) || (r == b && scratch == a)
      invariant fresh(r) && fresh(scratch)
      invariant r != scratch && r != roots && scratch != roots
      invariant scratch.Length == 256
      invariant T.Canonical(r) && T.Ints(r) == S.NttPrefix(before,s as int)
    {
      S.NttPrefixStep(before,s as int);
      ForwardStage(r,scratch,roots,s);
      r,scratch := scratch,r;
    }
    Wipe(scratch);
    S.NttRepresentation(before);
  }

  method InverseNtt(f: array<T.I>) returns (r: array<T.I>)
    requires T.Canonical(f)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.InverseNtt(T.Ints(f))
    ensures S.Representation(T.Ints(r)) == T.Ints(f)
  {
    ghost var before := T.Ints(f);
    r := Copy(f);
    var scratch := new T.I[256 as T.I];
    var roots := NewZetas();
    ghost var a,b := r,scratch;
    for s: T.I := 0 to 7
      modifies a,b
      invariant (r == a && scratch == b) || (r == b && scratch == a)
      invariant fresh(r) && fresh(scratch)
      invariant r != scratch && r != roots && scratch != roots
      invariant scratch.Length == 256
      invariant T.Canonical(r) && T.Ints(r) == S.InversePrefix(before,s as int)
    {
      InverseStage(r,scratch,roots,s);
      r,scratch := scratch,r;
    }
    Wipe(scratch);
    Scale(r,3303);
    R.NttInverseRoundTrip(before);
    S.NttRepresentation(T.Ints(r));
  }

  method BaseCase(a0: T.I, a1: T.I, b0: T.I, b1: T.I, gamma: T.I, r: array<T.I>, i: T.I)
    requires r.Length == 256 && 0 <= i < 255
    modifies r
    requires 0 <= a0 < 3329 && 0 <= a1 < 3329
    requires 0 <= b0 < 3329 && 0 <= b1 < 3329 && 0 <= gamma < 3329
    ensures 0 <= r[i] < 3329 && 0 <= r[i+1] < 3329
    ensures r[i] as int == ((a0 as int)*(b0 as int)+(a1 as int)*(b1 as int)*(gamma as int))%3329
    ensures r[i+1] as int == ((a0 as int)*(b1 as int)+(a1 as int)*(b0 as int))%3329
    ensures forall j: int :: 0 <= j < 256 && j != i as int && j != (i as int)+1 ==> r[j] == old(r[j])
  {
    var t := F.Mul(a1,b1);
    var c0 := F.AddMul(a0,b0,t,gamma);
    var c1 := F.AddMul(a0,b1,a1,b0);
    r[i],r[i+1] := c0,c1;
    P.ModProduct((a1 as int)*(b1 as int),gamma as int);
  }

  method {:isolate_assertions} NttMul(f: array<T.I>, g: array<T.I>) returns (r: array<T.I>)
    requires T.Canonical(f) && T.Canonical(g)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.NttMul(T.Ints(f),T.Ints(g))
  {
    r := new T.I[256 as T.I];
    var gammas := NewGammas();
    for i: T.I := 0 to 128
      modifies r
      invariant forall j: int :: 0 <= j < 2*(i as int) ==> r[j] as int == S.NttMul(T.Ints(f),T.Ints(g))[j]
    {
      S.RootTables(i as int);
      BaseCase(f[2*i],f[2*i+1],g[2*i],g[2*i+1],gammas[i],r,2*i);
    }
    assert T.Ints(r) == S.NttMul(T.Ints(f),T.Ints(g));
  }

  // Source-level clearing only; physical erasure still depends on compiler/JIT.
  method Wipe(a: array<T.I>)
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
