include "../primitives/Field.dfy"

// FIPS 203, sections 2.4.5 and 4.3. New contracts and proofs.
// Scalar helper formulas and the butterfly organization originate in the existing
// Go-derived MlKem768.java (Go Authors, BSD-3-Clause).
module PolySpec {
  const Q: int := 3329
  const N: int := 256

  ghost predicate Canonical(f: seq<int>) {
    |f| == N && forall i :: 0 <= i < N ==> 0 <= f[i] < Q
  }

  ghost function Add(f: seq<int>, g: seq<int>): seq<int>
    requires Canonical(f) && Canonical(g)
    ensures Canonical(Add(f, g))
  { seq(N, i requires 0 <= i < N => (f[i] + g[i]) % Q) }

  ghost function Sub(f: seq<int>, g: seq<int>): seq<int>
    requires Canonical(f) && Canonical(g)
    ensures Canonical(Sub(f, g))
  { seq(N, i requires 0 <= i < N => (f[i] - g[i]) % Q) }

  function {:opaque} PowMod(a: int, e: nat): int
    ensures 0 <= PowMod(a, e) < Q
    decreases e
  {
    if e == 0 then 1 else
      var h := PowMod(a, e / 2);
      (h*h*(if e%2 == 0 then 1 else a))%Q
  }

  function BitRev7(i: nat): nat
    requires i < 128
    ensures BitRev7(i) < 128
  { 64*(i%2)+32*((i/2)%2)+16*((i/4)%2)+8*((i/8)%2)+4*((i/16)%2)+2*((i/32)%2)+i/64 }

  function {:opaque} Zeta(i: nat): int
    requires i < 128
    ensures 0 <= Zeta(i) < Q
  { PowMod(17, BitRev7(i)) }

  function {:opaque} Gamma(i: nat): int
    requires i < 128
    ensures 0 <= Gamma(i) < Q
  { PowMod(17, 2*BitRev7(i)+1) }

  // Appendix A constants, also used by the production Go-derived port.
  // Each entry is proved against the section 4.3 exponent definition below.
  function {:opaque} Zetas(): seq<int>
    ensures |Zetas()| == 128
  {
    [1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746] +
    [296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821] +
    [289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915] +
    [2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910] +
    [17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050] +
    [1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641] +
    [1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594] +
    [2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154]
  }

  function {:opaque} Gammas(): seq<int>
    ensures |Gammas()| == 128
  {
    [17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229] +
    [1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279] +
    [1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642] +
    [939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688] +
    [1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684] +
    [1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735] +
    [2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443] +
    [1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175]
  }

  lemma RootTables(i: nat)
    requires i < 128
    ensures Zetas()[i] == Zeta(i) && Gammas()[i] == Gamma(i)
  {
    if i == 0 { RootEntry0(); }
    else if i == 1 { RootEntry1(); }
    else if i == 2 { RootEntry2(); }
    else if i == 3 { RootEntry3(); }
    else if i == 4 { RootEntry4(); }
    else if i == 5 { RootEntry5(); }
    else if i == 6 { RootEntry6(); }
    else if i == 7 { RootEntry7(); }
    else if i == 8 { RootEntry8(); }
    else if i == 9 { RootEntry9(); }
    else if i == 10 { RootEntry10(); }
    else if i == 11 { RootEntry11(); }
    else if i == 12 { RootEntry12(); }
    else if i == 13 { RootEntry13(); }
    else if i == 14 { RootEntry14(); }
    else if i == 15 { RootEntry15(); }
    else if i == 16 { RootEntry16(); }
    else if i == 17 { RootEntry17(); }
    else if i == 18 { RootEntry18(); }
    else if i == 19 { RootEntry19(); }
    else if i == 20 { RootEntry20(); }
    else if i == 21 { RootEntry21(); }
    else if i == 22 { RootEntry22(); }
    else if i == 23 { RootEntry23(); }
    else if i == 24 { RootEntry24(); }
    else if i == 25 { RootEntry25(); }
    else if i == 26 { RootEntry26(); }
    else if i == 27 { RootEntry27(); }
    else if i == 28 { RootEntry28(); }
    else if i == 29 { RootEntry29(); }
    else if i == 30 { RootEntry30(); }
    else if i == 31 { RootEntry31(); }
    else if i == 32 { RootEntry32(); }
    else if i == 33 { RootEntry33(); }
    else if i == 34 { RootEntry34(); }
    else if i == 35 { RootEntry35(); }
    else if i == 36 { RootEntry36(); }
    else if i == 37 { RootEntry37(); }
    else if i == 38 { RootEntry38(); }
    else if i == 39 { RootEntry39(); }
    else if i == 40 { RootEntry40(); }
    else if i == 41 { RootEntry41(); }
    else if i == 42 { RootEntry42(); }
    else if i == 43 { RootEntry43(); }
    else if i == 44 { RootEntry44(); }
    else if i == 45 { RootEntry45(); }
    else if i == 46 { RootEntry46(); }
    else if i == 47 { RootEntry47(); }
    else if i == 48 { RootEntry48(); }
    else if i == 49 { RootEntry49(); }
    else if i == 50 { RootEntry50(); }
    else if i == 51 { RootEntry51(); }
    else if i == 52 { RootEntry52(); }
    else if i == 53 { RootEntry53(); }
    else if i == 54 { RootEntry54(); }
    else if i == 55 { RootEntry55(); }
    else if i == 56 { RootEntry56(); }
    else if i == 57 { RootEntry57(); }
    else if i == 58 { RootEntry58(); }
    else if i == 59 { RootEntry59(); }
    else if i == 60 { RootEntry60(); }
    else if i == 61 { RootEntry61(); }
    else if i == 62 { RootEntry62(); }
    else if i == 63 { RootEntry63(); }
    else if i == 64 { RootEntry64(); }
    else if i == 65 { RootEntry65(); }
    else if i == 66 { RootEntry66(); }
    else if i == 67 { RootEntry67(); }
    else if i == 68 { RootEntry68(); }
    else if i == 69 { RootEntry69(); }
    else if i == 70 { RootEntry70(); }
    else if i == 71 { RootEntry71(); }
    else if i == 72 { RootEntry72(); }
    else if i == 73 { RootEntry73(); }
    else if i == 74 { RootEntry74(); }
    else if i == 75 { RootEntry75(); }
    else if i == 76 { RootEntry76(); }
    else if i == 77 { RootEntry77(); }
    else if i == 78 { RootEntry78(); }
    else if i == 79 { RootEntry79(); }
    else if i == 80 { RootEntry80(); }
    else if i == 81 { RootEntry81(); }
    else if i == 82 { RootEntry82(); }
    else if i == 83 { RootEntry83(); }
    else if i == 84 { RootEntry84(); }
    else if i == 85 { RootEntry85(); }
    else if i == 86 { RootEntry86(); }
    else if i == 87 { RootEntry87(); }
    else if i == 88 { RootEntry88(); }
    else if i == 89 { RootEntry89(); }
    else if i == 90 { RootEntry90(); }
    else if i == 91 { RootEntry91(); }
    else if i == 92 { RootEntry92(); }
    else if i == 93 { RootEntry93(); }
    else if i == 94 { RootEntry94(); }
    else if i == 95 { RootEntry95(); }
    else if i == 96 { RootEntry96(); }
    else if i == 97 { RootEntry97(); }
    else if i == 98 { RootEntry98(); }
    else if i == 99 { RootEntry99(); }
    else if i == 100 { RootEntry100(); }
    else if i == 101 { RootEntry101(); }
    else if i == 102 { RootEntry102(); }
    else if i == 103 { RootEntry103(); }
    else if i == 104 { RootEntry104(); }
    else if i == 105 { RootEntry105(); }
    else if i == 106 { RootEntry106(); }
    else if i == 107 { RootEntry107(); }
    else if i == 108 { RootEntry108(); }
    else if i == 109 { RootEntry109(); }
    else if i == 110 { RootEntry110(); }
    else if i == 111 { RootEntry111(); }
    else if i == 112 { RootEntry112(); }
    else if i == 113 { RootEntry113(); }
    else if i == 114 { RootEntry114(); }
    else if i == 115 { RootEntry115(); }
    else if i == 116 { RootEntry116(); }
    else if i == 117 { RootEntry117(); }
    else if i == 118 { RootEntry118(); }
    else if i == 119 { RootEntry119(); }
    else if i == 120 { RootEntry120(); }
    else if i == 121 { RootEntry121(); }
    else if i == 122 { RootEntry122(); }
    else if i == 123 { RootEntry123(); }
    else if i == 124 { RootEntry124(); }
    else if i == 125 { RootEntry125(); }
    else if i == 126 { RootEntry126(); }
    else if i == 127 { RootEntry127(); }
  }

  lemma RootEntry0()
    ensures Zetas()[0] == Zeta(0) && Gammas()[0] == Gamma(0)
    ensures Zeta(0) == 1 && Gamma(0) == 17
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(0) == 0;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
  }

  lemma RootEntry1()
    ensures Zetas()[1] == Zeta(1) && Gammas()[1] == Gamma(1)
    ensures Zeta(1) == 1729 && Gamma(1) == 3312
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(1) == 64;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,16) == 2642;
    assert PowMod(17,32) == 2580;
    assert PowMod(17,64) == 1729;
    assert PowMod(17,129) == 3312;
  }

  lemma RootEntry2()
    ensures Zetas()[2] == Zeta(2) && Gammas()[2] == Gamma(2)
    ensures Zeta(2) == 2580 && Gamma(2) == 2761
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(2) == 32;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,16) == 2642;
    assert PowMod(17,32) == 2580;
    assert PowMod(17,65) == 2761;
  }

  lemma RootEntry3()
    ensures Zetas()[3] == Zeta(3) && Gammas()[3] == Gamma(3)
    ensures Zeta(3) == 3289 && Gamma(3) == 568
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(3) == 96;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,24) == 2786;
    assert PowMod(17,48) == 1897;
    assert PowMod(17,96) == 3289;
    assert PowMod(17,193) == 568;
  }

  lemma RootEntry4()
    ensures Zetas()[4] == Zeta(4) && Gammas()[4] == Gamma(4)
    ensures Zeta(4) == 2642 && Gamma(4) == 583
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(4) == 16;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,16) == 2642;
    assert PowMod(17,33) == 583;
  }

  lemma RootEntry5()
    ensures Zetas()[5] == Zeta(5) && Gammas()[5] == Gamma(5)
    ensures Zeta(5) == 630 && Gamma(5) == 2746
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(5) == 80;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,20) == 3046;
    assert PowMod(17,40) == 193;
    assert PowMod(17,80) == 630;
    assert PowMod(17,161) == 2746;
  }

  lemma RootEntry6()
    ensures Zetas()[6] == Zeta(6) && Gammas()[6] == Gamma(6)
    ensures Zeta(6) == 1897 && Gamma(6) == 2649
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(6) == 48;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,24) == 2786;
    assert PowMod(17,48) == 1897;
    assert PowMod(17,97) == 2649;
  }

  lemma RootEntry7()
    ensures Zetas()[7] == Zeta(7) && Gammas()[7] == Gamma(7)
    ensures Zeta(7) == 848 && Gamma(7) == 680
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(7) == 112;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,28) == 2393;
    assert PowMod(17,56) == 569;
    assert PowMod(17,112) == 848;
    assert PowMod(17,225) == 680;
  }

  lemma RootEntry8()
    ensures Zetas()[8] == Zeta(8) && Gammas()[8] == Gamma(8)
    ensures Zeta(8) == 1062 && Gamma(8) == 1637
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(8) == 8;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,17) == 1637;
  }

  lemma RootEntry9()
    ensures Zetas()[9] == Zeta(9) && Gammas()[9] == Gamma(9)
    ensures Zeta(9) == 1919 && Gamma(9) == 1692
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(9) == 72;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,18) == 1197;
    assert PowMod(17,36) == 1339;
    assert PowMod(17,72) == 1919;
    assert PowMod(17,145) == 1692;
  }

  lemma RootEntry10()
    ensures Zetas()[10] == Zeta(10) && Gammas()[10] == Gamma(10)
    ensures Zeta(10) == 193 && Gamma(10) == 723
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(10) == 40;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,20) == 3046;
    assert PowMod(17,40) == 193;
    assert PowMod(17,81) == 723;
  }

  lemma RootEntry11()
    ensures Zetas()[11] == Zeta(11) && Gammas()[11] == Gamma(11)
    ensures Zeta(11) == 797 && Gamma(11) == 2606
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(11) == 104;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,26) == 2865;
    assert PowMod(17,52) == 2240;
    assert PowMod(17,104) == 797;
    assert PowMod(17,209) == 2606;
  }

  lemma RootEntry12()
    ensures Zetas()[12] == Zeta(12) && Gammas()[12] == Gamma(12)
    ensures Zeta(12) == 2786 && Gamma(12) == 2288
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(12) == 24;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,24) == 2786;
    assert PowMod(17,49) == 2288;
  }

  lemma RootEntry13()
    ensures Zetas()[13] == Zeta(13) && Gammas()[13] == Gamma(13)
    ensures Zeta(13) == 3260 && Gamma(13) == 1041
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(13) == 88;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,22) == 1438;
    assert PowMod(17,44) == 535;
    assert PowMod(17,88) == 3260;
    assert PowMod(17,177) == 1041;
  }

  lemma RootEntry14()
    ensures Zetas()[14] == Zeta(14) && Gammas()[14] == Gamma(14)
    ensures Zeta(14) == 569 && Gamma(14) == 1100
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(14) == 56;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,28) == 2393;
    assert PowMod(17,56) == 569;
    assert PowMod(17,113) == 1100;
  }

  lemma RootEntry15()
    ensures Zetas()[15] == Zeta(15) && Gammas()[15] == Gamma(15)
    ensures Zeta(15) == 1746 && Gamma(15) == 2229
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(15) == 120;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,30) == 2474;
    assert PowMod(17,60) == 1974;
    assert PowMod(17,120) == 1746;
    assert PowMod(17,241) == 2229;
  }

  lemma RootEntry16()
    ensures Zetas()[16] == Zeta(16) && Gammas()[16] == Gamma(16)
    ensures Zeta(16) == 296 && Gamma(16) == 1409
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(16) == 4;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
  }

  lemma RootEntry17()
    ensures Zetas()[17] == Zeta(17) && Gammas()[17] == Gamma(17)
    ensures Zeta(17) == 2447 && Gamma(17) == 1920
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(17) == 68;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,17) == 1637;
    assert PowMod(17,34) == 3253;
    assert PowMod(17,68) == 2447;
    assert PowMod(17,137) == 1920;
  }

  lemma RootEntry18()
    ensures Zetas()[18] == Zeta(18) && Gammas()[18] == Gamma(18)
    ensures Zeta(18) == 1339 && Gamma(18) == 2662
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(18) == 36;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,18) == 1197;
    assert PowMod(17,36) == 1339;
    assert PowMod(17,73) == 2662;
  }

  lemma RootEntry19()
    ensures Zetas()[19] == Zeta(19) && Gammas()[19] == Gamma(19)
    ensures Zeta(19) == 1476 && Gamma(19) == 667
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(19) == 100;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,25) == 756;
    assert PowMod(17,50) == 2277;
    assert PowMod(17,100) == 1476;
    assert PowMod(17,201) == 667;
  }

  lemma RootEntry20()
    ensures Zetas()[20] == Zeta(20) && Gammas()[20] == Gamma(20)
    ensures Zeta(20) == 3046 && Gamma(20) == 3281
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(20) == 20;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,20) == 3046;
    assert PowMod(17,41) == 3281;
  }

  lemma RootEntry21()
    ensures Zetas()[21] == Zeta(21) && Gammas()[21] == Gamma(21)
    ensures Zeta(21) == 56 && Gamma(21) == 48
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(21) == 84;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,21) == 1847;
    assert PowMod(17,42) == 2513;
    assert PowMod(17,84) == 56;
    assert PowMod(17,169) == 48;
  }

  lemma RootEntry22()
    ensures Zetas()[22] == Zeta(22) && Gammas()[22] == Gamma(22)
    ensures Zeta(22) == 2240 && Gamma(22) == 233
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(22) == 52;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,26) == 2865;
    assert PowMod(17,52) == 2240;
    assert PowMod(17,105) == 233;
  }

  lemma RootEntry23()
    ensures Zetas()[23] == Zeta(23) && Gammas()[23] == Gamma(23)
    ensures Zeta(23) == 1333 && Gamma(23) == 3096
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(23) == 116;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,29) == 733;
    assert PowMod(17,58) == 1320;
    assert PowMod(17,116) == 1333;
    assert PowMod(17,233) == 3096;
  }

  lemma RootEntry24()
    ensures Zetas()[24] == Zeta(24) && Gammas()[24] == Gamma(24)
    ensures Zeta(24) == 1426 && Gamma(24) == 756
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(24) == 12;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,25) == 756;
  }

  lemma RootEntry25()
    ensures Zetas()[25] == Zeta(25) && Gammas()[25] == Gamma(25)
    ensures Zeta(25) == 2094 && Gamma(25) == 2573
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(25) == 76;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,19) == 375;
    assert PowMod(17,38) == 807;
    assert PowMod(17,76) == 2094;
    assert PowMod(17,153) == 2573;
  }

  lemma RootEntry26()
    ensures Zetas()[26] == Zeta(26) && Gammas()[26] == Gamma(26)
    ensures Zeta(26) == 535 && Gamma(26) == 2156
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(26) == 44;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,22) == 1438;
    assert PowMod(17,44) == 535;
    assert PowMod(17,89) == 2156;
  }

  lemma RootEntry27()
    ensures Zetas()[27] == Zeta(27) && Gammas()[27] == Gamma(27)
    ensures Zeta(27) == 2882 && Gamma(27) == 1173
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(27) == 108;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,27) == 2099;
    assert PowMod(17,54) == 1534;
    assert PowMod(17,108) == 2882;
    assert PowMod(17,217) == 1173;
  }

  lemma RootEntry28()
    ensures Zetas()[28] == Zeta(28) && Gammas()[28] == Gamma(28)
    ensures Zeta(28) == 2393 && Gamma(28) == 3015
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(28) == 28;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,28) == 2393;
    assert PowMod(17,57) == 3015;
  }

  lemma RootEntry29()
    ensures Zetas()[29] == Zeta(29) && Gammas()[29] == Gamma(29)
    ensures Zeta(29) == 2879 && Gamma(29) == 314
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(29) == 92;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,23) == 1143;
    assert PowMod(17,46) == 1481;
    assert PowMod(17,92) == 2879;
    assert PowMod(17,185) == 314;
  }

  lemma RootEntry30()
    ensures Zetas()[30] == Zeta(30) && Gammas()[30] == Gamma(30)
    ensures Zeta(30) == 1974 && Gamma(30) == 3050
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(30) == 60;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,30) == 2474;
    assert PowMod(17,60) == 1974;
    assert PowMod(17,121) == 3050;
  }

  lemma RootEntry31()
    ensures Zetas()[31] == Zeta(31) && Gammas()[31] == Gamma(31)
    ensures Zeta(31) == 821 && Gamma(31) == 279
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(31) == 124;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,31) == 2110;
    assert PowMod(17,62) == 1227;
    assert PowMod(17,124) == 821;
    assert PowMod(17,249) == 279;
  }

  lemma RootEntry32()
    ensures Zetas()[32] == Zeta(32) && Gammas()[32] == Gamma(32)
    ensures Zeta(32) == 289 && Gamma(32) == 1703
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(32) == 2;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
  }

  lemma RootEntry33()
    ensures Zetas()[33] == Zeta(33) && Gammas()[33] == Gamma(33)
    ensures Zeta(33) == 331 && Gamma(33) == 1626
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(33) == 66;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,16) == 2642;
    assert PowMod(17,33) == 583;
    assert PowMod(17,66) == 331;
    assert PowMod(17,133) == 1626;
  }

  lemma RootEntry34()
    ensures Zetas()[34] == Zeta(34) && Gammas()[34] == Gamma(34)
    ensures Zeta(34) == 3253 && Gamma(34) == 1651
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(34) == 34;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,17) == 1637;
    assert PowMod(17,34) == 3253;
    assert PowMod(17,69) == 1651;
  }

  lemma RootEntry35()
    ensures Zetas()[35] == Zeta(35) && Gammas()[35] == Gamma(35)
    ensures Zeta(35) == 1756 && Gamma(35) == 1678
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(35) == 98;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,24) == 2786;
    assert PowMod(17,49) == 2288;
    assert PowMod(17,98) == 1756;
    assert PowMod(17,197) == 1678;
  }

  lemma RootEntry36()
    ensures Zetas()[36] == Zeta(36) && Gammas()[36] == Gamma(36)
    ensures Zeta(36) == 1197 && Gamma(36) == 2789
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(36) == 18;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,18) == 1197;
    assert PowMod(17,37) == 2789;
  }

  lemma RootEntry37()
    ensures Zetas()[37] == Zeta(37) && Gammas()[37] == Gamma(37)
    ensures Zeta(37) == 2304 && Gamma(37) == 540
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(37) == 82;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,20) == 3046;
    assert PowMod(17,41) == 3281;
    assert PowMod(17,82) == 2304;
    assert PowMod(17,165) == 540;
  }

  lemma RootEntry38()
    ensures Zetas()[38] == Zeta(38) && Gammas()[38] == Gamma(38)
    ensures Zeta(38) == 2277 && Gamma(38) == 1789
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(38) == 50;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,25) == 756;
    assert PowMod(17,50) == 2277;
    assert PowMod(17,101) == 1789;
  }

  lemma RootEntry39()
    ensures Zetas()[39] == Zeta(39) && Gammas()[39] == Gamma(39)
    ensures Zeta(39) == 2055 && Gamma(39) == 1540
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(39) == 114;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,28) == 2393;
    assert PowMod(17,57) == 3015;
    assert PowMod(17,114) == 2055;
    assert PowMod(17,229) == 1540;
  }

  lemma RootEntry40()
    ensures Zetas()[40] == Zeta(40) && Gammas()[40] == Gamma(40)
    ensures Zeta(40) == 650 && Gamma(40) == 1847
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(40) == 10;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,21) == 1847;
  }

  lemma RootEntry41()
    ensures Zetas()[41] == Zeta(41) && Gammas()[41] == Gamma(41)
    ensures Zeta(41) == 1977 && Gamma(41) == 1482
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(41) == 74;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,18) == 1197;
    assert PowMod(17,37) == 2789;
    assert PowMod(17,74) == 1977;
    assert PowMod(17,149) == 1482;
  }

  lemma RootEntry42()
    ensures Zetas()[42] == Zeta(42) && Gammas()[42] == Gamma(42)
    ensures Zeta(42) == 2513 && Gamma(42) == 952
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(42) == 42;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,21) == 1847;
    assert PowMod(17,42) == 2513;
    assert PowMod(17,85) == 952;
  }

  lemma RootEntry43()
    ensures Zetas()[43] == Zeta(43) && Gammas()[43] == Gamma(43)
    ensures Zeta(43) == 632 && Gamma(43) == 2377
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(43) == 106;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,26) == 2865;
    assert PowMod(17,53) == 1461;
    assert PowMod(17,106) == 632;
    assert PowMod(17,213) == 2377;
  }

  lemma RootEntry44()
    ensures Zetas()[44] == Zeta(44) && Gammas()[44] == Gamma(44)
    ensures Zeta(44) == 2865 && Gamma(44) == 1461
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(44) == 26;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,26) == 2865;
    assert PowMod(17,53) == 1461;
  }

  lemma RootEntry45()
    ensures Zetas()[45] == Zeta(45) && Gammas()[45] == Gamma(45)
    ensures Zeta(45) == 33 && Gamma(45) == 1868
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(45) == 90;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,22) == 1438;
    assert PowMod(17,45) == 2437;
    assert PowMod(17,90) == 33;
    assert PowMod(17,181) == 1868;
  }

  lemma RootEntry46()
    ensures Zetas()[46] == Zeta(46) && Gammas()[46] == Gamma(46)
    ensures Zeta(46) == 1320 && Gamma(46) == 2687
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(46) == 58;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,29) == 733;
    assert PowMod(17,58) == 1320;
    assert PowMod(17,117) == 2687;
  }

  lemma RootEntry47()
    ensures Zetas()[47] == Zeta(47) && Gammas()[47] == Gamma(47)
    ensures Zeta(47) == 1915 && Gamma(47) == 642
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(47) == 122;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,30) == 2474;
    assert PowMod(17,61) == 268;
    assert PowMod(17,122) == 1915;
    assert PowMod(17,245) == 642;
  }

  lemma RootEntry48()
    ensures Zetas()[48] == Zeta(48) && Gammas()[48] == Gamma(48)
    ensures Zeta(48) == 2319 && Gamma(48) == 939
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(48) == 6;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
  }

  lemma RootEntry49()
    ensures Zetas()[49] == Zeta(49) && Gammas()[49] == Gamma(49)
    ensures Zeta(49) == 1435 && Gamma(49) == 2390
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(49) == 70;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,17) == 1637;
    assert PowMod(17,35) == 2037;
    assert PowMod(17,70) == 1435;
    assert PowMod(17,141) == 2390;
  }

  lemma RootEntry50()
    ensures Zetas()[50] == Zeta(50) && Gammas()[50] == Gamma(50)
    ensures Zeta(50) == 807 && Gamma(50) == 2308
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(50) == 38;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,19) == 375;
    assert PowMod(17,38) == 807;
    assert PowMod(17,77) == 2308;
  }

  lemma RootEntry51()
    ensures Zetas()[51] == Zeta(51) && Gammas()[51] == Gamma(51)
    ensures Zeta(51) == 452 && Gamma(51) == 1021
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(51) == 102;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,25) == 756;
    assert PowMod(17,51) == 2090;
    assert PowMod(17,102) == 452;
    assert PowMod(17,205) == 1021;
  }

  lemma RootEntry52()
    ensures Zetas()[52] == Zeta(52) && Gammas()[52] == Gamma(52)
    ensures Zeta(52) == 1438 && Gamma(52) == 2437
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(52) == 22;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,22) == 1438;
    assert PowMod(17,45) == 2437;
  }

  lemma RootEntry53()
    ensures Zetas()[53] == Zeta(53) && Gammas()[53] == Gamma(53)
    ensures Zeta(53) == 2868 && Gamma(53) == 892
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(53) == 86;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,21) == 1847;
    assert PowMod(17,43) == 2773;
    assert PowMod(17,86) == 2868;
    assert PowMod(17,173) == 892;
  }

  lemma RootEntry54()
    ensures Zetas()[54] == Zeta(54) && Gammas()[54] == Gamma(54)
    ensures Zeta(54) == 1534 && Gamma(54) == 2388
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(54) == 54;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,27) == 2099;
    assert PowMod(17,54) == 1534;
    assert PowMod(17,109) == 2388;
  }

  lemma RootEntry55()
    ensures Zetas()[55] == Zeta(55) && Gammas()[55] == Gamma(55)
    ensures Zeta(55) == 2402 && Gamma(55) == 941
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(55) == 118;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,29) == 733;
    assert PowMod(17,59) == 2466;
    assert PowMod(17,118) == 2402;
    assert PowMod(17,237) == 941;
  }

  lemma RootEntry56()
    ensures Zetas()[56] == Zeta(56) && Gammas()[56] == Gamma(56)
    ensures Zeta(56) == 2647 && Gamma(56) == 733
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(56) == 14;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,29) == 733;
  }

  lemma RootEntry57()
    ensures Zetas()[57] == Zeta(57) && Gammas()[57] == Gamma(57)
    ensures Zeta(57) == 2617 && Gamma(57) == 2596
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(57) == 78;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,19) == 375;
    assert PowMod(17,39) == 403;
    assert PowMod(17,78) == 2617;
    assert PowMod(17,157) == 2596;
  }

  lemma RootEntry58()
    ensures Zetas()[58] == Zeta(58) && Gammas()[58] == Gamma(58)
    ensures Zeta(58) == 1481 && Gamma(58) == 2337
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(58) == 46;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,23) == 1143;
    assert PowMod(17,46) == 1481;
    assert PowMod(17,93) == 2337;
  }

  lemma RootEntry59()
    ensures Zetas()[59] == Zeta(59) && Gammas()[59] == Gamma(59)
    ensures Zeta(59) == 648 && Gamma(59) == 992
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(59) == 110;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,27) == 2099;
    assert PowMod(17,55) == 2775;
    assert PowMod(17,110) == 648;
    assert PowMod(17,221) == 992;
  }

  lemma RootEntry60()
    ensures Zetas()[60] == Zeta(60) && Gammas()[60] == Gamma(60)
    ensures Zeta(60) == 2474 && Gamma(60) == 268
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(60) == 30;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,30) == 2474;
    assert PowMod(17,61) == 268;
  }

  lemma RootEntry61()
    ensures Zetas()[61] == Zeta(61) && Gammas()[61] == Gamma(61)
    ensures Zeta(61) == 3110 && Gamma(61) == 3061
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(61) == 94;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,23) == 1143;
    assert PowMod(17,47) == 1874;
    assert PowMod(17,94) == 3110;
    assert PowMod(17,189) == 3061;
  }

  lemma RootEntry62()
    ensures Zetas()[62] == Zeta(62) && Gammas()[62] == Gamma(62)
    ensures Zeta(62) == 1227 && Gamma(62) == 641
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(62) == 62;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,31) == 2110;
    assert PowMod(17,62) == 1227;
    assert PowMod(17,125) == 641;
  }

  lemma RootEntry63()
    ensures Zetas()[63] == Zeta(63) && Gammas()[63] == Gamma(63)
    ensures Zeta(63) == 910 && Gamma(63) == 2688
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(63) == 126;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,31) == 2110;
    assert PowMod(17,63) == 885;
    assert PowMod(17,126) == 910;
    assert PowMod(17,253) == 2688;
  }

  lemma RootEntry64()
    ensures Zetas()[64] == Zeta(64) && Gammas()[64] == Gamma(64)
    ensures Zeta(64) == 17 && Gamma(64) == 1584
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(64) == 1;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
  }

  lemma {:isolate_assertions} RootEntry65()
    ensures Zetas()[65] == Zeta(65) && Gammas()[65] == Gamma(65)
    ensures Zeta(65) == 2761 && Gamma(65) == 1745
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(65) == 65;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,16) == 2642;
    assert PowMod(17,32) == 2580;
    assert PowMod(17,65) == 2761;
    assert PowMod(17,131) == 1745;
  }

  lemma RootEntry66()
    ensures Zetas()[66] == Zeta(66) && Gammas()[66] == Gamma(66)
    ensures Zeta(66) == 583 && Gamma(66) == 2298
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(66) == 33;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,16) == 2642;
    assert PowMod(17,33) == 583;
    assert PowMod(17,67) == 2298;
  }

  lemma RootEntry67()
    ensures Zetas()[67] == Zeta(67) && Gammas()[67] == Gamma(67)
    ensures Zeta(67) == 2649 && Gamma(67) == 1031
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(67) == 97;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,24) == 2786;
    assert PowMod(17,48) == 1897;
    assert PowMod(17,97) == 2649;
    assert PowMod(17,195) == 1031;
  }

  lemma RootEntry68()
    ensures Zetas()[68] == Zeta(68) && Gammas()[68] == Gamma(68)
    ensures Zeta(68) == 1637 && Gamma(68) == 2037
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(68) == 17;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,17) == 1637;
    assert PowMod(17,35) == 2037;
  }

  lemma RootEntry69()
    ensures Zetas()[69] == Zeta(69) && Gammas()[69] == Gamma(69)
    ensures Zeta(69) == 723 && Gamma(69) == 1292
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(69) == 81;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,20) == 3046;
    assert PowMod(17,40) == 193;
    assert PowMod(17,81) == 723;
    assert PowMod(17,163) == 1292;
  }

  lemma RootEntry70()
    ensures Zetas()[70] == Zeta(70) && Gammas()[70] == Gamma(70)
    ensures Zeta(70) == 2288 && Gamma(70) == 3220
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(70) == 49;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,24) == 2786;
    assert PowMod(17,49) == 2288;
    assert PowMod(17,99) == 3220;
  }

  lemma RootEntry71()
    ensures Zetas()[71] == Zeta(71) && Gammas()[71] == Gamma(71)
    ensures Zeta(71) == 1100 && Gamma(71) == 109
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(71) == 113;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,28) == 2393;
    assert PowMod(17,56) == 569;
    assert PowMod(17,113) == 1100;
    assert PowMod(17,227) == 109;
  }

  lemma RootEntry72()
    ensures Zetas()[72] == Zeta(72) && Gammas()[72] == Gamma(72)
    ensures Zeta(72) == 1409 && Gamma(72) == 375
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(72) == 9;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,19) == 375;
  }

  lemma {:isolate_assertions} RootEntry73()
    ensures Zetas()[73] == Zeta(73) && Gammas()[73] == Gamma(73)
    ensures Zeta(73) == 2662 && Gamma(73) == 2954
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(73) == 73;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,18) == 1197;
    assert PowMod(17,36) == 1339;
    assert PowMod(17,73) == 2662;
    assert PowMod(17,147) == 2954;
  }

  lemma RootEntry74()
    ensures Zetas()[74] == Zeta(74) && Gammas()[74] == Gamma(74)
    ensures Zeta(74) == 3281 && Gamma(74) == 2549
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(74) == 41;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,20) == 3046;
    assert PowMod(17,41) == 3281;
    assert PowMod(17,83) == 2549;
  }

  lemma RootEntry75()
    ensures Zetas()[75] == Zeta(75) && Gammas()[75] == Gamma(75)
    ensures Zeta(75) == 233 && Gamma(75) == 780
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(75) == 105;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,26) == 2865;
    assert PowMod(17,52) == 2240;
    assert PowMod(17,105) == 233;
    assert PowMod(17,211) == 780;
  }

  lemma RootEntry76()
    ensures Zetas()[76] == Zeta(76) && Gammas()[76] == Gamma(76)
    ensures Zeta(76) == 756 && Gamma(76) == 2090
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(76) == 25;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,25) == 756;
    assert PowMod(17,51) == 2090;
  }

  lemma RootEntry77()
    ensures Zetas()[77] == Zeta(77) && Gammas()[77] == Gamma(77)
    ensures Zeta(77) == 2156 && Gamma(77) == 1239
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(77) == 89;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,22) == 1438;
    assert PowMod(17,44) == 535;
    assert PowMod(17,89) == 2156;
    assert PowMod(17,179) == 1239;
  }

  lemma RootEntry78()
    ensures Zetas()[78] == Zeta(78) && Gammas()[78] == Gamma(78)
    ensures Zeta(78) == 3015 && Gamma(78) == 1645
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(78) == 57;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,28) == 2393;
    assert PowMod(17,57) == 3015;
    assert PowMod(17,115) == 1645;
  }

  lemma RootEntry79()
    ensures Zetas()[79] == Zeta(79) && Gammas()[79] == Gamma(79)
    ensures Zeta(79) == 3050 && Gamma(79) == 1684
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(79) == 121;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,30) == 2474;
    assert PowMod(17,60) == 1974;
    assert PowMod(17,121) == 3050;
    assert PowMod(17,243) == 1684;
  }

  lemma RootEntry80()
    ensures Zetas()[80] == Zeta(80) && Gammas()[80] == Gamma(80)
    ensures Zeta(80) == 1703 && Gamma(80) == 1063
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(80) == 5;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
  }

  lemma RootEntry81()
    ensures Zetas()[81] == Zeta(81) && Gammas()[81] == Gamma(81)
    ensures Zeta(81) == 1651 && Gamma(81) == 2266
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(81) == 69;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,17) == 1637;
    assert PowMod(17,34) == 3253;
    assert PowMod(17,69) == 1651;
    assert PowMod(17,139) == 2266;
  }

  lemma RootEntry82()
    ensures Zetas()[82] == Zeta(82) && Gammas()[82] == Gamma(82)
    ensures Zeta(82) == 2789 && Gamma(82) == 319
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(82) == 37;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,18) == 1197;
    assert PowMod(17,37) == 2789;
    assert PowMod(17,75) == 319;
  }

  lemma RootEntry83()
    ensures Zetas()[83] == Zeta(83) && Gammas()[83] == Gamma(83)
    ensures Zeta(83) == 1789 && Gamma(83) == 3010
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(83) == 101;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,25) == 756;
    assert PowMod(17,50) == 2277;
    assert PowMod(17,101) == 1789;
    assert PowMod(17,203) == 3010;
  }

  lemma RootEntry84()
    ensures Zetas()[84] == Zeta(84) && Gammas()[84] == Gamma(84)
    ensures Zeta(84) == 1847 && Gamma(84) == 2773
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(84) == 21;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,21) == 1847;
    assert PowMod(17,43) == 2773;
  }

  lemma {:isolate_assertions} RootEntry85()
    ensures Zetas()[85] == Zeta(85) && Gammas()[85] == Gamma(85)
    ensures Zeta(85) == 952 && Gamma(85) == 556
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(85) == 85;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,21) == 1847;
    assert PowMod(17,42) == 2513;
    assert PowMod(17,85) == 952;
    assert PowMod(17,171) == 556;
  }

  lemma RootEntry86()
    ensures Zetas()[86] == Zeta(86) && Gammas()[86] == Gamma(86)
    ensures Zeta(86) == 1461 && Gamma(86) == 757
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(86) == 53;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,26) == 2865;
    assert PowMod(17,53) == 1461;
    assert PowMod(17,107) == 757;
  }

  lemma RootEntry87()
    ensures Zetas()[87] == Zeta(87) && Gammas()[87] == Gamma(87)
    ensures Zeta(87) == 2687 && Gamma(87) == 2572
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(87) == 117;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,29) == 733;
    assert PowMod(17,58) == 1320;
    assert PowMod(17,117) == 2687;
    assert PowMod(17,235) == 2572;
  }

  lemma RootEntry88()
    ensures Zetas()[88] == Zeta(88) && Gammas()[88] == Gamma(88)
    ensures Zeta(88) == 939 && Gamma(88) == 2099
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(88) == 13;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,27) == 2099;
  }

  lemma RootEntry89()
    ensures Zetas()[89] == Zeta(89) && Gammas()[89] == Gamma(89)
    ensures Zeta(89) == 2308 && Gamma(89) == 1230
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(89) == 77;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,19) == 375;
    assert PowMod(17,38) == 807;
    assert PowMod(17,77) == 2308;
    assert PowMod(17,155) == 1230;
  }

  lemma RootEntry90()
    ensures Zetas()[90] == Zeta(90) && Gammas()[90] == Gamma(90)
    ensures Zeta(90) == 2437 && Gamma(90) == 561
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(90) == 45;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,22) == 1438;
    assert PowMod(17,45) == 2437;
    assert PowMod(17,91) == 561;
  }

  lemma RootEntry91()
    ensures Zetas()[91] == Zeta(91) && Gammas()[91] == Gamma(91)
    ensures Zeta(91) == 2388 && Gamma(91) == 2768
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(91) == 109;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,27) == 2099;
    assert PowMod(17,54) == 1534;
    assert PowMod(17,109) == 2388;
    assert PowMod(17,219) == 2768;
  }

  lemma RootEntry92()
    ensures Zetas()[92] == Zeta(92) && Gammas()[92] == Gamma(92)
    ensures Zeta(92) == 733 && Gamma(92) == 2466
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(92) == 29;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,29) == 733;
    assert PowMod(17,59) == 2466;
  }

  lemma {:isolate_assertions} RootEntry93()
    ensures Zetas()[93] == Zeta(93) && Gammas()[93] == Gamma(93)
    ensures Zeta(93) == 2337 && Gamma(93) == 863
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(93) == 93;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,23) == 1143;
    assert PowMod(17,46) == 1481;
    assert PowMod(17,93) == 2337;
    assert PowMod(17,187) == 863;
  }

  lemma RootEntry94()
    ensures Zetas()[94] == Zeta(94) && Gammas()[94] == Gamma(94)
    ensures Zeta(94) == 268 && Gamma(94) == 2594
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(94) == 61;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,30) == 2474;
    assert PowMod(17,61) == 268;
    assert PowMod(17,123) == 2594;
  }

  lemma RootEntry95()
    ensures Zetas()[95] == Zeta(95) && Gammas()[95] == Gamma(95)
    ensures Zeta(95) == 641 && Gamma(95) == 735
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(95) == 125;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,31) == 2110;
    assert PowMod(17,62) == 1227;
    assert PowMod(17,125) == 641;
    assert PowMod(17,251) == 735;
  }

  lemma RootEntry96()
    ensures Zetas()[96] == Zeta(96) && Gammas()[96] == Gamma(96)
    ensures Zeta(96) == 1584 && Gamma(96) == 2804
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(96) == 3;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
  }

  lemma RootEntry97()
    ensures Zetas()[97] == Zeta(97) && Gammas()[97] == Gamma(97)
    ensures Zeta(97) == 2298 && Gamma(97) == 525
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(97) == 67;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,16) == 2642;
    assert PowMod(17,33) == 583;
    assert PowMod(17,67) == 2298;
    assert PowMod(17,135) == 525;
  }

  lemma RootEntry98()
    ensures Zetas()[98] == Zeta(98) && Gammas()[98] == Gamma(98)
    ensures Zeta(98) == 2037 && Gamma(98) == 1092
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(98) == 35;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,17) == 1637;
    assert PowMod(17,35) == 2037;
    assert PowMod(17,71) == 1092;
  }

  lemma RootEntry99()
    ensures Zetas()[99] == Zeta(99) && Gammas()[99] == Gamma(99)
    ensures Zeta(99) == 3220 && Gamma(99) == 2237
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(99) == 99;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,24) == 2786;
    assert PowMod(17,49) == 2288;
    assert PowMod(17,99) == 3220;
    assert PowMod(17,199) == 2237;
  }

  lemma RootEntry100()
    ensures Zetas()[100] == Zeta(100) && Gammas()[100] == Gamma(100)
    ensures Zeta(100) == 375 && Gamma(100) == 403
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(100) == 19;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,19) == 375;
    assert PowMod(17,39) == 403;
  }

  lemma RootEntry101()
    ensures Zetas()[101] == Zeta(101) && Gammas()[101] == Gamma(101)
    ensures Zeta(101) == 2549 && Gamma(101) == 2926
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(101) == 83;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,20) == 3046;
    assert PowMod(17,41) == 3281;
    assert PowMod(17,83) == 2549;
    assert PowMod(17,167) == 2926;
  }

  lemma RootEntry102()
    ensures Zetas()[102] == Zeta(102) && Gammas()[102] == Gamma(102)
    ensures Zeta(102) == 2090 && Gamma(102) == 1026
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(102) == 51;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,25) == 756;
    assert PowMod(17,51) == 2090;
    assert PowMod(17,103) == 1026;
  }

  lemma RootEntry103()
    ensures Zetas()[103] == Zeta(103) && Gammas()[103] == Gamma(103)
    ensures Zeta(103) == 1645 && Gamma(103) == 2303
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(103) == 115;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,28) == 2393;
    assert PowMod(17,57) == 3015;
    assert PowMod(17,115) == 1645;
    assert PowMod(17,231) == 2303;
  }

  lemma RootEntry104()
    ensures Zetas()[104] == Zeta(104) && Gammas()[104] == Gamma(104)
    ensures Zeta(104) == 1063 && Gamma(104) == 1143
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(104) == 11;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,23) == 1143;
  }

  lemma RootEntry105()
    ensures Zetas()[105] == Zeta(105) && Gammas()[105] == Gamma(105)
    ensures Zeta(105) == 319 && Gamma(105) == 2186
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(105) == 75;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,18) == 1197;
    assert PowMod(17,37) == 2789;
    assert PowMod(17,75) == 319;
    assert PowMod(17,151) == 2186;
  }

  lemma RootEntry106()
    ensures Zetas()[106] == Zeta(106) && Gammas()[106] == Gamma(106)
    ensures Zeta(106) == 2773 && Gamma(106) == 2150
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(106) == 43;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,21) == 1847;
    assert PowMod(17,43) == 2773;
    assert PowMod(17,87) == 2150;
  }

  lemma RootEntry107()
    ensures Zetas()[107] == Zeta(107) && Gammas()[107] == Gamma(107)
    ensures Zeta(107) == 757 && Gamma(107) == 1179
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(107) == 107;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,26) == 2865;
    assert PowMod(17,53) == 1461;
    assert PowMod(17,107) == 757;
    assert PowMod(17,215) == 1179;
  }

  lemma RootEntry108()
    ensures Zetas()[108] == Zeta(108) && Gammas()[108] == Gamma(108)
    ensures Zeta(108) == 2099 && Gamma(108) == 2775
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(108) == 27;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,27) == 2099;
    assert PowMod(17,55) == 2775;
  }

  lemma RootEntry109()
    ensures Zetas()[109] == Zeta(109) && Gammas()[109] == Gamma(109)
    ensures Zeta(109) == 561 && Gamma(109) == 554
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(109) == 91;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,22) == 1438;
    assert PowMod(17,45) == 2437;
    assert PowMod(17,91) == 561;
    assert PowMod(17,183) == 554;
  }

  lemma RootEntry110()
    ensures Zetas()[110] == Zeta(110) && Gammas()[110] == Gamma(110)
    ensures Zeta(110) == 2466 && Gamma(110) == 886
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(110) == 59;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,29) == 733;
    assert PowMod(17,59) == 2466;
    assert PowMod(17,119) == 886;
  }

  lemma RootEntry111()
    ensures Zetas()[111] == Zeta(111) && Gammas()[111] == Gamma(111)
    ensures Zeta(111) == 2594 && Gamma(111) == 2443
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(111) == 123;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,30) == 2474;
    assert PowMod(17,61) == 268;
    assert PowMod(17,123) == 2594;
    assert PowMod(17,247) == 2443;
  }

  lemma RootEntry112()
    ensures Zetas()[112] == Zeta(112) && Gammas()[112] == Gamma(112)
    ensures Zeta(112) == 2804 && Gamma(112) == 1722
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(112) == 7;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
  }

  lemma RootEntry113()
    ensures Zetas()[113] == Zeta(113) && Gammas()[113] == Gamma(113)
    ensures Zeta(113) == 1092 && Gamma(113) == 1607
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(113) == 71;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,8) == 1062;
    assert PowMod(17,17) == 1637;
    assert PowMod(17,35) == 2037;
    assert PowMod(17,71) == 1092;
    assert PowMod(17,143) == 1607;
  }

  lemma RootEntry114()
    ensures Zetas()[114] == Zeta(114) && Gammas()[114] == Gamma(114)
    ensures Zeta(114) == 403 && Gamma(114) == 1212
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(114) == 39;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,19) == 375;
    assert PowMod(17,39) == 403;
    assert PowMod(17,79) == 1212;
  }

  lemma RootEntry115()
    ensures Zetas()[115] == Zeta(115) && Gammas()[115] == Gamma(115)
    ensures Zeta(115) == 1026 && Gamma(115) == 2117
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(115) == 103;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,12) == 1426;
    assert PowMod(17,25) == 756;
    assert PowMod(17,51) == 2090;
    assert PowMod(17,103) == 1026;
    assert PowMod(17,207) == 2117;
  }

  lemma RootEntry116()
    ensures Zetas()[116] == Zeta(116) && Gammas()[116] == Gamma(116)
    ensures Zeta(116) == 1143 && Gamma(116) == 1874
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(116) == 23;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,23) == 1143;
    assert PowMod(17,47) == 1874;
  }

  lemma RootEntry117()
    ensures Zetas()[117] == Zeta(117) && Gammas()[117] == Gamma(117)
    ensures Zeta(117) == 2150 && Gamma(117) == 1455
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(117) == 87;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,10) == 650;
    assert PowMod(17,21) == 1847;
    assert PowMod(17,43) == 2773;
    assert PowMod(17,87) == 2150;
    assert PowMod(17,175) == 1455;
  }

  lemma RootEntry118()
    ensures Zetas()[118] == Zeta(118) && Gammas()[118] == Gamma(118)
    ensures Zeta(118) == 2775 && Gamma(118) == 1029
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(118) == 55;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,27) == 2099;
    assert PowMod(17,55) == 2775;
    assert PowMod(17,111) == 1029;
  }

  lemma RootEntry119()
    ensures Zetas()[119] == Zeta(119) && Gammas()[119] == Gamma(119)
    ensures Zeta(119) == 886 && Gamma(119) == 2300
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(119) == 119;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,14) == 2647;
    assert PowMod(17,29) == 733;
    assert PowMod(17,59) == 2466;
    assert PowMod(17,119) == 886;
    assert PowMod(17,239) == 2300;
  }

  lemma RootEntry120()
    ensures Zetas()[120] == Zeta(120) && Gammas()[120] == Gamma(120)
    ensures Zeta(120) == 1722 && Gamma(120) == 2110
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(120) == 15;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,31) == 2110;
  }

  lemma RootEntry121()
    ensures Zetas()[121] == Zeta(121) && Gammas()[121] == Gamma(121)
    ensures Zeta(121) == 1212 && Gamma(121) == 1219
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(121) == 79;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,4) == 296;
    assert PowMod(17,9) == 1409;
    assert PowMod(17,19) == 375;
    assert PowMod(17,39) == 403;
    assert PowMod(17,79) == 1212;
    assert PowMod(17,159) == 1219;
  }

  lemma RootEntry122()
    ensures Zetas()[122] == Zeta(122) && Gammas()[122] == Gamma(122)
    ensures Zeta(122) == 1874 && Gamma(122) == 2935
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(122) == 47;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,23) == 1143;
    assert PowMod(17,47) == 1874;
    assert PowMod(17,95) == 2935;
  }

  lemma RootEntry123()
    ensures Zetas()[123] == Zeta(123) && Gammas()[123] == Gamma(123)
    ensures Zeta(123) == 1029 && Gamma(123) == 394
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(123) == 111;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,6) == 2319;
    assert PowMod(17,13) == 939;
    assert PowMod(17,27) == 2099;
    assert PowMod(17,55) == 2775;
    assert PowMod(17,111) == 1029;
    assert PowMod(17,223) == 394;
  }

  lemma RootEntry124()
    ensures Zetas()[124] == Zeta(124) && Gammas()[124] == Gamma(124)
    ensures Zeta(124) == 2110 && Gamma(124) == 885
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(124) == 31;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,31) == 2110;
    assert PowMod(17,63) == 885;
  }

  lemma RootEntry125()
    ensures Zetas()[125] == Zeta(125) && Gammas()[125] == Gamma(125)
    ensures Zeta(125) == 2935 && Gamma(125) == 2444
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(125) == 95;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,2) == 289;
    assert PowMod(17,5) == 1703;
    assert PowMod(17,11) == 1063;
    assert PowMod(17,23) == 1143;
    assert PowMod(17,47) == 1874;
    assert PowMod(17,95) == 2935;
    assert PowMod(17,191) == 2444;
  }

  lemma RootEntry126()
    ensures Zetas()[126] == Zeta(126) && Gammas()[126] == Gamma(126)
    ensures Zeta(126) == 885 && Gamma(126) == 2154
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(126) == 63;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,31) == 2110;
    assert PowMod(17,63) == 885;
    assert PowMod(17,127) == 2154;
  }

  lemma RootEntry127()
    ensures Zetas()[127] == Zeta(127) && Gammas()[127] == Gamma(127)
    ensures Zeta(127) == 2154 && Gamma(127) == 1175
  {
    reveal PowMod(), Zeta(), Gamma(), Zetas(), Gammas();
    assert BitRev7(127) == 127;
    assert PowMod(17,0) == 1;
    assert PowMod(17,1) == 17;
    assert PowMod(17,3) == 1584;
    assert PowMod(17,7) == 2804;
    assert PowMod(17,15) == 1722;
    assert PowMod(17,31) == 2110;
    assert PowMod(17,63) == 885;
    assert PowMod(17,127) == 2154;
    assert PowMod(17,255) == 1175;
  }

  function Len(s: nat): int
    requires s < 7
    ensures 2 <= Len(s) <= 128
    ensures 256 % (2*Len(s)) == 0
  { [128, 64, 32, 16, 8, 4, 2][s] }

  lemma StageBounds(s: nat, i: nat)
    requires s < 7 && i < 256
    ensures 0 <= 128/Len(s)+i/(2*Len(s)) < 128
    ensures 0 <= 256/Len(s)-1-i/(2*Len(s)) < 128
    ensures i%(2*Len(s)) < Len(s) ==> i+Len(s) < 256
    ensures i%(2*Len(s)) >= Len(s) ==> 0 <= i-Len(s)
  {
    if s == 0 {} else if s == 1 {} else if s == 2 {} else if s == 3 {}
    else if s == 4 {} else if s == 5 {} else {}
  }

  lemma InverseRoots(s: nat, b: nat)
    requires s < 7 && b < 128/Len(s)
    ensures (Zeta(128/Len(s)+b)*Zeta(256/Len(s)-1-b))%Q == Q-1
  {
    if s == 0 {
      if b == 0 { RootEntry1(); RootEntry1(); }
    }
    else if s == 1 {
      if b == 0 { RootEntry2(); RootEntry3(); }
      else if b == 1 { RootEntry3(); RootEntry2(); }
    }
    else if s == 2 {
      if b == 0 { RootEntry4(); RootEntry7(); }
      else if b == 1 { RootEntry5(); RootEntry6(); }
      else if b == 2 { RootEntry6(); RootEntry5(); }
      else if b == 3 { RootEntry7(); RootEntry4(); }
    }
    else if s == 3 {
      if b == 0 { RootEntry8(); RootEntry15(); }
      else if b == 1 { RootEntry9(); RootEntry14(); }
      else if b == 2 { RootEntry10(); RootEntry13(); }
      else if b == 3 { RootEntry11(); RootEntry12(); }
      else if b == 4 { RootEntry12(); RootEntry11(); }
      else if b == 5 { RootEntry13(); RootEntry10(); }
      else if b == 6 { RootEntry14(); RootEntry9(); }
      else if b == 7 { RootEntry15(); RootEntry8(); }
    }
    else if s == 4 {
      if b == 0 { RootEntry16(); RootEntry31(); }
      else if b == 1 { RootEntry17(); RootEntry30(); }
      else if b == 2 { RootEntry18(); RootEntry29(); }
      else if b == 3 { RootEntry19(); RootEntry28(); }
      else if b == 4 { RootEntry20(); RootEntry27(); }
      else if b == 5 { RootEntry21(); RootEntry26(); }
      else if b == 6 { RootEntry22(); RootEntry25(); }
      else if b == 7 { RootEntry23(); RootEntry24(); }
      else if b == 8 { RootEntry24(); RootEntry23(); }
      else if b == 9 { RootEntry25(); RootEntry22(); }
      else if b == 10 { RootEntry26(); RootEntry21(); }
      else if b == 11 { RootEntry27(); RootEntry20(); }
      else if b == 12 { RootEntry28(); RootEntry19(); }
      else if b == 13 { RootEntry29(); RootEntry18(); }
      else if b == 14 { RootEntry30(); RootEntry17(); }
      else if b == 15 { RootEntry31(); RootEntry16(); }
    }
    else if s == 5 {
      if b == 0 { RootEntry32(); RootEntry63(); }
      else if b == 1 { RootEntry33(); RootEntry62(); }
      else if b == 2 { RootEntry34(); RootEntry61(); }
      else if b == 3 { RootEntry35(); RootEntry60(); }
      else if b == 4 { RootEntry36(); RootEntry59(); }
      else if b == 5 { RootEntry37(); RootEntry58(); }
      else if b == 6 { RootEntry38(); RootEntry57(); }
      else if b == 7 { RootEntry39(); RootEntry56(); }
      else if b == 8 { RootEntry40(); RootEntry55(); }
      else if b == 9 { RootEntry41(); RootEntry54(); }
      else if b == 10 { RootEntry42(); RootEntry53(); }
      else if b == 11 { RootEntry43(); RootEntry52(); }
      else if b == 12 { RootEntry44(); RootEntry51(); }
      else if b == 13 { RootEntry45(); RootEntry50(); }
      else if b == 14 { RootEntry46(); RootEntry49(); }
      else if b == 15 { RootEntry47(); RootEntry48(); }
      else if b == 16 { RootEntry48(); RootEntry47(); }
      else if b == 17 { RootEntry49(); RootEntry46(); }
      else if b == 18 { RootEntry50(); RootEntry45(); }
      else if b == 19 { RootEntry51(); RootEntry44(); }
      else if b == 20 { RootEntry52(); RootEntry43(); }
      else if b == 21 { RootEntry53(); RootEntry42(); }
      else if b == 22 { RootEntry54(); RootEntry41(); }
      else if b == 23 { RootEntry55(); RootEntry40(); }
      else if b == 24 { RootEntry56(); RootEntry39(); }
      else if b == 25 { RootEntry57(); RootEntry38(); }
      else if b == 26 { RootEntry58(); RootEntry37(); }
      else if b == 27 { RootEntry59(); RootEntry36(); }
      else if b == 28 { RootEntry60(); RootEntry35(); }
      else if b == 29 { RootEntry61(); RootEntry34(); }
      else if b == 30 { RootEntry62(); RootEntry33(); }
      else if b == 31 { RootEntry63(); RootEntry32(); }
    }
    else if s == 6 {
      if b == 0 { RootEntry64(); RootEntry127(); }
      else if b == 1 { RootEntry65(); RootEntry126(); }
      else if b == 2 { RootEntry66(); RootEntry125(); }
      else if b == 3 { RootEntry67(); RootEntry124(); }
      else if b == 4 { RootEntry68(); RootEntry123(); }
      else if b == 5 { RootEntry69(); RootEntry122(); }
      else if b == 6 { RootEntry70(); RootEntry121(); }
      else if b == 7 { RootEntry71(); RootEntry120(); }
      else if b == 8 { RootEntry72(); RootEntry119(); }
      else if b == 9 { RootEntry73(); RootEntry118(); }
      else if b == 10 { RootEntry74(); RootEntry117(); }
      else if b == 11 { RootEntry75(); RootEntry116(); }
      else if b == 12 { RootEntry76(); RootEntry115(); }
      else if b == 13 { RootEntry77(); RootEntry114(); }
      else if b == 14 { RootEntry78(); RootEntry113(); }
      else if b == 15 { RootEntry79(); RootEntry112(); }
      else if b == 16 { RootEntry80(); RootEntry111(); }
      else if b == 17 { RootEntry81(); RootEntry110(); }
      else if b == 18 { RootEntry82(); RootEntry109(); }
      else if b == 19 { RootEntry83(); RootEntry108(); }
      else if b == 20 { RootEntry84(); RootEntry107(); }
      else if b == 21 { RootEntry85(); RootEntry106(); }
      else if b == 22 { RootEntry86(); RootEntry105(); }
      else if b == 23 { RootEntry87(); RootEntry104(); }
      else if b == 24 { RootEntry88(); RootEntry103(); }
      else if b == 25 { RootEntry89(); RootEntry102(); }
      else if b == 26 { RootEntry90(); RootEntry101(); }
      else if b == 27 { RootEntry91(); RootEntry100(); }
      else if b == 28 { RootEntry92(); RootEntry99(); }
      else if b == 29 { RootEntry93(); RootEntry98(); }
      else if b == 30 { RootEntry94(); RootEntry97(); }
      else if b == 31 { RootEntry95(); RootEntry96(); }
      else if b == 32 { RootEntry96(); RootEntry95(); }
      else if b == 33 { RootEntry97(); RootEntry94(); }
      else if b == 34 { RootEntry98(); RootEntry93(); }
      else if b == 35 { RootEntry99(); RootEntry92(); }
      else if b == 36 { RootEntry100(); RootEntry91(); }
      else if b == 37 { RootEntry101(); RootEntry90(); }
      else if b == 38 { RootEntry102(); RootEntry89(); }
      else if b == 39 { RootEntry103(); RootEntry88(); }
      else if b == 40 { RootEntry104(); RootEntry87(); }
      else if b == 41 { RootEntry105(); RootEntry86(); }
      else if b == 42 { RootEntry106(); RootEntry85(); }
      else if b == 43 { RootEntry107(); RootEntry84(); }
      else if b == 44 { RootEntry108(); RootEntry83(); }
      else if b == 45 { RootEntry109(); RootEntry82(); }
      else if b == 46 { RootEntry110(); RootEntry81(); }
      else if b == 47 { RootEntry111(); RootEntry80(); }
      else if b == 48 { RootEntry112(); RootEntry79(); }
      else if b == 49 { RootEntry113(); RootEntry78(); }
      else if b == 50 { RootEntry114(); RootEntry77(); }
      else if b == 51 { RootEntry115(); RootEntry76(); }
      else if b == 52 { RootEntry116(); RootEntry75(); }
      else if b == 53 { RootEntry117(); RootEntry74(); }
      else if b == 54 { RootEntry118(); RootEntry73(); }
      else if b == 55 { RootEntry119(); RootEntry72(); }
      else if b == 56 { RootEntry120(); RootEntry71(); }
      else if b == 57 { RootEntry121(); RootEntry70(); }
      else if b == 58 { RootEntry122(); RootEntry69(); }
      else if b == 59 { RootEntry123(); RootEntry68(); }
      else if b == 60 { RootEntry124(); RootEntry67(); }
      else if b == 61 { RootEntry125(); RootEntry66(); }
      else if b == 62 { RootEntry126(); RootEntry65(); }
      else if b == 63 { RootEntry127(); RootEntry64(); }
    }
  }

  lemma StagePartner(s: nat, i: nat)
    requires s < 7 && i < 256
    ensures i%(2*Len(s)) < Len(s) ==>
      (i+Len(s))/(2*Len(s)) == i/(2*Len(s)) &&
      (i+Len(s))%(2*Len(s)) >= Len(s)
    ensures i%(2*Len(s)) >= Len(s) ==>
      (i-Len(s))/(2*Len(s)) == i/(2*Len(s)) &&
      (i-Len(s))%(2*Len(s)) < Len(s)
  {
    if s == 0 {} else if s == 1 {} else if s == 2 {} else if s == 3 {}
    else if s == 4 {} else if s == 5 {} else {}
  }

  // Coefficient-level equations describe an entire simultaneous stage. They do
  // not execute or model the in-place update loop used by VerifiedPolynomial.
  ghost function ForwardLane(f: seq<int>, s: nat, i: nat): int
    requires Canonical(f) && s < 7 && i < N
    ensures 0 <= ForwardLane(f, s, i) < Q
  {
    StageBounds(s, i);
    var l := Len(s);
    var z := Zeta(128/l + i/(2*l));
    if i%(2*l) < l then (f[i]+z*f[i+l])%Q
    else (f[i-l]-z*f[i])%Q
  }

  ghost function ForwardStage(f: seq<int>, s: nat): seq<int>
    requires Canonical(f) && s < 7
    ensures Canonical(ForwardStage(f, s))
  { seq(N, i requires 0 <= i < N => ForwardLane(f, s, i)) }

  ghost function {:opaque} NttPrefix(f: seq<int>, stages: nat): seq<int>
    requires Canonical(f) && stages <= 7
    ensures Canonical(NttPrefix(f, stages))
    decreases stages
  { if stages == 0 then f else ForwardStage(NttPrefix(f, stages-1), stages-1) }

  lemma NttPrefixZero(f: seq<int>)
    requires Canonical(f)
    ensures NttPrefix(f,0) == f
  { reveal NttPrefix(); }

  lemma NttPrefixStep(f: seq<int>, s: nat)
    requires Canonical(f) && s < 7
    ensures NttPrefix(f,s+1) == ForwardStage(NttPrefix(f,s),s)
  { reveal NttPrefix(); }

  ghost function Ntt(f: seq<int>): seq<int>
    requires Canonical(f) ensures Canonical(Ntt(f))
  { NttPrefix(f, 7) }

  ghost function InverseLane(f: seq<int>, s: nat, i: nat): int
    requires Canonical(f) && s < 7 && i < N
    ensures 0 <= InverseLane(f, s, i) < Q
  {
    StageBounds(6-s, i);
    var l := Len(6-s);
    var z := Zeta(256/l-1-i/(2*l));
    if i%(2*l) < l then (f[i]+f[i+l])%Q
    else (z*(f[i]-f[i-l]))%Q
  }

  ghost function InverseStage(f: seq<int>, s: nat): seq<int>
    requires Canonical(f) && s < 7
    ensures Canonical(InverseStage(f, s))
  { seq(N, i requires 0 <= i < N => InverseLane(f, s, i)) }

  ghost function InversePrefix(f: seq<int>, stages: nat): seq<int>
    requires Canonical(f) && stages <= 7
    ensures Canonical(InversePrefix(f, stages))
    decreases stages
  { if stages == 0 then f else InverseStage(InversePrefix(f, stages-1), stages-1) }

  ghost function Scale(f: seq<int>, a: int): seq<int>
    requires Canonical(f) ensures Canonical(Scale(f,a))
  { seq(N, i requires 0 <= i < N => (a*f[i])%Q) }

  ghost function InverseNtt(f: seq<int>): seq<int>
    requires Canonical(f) ensures Canonical(InverseNtt(f))
  { Scale(InversePrefix(f, 7), 3303) }

  ghost function NttMul(f: seq<int>, g: seq<int>): seq<int>
    requires Canonical(f) && Canonical(g)
    ensures Canonical(NttMul(f,g))
  {
    seq(N, i requires 0 <= i < N =>
      if i%2 == 0 then (f[i]*g[i]+f[i+1]*g[i+1]*Gamma(i/2))%Q
      else (f[i-1]*g[i]+f[i]*g[i-1])%Q)
  }

  // The independent mathematical representation, FIPS 203 equations 4.12/4.13:
  // remainder modulo X^2-gamma, separated into its even and odd coefficients.
  ghost function Remainder(f: seq<int>, gamma: int, parity: nat, terms: nat): int
    requires Canonical(f) && parity < 2 && terms <= 128
    ensures 0 <= Remainder(f,gamma,parity,terms) < Q
    decreases terms
  {
    if terms == 0 then 0 else
      (Remainder(f,gamma,parity,terms-1)+f[2*(terms-1)+parity]*PowMod(gamma,terms-1))%Q
  }

  ghost function Representation(f: seq<int>): seq<int>
    requires Canonical(f) ensures Canonical(Representation(f))
  { seq(N, i requires 0 <= i < N => Remainder(f,Gamma(i/2),i%2,128)) }  lemma ModProduct(a: int, b: int)
    ensures ((a%Q)*b)%Q == (a*b)%Q
  {
    assert a == (a/Q)*Q+a%Q;
    assert a*b == (a/Q)*b*Q+(a%Q)*b;
  }

  lemma ModSum(a: int, b: int)
    ensures (a%Q+b%Q)%Q == (a+b)%Q
    ensures (a%Q-b%Q)%Q == (a-b)%Q
  {}

  lemma ButterflyUndo(a: int, b: int, z: int, w: int)
    requires (z*w)%Q == Q-1
    ensures ((a+z*b)%Q+(a-z*b)%Q)%Q == (2*a)%Q
    ensures (w*((a-z*b)%Q-(a+z*b)%Q))%Q == (2*b)%Q
  {
    ModSum(a+z*b,a-z*b);
    ModSum(a-z*b,a+z*b);
    ModProduct((a-z*b)%Q-(a+z*b)%Q,w);
    ModProduct(-2*z*b,w);
    ModProduct(z*w,-2*b);
    assert w*(-2*z*b) == (z*w)*(-2*b);
    assert ((Q-1)*(-2*b))%Q == (2*b)%Q;
  }

  lemma StageUndo(f: seq<int>, s: nat)
    requires Canonical(f) && s < 7
    ensures InverseStage(ForwardStage(f,s),6-s) == Scale(f,2)
  {
    var l := Len(s);
    var h := ForwardStage(f,s);
    forall i | 0 <= i < 256
      ensures InverseStage(h,6-s)[i] == Scale(f,2)[i]
    {
      StageBounds(s,i);
      StagePartner(s,i);
      var b := i/(2*l);
      assert b < 128/l;
      InverseRoots(s,b);
      var z := Zeta(128/l+b);
      var w := Zeta(256/l-1-b);
      if i%(2*l) < l {
        ButterflyUndo(f[i],f[i+l],z,w);
      } else {
        ButterflyUndo(f[i-l],f[i],z,w);
      }
    }
  }

  lemma {:isolate_assertions} ScaleButterfly(a: int, b: int, z: int, c: int)
    ensures (((c*a)%Q+(c*b)%Q)%Q) == (c*((a+b)%Q))%Q
    ensures (z*((c*b)%Q-(c*a)%Q))%Q == (c*((z*(b-a))%Q))%Q
  {
    ModSum(c*a,c*b);
    ModProduct(a+b,c);
    var d := (c*b)%Q-(c*a)%Q;
    ModSum(c*b,c*a);
    assert d%Q == (c*(b-a))%Q;
    ModProduct(d,z);
    assert (z*d)%Q == (z*(d%Q))%Q;
    ModProduct(c*(b-a),z);
    assert (z*(d%Q))%Q == (z*c*(b-a))%Q;
    ModProduct(z*(b-a),c);
    assert z*c*(b-a) == c*(z*(b-a));
    assert (c*((z*(b-a))%Q))%Q == (z*c*(b-a))%Q;
  }

  lemma ScaleStage(f: seq<int>, s: nat, c: int)
    requires Canonical(f) && s < 7
    ensures InverseStage(Scale(f,c),s) == Scale(InverseStage(f,s),c)
  {
    var l := Len(6-s);
    forall i | 0 <= i < 256
      ensures InverseStage(Scale(f,c),s)[i] == Scale(InverseStage(f,s),c)[i]
    {
      StageBounds(6-s,i);
      var z := Zeta(256/l-1-i/(2*l));
      if i%(2*l) < l { ScaleButterfly(f[i],f[i+l],z,c); }
      else { ScaleButterfly(f[i-l],f[i],z,c); }
    }
  }

  lemma ScaleCompose(f: seq<int>, a: int, b: int)
    requires Canonical(f)
    ensures Scale(Scale(f,a),b) == Scale(f,a*b)
  {
    forall i | 0 <= i < 256
      ensures Scale(Scale(f,a),b)[i] == Scale(f,a*b)[i]
    { ModProduct(a*f[i],b); }
  }

  lemma ScaleIdentity(f: seq<int>, a: int)
    requires Canonical(f) && a%Q == 1
    ensures Scale(f,a) == f
  {
    forall i | 0 <= i < 256
      ensures Scale(f,a)[i] == f[i]
    { ModProduct(a,f[i]); }
  }

  function Factor(k: nat): int
    requires k <= 7
    ensures 1 <= Factor(k) <= 128
  { [1,2,4,8,16,32,64,128][k] }

  lemma FactorStep(k: nat)
    requires k < 7
    ensures 2*Factor(k) == Factor(k+1)
  {
    if k == 0 {} else if k == 1 {} else if k == 2 {} else if k == 3 {}
    else if k == 4 {} else if k == 5 {} else {}
  }

  lemma PrefixUndo(f: seq<int>, k: nat)
    requires Canonical(f) && k <= 7
    ensures InversePrefix(Ntt(f),k) == Scale(NttPrefix(f,7-k),Factor(k))
    decreases k
  {
    if k == 0 { ScaleIdentity(Ntt(f),1); }
    else {
      PrefixUndo(f,k-1);
      ScaleStage(NttPrefix(f,8-k),k-1,Factor(k-1));
      NttPrefixStep(f,7-k);
      assert NttPrefix(f,8-k) == ForwardStage(NttPrefix(f,7-k),7-k);
      StageUndo(NttPrefix(f,7-k),7-k);
      ScaleCompose(NttPrefix(f,7-k),2,Factor(k-1));
      FactorStep(k-1);
    }
  }

  lemma NttRoundTrip(f: seq<int>)
    requires Canonical(f)
    ensures InverseNtt(Ntt(f)) == f
  {
    PrefixUndo(f,7);
    NttPrefixZero(f);
    ScaleCompose(f,128,3303);
    ScaleIdentity(f,128*3303);
  }

  // Ordinary Horner evaluation of an arithmetic progression of coefficients.
  // The two parity evaluations are the coefficients of reduction modulo X^2-r.
  ghost function Eval(f: seq<int>, start: nat, stride: nat, r: int, terms: nat): int
    requires stride > 0
    requires terms == 0 || start+stride*(terms-1) < |f|
    ensures 0 <= Eval(f,start,stride,r,terms) < Q
    decreases terms
  {
    if terms == 0 then 0 else
      (f[start]+r*Eval(f,start+stride,stride,r,terms-1))%Q
  }

  lemma CongruentProduct(a: int, b: int, c: int, d: int)
    requires a%Q == b%Q && c%Q == d%Q
    ensures (a*c)%Q == (b*d)%Q
  {
    ModProduct(a,c); ModProduct(c,a%Q);
    ModProduct(b,d); ModProduct(d,b%Q);
  }

  lemma CongruentSum(a: int, b: int, c: int, d: int)
    requires a%Q == b%Q && c%Q == d%Q
    ensures (a+c)%Q == (b+d)%Q
  { ModSum(a,c); ModSum(b,d); }

  lemma {:isolate_assertions} SplitArithmetic(a: int, b: int, c: int, d: int, r: int)
    ensures (a+r*((b+r*((c+r*d)%Q))%Q))%Q ==
      (((a+(r*r)%Q*c)%Q)+r*((b+(r*r)%Q*d)%Q))%Q
  {
    var left0 := (c+r*d)%Q;
    CongruentProduct(r,r,left0,c+r*d);
    CongruentSum(b,b,r*left0,r*(c+r*d));
    var left1 := (b+r*left0)%Q;
    CongruentProduct(r,r,left1,b+r*(c+r*d));
    CongruentSum(a,a,r*left1,r*(b+r*(c+r*d)));
    var even := (a+(r*r)%Q*c)%Q;
    var odd := (b+(r*r)%Q*d)%Q;
    CongruentProduct((r*r)%Q,r*r,c,c);
    CongruentProduct((r*r)%Q,r*r,d,d);
    CongruentSum(a,a,(r*r)%Q*c,r*r*c);
    CongruentSum(b,b,(r*r)%Q*d,r*r*d);
    CongruentProduct(r,r,odd,b+r*r*d);
    assert even%Q == (a+r*r*c)%Q;
    assert (r*odd)%Q == (r*(b+r*r*d))%Q;
    CongruentSum(even,a+r*r*c,r*odd,r*(b+r*r*d));
    assert a+r*(b+r*(c+r*d)) == a+r*r*c+r*(b+r*r*d);
  }

  lemma EvalSplit(f: seq<int>, start: nat, stride: nat, r: int, pairs: nat)
    requires stride > 0
    requires pairs == 0 || start+stride*(2*pairs-1) < |f|
    ensures Eval(f,start,stride,r,2*pairs) ==
      (Eval(f,start,2*stride,(r*r)%Q,pairs)+
       r*Eval(f,start+stride,2*stride,(r*r)%Q,pairs))%Q
    decreases pairs
  {
    if pairs > 0 {
      EvalSplit(f,start+2*stride,stride,r,pairs-1);
      var c := Eval(f,start+2*stride,2*stride,(r*r)%Q,pairs-1);
      var d := Eval(f,start+3*stride,2*stride,(r*r)%Q,pairs-1);
      SplitArithmetic(f[start],f[start+stride],c,d,r);
    }
  }

  lemma TreeIndex(stages: nat, b: nat)
    requires stages <= 7 && b < Factor(stages)
    ensures stages > 0 ==> 0 <= Factor(stages-1)+b/2 < 128
    ensures 1 <= Factor(stages) <= 128
  {
    if stages == 0 {} else if stages == 1 {} else if stages == 2 {}
    else if stages == 3 {} else if stages == 4 {} else if stages == 5 {}
    else if stages == 6 {} else {}
  }

  ghost function TreeRoot(stages: nat, b: nat): int
    requires stages <= 7 && b < Factor(stages)
    ensures 0 <= TreeRoot(stages,b) < Q
  {
    TreeIndex(stages,b);
    if stages == 0 then Q-1 else
      var z := Zeta(Factor(stages-1)+b/2);
      if b%2 == 0 then z else (-z)%Q
  }

  lemma RootSquare(s: nat, b: nat)
    requires s < 7 && b < Factor(s)
    ensures (Zeta(Factor(s)+b)*Zeta(Factor(s)+b))%Q == TreeRoot(s,b)
  {
    if s == 0 { RootSquareStage0(b); }
    else if s == 1 { RootSquareStage1(b); }
    else if s == 2 { RootSquareStage2(b); }
    else if s == 3 { RootSquareStage3(b); }
    else if s == 4 { RootSquareStage4(b); }
    else if s == 5 { RootSquareStage5(b); }
    else if s == 6 { RootSquareStage6(b); }
  }

  lemma {:isolate_assertions} RootSquareStage0(b: nat)
    requires b < 1
    ensures (Zeta(1+b)*Zeta(1+b))%Q == TreeRoot(0,b)
  {
    if b == 0 { RootEntry1(); }
  }

  lemma {:isolate_assertions} RootSquareStage1(b: nat)
    requires b < 2
    ensures (Zeta(2+b)*Zeta(2+b))%Q == TreeRoot(1,b)
  {
    if b == 0 { RootEntry2(); RootEntry1(); }
    else if b == 1 { RootEntry3(); RootEntry1(); }
  }

  lemma {:isolate_assertions} RootSquareStage2(b: nat)
    requires b < 4
    ensures (Zeta(4+b)*Zeta(4+b))%Q == TreeRoot(2,b)
  {
    if b == 0 { RootEntry4(); RootEntry2(); }
    else if b == 1 { RootEntry5(); RootEntry2(); }
    else if b == 2 { RootEntry6(); RootEntry3(); }
    else if b == 3 { RootEntry7(); RootEntry3(); }
  }

  lemma {:isolate_assertions} RootSquareStage3(b: nat)
    requires b < 8
    ensures (Zeta(8+b)*Zeta(8+b))%Q == TreeRoot(3,b)
  {
    if b == 0 { RootEntry8(); RootEntry4(); }
    else if b == 1 { RootEntry9(); RootEntry4(); }
    else if b == 2 { RootEntry10(); RootEntry5(); }
    else if b == 3 { RootEntry11(); RootEntry5(); }
    else if b == 4 { RootEntry12(); RootEntry6(); }
    else if b == 5 { RootEntry13(); RootEntry6(); }
    else if b == 6 { RootEntry14(); RootEntry7(); }
    else if b == 7 { RootEntry15(); RootEntry7(); }
  }

  lemma {:isolate_assertions} RootSquareStage4(b: nat)
    requires b < 16
    ensures (Zeta(16+b)*Zeta(16+b))%Q == TreeRoot(4,b)
  {
    if b == 0 { RootEntry16(); RootEntry8(); }
    else if b == 1 { RootEntry17(); RootEntry8(); }
    else if b == 2 { RootEntry18(); RootEntry9(); }
    else if b == 3 { RootEntry19(); RootEntry9(); }
    else if b == 4 { RootEntry20(); RootEntry10(); }
    else if b == 5 { RootEntry21(); RootEntry10(); }
    else if b == 6 { RootEntry22(); RootEntry11(); }
    else if b == 7 { RootEntry23(); RootEntry11(); }
    else if b == 8 { RootEntry24(); RootEntry12(); }
    else if b == 9 { RootEntry25(); RootEntry12(); }
    else if b == 10 { RootEntry26(); RootEntry13(); }
    else if b == 11 { RootEntry27(); RootEntry13(); }
    else if b == 12 { RootEntry28(); RootEntry14(); }
    else if b == 13 { RootEntry29(); RootEntry14(); }
    else if b == 14 { RootEntry30(); RootEntry15(); }
    else if b == 15 { RootEntry31(); RootEntry15(); }
  }

  lemma {:isolate_assertions} RootSquareStage5(b: nat)
    requires b < 32
    ensures (Zeta(32+b)*Zeta(32+b))%Q == TreeRoot(5,b)
  {
    if b == 0 { RootEntry32(); RootEntry16(); }
    else if b == 1 { RootEntry33(); RootEntry16(); }
    else if b == 2 { RootEntry34(); RootEntry17(); }
    else if b == 3 { RootEntry35(); RootEntry17(); }
    else if b == 4 { RootEntry36(); RootEntry18(); }
    else if b == 5 { RootEntry37(); RootEntry18(); }
    else if b == 6 { RootEntry38(); RootEntry19(); }
    else if b == 7 { RootEntry39(); RootEntry19(); }
    else if b == 8 { RootEntry40(); RootEntry20(); }
    else if b == 9 { RootEntry41(); RootEntry20(); }
    else if b == 10 { RootEntry42(); RootEntry21(); }
    else if b == 11 { RootEntry43(); RootEntry21(); }
    else if b == 12 { RootEntry44(); RootEntry22(); }
    else if b == 13 { RootEntry45(); RootEntry22(); }
    else if b == 14 { RootEntry46(); RootEntry23(); }
    else if b == 15 { RootEntry47(); RootEntry23(); }
    else if b == 16 { RootEntry48(); RootEntry24(); }
    else if b == 17 { RootEntry49(); RootEntry24(); }
    else if b == 18 { RootEntry50(); RootEntry25(); }
    else if b == 19 { RootEntry51(); RootEntry25(); }
    else if b == 20 { RootEntry52(); RootEntry26(); }
    else if b == 21 { RootEntry53(); RootEntry26(); }
    else if b == 22 { RootEntry54(); RootEntry27(); }
    else if b == 23 { RootEntry55(); RootEntry27(); }
    else if b == 24 { RootEntry56(); RootEntry28(); }
    else if b == 25 { RootEntry57(); RootEntry28(); }
    else if b == 26 { RootEntry58(); RootEntry29(); }
    else if b == 27 { RootEntry59(); RootEntry29(); }
    else if b == 28 { RootEntry60(); RootEntry30(); }
    else if b == 29 { RootEntry61(); RootEntry30(); }
    else if b == 30 { RootEntry62(); RootEntry31(); }
    else if b == 31 { RootEntry63(); RootEntry31(); }
  }

  lemma RootSquareStage6(b: nat)
    requires b < 64
    ensures (Zeta(64+b)*Zeta(64+b))%Q == TreeRoot(6,b)
  {
    if b == 0 { SquareLeaf0(); }
    else if b == 1 { SquareLeaf1(); }
    else if b == 2 { SquareLeaf2(); }
    else if b == 3 { SquareLeaf3(); }
    else if b == 4 { SquareLeaf4(); }
    else if b == 5 { SquareLeaf5(); }
    else if b == 6 { SquareLeaf6(); }
    else if b == 7 { SquareLeaf7(); }
    else if b == 8 { SquareLeaf8(); }
    else if b == 9 { SquareLeaf9(); }
    else if b == 10 { SquareLeaf10(); }
    else if b == 11 { SquareLeaf11(); }
    else if b == 12 { SquareLeaf12(); }
    else if b == 13 { SquareLeaf13(); }
    else if b == 14 { SquareLeaf14(); }
    else if b == 15 { SquareLeaf15(); }
    else if b == 16 { SquareLeaf16(); }
    else if b == 17 { SquareLeaf17(); }
    else if b == 18 { SquareLeaf18(); }
    else if b == 19 { SquareLeaf19(); }
    else if b == 20 { SquareLeaf20(); }
    else if b == 21 { SquareLeaf21(); }
    else if b == 22 { SquareLeaf22(); }
    else if b == 23 { SquareLeaf23(); }
    else if b == 24 { SquareLeaf24(); }
    else if b == 25 { SquareLeaf25(); }
    else if b == 26 { SquareLeaf26(); }
    else if b == 27 { SquareLeaf27(); }
    else if b == 28 { SquareLeaf28(); }
    else if b == 29 { SquareLeaf29(); }
    else if b == 30 { SquareLeaf30(); }
    else if b == 31 { SquareLeaf31(); }
    else if b == 32 { SquareLeaf32(); }
    else if b == 33 { SquareLeaf33(); }
    else if b == 34 { SquareLeaf34(); }
    else if b == 35 { SquareLeaf35(); }
    else if b == 36 { SquareLeaf36(); }
    else if b == 37 { SquareLeaf37(); }
    else if b == 38 { SquareLeaf38(); }
    else if b == 39 { SquareLeaf39(); }
    else if b == 40 { SquareLeaf40(); }
    else if b == 41 { SquareLeaf41(); }
    else if b == 42 { SquareLeaf42(); }
    else if b == 43 { SquareLeaf43(); }
    else if b == 44 { SquareLeaf44(); }
    else if b == 45 { SquareLeaf45(); }
    else if b == 46 { SquareLeaf46(); }
    else if b == 47 { SquareLeaf47(); }
    else if b == 48 { SquareLeaf48(); }
    else if b == 49 { SquareLeaf49(); }
    else if b == 50 { SquareLeaf50(); }
    else if b == 51 { SquareLeaf51(); }
    else if b == 52 { SquareLeaf52(); }
    else if b == 53 { SquareLeaf53(); }
    else if b == 54 { SquareLeaf54(); }
    else if b == 55 { SquareLeaf55(); }
    else if b == 56 { SquareLeaf56(); }
    else if b == 57 { SquareLeaf57(); }
    else if b == 58 { SquareLeaf58(); }
    else if b == 59 { SquareLeaf59(); }
    else if b == 60 { SquareLeaf60(); }
    else if b == 61 { SquareLeaf61(); }
    else if b == 62 { SquareLeaf62(); }
    else if b == 63 { SquareLeaf63(); }
  }

  lemma SquareLeaf0()
    ensures (Zeta(64)*Zeta(64))%Q == TreeRoot(6,0)
  { RootEntry64(); RootEntry32(); }

  lemma SquareLeaf1()
    ensures (Zeta(65)*Zeta(65))%Q == TreeRoot(6,1)
  { RootEntry65(); RootEntry32(); }

  lemma SquareLeaf2()
    ensures (Zeta(66)*Zeta(66))%Q == TreeRoot(6,2)
  { RootEntry66(); RootEntry33(); }

  lemma SquareLeaf3()
    ensures (Zeta(67)*Zeta(67))%Q == TreeRoot(6,3)
  { RootEntry67(); RootEntry33(); }

  lemma SquareLeaf4()
    ensures (Zeta(68)*Zeta(68))%Q == TreeRoot(6,4)
  { RootEntry68(); RootEntry34(); }

  lemma SquareLeaf5()
    ensures (Zeta(69)*Zeta(69))%Q == TreeRoot(6,5)
  { RootEntry69(); RootEntry34(); }

  lemma SquareLeaf6()
    ensures (Zeta(70)*Zeta(70))%Q == TreeRoot(6,6)
  { RootEntry70(); RootEntry35(); }

  lemma SquareLeaf7()
    ensures (Zeta(71)*Zeta(71))%Q == TreeRoot(6,7)
  { RootEntry71(); RootEntry35(); }

  lemma SquareLeaf8()
    ensures (Zeta(72)*Zeta(72))%Q == TreeRoot(6,8)
  { RootEntry72(); RootEntry36(); }

  lemma SquareLeaf9()
    ensures (Zeta(73)*Zeta(73))%Q == TreeRoot(6,9)
  { RootEntry73(); RootEntry36(); }

  lemma SquareLeaf10()
    ensures (Zeta(74)*Zeta(74))%Q == TreeRoot(6,10)
  { RootEntry74(); RootEntry37(); }

  lemma SquareLeaf11()
    ensures (Zeta(75)*Zeta(75))%Q == TreeRoot(6,11)
  { RootEntry75(); RootEntry37(); }

  lemma SquareLeaf12()
    ensures (Zeta(76)*Zeta(76))%Q == TreeRoot(6,12)
  { RootEntry76(); RootEntry38(); }

  lemma SquareLeaf13()
    ensures (Zeta(77)*Zeta(77))%Q == TreeRoot(6,13)
  { RootEntry77(); RootEntry38(); }

  lemma SquareLeaf14()
    ensures (Zeta(78)*Zeta(78))%Q == TreeRoot(6,14)
  { RootEntry78(); RootEntry39(); }

  lemma SquareLeaf15()
    ensures (Zeta(79)*Zeta(79))%Q == TreeRoot(6,15)
  { RootEntry79(); RootEntry39(); }

  lemma SquareLeaf16()
    ensures (Zeta(80)*Zeta(80))%Q == TreeRoot(6,16)
  { RootEntry80(); RootEntry40(); }

  lemma SquareLeaf17()
    ensures (Zeta(81)*Zeta(81))%Q == TreeRoot(6,17)
  { RootEntry81(); RootEntry40(); }

  lemma SquareLeaf18()
    ensures (Zeta(82)*Zeta(82))%Q == TreeRoot(6,18)
  { RootEntry82(); RootEntry41(); }

  lemma SquareLeaf19()
    ensures (Zeta(83)*Zeta(83))%Q == TreeRoot(6,19)
  { RootEntry83(); RootEntry41(); }

  lemma SquareLeaf20()
    ensures (Zeta(84)*Zeta(84))%Q == TreeRoot(6,20)
  { RootEntry84(); RootEntry42(); }

  lemma SquareLeaf21()
    ensures (Zeta(85)*Zeta(85))%Q == TreeRoot(6,21)
  { RootEntry85(); RootEntry42(); }

  lemma SquareLeaf22()
    ensures (Zeta(86)*Zeta(86))%Q == TreeRoot(6,22)
  { RootEntry86(); RootEntry43(); }

  lemma SquareLeaf23()
    ensures (Zeta(87)*Zeta(87))%Q == TreeRoot(6,23)
  { RootEntry87(); RootEntry43(); }

  lemma SquareLeaf24()
    ensures (Zeta(88)*Zeta(88))%Q == TreeRoot(6,24)
  { RootEntry88(); RootEntry44(); }

  lemma SquareLeaf25()
    ensures (Zeta(89)*Zeta(89))%Q == TreeRoot(6,25)
  { RootEntry89(); RootEntry44(); }

  lemma SquareLeaf26()
    ensures (Zeta(90)*Zeta(90))%Q == TreeRoot(6,26)
  { RootEntry90(); RootEntry45(); }

  lemma SquareLeaf27()
    ensures (Zeta(91)*Zeta(91))%Q == TreeRoot(6,27)
  { RootEntry91(); RootEntry45(); }

  lemma SquareLeaf28()
    ensures (Zeta(92)*Zeta(92))%Q == TreeRoot(6,28)
  { RootEntry92(); RootEntry46(); }

  lemma SquareLeaf29()
    ensures (Zeta(93)*Zeta(93))%Q == TreeRoot(6,29)
  { RootEntry93(); RootEntry46(); }

  lemma SquareLeaf30()
    ensures (Zeta(94)*Zeta(94))%Q == TreeRoot(6,30)
  { RootEntry94(); RootEntry47(); }

  lemma SquareLeaf31()
    ensures (Zeta(95)*Zeta(95))%Q == TreeRoot(6,31)
  { RootEntry95(); RootEntry47(); }

  lemma SquareLeaf32()
    ensures (Zeta(96)*Zeta(96))%Q == TreeRoot(6,32)
  { RootEntry96(); RootEntry48(); }

  lemma SquareLeaf33()
    ensures (Zeta(97)*Zeta(97))%Q == TreeRoot(6,33)
  { RootEntry97(); RootEntry48(); }

  lemma SquareLeaf34()
    ensures (Zeta(98)*Zeta(98))%Q == TreeRoot(6,34)
  { RootEntry98(); RootEntry49(); }

  lemma SquareLeaf35()
    ensures (Zeta(99)*Zeta(99))%Q == TreeRoot(6,35)
  { RootEntry99(); RootEntry49(); }

  lemma SquareLeaf36()
    ensures (Zeta(100)*Zeta(100))%Q == TreeRoot(6,36)
  { RootEntry100(); RootEntry50(); }

  lemma SquareLeaf37()
    ensures (Zeta(101)*Zeta(101))%Q == TreeRoot(6,37)
  { RootEntry101(); RootEntry50(); }

  lemma SquareLeaf38()
    ensures (Zeta(102)*Zeta(102))%Q == TreeRoot(6,38)
  { RootEntry102(); RootEntry51(); }

  lemma SquareLeaf39()
    ensures (Zeta(103)*Zeta(103))%Q == TreeRoot(6,39)
  { RootEntry103(); RootEntry51(); }

  lemma SquareLeaf40()
    ensures (Zeta(104)*Zeta(104))%Q == TreeRoot(6,40)
  { RootEntry104(); RootEntry52(); }

  lemma SquareLeaf41()
    ensures (Zeta(105)*Zeta(105))%Q == TreeRoot(6,41)
  { RootEntry105(); RootEntry52(); }

  lemma SquareLeaf42()
    ensures (Zeta(106)*Zeta(106))%Q == TreeRoot(6,42)
  { RootEntry106(); RootEntry53(); }

  lemma SquareLeaf43()
    ensures (Zeta(107)*Zeta(107))%Q == TreeRoot(6,43)
  { RootEntry107(); RootEntry53(); }

  lemma SquareLeaf44()
    ensures (Zeta(108)*Zeta(108))%Q == TreeRoot(6,44)
  { RootEntry108(); RootEntry54(); }

  lemma SquareLeaf45()
    ensures (Zeta(109)*Zeta(109))%Q == TreeRoot(6,45)
  { RootEntry109(); RootEntry54(); }

  lemma SquareLeaf46()
    ensures (Zeta(110)*Zeta(110))%Q == TreeRoot(6,46)
  { RootEntry110(); RootEntry55(); }

  lemma SquareLeaf47()
    ensures (Zeta(111)*Zeta(111))%Q == TreeRoot(6,47)
  { RootEntry111(); RootEntry55(); }

  lemma SquareLeaf48()
    ensures (Zeta(112)*Zeta(112))%Q == TreeRoot(6,48)
  { RootEntry112(); RootEntry56(); }

  lemma SquareLeaf49()
    ensures (Zeta(113)*Zeta(113))%Q == TreeRoot(6,49)
  { RootEntry113(); RootEntry56(); }

  lemma SquareLeaf50()
    ensures (Zeta(114)*Zeta(114))%Q == TreeRoot(6,50)
  { RootEntry114(); RootEntry57(); }

  lemma SquareLeaf51()
    ensures (Zeta(115)*Zeta(115))%Q == TreeRoot(6,51)
  { RootEntry115(); RootEntry57(); }

  lemma SquareLeaf52()
    ensures (Zeta(116)*Zeta(116))%Q == TreeRoot(6,52)
  { RootEntry116(); RootEntry58(); }

  lemma SquareLeaf53()
    ensures (Zeta(117)*Zeta(117))%Q == TreeRoot(6,53)
  { RootEntry117(); RootEntry58(); }

  lemma SquareLeaf54()
    ensures (Zeta(118)*Zeta(118))%Q == TreeRoot(6,54)
  { RootEntry118(); RootEntry59(); }

  lemma SquareLeaf55()
    ensures (Zeta(119)*Zeta(119))%Q == TreeRoot(6,55)
  { RootEntry119(); RootEntry59(); }

  lemma SquareLeaf56()
    ensures (Zeta(120)*Zeta(120))%Q == TreeRoot(6,56)
  { RootEntry120(); RootEntry60(); }

  lemma SquareLeaf57()
    ensures (Zeta(121)*Zeta(121))%Q == TreeRoot(6,57)
  { RootEntry121(); RootEntry60(); }

  lemma SquareLeaf58()
    ensures (Zeta(122)*Zeta(122))%Q == TreeRoot(6,58)
  { RootEntry122(); RootEntry61(); }

  lemma SquareLeaf59()
    ensures (Zeta(123)*Zeta(123))%Q == TreeRoot(6,59)
  { RootEntry123(); RootEntry61(); }

  lemma SquareLeaf60()
    ensures (Zeta(124)*Zeta(124))%Q == TreeRoot(6,60)
  { RootEntry124(); RootEntry62(); }

  lemma SquareLeaf61()
    ensures (Zeta(125)*Zeta(125))%Q == TreeRoot(6,61)
  { RootEntry125(); RootEntry62(); }

  lemma SquareLeaf62()
    ensures (Zeta(126)*Zeta(126))%Q == TreeRoot(6,62)
  { RootEntry126(); RootEntry63(); }

  lemma SquareLeaf63()
    ensures (Zeta(127)*Zeta(127))%Q == TreeRoot(6,63)
  { RootEntry127(); RootEntry63(); }

  lemma RootSplit(s: nat, b: nat)
    requires s < 7 && b < Factor(s)
    ensures TreeRoot(s+1,2*b) == Zeta(Factor(s)+b)
    ensures TreeRoot(s+1,2*b+1) == (-Zeta(Factor(s)+b))%Q
    ensures (TreeRoot(s+1,2*b)*TreeRoot(s+1,2*b))%Q == TreeRoot(s,b)
    ensures (TreeRoot(s+1,2*b+1)*TreeRoot(s+1,2*b+1))%Q == TreeRoot(s,b)
  {
    FactorStep(s);
    RootSquare(s,b);
    ModProduct(-Zeta(Factor(s)+b),(-Zeta(Factor(s)+b))%Q);
    ModProduct(-Zeta(Factor(s)+b),-Zeta(Factor(s)+b));
  }

  lemma LeafGamma(b: nat)
    requires b < 128
    ensures TreeRoot(7,b) == Gamma(b)
  {
    if b == 0 { RootEntry0(); RootEntry64(); }
    else if b == 1 { RootEntry1(); RootEntry64(); }
    else if b == 2 { RootEntry2(); RootEntry65(); }
    else if b == 3 { RootEntry3(); RootEntry65(); }
    else if b == 4 { RootEntry4(); RootEntry66(); }
    else if b == 5 { RootEntry5(); RootEntry66(); }
    else if b == 6 { RootEntry6(); RootEntry67(); }
    else if b == 7 { RootEntry7(); RootEntry67(); }
    else if b == 8 { RootEntry8(); RootEntry68(); }
    else if b == 9 { RootEntry9(); RootEntry68(); }
    else if b == 10 { RootEntry10(); RootEntry69(); }
    else if b == 11 { RootEntry11(); RootEntry69(); }
    else if b == 12 { RootEntry12(); RootEntry70(); }
    else if b == 13 { RootEntry13(); RootEntry70(); }
    else if b == 14 { RootEntry14(); RootEntry71(); }
    else if b == 15 { RootEntry15(); RootEntry71(); }
    else if b == 16 { RootEntry16(); RootEntry72(); }
    else if b == 17 { RootEntry17(); RootEntry72(); }
    else if b == 18 { RootEntry18(); RootEntry73(); }
    else if b == 19 { RootEntry19(); RootEntry73(); }
    else if b == 20 { RootEntry20(); RootEntry74(); }
    else if b == 21 { RootEntry21(); RootEntry74(); }
    else if b == 22 { RootEntry22(); RootEntry75(); }
    else if b == 23 { RootEntry23(); RootEntry75(); }
    else if b == 24 { RootEntry24(); RootEntry76(); }
    else if b == 25 { RootEntry25(); RootEntry76(); }
    else if b == 26 { RootEntry26(); RootEntry77(); }
    else if b == 27 { RootEntry27(); RootEntry77(); }
    else if b == 28 { RootEntry28(); RootEntry78(); }
    else if b == 29 { RootEntry29(); RootEntry78(); }
    else if b == 30 { RootEntry30(); RootEntry79(); }
    else if b == 31 { RootEntry31(); RootEntry79(); }
    else if b == 32 { RootEntry32(); RootEntry80(); }
    else if b == 33 { RootEntry33(); RootEntry80(); }
    else if b == 34 { RootEntry34(); RootEntry81(); }
    else if b == 35 { RootEntry35(); RootEntry81(); }
    else if b == 36 { RootEntry36(); RootEntry82(); }
    else if b == 37 { RootEntry37(); RootEntry82(); }
    else if b == 38 { RootEntry38(); RootEntry83(); }
    else if b == 39 { RootEntry39(); RootEntry83(); }
    else if b == 40 { RootEntry40(); RootEntry84(); }
    else if b == 41 { RootEntry41(); RootEntry84(); }
    else if b == 42 { RootEntry42(); RootEntry85(); }
    else if b == 43 { RootEntry43(); RootEntry85(); }
    else if b == 44 { RootEntry44(); RootEntry86(); }
    else if b == 45 { RootEntry45(); RootEntry86(); }
    else if b == 46 { RootEntry46(); RootEntry87(); }
    else if b == 47 { RootEntry47(); RootEntry87(); }
    else if b == 48 { RootEntry48(); RootEntry88(); }
    else if b == 49 { RootEntry49(); RootEntry88(); }
    else if b == 50 { RootEntry50(); RootEntry89(); }
    else if b == 51 { RootEntry51(); RootEntry89(); }
    else if b == 52 { RootEntry52(); RootEntry90(); }
    else if b == 53 { RootEntry53(); RootEntry90(); }
    else if b == 54 { RootEntry54(); RootEntry91(); }
    else if b == 55 { RootEntry55(); RootEntry91(); }
    else if b == 56 { RootEntry56(); RootEntry92(); }
    else if b == 57 { RootEntry57(); RootEntry92(); }
    else if b == 58 { RootEntry58(); RootEntry93(); }
    else if b == 59 { RootEntry59(); RootEntry93(); }
    else if b == 60 { RootEntry60(); RootEntry94(); }
    else if b == 61 { RootEntry61(); RootEntry94(); }
    else if b == 62 { RootEntry62(); RootEntry95(); }
    else if b == 63 { RootEntry63(); RootEntry95(); }
    else if b == 64 { RootEntry64(); RootEntry96(); }
    else if b == 65 { RootEntry65(); RootEntry96(); }
    else if b == 66 { RootEntry66(); RootEntry97(); }
    else if b == 67 { RootEntry67(); RootEntry97(); }
    else if b == 68 { RootEntry68(); RootEntry98(); }
    else if b == 69 { RootEntry69(); RootEntry98(); }
    else if b == 70 { RootEntry70(); RootEntry99(); }
    else if b == 71 { RootEntry71(); RootEntry99(); }
    else if b == 72 { RootEntry72(); RootEntry100(); }
    else if b == 73 { RootEntry73(); RootEntry100(); }
    else if b == 74 { RootEntry74(); RootEntry101(); }
    else if b == 75 { RootEntry75(); RootEntry101(); }
    else if b == 76 { RootEntry76(); RootEntry102(); }
    else if b == 77 { RootEntry77(); RootEntry102(); }
    else if b == 78 { RootEntry78(); RootEntry103(); }
    else if b == 79 { RootEntry79(); RootEntry103(); }
    else if b == 80 { RootEntry80(); RootEntry104(); }
    else if b == 81 { RootEntry81(); RootEntry104(); }
    else if b == 82 { RootEntry82(); RootEntry105(); }
    else if b == 83 { RootEntry83(); RootEntry105(); }
    else if b == 84 { RootEntry84(); RootEntry106(); }
    else if b == 85 { RootEntry85(); RootEntry106(); }
    else if b == 86 { RootEntry86(); RootEntry107(); }
    else if b == 87 { RootEntry87(); RootEntry107(); }
    else if b == 88 { RootEntry88(); RootEntry108(); }
    else if b == 89 { RootEntry89(); RootEntry108(); }
    else if b == 90 { RootEntry90(); RootEntry109(); }
    else if b == 91 { RootEntry91(); RootEntry109(); }
    else if b == 92 { RootEntry92(); RootEntry110(); }
    else if b == 93 { RootEntry93(); RootEntry110(); }
    else if b == 94 { RootEntry94(); RootEntry111(); }
    else if b == 95 { RootEntry95(); RootEntry111(); }
    else if b == 96 { RootEntry96(); RootEntry112(); }
    else if b == 97 { RootEntry97(); RootEntry112(); }
    else if b == 98 { RootEntry98(); RootEntry113(); }
    else if b == 99 { RootEntry99(); RootEntry113(); }
    else if b == 100 { RootEntry100(); RootEntry114(); }
    else if b == 101 { RootEntry101(); RootEntry114(); }
    else if b == 102 { RootEntry102(); RootEntry115(); }
    else if b == 103 { RootEntry103(); RootEntry115(); }
    else if b == 104 { RootEntry104(); RootEntry116(); }
    else if b == 105 { RootEntry105(); RootEntry116(); }
    else if b == 106 { RootEntry106(); RootEntry117(); }
    else if b == 107 { RootEntry107(); RootEntry117(); }
    else if b == 108 { RootEntry108(); RootEntry118(); }
    else if b == 109 { RootEntry109(); RootEntry118(); }
    else if b == 110 { RootEntry110(); RootEntry119(); }
    else if b == 111 { RootEntry111(); RootEntry119(); }
    else if b == 112 { RootEntry112(); RootEntry120(); }
    else if b == 113 { RootEntry113(); RootEntry120(); }
    else if b == 114 { RootEntry114(); RootEntry121(); }
    else if b == 115 { RootEntry115(); RootEntry121(); }
    else if b == 116 { RootEntry116(); RootEntry122(); }
    else if b == 117 { RootEntry117(); RootEntry122(); }
    else if b == 118 { RootEntry118(); RootEntry123(); }
    else if b == 119 { RootEntry119(); RootEntry123(); }
    else if b == 120 { RootEntry120(); RootEntry124(); }
    else if b == 121 { RootEntry121(); RootEntry124(); }
    else if b == 122 { RootEntry122(); RootEntry125(); }
    else if b == 123 { RootEntry123(); RootEntry125(); }
    else if b == 124 { RootEntry124(); RootEntry126(); }
    else if b == 125 { RootEntry125(); RootEntry126(); }
    else if b == 126 { RootEntry126(); RootEntry127(); }
    else if b == 127 { RootEntry127(); RootEntry127(); }
  }
  lemma StageShape(stages: nat)
    requires 1 <= stages <= 7
    ensures 256/Factor(stages) == Len(stages-1)
    ensures 2 <= 256/Factor(stages) <= 128
    ensures Factor(stages) == 2*Factor(stages-1)
    ensures Factor(stages)*(256/Factor(stages)) == 256
    ensures Factor(stages-1)*(2*(256/Factor(stages))) == 256
  {
    if stages == 1 {} else if stages == 2 {} else if stages == 3 {}
    else if stages == 4 {} else if stages == 5 {} else if stages == 6 {} else {}
  }

  lemma BlockIndex(stages: nat, b: nat, j: nat)
    requires 1 <= stages <= 7 && b < Factor(stages) && j < 256/Factor(stages)
    ensures 0 <= b*(256/Factor(stages))+j < 256
    ensures 0 <= (b/2)*(2*(256/Factor(stages)))+j
    ensures (b/2)*(2*(256/Factor(stages)))+j+256/Factor(stages) < 256
    ensures (b*(256/Factor(stages))+j)/(2*(256/Factor(stages))) == b/2
    ensures (b*(256/Factor(stages))+j)%(2*(256/Factor(stages))) < 256/Factor(stages) <==> b%2 == 0
    ensures 128/(256/Factor(stages)) == Factor(stages-1)
    ensures b%2 == 0 ==> b*(256/Factor(stages))+j == (b/2)*(2*(256/Factor(stages)))+j
    ensures b%2 == 1 ==> b*(256/Factor(stages))+j == (b/2)*(2*(256/Factor(stages)))+j+256/Factor(stages)
  {
    if stages == 1 {} else if stages == 2 {} else if stages == 3 {}
    else if stages == 4 {} else if stages == 5 {} else if stages == 6 {} else {}
  }

  lemma NegRoot(a: int, b: int, z: int)
    ensures (a-z*b)%Q == (a+((-z)%Q)*b)%Q
  {
    ModProduct(-z,b);
    CongruentSum(a,a,(-z)*b,((-z)%Q)*b);
  }

  lemma {:isolate_assertions} PrefixEvaluation(f: seq<int>, stages: nat, b: nat, j: nat)
    requires Canonical(f) && stages <= 7
    requires b < Factor(stages) && j < 256/Factor(stages)
    ensures NttPrefix(f,stages)[b*(256/Factor(stages))+j] ==
      Eval(f,j,256/Factor(stages),TreeRoot(stages,b),Factor(stages))
    decreases stages
  {
    if stages == 0 {
      NttPrefixZero(f);
      assert b == 0;
      assert Eval(f,j,256,TreeRoot(0,b),1) == f[j];
      assert NttPrefix(f,0)[j] == f[j];
    } else {
      NttPrefixStep(f,stages-1);
      StageShape(stages);
      BlockIndex(stages,b,j);
      var w := 256/Factor(stages);
      var k := Factor(stages-1);
      assert 256/Factor(stages-1) == 2*w;
      PrefixEvaluation(f,stages-1,b/2,j);
      PrefixEvaluation(f,stages-1,b/2,j+w);
      RootSplit(stages-1,b/2);
      var r := TreeRoot(stages,b);
      assert (r*r)%Q == TreeRoot(stages-1,b/2);
      EvalSplit(f,j,w,r,k);
      var h := NttPrefix(f,stages-1);
      var z := Zeta(k+b/2);
      var i := b*w+j;
      var lo := (b/2)*(2*w)+j;
      var even := Eval(f,j,2*w,TreeRoot(stages-1,b/2),k);
      var odd := Eval(f,j+w,2*w,TreeRoot(stages-1,b/2),k);
      assert h[lo] == even && h[lo+w] == odd;
      assert NttPrefix(f,stages)[i] == ForwardLane(h,stages-1,i);
      assert Eval(f,j,w,r,2*k) == (even+r*odd)%Q;
      if b%2 == 0 {
        assert r == z;
        assert i == lo;
        assert ForwardLane(h,stages-1,i) == (even+z*odd)%Q;
      } else {
        assert r == (-z)%Q;
        assert i == lo+w;
        ModProduct(-z,odd);
        assert (r*odd)%Q == (-z*odd)%Q;
        CongruentSum(even,even,r*odd,-z*odd);
        assert ForwardLane(h,stages-1,i) == (even-z*odd)%Q;
        NegRoot(even,odd,z);
        assert (even-z*odd)%Q == (even+r*odd)%Q;
      }
      assert NttPrefix(f,stages)[i] == (even+r*odd)%Q;
      assert Eval(f,j,w,r,Factor(stages)) == (even+r*odd)%Q;
      assert NttPrefix(f,stages)[i] == Eval(f,j,w,r,Factor(stages));
    }
  }

  ghost function HornerRepresentation(f: seq<int>): seq<int>
    requires Canonical(f)
    ensures Canonical(HornerRepresentation(f))
  { seq(256, i requires 0 <= i < 256 => Eval(f,i%2,2,Gamma(i/2),128)) }

  // Isolate one coefficient before sequence extensionality. This keeps the
  // recursive evaluation context out of the quantified whole-sequence goal.
  lemma {:isolate_assertions} {:induction false} NttHornerLane(f: seq<int>, i: nat)
    requires Canonical(f) && i < 256
    ensures Ntt(f)[i] == HornerRepresentation(f)[i]
  {
    assert Factor(7) == 128;
    assert 256/Factor(7) == 2;
    assert (i/2)*2+i%2 == i;
    PrefixEvaluation(f,7,i/2,i%2);
    assert NttPrefix(f,7)[i] == Eval(f,i%2,2,TreeRoot(7,i/2),128);
    LeafGamma(i/2);
    assert TreeRoot(7,i/2) == Gamma(i/2);
    assert Ntt(f)[i] == Eval(f,i%2,2,Gamma(i/2),128);
    assert HornerRepresentation(f)[i] == Eval(f,i%2,2,Gamma(i/2),128);
  }

  lemma {:induction false} NttHornerRepresentation(f: seq<int>)
    requires Canonical(f)
    ensures Ntt(f) == HornerRepresentation(f)
  {
    forall i | 0 <= i < 256
      ensures Ntt(f)[i] == HornerRepresentation(f)[i]
    { NttHornerLane(f,i); }
  }

  ghost function {:opaque} Power(a: int, e: nat): int
    ensures 0 <= Power(a,e) < Q
    decreases e
  { if e == 0 then 1 else (a*Power(a,e-1))%Q }

  lemma PowerStep(a: int, e: nat)
    ensures Power(a,0) == 1
    ensures Power(a,e+1) == (a*Power(a,e))%Q
  { reveal Power(); }

  lemma {:isolate_assertions} PowerAdd(a: int, m: nat, n: nat)
    ensures Power(a,m+n) == (Power(a,m)*Power(a,n))%Q
    decreases n
  {
    PowerStep(a,n);
    if n == 0 { }
    else {
      PowerAdd(a,m,n-1);
      PowerStep(a,m+n-1);
      PowerStep(a,n-1);
      var x := Power(a,m);
      var y := Power(a,n-1);
      ModProduct(x*y,a);
      ModProduct(a*y,x);
      assert a*(x*y) == x*(a*y);
    }
  }

  lemma {:isolate_assertions} PowModPower(a: int, e: nat)
    ensures PowMod(a,e) == Power(a,e)
    decreases e
  {
    reveal PowMod();
    PowerStep(a,e);
    if e > 0 {
      PowModPower(a,e/2);
      PowerAdd(a,e/2,e/2);
      if e%2 == 0 {
        assert e == e/2+e/2;
      } else {
        assert e == e/2+e/2+1;
        PowerStep(a,e-1);
        ModProduct(Power(a,e/2)*Power(a,e/2),a);
      }
    }
  }

  lemma {:isolate_assertions} AppendArithmetic(a: int, h: int, c: int, p: int, r: int)
    ensures (a+r*((h+c*p)%Q))%Q == ((a+r*h)%Q+c*((r*p)%Q))%Q
  {
    CongruentProduct(r,r,(h+c*p)%Q,h+c*p);
    CongruentSum(a,a,r*((h+c*p)%Q),r*(h+c*p));
    CongruentProduct(c,c,(r*p)%Q,r*p);
    CongruentSum(a+r*h,a+r*h,c*((r*p)%Q),c*(r*p));
    ModSum(a+r*h,c*((r*p)%Q));
    assert a+r*(h+c*p) == a+r*h+c*(r*p);
  }

  lemma {:isolate_assertions} EvalAppend(f: seq<int>, start: nat, stride: nat, r: int, terms: nat)
    requires stride > 0 && start+stride*terms < |f|
    ensures Eval(f,start,stride,r,terms+1) ==
      (Eval(f,start,stride,r,terms)+f[start+stride*terms]*Power(r,terms))%Q
    decreases terms
  {
    PowerStep(r,terms);
    if terms > 0 {
      EvalAppend(f,start+stride,stride,r,terms-1);
      PowerStep(r,terms-1);
      var h := Eval(f,start+stride,stride,r,terms-1);
      var c := f[start+stride*terms];
      var p := Power(r,terms-1);
      AppendArithmetic(f[start],h,c,p,r);
    }
  }

  lemma RemainderHorner(f: seq<int>, r: int, parity: nat, terms: nat)
    requires Canonical(f) && parity < 2 && terms <= 128
    ensures Remainder(f,r,parity,terms) == Eval(f,parity,2,r,terms)
    decreases terms
  {
    if terms > 0 {
      RemainderHorner(f,r,parity,terms-1);
      EvalAppend(f,parity,2,r,terms-1);
      PowModPower(r,terms-1);
    }
  }

  lemma NttRepresentation(f: seq<int>)
    requires Canonical(f)
    ensures Ntt(f) == Representation(f)
  {
    NttHornerRepresentation(f);
    forall i | 0 <= i < 256
      ensures HornerRepresentation(f)[i] == Representation(f)[i]
    { RemainderHorner(f,Gamma(i/2),i%2,128); }
  }


}

module VerifiedPolynomial {
  import S = PolySpec
  import F = VerifiedField
  import R = PolynomialRing

  method Add(f: seq<int>, g: seq<int>) returns (r: seq<int>)
    requires S.Canonical(f) && S.Canonical(g)
    ensures S.Canonical(r) && r == S.Add(f,g)
  {
    var a := new int[256];
    for i := 0 to 256
      invariant forall j :: 0 <= j < i ==> a[j] == S.Add(f,g)[j]
    { a[i] := F.Add(f[i],g[i]); }
    r := a[..];
    assert r == S.Add(f,g);
  }

  method Sub(f: seq<int>, g: seq<int>) returns (r: seq<int>)
    requires S.Canonical(f) && S.Canonical(g)
    ensures S.Canonical(r) && r == S.Sub(f,g)
  {
    var a := new int[256];
    for i := 0 to 256
      invariant forall j :: 0 <= j < i ==> a[j] == S.Sub(f,g)[j]
    { a[i] := F.Sub(f[i],g[i]); }
    r := a[..];
    assert r == S.Sub(f,g);
  }

  method ForwardStage(f: seq<int>, s: nat) returns (r: seq<int>)
    requires S.Canonical(f) && s < 7
    ensures S.Canonical(r) && r == S.ForwardStage(f,s)
  {
    var a := new int[256];
    var l := S.Len(s);
    var roots := S.Zetas();
    for i := 0 to 256
      invariant forall j :: 0 <= j < i ==> a[j] == S.ForwardLane(f,s,j)
    {
      S.StageBounds(s,i);
      S.RootTables(128/l+i/(2*l));
      var z := roots[128/l+i/(2*l)];
      if i%(2*l) < l {
        var t := F.Mul(z,f[i+l]);
        a[i] := F.Add(f[i],t);
      } else {
        var t := F.Mul(z,f[i]);
        a[i] := F.Sub(f[i-l],t);
      }
    }
    r := a[..];
    assert r == S.ForwardStage(f,s);
  }

  method Ntt(f: seq<int>) returns (r: seq<int>)
    requires S.Canonical(f)
    ensures S.Canonical(r) && r == S.Ntt(f) && r == S.Representation(f)
  {
    r := f;
    S.NttPrefixZero(f);
    for s := 0 to 7
      invariant S.Canonical(r) && r == S.NttPrefix(f,s)
    { S.NttPrefixStep(f,s); r := ForwardStage(r,s); }
    S.NttRepresentation(f);
  }

  method InverseStage(f: seq<int>, s: nat) returns (r: seq<int>)
    requires S.Canonical(f) && s < 7
    ensures S.Canonical(r) && r == S.InverseStage(f,s)
  {
    var a := new int[256];
    var l := S.Len(6-s);
    var roots := S.Zetas();
    for i := 0 to 256
      invariant forall j :: 0 <= j < i ==> a[j] == S.InverseLane(f,s,j)
    {
      S.StageBounds(6-s,i);
      S.RootTables(256/l-1-i/(2*l));
      var z := roots[256/l-1-i/(2*l)];
      if i%(2*l) < l {
        a[i] := F.Add(f[i],f[i+l]);
      } else {
        a[i] := F.MulSub(z,f[i],f[i-l]);
      }
    }
    r := a[..];
    assert r == S.InverseStage(f,s);
  }

  method Scale(f: seq<int>, scalar: int) returns (r: seq<int>)
    requires S.Canonical(f) && 0 <= scalar < 3329
    ensures S.Canonical(r) && r == S.Scale(f,scalar)
  {
    var a := new int[256];
    for i := 0 to 256
      invariant forall j :: 0 <= j < i ==> a[j] == S.Scale(f,scalar)[j]
    { a[i] := F.Mul(f[i],scalar); }
    r := a[..];
    assert r == S.Scale(f,scalar);
  }

  method InverseNtt(f: seq<int>) returns (r: seq<int>)
    requires S.Canonical(f)
    ensures S.Canonical(r) && r == S.InverseNtt(f)
    ensures S.Representation(r) == f
  {
    r := f;
    for s := 0 to 7
      invariant S.Canonical(r) && r == S.InversePrefix(f,s)
    { r := InverseStage(r,s); }
    r := Scale(r,3303);
    R.NttInverseRoundTrip(f);
    S.NttRepresentation(r);
  }

  lemma ModProduct(a: int, b: int)
    ensures ((a%3329)*b)%3329 == (a*b)%3329
  {
    assert a == (a/3329)*3329+a%3329;
    assert a*b == (a/3329)*b*3329+(a%3329)*b;
  }

  method BaseCase(a0: int, a1: int, b0: int, b1: int, gamma: int)
      returns (c0: int, c1: int)
    requires 0 <= a0 < 3329 && 0 <= a1 < 3329
    requires 0 <= b0 < 3329 && 0 <= b1 < 3329 && 0 <= gamma < 3329
    ensures 0 <= c0 < 3329 && 0 <= c1 < 3329
    ensures c0 == (a0*b0+a1*b1*gamma)%3329
    ensures c1 == (a0*b1+a1*b0)%3329
  {
    var t := F.Mul(a1,b1);
    c0 := F.AddMul(a0,b0,t,gamma);
    c1 := F.AddMul(a0,b1,a1,b0);
    ModProduct(a1*b1,gamma);
  }

  method NttMul(f: seq<int>, g: seq<int>) returns (r: seq<int>)
    requires S.Canonical(f) && S.Canonical(g)
    ensures S.Canonical(r) && r == S.NttMul(f,g)
  {
    var a := new int[256];
    var gammas := S.Gammas();
    for i := 0 to 128
      invariant forall j :: 0 <= j < 2*i ==> a[j] == S.NttMul(f,g)[j]
    {
      S.RootTables(i);
      var c0, c1 := BaseCase(f[2*i],f[2*i+1],g[2*i],g[2*i+1],gammas[i]);
      a[2*i], a[2*i+1] := c0, c1;
    }
    r := a[..];
    assert r == S.NttMul(f,g);
  }
}

// Independent quotient-ring multiplication and NTT homomorphism proofs.
module PolynomialRing {
  import S = PolySpec
  const Q: int := 3329

  datatype Residue = Pair(e: int, o: int)
  ghost predicate PairCanonical(p: Residue) { 0 <= p.e < Q && 0 <= p.o < Q }
  ghost function PairAdd(a: Residue, b: Residue): Residue
    ensures PairCanonical(PairAdd(a,b))
  { Pair((a.e+b.e)%Q,(a.o+b.o)%Q) }
  ghost function PairScale(a: Residue, c: int): Residue
    ensures PairCanonical(PairScale(a,c))
  { Pair((c*a.e)%Q,(c*a.o)%Q) }
  ghost function TimesX(a: Residue, r: int): Residue
    requires PairCanonical(a)
    ensures PairCanonical(TimesX(a,r))
  { Pair((r*a.o)%Q,a.e) }
  ghost function PairProduct(a: Residue, b: Residue, r: int): Residue
    ensures PairCanonical(PairProduct(a,b,r))
  { Pair((a.e*b.e+r*a.o*b.o)%Q,(a.e*b.o+a.o*b.e)%Q) }

  ghost function {:opaque} PairEval(f: seq<int>, start: nat, r: int, terms: nat): Residue
    requires S.Canonical(f) && start+terms <= 256
    ensures PairCanonical(PairEval(f,start,r,terms))
    decreases terms
  {
    if terms == 0 then Pair(0,0) else
      var tail := PairEval(f,start+1,r,terms-1);
      Pair((f[start]+r*tail.o)%Q,tail.e)
  }

  lemma PairEvalStep(f: seq<int>, start: nat, r: int, terms: nat)
    requires S.Canonical(f) && start+terms <= 256
    ensures terms == 0 ==> PairEval(f,start,r,terms) == Pair(0,0)
    ensures terms > 0 ==> (PairEval(f,start,r,terms) ==
      Pair((f[start]+r*PairEval(f,start+1,r,terms-1).o)%Q,PairEval(f,start+1,r,terms-1).e))
  { reveal PairEval(); }

  lemma EvalHead(f: seq<int>, start: nat, stride: nat, r: int, terms: nat)
    requires stride > 0 && start+stride*terms < |f|
    ensures S.Eval(f,start,stride,r,terms+1) == (f[start]+r*S.Eval(f,start+stride,stride,r,terms))%Q
  {}

  lemma {:induction false} PairEvalBoth(f: seq<int>, start: nat, r: int, terms: nat)
    requires S.Canonical(f) && start+terms <= 256
    ensures PairEval(f,start,r,terms) ==
      Pair(S.Eval(f,start,2,r,(terms+1)/2),S.Eval(f,start+1,2,r,terms/2))
    decreases terms
  {
    PairEvalStep(f,start,r,terms);
    if terms >= 1 { PairEvalStep(f,start+1,r,terms-1); }
    if terms >= 2 { PairEvalBoth(f,start+2,r,terms-2); }
  }

  ghost function Zero(): seq<int>
    ensures S.Canonical(Zero())
  { seq(256,i requires 0 <= i < 256 => 0) }

  // Multiplication by X in Z_q[X]/(X^256+1).
  ghost function Shift(f: seq<int>): seq<int>
    requires S.Canonical(f)
    ensures S.Canonical(Shift(f))
  { seq(256,i requires 0 <= i < 256 => if i == 0 then (-f[255])%Q else f[i-1]) }

  // Ordinary polynomial multiplication evaluated by Horner's rule, with every
  // multiplication by X reduced using X^256 == -1. Independent of the NTT.
  ghost function {:opaque} ProductFrom(f: seq<int>, g: seq<int>, start: nat): seq<int>
    requires S.Canonical(f) && S.Canonical(g) && start <= 256
    ensures S.Canonical(ProductFrom(f,g,start))
    decreases 256-start
  {
    if start == 256 then Zero() else
      S.Add(S.Scale(f,g[start]),Shift(ProductFrom(f,g,start+1)))
  }

  ghost function NegacyclicProduct(f: seq<int>, g: seq<int>): seq<int>
    requires S.Canonical(f) && S.Canonical(g)
    ensures S.Canonical(NegacyclicProduct(f,g))
  { ProductFrom(f,g,0) }

  lemma {:induction false} {:isolate_assertions} PowerSquare(a: int, n: nat)
    ensures S.Power(a,2*n) == S.Power((a*a)%Q,n)
    decreases n
  {
    S.PowerStep(a,0);
    S.PowerStep((a*a)%Q,0);
    if n > 0 {
      PowerSquare(a,n-1);
      S.PowerAdd(a,2*(n-1),2);
      S.PowerStep(a,1);
      S.ModProduct(a,a);
      assert S.Power(a,2) == (a*a)%Q;
      S.PowerStep((a*a)%Q,n-1);
      var z := (a*a)%Q;
      var h := S.Power(z,n-1);
      assert S.Power(a,2*n) == (h*z)%Q;
      assert S.Power(z,n) == (z*h)%Q;
      assert h*z == z*h;
    }
  }

  lemma {:induction false} RootPower(stages: nat, b: nat)
    requires stages <= 7 && b < S.Factor(stages)
    ensures S.Power(S.TreeRoot(stages,b),S.Factor(stages)) == Q-1
    decreases stages
  {
    if stages == 0 { S.PowerStep(Q-1,0); }
    else {
      S.FactorStep(stages-1);
      S.RootSplit(stages-1,b/2);
      RootPower(stages-1,b/2);
      assert (S.TreeRoot(stages,b)*S.TreeRoot(stages,b))%Q == S.TreeRoot(stages-1,b/2);
      PowerSquare(S.TreeRoot(stages,b),S.Factor(stages-1));
    }
  }

  lemma GammaPower(b: nat)
    requires b < 128
    ensures S.Power(S.Gamma(b),128) == Q-1
  { RootPower(7,b); S.LeafGamma(b); }

  ghost function {:opaque} At(f: seq<int>, start: nat, stride: nat, i: nat): int
    requires start+stride*i < |f|
    ensures At(f,start,stride,i) == f[start+stride*i]
  { f[start+stride*i] }

  lemma {:induction false} {:isolate_assertions} EvalEqual(f: seq<int>, g: seq<int>, startF: nat, startG: nat,
                  stride: nat, r: int, terms: nat)
    requires S.Canonical(f) && S.Canonical(g) && stride > 0
    requires terms == 0 || (startF+stride*(terms-1) < 256 && startG+stride*(terms-1) < 256)
    requires forall i {:trigger At(f,startF,stride,i)} :: 0 <= i < terms ==> At(f,startF,stride,i) == At(g,startG,stride,i)
    ensures S.Eval(f,startF,stride,r,terms) == S.Eval(g,startG,stride,r,terms)
    decreases terms
  {
    if terms > 0 {
      assert At(f,startF,stride,0) == At(g,startG,stride,0);
      assert f[startF] == g[startG];
      forall i {:trigger At(f,startF+stride,stride,i)} | 0 <= i < terms-1
        ensures At(f,startF+stride,stride,i) == At(g,startG+stride,stride,i)
      {
        assert At(f,startF,stride,i+1) == At(g,startG,stride,i+1);
        assert startF+stride+stride*i == startF+stride*(i+1);
      }
      EvalEqual(f,g,startF+stride,startG+stride,stride,r,terms-1);
      EvalHead(f,startF,stride,r,terms-1);
      EvalHead(g,startG,stride,r,terms-1);
    }
  }

  lemma {:isolate_assertions} WrapArithmetic(a: int, b: int, r: int, p: int)
    requires (r*p)%Q == Q-1
    ensures ((-a)%Q+r*b)%Q == (r*((b+a*p)%Q))%Q
  {
    S.CongruentProduct(r,r,(b+a*p)%Q,b+a*p);
    S.ModProduct(r*p,a);
    assert ((r*p)*a)%Q == ((Q-1)*a)%Q;
    assert ((Q-1)*a)%Q == (-a)%Q;
    S.CongruentSum(r*b,r*b,(r*p)*a,-a);
    assert r*(b+a*p) == r*b+(r*p)*a;
    S.ModSum(-a,r*b);
  }

  lemma {:isolate_assertions} ShiftEvaluation(f: seq<int>, r: int)
    requires S.Canonical(f)
    ensures S.Eval(Shift(f),1,2,r,128) == S.Eval(f,0,2,r,128)
    ensures S.Eval(Shift(f),0,2,r,128) == ((-f[255])%Q+r*S.Eval(f,1,2,r,127))%Q
  {
    forall i | 0 <= i < 128
      ensures At(Shift(f),1,2,i) == At(f,0,2,i)
    {}
    EvalEqual(Shift(f),f,1,0,2,r,128);
    forall i | 0 <= i < 127
      ensures At(Shift(f),2,2,i) == At(f,1,2,i)
    {}
    EvalEqual(Shift(f),f,2,1,2,r,127);
    EvalHead(Shift(f),0,2,r,127);
  }

  lemma {:isolate_assertions} PairEvalShift(f: seq<int>, r: int)
    requires S.Canonical(f) && S.Power(r,128) == Q-1
    ensures PairEval(Shift(f),0,r,256) == TimesX(PairEval(f,0,r,256),r)
  {
    PairEvalBoth(f,0,r,256);
    PairEvalBoth(Shift(f),0,r,256);
    ShiftEvaluation(f,r);
    S.EvalAppend(f,1,2,r,127);
    S.PowerStep(r,127);
    WrapArithmetic(f[255],S.Eval(f,1,2,r,127),r,S.Power(r,127));
  }

  lemma {:isolate_assertions} ScaleScalar(a: int, b: int, c: int, r: int)
    ensures ((c*a)%Q+r*((c*b)%Q))%Q == (c*((a+r*b)%Q))%Q
  {
    S.CongruentProduct(r,r,(c*b)%Q,c*b);
    S.CongruentSum((c*a)%Q,c*a,r*((c*b)%Q),r*(c*b));
    S.ModProduct(a+r*b,c);
    assert c*a+r*(c*b) == c*(a+r*b);
  }

  lemma {:isolate_assertions} SumScalar(a: int, b: int, c: int, d: int, r: int)
    ensures ((a+c)%Q+r*((b+d)%Q))%Q == ((a+r*b)%Q+(c+r*d)%Q)%Q
  {
    S.CongruentProduct(r,r,(b+d)%Q,b+d);
    S.CongruentSum((a+c)%Q,a+c,r*((b+d)%Q),r*(b+d));
    S.ModSum(a+r*b,c+r*d);
    assert a+c+r*(b+d) == (a+r*b)+(c+r*d);
  }

  lemma {:induction false} PairEvalScale(f: seq<int>, c: int, start: nat, r: int, terms: nat)
    requires S.Canonical(f) && start+terms <= 256
    ensures PairEval(S.Scale(f,c),start,r,terms) == PairScale(PairEval(f,start,r,terms),c)
    decreases terms
  {
    PairEvalStep(f,start,r,terms);
    PairEvalStep(S.Scale(f,c),start,r,terms);
    if terms > 0 {
      PairEvalScale(f,c,start+1,r,terms-1);
      ScaleScalar(f[start],PairEval(f,start+1,r,terms-1).o,c,r);
    }
  }

  lemma AddAt(f: seq<int>, g: seq<int>, i: nat)
    requires S.Canonical(f) && S.Canonical(g) && i < 256
    ensures S.Add(f,g)[i] == (f[i]+g[i])%Q
  {}

  lemma PairCombine(x: int, y: int, a: Residue, b: Residue, r: int)
    ensures PairAdd(Pair((x+r*a.o)%Q,a.e),Pair((y+r*b.o)%Q,b.e)) ==
      Pair(((x+y)%Q+r*((a.o+b.o)%Q))%Q,(a.e+b.e)%Q)
  { SumScalar(x,a.o,y,b.o,r); }

  lemma {:induction false} {:isolate_assertions} PairEvalAdd(f: seq<int>, g: seq<int>, start: nat, r: int, terms: nat)
    requires S.Canonical(f) && S.Canonical(g) && start+terms <= 256
    ensures PairEval(S.Add(f,g),start,r,terms) ==
      PairAdd(PairEval(f,start,r,terms),PairEval(g,start,r,terms))
    decreases terms
  {
    PairEvalStep(f,start,r,terms);
    PairEvalStep(g,start,r,terms);
    PairEvalStep(S.Add(f,g),start,r,terms);
    if terms > 0 {
      PairEvalAdd(f,g,start+1,r,terms-1);
      AddAt(f,g,start);
      var a := PairEval(f,start+1,r,terms-1);
      var b := PairEval(g,start+1,r,terms-1);
      assert PairEval(f,start,r,terms) == Pair((f[start]+r*a.o)%Q,a.e);
      assert PairEval(g,start,r,terms) == Pair((g[start]+r*b.o)%Q,b.e);
      PairCombine(f[start],g[start],a,b,r);
    }
  }

  lemma {:induction false} PairEvalZero(start: nat, r: int, terms: nat)
    requires start+terms <= 256
    ensures PairEval(Zero(),start,r,terms) == Pair(0,0)
    decreases terms
  {
    PairEvalStep(Zero(),start,r,terms);
    if terms > 0 { PairEvalZero(start+1,r,terms-1); }
  }

  lemma {:isolate_assertions} ProductScalar(a: int, b: int, c: int, d: int, k: int, r: int)
    ensures ((k*a)%Q+(r*((a*d+b*c)%Q))%Q)%Q == (a*((k+r*d)%Q)+r*b*c)%Q
    ensures ((k*b)%Q+(a*c+r*b*d)%Q)%Q == (a*c+b*((k+r*d)%Q))%Q
  {
    S.ModSum(k*a,r*((a*d+b*c)%Q));
    S.CongruentProduct(r,r,(a*d+b*c)%Q,a*d+b*c);
    S.CongruentSum(k*a,k*a,r*((a*d+b*c)%Q),r*(a*d+b*c));
    S.CongruentProduct(a,a,(k+r*d)%Q,k+r*d);
    S.CongruentSum(a*((k+r*d)%Q),a*(k+r*d),r*b*c,r*b*c);
    assert k*a+r*(a*d+b*c) == a*(k+r*d)+r*b*c;
    S.ModSum(k*b,a*c+r*b*d);
    S.CongruentProduct(b,b,(k+r*d)%Q,k+r*d);
    S.CongruentSum(a*c,a*c,b*((k+r*d)%Q),b*(k+r*d));
    assert k*b+(a*c+r*b*d) == a*c+b*(k+r*d);
  }

  lemma PairProductStep(a: Residue, tail: Residue, k: int, r: int)
    requires PairCanonical(a) && PairCanonical(tail)
    ensures PairAdd(PairScale(a,k),TimesX(PairProduct(a,tail,r),r)) ==
      PairProduct(a,Pair((k+r*tail.o)%Q,tail.e),r)
  { ProductScalar(a.e,a.o,tail.e,tail.o,k,r); }

  lemma ProductFromZero(f: seq<int>, g: seq<int>)
    requires S.Canonical(f) && S.Canonical(g)
    ensures ProductFrom(f,g,256) == Zero()
  { reveal ProductFrom(); }

  lemma ProductFromStep(f: seq<int>, g: seq<int>, start: nat)
    requires S.Canonical(f) && S.Canonical(g) && start < 256
    ensures ProductFrom(f,g,start) == S.Add(S.Scale(f,g[start]),Shift(ProductFrom(f,g,start+1)))
  { reveal ProductFrom(); }

  lemma {:induction false} PairEvalProduct(f: seq<int>, g: seq<int>, start: nat, r: int)
    requires S.Canonical(f) && S.Canonical(g) && start <= 256
    requires S.Power(r,128) == Q-1
    ensures PairEval(ProductFrom(f,g,start),0,r,256) ==
      PairProduct(PairEval(f,0,r,256),PairEval(g,start,r,256-start),r)
    decreases 256-start
  {
    PairEvalStep(g,start,r,256-start);
    if start == 256 {
      ProductFromZero(f,g);
      PairEvalZero(0,r,256);
    } else {
      ProductFromStep(f,g,start);
      PairEvalProduct(f,g,start+1,r);
      PairEvalScale(f,g[start],0,r,256);
      PairEvalShift(ProductFrom(f,g,start+1),r);
      PairEvalAdd(S.Scale(f,g[start]),Shift(ProductFrom(f,g,start+1)),0,r,256);
      PairProductStep(PairEval(f,0,r,256),PairEval(g,start+1,r,255-start),g[start],r);
    }
  }

  lemma NttMulPair(f: seq<int>, g: seq<int>, b: nat)
    requires S.Canonical(f) && S.Canonical(g) && b < 128
    ensures Pair(S.NttMul(f,g)[2*b],S.NttMul(f,g)[2*b+1]) ==
      PairProduct(Pair(f[2*b],f[2*b+1]),Pair(g[2*b],g[2*b+1]),S.Gamma(b))
  {}

  lemma NttCoefficient(f: seq<int>, i: nat)
    requires S.Canonical(f) && i < 256
    ensures S.Ntt(f)[i] == S.Eval(f,i%2,2,S.Gamma(i/2),128)
  { S.NttHornerRepresentation(f); }

  lemma NttResidue(f: seq<int>, b: nat)
    requires S.Canonical(f) && b < 128
    ensures Pair(S.Ntt(f)[2*b],S.Ntt(f)[2*b+1]) == PairEval(f,0,S.Gamma(b),256)
  {
    NttCoefficient(f,2*b);
    NttCoefficient(f,2*b+1);
    PairEvalBoth(f,0,S.Gamma(b),256);
  }

  lemma NttProductPair(f: seq<int>, g: seq<int>, b: nat)
    requires S.Canonical(f) && S.Canonical(g) && b < 128
    ensures Pair(S.Ntt(NegacyclicProduct(f,g))[2*b],S.Ntt(NegacyclicProduct(f,g))[2*b+1]) ==
      Pair(S.NttMul(S.Ntt(f),S.Ntt(g))[2*b],S.NttMul(S.Ntt(f),S.Ntt(g))[2*b+1])
  {
    GammaPower(b);
    PairEvalProduct(f,g,0,S.Gamma(b));
    NttResidue(f,b);
    NttResidue(g,b);
    NttResidue(NegacyclicProduct(f,g),b);
    NttMulPair(S.Ntt(f),S.Ntt(g),b);
  }

  lemma NttProduct(f: seq<int>, g: seq<int>)
    requires S.Canonical(f) && S.Canonical(g)
    ensures S.Ntt(NegacyclicProduct(f,g)) == S.NttMul(S.Ntt(f),S.Ntt(g))
  {
    forall i | 0 <= i < 256
      ensures S.Ntt(NegacyclicProduct(f,g))[i] == S.NttMul(S.Ntt(f),S.Ntt(g))[i]
    { NttProductPair(f,g,i/2); }
  }

  lemma NegacyclicViaNtt(f: seq<int>, g: seq<int>)
    requires S.Canonical(f) && S.Canonical(g)
    ensures S.InverseNtt(S.NttMul(S.Ntt(f),S.Ntt(g))) == NegacyclicProduct(f,g)
  {
    NttProduct(f,g);
    S.NttRoundTrip(NegacyclicProduct(f,g));
  }
  lemma CongruentDifference(a: int, b: int, c: int, d: int)
    requires a%Q == b%Q && c%Q == d%Q
    ensures (a-c)%Q == (b-d)%Q
  { S.ModSum(a,c); S.ModSum(b,d); }

  lemma {:isolate_assertions} ReverseButterfly(a: int, b: int, z: int, w: int)
    requires (z*w)%Q == Q-1
    ensures ((a+b)%Q+z*((w*(b-a))%Q))%Q == (2*a)%Q
    ensures ((a+b)%Q-z*((w*(b-a))%Q))%Q == (2*b)%Q
  {
    S.CongruentProduct(z,z,(w*(b-a))%Q,w*(b-a));
    S.ModProduct(z*w,b-a);
    assert z*(w*(b-a)) == (z*w)*(b-a);
    assert ((Q-1)*(b-a))%Q == (a-b)%Q;
    assert (z*((w*(b-a))%Q))%Q == (a-b)%Q;
    S.CongruentSum((a+b)%Q,a+b,z*((w*(b-a))%Q),a-b);
    CongruentDifference((a+b)%Q,a+b,z*((w*(b-a))%Q),a-b);
  }

  lemma StageReverse(f: seq<int>, s: nat)
    requires S.Canonical(f) && s < 7
    ensures S.ForwardStage(S.InverseStage(f,6-s),s) == S.Scale(f,2)
  {
    var l := S.Len(s);
    var h := S.InverseStage(f,6-s);
    forall i | 0 <= i < 256
      ensures S.ForwardStage(h,s)[i] == S.Scale(f,2)[i]
    {
      S.StageBounds(s,i); S.StagePartner(s,i);
      var b := i/(2*l);
      assert b < 128/l;
      S.InverseRoots(s,b);
      var z := S.Zeta(128/l+b);
      var w := S.Zeta(256/l-1-b);
      if i%(2*l) < l { ReverseButterfly(f[i],f[i+l],z,w); }
      else { ReverseButterfly(f[i-l],f[i],z,w); }
    }
  }

  lemma ScaleScalarMinus(a: int, b: int, c: int, z: int)
    ensures ((c*a)%Q-z*((c*b)%Q))%Q == (c*((a-z*b)%Q))%Q
  { ScaleScalar(a,b,c,-z); }

  lemma ForwardScale(f: seq<int>, s: nat, c: int)
    requires S.Canonical(f) && s < 7
    ensures S.ForwardStage(S.Scale(f,c),s) == S.Scale(S.ForwardStage(f,s),c)
  {
    var l := S.Len(s);
    forall i | 0 <= i < 256
      ensures S.ForwardStage(S.Scale(f,c),s)[i] == S.Scale(S.ForwardStage(f,s),c)[i]
    {
      S.StageBounds(s,i);
      var z := S.Zeta(128/l+i/(2*l));
      if i%(2*l) < l { ScaleScalar(f[i],f[i+l],c,z); }
      else { ScaleScalarMinus(f[i-l],f[i],c,z); }
    }
  }

  lemma {:induction false} ForwardPrefixScale(f: seq<int>, c: int, k: nat)
    requires S.Canonical(f) && k <= 7
    ensures S.NttPrefix(S.Scale(f,c),k) == S.Scale(S.NttPrefix(f,k),c)
    decreases k
  {
    if k == 0 { S.NttPrefixZero(f); S.NttPrefixZero(S.Scale(f,c)); }
    else {
      ForwardPrefixScale(f,c,k-1);
      S.NttPrefixStep(f,k-1); S.NttPrefixStep(S.Scale(f,c),k-1);
      ForwardScale(S.NttPrefix(f,k-1),k-1,c);
    }
  }

  lemma {:induction false} InverseCancelPrefix(f: seq<int>, k: nat)
    requires S.Canonical(f) && k <= 7
    ensures S.NttPrefix(S.InversePrefix(f,7),k) == S.Scale(S.InversePrefix(f,7-k),S.Factor(k))
    decreases k
  {
    if k == 0 {
      S.NttPrefixZero(S.InversePrefix(f,7));
      S.ScaleIdentity(S.InversePrefix(f,7),1);
    } else {
      InverseCancelPrefix(f,k-1);
      S.NttPrefixStep(S.InversePrefix(f,7),k-1);
      ForwardScale(S.InversePrefix(f,8-k),k-1,S.Factor(k-1));
      assert S.InversePrefix(f,8-k) == S.InverseStage(S.InversePrefix(f,7-k),7-k);
      StageReverse(S.InversePrefix(f,7-k),k-1);
      S.ScaleCompose(S.InversePrefix(f,7-k),2,S.Factor(k-1));
      S.FactorStep(k-1);
    }
  }

  lemma NttInverseRoundTrip(f: seq<int>)
    requires S.Canonical(f)
    ensures S.Ntt(S.InverseNtt(f)) == f
  {
    InverseCancelPrefix(f,7);
    ForwardPrefixScale(S.InversePrefix(f,7),3303,7);
    S.ScaleCompose(f,128,3303);
    S.ScaleIdentity(f,128*3303);
  }

}
