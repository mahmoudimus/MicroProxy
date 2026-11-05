include "NativeTypes.dfy"
include "../primitives/Keccak.dfy"
include "../source/SourceTrace.dfy"

// Array refinement of the FIPS202 permutation. All runtime indices are native
// signed Java ints with their bounds verified; values are native bv64 longs.
//
// Every declaration carries a ghost observation trace built only from the
// canonical SourceTrace markers and the exact child traces returned by callees.
// The value expressions, contracts and alias/frame domains are the released
// ones; trace summaries below are ghost-only specifications.
module NativeKeccak {
  import T = NativeTypes
  import S = KeccakSpec
  import ST = SourceTrace

  // ---------- specification-only trace summaries (ghost) ----------
  ghost function RotateTrace(n: T.I): seq<int>
    requires 0 <= n < 64
  { if n == 0 then ST.Branch(0,true)
    else ST.Branch(0,false) + ST.Ops(0,1,0,0,0,1,2) }

  ghost function ConstantTrace(i: T.I): seq<int>
    requires 0 <= i < 24
  { if i == 0 then ST.Branch(0,true)

    else if i == 1 then ST.Branch(0,false) + ST.Branch(1,true)

    else if i == 2 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,true)

    else if i == 3 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,true)

    else if i == 4 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,true)
    else if i == 5 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,true)
    else if i == 6 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,true)
    else if i == 7 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,true)
    else if i == 8 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,true)
    else if i == 9 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,true)
    else if i == 10 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,true)
    else if i == 11 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,true)
    else if i == 12 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,true)
    else if i == 13 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,true)
    else if i == 14 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,true)
    else if i == 15 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,true)
    else if i == 16 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,true)
    else if i == 17 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,true)
    else if i == 18 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,true)
    else if i == 19 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,true)
    else if i == 20 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,true)
    else if i == 21 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,true)
    else if i == 22 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,true)
    else ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false) }

  ghost function OffsetTrace(i: T.I): seq<int>
    requires 0 <= i < 25
  { if i == 0 then ST.Branch(0,true)

    else if i == 1 then ST.Branch(0,false) + ST.Branch(1,true)

    else if i == 2 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,true)

    else if i == 3 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,true)

    else if i == 4 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,true)
    else if i == 5 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,true)
    else if i == 6 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,true)
    else if i == 7 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,true)
    else if i == 8 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,true)
    else if i == 9 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,true)
    else if i == 10 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,true)
    else if i == 11 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,true)
    else if i == 12 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,true)
    else if i == 13 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,true)
    else if i == 14 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,true)
    else if i == 15 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,true)
    else if i == 16 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,true)
    else if i == 17 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,true)
    else if i == 18 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,true)
    else if i == 19 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,true)
    else if i == 20 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,true)
    else if i == 21 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,true)
    else if i == 22 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,true)
    else if i == 23 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false) + ST.Branch(23,true)
    else ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false) + ST.Branch(23,false) }

  ghost function SourceTraceTable(i: T.I): seq<int>
    requires 0 <= i < 25
  { if i == 0 then ST.Branch(0,true)

    else if i == 1 then ST.Branch(0,false) + ST.Branch(1,true)

    else if i == 2 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,true)

    else if i == 3 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,true)

    else if i == 4 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,true)
    else if i == 5 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,true)
    else if i == 6 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,true)
    else if i == 7 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,true)
    else if i == 8 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,true)
    else if i == 9 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,true)
    else if i == 10 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,true)
    else if i == 11 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,true)
    else if i == 12 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,true)
    else if i == 13 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,true)
    else if i == 14 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,true)
    else if i == 15 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,true)
    else if i == 16 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,true)
    else if i == 17 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,true)
    else if i == 18 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,true)
    else if i == 19 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,true)
    else if i == 20 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,true)
    else if i == 21 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,true)
    else if i == 22 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,true)
    else if i == 23 then ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false) + ST.Branch(23,true)
    else ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false) + ST.Branch(23,false) }

  ghost function OffsetsStep(i: int): seq<int>
    requires 0 <= i < 25
  { ST.LoopCheck(3,true,i) + ST.Call(4,23,1) + OffsetTrace(i as T.I) + ST.Write(5,0,i) }
  ghost function {:opaque} OffsetsUpTo(n: int): seq<int>
    requires 0 <= n <= 25
    decreases n
  { if n <= 0 then [] else OffsetsUpTo(n-1) + OffsetsStep(n-1) }
  lemma OffsetsUpToZero()
    ensures OffsetsUpTo(0) == []
  { reveal OffsetsUpTo(); }
  lemma OffsetsUpToSucc(n: int)
    requires 0 <= n < 25
    ensures OffsetsUpTo(n+1) == OffsetsUpTo(n) + OffsetsStep(n)
  { reveal OffsetsUpTo(); }
  ghost function NewOffsetsTrace(): seq<int>
  { ST.Alloc(0,25) + ST.LoopBound(1,0) + ST.LoopBound(2,25)
    + OffsetsUpTo(25) + ST.LoopCheck(3,false,25) }

  ghost function SourcesStep(i: int): seq<int>
    requires 0 <= i < 25
  { ST.LoopCheck(3,true,i) + ST.Call(4,24,1) + SourceTraceTable(i as T.I) + ST.Write(5,0,i) }
  ghost function {:opaque} SourcesUpTo(n: int): seq<int>
    requires 0 <= n <= 25
    decreases n
  { if n <= 0 then [] else SourcesUpTo(n-1) + SourcesStep(n-1) }
  lemma SourcesUpToZero()
    ensures SourcesUpTo(0) == []
  { reveal SourcesUpTo(); }
  lemma SourcesUpToSucc(n: int)
    requires 0 <= n < 25
    ensures SourcesUpTo(n+1) == SourcesUpTo(n) + SourcesStep(n)
  { reveal SourcesUpTo(); }
  ghost function NewSourcesTrace(): seq<int>
  { ST.Alloc(0,25) + ST.LoopBound(1,0) + ST.LoopBound(2,25)
    + SourcesUpTo(25) + ST.LoopCheck(3,false,25) }

  ghost function SetLaneTrace(index: T.I): seq<int>
    requires 0 <= index < 25
  { ST.Write(0,0,index as int) }
  ghost function IotaTrace(): seq<int>
  { ST.Read(0,0,0) + ST.Ops(0,0,0,0,0,1,0) + ST.Call(1,10,3) + SetLaneTrace(0) }

  ghost function ThetaColumnStep(x: int): seq<int>
    requires 0 <= x < 5
  { ST.LoopCheck(2,true,x) + ST.Read(3,0,x)
    + ST.Ops(1,0,0,0,0,0,0) + ST.Read(4,0,x+5) + ST.Ops(0,0,0,0,0,1,0)
    + ST.Ops(1,0,0,0,0,0,0) + ST.Read(5,0,x+10) + ST.Ops(0,0,0,0,0,1,0)
    + ST.Ops(1,0,0,0,0,0,0) + ST.Read(6,0,x+15) + ST.Ops(0,0,0,0,0,1,0)
    + ST.Ops(1,0,0,0,0,0,0) + ST.Read(7,0,x+20) + ST.Ops(0,0,0,0,0,1,0)
    + ST.Write(8,1,x) }
  ghost function {:opaque} ThetaColumnUpTo(n: int): seq<int>
    requires 0 <= n <= 5
    decreases n
  { if n <= 0 then [] else ThetaColumnUpTo(n-1) + ThetaColumnStep(n-1) }
  lemma ThetaColumnUpToZero()
    ensures ThetaColumnUpTo(0) == []
  { reveal ThetaColumnUpTo(); }
  lemma ThetaColumnUpToSucc(n: int)
    requires 0 <= n < 5
    ensures ThetaColumnUpTo(n+1) == ThetaColumnUpTo(n) + ThetaColumnStep(n)
  { reveal ThetaColumnUpTo(); }
  ghost function ThetaDStep(x: int): seq<int>
    requires 0 <= x < 5
  { ST.LoopCheck(11,true,x)
    + ST.Ops(1,0,0,0,0,0,0) + ST.Ops(0,0,0,0,1,0,0) + ST.Read(12,1,(x+4)%5)
    + ST.Ops(1,0,0,0,0,0,0) + ST.Ops(0,0,0,0,1,0,0) + ST.Read(13,1,(x+1)%5)
    + ST.Call(14,20,2) + RotateTrace(1) + ST.Ops(0,0,0,0,0,1,0)
    + ST.LoopBound(15,0) + ST.LoopBound(16,5) }
  ghost function ThetaInnerStep(x: int, y: int): seq<int>
    requires 0 <= x < 5 && 0 <= y < 5
  { ST.LoopCheck(17,true,y) + ST.Ops(0,0,1,0,0,0,0) + ST.Ops(1,0,0,0,0,0,0)
    + ST.Read(18,0,x+5*y) + ST.Ops(0,0,0,0,0,1,0) + ST.Write(19,0,x+5*y) }
  ghost function {:opaque} ThetaInnerUpTo(x: int, n: int): seq<int>
    requires 0 <= x < 5 && 0 <= n <= 5
    decreases n
  { if n <= 0 then [] else ThetaInnerUpTo(x,n-1) + ThetaInnerStep(x,n-1) }
  lemma ThetaInnerUpToZero(x: int)
    requires 0 <= x < 5
    ensures ThetaInnerUpTo(x,0) == []
  { reveal ThetaInnerUpTo(); }
  lemma ThetaInnerUpToSucc(x: int, n: int)
    requires 0 <= x < 5 && 0 <= n < 5
    ensures ThetaInnerUpTo(x,n+1) == ThetaInnerUpTo(x,n) + ThetaInnerStep(x,n)
  { reveal ThetaInnerUpTo(); }
  ghost function ThetaLaneStep(x: int): seq<int>
    requires 0 <= x < 5
  { ThetaDStep(x) + ThetaInnerUpTo(x,5) + ST.LoopCheck(17,false,5) }
  ghost function {:opaque} ThetaLaneUpTo(n: int): seq<int>
    requires 0 <= n <= 5
    decreases n
  { if n <= 0 then [] else ThetaLaneUpTo(n-1) + ThetaLaneStep(n-1) }
  lemma ThetaLaneUpToZero()
    ensures ThetaLaneUpTo(0) == []
  { reveal ThetaLaneUpTo(); }
  lemma ThetaLaneUpToSucc(n: int)
    requires 0 <= n < 5
    ensures ThetaLaneUpTo(n+1) == ThetaLaneUpTo(n) + ThetaLaneStep(n)
  { reveal ThetaLaneUpTo(); }
  ghost function ThetaColumns(): seq<int>
  { ST.LoopBound(0,0) + ST.LoopBound(1,5) + ThetaColumnUpTo(5) + ST.LoopCheck(2,false,5) }
  ghost function ThetaLanes(): seq<int>
  { ST.LoopBound(9,0) + ST.LoopBound(10,5) + ThetaLaneUpTo(5) + ST.LoopCheck(11,false,5) }
  ghost function ThetaTrace(): seq<int>
  { ThetaColumns() + ThetaLanes() }

  ghost function SourceIndexAt(i: int): int
    requires 0 <= i < 25
    ensures 0 <= SourceIndexAt(i) < 25
  { ((i%5)+3*(i/5))%5+5*(i%5) }
  ghost function RotateDistanceAt(j: int): T.I
    requires 0 <= j < 25
    ensures 0 <= RotateDistanceAt(j) < 64
  { (S.Offsets()[j]%64) as T.I }
  ghost function RhoPiStep(i: int): seq<int>
    requires 0 <= i < 25
  { ST.LoopCheck(2,true,i) + ST.Read(3,3,i)
    + ST.Read(4,0,SourceIndexAt(i)) + ST.Read(5,2,SourceIndexAt(i))
    + ST.Call(6,20,2) + RotateTrace(RotateDistanceAt(SourceIndexAt(i))) + ST.Write(7,1,i) }
  ghost function {:opaque} RhoPiUpTo(n: int): seq<int>
    requires 0 <= n <= 25
    decreases n
  { if n <= 0 then [] else RhoPiUpTo(n-1) + RhoPiStep(n-1) }
  lemma RhoPiUpToZero()
    ensures RhoPiUpTo(0) == []
  { reveal RhoPiUpTo(); }
  lemma RhoPiUpToSucc(n: int)
    requires 0 <= n < 25
    ensures RhoPiUpTo(n+1) == RhoPiUpTo(n) + RhoPiStep(n)
  { reveal RhoPiUpTo(); }
  ghost function RhoPiTrace(): seq<int>
  { ST.LoopBound(0,0) + ST.LoopBound(1,25) + RhoPiUpTo(25) + ST.LoopCheck(2,false,25) }

  ghost function ChiStep(i: int): seq<int>
    requires 0 <= i < 25
  { ST.LoopCheck(2,true,i)
    + ST.Ops(0,0,0,1,0,0,0) + ST.Ops(0,0,1,0,0,0,0) + ST.Ops(0,0,0,0,1,0,0)
    + ST.Read(3,1,i)
    + ST.Ops(1,0,0,0,0,0,0) + ST.Ops(0,0,0,0,1,0,0) + ST.Ops(1,0,0,0,0,0,0)
    + ST.Read(4,1,5*(i/5)+(i%5+1)%5) + ST.Ops(0,0,0,0,0,1,0)
    + ST.Ops(1,0,0,0,0,0,0) + ST.Ops(0,0,0,0,1,0,0) + ST.Ops(1,0,0,0,0,0,0)
    + ST.Read(5,1,5*(i/5)+(i%5+2)%5)
    + ST.Ops(0,0,0,0,0,1,0) + ST.Ops(0,0,0,0,0,1,0)
    + ST.Write(6,0,i) }
  ghost function {:opaque} ChiUpTo(n: int): seq<int>
    requires 0 <= n <= 25
    decreases n
  { if n <= 0 then [] else ChiUpTo(n-1) + ChiStep(n-1) }
  lemma ChiUpToZero()
    ensures ChiUpTo(0) == []
  { reveal ChiUpTo(); }
  lemma ChiUpToSucc(n: int)
    requires 0 <= n < 25
    ensures ChiUpTo(n+1) == ChiUpTo(n) + ChiStep(n)
  { reveal ChiUpTo(); }
  ghost function ChiTrace(): seq<int>
  { ST.LoopBound(0,0) + ST.LoopBound(1,25) + ChiUpTo(25) + ST.LoopCheck(2,false,25) }

  ghost function RoundTrace(): seq<int>
  { ST.Call(0,14,2) + ThetaTrace() + ST.Call(1,15,4) + RhoPiTrace()
    + ST.Call(2,13,2) + ChiTrace() + ST.Call(3,11,2) + IotaTrace() }

  ghost function PermuteScratchStep(i: int): seq<int>
    requires 0 <= i < 24
  { ST.LoopCheck(2,true,i) + ST.Call(3,22,1) + ConstantTrace(i as T.I)
    + ST.Call(4,16,6) + RoundTrace() }
  ghost function {:opaque} PermuteScratchUpTo(n: int): seq<int>
    requires 0 <= n <= 24
    decreases n
  { if n <= 0 then [] else PermuteScratchUpTo(n-1) + PermuteScratchStep(n-1) }
  lemma PermuteScratchUpToZero()
    ensures PermuteScratchUpTo(0) == []
  { reveal PermuteScratchUpTo(); }
  lemma PermuteScratchUpToSucc(n: int)
    requires 0 <= n < 24
    ensures PermuteScratchUpTo(n+1) == PermuteScratchUpTo(n) + PermuteScratchStep(n)
  { reveal PermuteScratchUpTo(); }
  ghost function PermuteScratchTrace(): seq<int>
  { ST.LoopBound(0,0) + ST.LoopBound(1,24) + PermuteScratchUpTo(24) + ST.LoopCheck(2,false,24) }

  ghost function WipeStep(i: int): seq<int>
    requires 0 <= i
  { ST.LoopCheck(2,true,i) + ST.Write(3,0,i) }
  ghost function {:opaque} WipeUpTo(n: int): seq<int>
    requires 0 <= n
    decreases n
  { if n <= 0 then [] else WipeUpTo(n-1) + WipeStep(n-1) }
  lemma WipeUpToZero()
    ensures WipeUpTo(0) == []
  { reveal WipeUpTo(); }
  lemma WipeUpToSucc(n: int)
    requires 0 <= n
    ensures WipeUpTo(n+1) == WipeUpTo(n) + WipeStep(n)
  { reveal WipeUpTo(); }
  ghost function WipeTrace(n: int): seq<int>
    requires 0 <= n
  { ST.LoopBound(0,0) + ST.LoopBound(1,n) + WipeUpTo(n) + ST.LoopCheck(2,false,n) }

  ghost function PermuteTrace(): seq<int>
  { ST.Alloc(0,25) + ST.Alloc(1,5)
    + ST.Call(2,19,0) + NewOffsetsTrace() + ST.Call(3,21,0) + NewSourcesTrace()
    + ST.Call(4,17,5) + PermuteScratchTrace()
    + ST.Call(5,12,1) + WipeTrace(25) + ST.Call(6,12,1) + WipeTrace(5) }

  // ---------- pure functions: original value tuple + ghost trace ----------
  function Rotate(v: bv64, n: T.I): (bv64, ghost seq<int>)
    requires 0 <= n < 64
    ensures Rotate(v,n).0 == S.Rotate(v,n as int)
    ensures Rotate(v,n).1 == RotateTrace(n)
  { if n == 0 then (v, ghost ST.Branch(0,true))
    else ((v << n) | (v >> (64-n)), ghost ST.Branch(0,false) + ST.Ops(0,1,0,0,0,1,2)) }
  function Constant(i: T.I): (bv64, ghost seq<int>)
    requires 0 <= i < 24
    ensures Constant(i).0 == S.Constants()[i]
    ensures Constant(i).1 == ConstantTrace(i)
  { if i == 0 then (0x0000000000000001, ghost ST.Branch(0,true)
)
    else if i == 1 then (0x0000000000008082, ghost ST.Branch(0,false) + ST.Branch(1,true)
)
    else if i == 2 then (0x800000000000808a, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,true)
)
    else if i == 3 then (0x8000000080008000, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,true)
)
    else if i == 4 then (0x000000000000808b, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,true))
    else if i == 5 then (0x0000000080000001, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,true))
    else if i == 6 then (0x8000000080008081, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,true))
    else if i == 7 then (0x8000000000008009, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,true))
    else if i == 8 then (0x000000000000008a, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,true))
    else if i == 9 then (0x0000000000000088, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,true))
    else if i == 10 then (0x0000000080008009, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,true))
    else if i == 11 then (0x000000008000000a, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,true))
    else if i == 12 then (0x000000008000808b, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,true))
    else if i == 13 then (0x800000000000008b, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,true))
    else if i == 14 then (0x8000000000008089, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,true))
    else if i == 15 then (0x8000000000008003, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,true))
    else if i == 16 then (0x8000000000008002, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,true))
    else if i == 17 then (0x8000000000000080, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,true))
    else if i == 18 then (0x000000000000800a, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,true))
    else if i == 19 then (0x800000008000000a, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,true))
    else if i == 20 then (0x8000000080008081, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,true))
    else if i == 21 then (0x8000000000008080, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,true))
    else if i == 22 then (0x0000000080000001, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,true))
    else (0x8000000080008008, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false)) }
  function Offset(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 25
    ensures 0 <= Offset(i).0 < 64 && Offset(i).0 as int == S.Offsets()[i]%64
    ensures Offset(i).1 == OffsetTrace(i)
  { if i == 0 then (0, ghost ST.Branch(0,true)
)
    else if i == 1 then (1, ghost ST.Branch(0,false) + ST.Branch(1,true)
)
    else if i == 2 then (62, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,true)
)
    else if i == 3 then (28, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,true)
)
    else if i == 4 then (27, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,true))
    else if i == 5 then (36, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,true))
    else if i == 6 then (44, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,true))
    else if i == 7 then (6, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,true))
    else if i == 8 then (55, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,true))
    else if i == 9 then (20, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,true))
    else if i == 10 then (3, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,true))
    else if i == 11 then (10, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,true))
    else if i == 12 then (43, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,true))
    else if i == 13 then (25, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,true))
    else if i == 14 then (39, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,true))
    else if i == 15 then (41, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,true))
    else if i == 16 then (45, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,true))
    else if i == 17 then (15, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,true))
    else if i == 18 then (21, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,true))
    else if i == 19 then (8, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,true))
    else if i == 20 then (18, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,true))
    else if i == 21 then (2, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,true))
    else if i == 22 then (61, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,true))
    else if i == 23 then (56, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false) + ST.Branch(23,true))
    else (14, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false) + ST.Branch(23,false)) }

  method NewOffsets() returns(r: array<T.I>, ghost trace: seq<int>)
    ensures fresh(r) && r.Length == 25
    ensures forall i: int :: 0 <= i < 25 ==> 0 <= r[i] < 64 && r[i] as int == S.Offsets()[i]%64
    ensures trace == NewOffsetsTrace()
  {
    trace := ST.Alloc(0,25);
    r := new T.I[25];
    trace := trace + ST.LoopBound(1,0) + ST.LoopBound(2,25);
    OffsetsUpToZero();
    for i: T.I := 0 to 25
      invariant 0 <= i <= 25
      invariant forall k: int :: 0 <= k < i as int ==> 0 <= r[k] < 64 && r[k] as int == S.Offsets()[k]%64
      invariant trace == ST.Alloc(0,25) + ST.LoopBound(1,0) + ST.LoopBound(2,25) + OffsetsUpTo(i as int)
    {
      ghost var callWitness := Offset(i);
      trace := trace + ST.LoopCheck(3,true,i as int) + ST.Call(4,23,1) + callWitness.1
        + ST.Write(5,0,i as int);
      assert callWitness.1 == OffsetTrace(i);
      assert callWitness == Offset(i);
      r[i] := Offset(i).0;
      OffsetsUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(3,false,25);
  }

  function Source(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 25
    ensures 0 <= Source(i).0 < 25
    ensures Source(i).0 as int == (((i as int)%5)+3*((i as int)/5))%5+5*((i as int)%5)
    ensures Source(i).1 == SourceTraceTable(i)
  { if i == 0 then (0, ghost ST.Branch(0,true)
)
    else if i == 1 then (6, ghost ST.Branch(0,false) + ST.Branch(1,true)
)
    else if i == 2 then (12, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,true)
)
    else if i == 3 then (18, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,true)
)
    else if i == 4 then (24, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,true))
    else if i == 5 then (3, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,true))
    else if i == 6 then (9, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,true))
    else if i == 7 then (10, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,true))
    else if i == 8 then (16, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,true))
    else if i == 9 then (22, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,true))
    else if i == 10 then (1, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,true))
    else if i == 11 then (7, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,true))
    else if i == 12 then (13, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,true))
    else if i == 13 then (19, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,true))
    else if i == 14 then (20, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,true))
    else if i == 15 then (4, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,true))
    else if i == 16 then (5, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,true))
    else if i == 17 then (11, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,true))
    else if i == 18 then (17, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,true))
    else if i == 19 then (23, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,true))
    else if i == 20 then (2, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,true))
    else if i == 21 then (8, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,true))
    else if i == 22 then (14, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,true))
    else if i == 23 then (15, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false) + ST.Branch(23,true))
    else (21, ghost ST.Branch(0,false) + ST.Branch(1,false) + ST.Branch(2,false) + ST.Branch(3,false)
          + ST.Branch(4,false) + ST.Branch(5,false) + ST.Branch(6,false) + ST.Branch(7,false)
          + ST.Branch(8,false) + ST.Branch(9,false) + ST.Branch(10,false) + ST.Branch(11,false)
          + ST.Branch(12,false) + ST.Branch(13,false) + ST.Branch(14,false) + ST.Branch(15,false)
          + ST.Branch(16,false) + ST.Branch(17,false) + ST.Branch(18,false) + ST.Branch(19,false)
          + ST.Branch(20,false) + ST.Branch(21,false) + ST.Branch(22,false) + ST.Branch(23,false)) }
  method NewSources() returns(r: array<T.I>, ghost trace: seq<int>)
    ensures fresh(r) && r.Length == 25
    ensures forall i: int :: 0 <= i < 25 ==> 0 <= r[i] < 25 && r[i] as int == ((i%5)+3*(i/5))%5+5*(i%5)
    ensures trace == NewSourcesTrace()
  {
    trace := ST.Alloc(0,25);
    r := new T.I[25];
    trace := trace + ST.LoopBound(1,0) + ST.LoopBound(2,25);
    SourcesUpToZero();
    for i: T.I := 0 to 25
      invariant 0 <= i <= 25
      invariant forall k: int :: 0 <= k < i as int ==> 0 <= r[k] < 25 && r[k] as int == ((k%5)+3*(k/5))%5+5*(k%5)
      invariant trace == ST.Alloc(0,25) + ST.LoopBound(1,0) + ST.LoopBound(2,25) + SourcesUpTo(i as int)
    {
      ghost var callWitness := Source(i);
      trace := trace + ST.LoopCheck(3,true,i as int) + ST.Call(4,24,1) + callWitness.1
        + ST.Write(5,0,i as int);
      assert callWitness.1 == SourceTraceTable(i);
      assert callWitness == Source(i);
      r[i] := Source(i).0;
      SourcesUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(3,false,25);
  }
  method SetLane(a: array<bv64>, index: T.I, value: bv64) returns(ghost trace: seq<int>)
    requires a.Length == 25 && 0 <= index < 25
    modifies a
    ensures a[..] == old(a[..])[index as int := value]
    ensures trace == SetLaneTrace(index)
  {
    trace := ST.Write(0,0,index as int);
    ghost var before := a[..];
    a[index] := value;
    forall j: int | 0 <= j < 25
      ensures a[j] == before[index as int := value][j]
    { if j == index as int {} }
  }

  method Iota(a: array<bv64>, rc: bv64) returns(ghost trace: seq<int>)
    requires a.Length == 25
    modifies a
    ensures a[..] == S.Iota(old(a[..]),rc)
    ensures trace == IotaTrace()
  {
    trace := ST.Read(0,0,0) + ST.Ops(0,0,0,0,0,1,0);
    var value := a[0]^rc;
    ghost var childTrace: seq<int>;
    childTrace := SetLane(a,0,value);
    trace := trace + ST.Call(1,10,3) + childTrace;
  }

  method {:isolate_assertions} Theta(a: array<bv64>, c: array<bv64>) returns(ghost trace: seq<int>)
    requires a.Length == 25 && c.Length == 5 && a != c
    modifies a,c
    ensures a[..] == S.Theta(old(a[..]))
    ensures trace == ThetaTrace()
  {
    trace := ST.LoopBound(0,0) + ST.LoopBound(1,5);
    ghost var start := a[..];
    ThetaColumnUpToZero();
    for x: T.I := 0 to 5
      modifies c
      invariant 0 <= x <= 5
      invariant forall k: int :: 0 <= k < x as int ==> c[k] == S.Column(start,k)
      invariant trace == ST.LoopBound(0,0) + ST.LoopBound(1,5) + ThetaColumnUpTo(x as int)
    {
      S.ColumnAt(start,x as int);
      trace := trace + ST.LoopCheck(2,true,x as int) + ST.Read(3,0,x as int)
        + ST.Ops(1,0,0,0,0,0,0) + ST.Read(4,0,(x+5) as int) + ST.Ops(0,0,0,0,0,1,0)
        + ST.Ops(1,0,0,0,0,0,0) + ST.Read(5,0,(x+10) as int) + ST.Ops(0,0,0,0,0,1,0)
        + ST.Ops(1,0,0,0,0,0,0) + ST.Read(6,0,(x+15) as int) + ST.Ops(0,0,0,0,0,1,0)
        + ST.Ops(1,0,0,0,0,0,0) + ST.Read(7,0,(x+20) as int) + ST.Ops(0,0,0,0,0,1,0)
        + ST.Write(8,1,x as int);
      c[x] := a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
      ThetaColumnUpToSucc(x as int);
    }
    trace := trace + ST.LoopCheck(2,false,5);
    trace := trace + ST.LoopBound(9,0) + ST.LoopBound(10,5);
    ThetaLaneUpToZero();
    for x: T.I := 0 to 5
      modifies a
      invariant 0 <= x <= 5
      invariant forall k: int :: 0 <= k < 25 && k%5 < x as int ==> a[k] == S.Theta(start)[k]
      invariant forall k: int :: 0 <= k < 25 && x as int <= k%5 ==> a[k] == start[k]
      invariant trace == ThetaColumns() + ST.LoopBound(9,0) + ST.LoopBound(10,5) + ThetaLaneUpTo(x as int)
    {
      ghost var callWitness := Rotate(c[(x+1)%5],1);
      trace := trace + ST.LoopCheck(11,true,x as int)
        + ST.Ops(1,0,0,0,0,0,0) + ST.Ops(0,0,0,0,1,0,0) + ST.Read(12,1,((x+4)%5) as int)
        + ST.Ops(1,0,0,0,0,0,0) + ST.Ops(0,0,0,0,1,0,0) + ST.Read(13,1,((x+1)%5) as int)
        + ST.Call(14,20,2) + callWitness.1 + ST.Ops(0,0,0,0,0,1,0);
      assert callWitness.1 == RotateTrace(1);
      assert callWitness == Rotate(c[(x+1)%5],1);
      var d := c[(x+4)%5] ^ Rotate(c[(x+1)%5],1).0;
      trace := trace + ST.LoopBound(15,0) + ST.LoopBound(16,5);
      ThetaInnerUpToZero(x as int);
      for y: T.I := 0 to 5
        modifies a
        invariant 0 <= y <= 5
        invariant forall k: int :: 0 <= k < 25 && (k%5 < x as int || (k%5 == x as int && k/5 < y as int)) ==> a[k] == S.Theta(start)[k]
        invariant forall k: int :: 0 <= k < 25 && (x as int < k%5 || (k%5 == x as int && y as int <= k/5)) ==> a[k] == start[k]
        invariant trace == ThetaColumns() + ST.LoopBound(9,0) + ST.LoopBound(10,5) + ThetaLaneUpTo(x as int)
          + ThetaDStep(x as int) + ThetaInnerUpTo(x as int,y as int)
      {
        trace := trace + ST.LoopCheck(17,true,y as int)
          + ST.Ops(0,0,1,0,0,0,0) + ST.Ops(1,0,0,0,0,0,0);
        var i: T.I := x+5*y;
        trace := trace + ST.Read(18,0,i as int) + ST.Ops(0,0,0,0,0,1,0)
          + ST.Write(19,0,i as int);
        assert i%5 == x && i/5 == y;
        S.ThetaLaneAt(start,i as int); S.ThetaAt(start,i as int);
        a[i] := a[i]^d;
        ThetaInnerUpToSucc(x as int,y as int);
      }
      trace := trace + ST.LoopCheck(17,false,5);
      ThetaLaneUpToSucc(x as int);
    }
    trace := trace + ST.LoopCheck(11,false,5);
    assert a[..] == S.Theta(start);
  }
  method {:isolate_assertions} RhoPi(a: array<bv64>, b: array<bv64>, offsets: array<T.I>, sources: array<T.I>) returns(ghost trace: seq<int>)
    requires a.Length == 25 && b.Length == 25 && a != b
    requires offsets.Length == 25 && (offsets as object) != (b as object)
    requires forall i: int :: 0 <= i < 25 ==> 0 <= offsets[i] < 64 && offsets[i] as int == S.Offsets()[i]%64
    requires sources.Length == 25
    requires (sources as object) != (b as object) && (sources as object) != (a as object)
    requires forall i: int :: 0 <= i < 25 ==> 0 <= sources[i] < 25 && sources[i] as int == ((i%5)+3*(i/5))%5+5*(i%5)
    modifies b
    ensures b[..] == S.Pi(S.Rho(a[..]))
    ensures trace == RhoPiTrace()
  {
    trace := ST.LoopBound(0,0) + ST.LoopBound(1,25);
    ghost var theta := a[..];
    // A pull mapping combines rho and pi; addresses depend only on loop index.
    RhoPiUpToZero();
    for i: T.I := 0 to 25
      modifies b
      invariant 0 <= i <= 25
      invariant forall k: int :: 0 <= k < i as int ==> b[k] == S.Pi(S.Rho(theta))[k]
      invariant trace == ST.LoopBound(0,0) + ST.LoopBound(1,25) + RhoPiUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(2,true,i as int) + ST.Read(3,3,i as int);
      var j: T.I := sources[i];
      assert j as int == (((i as int)%5)+3*((i as int)/5))%5+5*((i as int)%5);
      assert 0 <= offsets[j] < 64;
      assert offsets[j] as int == S.Offsets()[j]%64;
      ghost var callWitness := Rotate(a[j],offsets[j]);
      trace := trace + ST.Read(4,0,j as int) + ST.Read(5,2,j as int)
        + ST.Call(6,20,2) + callWitness.1 + ST.Write(7,1,i as int);
      assert callWitness.1 == RotateTrace(offsets[j]);
      assert RotateTrace(offsets[j]) == RotateTrace(RotateDistanceAt(SourceIndexAt(i as int)));
      assert callWitness == Rotate(a[j],offsets[j]);
      b[i] := Rotate(a[j],offsets[j]).0;
      RhoPiUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(2,false,25);
    assert b[..] == S.Pi(S.Rho(theta));
  }
  method {:isolate_assertions} Chi(a: array<bv64>, b: array<bv64>) returns(ghost trace: seq<int>)
    requires a.Length == 25 && b.Length == 25 && a != b
    modifies a
    ensures a[..] == S.Chi(b[..])
    ensures trace == ChiTrace()
  {
    trace := ST.LoopBound(0,0) + ST.LoopBound(1,25);
    ghost var pi := b[..];
    ChiUpToZero();
    for i: T.I := 0 to 25
      modifies a
      invariant 0 <= i <= 25
      invariant forall k: int :: 0 <= k < i as int ==> a[k] == S.Chi(pi)[k]
      invariant trace == ST.LoopBound(0,0) + ST.LoopBound(1,25) + ChiUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(2,true,i as int)
        + ST.Ops(0,0,0,1,0,0,0) + ST.Ops(0,0,1,0,0,0,0);
      var row: T.I := 5*(i/5);
      trace := trace + ST.Ops(0,0,0,0,1,0,0);
      var x: T.I := i%5;
      trace := trace + ST.Read(3,1,i as int)
        + ST.Ops(1,0,0,0,0,0,0) + ST.Ops(0,0,0,0,1,0,0) + ST.Ops(1,0,0,0,0,0,0)
        + ST.Read(4,1,(row+(x+1)%5) as int) + ST.Ops(0,0,0,0,0,1,0)
        + ST.Ops(1,0,0,0,0,0,0) + ST.Ops(0,0,0,0,1,0,0) + ST.Ops(1,0,0,0,0,0,0)
        + ST.Read(5,1,(row+(x+2)%5) as int)
        + ST.Ops(0,0,0,0,0,1,0) + ST.Ops(0,0,0,0,0,1,0)
        + ST.Write(6,0,i as int);
      a[i] := b[i] ^ ((!b[row+(x+1)%5]) & b[row+(x+2)%5]);
      ChiUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(2,false,25);
    assert a[..] == S.Chi(pi);
  }
  method {:isolate_assertions} Round(a: array<bv64>, b: array<bv64>, c: array<bv64>, offsets: array<T.I>, sources: array<T.I>, rc: bv64) returns(ghost trace: seq<int>)
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
    ensures trace == RoundTrace()
  {
    ghost var start := a[..];
    trace := [];
    ghost var thetaTrace: seq<int>;
    thetaTrace := Theta(a,c);
    trace := trace + ST.Call(0,14,2) + thetaTrace;
    ghost var rhoPiTrace: seq<int>;
    rhoPiTrace := RhoPi(a,b,offsets,sources);
    trace := trace + ST.Call(1,15,4) + rhoPiTrace;
    ghost var chiTrace: seq<int>;
    chiTrace := Chi(a,b);
    trace := trace + ST.Call(2,13,2) + chiTrace;
    ghost var iotaTrace: seq<int>;
    iotaTrace := Iota(a,rc);
    trace := trace + ST.Call(3,11,2) + iotaTrace;
    S.RoundEquation(start,rc);
  }
  method {:isolate_assertions} PermuteScratch(a: array<bv64>, b: array<bv64>, c: array<bv64>, offsets: array<T.I>, sources: array<T.I>) returns(ghost trace: seq<int>)
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
    ensures trace == PermuteScratchTrace()
  {
    trace := ST.LoopBound(0,0) + ST.LoopBound(1,24);
    ghost var start := a[..];
    S.IterZero(start);
    ghost var completed := 0;
    PermuteScratchUpToZero();
    for i: T.I := 0 to 24
      modifies a,b,c
      invariant 0 <= i <= 24
      invariant a[..] == S.Iter(start,i as int)
      invariant completed == i as int
      invariant trace == ST.LoopBound(0,0) + ST.LoopBound(1,24) + PermuteScratchUpTo(i as int)
    {
      S.IterStep(start,i as int);
      ghost var roundTrace: seq<int>;
      ghost var constantWitness := Constant(i);
      trace := trace + ST.LoopCheck(2,true,i as int) + ST.Call(3,22,1) + constantWitness.1;
      assert constantWitness.1 == ConstantTrace(i);
      assert constantWitness == Constant(i);
      roundTrace := Round(a,b,c,offsets,sources,Constant(i).0);
      trace := trace + ST.Call(4,16,6) + roundTrace;
      completed := i as int+1;
      PermuteScratchUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(2,false,24);
    assert completed == 24;
  }
  method {:isolate_assertions} Permute(a: array<bv64>) returns(ghost trace: seq<int>)
    requires a.Length == 25
    modifies a
    ensures a[..] == S.Iter(old(a[..]),24)
    ensures trace == PermuteTrace()
  {
    trace := ST.Alloc(0,25);
    var b := new bv64[25];
    trace := trace + ST.Alloc(1,5);
    var c := new bv64[5];
    var offsets, offsetsTrace := NewOffsets();
    trace := trace + ST.Call(2,19,0) + offsetsTrace;
    var sources, sourcesTrace := NewSources();
    trace := trace + ST.Call(3,21,0) + sourcesTrace;
    ghost var permuteScratchTrace: seq<int>;
    permuteScratchTrace := PermuteScratch(a,b,c,offsets,sources);
    trace := trace + ST.Call(4,17,5) + permuteScratchTrace;
    ghost var wipeBTrace: seq<int>;
    wipeBTrace := Wipe(b);
    trace := trace + ST.Call(5,12,1) + wipeBTrace;
    ghost var wipeCTrace: seq<int>;
    wipeCTrace := Wipe(c);
    trace := trace + ST.Call(6,12,1) + wipeCTrace;
  }

  method Wipe(a: array<bv64>) returns(ghost trace: seq<int>)
    requires T.JavaLength(a.Length)
    modifies a
    ensures forall i: int :: 0 <= i < a.Length ==> a[i] == 0
    ensures trace == WipeTrace(a.Length)
  {
    trace := [];
    var length: T.I := a.Length as T.I;
    trace := trace + ST.LoopBound(0,0) + ST.LoopBound(1,length as int);
    WipeUpToZero();
    for i: T.I := 0 to length
      invariant 0 <= i <= length
      invariant forall k: int :: 0 <= k < i as int ==> a[k] == 0
      invariant trace == ST.LoopBound(0,0) + ST.LoopBound(1,length as int) + WipeUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(2,true,i as int) + ST.Write(3,0,i as int);
      a[i] := 0;
      WipeUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(2,false,length as int);
    assert length as int == a.Length;
  }
}
