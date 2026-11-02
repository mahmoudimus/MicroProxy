// SPDX-License-Identifier: Apache-2.0
//
// Target-id-free public word arithmetic for the reusable Keccak trace replay.
//
// This file deliberately contains no target table and no oracle instance: the
// caller's generated per-root oracle supplies the actual translated target ids.
// The finite domain facts for division/modulus by 5 are concrete lemmas for
// i = 0..24, not a symbolic forall index law; the replay reports that boundary.
//
// Included by formal/timing/PublicProvider.dfy's consumers; the include is
// relative so the file is portable with the repository, not this worktree.

include "PublicProvider.dfy"

module WordArithmetic {
  import opened SecretTrace
  import opened PublicProvider

  const TWO63: int := 0x8000000000000000
  const TWO64I: int := 0x10000000000000000

  function Signed(w: bv64): int {
    var u := w as int;
    if u < TWO63 then u else u - TWO64I
  }

  function IntToWord(x: int): bv64 {
    (x % TWO64I) as bv64
  }

  function EuclideanModulus(a: int, b: int): int {
    if b == 0 then 0 else a % b
  }

  function EuclideanDivision(a: int, b: int): int {
    if b == 0 then 0 else (a - EuclideanModulus(a, b)) / b
  }

  function WordDivision(a: bv64, b: bv64): bv64 {
    IntToWord(EuclideanDivision(Signed(a), Signed(b)))
  }

  function WordModulus(a: bv64, b: bv64): bv64 {
    IntToWord(EuclideanModulus(Signed(a), Signed(b)))
  }

  // Java Integer.signum on the modelled signed word.  Actual Keccak counts and
  // round constants are non-negative; the general signed case is total.
  function SignumWord(w: bv64): bv64 {
    var x := Signed(w);
    if x < 0 then IntToWord(-1)
    else if x == 0 then IntToWord(0)
    else IntToWord(1)
  }

  // Helpers.toInt:(I)I is the identity on the modelled int word.
  function ToIntIntWord(w: bv64): bv64 { w }

  // Helpers.toInt:(Ljava/math/BigInteger;)I.  The extractor models the static
  // java.math.BigInteger.ZERO field as word 0; that is the only argument used by
  // the actual candidate.  This is an explicit abstract-handle mapping, not a
  // BigInteger/JVM semantics: word 0 (ZERO) -> 0; other handles pass through.
  function ToIntBigIntegerWord(w: bv64): bv64 { if w == 0 then 0 else w }

  // Target-free shift/rotate values used by the compiled public KAT probe.  The
  // inlined actual Helpers bodies use the same bv64 low-six-bits amount for the
  // finite rotate counts 0..63; the count==64 helper guard/zero case is tested by
  // runtime_primitives.replay, not by this KAT.
  function ShiftLeftWord(v: bv64, n: nat): bv64 { v << (n % 64) }
  function ShiftRightWord(v: bv64, n: nat): bv64 { v >> (n % 64) }
  function RotateWord(v: bv64, n: nat): bv64 {
    if n % 64 == 0 then v
    else (v << (n % 64)) | (v >> (64 - (n % 64)))
  }

  lemma Div5_0()
    ensures WordModulus(ToWord(0), ToWord(5)) == ToWord(0)
    ensures WordDivision(ToWord(0), ToWord(5)) == ToWord(0)
  {}

  lemma Div5_1()
    ensures WordModulus(ToWord(1), ToWord(5)) == ToWord(1)
    ensures WordDivision(ToWord(1), ToWord(5)) == ToWord(0)
  {}

  lemma Div5_2()
    ensures WordModulus(ToWord(2), ToWord(5)) == ToWord(2)
    ensures WordDivision(ToWord(2), ToWord(5)) == ToWord(0)
  {}

  lemma Div5_3()
    ensures WordModulus(ToWord(3), ToWord(5)) == ToWord(3)
    ensures WordDivision(ToWord(3), ToWord(5)) == ToWord(0)
  {}

  lemma Div5_4()
    ensures WordModulus(ToWord(4), ToWord(5)) == ToWord(4)
    ensures WordDivision(ToWord(4), ToWord(5)) == ToWord(0)
  {}

  lemma Div5_5()
    ensures WordModulus(ToWord(5), ToWord(5)) == ToWord(0)
    ensures WordDivision(ToWord(5), ToWord(5)) == ToWord(1)
  {}

  lemma Div5_6()
    ensures WordModulus(ToWord(6), ToWord(5)) == ToWord(1)
    ensures WordDivision(ToWord(6), ToWord(5)) == ToWord(1)
  {}

  lemma Div5_7()
    ensures WordModulus(ToWord(7), ToWord(5)) == ToWord(2)
    ensures WordDivision(ToWord(7), ToWord(5)) == ToWord(1)
  {}

  lemma Div5_8()
    ensures WordModulus(ToWord(8), ToWord(5)) == ToWord(3)
    ensures WordDivision(ToWord(8), ToWord(5)) == ToWord(1)
  {}

  lemma Div5_9()
    ensures WordModulus(ToWord(9), ToWord(5)) == ToWord(4)
    ensures WordDivision(ToWord(9), ToWord(5)) == ToWord(1)
  {}

  lemma Div5_10()
    ensures WordModulus(ToWord(10), ToWord(5)) == ToWord(0)
    ensures WordDivision(ToWord(10), ToWord(5)) == ToWord(2)
  {}

  lemma Div5_11()
    ensures WordModulus(ToWord(11), ToWord(5)) == ToWord(1)
    ensures WordDivision(ToWord(11), ToWord(5)) == ToWord(2)
  {}

  lemma Div5_12()
    ensures WordModulus(ToWord(12), ToWord(5)) == ToWord(2)
    ensures WordDivision(ToWord(12), ToWord(5)) == ToWord(2)
  {}

  lemma Div5_13()
    ensures WordModulus(ToWord(13), ToWord(5)) == ToWord(3)
    ensures WordDivision(ToWord(13), ToWord(5)) == ToWord(2)
  {}

  lemma Div5_14()
    ensures WordModulus(ToWord(14), ToWord(5)) == ToWord(4)
    ensures WordDivision(ToWord(14), ToWord(5)) == ToWord(2)
  {}

  lemma Div5_15()
    ensures WordModulus(ToWord(15), ToWord(5)) == ToWord(0)
    ensures WordDivision(ToWord(15), ToWord(5)) == ToWord(3)
  {}

  lemma Div5_16()
    ensures WordModulus(ToWord(16), ToWord(5)) == ToWord(1)
    ensures WordDivision(ToWord(16), ToWord(5)) == ToWord(3)
  {}

  lemma Div5_17()
    ensures WordModulus(ToWord(17), ToWord(5)) == ToWord(2)
    ensures WordDivision(ToWord(17), ToWord(5)) == ToWord(3)
  {}

  lemma Div5_18()
    ensures WordModulus(ToWord(18), ToWord(5)) == ToWord(3)
    ensures WordDivision(ToWord(18), ToWord(5)) == ToWord(3)
  {}

  lemma Div5_19()
    ensures WordModulus(ToWord(19), ToWord(5)) == ToWord(4)
    ensures WordDivision(ToWord(19), ToWord(5)) == ToWord(3)
  {}

  lemma Div5_20()
    ensures WordModulus(ToWord(20), ToWord(5)) == ToWord(0)
    ensures WordDivision(ToWord(20), ToWord(5)) == ToWord(4)
  {}

  lemma Div5_21()
    ensures WordModulus(ToWord(21), ToWord(5)) == ToWord(1)
    ensures WordDivision(ToWord(21), ToWord(5)) == ToWord(4)
  {}

  lemma Div5_22()
    ensures WordModulus(ToWord(22), ToWord(5)) == ToWord(2)
    ensures WordDivision(ToWord(22), ToWord(5)) == ToWord(4)
  {}

  lemma Div5_23()
    ensures WordModulus(ToWord(23), ToWord(5)) == ToWord(3)
    ensures WordDivision(ToWord(23), ToWord(5)) == ToWord(4)
  {}

  lemma Div5_24()
    ensures WordModulus(ToWord(24), ToWord(5)) == ToWord(4)
    ensures WordDivision(ToWord(24), ToWord(5)) == ToWord(4)
  {}

}
