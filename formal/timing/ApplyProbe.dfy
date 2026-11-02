// SPDX-License-Identifier: Apache-2.0
//
// Compiled cross-check of the *pinned* `SecretTrace.Apply` operand table.
//
// This is runtime evidence from compiled Dafny (`dafny run`), not a proof. It
// exists because the bytecode translator and the finite witness executor
// (`trace_exec.py`) must agree with the frozen model on the operand semantics
// of every `Op(kind, a, b)` they emit:
//
//   * `bytecode_trace.KIND['copy'] == 12` and the extractor emits copies as
//     `Op(12, 0, src)`, exactly like `Op(8, src, 0)` for casts;
//   * `trace_exec.apply` mirrors the same table.
//
// The expectations below are transcribed from the model source. If
// `SecretTrace.Apply` changes (the model is frozen for this change), this
// controlled execution fails instead of silently letting a stale mirror pass.
// `run.py` additionally compares the printed table row-by-row against
// `trace_exec.apply`; `test_trace.py` does the same when Dafny is available.
include "SecretTrace.dfy"

module ApplyProbe {
  import opened SecretTrace

  method Main() {
    var pairs: seq<(bv64, bv64)> :=
      [(5 as bv64, 9 as bv64), (9 as bv64, 5 as bv64), (0 as bv64, 7 as bv64),
       (7 as bv64, 0 as bv64), (0x8000000000000000 as bv64, 3 as bv64),
       (0xFFFFFFFFFFFFFFFF as bv64, 1 as bv64)];
    var kinds: seq<nat> :=
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
       20, 41, 200];
    var rows := 0;
    for k := 0 to |kinds| {
      for j := 0 to |pairs| {
        var a := pairs[j].0;
        var b := pairs[j].1;
        var r := Apply(kinds[k], a, b);
        print kinds[k], " ", a, " ", b, " ", r, "\n";
        rows := rows + 1;
      }
    }
    // Operand-sensitive spot checks: copy reads b, cast reads a, arithmetic is
    // wrapping bv64, shifts use `b % 64`, unknown kinds fall through to b.
    expect Apply(12, 5, 9) == 9;
    expect Apply(12, 9, 5) == 5;
    expect Apply(12, 5, 0) == 0;
    expect Apply(8, 5, 9) == 5;
    expect Apply(2, 0xFFFFFFFFFFFFFFFF, 1) == 0;
    expect Apply(5, 0, 7) == 0xFFFFFFFFFFFFFFF9;
    expect Apply(9, 1, 64) == 1;
    expect Apply(7, 0, 0) == 0;
    expect Apply(200, 5, 9) == 9;
    expect rows == |kinds| * |pairs|;
    print "apply-probe-ok ", rows, "\n";
  }
}
