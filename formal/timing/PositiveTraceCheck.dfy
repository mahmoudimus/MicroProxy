// SPDX-License-Identifier: Apache-2.0
//
// Compiled positive control for the SecretTrace model. This is *runtime*
// evidence from compiled Dafny (`dafny run`), not a proof: it confirms that the
// machine really records branch outcomes and secret-array stores at public
// indices, and that a second run with a different secret word has the same
// trace. The universal statement is `SecretTrace.ExecTwoRun`.
include "SecretTrace.dfy"
module PositiveTraceCheck {
  import opened SecretTrace

  method Main() {
    var p := CounterProgram();
    var expected: seq<Event> :=
      [EOp(1, 0), EOp(2, 0), EOp(3, 1), EGuard(4, true),
       EStore(5, 0, 0), EOp(6, 2),
       EOp(3, 1), EGuard(4, true), EStore(5, 0, 1), EOp(6, 2),
       EOp(3, 1), EGuard(4, false)];
    var s := State([2, 7, 0, 0, 0], [seq(4, _ => 0 as bv64)]);
    var t := State([2, 99, 0, 0, 0], [seq(4, _ => 0 as bv64)]);
    var (_, events) := Exec(p, 0, s, 32);
    expect events == expected;
    var (_, other) := Exec(p, 0, t, 32);
    expect other == expected;
    print "positive-control-ok\n";
  }
}
