// SPDX-License-Identifier: Apache-2.0
//
// Arity-aware public-call predicate layer over the original generic model.
// This file does NOT change ExecPTwoRun, SecretTrace, PublicProvider, the old
// certificates, or the frozen model.  It adds a checked *mapping* premise for
// actual provider calls:
//
//   * every remaining Call target is a key in the exact generated arity map;
//   * all scalar arguments are RegTaint Pub;
//   * heapArgs is empty for these arithmetic roots;
//   * the scalar argument count equals the target's exact arity.
//
// The generated oracle keeps a total defined fallback for unknown targets and
// uses exact argument-count equality, not >=; CallsOnly proves every call target
// and arity in the concrete program, so the fallback is unreachable for actual
// calls.  This is not an assert-false device and does not make the oracle partial.
include "WordArithmetic.dfy"

module PublicProviderPublic {
  import opened SecretTrace
  import opened PublicProvider

  predicate PublicKind(p: Program, arity: map<nat, nat>, kind: StepKind) {
    match kind
    case Call(target, args, heapArgs, shape) =>
      target in arity &&
      |heapArgs| == 0 &&
      (forall k :: 0 <= k < |args| ==> args[k] < p.registers && RegTaint(p, args[k]) == Pub) &&
      |args| == arity[target]
    case _ => true
  }

  predicate PublicProviderInsn(p: Program, arity: map<nat, nat>, inst: Instr) {
    match inst
    case IStep(_, _, kind, _) => PublicKind(p, arity, kind)
    case _ => true
  }

  predicate CallsOnly(p: Program, arity: map<nat, nat>) {
    forall c :: 0 <= c < |p.chunks| ==>
      forall i :: 0 <= i < |p.chunks[c]| ==>
        PublicProviderInsn(p, arity, p.chunks[c][i])
  }

  predicate PublicOnly(p: Program, arity: map<nat, nat>) {
    CallsOnly(p, arity)
  }

  predicate InstrInProgram(p: Program, inst: Instr) {
    exists c, i :: 0 <= c < |p.chunks| && 0 <= i < |p.chunks[c]| &&
      p.chunks[c][i] == inst
  }

  lemma CallsOnlyTarget(p: Program, arity: map<nat, nat>, inst: Instr)
    requires CallsOnly(p, arity)
    requires InstrInProgram(p, inst)
    requires inst.IStep? && inst.kind.Call?
    ensures inst.kind.target in arity
  {
    var c, i :| 0 <= c < |p.chunks| && 0 <= i < |p.chunks[c]| &&
      p.chunks[c][i] == inst;
    assert PublicProviderInsn(p, arity, inst);
  }

  lemma CallsOnlyArity(p: Program, arity: map<nat, nat>, inst: Instr)
    requires CallsOnly(p, arity)
    requires InstrInProgram(p, inst)
    requires inst.IStep? && inst.kind.Call?
    ensures |inst.kind.args| == arity[inst.kind.target]
  {
    var c, i :| 0 <= c < |p.chunks| && 0 <= i < |p.chunks[c]| &&
      p.chunks[c][i] == inst;
    assert PublicProviderInsn(p, arity, inst);
  }

  lemma PublicProviderInsnArgs(p: Program, arity: map<nat, nat>, inst: Instr)
    requires PublicProviderInsn(p, arity, inst)
    requires inst.IStep? && inst.kind.Call?
    ensures forall k :: 0 <= k < |inst.kind.args| ==>
      inst.kind.args[k] < p.registers && RegTaint(p, inst.kind.args[k]) == Pub
    ensures |inst.kind.heapArgs| == 0
    ensures inst.kind.target in arity
    ensures |inst.kind.args| == arity[inst.kind.target]
  {}
}
