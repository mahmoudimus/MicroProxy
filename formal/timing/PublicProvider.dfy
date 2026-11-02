// SPDX-License-Identifier: Apache-2.0
//
// Conservative extension of the FROZEN formal/timing/SecretTrace.dfy model.
//
// The only semantic change is the provider oracle used by a `Call` step: the
// frozen model fixed `ProviderResult` to a placeholder.  Here an arbitrary
// deterministic pure total function
//
//     Oracle = (nat, seq<Arg>) -> bv64           (target, public arguments)
//
// may be supplied.  Its type is the visibility boundary: an oracle cannot
// receive private registers or heap contents, because the only value arguments
// are the target id and the sequence of *public* arguments built by the frozen
// `PublicArgs` function.
//
// Everything else is the frozen model, and non-`Call` steps are delegated to the
// frozen `SecretTrace.DoStep` verbatim.  No axiom, assume, extern or
// `{:verify false}` is used, and SecretTrace.dfy is not modified.  In
// particular the old `Exec` is definitionally reproduced by `DefaultOracle`
// (proved below), so all 57 old checks and every old certificate remain valid.
//
// Trust boundary: this file proves machine-level trace preservation for any
// oracle with the above signature.  It does NOT prove that a real Java/Dafny
// provider is pure, deterministic, receives only those arguments, or that its
// bv64 result equals the JVM value.  Those are the explicit provider/trust
// mappings recorded by the caller; see PublicArithmetic.dfy for the concrete
// public Euclidean instance and the report for the JAVA narrowing caveat.

include "SecretTrace.dfy"

module PublicProvider {
  import opened SecretTrace

  // The same pure, total oracle is used in both runs. Its explicit arguments
  // contain public values only. This does not model private provider outputs
  // or prove purity/determinism of a JVM implementation; a production root
  // using this extension must inline private/owned helpers and separately
  // check its remaining public provider contracts.
  type Oracle = (nat, seq<Arg>) -> bv64

  // The frozen placeholder, named explicitly so default equivalence is a
  // theorem rather than a change of meaning.
  function DefaultOracle(target: nat, publicArgs: seq<Arg>): bv64 {
    SecretTrace.ProviderResult(target, publicArgs)
  }

  // Generalised step semantics.  Non-Call steps are the frozen `DoStep`; the
  // Call case uses the supplied oracle on exactly the frozen event payload
  // (`PublicArgs`, target) and leaves the heap untouched.  The event is still
  // `ECall(site, target, PublicArgs(...))`, so an oracle value is never observed
  // unless it controls a later branch/address, exactly as before.
  function DoStepP(p: Program, site: nat, dst: nat, kind: StepKind, s: State,
                   oracle: Oracle): (State, Event)
    requires StepSafe(s, dst, kind)
    ensures Shape(p, s) ==> Shape(p, DoStepP(p, site, dst, kind, s, oracle).0)
  {
    match kind
    case Call(target, args, heapArgs, shape) =>
      var pub := PublicArgs(p, s.regs, args);
      (State(s.regs[dst := oracle(target, pub)], s.heap), ECall(site, target, pub))
    case _ =>
      SecretTrace.DoStep(p, site, dst, kind, s)
  }

  // Generalised executable semantics.  Fuel, fault terminality, branch/switch
  // observation and all events are byte-for-byte the frozen `Exec` structure;
  // only `DoStep` is replaced by `DoStepP`.
  function ExecP(p: Program, pc: nat, s: State, fuel: nat, oracle: Oracle): (State, seq<Event>)
    requires Structure(p)
    requires Shape(p, s)
    requires pc < p.instructions
    decreases fuel
  {
    if fuel == 0 then (s, [])
    else
      var inst := InstrAt(p, pc);
      match inst
      case IStep(site, dst, kind, next) =>
        var (s1, e1) := DoStepP(p, site, dst, kind, s, oracle);
        if e1.EFault? then (s1, [e1])
        else
          var (s2, e2) := ExecP(p, next, s1, fuel - 1, oracle);
          (s2, [e1] + e2)
      case IGoto(next) =>
        ExecP(p, next, s, fuel - 1, oracle)
      case IBranch(site, cond, thn, els) =>
        var take := Get(s.regs, cond) != 0;
        var (s1, e1) := ExecP(p, if take then thn else els, s, fuel - 1, oracle);
        (s1, [EGuard(site, take)] + e1)
      case ISwitch(site, cond, cases, dflt) =>
        var v := Get(s.regs, cond);
        var index := SwitchIndex(v, cases);
        var target := if index < |cases| then cases[index].1 else dflt;
        var (s1, e1) := ExecP(p, target, s, fuel - 1, oracle);
        (s1, [ESwitch(site, index)] + e1)
      case IStop =>
        (s, [])
      case IRaise(site, code) =>
        (s, [ERaise(site, code)])
  }

  // ---------- Default-oracle equivalence with the frozen semantics ----------

  lemma DoStepPDefault(p: Program, site: nat, dst: nat, kind: StepKind, s: State)
    requires StepSafe(s, dst, kind)
    ensures DoStepP(p, site, dst, kind, s, DefaultOracle) ==
            SecretTrace.DoStep(p, site, dst, kind, s)
  {
    match kind
    case Call(target, args, heapArgs, shape) =>
    case _ =>
  }

  lemma DoStepPNonCallEquals(p: Program, site: nat, dst: nat, kind: StepKind,
                             s: State, oracle: Oracle)
    requires !kind.Call?
    requires StepSafe(s, dst, kind)
    ensures DoStepP(p, site, dst, kind, s, oracle) ==
            SecretTrace.DoStep(p, site, dst, kind, s)
  {
    match kind {
      case Call(target, args, heapArgs, shape) => assert false;
      case _ =>
    }
  }

  lemma ExecPDefault(p: Program, pc: nat, s: State, fuel: nat)
    requires Structure(p) && Shape(p, s) && pc < p.instructions
    ensures ExecP(p, pc, s, fuel, DefaultOracle) == Exec(p, pc, s, fuel)
    decreases fuel
  {
    if fuel == 0 {
    } else {
      var inst := InstrAt(p, pc);
      match inst {
        case IStep(site, dst, kind, next) =>
          StepSafeOK(p, dst, kind, s);
          DoStepPDefault(p, site, dst, kind, s);
          var s1 := SecretTrace.DoStep(p, site, dst, kind, s).0;
          var e1 := SecretTrace.DoStep(p, site, dst, kind, s).1;
          if e1.EFault? {
          } else {
            ExecPDefault(p, next, s1, fuel - 1);
          }
        case IGoto(next) =>
          ExecPDefault(p, next, s, fuel - 1);
        case IBranch(site, cond, thn, els) =>
          var take := Get(s.regs, cond) != 0;
          ExecPDefault(p, if take then thn else els, s, fuel - 1);
        case ISwitch(site, cond, cases, dflt) =>
          var v := Get(s.regs, cond);
          var index := SwitchIndex(v, cases);
          var target := if index < |cases| then cases[index].1 else dflt;
          ExecPDefault(p, target, s, fuel - 1);
        case IStop =>
        case IRaise(site, code) =>
      }
    }
  }

  // `StepOK` implies the `StepSafe` preconditions used by the executable
  // semantics.  This is a direct re-derivation (Shape supplies the length
  // equalities); the non-call *trace/state* proofs then reuse the frozen
  // `DoStepTrace` / `DoStepAgree` lemmas.
  lemma StepSafeOK(p: Program, dst: nat, kind: StepKind, s: State)
    requires Shape(p, s)
    requires dst < p.registers && StepOK(p, dst, kind)
    ensures StepSafe(s, dst, kind)
  {
    // `Shape` equates the state's register/heap lengths with the program's, so
    // the `StepOK` bounds are exactly the `StepSafe` bounds.  This is a direct
    // re-derivation of the frozen `DoStepSafe` conclusion without needing the
    // frozen lemma's second state.
    match kind
    case Lit(w) =>
    case Op(k, a, b) =>
    case LenOf(role) =>
    case Load(role, idx) =>
    case Store(role, idx, v) =>
    case Alloc(role, size, fill) =>
    case Call(target, args, heapArgs, shape) =>
      assert forall k :: 0 <= k < |args| ==> args[k] < |s.regs|;
  }

  // ---------- Preservation for an arbitrary oracle ----------

  lemma DoStepPSafe(p: Program, site: nat, dst: nat, kind: StepKind, s: State,
                    t: State, oracle: Oracle)
    requires Structure(p) && Agree(p, s, t)
    requires dst < p.registers && StepOK(p, dst, kind)
    ensures StepSafe(s, dst, kind) && StepSafe(t, dst, kind)
  {
    StepSafeOK(p, dst, kind, s);
    StepSafeOK(p, dst, kind, t);
  }

  lemma DoStepPTrace(p: Program, site: nat, dst: nat, kind: StepKind, s: State,
                     t: State, oracle: Oracle)
    requires Structure(p) && Agree(p, s, t)
    requires dst < p.registers && StepOK(p, dst, kind)
    requires StepSafe(s, dst, kind) && StepSafe(t, dst, kind)
    ensures DoStepP(p, site, dst, kind, s, oracle).1 ==
            DoStepP(p, site, dst, kind, t, oracle).1
  {
    match kind {
      case Call(target, args, heapArgs, shape) =>
        forall k | 0 <= k < |args| && RegTaint(p, args[k]) == Pub
          ensures Get(s.regs, args[k]) == Get(t.regs, args[k])
        {
          AgreeReg(p, s, t, args[k]);
        }
        PublicArgsAgree(p, s.regs, t.regs, args);
      case _ =>
        // Non-call steps are the frozen `DoStep`; reuse the frozen trace lemma.
        DoStepPNonCallEquals(p, site, dst, kind, s, oracle);
        DoStepPNonCallEquals(p, site, dst, kind, t, oracle);
        SecretTrace.DoStepTrace(p, site, dst, kind, s, t);
    }
  }

  lemma DoStepPAgree(p: Program, site: nat, dst: nat, kind: StepKind, s: State,
                     t: State, oracle: Oracle)
    requires Structure(p) && Agree(p, s, t)
    requires dst < p.registers && StepOK(p, dst, kind)
    requires StepSafe(s, dst, kind) && StepSafe(t, dst, kind)
    ensures Agree(p, DoStepP(p, site, dst, kind, s, oracle).0,
                    DoStepP(p, site, dst, kind, t, oracle).0)
  {
    var s1 := DoStepP(p, site, dst, kind, s, oracle).0;
    var t1 := DoStepP(p, site, dst, kind, t, oracle).0;
    assert Shape(p, s1) && Shape(p, t1);
    match kind {
      case Call(target, args, heapArgs, shape) =>
        forall k | 0 <= k < |args| && RegTaint(p, args[k]) == Pub
          ensures Get(s.regs, args[k]) == Get(t.regs, args[k])
        {
          AgreeReg(p, s, t, args[k]);
        }
        PublicArgsAgree(p, s.regs, t.regs, args);
        assert PublicArgs(p, s.regs, args) == PublicArgs(p, t.regs, args);
        assert s1.regs[dst] == t1.regs[dst];
        assert s1.heap == s.heap && t1.heap == t.heap;
      case _ =>
        // Non-call steps reuse the frozen `DoStepAgree` state-relation lemma.
        DoStepPNonCallEquals(p, site, dst, kind, s, oracle);
        DoStepPNonCallEquals(p, site, dst, kind, t, oracle);
        SecretTrace.DoStepAgree(p, site, dst, kind, s, t);
    }
    forall i | 0 <= i < p.registers && RegTaint(p, i) == Pub
      ensures s1.regs[i] == t1.regs[i]
    {
      if i != dst {
        AgreeReg(p, s, t, i);
      }
    }
    forall r | 0 <= r < p.roles
      ensures |s1.heap[r]| == |t1.heap[r]| &&
              (HeapTaint(p, r) == Pub ==> s1.heap[r] == t1.heap[r])
    {
      if r != RoleOf(kind) {
        AgreeLen(p, s, t, r);
        if HeapTaint(p, r) == Pub {
          AgreeHeap(p, s, t, r);
        }
      }
    }
  }

  // Universal non-interference for every oracle with the public signature.
  lemma ExecPTwoRun(p: Program, pc: nat, s: State, t: State, fuel: nat, oracle: Oracle)
    requires Structure(p)
    requires Agree(p, s, t)
    requires pc < p.instructions
    ensures ExecP(p, pc, s, fuel, oracle).1 == ExecP(p, pc, t, fuel, oracle).1
    ensures Agree(p, ExecP(p, pc, s, fuel, oracle).0,
                    ExecP(p, pc, t, fuel, oracle).0)
    decreases fuel
  {
    if fuel == 0 {
    } else {
      var inst := InstrAt(p, pc);
      match inst {
        case IStep(site, dst, kind, next) =>
          DoStepPSafe(p, site, dst, kind, s, t, oracle);
          DoStepPTrace(p, site, dst, kind, s, t, oracle);
          DoStepPAgree(p, site, dst, kind, s, t, oracle);
          var s1 := DoStepP(p, site, dst, kind, s, oracle).0;
          var t1 := DoStepP(p, site, dst, kind, t, oracle).0;
          assert Shape(p, s1) && Shape(p, t1);
          ExecPTwoRun(p, next, s1, t1, fuel - 1, oracle);
        case IGoto(next) =>
          ExecPTwoRun(p, next, s, t, fuel - 1, oracle);
        case IBranch(site, cond, thn, els) =>
          AgreeReg(p, s, t, cond);
          var take := Get(s.regs, cond) != 0;
          assert (Get(t.regs, cond) != 0) == take;
          ExecPTwoRun(p, if take then thn else els, s, t, fuel - 1, oracle);
        case ISwitch(site, cond, cases, dflt) =>
          AgreeReg(p, s, t, cond);
          var v := Get(s.regs, cond);
          assert Get(t.regs, cond) == v;
          var index := SwitchIndex(v, cases);
          var target := if index < |cases| then cases[index].1 else dflt;
          assert SwitchIndex(Get(t.regs, cond), cases) == index;
          ExecPTwoRun(p, target, s, t, fuel - 1, oracle);
        case IStop =>
        case IRaise(site, code) =>
      }
    }
  }
}
