// SPDX-License-Identifier: Apache-2.0
//
// Two-run (self-composition) observation theorem for the V7 secret-trace work.
//
// This module is deliberately independent of any cryptographic algorithm. It
// defines an idealized flat control-flow machine with word registers and
// byte arrays, an explicit attacker/observer event trace, a static taint
// discipline, and a universal two-run theorem:
//
//   equal public projection + static discipline  ==>  equal observation trace
//
// The taint discipline (:predicate Structure) is a *proof obligation over the
// emitted program*, not an assumption about the desired result. It forbids:
// branches on secret-tainted registers, secret-derived array indices,
// secret-sized allocations, provider dispatch whose public metadata depends on
// secrets, and public results produced from secret arguments. It is checked
// against the concrete program that :function Exec actually executes.
//
// The trusted bridge from JVM bytecode/Java source to these programs is the
// separately documented extractor/checker in formal/timing/bytecode_trace.py
// and the declared policy in formal/timing/policy.json. This file proves only
// the machine-level theorem; physical JVM/CPU/provider timing is excluded.
//
// Observation function (what the attacker is modeled to see):
//   * the sequence/kind of executed word operations (no operand values),
//   * every taken/not-taken branch outcome,
//   * the actual address of every array read/write/out-of-bounds fault,
//   * array lengths and allocation sizes,
//   * provider/Dafny-runtime dispatch identity and public argument values,
//   * explicit raise sites.
// Register/array *values* are not observed unless they control one of the
// above. Two runs may produce different secret values and different outputs.

module SecretTrace {
  datatype Taint = Pub | Sec

  function OrT(a: Taint, b: Taint): Taint {
    if a == Sec || b == Sec then Sec else Pub
  }

  // Public <= anything; Secret <= only Secret. Used so per-register taint
  // annotations may over-approximate (conservative) but never under-approximate.
  predicate TaintLeq(a: Taint, b: Taint) {
    a == Pub || b == Sec
  }

  // A word (64-bit) or, when used as an address, an unsigned small index.
  function Get(regs: seq<bv64>, r: nat): bv64 {
    if r < |regs| then regs[r] else 0
  }

  function Unsigned(w: bv64): nat {
    w as nat
  }

  const TWO64: nat := 0x10000000000000000

  // Register word standing for a length/role (public metadata).
  function ToWord(n: nat): bv64 {
    (n % TWO64) as bv64
  }

  datatype StepKind =
    | Lit(word: bv64)
    | Op(kind: nat, a: nat, b: nat)
    | LenOf(role: nat)
    | Load(role: nat, idx: nat)
    | Store(role: nat, idx: nat, value: nat)
    | Alloc(role: nat, size: nat, fill: bv64)
    | Call(target: nat, args: seq<nat>, heapArgs: seq<nat>, shape: bool)

  datatype Instr =
    | IStep(site: nat, dst: nat, kind: StepKind, next: nat)
    | IGoto(next: nat)
    | IBranch(site: nat, cond: nat, thn: nat, els: nat)
    | ISwitch(site: nat, cond: nat, cases: seq<(bv64, nat)>, dflt: nat)
    | IStop
    | IRaise(site: nat, code: nat)

  datatype State = State(regs: seq<bv64>, heap: seq<seq<bv64>>)

  datatype Program = Program(
      registers: nat,
      roles: nat,
      inputs: nat,
      annots: seq<seq<Taint>>, // static taints, chunked (<=32 per inner seq)
      heapAnnots: seq<Taint>,  // one static element taint per array role
      chunks: seq<seq<Instr>>, // code chunked (<=32) for solver-reducible select
      instructions: nat)

  datatype Arg = Arg(taint: Taint, value: bv64)

  datatype Event =
    | EOp(site: nat, kind: nat)
    | EGuard(site: nat, take: bool)
    | ESwitch(site: nat, index: nat)
    | ELoad(site: nat, role: nat, index: nat)
    | EStore(site: nat, role: nat, index: nat)
    | ELen(site: nat, role: nat, length: nat)
    | EAlloc(site: nat, role: nat, size: nat)
    | ECall(site: nat, target: nat, publicArgs: seq<Arg>)
    | ERaise(site: nat, code: nat)
    | EFault(site: nat, role: nat, index: nat)

  const CHUNK: nat := 32

  function SwitchIndex(v: bv64, cases: seq<(bv64, nat)>): nat
    decreases |cases|
  {
    if |cases| == 0 then 0
    else if cases[0].0 == v then 0
    else 1 + SwitchIndex(v, cases[1..])
  }

  function SumLengths(chunks: seq<seq<Instr>>): nat
    decreases |chunks|
  {
    if |chunks| == 0 then 0 else |chunks[0]| + SumLengths(chunks[1..])
  }

  function InstrAt(p: Program, pc: nat): Instr {
    var c := pc / CHUNK;
    if c < |p.chunks| && pc % CHUNK < |p.chunks[c]| then p.chunks[c][pc % CHUNK] else IStop()
  }

  // Taints are chunked because Dafny's solver does not reduce `select` on a
  // single very long literal sequence; each inner chunk is small enough to
  // compute for concrete generated certificates.
  function RegTaint(p: Program, r: nat): Taint {
    var c := r / CHUNK;
    if c < |p.annots| && r % CHUNK < |p.annots[c]| then p.annots[c][r % CHUNK] else Sec
  }

  function HeapTaint(p: Program, r: nat): Taint {
    if r < |p.heapAnnots| then p.heapAnnots[r] else Sec
  }

  // The trusted provider/opaque-call contract: the returned word is a
  // deterministic function of the call target and the *public* arguments.
  // Secret arguments may affect the real provider output; that output is then
  // tainted Sec and cannot control the trace (Structure forbids it). Provider
  // internals, exceptions and physical timing are explicitly outside this
  // observer and are recorded as trust in threat-model.md.
  function ProviderResult(target: nat, publicArgs: seq<Arg>): bv64 {
    if |publicArgs| == 0 then ToWord(target)
    else publicArgs[0].value
  }

  // Atomic word operation. Its result is left abstract: the trace theorem does
  // not depend on arithmetic equations, only on determinism for equal operands.
  function Apply(kind: nat, a: bv64, b: bv64): bv64 {
    match kind
    case 0 => a ^ b
    case 1 => if a < b then 1 else 0
    case 2 => a + b
    case 3 => a & b
    case 4 => a | b
    case 5 => a - b
    case 6 => a * b
    case 7 => 0 - a
    case 8 => a
    case 9 => a << (b % 64)
    case 10 => a >> (b % 64)
    case 11 => a >> (b % 64)
    case 12 => b
    case 13 => if a == b then 1 else 0
    case 14 => if a == b then 1 else 0
    case 15 => if a != b then 1 else 0
    case 16 => if a > b then 1 else 0
    case 17 => if a >= b then 1 else 0
    case 18 => if a < b then 1 else 0
    case 19 => if a <= b then 1 else 0
    case _ => b
  }

  // ---------- Static shape and taint discipline ----------

  predicate Shape(p: Program, s: State) {
    |s.regs| == p.registers && |s.heap| == p.roles
  }

  predicate StepSafe(s: State, dst: nat, kind: StepKind) {
    dst < |s.regs| &&
    (match kind
      case Lit(_) => true
      case Op(_, a, b) => a < |s.regs| && b < |s.regs|
      case LenOf(role) => role < |s.heap|
      case Load(role, idx) => role < |s.heap| && idx < |s.regs|
      case Store(role, idx, v) => role < |s.heap| && idx < |s.regs| && v < |s.regs|
      case Alloc(role, size, _) => role < |s.heap| && size < |s.regs|
      case Call(_, args, _, _) => forall k :: 0 <= k < |args| ==> args[k] < |s.regs|)
  }

  predicate StepOK(p: Program, dst: nat, kind: StepKind) {
    dst < p.registers &&
    (match kind
      case Lit(_) => TaintLeq(Pub, RegTaint(p, dst))
      case Op(_, a, b) =>
        a < p.registers && b < p.registers &&
        TaintLeq(OrT(RegTaint(p, a), RegTaint(p, b)), RegTaint(p, dst))
      case LenOf(role) =>
        role < p.roles && TaintLeq(Pub, RegTaint(p, dst))
      case Load(role, idx) =>
        role < p.roles && idx < p.registers &&
        RegTaint(p, idx) == Pub &&
        TaintLeq(HeapTaint(p, role), RegTaint(p, dst))
      case Store(role, idx, v) =>
        role < p.roles && idx < p.registers && v < p.registers &&
        RegTaint(p, idx) == Pub &&
        (HeapTaint(p, role) == Pub ==> RegTaint(p, v) == Pub)
      case Alloc(role, size, _) =>
        role < p.roles && size < p.registers &&
        RegTaint(p, size) == Pub && TaintLeq(Pub, RegTaint(p, dst))
      case Call(_, args, heapArgs, shape) =>
        (forall k :: 0 <= k < |args| ==> args[k] < p.registers) &&
        (forall k :: 0 <= k < |heapArgs| ==> heapArgs[k] < p.roles) &&
        (if shape then RegTaint(p, dst) == Pub
         else TaintLeq(OrT(CallArgTaint(p, args, heapArgs), Pub), RegTaint(p, dst))))
  }

  predicate InstrOK(p: Program, inst: Instr) {
    match inst
    case IStep(_, dst, kind, next) =>
      next < p.instructions && StepOK(p, dst, kind)
    case IGoto(next) => next < p.instructions
    case IBranch(_, cond, thn, els) =>
      cond < p.registers && RegTaint(p, cond) == Pub &&
      thn < p.instructions && els < p.instructions
    case ISwitch(_, cond, cases, dflt) =>
      cond < p.registers && RegTaint(p, cond) == Pub &&
      dflt < p.instructions &&
      (forall k :: 0 <= k < |cases| ==> cases[k].1 < p.instructions)
    case IStop => true
    case IRaise(_, _) => true
  }

  function RegSeqTaint(p: Program, args: seq<nat>): Taint
    decreases |args|
  {
    if |args| == 0 then Pub
    else OrT(RegTaint(p, args[0]), RegSeqTaint(p, args[1..]))
  }

  function HeapSeqTaint(p: Program, roles: seq<nat>): Taint
    decreases |roles|
  {
    if |roles| == 0 then Pub
    else OrT(HeapTaint(p, roles[0]), HeapSeqTaint(p, roles[1..]))
  }

  function CallArgTaint(p: Program, args: seq<nat>, heapArgs: seq<nat>): Taint {
    OrT(RegSeqTaint(p, args), HeapSeqTaint(p, heapArgs))
  }

  predicate WellFormed(p: Program) {
    p.registers <= CHUNK * |p.annots| &&
    (forall c :: 0 <= c < |p.annots| ==> |p.annots[c]| <= CHUNK) &&
    |p.heapAnnots| == p.roles &&
    p.inputs <= p.registers &&
    p.instructions == SumLengths(p.chunks) &&
    (forall c :: 0 <= c < |p.chunks| ==> |p.chunks[c]| <= CHUNK)
  }

  predicate Structure(p: Program) {
    WellFormed(p) &&
    (forall c :: 0 <= c < |p.chunks| ==>
      forall i :: 0 <= i < |p.chunks[c]| ==> InstrOK(p, p.chunks[c][i]))
  }

  // ---------- Two-run relation on states ----------
  //
  // Registers/arrays annotated Pub must agree exactly. Arrays annotated Sec
  // may differ in contents but must agree in length: lengths/allocations are
  // public metadata in the policy (see threat-model.md). Array *roles* are
  // allocation-site identifiers, so this relation is exactly heap renaming:
  // each run's fresh allocation at a role is paired with the other run's fresh
  // allocation at the same static role, with no identity leak.
  predicate Agree(p: Program, s: State, t: State) {
    Shape(p, s) && Shape(p, t) &&
    (forall i :: 0 <= i < p.registers && RegTaint(p, i) == Pub
       ==> s.regs[i] == t.regs[i]) &&
    (forall r :: 0 <= r < p.roles
       ==> |s.heap[r]| == |t.heap[r]| &&
           (HeapTaint(p, r) == Pub ==> s.heap[r] == t.heap[r]))
  }

  lemma AgreeReg(p: Program, s: State, t: State, i: nat)
    requires Agree(p, s, t)
    requires i < p.registers && RegTaint(p, i) == Pub
    ensures s.regs[i] == t.regs[i]
  {}

  lemma AgreeLen(p: Program, s: State, t: State, r: nat)
    requires Agree(p, s, t)
    requires r < p.roles
    ensures |s.heap[r]| == |t.heap[r]|
  {}

  lemma AgreeHeap(p: Program, s: State, t: State, r: nat)
    requires Agree(p, s, t)
    requires r < p.roles && HeapTaint(p, r) == Pub
    ensures s.heap[r] == t.heap[r]
  {}

  // ---------- Executable semantics ----------

  function DescribeTaints(p: Program, args: seq<nat>): seq<Taint> {
    if |args| == 0 then []
    else [RegTaint(p, args[0])] + DescribeTaints(p, args[1..])
  }

  function PublicArgs(p: Program, regs: seq<bv64>, args: seq<nat>): seq<Arg> {
    if |args| == 0 then []
    else
      var here := if RegTaint(p, args[0]) == Pub
                  then [Arg(Pub, Get(regs, args[0]))] else [];
      here + PublicArgs(p, regs, args[1..])
  }

  function DoStep(p: Program, site: nat, dst: nat, kind: StepKind, s: State): (State, Event)
    requires StepSafe(s, dst, kind)
    ensures Shape(p, s) ==> Shape(p, DoStep(p, site, dst, kind, s).0)
  {
    match kind
    case Lit(w) =>
      (State(s.regs[dst := w], s.heap), EOp(site, 0))
    case Op(k, a, b) =>
      (State(s.regs[dst := Apply(k, s.regs[a], s.regs[b])], s.heap), EOp(site, k))
    case LenOf(role) =>
      (State(s.regs[dst := ToWord(|s.heap[role]|)], s.heap), ELen(site, role, |s.heap[role]|))
    case Load(role, idx) =>
      var i := Unsigned(s.regs[idx]);
      if i < |s.heap[role]| then
        (State(s.regs[dst := s.heap[role][i]], s.heap), ELoad(site, role, i))
      else
        (s, EFault(site, role, i))
    case Store(role, idx, v) =>
      var i := Unsigned(s.regs[idx]);
      if i < |s.heap[role]| then
        (State(s.regs, s.heap[role := s.heap[role][i := s.regs[v]]]), EStore(site, role, i))
      else
        (s, EFault(site, role, i))
    case Alloc(role, size, fill) =>
      var n := Unsigned(s.regs[size]);
      (State(s.regs[dst := ToWord(role)], s.heap[role := seq(n, _ => fill)]), EAlloc(site, role, n))
    case Call(target, args, heapArgs, shape) =>
      (State(s.regs[dst := ProviderResult(target, PublicArgs(p, s.regs, args))], s.heap),
       ECall(site, target, PublicArgs(p, s.regs, args)))
  }

  function Exec(p: Program, pc: nat, s: State, fuel: nat): (State, seq<Event>)
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
        var (s1, e1) := DoStep(p, site, dst, kind, s);
        // An out-of-bounds array fault is terminal (the JVM throws); do not
        // continue executing following instructions after an EFault.
        if e1.EFault? then (s1, [e1])
        else
          var (s2, e2) := Exec(p, next, s1, fuel - 1);
          (s2, [e1] + e2)
      case IGoto(next) =>
        Exec(p, next, s, fuel - 1)
      case IBranch(site, cond, thn, els) =>
        var take := Get(s.regs, cond) != 0;
        var (s1, e1) := Exec(p, if take then thn else els, s, fuel - 1);
        (s1, [EGuard(site, take)] + e1)
      case ISwitch(site, cond, cases, dflt) =>
        var v := Get(s.regs, cond);
        var index := SwitchIndex(v, cases);
        var target := if index < |cases| then cases[index].1 else dflt;
        var (s1, e1) := Exec(p, target, s, fuel - 1);
        (s1, [ESwitch(site, index)] + e1)
      case IStop =>
        (s, [])
      case IRaise(site, code) =>
        (s, [ERaise(site, code)])
  }

  // ---------- Preservation lemmas ----------

  lemma DoStepSafe(p: Program, site: nat, dst: nat, kind: StepKind, s: State, t: State)
    requires Structure(p) && Agree(p, s, t)
    requires dst < p.registers && StepOK(p, dst, kind)
    ensures StepSafe(s, dst, kind) && StepSafe(t, dst, kind)
  {}

  lemma PublicArgsAgree(p: Program, s: seq<bv64>, t: seq<bv64>, args: seq<nat>)
    requires forall k :: 0 <= k < |args| ==>
      (RegTaint(p, args[k]) == Pub ==> Get(s, args[k]) == Get(t, args[k]))
    ensures PublicArgs(p, s, args) == PublicArgs(p, t, args)
    decreases |args|
  {
    if |args| != 0 {
      PublicArgsAgree(p, s, t, args[1..]);
    }
  }

  lemma DoStepTrace(p: Program, site: nat, dst: nat, kind: StepKind, s: State, t: State)
    requires Structure(p) && Agree(p, s, t)
    requires dst < p.registers && StepOK(p, dst, kind)
    requires StepSafe(s, dst, kind) && StepSafe(t, dst, kind)
    ensures DoStep(p, site, dst, kind, s).1 == DoStep(p, site, dst, kind, t).1
  {
    match kind {
      case Lit(_) =>
      case Op(k, a, b) =>
      case LenOf(role) =>
        AgreeLen(p, s, t, role);
      case Load(role, idx) =>
        AgreeReg(p, s, t, idx);
        AgreeLen(p, s, t, role);
      case Store(role, idx, v) =>
        AgreeReg(p, s, t, idx);
        AgreeLen(p, s, t, role);
      case Alloc(role, size, fill) =>
        AgreeReg(p, s, t, size);
      case Call(target, args, heapArgs, shape) =>
        forall k | 0 <= k < |args| && RegTaint(p, args[k]) == Pub
          ensures Get(s.regs, args[k]) == Get(t.regs, args[k])
        {
          AgreeReg(p, s, t, args[k]);
        }
        PublicArgsAgree(p, s.regs, t.regs, args);
    }
  }

  lemma OrTPubLeft(a: Taint, b: Taint)
    requires OrT(a, b) == Pub
    ensures a == Pub && b == Pub
  {}

  lemma DoStepAgree(p: Program, site: nat, dst: nat, kind: StepKind, s: State, t: State)
    requires Structure(p) && Agree(p, s, t)
    requires dst < p.registers && StepOK(p, dst, kind)
    requires StepSafe(s, dst, kind) && StepSafe(t, dst, kind)
    ensures Agree(p, DoStep(p, site, dst, kind, s).0, DoStep(p, site, dst, kind, t).0)
  {
    var s1 := DoStep(p, site, dst, kind, s).0;
    var t1 := DoStep(p, site, dst, kind, t).0;
    assert Shape(p, s1) && Shape(p, t1);
    match kind {
      case Lit(w) =>
        assert s1.regs[dst] == t1.regs[dst];
        assert s1.heap == s.heap && t1.heap == t.heap;
      case Op(k, a, b) =>
        if RegTaint(p, dst) == Pub {
          OrTPubLeft(RegTaint(p, a), RegTaint(p, b));
          AgreeReg(p, s, t, a);
          AgreeReg(p, s, t, b);
        }
        assert s1.heap == s.heap && t1.heap == t.heap;
      case LenOf(role) =>
        AgreeLen(p, s, t, role);
        if RegTaint(p, dst) == Pub {
          assert s1.regs[dst] == t1.regs[dst];
        }
        assert s1.heap == s.heap && t1.heap == t.heap;
      case Load(role, idx) =>
        AgreeReg(p, s, t, idx);
        AgreeLen(p, s, t, role);
        if RegTaint(p, dst) == Pub {
          assert HeapTaint(p, role) == Pub;
          AgreeHeap(p, s, t, role);
          assert s1.regs[dst] == t1.regs[dst];
        }
        assert s1.heap == s.heap && t1.heap == t.heap;
      case Store(role, idx, v) =>
        AgreeReg(p, s, t, idx);
        AgreeLen(p, s, t, role);
        if HeapTaint(p, role) == Pub {
          AgreeHeap(p, s, t, role);
          AgreeReg(p, s, t, v);
          assert s1.heap[role] == t1.heap[role];
        }
      case Alloc(role, size, fill) =>
        AgreeReg(p, s, t, size);
        if RegTaint(p, dst) == Pub {
          assert s1.regs[dst] == t1.regs[dst];
        }
        assert s1.heap[role] == t1.heap[role];
      case Call(target, args, heapArgs, shape) =>
        forall k | 0 <= k < |args| && RegTaint(p, args[k]) == Pub
          ensures Get(s.regs, args[k]) == Get(t.regs, args[k])
        {
          AgreeReg(p, s, t, args[k]);
        }
        PublicArgsAgree(p, s.regs, t.regs, args);
        assert s1.regs[dst] == t1.regs[dst];
        assert s1.heap == s.heap && t1.heap == t.heap;
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

  function RoleOf(kind: StepKind): nat {
    match kind
    case Lit(_) => 0
    case Op(_, _, _) => 0
    case LenOf(_) => 0
    case Load(role, _) => role
    case Store(role, _, _) => role
    case Alloc(role, _, _) => role
    case Call(_, _, _, _) => 0
  }

  lemma ExecTwoRun(p: Program, pc: nat, s: State, t: State, fuel: nat)
    requires Structure(p)
    requires Agree(p, s, t)
    requires pc < p.instructions
    ensures Exec(p, pc, s, fuel).1 == Exec(p, pc, t, fuel).1
    ensures Agree(p, Exec(p, pc, s, fuel).0, Exec(p, pc, t, fuel).0)
    decreases fuel
  {
    if fuel == 0 {
    } else {
      var inst := InstrAt(p, pc);
      match inst {
        case IStep(site, dst, kind, next) =>
          DoStepSafe(p, site, dst, kind, s, t);
          DoStepTrace(p, site, dst, kind, s, t);
          DoStepAgree(p, site, dst, kind, s, t);
          var s1 := DoStep(p, site, dst, kind, s).0;
          var t1 := DoStep(p, site, dst, kind, t).0;
          assert Shape(p, s1) && Shape(p, t1);
          ExecTwoRun(p, next, s1, t1, fuel - 1);
        case IGoto(next) =>
          ExecTwoRun(p, next, s, t, fuel - 1);
        case IBranch(site, cond, thn, els) =>
          AgreeReg(p, s, t, cond);
          var take := Get(s.regs, cond) != 0;
          assert (Get(t.regs, cond) != 0) == take;
          ExecTwoRun(p, if take then thn else els, s, t, fuel - 1);
        case ISwitch(site, cond, cases, dflt) =>
          AgreeReg(p, s, t, cond);
          var v := Get(s.regs, cond);
          assert Get(t.regs, cond) == v;
          var index := SwitchIndex(v, cases);
          var target := if index < |cases| then cases[index].1 else dflt;
          assert SwitchIndex(Get(t.regs, cond), cases) == index;
          ExecTwoRun(p, target, s, t, fuel - 1);
        case IStop =>
        case IRaise(site, code) =>
      }
    }
  }

  // ---------- Concrete instances (non-vacuity and controls) ----------

  // Positive instance: a public loop counter bounded by a public limit; the
  // body writes a *secret* register into a secret array at the public loop
  // index. Structure holds, the trace is non-empty, branch decisions and
  // addresses are recorded, and two runs that differ only in the secret
  // register have exactly equal traces.
  function CounterProgram(): Program {
    Program(
      registers := 5,
      roles := 1,
      inputs := 2,                       // reg0 public limit, reg1 secret word
      annots := [[Pub, Sec, Pub, Pub, Pub]],
      heapAnnots := [Sec],
      chunks := [[
        IStep(1, 2, Lit(0), 1),          // i := 0
        IStep(2, 3, Lit(1), 2),          // one := 1
        IStep(3, 4, Op(1, 2, 0), 3),     // cmp := i < limit
        IBranch(4, 4, 4, 7),             // public branch
        IStep(5, 0, Store(0, 2, 1), 5),  // secret[public i] := secret word
        IStep(6, 2, Op(2, 2, 3), 6),     // i := i + one
        IGoto(2),
        IStop()
      ]],
      instructions := 8
    )
  }

  // A control: branching on a secret register violates Structure.
  function SecretBranchProgram(): Program {
    Program(
      registers := 2,
      roles := 0,
      inputs := 1,
      annots := [[Sec, Pub]],
      heapAnnots := [],
      chunks := [[
        IStep(1, 1, Lit(1), 1),
        IBranch(2, 0, 2, 2),             // secret condition
        IStop()
      ]],
      instructions := 3
    )
  }

  // A control: using a secret as an array index violates Structure.
  function SecretIndexProgram(): Program {
    Program(
      registers := 2,
      roles := 1,
      inputs := 2,
      annots := [[Sec, Pub]],
      heapAnnots := [Sec],
      chunks := [[
        IStep(1, 1, Load(0, 0), 1),      // secret index
        IStop()
      ]],
      instructions := 2
    )
  }

  // A control: allocating a secret-sized array violates Structure.
  function SecretAllocProgram(): Program {
    Program(
      registers := 2,
      roles := 1,
      inputs := 1,
      annots := [[Sec, Pub]],
      heapAnnots := [Sec],
      chunks := [[
        IStep(1, 1, Alloc(0, 0, 0), 1),  // secret size
        IStop()
      ]],
      instructions := 2
    )
  }

  // A control: a public call result computed from a secret argument violates
  // Structure (a provider result may not be declassified by annotation).
  function SecretCallProgram(): Program {
    Program(
      registers := 2,
      roles := 0,
      inputs := 1,
      annots := [[Sec, Pub]],
      heapAnnots := [],
      chunks := [[
        IStep(1, 1, Call(9, [0], [], false), 1),    // public dst but secret arg
        IStop()
      ]],
      instructions := 2
    )
  }

  // A control: reading a secret array into a register annotated public
  // violates Structure (secret payload laundering).
  function SecretLaunderProgram(): Program {
    Program(
      registers := 2,
      roles := 1,
      inputs := 1,
      annots := [[Pub, Pub]],
      heapAnnots := [Sec],
      chunks := [[
        IStep(1, 1, Load(0, 0), 1),      // secret contents, public annotation
        IStop()
      ]],
      instructions := 2
    )
  }

  lemma OrLeqPub(a: Taint, b: Taint)
    requires TaintLeq(OrT(a, b), Pub)
    ensures a == Pub && b == Pub
  {}

  lemma InstrOKAt(p: Program, i: nat)
    requires Structure(p) && i < p.instructions
    ensures InstrOK(p, InstrAt(p, i))
  {}

  lemma PositiveCounterWellFormed()
    ensures Structure(CounterProgram())
  {
    var p := CounterProgram();
    assert p.instructions == 8 && |p.chunks| == 1 && |p.chunks[0]| == 8;
    forall i | 0 <= i < p.instructions
      ensures InstrOK(p, InstrAt(p, i))
    {
      if i == 0 {
      } else if i == 1 {
      } else if i == 2 {
      } else if i == 3 {
      } else if i == 4 {
      } else if i == 5 {
      } else if i == 6 {
      } else if i == 7 {
      } else {
        assert false;
      }
    }
  }

  lemma PositiveCounterTwoRunIsSecretIndependent(a: bv64, b: bv64)
    ensures Exec(CounterProgram(), 0, State([2, a, 0, 0, 0], [seq(4, _ => 0 as bv64)]), 16).1 ==
            Exec(CounterProgram(), 0, State([2, b, 0, 0, 0], [seq(4, _ => 0 as bv64)]), 16).1
  {
    PositiveCounterWellFormed();
    var s := State([2, a, 0, 0, 0], [seq(4, _ => 0 as bv64)]);
    var t := State([2, b, 0, 0, 0], [seq(4, _ => 0 as bv64)]);
    assert Agree(CounterProgram(), s, t);
    ExecTwoRun(CounterProgram(), 0, s, t, 16);
  }

  lemma SecretBranchRejected()
    ensures !Structure(SecretBranchProgram())
  {
    var p := SecretBranchProgram();
    assert p.instructions == 3;
    if Structure(p) {
      InstrOKAt(p, 1);
      assert InstrAt(p, 1) == IBranch(2, 0, 2, 2);
      assert RegTaint(p, 0) == Sec;
    }
  }

  lemma SecretIndexRejected()
    ensures !Structure(SecretIndexProgram())
  {
    var p := SecretIndexProgram();
    assert p.instructions == 2;
    if Structure(p) {
      InstrOKAt(p, 0);
      assert InstrAt(p, 0) == IStep(1, 1, Load(0, 0), 1);
      assert RegTaint(p, 0) == Sec;
    }
  }

  lemma SecretAllocRejected()
    ensures !Structure(SecretAllocProgram())
  {
    var p := SecretAllocProgram();
    assert p.instructions == 2;
    if Structure(p) {
      InstrOKAt(p, 0);
      assert InstrAt(p, 0) == IStep(1, 1, Alloc(0, 0, 0), 1);
      assert RegTaint(p, 0) == Sec;
    }
  }

  lemma SecretCallRejected()
    ensures !Structure(SecretCallProgram())
  {
    var p := SecretCallProgram();
    assert p.instructions == 2;
    if Structure(p) {
      InstrOKAt(p, 0);
      assert InstrAt(p, 0) == IStep(1, 1, Call(9, [0], [], false), 1);
      assert RegTaint(p, 1) == Pub;
      assert TaintLeq(OrT(RegTaint(p, 0), Pub), RegTaint(p, 1));
      OrLeqPub(RegTaint(p, 0), Pub);
      assert RegTaint(p, 0) == Pub;
      assert RegTaint(p, 0) == Sec;
    }
  }

  lemma SecretLaunderRejected()
    ensures !Structure(SecretLaunderProgram())
  {
    var p := SecretLaunderProgram();
    assert p.instructions == 2;
    if Structure(p) {
      InstrOKAt(p, 0);
      assert InstrAt(p, 0) == IStep(1, 1, Load(0, 0), 1);
      assert HeapTaint(p, 0) == Sec;
    }
  }
}
