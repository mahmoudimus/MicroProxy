// SPDX-License-Identifier: Apache-2.0
// Idealized straight-line word machine. The bytecode checker is the trusted
// bridge from emitted Java to this language. Atomic primitive cost/behavior,
// JVM exceptions/JIT/GC/CPU/provider details are outside the trace observer.
module PacketTrace {
  datatype Node = Node(kind: nat, a: nat, b: nat, literal: bv64)
  // kind0: literal; kind1: input slot; kind>=2: atomic word instruction.
  ghost predicate ValidNode(n: Node, inputs: nat, registers: nat) {
    if n.kind == 0 then true
    else if n.kind == 1 then n.a < inputs
    else n.a < registers && n.b < registers
  }
  ghost predicate Valid(code: seq<Node>, inputs: nat, registers: nat) {
    forall i :: 0 <= i < |code| ==> ValidNode(code[i], inputs, registers + i)
  }
  lemma ValidAppend(left: seq<Node>, right: seq<Node>, inputs: nat, registers: nat)
    requires Valid(left, inputs, registers)
    requires Valid(right, inputs, registers + |left|)
    ensures Valid(left + right, inputs, registers)
  {
    forall i | 0 <= i < |left + right|
      ensures ValidNode((left + right)[i], inputs, registers + i)
    {
      if i < |left| {
        assert (left + right)[i] == left[i];
      } else {
        assert (left + right)[i] == right[i - |left|];
      }
    }
  }
  ghost function Observe(n: Node): seq<nat> { [n.kind, n.a, n.b] }
  ghost function ProgramTrace(code: seq<Node>): seq<nat>
    decreases |code|
  {
    if |code| == 0 then [] else Observe(code[0]) + ProgramTrace(code[1..])
  }
  ghost function Step(n: Node, inputs: seq<bv64>, registers: seq<bv64>,
                       operation: (nat, bv64, bv64) -> bv64): bv64
    requires ValidNode(n, |inputs|, |registers|)
  {
    if n.kind == 0 then n.literal
    else if n.kind == 1 then inputs[n.a]
    else operation(n.kind, registers[n.a], registers[n.b])
  }
  ghost function Run(code: seq<Node>, inputs: seq<bv64>, registers: seq<bv64>,
                      operation: (nat, bv64, bv64) -> bv64): (seq<bv64>, seq<nat>)
    requires Valid(code, |inputs|, |registers|)
    decreases |code|
  {
    if |code| == 0 then (registers, [])
    else
      var value := Step(code[0], inputs, registers, operation);
      var tail := Run(code[1..], inputs, registers + [value], operation);
      (tail.0, Observe(code[0]) + tail.1)
  }
  lemma TraceMatches(code: seq<Node>, inputs: seq<bv64>, registers: seq<bv64>,
                     operation: (nat, bv64, bv64) -> bv64)
    requires Valid(code, |inputs|, |registers|)
    ensures Run(code, inputs, registers, operation).1 == ProgramTrace(code)
    decreases |code|
  {
    if |code| != 0 {
      var value := Step(code[0], inputs, registers, operation);
      TraceMatches(code[1..], inputs, registers + [value], operation);
    }
  }
  lemma TwoRun(code: seq<Node>, left: seq<bv64>, right: seq<bv64>,
               a: seq<bv64>, b: seq<bv64>, operation: (nat, bv64, bv64) -> bv64)
    requires |left| == |right| && |a| == |b|
    requires Valid(code, |left|, |a|)
    ensures Run(code, left, a, operation).1 == Run(code, right, b, operation).1
  {
    TraceMatches(code, left, a, operation);
    TraceMatches(code, right, b, operation);
  }
}
