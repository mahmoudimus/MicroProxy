# SHAKE and ML-KEM Dafny foundations

> **For agentic workers:** Use `superpowers:executing-plans` to implement this
> selected route in the current isolated worktree. The user requested execution
> and publication; preserve the existing PR stack and unrelated work.

**Goal:** Deliver the first independently replayable SHAKE/ML-KEM Dafny component:
Keccak lane-level permutation equations and ML-KEM field-helper/range proofs,
with generated Java exercised against the canonical handwritten implementation.

**Architecture:** Keep pure mathematical reference functions separate from
executable Dafny loops/arithmetic. Generate Java with verification enabled and
test the exact output with the pinned Dafny runtime in an opt-in harness. Existing
production SHAKE/ML-KEM and runtime dependencies remain unchanged at this stage.

**Tech stack:** Dafny 4.9.1, its pinned bundled solver/runtime, Python 3.11+, JDK 21/25.
**Spec:** FIPS 202 sections 3.2/3.3 (64-bit lanes indexed x+5y), FIPS 203 q=3329,
and the field-helper contracts in canonical `MlKem768.java`. This document is the
bounded design and implementation plan for V4/V5 in issue #117.

## Design and alternatives

The user selected verified Dafny implementations compiled to Java. A copied model
alone would leave the generated-code delivery unchecked; direct SAW refinement is
still useful for retained Java but its array support is incomplete here. Start
with an isolated component so compilation/runtime/array ownership and cost can be
reviewed before production adoption. Existing TLA+/Lean evidence stays separate.

The permutation spec composes theta, rho, pi, chi and iota for 24 rounds. The
executable implementation uses snapshot-based lane loops. Round constants and
rho offsets are standards-reviewed tables, additionally checked against independent
FIPS recurrences in the harness; no full bit-string-to-lane refinement is claimed.
The field spec uses mathematical remainder. Executable arithmetic models the
existing 16-bit wrap/shift reduction and Barrett quotient. Its maximum input is
3328*6657=22154496, covering scalar mul/mulSub/addMul contracts, including inputs
above the existing reduce comment's 2^24 bound. Polynomial caller invariants stay open.

## Global constraints

- No new production dependency, API, wire, browser-profile or fixture changes.
- Proofs must cover all 25-lane inputs and all declared field-helper inputs.
- No custom axioms, assumptions or skipped verification in these owned kernels.
- Parsing failures, timeouts and resource exhaustion cannot pass negative controls.
- Generated Java must come from the verified source; no handwritten alternative.
- Compiler/runtime, Java adapters and finite tests remain explicitly trusted.
- Full sponge padding/segmented API, NTT/codecs/sampling/KEM composition and timing
  remain open. Functional correctness is not a hardness/security reduction.

## Review focus

1. Swapped lane axes or rotation directions: independent rotation/coordinate checks
   and canonical permutation comparisons, including every one-bit input.
2. Round omission/order/constants: independent recurrence/table checks, a changed
   round-count negative control and Keccak zero-state known answer.
3. Barrett inputs above 2^24: full-domain proof plus boundary and randomized Java
   comparisons through 22154496; don't imply Java caller invariants are proved.
4. Narrowed preconditions/extra assumptions: unconstrained domain harnesses and
   positive/negative audit controls.
5. Stale evidence or wrong generated class: fail-closed reporting, source/tool
   pins, generated/class hashes and exact compilation of canonical references.

## Task 1: Publish the method overview

- [x] Explain TLA+/TLC, Lean4, Dafny and SAW roles in `docs/formal-security.md` and
  `formal/README.md`; distinguish models, generated code and implementation bridges.
- [x] Run strict docs/index checks; commit and push to the existing packet PR.

## Task 2: Verify the isolated kernels

Files: `formal/primitives/Keccak.dfy`, `Field.dfy`.
Interfaces: `VerifiedKeccak.Permute(seq<bv64>) -> seq<bv64>` for length25;
`VerifiedField.ReduceOnce`, `Reduce`, `Add`, `Sub`, `Mul`, `MulSub`, `AddMul`
over their stated nonnegative canonical-coefficient domains.

- [x] Write full result specifications and a deliberately wrong executable body;
  observe actual proof-obligation rejection before implementing.
- [x] Prove snapshot-loop invariants for all Keccak stages and 24-round composition.
- [x] Prove scalar range preservation and modular results through 22154496.
- [x] Add public-domain harnesses and meaningful semantic/domain/audit mutants.

## Task 3: Replay generated Java and publish evidence

Files: `formal/primitives/run.py`, `inputs.json`, `test_run.py`,
`java/.../GeneratedPrimitivesTest.java`, `README.md`; formal-security CI and docs.

- [x] Start with failing gate/harness tests, then implement the minimal replay.
- [x] Reuse pinned installer and bounded process cleanup; invalidate prior success,
  verify/audit/generate, compile exact output plus canonical references, test, hash.
- [x] Check independent coordinates/constants, all one-bit permutation inputs,
  randomized/high-bit states, all ReduceOnce values and wider Barrett boundaries.
- [x] Replay on JDK 21 and25, run regression/standards/fingerprint tests, docs checks
  and independent agent review; fix important findings with regression controls.
Publication/handoff: commit the delivery gates/evidence, push a stacked draft PR
and update issue117 without closing V4/V5/V6. The execution ledger and PR record
publication status.
