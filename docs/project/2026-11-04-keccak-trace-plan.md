# Complete Keccak source observations implementation plan

> **For agentic workers:** Use `superpowers:executing-plans` for root-owned
> implementation and fresh independent review at each gate. Delegated production
> work uses the user's selected Pi DeepSeek Flash or Composer 2.5. Preserve
> explicit ownership and unrelated work.

**Goal:** Qualify complete same-body logical observations for all eleven native
Keccak methods and four pure functions without changing production class bytes.

**Architecture:** Keep historical Select qualification frozen. Add a separate
resolved-AST binding and coverage package, instrument the actual executable
Dafny implementation, prove paired executions, then regenerate and qualify the
complete delivered Java closure. First settle the smallest pure-snapshot grammar
against actual Dafny ASTs; expand coverage only after that gate passes.

**Tech stack:** Dafny 4.9.1, its pinned bundled solver, the fixed 30-second /
50-million-resource / two-core proof policy, C# plugin, Python replay, JDK 21/25.

**Spec:** [Full source trace and adapter composition](2026-11-04-full-trace-composition.md).

## Global constraints

- Preserve functional contracts, API domains, frames, freshness and alias cases.
- Logical observations and compiler/provider/JVM timing claims stay distinct.
- No new axioms, opaque owned algorithms, handwritten generated Java or edited
  frozen Select fixtures. No successful control from resource/parse/tool errors.
- Preserve literal Java source diffs; require complete class-set/byte equality
  on each qualified JDK profile before adopting ghost instrumentation.
- Do not alter or duplicate the separately owned 0.8.1 publication chain.

## Review focus

- Wrong private arguments can preserve Rotate's trace: test full-result/value
  correspondence and reject mismatched snapshots (task 1).
- Ghost branches can reassign a captured witness: count every definition and
  reject rebinding even when the positive proof still succeeds (task 1).
- Interposed array writes can stale a snapshot: reject executable gaps and
  prove a faithful stale-value control fails (task 1).
- Child traces can have correct values in the wrong position: test dropped,
  duplicated and reordered children/calls in surrounding expressions (task 2).
- Permitted shared buffers can couple paired executions: prove the original
  frame domains and specific shared-buffer callers (task 3).

## Task 1: Resolve and test the pure-snapshot binding

**Files:** Create `formal/source/keccak/checker/PureSnapshotCoverage.cs` and its
project, `formal/source/keccak/test_snapshot_binding.py`, a focused fixture/proof
under `formal/source/keccak/controls/`, and a package README. Develop candidates
outside historical qualification packages.

**Interfaces:** The plugin resolves the actual `NativeKeccak` functions and
caller ASTs. Its canonical root/function inventories are fixed, never reduced
by ambient environment selectors. It reports each accepted executable call and
its witness binding; unsupported or uncovered bindings are errors. This focused
gate does not claim full operation coverage.

- [ ] Write positive actual-source fixtures for local and array-read arguments,
  and failing controls for mismatched private arguments, ghost reassignment,
  interposed writes, shadows, by-method functions, unbound second calls and
  fabricated witnesses.
- [ ] Run the controls against the old checker and preserve its rejection of
  the new representation; do not weaken its frozen expectations.
- [ ] Implement exact resolved declaration/argument/prestate binding with a
  single-definition full-tuple ghost witness, inline actual `.0`, and exactly
  one ordered `.1` consumption. Reject unsupported syntax.
- [x] Add and verify a direct Dafny value/full-result bridge over actual Rotate.
  A changed private value between snapshot and actual call must fail a genuine
  assertion under the same policy as its original positive counterpart.
- [ ] Run the plugin against actual mutated resolved ASTs. Require each negative
  to fail for its intended binding error, with unchanged positives passing.
- [ ] Obtain fresh independent design/code review and commit only explicit paths.

## Task 2: Complete executable Keccak instrumentation and coverage

**Files:** Modify actual `formal/crypto/NativeKeccak.dfy` and its direct Dafny
callers on the isolated branch; create `formal/source/keccak/checker/KeccakSourceCoverage.cs`,
`NativeKeccakTraceHarness.dfy`, package replay, controls and manifest.

**Interfaces:** Consume task 1's reviewed binding. Produce actual ghost outputs
and an exact eleven-method/four-function inventory. Use the existing canonical
SourceTrace encoding, mandatory declared operation counts and actual child
outputs. Do not introduce a separate executable Keccak model.

- [ ] Add omission/order controls for Ops, branches, reads/writes, calls,
  allocation/initialization, loops and cleanup; confirm missing coverage rejects.
- [ ] Instrument all actual bodies and preserve their functional contracts.
  Thread traces through `Round`, `PermuteScratch`, factories and `Permute`.
- [ ] Implement resolved AST coverage in evaluation order, including argument
  reads, each declared operation family and the snapshot protocol. Require the
  exact root sets and reject unknown syntax/callees.
- [ ] Prove every included owned body and all four pure value/trace bodies.
  Audit each included source. Preserve exact source/tool maps and raw logs.
- [ ] Regenerate the complete production Java graph and compare literal sources
  and all class sets/bytes on both qualified JDKs. Investigate every difference.
- [ ] Obtain independent code review of observation faithfulness and controls.

## Task 3: Paired closure and fresh qualification

**Files:** Keccak paired harness/replay/controls plus affected Select,
polynomial, SHAKE API, functional and delivery qualification consumers.

**Interfaces:** Consume task 2's actual checked program and produce receipts
bound to that exact graph. Every receipt distinguishes new evidence from reused
historical results. No old receipt is relabeled for changed source bytes.

- [ ] Prove independent secret words/constants produce equal declared traces for
  every root, including allocation and cleanup paths. Preserve all original
  within-call aliases and prove cross-run frames/shared-buffer cases.
- [ ] Inject a faithfully observed private branch and address; require paired
  equality failures and coverage acceptance. Drop their observations and require
  coverage failure. Include unchanged focused positives for each control.
- [ ] Freeze manifests, checker build and tool identities; replay proofs, audits
  and controls from immutable inputs and verify receipt/log integrity.
- [ ] Requalify every affected consumer with a new epoch and preserved historical
  packages. Run appropriate crypto, delivery and fingerprint regressions.
- [ ] Obtain independent whole-change review, address findings and commit.

## Task 4: Documentation and coordinated delivery

**Files:** Assurance documentation, evidence bundles/gates, documentation index
and issue #117. Production generated Java changes only through regeneration.

- [ ] Record the exact Keccak theorem, public/secret domain, logical observation
  limits, accepted Java diff and remaining trusted components.
- [ ] Refresh the immutable baseline after 0.8.1 publication completes. Qualify
  the actual released JAR/bundle separately if required by the release ledger.
- [ ] Run documentation generation/checks and the current eligible-head CI/proof
  matrix. Push only explicit branch refs; leave the release owner in control.
- [ ] Merge only after required exact-head checks pass and release coordination
  permits it. Keep #117 open for subsequent SHAKE/KEM/HKDF and adapter composition.

The broader stages follow this deliverable. Their concrete plans must use the
reviewed caller/adapter inventory and actual new Keccak contracts; this document
does not imply those later composition proofs already exist.
