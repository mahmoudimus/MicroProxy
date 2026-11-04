# SHAKE public API state implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove public state/status coupling across actual SHAKE API calls with arbitrary secret contents, retaining an explicit gap to complete logical traces.

**Architecture:** An independent proof root calls unchanged executable Dafny. Relational lemmas over its existing functional specification compose constructor, input, output and destroy calls. An exact source/audit replay qualifies this root without changing the frozen Select component's inputs.

**Tech Stack:** Dafny 4.9.1, bundled Z3, Python and existing source/distribution helpers.

**Spec:** [Approved bounded design](../specs/2026-11-04-shake-api-state-design.md).

## Global Constraints

- Preserve production Dafny/Java, public domains, browser fingerprints, old Select inputs and unrelated edits.
- Use the existing 30-second / 50,000,000-resource policy and `O:smt.case_split=0`.
- No new assumptions, opaque owned algorithms or trace-completeness claim.
- Physical JVM timing stays outstanding; component proof, development review and external review are separate.

## Review Focus

- Phase error must precede an invalid slice after output starts; statuses agree without comparing secret bytes.
- Zero-byte reads still start squeezing; public state coupling must cover that transition.
- Reads at the exact rate boundary and segmented updates must compose for arbitrary lengths.
- Sequential paired calls must not change the second run through hidden cross-run aliases.
- A missing included-body audit, forged summary or timeout must fail the replay, never qualify a negative control.

### Task 1: Actual API relational proofs and replay

**Files:** Create `assurance/shake-api/ApiStateHarness.dfy`, `replay.py`, `test_replay.py`, `inputs.json` and `README.md`; add focused CI replay to `.github/workflows/formal-security.yml` only after local qualification.

**Interfaces:** Consumes actual `NativeShake.Sponge` constructor, `Update`, `Start`, `Next`, `Read`, `Destroy` and `SpongeSpec` equations. Produces a bounded proof root plus a pinned, fail-closed replay report with raw commands/audits/controls; no new broad ledger claim.

- [ ] Write paired-call assertions over equal public states and independent secret contents; record the initial unproved assertions before adding the required relational lemmas.
- [ ] Prove public state relations for absorb/next/read and compose actual method calls, including segmented calls, invalid-slice/phase precedence, zero-byte reads and rate boundaries. State required cross-run alias separation explicitly.
- [ ] Add named false status/phase/position assertions and show genuine verifier failures, rejecting tool failures.
- [ ] Add replay regression tests first for omitted sources/audits, unsafe paths/output refusal, before/after drift and diagnostic misclassification; record RED then GREEN.
- [ ] Implement exact parser-discovered closure, pinned tool policy, included-body verification/audits, preserved raw logs and typed incomplete/failure/success reports. Run `python3 -m unittest discover -s assurance/shake-api -p 'test_*.py' -v` and the documented actual replay; require all positives and exact negatives to pass.
- [ ] Confirm existing production source/generated Java identities and old Select inputs remain unchanged. Add the replay/tests to CI without weakening previous gates. Commit explicit owned paths with `test(formal): prove SHAKE public API state coupling`.

### Task 2: Scope documentation, development review and delivery

**Files:** Update `docs/formal-security.md`, approved source-assurance design/plan, `mkdocs.yml` and any documentation/workflow identity pins in `formal/crypto-obligations.json`; add the external review brief. Root owns these files and issue #117.

**Interfaces:** Consumes Task 1's actual reviewed proof report and exact scope. Produces truthful docs, a review record and tested coherent commits/PR referring to #117 without closing it.

- [ ] Record timing as outstanding and prepare external review scope without claiming that review occurred.
- [ ] Document actual API state/status proofs and all remaining trace/observer/adapter boundaries. Retain existing claim statuses and old proof inputs.
- [ ] Run ledger/release gates, meaningful regression suites and `mkdocs build --strict`; inspect actual results.
- [ ] Obtain a fresh development review against this design/plan, fix important findings with regressions, and record any scope ruling.
- [ ] Commit/push with explicit `HEAD:refs/heads/diff/dafny-shake-source-traces`, open a PR using `Refs #117`, and merge only after eligible final-head checks pass under the existing maintainer authorization. Keep #117 open with precise remaining work.
