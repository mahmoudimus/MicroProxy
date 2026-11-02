# Crypto verification issue 117 completion plan

> **For agentic workers:** Use the existing crypto verification design and execute the independently reviewable tasks below. The user selected Pi subagents using DeepSeek Flash or Composer 2.5.

**Goal:** Complete the remaining implementation and assurance work in issue 117, preserving explicit gaps that require external review or deferred JVM timing work.

**Status of this plan (2026-11-02): partial, not complete.** The generated-nonce functional
production route is implemented and locally bound; its required CI and merge gates
are separate acceptance steps, and the broad issue remains open. This plan does not
claim that only timing remains: the SAW nonce bytecode route is still blocked, the full AWS
upstream closure is still unreproduced, the trace work still has open roots/assumed callees
(the corrected trace snapshot retains 15 open roots, 19 assumed contracts and
31 unchecked labels), and independent external expert review is absent.

**Architecture:** Continue the approved Dafny-to-Java route for HKDF, with the existing generated SHAKE/ML-KEM backend. Establish separate evidence for functional correctness, source-level traces, measured execution and external review. A unified ledger checks the declared scope and provenance; it does not replace proof replays.

**Tech stack:** Dafny 4.9.1, bundled Z3 4.12.1, Java 21 and 25, DafnyRuntime 4.9.1, Python gates, existing Lean/TLC and SAW evidence.

**Spec:** [Original verification plan](2026-10-28-java-crypto-verification.md) and [assurance design](2026-10-28-quic-crypto-assurance-design.md). This is an execution supplement, not a weaker replacement.

## Constraints

- Preserve public APIs, accepted input domains, standards outputs, captured browser fingerprints and unrelated work.
- Generate production algorithm code from verified Dafny; review Java/provider adapters explicitly.
- Keep compiler/runtime/JDK primitive, entropy and hardness assumptions separate.
- Do not admit new assumptions to discharge owned algorithm obligations or count resource failures as successful mutation controls.
- Require exact source, generated-file inventory, class and artifact provenance for the claim being made.
- JVM physical timing remains deferred by the user. Agent review is not external cryptographic expert review.
- SAW array-clone work remains an alternative for retained handwritten Java; it does not block the selected generated-HKDF route. Its historical blocked result stays visible until actually discharged.

## Review focus

1. Short nonempty PRKs, zero output and empty TLS labels remain accepted where the existing Java implementation accepted them.
2. Mutable caller arrays, repeated calls and concurrent calls must not share secret provider state or returned buffers.
3. Byte-oriented SHAKE, public-seed sampling and secret noise generation have different public/secret classifications; no reclassification may hide a leak.
4. A control must fail because its named property is false, rather than because the verifier timed out, crashed or rejected syntax.
5. A stale historical JAR receipt, model-only theorem or agent review must never authenticate a current production, timing or expert-review claim.

## Task 1: Production HKDF delivery (V1/V2)

**Owner:** Pi HKDF worker. **Files:** `formal/dafny/`, a distinct production generated-HKDF package, `quic/.../Hkdf.java` and focused regression tests. The coordinator owns shared manifests, CI and final documentation.

- [x] Pin compatibility with regression tests for SHA-256/SHA-384, RFC vectors, boundary lengths, ASCII labels, caller preservation and repeated/concurrent execution.
- [x] Verify the general accepted domain and meaningful negative controls, then generate the production Java implementation.
- [x] Review JCE state/reset semantics and buffer adapters; record any remaining trusted implementation boundary.
- [x] Connect generation to exact source/class/JAR checks and run key-schedule/fingerprint compatibility and performance checks.
- [x] Independently review the implementation and evidence before integration.

## Task 2: Implementation-connected secret traces (V7)

**Owner:** Pi trace worker. **Files:** new `formal/timing/` component and target-specific checked extraction/guards.

- [x] Specify the observer, public inputs, secrets, permitted declassifications, provider calls, errors and allocation identity.
- [ ] Write paired-execution Dafny proofs for the actual owned control/data flow, with an explicit checked connection to final implementation classes.
- [x] Reject secret branches, secret indices, early comparisons, exception oracles and unsupported instructions with authentic controls.
- [x] Replay final HKDF, SHAKE and ML-KEM targets and report any untranslated operations or residual source-level leaks separately from deferred physical timing.

## Task 3: Unified ledger and claim gate (V0/V8)

**Owner:** Pi ledger worker. **Files:** `formal/crypto-obligations.json`, `formal/obligations.md`, `scripts/security/check_crypto_obligations.py`, `check_crypto_release.py` and gate regressions.

- [x] Create a fixed obligation inventory and dependency graph, distinguishing proofs, tests, assumptions, alternatives, blockers and deferrals.
- [x] Consume existing component evidence without promoting finite checks to universal implementation proofs.
- [x] Test stale hashes, dropped obligations, unknown assumptions, vacuity, unsupported operations, resource failures, altered classes and overbroad claims.
- [x] Require current replay evidence for current artifact claims, with honest residuals and separate functional/trace/timing/expert-review gates.

## Task 4: Provenance and alternative backend audit (V1/V3)

**Owner:** coordinator after the Pi PR audit.

- [x] Replay the pinned AWS HKDF dependency graph where supported; preserve attribution and report unreproduced graph obligations.
- [x] Inspect portable SAW/Crucible and array-clone support against the recorded blocker. Implement a reviewed bridge only if it proves fresh allocation, element equality and source preservation without assuming the desired result.
- [x] Retain an explicit alternative-route classification if the selected generated route makes that backend unnecessary; never mark a blocked backend proved.

## Task 5: PR and documentation delivery

**Owner:** coordinator; Pi PR worker supplies independent review.

- [x] Add GitHub to the top-level navigation and verify rendered HTML, strict MkDocs and links.
- [x] Review current open PRs against exact heads. Merge only eligible changes after the required checks; assess release side effects separately.
- [x] Reconcile assurance documentation, original checklist and issue 117 with current evidence. Keep external review and timing obligations visible. (Bounded reconciliation: this plan remains partial; the nonce functional route is implemented, and the SAW bytecode route stays blocked.)
- [ ] Run the appropriate proof, gate, Maven, fingerprint and packaging checks; commit/push coherent changes and verify remote heads.

## Execution evidence and remaining work

Production HKDF now delegates to the verified generated kernel. The final replay
checks 21 kernel obligations, 22 unrestricted-domain obligations, ten proof/audit/
compiled-adapter controls, and 45 JCE cases with 2,766 assertions on each of JDK
21 and 25. The earlier HKDF adoption record reports 4,146 test executions per
JDK with no failures/errors and 23 skips; its fingerprint tests passed. The source, runtime,
canonical-class and actual library/bundle evidence is in the
[HKDF adoption record](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/crypto/adoption/hkdf).
It includes the measured allocation increase and inconclusive shared-host CPU
results, rather than treating performance measurements as timing-security proof.

The combined ledger and release gates have 123 regression tests on this base. The reviewed policy requires
the complete source/generated-file/control inventories and positive proof/execution results.
A self-declared JSON status cannot enable future timing, expert-review,
whole-system, AWS-closure or current-release claims. Actual artifact checks run
against the specified build separately from those static claim labels.

Production `PacketKey.nonce` delegates to the Dafny-verified generated
`VerifiedNonce.__default.Nonce`. The combined local `mvn test` reactor passes
4,109 tests per JDK 21/25, with zero failures/errors and 23 skips; CI additionally
runs `verify` and the Linux nonce proof replay. Local evidence is not a release
or deployment attestation. The frozen nonce replay records 337 kernel and 343
domain assertions, zero audit findings, five genuine proof-obligation rejects, a bounded
`--no-verify` translation byte-identical to the checked-in source, and
`NONCE-TEST-OK cases=10 assertions=162774` on JDK 21 and 25. The candidate adoption receipt binds
the live bridge, generated source, `GENERATED.json`, the central delivery inventory
(468 library / 84 scoped crypto / 468 retained classes), a separate executed 9-case
bundle nonce/seal/open smoke and eight `PacketKeyNonceTest` cases on both JDKs. The
narrow `packet-nonce-functional-production` claim is supported; V3 remains `blocked`
because the historical SAW `PacketKey.nonce` proof is still blocked by array-clone
translation. No cryptographic-hardness, constant-time, JVM-timing or full-JAR claim
follows.

The trace milestone covers five conditional caller certificates: ML-KEM's full
1088-byte comparison/selection, public-seed rejection sampling, and generated HKDF
Extract, Expand and label serialization. All instructions in those certificates
are reachable from entry. The corrected snapshot also verifies four owned helpers and a separate composed
Feed. A compiled 138-row Apply probe, 90 trace tests, 27 fixtures and nine genuine
proof-failure mutants exercise extraction and execution controls. Wipe must
execute four stores to its private parameter role; private-input liveness is
enforced. The original 19 opaque owned helper/adapter contracts used by
these callers remain explicit assumptions; binding their actual class bytes does
not prove their traces. This is why the full paired-flow task remains unchecked.
Unsupported object, dispatch, alias and exception paths are rejected. The separate composed Feed reduces its own opaque set from ten to seven;
substituting it would yield a 16-contract union, which is not the selected
five-caller set. The report records 15 open roots and 31 unchecked callee labels instead of hiding them as
provider code. Those counts are the pre-trace-correction snapshot; the separately
reviewed trace correction is reconciled by root, not silently reclassified here.
The final core and replay evidence stays in
[the trace component](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/timing).

The next implementation work is to establish exact receiver/type and ownership
contracts for the production factories, then compose SHAKE sponge, Keccak,
polynomial/NTT/KEM and Java adapter callees. Secret-comparison wrappers also need
implementation-connected relational coverage beyond their existing reviewed
JDK equality calls. A newly admitted path needs a successful certificate and
controls for the previous counterexample; a version string, finite test or
caller-only theorem cannot close that work.

The AWS target passes nine checks; its full 71-file dependency replay failed and
remains a separate reference obligation. The selected standalone HKDF kernel
imports none of that graph. SAW's primitive-array clone translation remains a
concrete blocker for the alternative nonce proof. PRs #123 and #124 were reviewed
and merged; release PR #98 is held for its snapshot-install documentation defect
and absent successful CI. Independent external expert review is still required;
JVM/JIT/CPU/GC/provider physical timing remains explicitly deferred.
