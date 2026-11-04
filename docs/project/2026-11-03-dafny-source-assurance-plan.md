# Executable Dafny source assurance implementation plan

> For agentic workers: execute the approved source-first direction. Use Pi
> DeepSeek Flash or Composer 2.5 for the delegated tasks. Do not restart the
> paused bytecode receiver/compositor experiments as the primary route.

**Goal:** Complete the owned crypto source-level obligations using the actual
verified Dafny implementation and its generated Java, preserving explicit
remaining trust boundaries.

**Architecture:** Actual Dafny heap, freshness and frame contracts provide the
ownership boundary. Source trace proofs must consume observations connected to
the same executable bodies; they must not rely on a second unchecked model.
Reviewed Java adapters and actual supplied-artifact checks provide separate
integration evidence. Existing bytecode results remain supplementary.

**Tech stack:** Dafny 4.9.1, bundled Z3, Java 21/25 and DafnyRuntime 4.9.1.

**Spec:** [Approved direction and acceptance criteria](2026-11-03-dafny-source-assurance.md).

## Constraints and review focus

- Preserve public APIs, accepted input domains, generated algorithm behavior,
  browser fingerprints and unrelated work. Separate ghost-only changes from
  changes to executable code and measure the latter before adoption.
- Preserve all existing functional postconditions and the original residual
  inventories until corresponding source-connected obligations are discharged.
- Use the fixed proof policy and genuine semantic negative controls. No new
  opaque owned algorithms, new axioms or successful claims from resource errors.
- Explicitly test external input/output aliasing, public/private buffer
  separation, observer omissions, changed secret conditions/indices and stale
  generated/delivered source identities.
- Keep compilation/primitive contracts, Java adapter review, cryptographic
  hardness, physical timing and external review distinct.

## Task 1: Actual Sponge ownership and frames

Files: actual `formal/crypto/NativeShake.dfy` as the verified dependency, new
`formal/source/ShakeOwnership.dfy`, source-assurance replay/control files.

- [x] Derive a ghost factory footprint and constructor freshness guarantees
  from existing contracts without narrowing the `Valid()` domain.
- [x] Prove identity, disjointness and frames by calling the actual constructor,
  `Update`, `Read`, `Destroy` and `Xof` over arbitrary permitted inputs.
- [x] Reject incorrect alias/freshness claims with genuine proof controls.
- [x] Verify all included source bodies and harness, confirm executable source
  and generated Java remain unchanged, and independently review before integration.

The direct harness proves the stronger footprint using the existing `Valid()`
table equations: their index-1 entries are distinct. No production contract
change is needed. The complete local replay has 1,552 verified checks, 20 new
harness checks, zero audit findings and three genuine assertion controls.
Independent review accepted the scoped theorem and found an audit-coverage gap.
The replay now audits every included source, rejects an injected included-body
axiom, enforces the reviewed complete-graph count and freezes its tool module.

## Task 2: Same-body source observation and paired execution

Files: actual target `.dfy` bodies; a new `formal/source/` component for the
observer, replay, controls and documentation. The component's design experiment
must settle its concrete instrumentation interface before production changes.

- [ ] Execute a source-level proof for a real native crypto operation and a
  secret-dependent branch/index negative, with an explicit coverage argument.
- [ ] Check ghost erasure, omission detection and method/callee coverage. Record
  any remaining instrumentation checker as trusted rather than formally proved.
- [ ] Extend the same mechanism through SHAKE/Keccak, polynomial/NTT, ML-KEM,
  HKDF and retained adapters/comparison paths. Preserve actual heap/call effects.
- [ ] Prove paired observations over the complete stated public/secret domains,
  including permitted output declassifications and invalid-input behavior.

The HKDF component now implements this same-body route for its four methods:
248 body checks, 259 included paired/domain checks, actual event-helper contracts,
reviewed coverage/order checks and Java erasure checks. The coverage adapter remains
trusted C#. This scoped delivery leaves the native SHAKE/Keccak/NTT/KEM and
Java-adapter/comparison composition items above open.

## Task 3: Actual published artifact validation

Files: existing supplied-artifact validator and new scoped release receipt.

- [x] Download the actual v0.7.0 library and bundle; verify published asset
  digests and record the exact release commit.
- [x] Run the existing identity and loaded-origin checks against a canonical
  stage built from those exact sources on JDK 21/25. Investigate differences;
  never renew a digest simply to accept changed classes.
- [x] Record this invocation's artifact scope without enabling a static claim
  about arbitrary future releases or whole-bundle dependency correctness.

The [published-artifact record](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/releases/v0.7.0)
binds the exact library/bundle digests. Fresh stage verification totals 8,905
checks across 18 roots. Identity checks cover 468 library, 84 crypto and 37
runtime classes; each JDK passes nine handshake and nine nonce cases. Reuse of
the exact-matched native control/JDK receipt is disclosed separately from the
fresh proof/generation/artifact work.

## Task 4: Evidence, review and delivery

Files: assurance documentation, obligation inventory/gates, CI and issue #117.

- [ ] Add reproducible proof/generation commands and mandatory inventories;
  reject altered inputs, omitted observations and mislabeled negative outcomes.
- [ ] Reconcile the source-first route with existing evidence and the issue
  checklist, keeping incomplete coverage visible.
- [ ] Run required proof, artifact, documentation and regression checks; obtain
  independent development review; commit and push coherent changes.
- [ ] Merge only an eligible exact head after its required checks pass. Keep
  external expert review and deferred physical timing open.
