# Java Crypto Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Use Dafny to establish checked functional and secret-trace properties across our cryptographic code, starting with HKDF and its pinned AWS reference.

**Architecture:** Use Dafny as the primary implementation/specification/proof language. The selected HKDF route compiles the verified kernel to Java, with Dafny compiler/runtime and Java/JCE adapters explicitly trusted. Start with an isolated replay component before production packaging/performance review. For existing handwritten methods, SAW remains an implementation bridge; Lean/TLC evidence stays separate. Tool gaps remain visible blockers.

**First implementation:** [Generated HKDF component](https://github.com/mahmoudimus/MicroProxy/blob/73c12c57baa765caeea78971ae8c3a7bc4f17f1d/formal/dafny/README.md).
It proves the complete local Extract/Expand/TLS-label kernel, generates Java and
tests its real JCE boundary. This does not close every V0-V8 obligation below.
The full upstream MPL replay remains unperformed; our standalone kernel has no
upstream includes and is independently verified. Production adoption remains open.

**Tech Stack:** Dafny (4.9.1 for initial AWS-reference replay; reviewed upgrades after replay), SAW 1.6/Crucible and Cryptol for the Java bridge, JDK 21+, Python runners and JUnit vectors. Retain pinned Lean 4.35.0/TLC 1.7.4 evidence; additional Lean proofs are optional.

**Spec:** [QUIC completion and Java cryptography assurance](2026-10-28-quic-crypto-assurance-design.md).

## Global Constraints

- Preserve existing public APIs, outputs, labels and captured fingerprints. A production rewrite is a separate reviewed design.
- Prove our glue and handwritten primitives relative to explicit JDK/randomness assumptions; no runtime provider dependency is added by default.
- Pin exact source/class/tool/spec inputs. A blocked/finite/model-only result cannot be promoted to a full implementation proof.
- Every proof has satisfiable preconditions, independent specifications and meaningful weakened/mutated controls. Audit all assumptions and overrides.
- Normal vectors and independent comparisons remain required alongside proofs.
- AWS attribution describes reused HKDF material only. Other cryptographic models are our standards-based Dafny work; do not invent AWS provenance for them.

## Review Focus

1. AWS's narrower PRK/domain or weak top-level contracts could leave Java inputs uncovered: V1/V2.
2. Mutable-array copies, aliasing and provider reset semantics can break a correct sequence model: V2/V3.
3. Padding/rate transitions and repeated read/update calls can escape a one-shot SHAKE proof: V4.
4. Arithmetic helper preconditions may not hold at every ML-KEM caller: V5/V6.
5. Implicit-rejection equality or exception paths may reveal secrets despite correct returned bytes: V7/V8.

## V0: Obligation ledger and tool trust gates

**Files:** Create `formal/crypto-obligations.json`, `formal/README.md` updates, `scripts/security/check_crypto_obligations.py` and gate tests; extend `docs/formal-security.md` and `.github/workflows/formal-security.yml`.

**Interfaces:** Each obligation lists target/source/class/spec hashes, theorem/domain, dependencies, status, replay, controls and evidence. Status values distinguish model proof, implementation proof, assumption, tested, blocked and proposed.

- [ ] Add negative fixtures for vacuous preconditions, dropped obligations, unexpected assumptions, stale successful evidence, unsupported operations, timeouts and changed production classes.
- [ ] Implement validation that fails closed and cannot close an implementation obligation with a finite example list.
- [ ] Replay the current one-method SAW proof and existing Lean/TLC evidence, recording their actual domains unchanged.
- [ ] Run gate tests and reviewed CI installation with checksum-pinned tools. Keep this ledger as the dependency boundary for all subsequent tasks; commit after review.

## V1: Dafny HKDF functional specification (first crypto deliverable)

**Files:** Create `formal/dafny/HmacModel.dfy`, `Hkdf.dfy`, `HkdfProofs.dfy`, `tools.json`, `sources.json`, `NOTICE`, `run.py`, `test_run.py` and negative controls under `formal/dafny/`; reuse `quic/src/test/java/io/github/mahmoudimus/quic/HkdfTest.java`.

**Interfaces:** Define a total, deterministic abstract HMAC over byte sequences with fixed hash output length, plus explicit stateful Java-provider contracts for initialization, update and finalization. Model `Extract`, `Expand` and TLS label encoding as named functions/methods with full output equations and domain constraints, not merely output length.

- [ ] Pin the AWS commit from the design, verifier 4.9.1, dependency/submodule hashes and licenses. Reproduce its verification in an isolated tool cache before adaptation; record any mismatch rather than silently repinning.
- [ ] Adapt recurrence/invariant structure and strengthen our composition contracts. Specify empty-salt normalization, empty inputs, zero/maximum output, partial final blocks, counter width, supported hash algorithms, and Java's documented longer-PRK domain. Classify invalid inputs explicitly.
- [ ] Add controls with altered feedback, counter, truncation and label prefix; each must fail a named obligation. Check a satisfiable normal instance so reject-all is not a proof.
- [ ] Create `python3 formal/dafny/run.py` to verify contracts and controls with an atomic status report and assumption audit. Test its failure paths, then add it to opt-in formal CI. Commit after review.

## V2: Connect HKDF contracts to actual Java

**Selected route for HKDF:** implement in Dafny and generate Java. The initial
component lives in `formal/dafny/hkdf`, with handwritten tested adapters under
`formal/dafny/java`. Its replay pins the compiler distribution/runtime and inputs,
audits the external HMAC assumption, verifies the full algorithm and unrestricted
public domain, runs negative controls, generates Java, compiles it and tests JCE.
Production replacement requires packaging/runtime/performance and key-schedule
integration review. The SAW refinement steps below remain the alternative for
retaining handwritten HKDF; they are not prerequisites for this selected route.

**Files:** `formal/saw/hkdf.saw`, `formal/saw/Hkdf.cry`, reviewed provider contract scripts, `formal/crypto-obligations.json`; production target `quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java`.

**Interfaces:** Target the actual `extract(byte[],byte[])`, `expand(byte[],byte[],int)`, `expandLabel(byte[],String,byte[],int)` and `labelInfo(String,byte[],int)` methods. Provider contracts model the same abstract HMAC as V1 and `Mac.doFinal` reset behavior. No override may assume the result of our HKDF method.

- [ ] Start with a feasibility obligation for array copying, stateful `Mac` contracts, loop cutpoints and variable lengths on class-file version 65. Record precisely whether the backend can express the general domain.
- [ ] Prove agreement of Dafny and Cryptol mathematical specifications, or use a single checked specification translation. Differential vectors alone do not establish that relation.
- [ ] Discharge loop, integer-bound, caller-array preservation, fresh-output and label-serialization obligations for the documented domain. Each finite-length restriction stays visible until generalized.
- [ ] Replay RFC 5869/9001 vectors and negative controls against production classes. A generic bridge is done only when every claimed domain is covered.
- [ ] If the backend cannot express the proof, leave this task blocked and open the concrete translator/loop-support work. A generated-Java kernel is a possible separately approved alternative with Dafny compiler/runtime trust stated; copying the model into handwritten Java does not carry the proof. Review and commit verified artifacts only.

## V3: Portable SAW and mutable-array bridge

**Files:** `formal/saw/run.py`, `inputs.json`, `tools.json` (new), runner tests and blocked nonce experiment; a separately reviewed patch in the pinned Crucible JVM translator if required.

**Interfaces:** Add checksum-pinned Linux x86-64 and macOS arm64 tool installations. Model primitive array `clone` with equal elements, preserved source and fresh identity; handle actual Java bytecode without lowering class version.

- [ ] Add backend tests that catch aliased return values, changed source data, wrong length and unsupported receiver types. Existing nonce proof must first reproduce the documented translation blocker.
- [ ] Implement and review the smallest translator change, or adopt a pinned upstream fix after independently replaying those tests. No broad assumed `Object.clone` contract substitutes for missing translation.
- [ ] Replay actual `PacketKey.nonce` with all IV/packet-number bits symbolic, an endian mutation, alias mutation and satisfiable preconditions. Preserve the old blocked classification until this succeeds.
- [ ] Run portable CI and interruption/stale-report tests, recording tool revision and dependencies. Commit after review.

## V4: SHAKE/FIPS 202 refinement

**Files:** Create `formal/dafny/Keccak.dfy`, `formal/dafny/Shake.dfy`, `formal/dafny/ShakeProofs.dfy`, `formal/saw/shake.saw`, corresponding Java-bridge specs and controls; target `tls/Shake.java` and `tls/ShakeTest.java`.

**Interfaces:** Specify `keccak(long[25])`, SHAKE128/SHAKE256 absorbing state, domain separation, padding and arbitrarily partitioned squeeze/update calls. State precisely which call orders the Java API permits.

- [ ] Pin FIPS 202 and its published errata; write independent round/lane and sponge specifications.
- [ ] Prove all round operations and sponge composition in Dafny with explicit `bv64` lane semantics, then bridge to the actual Java methods including mutation and buffer bounds. Follow V2's checked-specification requirement and use V3 if backend copies require it.
- [ ] Add controls for rotation, lane/endian order and domain separation. Exercise lengths around both rates, segmented I/O, zero-length calls and invalid call order in Java.
- [ ] Run Dafny and bytecode proof replays, Python/OpenSSL independent values and Java vectors. No arbitrary fixed number of squeeze blocks may be called full SHAKE correctness. Review and commit.

## V5: ML-KEM arithmetic, NTT, codecs and sampling

**Files:** Extend `formal/saw/Field.cry`, reduction experiments and controls; create `formal/dafny/MlKemArithmetic.dfy`, `formal/dafny/MlKemNtt.dfy`, `formal/dafny/MlKemEncoding.dfy`, `formal/dafny/MlKemSampling.dfy` and corresponding bytecode obligations; target helpers in `tls/MlKem768.java` and its tests.

**Interfaces:** Derive contracts from every real caller, with Java signed-width semantics. Prove `reduceOnce`, `reduce`, `add`, `sub`, `mul`, `mulSub`, `addMul`, compression, serialization, polynomial operations, NTT/inverse NTT and samplers in dependency order.

- [ ] Produce a caller/range ledger before extending proofs. In particular, audit `addMul` and `mulSub` inputs against the existing reduction comment's `2^24` limit; a narrower helper theorem cannot discharge wider callers.
- [ ] Resolve reduction solver timeouts with reviewed decomposition/lemmas and explicit bounds, never a silent restricted input claim.
- [ ] Prove helper postconditions, range preservation and all call-site preconditions in Dafny. Specify signed Java operations explicitly alongside unsigned bitvectors. Link Dafny NTT/codec statements to actual bytecode and record randomness/public-seed assumptions for sampling.
- [ ] Run independent deterministic Go comparison vectors, malformed encodings and mutated arithmetic/codec controls. Any real counterexample becomes a focused code fix with renewed reviewed proof pins. Commit by independently reviewable helper families.

## V6: Full ML-KEM-768 functional composition

**Files:** Create `formal/dafny/MlKem768Spec.dfy`, `formal/dafny/MlKem768Proofs.dfy` and corresponding Java-bridge obligations under `formal/saw/`; target `MlKem768.generate`, encapsulation, encryption/decryption helpers and `DecapsulationKey.decapsulate`; extend malformed-input tests.

**Interfaces:** Define complete deterministic functions of supplied coins/inputs and provider hashes. Enumerate all private/public key encodings and API validation results. V4 and V5 discharge owned SHAKE/helper dependencies; JDK SHA3 and randomness retain listed contracts.

- [ ] Pin FIPS 203, review its published errata, and map every algorithm step to an implementation obligation.
- [ ] Prove key generation, encapsulation and valid/invalid-ciphertext decapsulation in Dafny, including fallback key selection and malformed-key handling, then discharge their Java refinement obligations. The existing one-method proof is a dependency, not the whole result.
- [ ] Add controls for fallback selection, ciphertext comparison coverage, wrong hash/context and a missing input validation. Separate mathematical functional equivalence from cryptographic hardness/security reductions.
- [ ] Require no open owned-algorithm obligations in the declared ML-KEM-768 domain, plus independent vectors and expert review before using a full functional-correctness claim. Commit reviewed stages; leave composition open while any required bridge is blocked.

## V7: Secret-trace proof for our code

**Files:** Create `formal/timing/threat-model.md`, `formal/dafny/SecretTrace.dfy`, `formal/dafny/SecretTraceProofs.dfy`, target-specific Java trace obligations and negative controls; update the crypto ledger and `docs/security-timing-audit.md`.

**Interfaces:** Declare public fields per operation (algorithm, lengths, public keys/ciphertexts, allowed declassification) and secret values (private keys, key material, unrevealed intermediate values). For paired executions with equal public inputs, compare branches, memory indices, dispatch and observable errors; fresh allocations use an explicit heap-renaming relation. Outputs may differ as the cryptographic interface permits.

- [ ] Define the observer and exceptional/provider behavior before any constant-time theorem. Classify public-seed rejection sampling separately from secret-dependent work.
- [ ] Add secret-branch, secret-index, early-comparison and exception-oracle mutations; each must break the corresponding trace property.
- [ ] Use explicit paired-execution/self-composition proofs in Dafny for HKDF orchestration, SHAKE, ML-KEM implicit rejection and secret-comparison call paths. Ordinary method contracts or old/new-heap lemmas alone are not a two-execution trace proof. Model JDK/provider calls as explicit trusted contracts; do not infer their execution trace from the Java caller proof.
- [ ] Connect the trace semantics to implementation control/data flow with a checked mechanism. Until that connection exists, label results model-only. Replay with the final V2/V4/V6 implementations and review the complete declassification list.

## V8: Runtime evidence and assurance release gate

**Files:** Extend `scripts/security/assess-local-timing.sh`, add repeatable provider/runtime manifests and `scripts/security/check_crypto_release.py`; update `docs/formal-security.md` and CI evidence artifacts.

**Interfaces:** Every runtime record pins JDK build, provider/algorithm, JVM flags, architecture/CPU, binary hashes, cohort definitions, sample counts and controls. The release checker consumes the V0 ledger and rejects missing claims, stale inputs or unlisted assumptions.

- [ ] Test the release gate against a model-only Java claim, incomplete proof, altered source/class hash, absent mutation failure and unpinned timing result.
- [ ] Measure multiple mismatch positions/equal-size cohorts, invalid ciphertext classes and a deliberately variable-time control; report inconclusive/noisy results honestly. Document that public input length may affect work.
- [ ] Inspect emitted code/intrinsics on pinned x86-64 and arm64 deployments where tooling permits. If a proof of those machine-code paths is feasible, track it as a separately scoped backend/CPU obligation; general HotSpot/GC/speculation behavior remains outside V7.
- [ ] Obtain independent cryptographic/proof review. Publish separate functional, trace and empirical claims with assumptions and residual gaps. Close only the properties actually achieved; no generic "proved secure" label follows from this plan.
