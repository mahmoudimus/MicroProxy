# SHAKE and ML-KEM functional verification and production delivery

> **For agentic workers:** Use `superpowers:subagent-driven-development` for
> independent polynomial/codec tasks and `superpowers:executing-plans` for the
> coordinator's SHAKE/composition/integration work. Continue across context limits;
> the active goal is not complete after one component or one successful test run.

**Goal:** Close owned SHAKE128/256 sponge/API and ML-KEM-768 functional composition
obligations with Dafny proofs and generated Java, then integrate production after
compatibility and performance gates. Commit and push reviewed increments to
`diff/dafny-shake-mlkem`. JVM timing stays explicitly open.

**Architecture:** Extend the already verified Keccak/field foundations using new
sibling modules in `formal/crypto/`, preserving existing replay inventories until
deliberate integration. Mathematical reference equations, executable contracts,+general-domain harnesses and semantic mutants are distinct evidence. Compile exact
verified sources to Java; use reviewed compiler/runtime and provider boundaries,
never infer universal Java behavior from differential tests alone.

**Tech stack:** Pinned Dafny 4.9.1/Z3 4.12.1, generated Java, JDK21/25, Python replay
gates, JUnit/independent FIPS vectors and benchmarks.
**Spec:** FIPS202 SHAKE128/256 and Keccak-f[1600]; FIPS203 ML-KEM-768 algorithms and
equations, including malformed-input behavior and implicit rejection. Existing
package-private `Shake`/`MlKem768` and hybrid TLS interfaces define compatibility.

## Authorization and design

The user explicitly requested the full functional proof goal and selected
production integration after compatibility/performance checks, allowing a Dafny
runtime dependency if required. Existing work through f888472 is already committed,
pushed and all PR122 checks are green. No merge or release is requested.

Selected approach: implement/prove in Dafny and generate the delivered Java.
An isolated model plus finite production comparisons cannot close this goal.
Direct SAW refinement remains available for small retained Java bridges; its
unsupported array operations are not silently replaced by copied code proofs.
Compiler/runtime/provider correctness and cryptographic assumptions remain listed
trust assumptions, distinct from unfinished owned algorithm proofs.

Full KEM functional conformance does not mean every honestly generated ciphertext
decrypts correctly for every random tape: FIPS203 includes a nonzero decapsulation
failure probability. Prove its exact reencryption/fallback equations, and label
any probabilistic correctness/security statement separately. Likewise, rejection
sampling needs an explicit success/failure/termination contract; never assume an
adversarial byte stream eventually contains acceptable coefficients. Any bounded
sampler must follow FIPS203 AppendixB and document its uniform failure behavior.

## Global constraints

- Preserve public/package interfaces, wire bytes, hybrid key layout and fingerprint
  fixtures. Preserve unrelated edits and keep the existing PR stack intact.
- SHAKE must cover arbitrary finite input/output lengths and arbitrary partitions,
  both rates136/168, the shared padding octet at rate-1, zero-length reads initiating
  squeezing, rejection of input after output and correct buffer ownership/bounds.
- ML-KEM covers q3329, n256, k3, eta2, du10 and dv4; all scalar preconditions must
  be discharged at polynomial/caller boundaries, not assumed by a whole-KEM theorem.
- No custom axioms/assumes/skipped proof for owned algorithms. A JDK SHA3 contract
  must be named and audited; entropy/hardness and compiler trust remain explicit.
- No vacuous false/narrowed domains, fixed-size message corpus masquerading as a
  universal theorem, arbitrary rejection cap or resource failure accepted as proof.
- New runtime allocations, footprint and throughput must be measured before the
  production switch. Correctness and fingerprint gates cannot be weakened to fit.
- JVM/JIT/CPU/provider timing is deferred; no new constant-time claim follows from
  functional verification. Do not mention another QUIC project's security status.

## Interfaces and ownership

All polynomial vectors are `seq<int>` with length256 and coefficients0..3328.
Bytes are `seq<bv8>`, lanes `seq<bv64>`. Implementations return exact spec equations
and bounds/lengths. Provider functions and randomness tapes are explicit inputs.

| Owner | Files | Interfaces produced/consumed |
|---|---|---|
| Coordinator | `formal/crypto/SpongeSpec.dfy`, `Shake.dfy`, replay/Java adapters/docs/CI | General SHAKE state, Update/Read and composition; consumes existing VerifiedKeccak.Permute |
| Polynomial worker | `formal/crypto/Polynomial.dfy` and focused proof-test files only | PolySpec.Canonical, VerifiedPolynomial.Add/Sub/Ntt/InverseNtt/NttMul; consumes VerifiedField |
| Codec worker | `formal/crypto/Codec.dfy`, `Sampling.dfy` and focused proof-test files only | VerifiedCodec.Compress/Decompress/Encode/Decode, VerifiedSampling.Cbd2/Feed; consumes VerifiedField, finite byte input independent of SHAKE implementation |
| Coordinator after prerequisites | `formal/crypto/MlKem.dfy`, production bindings | KeyGen/Encaps/Decaps, input validation, implicit rejection and integration, consuming the verified component contracts |

Workers are not alone in the checkout. They must not revert others, modify shared
foundations/manifests/runners/production files or commit the coordinator's work.
Each produces proof logs, domain coverage and genuine negative controls for review.

## Review focus

1. Boundary/partition equivalence, zero-length phase transitions and suffix/last
   padding byte collisions: general lemmas plus runtime boundary/partition tests.
2. NTT axes, roots/tables, inverse scale and product representation: exact FIPS
   equations and algebraic inverse/product lemmas, not merely an NTT-copy model.
3. Compression half ties, invalid12-bit coefficients and every output buffer bound:
   universal equations, malformed-input controls and canonical Java comparisons.
4. Rejection/nontermination, byte-consumption ordering, coin/nonce domain separation,
   fallback keys and validation precedence: explicit result/state contracts.
5. Compiler/adapters/production delivery and performance: exact generated artifact,
   reviewed bridges, unchanged standards/fingerprints and measured adoption gates.

## Task 1: SHAKE sponge and segmented API

Create `SpongeSpec.dfy` and `Shake.dfy` with rate136/168 state, little-endian byte/lane
mapping, absorb/pad/squeeze equations and arbitrary-length recursion/loop invariants.
Prove Update concatenation and Read partition laws, preserving zero-read phase change.

- [x] Write wrong padding/rate/endian/phase bodies or mutants and observe real proof failures.
- [x] Verify byte/lane refinement, all owned loops, padding and arbitrary partitions.
- [x] Generate Java; test exact artifact against hashlib/FIPS/canonical vectors and
  segmented cases; review all input/buffer ownership and error-domain contracts.
- [x] Review, commit and push the completed SHAKE stage without closing the whole goal.

## Task 2: Polynomial/NTT composition (parallel with Task1)

- [x] Prove canonical poly Add/Sub and every scalar caller range.
- [x] Verify forward/inverse butterflies over complete inputs, exact table/root
  relations, stage/index invariants and the mathematical FIPS NTT representation.
- [x] Prove inverse and multiplication relationships with the negacyclic ring;
  verify NttMul/scale and all general caller preconditions.
- [x] Add root/sign/index/scale mutants, general-domain harnesses and generated-Java
  differential checks; review and commit only genuinely discharged obligations.

## Task 3: Codecs/compression/sampling (parallel with Task1/2)

- [x] Prove Compress/Decompress rounding equations and all relevant widths.
- [x] Prove ByteEncode/Decode for d1/4/10/12, lengths, ownership and modulus rejection;
  prove lossless12-bit round trips and stated lossy compression properties.
- [x] Prove CBD2 and finite-prefix rejection Feed, including exact byte consumption,
  truncation at256, canonical output and rejection/NeedMore results.
- [x] Add meaningful bit/order/tie/rejection mutants and runtime boundary tests;
  review and commit the completed stage.

## Task 4: Complete ML-KEM-768 equations

- [x] Connect expanded matrix/PRF/CBD and hash/coin/nonce contracts with no assumed
  owned helper results. Settle sampling liveness/failure against FIPS AppendixB.
- [x] Verify K-PKE KeyGen/Encrypt/Decrypt and key/ciphertext serialization/validation.
- [x] Verify KEM KeyGen/Encaps/Decaps, exact hash/XOF input composition, retained seed,
  checked key encodings, malformed lengths and reencryption/fallback key selection.
- [x] Demonstrate honest and malformed/implicit-rejection fixtures plus universal
  result contracts; list remaining cryptographic/probabilistic assumptions precisely.
- [x] Reject coin reuse/transposition/fallback/validation mutants; review/commit/push.

## Task 5: Production adoption and completion audit

- [x] Generate reproducible Java for the final verified graph and close owned Java
  bridge obligations with checked semantics, not tests relabeled as refinement.
- [x] Measure footprint, allocation and representative SHAKE/KEM/hybrid TLS throughput
  against f888472; optimize only through reviewed proof-preserving transformations.
- [ ] Integrate after compatibility/performance review; verify FIPS/Go/hashlib values,
  all existing crypto/handshake/fingerprint fixtures and full Maven21/25 matrices.
- [ ] Fresh adversarial proof/source review and fix all material findings with
  regressions; pin/replay complete inputs, audit assumptions and archive evidence.
- [ ] Update claims/issue117 and docs; commit/push coherent stages. Mark the goal
  complete only when all required owned functional/integration obligations are closed.

References: [FIPS202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
[FIPS203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf),
[foundation evidence](https://github.com/mahmoudimus/MicroProxy/blob/f888472585a2dcbe2304db2713116d3ac90db99a/formal/primitives/EVIDENCE.md).
