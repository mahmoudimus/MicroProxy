# QUIC completion and Java cryptography assurance

This roadmap completes a named QUIC feature baseline and builds implementation proofs for our Java cryptography, starting with HKDF. It is a proposal for implementation; creating this document does not complete any new protocol feature or cryptographic proof.

Tracking: [epic #115](https://github.com/mahmoudimus/MicroProxy/issues/115), [QUIC track #116](https://github.com/mahmoudimus/MicroProxy/issues/116), [crypto track #117](https://github.com/mahmoudimus/MicroProxy/issues/117).

## Decisions and scope

Use two coordinated tracks, each with independently reviewable milestones:

1. [QUIC feature completion](2026-10-28-quic-feature-completion.md).
2. [Java crypto verification](2026-10-28-java-crypto-verification.md).

The chosen direction is incremental, Dafny-first verification of the existing implementation. Use Dafny for the primary functional specifications and proofs across HKDF, Keccak/SHAKE, ML-KEM arithmetic/NTT/codecs/composition, and explicit secret-trace models. SAW supplies actual Java bytecode obligations where supported. Existing Lean proofs remain valid; new Lean obligations are optional when a concrete need justifies them. TLA+/TLC remains useful for protocol/resource transitions. A theorem about a model and a theorem about production bytecode are different ledger entries.

The alternatives considered were replacing primitives with generated verified Java, or using a verified native library. Those may become useful if a bridge proves infeasible, but each changes dependencies, runtime behavior and trust boundaries. Neither is the default implementation decision. A production replacement requires its own reviewed design and fingerprint/API compatibility evidence.

### Dafny scope and Java delivery

The program is **Dafny-based verification of our cryptography**. AWS is the pinned HKDF reference and a provenance source for material actually adapted; it does not define which algorithms Dafny can verify. SHAKE and ML-KEM specifications come from their standards and our implementation, with their own attribution records.

Dafny supports contracts, loop invariants, arrays and fixed-width bitvectors for these algorithms. The models must explicitly match Java's signed integers, overflow, shifts and mutable heaps. A self-composed pair of modeled executions can establish a chosen secret-trace property; functional correctness alone does not establish that property.

There are two Java delivery paths: retain our handwritten Java and prove a checked refinement, or implement a verified Dafny kernel and compile it to Java. The latter trusts the Dafny compiler/runtime and Java compilation and requires a separately reviewed runtime-dependency decision. Neither path automatically proves HotSpot's generated machine code constant time. See the [Dafny reference and Java backend](https://dafny.org/latest/DafnyRef/DafnyRef).

### Named protocol baseline

The scope is RFC 9000/9001/9002, QUIC v2 (RFC 9369), compatible version negotiation (RFC 9368), DATAGRAM (RFC 9221), the partial-delivery reset extension pinned below, and application APIs for stream priority and preferred-address migration. HTTP/3 remains a separately layered application with integration tests. New extensions need an explicit addition to this baseline; the phrase "all QUIC features" is not an acceptance criterion.

## Verified starting point

Snapshot: `67777e80e7b0507661f404bc45cdde4445e27280`, based on current-main merge `05fb6f8`. The implementation work is in [PR #114](https://github.com/mahmoudimus/MicroProxy/pull/114); [runner registration #523](https://github.com/quic-interop/quic-interop-runner/pull/523) is open. The [result manifest](https://github.com/mahmoudimus/MicroProxy/blob/67777e80e7b0507661f404bc45cdde4445e27280/quic-interop/results/2026-10-28.json) records a local 22-case/role subset, not a full public matrix.

| Area | Observed implementation | Remaining deliverable |
|---|---|---|
| QUIC v1/v2, TLS 1.3, streams, Retry, three cipher suites, updates, resumption/0-RTT, DATAGRAM | Existing code, vectors, and differing levels of integration coverage | Normative requirement ledger and complete selected runner matrix |
| Compatible version negotiation | `Connection.followVersion` follows an offered v1/v2 switch; `handlePeerParams` checks the server's chosen version; ordinary VN still terminates on mismatch | Complete client/server role coverage, policy, downgrade checks and runner exposure |
| Migration | Client/server machinery, preferred-address socket binding and policy already exist | Expose and verify the adapter's `connectionmigration` server case |
| Priorities | `Connection.setPriority(StreamId,int)` and scheduling tests exist | Thread-safe blocking `QuicStream` API and observable scheduling test |
| Partial-delivery resets | Ordinary RESET_STREAM only | Negotiation, frame, retained-data state, application API and loss tests |
| ECN | ACK counters and recovery hooks exist; constructor explicitly disables sending ECN because the socket layer cannot mark it | Record the driver/platform capability gap; decide optional transport adapter separately |
| Formal evidence | 34 Lean model theorems; 583 finite Java observations; bounded TLC cases; one SAW `reduceOnce` proof | HKDF composition, SHAKE, complete ML-KEM functional proofs, and defined secret-trace properties |

The earlier "codec only" inventory predates the merged client version-switch path. Treat RFC 9368 as partial support requiring completion and evidence, not an empty implementation.

## HKDF foundation: pinned AWS Dafny reference

Use [AWS HKDF.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/c787ad12612ac0f35975afe9209e5dbe6b546654/AwsCryptographyPrimitives/src/HKDF/HKDF.dfy) at exactly `c787ad12612ac0f35975afe9209e5dbe6b546654` for recurrence/invariant design. Its [HMAC contract](https://github.com/aws/aws-cryptographic-material-providers-library/blob/c787ad12612ac0f35975afe9209e5dbe6b546654/AwsCryptographyPrimitives/src/HKDF/HMAC.dfy) declares external assumptions; the [Java adapter](https://github.com/aws/aws-cryptographic-material-providers-library/blob/c787ad12612ac0f35975afe9209e5dbe6b546654/AwsCryptographyPrimitives/runtimes/java/src/main/java/HMAC/HMac.java) calls JCE. Expand has a recurrence/truncation contract, while Extract and the top-level entry expose weaker postconditions. Our model must explicitly establish full functional composition relative to HMAC.

Start reproduction with the reference's pinned verification version, Dafny 4.9.1, and record its submodule commits and solver dependencies. Tool upgrades require a replay. Preserve Apache-2.0 attribution and applicable notices for any adapted material; do not silently import the AWS internal runtime into the default reactor.

## Assurance contracts

| Property | Completion evidence | Explicit assumptions/exclusions |
|---|---|---|
| HKDF functional correctness | Mathematical Extract/Expand/label contracts plus checked production-method refinement | JDK HMAC contract, including keyed reset; no entropy/PRF security reduction inferred |
| SHAKE functional correctness | Keccak-f, padding, absorb/squeeze composition, and Java implementation bridge against FIPS 202 | No collision/preimage or universal JVM timing theorem |
| ML-KEM-768 functional correctness | FIPS 203 keygen/encapsulation/decapsulation composition; helper ranges, codecs, NTT and implicit rejection discharged | SHA3/SHAKE contracts, randomness, hardness and compiler/runtime trust individually named |
| Own-code secret independence | Two-run branch/address/exception trace equality for the declared public-input class | Provider calls have declared contracts; allocations compared modulo fresh-address renaming; public lengths are allowed to affect work |
| Deployment timing evidence | Pinned JDK/provider/CPU/flags, provider identity, recorded timing controls and compiled-code inspection where justified | Empirical evidence remains separate from the trace proof and does not verify all HotSpot versions |
| Protocol safety | Invariant proofs/models plus actual malformed-input and independent-peer checks | Finite TLC exploration stays labeled bounded; liveness requires explicit delivery/scheduling fairness |

AES-GCM, ChaCha20-Poly1305, HMAC and JDK SHA3 remain provider responsibilities. Proving our orchestration is the first target. A full AES security proof or a universal HotSpot constant-time guarantee is outside this program's claim.

## Compatibility and release rules

- JDK 21 remains the floor. Exercise JDK 21 and exact current JDK 25 in compatibility CI.
- Preserve captured browser profiles and fixtures. Newly implemented extensions are opt-in until full behavior exists; publishing capability is a reviewed choice per profile.
- Keep the default library reactor free of new runtime dependencies. Dafny/SAW/Lean/TLC are development tools.
- Preserve the `Hkdf` public API and its documented valid domains, including PRKs longer than HashLen. AWS's exact-HashLen precondition must not silently narrow ours.
- Keep the interop adapter optional. A case becomes supported only when it exercises the actual feature and packet/file checks pass. Unknown cases keep exit 127.
- Every proof names source/class hashes, theorem domain, dependency assumptions, negative controls and replay command. Never close a Java proof task with only a model or a finite test corpus.
- Keep evidence statuses distinct: proposed, model-proved, implementation-proved, assumed, tested, or blocked. A blocked Java bridge keeps its completion task open.
- Add no comparison to another implementation's security status to our assurance documents.

## Sequence and dependencies

Both tracks start after the baseline/release audit. The first substantive crypto task is the Dafny HKDF contract using the pinned AWS reference (V1), followed by the actual-Java bridge (V2). Portable SAW/array-clone work (V3) enables broader mutable-array targets. Dafny SHAKE proofs (V4) precede final Dafny ML-KEM composition (V6); Dafny arithmetic/NTT/codecs (V5) can proceed independently of V4. The Dafny secret-trace model (V7) starts early but is discharged only against the final proven implementation.

QUIC client validation (F1) precedes full server negotiation and adapter `v2` (F2). Preferred-address adapter wiring (F3) and blocking priorities (F4) are independent. Reset wire/negotiation (F5) precedes retained-prefix behavior/API (F6). Full matrix/release evidence (F7) follows those features and every mandatory gap discovered in F0.

The upstream work item belongs in `mahmoudimus/MicroProxy`. The interop runner repository owns registration and harness changes; it is not the tracker for our protocol implementation.

## Definition of done

Feature-track completion requires a fully accounted named baseline, supported-role packet evidence, preserved browser captures and resolved mandatory ledger gaps. Optional gaps stay visible and prevent broader claims. Proof-track completion requires discharged implementation obligations for the declared domains and an audited assumption list; a timeout, tool limitation or reduced-domain result is not completion of the full goal.

Independent review is required before release-level claims. The functional verification program should be scheduled by achieved obligations and feasibility gates; no fixed date for full ML-KEM or JVM timing is asserted here.

## Sources and version policy

- [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368.html), [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html), [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html).
- [Reliable stream reset draft -11](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-11), checked 2026-10-28; recheck publication status and assignments before implementation.
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html), [JDK 21 Mac contract](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Mac.html).
- [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final), [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), including their published planning notes/errata. Pin the exact normative revisions in proof manifests.
- [Current assurance claims](../formal-security.md). This roadmap changes no completed-proof count.
