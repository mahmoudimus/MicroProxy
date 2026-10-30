# Security assurance and formal verification

MicroProxy has a custom TLS/QUIC implementation. Its assurance includes development review,
published standards vectors, interoperability/rejection tests, exploratory timing observations,
and the scoped models below. No end-to-end security proof, independent expert cryptographic
audit, certification, or constant-time HotSpot guarantee is claimed. Agent reviews are
development reviews, not an external expert audit. A green test or updated dependency does not
establish absence of vulnerabilities.

Interoperability and security assurance are separate. Our primitive boundary includes
owned ML-KEM and SHAKE algorithms as well as the selected JDK primitives.

## How verification reaches executable code

We use several tools for different obligations. They do not collectively establish
that the whole proxy is secure: each result names its inputs, property, domain and
remaining assumptions.

| Tool | What we use it for | Connection to Java |
|---|---|---|
| TLA+ with TLC | Explore TLS key/sequence/closure transitions and check invariants within the configured finite state space | Model checking plus finite observations of production behavior; it does not generate our Java or prove unbounded refinement. |
| Lean 4 | Kernel-checked mathematical theorems about counters, nonce/label encodings and resource bounds | Universal model theorems plus separately identified finite Java observations; it does not generate the production implementation. |
| Dafny | Specify exact results, verify executable algorithms, and generate Java from the verified source | Production SHAKE/ML-KEM use native-array refinements and checked Java delivery. The packet kernel is integrated; HKDF remains isolated. Compiler/runtime, facades and any lowering are explicit trust boundaries. |
| SAW/Crucible | Prove a property of supported actual Java class-file methods | One bounded reduction method from the pre-adoption Java artifact; it does not prove the current generated backend. Unsupported operations and caller preconditions remain outside that experiment. |

For generated components the delivery sequence is:

1. Write a standards-based specification and an executable Dafny implementation
   with exact postconditions, input domains and loop invariants.
2. Verify the implementation and audit assumptions. Independent domain harnesses
   prevent narrowing a contract merely to make verification pass; deliberately
   broken implementations must fail actual proof obligations.
3. Generate Java from frozen verified source and record source, tool, generated
   source and class hashes. Full crypto delivery verifies every module first, then
   translates the same graph with `--no-verify` to preserve the separately checked
   solver policies. That flag does not replace the preceding proofs. Native crypto
   uses unmodified compiler output; the packet kernel's two bounded-shift lowerings
   remain separately documented compiler adaptations.
4. Test the generated artifact at its Java boundary using independent standards
   vectors, production comparisons, invalid inputs, ownership checks and applicable
   fingerprint fixtures. These tests cover integration; they do not prove the
   adapter or compiler correct.
5. Review packaging, runtime dependencies and performance before production
   adoption. Replay the proof and integration gates in CI when inputs change.

Functional correctness means the algorithm meets its stated equations. A separate
two-run trace proof can address modeled secret-dependent observations. Neither
proves cryptographic hardness, provider correctness or physical JVM/CPU timing.
Those distinctions also apply to the SHAKE/ML-KEM work. AWS attribution belongs
to the reused HKDF proof structure; our other Dafny models follow their respective
standards and have their own provenance.

The [verification artifact guide](https://github.com/mahmoudimus/MicroProxy/tree/diff/quic-packet-traces/formal)
contains replay commands. The component sections below state which claims have
actually been discharged and which implementation bridges remain trusted.

## Trusted primitives and our code

We assume the selected JDK/provider correctly implements AES-GCM, ChaCha20-Poly1305, HMAC,
SHA-1/2/3, classical key agreement and digital signatures. Suitable randomness and the usual
cryptographic hardness/pseudorandomness properties are assumptions, not proof conclusions.
Provider choice, runtime, native intrinsics, CPU and deployment configuration remain relevant.

| Component | Our responsibility | Evidence and remaining boundary |
|---|---|---|
| `TlsRecordLayer`, `crypto/PacketKey` | Key/IV/nonce construction, counters, AAD, buffers, errors and lifetime around JDK AEAD | Published record/packet vectors, rejection tests, counter/nonce model proofs. No full Java record refinement. |
| `Hkdf` | Extract/Expand feedback/counter/block copying and TLS labels around JDK HMAC | RFC 5869/9001 vectors, validation and label model checks. Full Expand-loop equivalence/HKDF security reduction is not proved here. |
| Generated Dafny HKDF component | Extract/Expand/TLS-label implementation compiled from verified Dafny | Full functional result equations relative to abstract HMAC, unrestricted input harness and negative controls; generated Java tested with real JCE. Isolated component, not the production `Hkdf` replacement. |
| `KeySchedule`, `Tls12Prf`, `Hpke`, `crypto/Keys` | Role/stage order, transcripts, labels, contexts and updates | TLS/HPKE/QUIC vectors and integration tests; no general protocol/key-schedule security proof. |
| `crypto/HeaderKey`, `packet/PacketNumber` | Mask/sample offsets, header bits, PN prefix/reconstruction | JDK AES/ChaCha plus packet vectors; generated scalar functional/trace proofs and fixed-address adapter checks below. No complete Java buffer/provider or whole-record timing refinement. |
| `KeyExchange`, `EcCurves`, `Signatures` | Encodings, hybrid order, public point/zero checks, signature contexts/parameters | JDK classical primitives plus vectors/interop/negative tests. Wire/policy glue remains ours. |
| `MlKem768` | Keygen, sampling, field arithmetic, NTT, codecs, compression and implicit rejection | Native Dafny refinement covers complete deterministic K-PKE/KEM, caller ranges, validation, key ownership, temporary cleanup on modeled returns and fallback selection. SHA3 is trusted through four declarations for two primitives. Production uses generated Java through reviewed facades and exact artifact delivery; JVM timing remains open. |
| `Shake` | Keccak-f and SHAKE absorb/pad/squeeze | Native Dafny permutation and byte-oriented sponge/API refinement covers both rates and arbitrary finite segmented I/O. Reviewed facade preconditions and hashlib vectors cover integration. Non-byte-aligned input is not an offered API; JVM timing and physical erasure remain unproved. |
| Tickets/tokens/reset tokens | Nonces, rotation, framing/AAD, lifetime/address/reuse policy and comparisons | JDK AEAD/HMAC/equality plus negative tests. Random nonce collision bounds and rotation/clock/concurrency proofs remain separate. |
| Authentication/resumption | Certificates, hostname, policy, signatures/Finished and cached evidence | Regression/interop/fail-closed tests. The traffic-key model does not verify all acceptance paths. |
| DNSSEC/X.509 construction | Wire/DER encodings, chain/denial acceptance, mappings, budgets/caches | JDK verification plus standards/synthetic tests and resource models. No complete DNSSEC/DER/certificate-policy proof. |

TLS exporter labels must be ASCII: non-ASCII strings previously underwent replacement encoding
and could alias distinct labels. The encoder now rejects them. Internal ASCII TLS/QUIC labels
retain their bytes. The label field's 16-bit output-length bound is separate from Expand's
tighter `255 * HashLen` bound. Distinct serialized inputs do not imply collision-free HKDF outputs.

## Lean theorem scope

`formal/lean/` imports the standard library and uses pinned Lean 4.35.0. The theorem list and
axiom audits are in `formal/assurance.json` and the runner report. Proof holes, custom axioms and
native-evaluation trust are rejected; standard logical axioms are explicitly allowed. See
[Lean's proof-validation reference](https://lean-lang.org/doc/reference/latest/ValidatingProofs/).

| Model | Universal mathematical result | Preconditions / exclusions |
|---|---|---|
| `RecordBounds.lean` | Arbitrary-length accepted allocations within one key epoch have unique sequences below the cap; exact capacity and exhaustion rejection | Nonnegative counters, valid initial bound; allocations include later crypto/I/O failure. No same-key reset. Actual key freshness and Java semantics are not inferred from epoch labels. |
| `CryptoEncoding.lean` nonce | Fixed 96-bit IV XOR zero-extended 64-bit sequence is injective | Fixed IV, distinct sequences. Does not prove AEAD security or that every caller allocates unique packet numbers. |
| `CryptoEncoding.lean` label | Legal encodings contain bytes, decode to all original fields, and distinguish input tuples | Length <65536, label <=249 bytes, context <=255 bytes, valid bytes. Java String-to-ASCII validation is a separate obligation. |
| `ResourceBounds.lean` budget | Accepted arbitrary-length nonnegative charges conserve allowance and never overspend; failure never adds credit | Nonnegative costs. Current Java callers charge positive constants or unsigned iteration counts; negative `int` inputs are outside this model. |
| `ResourceBounds.lean` cache | Purge never grows; insertion preserves capacity/unique keys and leaves future-dated entries | Initially bounded/unique state; newest-first representation; stable clock within one operation. No Java synchronization, wall-clock, allocation or real-time cleanup proof. |

Record completeness theorems establish that requests within capacity actually succeed, preventing
vacuous safety by rejecting everything. Another theorem shows why resetting the same actual key
to sequence zero would repeat an input.

## TLA+/TLC scope

`formal/tla/` models post-handshake TLS 1.3 allocation, final-old-key KeyUpdate records,
accepted/rejected key installation, directions, and closure/failure. Its `.cfg` files and runner
report state the finite caps/epoch/direction bounds, invariants and witness/negative cases.
TLC exhaustively explores those finite models: this is **bounded model checking**, not an
unbounded Java/TLS security proof. A fresh modeled epoch assumes fresh actual key material.
Generic crypto/I/O failure may consume a sequence without closing; key-policy rejection closes
the connection. The model preserves that distinction.

## Connection to the implementation

The formal runner invokes production classes through test fixtures, recording budget/cache
transitions, actual TLS guard behavior, TLS/QUIC nonces and HKDF-label bytes. Concrete Lean
propositions check these observations against model results with the kernel. Fixed clocks and
synthetic inputs make the checks reproducible; TLS integration tests cover surrounding updates.

These are finite implementation checks, **not** verified Java extraction, bytecode equivalence
or an unbounded refinement theorem. SHA256 source mapping detects drift and requires reviewed
renewal; matching hashes do not close that semantic gap. Deliberately weakened models must fail
proof obligations or the named TLC invariant, rather than merely failing to parse.

From the repository root, with JDK 21+, Maven, Python 3.11+ and zstd:

```bash
python3 -m unittest discover -s scripts/security -p 'test_formal_tools.py' -v
python3 scripts/security/install_formal_tools.py
python3 scripts/security/formal_check.py
```

Tools are cached outside the checkout; evidence is in `target/formal-security/`. CI repeats the
checks. Normal Maven/interop tests still run separately. Formal tools are development dependencies.

## Timing and stronger implementation proofs

### Direct Java bytecode proof

The opt-in [SAW experiment](https://github.com/mahmoudimus/MicroProxy/tree/diff/dafny-shake-mlkem/formal/saw) verifies the checksum-pinned Java 21
`MlKem768.reduceOnce(int)` class-file method from before Dafny adoption against mathematical remainder:
for every integer `0 <= a < 6658`, its result is `a mod 3329`. The proof has no
method overrides or admitted dependencies. It establishes one scalar method's
functional result under its precondition; it does not cover callers, other
ML-KEM operations or timing. It does not recompile a copied
method or substitute an older class-file version.

The runner pins the historical reference source and class hashes, snapshots existing classes,
and records SAW summaries. A wrong-modulus specification must produce a proof
counterexample, and a deliberately contradictory precondition must be detected
as vacuous. An actual `PacketKey.nonce(long)` proof attempt is recorded as blocked
by SAW's unsupported primitive-array `clone` translation, never as verified.
SAW/Crucible semantics and translation, Cryptol, the solver, selected JDK classes
and the Java build remain trusted. This experiment is separate from the Lean/TLC
CI job and currently requires the documented local tool setup.

### Verified Dafny implementation and Java generation

The [Dafny HKDF component](https://github.com/mahmoudimus/MicroProxy/blob/73c12c57baa765caeea78971ae8c3a7bc4f17f1d/formal/dafny/README.md) implements Extract, Expand,
TLS label serialization and their composition. All four methods return explicit
validation results and have full output equations, with no caller preconditions.
The kernel verifies 21 checks; a separate harness verifies that all methods remain
callable over their complete mathematical input domain. Mutated feedback, counter,
truncation and prefix, a narrowed domain, an extra axiom and skipped verification
must be rejected. The sole permitted Dafny assumption is deterministic abstract
HMAC with its fixed output-length contract.

The runner generates Java with verification enabled and compiles/tests that exact
output with the actual Java/JCE adapters. The small adapters, Dafny/Boogie/Z3,
Dafny's compiler/runtime, `javac`, JVM and provider remain trusted. Finite tests
check RFC 5869/9001 values, all three HMAC digests, high-bit octets, Unicode labels,
validation bounds, array ownership and concurrent calls. They do not prove the
adapter or compiler correct. Source/generated/class hashes identify the replay.

This component is outside the default Maven runtime. Production `Hkdf` is unchanged
and used as a test reference; its general refinement remains open. The API retains
existing compatibility extensions for short nonempty PRKs and empty label suffixes.
No cryptographic security reduction or JVM/provider timing guarantee is added.

### Reference implementations

Verified source that generates Java is another practical route.
[AWS's Dafny HKDF implementation](https://github.com/aws/aws-cryptographic-material-providers-library/blob/c787ad12612ac0f35975afe9209e5dbe6b546654/AwsCryptographyPrimitives/src/HKDF/HKDF.dfy)
specifies the Expand recurrence and truncation relative to an external HMAC
contract. Its Extract and top-level HKDF postconditions are weaker. Java generation,
the JCE HMAC implementation and runtime remain trust boundaries; these contracts
do not establish constant-time JIT execution. The primitives package also warns
against standalone consumption. This is evidence that verified Java generation
is feasible, not an adopted replacement for our code.

The reviewed external candidates did not supply a ready verified Java backend.
Porting a verified native implementation would require a checked link before its
proof could apply to Java. Our generated SHAKE/ML-KEM implementation and its Java
delivery boundary are described below. Generated HKDF adoption and its
provider/Java boundary remain separate work.

### Packet scalar and trace verification

The [packet component](https://github.com/mahmoudimus/MicroProxy/blob/7be2a23be1d8dfe557b847bd4705f6a18f110340/formal/packet/README.md) implements packet-number reconstruction,
fixed-prefix reading and header unmasking in Dafny, then generates Java and
integrates it into the receive path. Conditional reference equations specify exact
results; mask-based code preserves the existing signed-overflow/decision-priority
behavior for all 64-bit largest/truncated values and each legal length1..4.
Header serialization preserves bytes beyond the actual PN and retains published
v1/v2 AES/ChaCha packet outputs.

A generic Dafny straight-line register machine proves paired-run observation
equality for arbitrary secret values under an atomic word-operation observer.
A trusted checker disassembles actual production classes, rejects unlisted
control flow/memory/calls, expands the scalar call closure, extracts SSA programs
and generates a checked application of that theorem. A taint/range checker binds
the exact scalar class/signatures and verifies fixed-address adapters plus the
common validation path for legal lengths. The checkers and `javap` remain trusted;
they are not a formally verified JVM semantics or whole-Java refinement.

The dependency-free Java artifact uses a documented trusted compiler adaptation:
exactly two bounded-shift intrinsics are lowered to JVM shifts. Dafny proves their
count-mask equivalence under `count<64` and every call-site precondition. Raw and
packaged source hashes, actual classes, SSA programs and proof harnesses are
recorded. Unexpected dependencies, branches, assumptions, narrowed domains and
semantic/trace mutants must fail the corresponding gates; resource exhaustion is
never accepted as a counterexample.

Replay with JDK21+, Maven, Python3.11+ and Ubuntu24.04 `libicu74` when applicable:

```sh
python3 -m unittest discover -s formal/packet -p 'test_*.py' -v
python3 formal/packet/run.py
```

The observer excludes JIT/CPU/GC/provider timing, ByteBuffer internals, subsequent
AEAD/key-phase/metadata processing and the outbound protection path. Exclusive
buffer ownership and valid non-overlapping header layouts are assumptions at the
Java boundary. This improves two identified receive-side source patterns; it is
not a claim of whole-record constant time or absence of remote side channels.
The research reference is [EverQUIC's paper](https://www.andrew.cmu.edu/user/bparno/papers/quic-record.pdf);
its F*/C theorems do not automatically transfer to our Java implementation.

### SHAKE and ML-KEM implementations in Dafny

The [native crypto component](https://github.com/mahmoudimus/MicroProxy/tree/diff/dafny-shake-mlkem/formal/crypto)
connects primitive-array implementations to separate standards equations. Its
functional refinements cover Keccak-f[1600], the byte-oriented SHAKE128/256 sponge
and segmented API, canonical polynomial ranges, both NTT inverse directions,
general negacyclic multiplication, codecs/compression, CBD2 and finite rejection
sampling. Deterministic ML-KEM-768 composition discharges caller ranges and proves
validation, deep key ownership, unchanged inputs, fresh outputs, temporary cleanup
on modeled returns and exact reencryption/implicit-rejection behavior. SHA3 uses four audited
declarations for two trusted primitives.

Caller harnesses cover the full documented domains. Broken arithmetic, padding,
indices, sampling, selection, cleanup and narrowed-domain variants must fail real
proof obligations. Parser errors, timeouts and resource exhaustion are
inconclusive. Independent hashlib/Go vectors and ownership/invalid-input tests on
JDK21 and JDK25 supplement these universal source theorems.

The sampler considers 840 bytes, or 280 complete triples, returning one failure
kind if it cannot fill 256 coefficients. This follows the permitted minimum in
[FIPS 203 Appendix B](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
The proof assumes neither eventual acceptance for every XOF stream nor universal
successful honest decapsulation; the standard permits a nonzero failure
probability. Source-level zeroing does not establish physical/JIT erasure.

Native execution uses bounded primitive integers and arrays. A narrow runtime
shift helper can branch on a signed payload even when the Dafny expression is
branchless. The selector therefore uses a wide shift with a public literal
distance; compiled controls reject a narrow helper, an equality-dependent branch
and payload boxing. Codec guards reject payload division/remainder and
payload-sized allocations. Secret values validated after widths1/4/10 have
proved bounds making those branch outcomes constant; width12 key validation
processes public encoded keys. These are reviewed source/bytecode checks with
explicit metadata boundaries, not a whole-program noninterference or JVM timing
proof.

Delivery freezes the include graph with the pinned Dafny parser, audits provider
assumptions, verifies every module and uses the compiler's built-in package
option without rewriting output. Reviewed facade templates are pinned too. Final
checks compare all actual Maven classes and JAR class entries byte for byte with
canonical compilation, including class attributes. The Maven DafnyRuntime is
pinned separately from the compiler bundle because their bytes differ. Compiler,
runtime, providers and the small handwritten facades remain trusted.

A scoped [toolchain review](https://github.com/mahmoudimus/MicroProxy/blob/diff/dafny-shake-mlkem/formal/crypto/TOOLCHAIN-REVIEW.md)
checks three known upstream issues against our actual source and emitted axioms,
with focused cross-checks under Dafny 4.11. None has an affected construct in the
reviewed graph; this is not a general verifier-soundness proof or full 4.11 replay.

Production SHAKE/ML-KEM now use the generated Java after compatibility and
performance review, with the pinned Maven DafnyRuntime 4.9.1 dependency. The
[adoption record](https://github.com/mahmoudimus/MicroProxy/blob/diff/dafny-shake-mlkem/formal/crypto/adoption/README.md)
binds the final stage, generated-source/class identity and agent evaluation to
the prior user authorization. Complete in-memory hybrid TLS handshakes cost
about 21-22% more CPU and 29-30% more allocation; observed local throughput is
13-27% lower. These measurements are not network-capacity or side-channel evidence. The
[completion plan](project/2026-10-29-dafny-crypto-completion.md) and component README
record acceptance criteria and replay commands. ML-KEM formulas retain their Go
provenance; the Dafny specifications, proofs and native ownership refinements are
new work. AWS attribution belongs to the separate HKDF proof structure.

### Timing boundary

Functional correctness, cryptographic security and timing independence are separate. Lean can
formalize AES and prove implementation conformance under suitable semantics; that does not
prove AES immune to cryptanalysis. HKDF security reductions need HMAC/entropy/adversary assumptions.

A trace semantics can describe observable branches, addresses and costs, with a proof of their
independence from secrets. Connecting that to HotSpot machine code, native providers, CPUs,
allocation and GC requires another justified link. Branchless source and noisy timing checks do
not supply it. Our JDK primitive/runtime boundary is explicit; see the [timing review](security-timing-audit.md).

Established projects name the layer they verify. [HACL*/EverCrypt](https://github.com/hacl-star/hacl-star)
verifies functional behavior and secret independence in F*/Low*, with Vale for selected assembly.
[s2n's HMAC verification](https://aws.amazon.com/blogs/security/automated-reasoning-and-amazon-s2n/)
is a component-level example. [SAW's JVM interface](https://galoisinc.github.io/saw-script/master/saw-user-manual/verifying-code.html)
supplies the bytecode interface used by the scoped experiment above.

Remaining work includes generated HKDF adoption and its Java trust boundary,
and a justified timing model for the final JVM implementations. The scoped results above do not establish that all
custom TLS/QUIC glue is formally verified or that the whole proxy is secure.

The [implementation roadmap](project/2026-10-28-quic-crypto-assurance-design.md)
uses Dafny across HKDF, SHAKE and ML-KEM, with TLA+/TLC and Lean covering their
separately stated protocol/model obligations. A theorem's scope and trust boundary
matter more than the language in which it was written.
