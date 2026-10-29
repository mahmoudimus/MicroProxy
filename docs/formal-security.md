# Security assurance and formal verification

MicroProxy has a custom TLS/QUIC implementation. Its assurance includes development review,
published standards vectors, interoperability/rejection tests, exploratory timing observations,
and the scoped models below. No end-to-end security proof, independent expert cryptographic
audit, certification, or constant-time HotSpot guarantee is claimed. Agent reviews are
development reviews, not an external expert audit. A green test or updated dependency does not
establish absence of vulnerabilities.

Interoperability and security assurance are separate. Our primitive boundary includes
handwritten ML-KEM and SHAKE implementations.

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
| `crypto/HeaderKey` | Mask/sample offsets, header bits and format | JDK AES/ChaCha plus packet vectors; no complete bit/buffer refinement. |
| `KeyExchange`, `EcCurves`, `Signatures` | Encodings, hybrid order, public point/zero checks, signature contexts/parameters | JDK classical primitives plus vectors/interop/negative tests. Wire/policy glue remains ours. |
| `MlKem768` | Keygen, sampling, field arithmetic, NTT, codecs, compression and implicit rejection | Handwritten primitive; vectors against Go, malformed-input tests, and the single-method bytecode proof below. No full FIPS 203 refinement or JVM timing proof. Only SHA3 digests/randomness are delegated here. |
| `Shake` | Keccak-f and SHAKE absorb/pad/squeeze | Handwritten primitive; Python hashlib values, rate boundaries and segmented-I/O tests. No FIPS 202 refinement or timing proof. |
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

The opt-in [SAW experiment](https://github.com/mahmoudimus/MicroProxy/tree/diff/quic-interop-submission/formal/saw) verifies the actual Java 21
`MlKem768.reduceOnce(int)` class-file method against mathematical remainder:
for every integer `0 <= a < 6658`, its result is `a mod 3329`. The proof has no
method overrides or admitted dependencies. It establishes one scalar method's
functional result under its precondition; callers' range obligations, the other
ML-KEM operations and timing remain unproved. It does not recompile a copied
method or substitute an older class-file version.

The runner pins production source and class hashes, snapshots existing classes,
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

The reviewed candidates do not establish a ready, fully verified pure-Java
ML-KEM-768 plus SHAKE replacement. Porting a verified native implementation would
require a new checked link before its proof could apply to Java. The useful next
steps are additional arithmetic/codecs proofs, adoption review of the generated
HKDF component and explicit provider/Java boundary contracts.

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

The next assurance work includes generated HKDF adoption and its Java trust boundary, then extends to ML-KEM
finite-width arithmetic/NTT/codecs and SHAKE/FIPS 202 refinement, with a defined secret-trace
timing model. Those remain gaps. Claiming all our handwritten crypto formally verified, or the
proxy proved secure, would be false.

The [implementation roadmap](project/2026-10-28-quic-crypto-assurance-design.md)
uses Dafny across HKDF, SHAKE and ML-KEM verification, starting with HKDF and the
pinned AWS reference. The selected HKDF delivery route is verified Dafny compiled
to Java, with explicit compiler/runtime trust. Later milestones remain proposed
work, separate from the completed proofs described here.
