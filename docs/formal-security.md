# Security assurance and formal verification

## Functionally verified cryptographic implementations with documented trust assumptions

Production HKDF, SHAKE128/256, ML-KEM-768 and the QUIC packet-number nonce primitive use Java generated from functionally verified
Dafny implementations. The proofs cover their stated functional specifications; checked source,
class and JAR delivery connects the verified source to the packaged Java. Compiler/runtime,
reviewed Java facades and selected JDK primitives remain trusted, as detailed below.

**Version scope:** these claims describe current `main` source and explicitly
validated build artifacts. The historical
[`v0.6.0` release](https://github.com/mahmoudimus/MicroProxy/releases/tag/v0.6.0)
predates the generated-backend integration; its downloadable binaries are outside
this proof scope. The published
[`v0.7.0` release](https://github.com/mahmoudimus/MicroProxy/releases/tag/v0.7.0)
contains the generated-backend source integration. Its downloadable artifacts
passed [scoped actual-artifact validation](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/releases/v0.7.0)
for the recorded library and bundle SHA-256 digests, with identity and
loaded-origin checks on JDK 21/25. A source commit alone does not certify binary
files. [Current source builds](getting-started/install.md#building-from-source)
and later releases still need validation for their exact supplied artifacts.

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
| Dafny | Specify exact results, verify executable algorithms, and generate Java from the verified source | Production HKDF, SHAKE and ML-KEM use generated Java with checked delivery. SHAKE/ML-KEM use native-array refinements; HKDF implements complete Extract/Expand/label equations. The packet kernel is integrated. Compiler/runtime, facades and any lowering are explicit trust boundaries. |
| SAW/Crucible | Prove a property of supported actual Java class-file methods | One bounded reduction method from the pre-adoption Java artifact; it does not prove the current generated backend. The `PacketKey.nonce` SAW attempt remains blocked; the adopted nonce uses a separate Dafny-generated functional route and claim. Unsupported operations and caller preconditions remain outside that experiment. |

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

The [verification artifact guide](https://github.com/mahmoudimus/MicroProxy/tree/main/formal)
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
| `Hkdf`, generated HKDF and Java/JCE adapters | Extract/Expand feedback/counters, block copying and TLS labels around JDK HMAC | The production facade delegates to the generated kernel. Full result equations, a general-domain harness, mutation controls, RFC/JCE vectors and source/class/JAR checks cover the selected route. The adapters, compiler/runtime and HMAC provider remain trusted; no HKDF security reduction or JVM timing proof. |
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
The original SAW input map is preserved verbatim and its pre-adoption
`PacketKey.java` entry is frozen under `formal/saw/historical`; a current-tree
replay is expected to fail that historical input check. The candidate production
nonce is a **separate** generated-Dafny functional route: `PacketKey.nonce`
delegates to `VerifiedNonce.__default.Nonce`, with its own proof/control/
generation/JDK21-25 receipt and a narrow `packet-nonce-functional-production`
claim. That claim is not a SAW bytecode result and makes no cryptographic-
hardness, timing or full-JAR claim.
SAW/Crucible semantics and translation, Cryptol, the solver, selected JDK classes
and the Java build remain trusted. This experiment is separate from the Lean/TLC
CI job and currently requires the documented local tool setup.

### Verified Dafny implementation and Java generation

The [Dafny HKDF component](https://github.com/mahmoudimus/MicroProxy/blob/main/formal/dafny/README.md) implements Extract, Expand,
TLS label serialization and their composition. All four methods return explicit
validation results and have full output equations, with no caller preconditions.
The kernel verifies 21 checks; a separate harness verifies that all methods remain
callable over their complete mathematical input domain. Mutated feedback, counter,
truncation and prefix, a narrowed domain, an extra axiom and skipped verification
must be rejected. The sole permitted Dafny assumption is deterministic abstract
HMAC with its fixed output-length contract.

The production byte adapters copy primitive arrays in bulk. An earlier integration
loop used `DafnySequence.select` on each secret byte; the pinned runtime boxed that
byte through Java's byte cache. The replacement uses the reviewed primitive-array
copy route. Actual-class checks and old-loop mutants guard both converters.
The pinned runtime's copying behavior remains an inspected and tested assumption;
this change does not prove HotSpot constant time.

The runner generates Java with verification enabled and compiles/tests that exact
output with the actual Java/JCE adapters. The small adapters, Dafny/Boogie/Z3,
Dafny's compiler/runtime, `javac`, JVM and provider remain trusted. Finite tests
check RFC 5869/9001 values, all three HMAC digests, high-bit octets, Unicode labels,
validation bounds, array ownership and concurrent calls. They do not prove the
adapter or compiler correct. Source/generated/class hashes identify the replay.

Production `Hkdf` delegates Extract, Expand and label serialization to this generated
kernel. A frozen copy of the earlier handwritten implementation supplies the test
oracle, so the differential comparison is independent of the new implementation.
The facade retains short nonempty PRKs, empty label suffixes, null IKM/info handling
and the public API. Java value/error conversion and the one-line composition in
`expandLabel` are reviewed and tested adapters, not universal Java refinement proofs.
Each HMAC block uses a fresh JCE `Mac`; the feedback loop shares no provider state.
No cryptographic security reduction or JVM/provider timing guarantee follows.

The [HKDF adoption record](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/crypto/adoption/hkdf)
retains the fresh canonical replay, all 467 Maven library classes and minimized
bundle checks. The bundle's 82 scoped crypto classes, packaged runtime and notices
match the expected artifacts; full hybrid-handshake smoke tests check loaded-class
origins on JDK 21 and 25. These are artifact and finite integration checks.
The HKDF-only experiment adds 30.45% allocation on JDK 21 and 27.85% on JDK 25
per complete handshake relative to the previous HKDF with the same generated
SHAKE/ML-KEM backend.
Shared-host fork drift leaves CPU impact inconclusive; no capacity or timing-security
claim follows from those measurements.

The pinned AWS reference target replays with nine verified checks. Its full
71-file include graph failed with dependency obligations, resource/time limits and
a verifier backend exception. Those obligations remain open; our standalone
kernel is independently verified and imports none of that graph. The
[reference replay record](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/reference/aws-hkdf)
keeps target success and full-graph failure separate.

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
delivery boundary are described below. Production HKDF follows the same generated
implementation approach with its own explicit provider/Java boundary.

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
[adoption record](https://github.com/mahmoudimus/MicroProxy/blob/main/formal/crypto/adoption/README.md)
binds the final stage, generated-source/class identity and agent evaluation to
the prior user authorization. Those earlier SHAKE/ML-KEM adoption measurements,
before generated HKDF, recorded about 21-22% more CPU and 29-30% more allocation
per complete in-memory hybrid handshake; observed local throughput was 13-27% lower.
These measurements are not network-capacity or side-channel evidence. The
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

### Source-first continuation

The approved continuation proves ownership, freshness, aliasing and frame
contracts directly over executable Dafny, then generates Java from those same
verified bodies. Source-level secret-trace proofs must additionally establish
the connection between their observations and the actual executed operations.
An independently handwritten trace model, an unobserved operation, or an
unchecked ghost-trace annotation cannot supply that connection.

The [source-assurance design](project/2026-11-03-dafny-source-assurance.md) and
[implementation plan](project/2026-11-03-dafny-source-assurance-plan.md) record
this direction. The broader source-trace obligation is still open. This route
does not remove compiler/runtime assumptions or establish physical JVM timing.
The existing bytecode results below remain supplementary evidence for their
stated scopes; they are not the primary route for proving Dafny ownership.


The [HKDF source-trace component](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/source/hkdf)
uses the actual production Extract, Expand, LabelInfo and ExpandLabel bodies with
ghost trace outputs. It proves equal source observations for arbitrary private
byte contents when public lengths/hash choice/TLS labels agree, including
invalid-input and boundary outcomes. The body has 248 verified checks; the
paired/domain harness has 259. A separately trusted C# adapter over Dafny's
resolved AST checks that observations cover the accepted executable operations
and remain in order. Its adversarial controls reject omitted/reordered events,
trace resets, shadow declarations and lost callee outputs. The checker is
reviewed code, not a formally verified execution semantics. Its binding scan
uses an exact supported statement grammar over resolved statements and
expressions, including ghost/proof code; unknown forms, ghost-call output
bindings and direct trace replacement by calls reject.
The assign-such-that regression demonstrates why this matters: its complete
Dafny proofs and generated Java still pass after callee observations are erased,
so the coverage adapter must independently reject that binding. Site IDs are
opaque method-local labels, not JVM program counters. Java erasure/delivery checks and
JDK HMAC/compiler/runtime assumptions remain explicit; this does not establish
physical constant-time execution or whole-crypto trace independence.

The [polynomial source-trace component](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/source/polynomial)
extends this approach to 13 native polynomial methods, their seven field-method
dependencies and 19 executable pure helpers. Paired harnesses call the actual
methods, including forward/inverse NTT and multiplication, with independently
varying permitted coefficient values. They retain the original frames and
within-call alias restrictions, and exercise permitted shared-buffer cases.
The body proofs include 1,001 polynomial and 86 field checks; the polynomial
paired harness has 26 checks and the field compatibility harness has 14.
The shared observation wrappers and canonical vocabulary are also verified.

Its separately trusted resolved-AST checker binds observations to actual
operations, resolved callees and trace outputs. The runner requires the exact
reviewed root identities, clears ambient test selectors and rejects scope
changes, omitted observations and reordered or replaced callee traces. Genuine
observed secret-branch and secret-index controls fail the paired proof. Memory
observations identify method-local buffer roles and indices, rather than physical
Java heap addresses. This scoped result does not discharge complete SHAKE,
ML-KEM, adapter or invalid-input composition. Generated class identity and the
existing functional and artifact checks remain separate delivery requirements.

The [Select source package](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/source/select)
applies the same route to the actual `NativeMlKem.Select` body. Its Dafny
contracts return a fresh 32-byte result, preserve existing input arrays through
the method frame, and retain permitted input aliases. The paired harness calls
the real method with independently varying expected/candidate/fallback bytes,
including permitted aliases, and proves equal logical observations. Its six
checks cover the fixed 1088-byte comparison and 32-byte selection trace; the
complete ML-KEM body replay has 2,773 overlapping checks. These counts are not
independent security theorems.

The resolved-AST coverage checker binds reads, writes, loop observations and
the single result allocation to the executable body. That C# checker remains
trusted code. Buffer roles and indices describe source observations, not
physical Java addresses. The package also checks erasure over 65 generated
algorithm sources/classes per supported JDK; the complete delivery's 66-class
inventory is a separate scope. These source, generation and delivery checks
retain their compiler/runtime/provider assumptions. Complete ML-KEM trace
composition, physical JVM timing and external expert review remain open.

Some component READMEs are frozen proof inputs. In particular, the polynomial
README's 2,767 row records its earlier snapshot; the current full report and
obligation ledger record 2,773. The frozen package README's candidate wording
likewise describes its qualification snapshot. Current support is determined
by the gated ledger and actual evidence, rather than renewing a receipt to
accept a documentation edit.

The [direct source component](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/source)
adds a SHAKE ownership harness that calls the actual constructor and methods.
It proves fresh outputs, a disjoint six-object factory footprint, preserved
frames and rate, unchanged external inputs, output survival through destruction,
and permitted external input/output aliasing. It verifies the included
implementation bodies and existing public-domain callers as well as the new
harness. These results use the existing contracts without changing executable
Dafny, generated Java or accepted caller domains. They do not discharge the
separate secret-trace, compiler-preservation or exclusive Java ownership claims.

### Existing bytecode trace evidence

The [secret-trace component](https://github.com/mahmoudimus/MicroProxy/tree/main/formal/timing)
adds a Dafny paired-execution model and a checked extraction route for selected
compiled methods. Its observer and public/secret classifications are explicit.
The current five caller certificates cover ML-KEM comparison/selection,
public-seed rejection sampling and generated HKDF Extract, Expand and label
serialization. Their 19 opaque owned helper/adapter contracts are explicit
assumptions; checked class identity does not prove those callees' traces.
Only methods accepted by the extractor and covered by successful certificates
are in scope; unsupported operations, unresolved callees and assumptions stay
visible. The bytecode mapper and provider/runtime contracts remain trusted.
This work does not yet close the compositional trace obligation for all crypto
and authentication paths.

Review found a copy-operand mismatch between the bytecode extractor and its trace
model. It could make modeled loops degenerate despite successful proof checking.
The affected receipts have been replaced after correcting extraction and adding
execution controls for loop stores and secret-value flow. All five caller
certificate hashes changed. Four helper certificates and a separate composed
sampler certificate supplement them; they do not close all owned-call assumptions.
The finite execution controls require private-input liveness and stores to the
intended secret parameter role. They supplement the model theorem and do not
prove Java/JVM value refinement. The functional
HKDF/SHAKE/ML-KEM proofs are separate. This is also why the extractor remains an
explicit trust assumption: proving the emitted model does not itself prove that
the model faithfully represents Java execution.

The extractor also rejects every method with a declared exception table. A repair
prevents javap's column header from hiding catch/finally ranges and keeps methods
with `throws` declarations separate. Unbound Code arrays and non-increasing
bytecode offsets are rejected. Fifteen additional regression tests independently
read real javap tables/member boundaries and exercise malformed-input rejection.
The current selected bodies contain no handlers and retain their certificates'
mathematical content. `JdkHmac.compute` remains an opaque owned assumption and
can throw when called by the generated Extract/Expand bodies; its exceptions
are not modeled. The other three handler-bearing wrapper methods in the class
inventory are outside the certified call graph. Implicit exceptions and JVM
timing remain outside this observer.

The component also checks two static HKDF helper bodies and seven private field
arithmetic bodies, supported by two public constant helpers. Owned field calls
are expanded into their certificates; their remaining shift runtime contract is
explicit. These additions leave 13 open roots, the original 19 caller assumptions
and 31 aggregate unchecked labels. The clone/sequence model does not prove copied
contents or alias ownership, and modeled arithmetic does not refine JVM values.
The full adapter, polynomial/NTT and KEM trace composition remains open.

The replay also checks seven Keccak helper bodies, including the complete
`PermuteScratch` loop, with private calls and the actual pinned runtime shift
bodies inlined. A conservative Dafny extension retains the same observer and
proves default-semantics equivalence. Its additional `PublicOnly` property
checks known targets, exact argument counts, public scalar arguments and no heap arguments for every
remaining provider call. The concrete certificate proves that property; it is
not a new assumption about our helpers. Completed finite controls exercise all
24 rounds and check public heaps as well as registers and traces. They are not
JVM timing evidence. The compiler/runtime, reviewed extraction and oracle
mapping remain trusted. Full Sponge, `Permute` wrapper, KEM and adapter trace
composition is still open; the original 19 caller assumptions, 13 open roots
and 31 aggregate labels remain explicit. Receiver/ownership prototypes have
not been promoted into this evidence.

### Obligation and release-claim gates

The [unified ledger](https://github.com/mahmoudimus/MicroProxy/blob/main/formal/obligations.md)
tracks V0-V8, their dependencies, source/tool pins, proof and control receipts,
trust assumptions and remaining blockers. Its validator rejects missing evidence,
stale hashes and claims stronger than the selected evidence policy. It is a
tested Python gate, not a proof of the validator or of all project code.

Functional production claims, a current artifact identity check, complete upstream
reference replay, source-trace independence, physical timing and external expert
review are separate claims. A scoped functional claim can pass while the aggregate
`--require-all` gate fails. The latter must continue to fail while required work
remains open; agent review cannot satisfy external expert review.

The release CLI accepts explicit classes, library JAR, minimized bundle, canonical
stage, runtime and JDK 21/25 inputs. It freshly runs the complete delivery and
bundle checks and supports `current-release-jar-identity` only for that invocation
and those unchanged artifacts. CI uses this route. The committed ledger keeps the
claim deferred, so a historical build receipt cannot authenticate a later build
or deployment. See the ledger guide for the command, output protections and trust
boundaries. This artifact check adds no timing or cryptographic-security theorem.

Established projects name the layer they verify. [HACL*/EverCrypt](https://github.com/hacl-star/hacl-star)
verifies functional behavior and secret independence in F*/Low*, with Vale for selected assembly.
[s2n's HMAC verification](https://aws.amazon.com/blogs/security/automated-reasoning-and-amazon-s2n/)
is a component-level example. [SAW's JVM interface](https://galoisinc.github.io/saw-script/master/saw-user-manual/verifying-code.html)
supplies the bytecode interface used by the scoped experiment above.

Remaining work includes the unclosed AWS dependency replay, broader compositional
secret-trace coverage, independent expert review and a justified timing model for the
final JVM implementations. The scoped results do not establish that all custom
TLS/QUIC glue is formally verified or that the whole proxy is secure.

The [implementation roadmap](project/2026-10-28-quic-crypto-assurance-design.md)
uses Dafny across HKDF, SHAKE and ML-KEM, with TLA+/TLC and Lean covering their
separately stated protocol/model obligations. A theorem's scope and trust boundary
matter more than the language in which it was written.
