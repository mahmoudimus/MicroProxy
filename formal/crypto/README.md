# SHAKE and ML-KEM functional verification

This directory contains the verified Dafny source for production SHAKE and
ML-KEM-768 Java, including native-array refinements and the checked delivery
route. The [adoption record](adoption/README.md) binds the composed graph to its
generated sources/classes, compatibility and performance evidence, and prior
user authority. The [completion plan](../../docs/project/2026-10-29-dafny-crypto-completion.md)
records the full scope; JVM timing remains open.

Differential replay uses the immutable pre-adoption Java in
[`reference/`](reference/README.md), with its original source hashes and provenance.
It is compiled only in isolated harnesses and is never shipped. Earlier evidence
files record the same bytes at their former production paths; current replays use
the fixed reference paths so adoption cannot change its own comparison baseline.
Agreement with that baseline remains finite evidence. Production delivery and
facade checks are separate from these comparisons.

## SHAKE sponge and segmented sequence API

`SpongeSpec.dfy` gives byte-oriented FIPS 202 absorption, SHAKE padding and
squeezing equations. `Shake.dfy` implements those equations with verified loops.
General concatenation and read-partition lemmas cover arbitrary finite lengths
at both rates, including empty input and zero-length output. A zero-length read
initiates squeezing, after which every update is rejected. Slice bounds use
subtraction to avoid overflowing an offset-plus-length check. Both padding XORs
are preserved when the suffix and final bit share the last rate byte.

`ByteLanes.dfy` proves the little-endian byte/lane mapping, pack/unpack round trips
and single-byte XOR behavior. The independent caller harness covers all legal
states, rates, slice arguments and finite output lengths. Fourteen semantic
controls include padding, phase, rate boundaries, byte order and five narrowed
caller domains; their actual proof failures are required for a successful replay.

```sh
python3 formal/crypto/shake_checks.py --output target/dafny-crypto-shake \
  --java-home /path/to/jdk21 --java-home /path/to/jdk25
```

The replay validates the pinned compiler distribution and all included sources,
audits every module, generates Java and checks independent Python hashlib vectors.
It verifies source, tool, JDK and generated-artifact identities before publishing
a receipt. [Recorded evidence](SHAKE-EVIDENCE.json) has zero proof errors and zero
audit findings: Shake 115 checks, SpongeSpec 159, ByteLanes 24, caller harness 11,
and the included Keccak foundation 122. Generated Java passes 47,663 assertions on
each JDK, including 198 vectors/partitions and 24 slice cases. An independent
review replayed the module proofs, both JDK tests and the hashlib vectors.

This immutable-sequence stage alone does not prove ownership of the mutable
Java facade. The native-array and production-delivery sections below describe
that path and its remaining trust assumptions. JVM timing stays open.

## Codec and finite sampling stage

`Codec.dfy` proves compression/decompression equations and the circular error
bound for widths 1 through 11, lossless packing/round trips for widths 1, 4, 10
and 12, and total validation results. Its 12-bit operation is **checked decoding**:
it rejects noncanonical coefficients rather than reducing raw 12-bit words modulo
3329. That combines FIPS 203 decoding with key validation, matching our existing
Java policy; it is not an equivalence claim for raw ByteDecode12 on invalid keys.

`Sampling.dfy` proves CBD2 and finite rejection-feed ordering, capacity and exact
three-byte consumption. Feed rejects incomplete triples and returns `Full` or
`NeedMore` over valid finite blocks. It does not assume an arbitrary XOF stream
eventually supplies 256 accepted coefficients. Termination/failure policy and
intermediate cleanup belong to KEM composition and production delivery.

The public-domain harnesses call these operations over their complete documented
domains. Ten semantic mutations test rounding, packing, canonicality, CBD sign,
sampling order, rejection at q, capacity, consumption and domain narrowing.
Resource exhaustion, syntax failures and timeouts do not count as rejection.

Run the focused replay with a pinned Dafny distribution and explicit JDK paths:

```sh
python3 formal/crypto/codec_sampling_checks.py \
  --dafny /path/to/dafny/dafny \
  --output target/dafny-crypto-codec \
  --java-home /path/to/jdk21 --java-home /path/to/jdk25
```

The repository's `formal/dafny/toolchain.py` installs and checks the official
checksum-pinned Dafny 4.9.1 distribution, including its bundled Z3 4.12.1 and
runtime. CI uses that installer before this replay. Each replay creates a unique
scratch directory and publishes its receipt only after every gate passes and
all source/reference inputs still match their starting hashes.

[Recorded evidence](CODEC-EVIDENCE.json): Codec 469 checks, Sampling 26, public
domain harnesses 7 and 2, and Java generation 70; all had zero errors. Both audits
reported zero findings. Generated Java passed 207,513 assertions on each of JDK
21 and 25. An independent replay/review approved this stage. These counts include
verification obligations, not independent security properties. Java differential
tests are finite compatibility evidence, not a universal bytecode proof.

This isolated codec stage itself makes no production primitive change. Native
composition and current production delivery are documented below. Compiler/runtime/
JDK assumptions, cryptographic hardness, entropy and JVM timing remain separate
from functional proofs.

## Polynomial and NTT algebra

`Polynomial.dfy` proves canonical field ranges throughout the executable
256-coefficient add/subtract, NTT, inverse NTT and NTT-domain multiplication
algorithms. The NTT result is connected to independent power-sum polynomial
remainders from FIPS 203 equations 4.12–4.13. Both inverse directions, all roots
and table entries, and the inverse scale are proved. A general ring theorem
derives negacyclic multiplication using `X^256 = -1` and residue evaluation;
the reference product is not defined through the NTT implementation.

These theorems quantify over every canonical coefficient vector, not a fixed
corpus. [Recorded evidence](POLYNOMIAL-EVIDENCE.json) includes 1,562 verified
obligations with zero errors, six genuine semantic controls, and generated Java
tests with 288 cases and 551,008 assertions on each JDK. The finite tests include
all 256 basis positions and 32 independent schoolbook products. An independent
review reran the full proof, zero-finding audit, caller harness, all controls and
both Java replays, and independently reconstructed both tables from powers of 17.

Use a fresh output directory for each scoped replay, and run its zero-finding
audit as CI does. `--phase` selects partial developer evidence; acceptance requires
`all`, matching input identities and every reported gate.

```sh
python3 formal/crypto/polynomial_checks.py --phase all \
  --dafny /path/to/dafny/dafny --output /fresh/output/directory \
  --java-home /path/to/jdk21 --runtime-home /path/to/jdk25
```

This closes the mathematical polynomial/NTT composition stage. Native-array
refinement and generated production delivery are documented separately below;
this stage supplies no JVM timing guarantee.

## K-PKE and KEM composition

`KemSpec.dfy` defines the deterministic FIPS 203 ML-KEM-768 equations and named
validation failures. `MlKem.dfy` composes the proved SHAKE, polynomial, codec and
sampling operations into matrix expansion, key generation, encryption, decryption,
serialization, public-key parsing, encapsulation and implicit rejection. Accepted
public keys provably re-encode to their original bytes; generated keys parse back
to the same expanded state. Every polynomial caller range is discharged.

The total external entries accept arbitrary seed, public-key, message and
ciphertext sequences and retain explicit validation precedence. The internal
cached-state decapsulator requires `ValidSecret`; there is no arbitrary 2400-byte
secret-key importer in this interface. Its seed-backed external entry establishes
the invariant before using cached state. Reencryption compares all 1088 bytes and
selects all 32 output bytes with masks. This functional/source-shape result does
not establish constant-time execution of the prototype: signed modulo in other
generated sequence operations still uses a runtime helper with sign branches.
The native refinements below remove those negative BigInteger payload paths.

The sampler considers 840 XOF bytes, or 280 complete three-byte iterations, and
returns one `RejectionLimit` failure if fewer than 256 coefficients are accepted.
This bounded policy follows the minimum in FIPS 203 Appendix B and is adopted
by the native composition below. The immutable-sequence stage alone does not
establish mutable intermediate destruction or physical erasure. The KEM theorem gives exact reencryption/fallback behavior,
not universal honest-ciphertext decryption success; the standard permits a nonzero
decapsulation failure probability.

`JdkHash.dfy` has exactly two named provider assumptions, SHA3-256 (`H`) and
SHA3-512 (`G`). The implementation equations are proved relative to those
deterministic primitive contracts. This does not prove their cryptographic
strength, entropy, provider internals or compiler/runtime correctness.

```sh
python3 formal/crypto/kem_checks.py --scope full --dafny /path/to/dafny/dafny \
  --output /fresh/output/base --java-home /path/to/jdk21 \
  --java-home /path/to/jdk25
```

[Recorded evidence](KEM-EVIDENCE.json): the frozen dependency graph has 2775
verified obligations with zero errors; Java generation has 80. Nine genuine
semantic controls cover coins, matrix axes/transposition, nonces, fallback seeds,
selection, comparison length, modulus failures and the sampler bound. Each JDK
passes 5091 assertions including the exact 100-round Go accumulator. Independent
review approved the composition and its two provider assumptions; the coordinator
then completed the final full replay against the frozen reviewed dependencies.
`--scope owned` is explicitly partial evidence and cannot close the full stage.

The polynomial Horner and canonical 12-bit encoding proofs are split into smaller
lemmas so that Linux and macOS complete at the same 30-second/50-million-resource
limits. Their domains and result equations are unchanged. The proof-only splits
produce exactly the same generated Java and compiled KEM classes as before.

## Native SHAKE sponge and API

`NativeKeccak.dfy` and `NativeShake.dfy` refine the same permutation and sponge
equations using primitive `long[]`, `byte[]` and bounded `int` indices. Their
contracts cover both rates, arbitrary valid states, all signed-int slice arguments
and segmented reads/updates. Invalid slices leave the state unchanged; empty
reads initiate squeezing. Constructor freshness and the private Java facade keep
caller buffers separate from sponge state and public rotation/index tables.
`Destroy` proves writes of zero to every secret lane and work-array element.

The independently reviewed component replay discharged 1,532 obligations with
zero errors, six clean audits and 22 genuine semantic controls. Both JDKs passed
25,218 assertions using the exact Maven runtime. The generated-source and actual
bytecode audit checks the permitted runtime calls; allocation boxing and
BigInteger conversions consume public constants. Source-level wiping does not
prove physical erasure, and the audit does not prove JVM timing.

```sh
python3 formal/crypto/native_shake_checks.py --output /fresh/output/base \
  --java-home /path/to/jdk21 --java-home /path/to/jdk25 \
  --runtime-jar /path/to/DafnyRuntime-4.9.1.jar \
  --runtime-sha256 dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6
```

The API facade is reviewed separately; the production delivery below binds it
to complete composition, compatibility/performance evaluation and exact artifacts.

## Native field and polynomial refinement

`NativeField.dfy` refines the field equations with bounded Java `int`/`long`
arithmetic. Its Barrett product covers the complete caller range through
22,154,496. Reduction uses reciprocal 5039, a 24-bit shift and one correction;
the correction uses a biased positive word and a 15-bit shift. Division and
remainder occur only in specifications and proofs. The generated scalar bytecode
has no value-dependent branch, division/remainder, BigInteger arithmetic or boxing.
That inspected bytecode shape is not a JVM machine-code timing theorem.

`NativePolynomial.dfy` connects mutable 256-coefficient arrays to the independently
proved polynomial/NTT equations. All inputs in `[0,3329)^256` are covered, including
aliasing permitted by the public contracts. The proof establishes caller ranges,
fresh outputs, unchanged inputs and source-level cleanup of discarded arrays.
Fourteen semantic controls cover scalar reduction/correction, butterfly signs and
indices, roots, inverse scaling, ownership and wiping. Legal witness restrictions
appear only in temporary negative copies; positive domains remain unchanged.

The component replay also checks the actual scalar bytecode and compares generated
Java with the fixed reference, all basis positions and independent schoolbook
products. Both JDKs passed 22,865,885 assertions in the recorded component replay.
The production delivery below composes this with the complete KEM graph and
checks the delivered artifacts.

```sh
python3 formal/crypto/native_polynomial_checks.py --phase all \
  --dafny /path/to/dafny/dafny --output /fresh/output/directory \
  --java-home /path/to/jdk21 --runtime-home /path/to/jdk25 \
  --runtime-jar /path/to/DafnyRuntime-4.9.1.jar \
  --runtime-sha256 dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6
```

## Native codec and sampling refinement

`NativeTypes.dfy` defines bounded Java `int`/`long` representations and ghost
array-to-sequence projections. `NativeCodec.dfy` and `NativeSampling.dfy` refine
the reviewed sequence contracts using primitive arrays and arithmetic. Their
proofs cover the full legal domains, native arithmetic bounds, fresh outputs,
unchanged inputs and zeroing of discarded intermediate arrays. Width-10 packing
uses native `long` intermediates below `2^40`; it cannot be narrowed to `int`.
Coefficient packing and rounding use proved shifts, masks and reciprocal
arithmetic. CBD2 uses `NativeField.ReduceOnce` for its canonical signed difference.
Coefficient values do not reach division/remainder helpers. The only retained
division/remainder operations process public indices, lengths and widths.

[Recorded evidence](NATIVE-CODEC-EVIDENCE.json) preserves the full-domain proof
results: codec 1,503 checks, sampling 281, field 84, and caller harnesses 8 and 4,
all with zero errors and zero audit findings. Fifteen genuine semantic controls
include native overflow, rounding/shift/reciprocal errors and discarded-buffer
cleanup. A subsequent checker-only revision explicitly reuses those proofs by
unchanged source and generated-artifact identities; it freshly compiles and runs
334,753 assertions on each JDK with the exact Maven runtime.

The packing radix proof is split into five explicit byte cases for bounded
Linux/macOS verification at unchanged limits. Its domains/contracts and generated
Java/classes are unchanged. Semantic controls require normal verifier exit4;
crashes never count as counterexamples, even after a semantic diagnostic.

An independently reviewed bytecode dataflow check covers 45 methods. It requires
public operands at metadata arithmetic calls and rejects payload-dependent array
allocation sizes, including allocations whose lengths would cross a native call.
Eight compiled controls exercise direct arithmetic, metadata laundering and JVM/
Dafny allocation paths. Constant-zero allocation boxing is listed explicitly;
secret-value boxing, BigInteger/sequence arithmetic and payload division are
rejected in the inspected paths. This checker is trusted, not a formal proof of
JVM timing or whole-program noninterference.

```sh
python3 formal/crypto/native_codec_checks.py --dafny /path/to/dafny/dafny \
  --runtime /path/to/DafnyRuntime-4.9.1.jar \
  --output /fresh/output/base --java-home /path/to/jdk21 \
  --java-home /path/to/jdk25
```

These component receipts alone do not establish full native KEM delivery;
the production section below records the composed path. Source-level zeroing is
a functional heap contract; physical/JIT erasure and JVM timing are not proved.

## Native K-PKE and KEM composition

`NativeMlKem.dfy` connects the primitive-array implementation to `KemSpec` for
keygen, matrix/noise expansion, K-PKE, key parsing, serialization, encapsulation
and decapsulation. Every caller range is discharged. Retained keys have deep
private ownership; caller inputs are preserved, results are fresh, and discarded
temporary arrays are zeroed on modeled returns. The seed-backed factory establishes
the cached-key invariant; arbitrary serialized private-key import is not offered.

[Strict evidence](NATIVE-KEM-EVIDENCE.json) records composition 2,776, reference
graph 2,649, native kernels 3,487 and generation 162 obligations, all with zero
errors. Counts include overlapping dependency checks, not independent security
properties. All 11 semantic controls terminate normally with exit4, and three
compiled controls reject selector narrowing, payload branches and payload boxing.
Both JDKs pass 7,813 assertions, including the Go accumulator and malformed-input,
all-position selector and destruction cases. The hash-matched [Linux composition replay](NATIVE-KEM-LINUX-EVIDENCE.json)
passes the same 2,776 checks at unchanged limits. Its ghost-only NoiseVector
model capture leaves all 66 emitted Java sources and 72 compiled component/test
classes byte-identical to the prior strict receipt. Native source/runtime reviews
were independent development reviews, not an external cryptographic audit.

The complete comparison covers all 1088 ciphertext bytes and all 32 output bytes.
Its mask uses a wide shift by public literal56, avoiding the pinned runtime's
narrow-helper payload-sign branch. Runtime helper bodies and JDK unsigned byte
conversions are inspected explicitly. This is not a JVM timing theorem.

`NativeJdkHash.dfy` binds four audited declarations to two trusted JDK SHA3
primitives. Normal completion, fresh fixed-length results and input preservation
are explicit provider assumptions. Compiler/runtime correctness, hardness,
entropy and physical erasure are not established by the functional proofs.

```sh
python3 formal/crypto/native_kem_checks.py --scope full \
  --dafny /path/to/dafny/dafny --runtime /path/to/DafnyRuntime-4.9.1.jar \
  --output /fresh/output/base --java-home /path/to/jdk21 \
  --java-home /path/to/jdk25
```

The generated implementation is used through the reviewed production Java
facades. Its mutable constructors and arrays are internal; the facade preserves
the verified ownership boundary under the documented Java/compiler assumptions.

## Production delivery

Production `Shake` and `MlKem768` delegate to the unmodified generated native
classes. The [delivery archive](adoption/README.md) records the 18-root verified
stage, exact 66-source/66-class identity, four freshly compiled facade classes,
13 compatibility tests on each JDK (including Go 10,000), complete hybrid TLS
measurements, and the separate prior-human/agent-evaluation adoption decision.
The pinned Maven DafnyRuntime 4.9.1 differs in bytes from the compiler bundle;
its identity and permitted native helper calls are checked explicitly.

The full local JDK21/25 Maven suites and actual Maven class/JAR/runtime checks
are recorded separately from source verification and performance. The enforced
CI job repeats the frozen generation/delivery route on the exact pushed head.
Compiler/runtime/provider correctness, entropy, hardness, physical erasure and
JVM timing remain explicit boundaries.
