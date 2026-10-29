# Dafny SHAKE/ML-KEM foundations

This isolated component starts V4/V5 of the crypto verification work. It verifies
an executable Keccak-f[1600] lane permutation and seven scalar ML-KEM field
helpers, generates Java with verification enabled, and tests that exact artifact
against the canonical handwritten Java. It does not replace production `Shake`
or `MlKem768`, and adds no production runtime dependency.

[Validation evidence](EVIDENCE.md) records the completed local checks and separates
them from CI, production adoption and the remaining proof obligations.

With Python 3.11+, JDK 21+ in `JAVA_HOME`, and Ubuntu 24.04 `libicu74` when applicable:

```sh
python3 -m unittest discover -s formal/primitives -p 'test_*.py' -v
python3 formal/primitives/run.py
# Optionally execute the same Java21 classes on another installed runtime:
python3 formal/primitives/run.py --java-home /absolute/path/to/jdk25
```

The replay reuses the checksum-pinned Dafny 4.9.1 distribution/runtime installer
and bounded process cleanup from `formal/dafny/`. No global toolchain is changed.
`--cache` and `MICROPROXY_FORMAL_CACHE` select the external cache; `--output`
selects an evidence root (default `target/dafny-primitives/`). The pinned runtime
is a development harness dependency only. Performance, allocation and packaging
need separate review before adoption.

## Verified equations and domains

`Keccak.dfy` separates a ghost functional spec from executable snapshot-based
array loops. For every sequence of exactly 25 arbitrary 64-bit lanes, the result
equals 24 applications of theta, rho, pi, chi and iota in order, with lanes indexed
`x+5*y`. Per-stage invariants prove complete results, bounds and termination.
Opaque helper definitions are revealed in proved lemmas to control solver work;
they are not admitted assumptions. Rotate covers all 64-bit values and offsets 0..63.

The reference equations follow FIPS 202 sections 3.2/3.3. The spec uses its unabridged
rho offsets, while executable offsets are reduced modulo 64; their relation is
proved. Both constant tables are reviewed spec inputs. The Java harness also
checks them against independent coordinate/LFSR recurrences and an XKCP known
answer. This is a lane-level equation proof: a complete bit-string/lane refinement,
SHAKE absorption, suffix/padding, arbitrary segmented squeezing and API validation
are still open. It is not full SHAKE/FIPS 202 conformance or a proof of cryptographic
permutation security.

`Field.dfy` proves exact remainder and canonical output range for q=3329:

| Method | Preconditions | Result |
|---|---|---|
| ReduceOnce | 0<=a<6658 | a mod 3329 |
| Reduce | 0<=a<=22154496 | a mod 3329 |
| Add/Sub/Mul | All coefficients in [0,3329) | Their sum/difference/product mod 3329 |
| MulSub | All three coefficients in [0,3329) | a*(b-c) mod 3329 |
| AddMul | All four coefficients in [0,3329) | a*b+c*d mod 3329 |

Executable arithmetic models 16-bit wrap and logical right shift with mathematical
remainder/division. Reduce uses the existing Barrett multiplier 5039 and shift 24;
the proof discharges its residual bound before calling ReduceOnce. ProductBound
discharges scalar helper call-site ranges, including MulSub's maximum 3328*6657.
These mathematical integers compile to Java BigInteger operations, not the
existing primitive-int bytecode. The separate SAW result remains the actual-Java
proof for ReduceOnce only.

The existing `reduce` comment describes inputs below 2^24, but canonical helper
contracts can produce larger inputs: AddMul reaches 22151168 and MulSub 22154496.
This component proves the wider scalar domain. It does not prove that every
polynomial/NTT caller supplies canonical coefficients. NTT/inverse NTT, codecs,
compression, sampling, key generation/encapsulation/decapsulation and implicit
rejection composition remain open obligations.

## Delivery gates and trust

The runner checks exact source/tool/reference input inventory and hashes, verifies
both kernels, audits zero added assumptions, and verifies unconstrained public
domain harnesses. Semantic/domain mutants must fail actual proof obligations;
extra axioms and skipped verification must fail the audit policy. A crash, parse
failure or resource exhaustion cannot count as rejection evidence.

Java generation has verification enabled. The runner compiles the exact generated
sources, the finite test harness and canonical production reference sources into
a fresh directory; generated source/classes must remain unchanged through tests.
It invalidates old success before setup and atomically publishes a complete report
only after all checks pass. Interrupted/setup/serialization failures cannot retain
a previous successful report. The lock prevents simultaneous writers.

The test harness covers all 1600 one-bit states, zero/all-ones/random states,
all 4096 one-bit/offset rotation combinations, an independent forward-pi coordinate
check, every valid ReduceOnce input, and wide Barrett/canonical helper cases. These
are finite tests of the generated Java/adapter boundary, not a refinement theorem
for the handwritten classes. The general Dafny result applies to the generated
algorithm under compiler/runtime trust.

Trust includes standards-to-spec review, Dafny/Boogie/Z3, its Java compiler/runtime,
javac/JVM, OS/tool execution and the handwritten harness/conversion code. No
secret-independent trace or physical JVM/CPU/provider timing theorem is added.
These BigInteger/sequence/array implementations are not claimed constant time.
No security reduction, entropy/hardness proof, secret-erasure guarantee or external
expert cryptographic audit is supplied by this component.

## Provenance and next steps

These are new standards-based Dafny kernels; AWS HKDF provenance does not apply.
The field formulas correspond to the existing Go-derived Java component; its Go
attribution is preserved. References:

- [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), sections 3.2/3.3.
- [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf), q=3329.
- [Pinned XKCP intermediate-value vector](https://github.com/XKCP/XKCP/blob/5585d0213203c0c5b2dfdf3b34f5da9275abc3e7/tests/TestVectors/KeccakF-1600-IntermediateValues.txt).
- [Work plan](../../docs/project/2026-10-29-shake-mlkem-dafny-foundations.md).

Next prove the sponge/segmented API over arbitrary lengths and discharge polynomial
caller ranges, then NTT/codecs/sampling and full ML-KEM composition. Production
adoption additionally needs runtime/performance review or a checked primitive
lowering. Existing bytecode/model/finite evidence remains separately labeled.
