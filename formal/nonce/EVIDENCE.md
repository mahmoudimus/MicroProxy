# Nonce component evidence

Scope: `VerifiedNonce` proof/generation/test component plus its narrow production
adoption (`PacketKey.nonce` delegation, central delivery inventory and the
`packet-nonce-functional-production` claim). The component replay itself does not
verify `PacketKey` delegation, Maven/class/JAR acceptance or CI; the separate
`formal/nonce/PRODUCTION-EVIDENCE.json` receipt binds the reviewed adoption. It
is also not a SAW proof and makes no cryptographic-hardness, constant-time,
JVM-timing, provider or deployment claim.

The generated class is under `quic/src/main/java` and is now called by
`PacketKey.nonce`. A normal Maven build compiles and packages it; central
inventory counts it (468 library / 84 crypto / 468 retained classes). The `quic`
artifact is **not** unchanged. A fresh canonical stage and actual-artifact
validation are still required.

## Production receipt

`formal/nonce/PRODUCTION-EVIDENCE.json` is the pinned adoption receipt. The
ledger's `packet-nonce-functional-production` claim is validated by a typed
Python validator that recomputes every repository hash and checks the proof
counts, five control anchors, generation identity, `GENERATED.json` binding, the
central delivery manifest entry, the live/frozen `PacketKey` split, the JDK 21/25
run identities, the eight-test JUnit source, the separate executed bundle smoke
and explicit non-claims. The external replay report SHA-256 is recorded for
provenance only; the validator does not trust it or a receipt checksum as
evidence.

`formal/nonce/BundleNonceSmoke.java` is a separate adoption/artifact-gate harness.
It is **not** part of the frozen core proof closure. It is compiled into a
dedicated temporary directory and executed against the actual minimized bundle
plus the pinned Maven DafnyRuntime jar: it first calls `PacketKey.nonce`,
`seal` and `open` for all three suites and packet numbers 0, 1 and -1, compares
the nonce with an independent clone/XOR oracle and the ciphertext with fixed
digests from a separate JCE implementation, and only then asserts that
`PacketKey`/`VerifiedNonce` loaded from the bundle, `dafny.Helpers` from the
pinned runtime jar and the harness from its own directory. The TLS-only hybrid
handshake smoke does not assert nonce origins by name.

## Portable replay

The component tool configuration is host-neutral. `formal/nonce/tools.json`
pins only the reviewed Dafny build and Maven runtime checksum. The platform
archive, extracted tool tree, executable, solver and distribution runtime are
validated through the audited `formal/dafny/toolchain.py` against the pinned
`formal/dafny/tools.json`; the selected identities are recorded in each fresh
report. No macOS executable hash is used as a cross-platform expectation.

Fresh replay output lives outside the checkout under the operator-supplied
cache, by default `$HOME/.cache/microproxy-formal/nonce/portable-replay`.
The current receipt is self-binding: it records the selected tool asset,
archive/exe/solver/runtime/tree hashes, explicit JDK hashes, pinned inputs and
command logs. The report hash is not copied into this file, because doing so
would create a pin/replay cycle rather than add evidence.

The accepted macOS component replay (report SHA-256
`82062ab01fb067e95d441a859c85fb1892d04277affd87fa9f8d7bfab3082a59`) is
historical component evidence, not a fresh Linux CI pass. A new Linux replay is
required before that portability is claimed. The earlier historical isolated-component replay at
`$HOME/.cache/microproxy-formal/issue117-20261101/nonce/component-replay` with
report SHA-256
`41667f7126200a9b8df7b0bf54765512b6933e7b8f80fe61bb03ebec63809eec` is retained
unmodified as historical evidence. It is not a substitute for the portable
replay and is not treated as a fresh production-success claim.

## Pinned proof and generated identities

| Item | Value |
|---|---|
| Dafny build | `4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2` |
| Dafny release manifest | `formal/dafny/tools.json`, SHA-256 `d0400f892192bd2e603651aa36c9fed32394b5d0600955d4854c852df729f1c6` |
| macOS arm64 official archive | `3209da6998c98c10e15970b85f6aa27925682c3273cd41539348ab8f7941553e` |
| Linux x86_64 official archive | `697ee703b39414b3904dc8c132e51481982f52205c1658f3374d313a284d43eb` |
| Maven Dafny runtime | `dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6` |
| Kernel source before/after | `e83c9a7a448a4b7d982f7c54822f9af53cffe4d3808870ed04ddac0bd89f5c28` |
| Checked-in/fresh generated Java | `aabace51edf58e4aefd398717b674ccbf8c138517f95fbb843139c8aea61cc06` |
| `GENERATED.json` | `d5f9952e1cef30f12653b2705a080d280fbb2cbc68df212f631385c9b73e7783` |
| Translation metadata | `e65cce5ab0364a300dcebbb537648f87b9b02a13efe8c321fb731d2c341604e4` |
| Aggregator | `2f2f4830f31902d3df27cdbadbef565be301cc18c45b73539f35ba94d1c0f924` |
| Generated class | `64ba6bbcccba2bc0f519b60ba090e11cf164544e98e24e73cd4699f9481c7069` |

The source hash is checked before verification, after `--no-verify` generation
and at the end of the replay. The fresh generated package must be byte-identical
to the checked-in package and to `GENERATED.json`.

## Proof and trust result

| Check | Result |
|---|---|
| Kernel audit | `Dafny auditor completed with 0 findings` |
| Public-domain audit | `Dafny auditor completed with 0 findings` |
| Forbidden `assume`/`{:axiom}`/`{:extern}`/`{:verify false}`/`{:trusted}` | none in code in either Dafny file |
| Kernel `Nonce.dfy` | 337 verified, 0 errors |
| `NonceDomain.dfy` with included kernel | 343 verified, 0 errors |
| Controls | 5/5 rejected as actual proof obligations, no timeout/resource/parse evidence |

The kernel proves, for an arbitrary 12-byte IV and an unconstrained 64-bit
packet number: length 12, fresh output (`nonce != iv`), IV preservation,
unchanged four-byte prefix, exact big-endian last-eight XOR, whole-sequence
equality to `NonceBytes`, and injectivity for distinct packet-number patterns
under a fixed IV. Both scalar byte extraction (`Decompose`) and the array/spec
bridge are proved; there is no scalar-only claim.

Control failure anchors:

| Control | Observed result |
|---|---|
| wrong-endian | 333 verified, 4 errors; `assert nonce[4] == NonceBytes(old(iv[..]), pn)[4];` |
| counter-truncation | 333 verified, 4 errors; same byte-4 big-endian bridge |
| alias-freshness | 169 verified, 1 error; related `ensures nonce != iv` |
| input-preservation | 342 verified, 1 error; related `ensures iv[..] == old(iv[..])` |
| counter-truncation-injectivity | 332 verified, 5 errors; related `ensures p == ((B7(p) as bv64) << 56)` |

## Runner controls and explicit inputs

Before any proof, the runner validates the host-neutral tools schema/version/
runtime pin, the explicit Maven runtime checksum, and exactly two explicit JDK
homes: one JDK 21 canonical compiler and one JDK 25 runtime. Duplicate homes,
missing homes, duplicate/other major sets and wrong runtimes are rejected
before the proof phases. Version probes are limited to those explicit homes.
After the run, the runner revalidates the pinned inputs, kernel source hash,
Maven runtime, official Dafny tool tree and explicit JDK binaries.

`formal/nonce/test_run.py` contains small fail-closed unit fixtures for wrong
runtime, tool asset/archive/runtime binding, duplicate JDK majors, duplicate or
missing homes, and host-neutral configuration. These are runner-control tests,
not proof evidence.

The pinned input closure is explicit: the Dafny sources, replay runner and unit
controls, fixed Maven runtime pin, generated receipt/source, frozen Java oracle
and test harness, nonce benchmark driver/script, and the shared audited Dafny
toolchain files. Development prototypes and the separate PacketKey benchmark
are not part of this closure. Root may add separate delivery tooling outside
it.

## Java checks

| Check | Result |
|---|---|
| Generated signature | `public static byte[] Nonce(byte[] iv, long pn)`; descriptor `([BJ)[B` |
| Sequence/select payload | none |
| Per-payload-byte boxing | none; one cached `Byte.valueOf(0)` for the fresh-array initializer |
| Runtime/helper calls | 7 `bv64ShiftRight`, 21 `BigInteger.valueOf`, 25 `Helpers.toInt` in this pinned bytecode |
| Strict compile | `javac --release 21 -Werror -Xlint:all,-serial,-cast,-rawtypes`, no diagnostics |
| JDK 21 test | `NONCE-TEST-OK cases=10 assertions=162774` |
| JDK 25 test | `NONCE-TEST-OK cases=10 assertions=162774` |

`cases=10` counts ten test **groups**, not ten input cases. `assertions=162774`
counts differential `check()` calls. The frozen harness is not edited to rename
the label. Functional coverage includes known vectors, all 64 single-bit packet
numbers, all 256 values in each of eight packet-number lanes, all 256 values in
each of twelve IV positions, 10,000 deterministic random pairs,
negative/high-bit patterns, distinct contents, freshness, IV preservation and
output independence.

## Diagnostic performance

The isolated old-vs-new benchmark was not rerun for this portability change
because the nonce math, generated Java and benchmark code were unchanged. The
historical macOS arm64 receipt remains diagnostic only. It reported roughly
11-15 ns extra per nonce with identical 32-byte allocation and paired CPU ratios
of 3.73x on JDK 21 and 2.35x on JDK 25 for the isolated primitive. Those ratios
are not a full packet or handshake prediction and no constant-time,
side-channel, throughput or capacity claim follows.

## What is not claimed

No AEAD/PRF security, crypto hardness, JVM/JIT/GC/CPU timing, constant-time
execution, secret erasure, compiler/runtime correctness, production JAR byte
identity, historical SAW nonce bytecode proof, Maven/canonical pipeline or full
handshake performance is proved here. The production adoption is the narrow
functional nonce primitive and its PacketKey delegation; Linux CI portability is
implemented, but no Linux live pass is claimed until CI actually runs it.
Dafny/Boogie/Z3, the Dafny Java compiler/runtime, `javac`, the JVM and the frozen
reference oracle are trusted. A fresh canonical stage and actual-artifact
class/JAR/bundle checks remain pending.
