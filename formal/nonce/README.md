# Verified QUIC nonce primitive

This component specifies, verifies and generates the QUIC packet-number nonce.
`PacketKey.nonce` delegates to `VerifiedNonce.__default.Nonce`; the central
`formal/crypto/delivery.json` inventory pins its generated source. The
`packet-nonce-functional-production` claim covers this reviewed functional and
generation connection, with documented compiler/runtime and facade assumptions.
A normal Maven build compiles and packages it; no POM generation hook was added.

The reviewed local artifact build covers 468 library classes, 84 crypto classes
and 468 retained library classes. Current-artifact acceptance separately requires
the actual-input class/JAR/bundle gate, including execution with the bundled
runtime on JDK 21/25. The nonce CI job replays proof, controls and generation on
Linux; the committed component evidence records its reviewed macOS snapshot.
Neither a static component receipt nor a local artifact snapshot certifies a
later release or deployment. This component does not prove the historical SAW
bytecode route, cryptographic hardness or JVM timing.

The component owns exactly:

| Role | Location |
|---|---|
| Dafny kernel | `formal/nonce/Nonce.dfy` |
| Universal public-domain harness | `formal/nonce/NonceDomain.dfy` |
| Bounded replay / negative controls / Java tests | `formal/nonce/run.py` |
| Isolated old-vs-new benchmark | `formal/nonce/bench_nonce.py` |
| Frozen independent test oracle | `formal/nonce/java/io/github/mahmoudimus/nonce/ReferenceNonce.java` |
| Differential test harness | `formal/nonce/java/io/github/mahmoudimus/nonce/GeneratedNonceTest.java` |
| Benchmark driver | `formal/nonce/bench/NonceBenchmark.java` |
| Executed bundle nonce/seal/open smoke | `formal/nonce/BundleNonceSmoke.java` |
| Pins and generated receipt | `formal/nonce/tools.json`, `inputs.json`, `GENERATED.json` |
| Production adoption receipt | `formal/nonce/PRODUCTION-EVIDENCE.json` |
| Generated production package | `quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/VerifiedNonce/` |

This component's replay does not edit `PacketKey`, the POM, delivery
manifests, the ledger, CI or shared documentation. Any PacketKey bridge and
its tests/benchmarks belong to the separate integration workstream; root owns
the final artifact inventory.

## Exact domain and behavior

The verified operation is the old `PacketKey.nonce` byte-for-byte:

* Input `iv` is a 12-byte array. `iv.Length == 12` is the only caller
  precondition, matching the `PacketKey` constructor check.
* Input `pn` is a full `bv64`. There is **no packet-number precondition and no
  62-bit narrowing**. All 2^64 bit patterns are in the domain, including
  patterns whose sign bit is set (negative Java `long` values).
* The result is a **fresh** 12-byte array; it is not the input IV.
* The first four output bytes equal the first four IV bytes.
* For `j = 0..7`, output byte `4+j` is `iv[4+j] XOR` the big-endian byte `j`
  of `pn` (most significant packet-number byte first).
* The caller's IV is unchanged.
* Under one fixed IV, distinct 64-bit packet-number patterns produce distinct
  12-byte nonce contents. The four unchanged prefix bytes carry no packet-number
  information; the eight XORed bytes determine it.

This is a primitive functional proof, not a QUIC protocol policy statement.
The 62-bit packet-number limit remains a connection-level policy, as before.

## Proof structure

`B0(pn)` through `B7(pn)` are ghost specification functions for the eight
big-endian bytes. `PacketNumberBytes` is the eight-byte mathematical encoding
and `NonceBytes` is the complete 12-byte result. The executable method uses
primitive `long` shifts, masks and `bv8` casts for the same bytes; bridge
assertions prove each executable byte equals its ghost `Bk`. This is deliberate:
the production method reads and writes `byte[]` directly and generated Java has
no `DafnySequence` or `select` payload path.

Proved lemmas:

| Lemma | Property |
|---|---|
| `XorCancel` | XOR with a fixed byte is cancellative |
| `Decompose` | The eight big-endian bytes reconstruct the whole `bv64` |
| `PacketNumberBytesInjective` | Equal big-endian bytes imply equal packet numbers |
| `NonceBytesInjective` | Equal 12-byte nonce sequences under one IV imply equal packet numbers |
| `NonceBytesDistinct` | Distinct packet numbers give distinct nonce sequences |
| `NonceContentsInjective` | Two fresh equal-content output arrays under one IV imply equal packet numbers |

The `Nonce` postcondition is elementwise for all 12 bytes as well as a
whole-sequence equality to `NonceBytes(old(iv[..]), pn)`, plus length,
freshness and input preservation. There is no scalar-pack-only gap: every
output element is proved, the array frame is proved, and the array-to-spec
bridge is explicit. `NonceDomain.dfy` quantifies over an unconstrained `pn` and
an arbitrary 12-byte IV, exercising every packet-number pattern, the array
freshness/preservation properties, and array-content injectivity.

`{:isolate_assertions}` on `Nonce` and `NonceBytesInjective` is a solver
granularity choice only: every assertion is still verified. It is not a trust
assumption or a proof shortcut. The initial combined array/sequence VCs hit the
10M resource limit; the fix is the repository's existing per-declaration
`{:isolate_assertions}` pattern (compare `NativeCodec.Extract`) plus explicit
per-byte bridge assertions, not a waived obligation. No timeout or resource
exhaustion is accepted as proof evidence.

## Trust and non-claims

The kernel has **no** `assume`, `{:axiom}`, `{:extern}`, `{:verify false}` or
other trusted declaration. The replay runs `dafny audit` separately on
`Nonce.dfy` and `NonceDomain.dfy` and requires `Dafny auditor completed with 0
findings` for both; it also strips comments and scans both files for forbidden
constructs. `--no-verify` is used for translation only after a fresh,
successful, bounded proof of the **same frozen source**; the source hash is
checked before verification, after generation and at the end of the replay.

Trusted without proof: Dafny/Boogie/Z3, the Dafny Java compiler and runtime,
`javac`, the JVM/JIT/GC/CPU, the frozen test oracle, and local OS/archive
extraction. The SHA-256 pins and the archive verifier are drift gates, not
independently signed release attestations. Not proved: AEAD
security, crypto hardness, JVM timing, constant-time execution, side channels,
secret erasure, compiler/runtime correctness, production JAR byte identity, or
PacketKey/protocol integration. No claim is made that the generated code is
constant-time.

## Negative proof controls

`run.py` creates five mutants in a private replay directory and verifies each
with the same bounded flags. A control is accepted only when Dafny exits with a
verification error (`4`), the summary has errors, no timeout/resource/parse/
resolution/internal error appears, and the intended source location is reported.
Timeout, `out of resource`, unresolved names and parser crashes are never
accepted as negative evidence.

| Mutant | Intended failure |
|---|---|
| `wrong-endian` | Little-endian body contradicts the big-endian byte-4 bridge assertion (`assert nonce[4] == NonceBytes(...)[4]`) |
| `counter-truncation` | Masking the packet number to 32 bits fails the high-byte big-endian bridge assertion |
| `alias-freshness` | Returning the IV as the nonce fails `ensures nonce != iv` (reported related location) |
| `input-preservation` | Mutating one caller IV byte fails `ensures iv[..] == old(iv[..])` |
| `counter-truncation-injectivity` | Dropping the high four packet-number bytes makes `Decompose` fail (`ensures p == ((B7(p) as bv64) << 56) ...`) |

The last control specifically shows that the injectivity theorem is
load-bearing: a truncating specification cannot reconstruct, hence cannot
distinguish, packet numbers that differ only in the dropped bytes.

## Replay

The tool configuration is host-neutral. `formal/nonce/tools.json` pins only the
reviewed Dafny build and Maven runtime checksum. The selected Dafny executable,
solver and distribution runtime are derived from the official platform archive
already pinned in `formal/dafny/tools.json` and are recorded in the report; no
macOS executable hash is checked in as a cross-platform expectation.

`run.py` requires two explicit JDK homes, one JDK 21 canonical compiler and one
JDK 25 runtime. `--java-home` may be repeated; `--extra-java-home` remains as a
legacy alias. Passing the same home twice, omitting a major, or passing any
other major set is rejected before the proof steps. Version probes run only on
those explicit homes. `--runtime` defaults to
`$HOME/.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar`,
`--cache` defaults to `$HOME/.cache/microproxy-formal`, and `--output` defaults
to `$HOME/.cache/microproxy-formal/nonce/portable-replay`. All can be
overridden explicitly:

```sh
python3 formal/nonce/run.py \
  --cache "$HOME/.cache/microproxy-formal" \
  --runtime "$HOME/.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar" \
  --java-home "$JAVA21_HOME" \
  --java-home "$JAVA25_HOME" \
  --output "$HOME/.cache/microproxy-formal/nonce/portable-replay"
```

For Linux CI, expose the JDK 21 and JDK 25 homes installed by the CI Java
setup explicitly, keep `--cache` on persistent runner storage, and run the same
command (optionally with `--skip-benchmark`). The reviewed
`formal/dafny/toolchain.py` selects the pinned Linux archive from
`formal/dafny/tools.json`; the runner does not use a host-specific binary pin.
This is a portable configuration, not a claim that Linux CI has already passed.

The pin inventory also covers the reviewed read-only
`formal/dafny/toolchain.py`/`tools.json` cache verifier; those shared files were
not modified. The runner:

1. validates the host-neutral nonce tools schema/version/runtime pin, then
   verifies the explicit core replay input closure before and after;
2. rejects a wrong runtime checksum, duplicate JDK homes, missing homes,
   missing JDK majors or any major set other than exactly one 21 and one 25
   before running a proof;
3. installs/validates the official platform archive through the audited
   `formal/dafny/toolchain.py`, which checks the archive checksum and every
   extracted file and runtime against the pinned `formal/dafny/tools.json`;
4. records the selected asset, archive, Dafny executable, solver binaries,
   distribution runtime, distribution tree digest and explicit JDK hashes;
5. audits `Nonce.dfy` and `NonceDomain.dfy` (0 findings each) and proves the
   kernel (337 verified assertions) and public domain with included files
   (343 verified assertions);
6. runs and checks all five negative controls;
7. translates the same frozen source with `--no-verify`, bounded by a 180 s
   process timeout, and requires the checked-in package to be byte-identical to
   the fresh output and to `GENERATED.json`;
8. compiles generated and test sources with `javac --release 21`, `-Werror` and
   strict lint, then runs the differential tests on JDK 21 and JDK 25;
9. inspects the generated source and `javap` bytecode for a raw
   `byte[] Nonce(byte[], long)` signature, sequence/select paths and per-byte
   boxing;
10. optionally runs the isolated benchmark, then revalidates the pinned inputs,
    source hash, Maven runtime, official Dafny tool tree and explicit JDK
    binaries;
11. writes `report.json` as `complete` only if every step succeeds. A failed or
    interrupted replay leaves `failed`/`incomplete`, never a stale success.

The explicit input closure is the proof/generation/test dependency set, not
every file under `formal/nonce`. Development prototypes and the separate
PacketKey benchmark are not silently promoted into the proof inputs; root may
add other delivery tooling such as `formal/nonce/deliver.py` outside this
closure. `formal/nonce/test_run.py` is pinned because its fail-closed runner
controls are part of the reviewed component.

The generated receipt is checked, not rewritten. To renew it after a reviewed
source/compiler change, run the replay and inspect the fresh generated package
in the replay workspace (the run will stop at the receipt/package drift check,
which is the intended review gate). If the new output is approved, copy the
fresh generated package verbatim, update `GENERATED.json` from the fresh
`generated_java`/`top_level_aggregator_sha256` values, and renew `inputs.json`.
Never hand-edit generated Java.

The benchmark can be replayed independently:

```sh
python3 formal/nonce/bench_nonce.py \
  --java-home "$JAVA21_HOME" \
  --extra-java-home "$JAVA25_HOME" \
  --runtime "$HOME/.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar" \
  --output "$HOME/.cache/microproxy-formal/nonce/benchmark.json"
```

## Generated Java boundary

The checked-in class is fresh compiler output, not a post-processed or
hand-edited file. Its public entry point is:

```java
public static byte[] Nonce(byte[] iv, long pn)
```

The source and bytecode inspection records:

* zero `DafnySequence` and zero `select`/boxed-payload paths;
* one `Byte.valueOf` in bytecode, used only for the cached zero in Dafny's
  fresh-array initializer; it is not per payload byte;
* primitive `baload`, `bastore`, `ixor` and `i2b` for the twelve bytes;
* seven `dafny.Helpers.bv64ShiftRight` helper calls and constant
  `BigInteger.valueOf`/`Helpers.toInt` array-index calls (21 and 25
  occurrences in this pinned output). These are compiler/runtime overhead, not
  secret-byte boxing, and are reported rather than hidden.

The generated class adds no new dependency: it uses the already-present
`DafnyRuntime` (mostly `TypeDescriptor` and `Helpers`). No POM change was made.
Because it lives under `quic/src/main/java`, Maven will compile and package it
whether or not `PacketKey` delegates to it. That makes it an artifact addition,
not an unchanged artifact. Exact class hashes are recorded in `report.json`;
production JAR/Maven acceptance and integration into the central delivery
manifests remain root-owned and are **not** claimed here.

## Differential and compatibility tests

`GeneratedNonceTest` compares the generated class against the frozen
pre-adoption clone/XOR oracle and independently computed vectors:

* 10 known vectors, including `0`, `1`, `Long.MAX_VALUE`, `Long.MIN_VALUE`,
  `-1`, and a high-byte pattern;
* all 64 single-bit packet numbers, with 64 distinct output contents;
* all 256 values in each of the eight packet-number byte lanes;
* all 256 values in each of the twelve IV byte positions;
* 10,000 deterministic random IV/packet-number pairs;
* 16 negative/high-bit packet-number patterns;
* 1,024 adjacent packet numbers plus seven distinct high patterns, all with
  distinct contents;
* all-zero and all-`0xff` IVs;
* fresh output, input preservation, output independence, and big-endian byte
  placement.

The two pinned JDKs each report `NONCE-TEST-OK cases=10 assertions=162774`.
The frozen harness prints `cases` for ten test **groups**, not ten input cases;
the functional coverage is the much larger list above. `assertions` is the
number of differential `check()` calls. The harness is not edited to rename
the label.

## Measured cost

`bench_nonce.py` measures one nonce construction with two warmup rounds, five
sampled rounds, five fresh forks per mode per JDK, alternating order, a
2 GiB heap, and a volatile array-escape store every 64 iterations. The primary
metric is thread CPU time; wall clock and per-thread allocation are also
recorded. The values below are from the 2026-11-01 replay on macOS arm64. They
are diagnostic, host-specific and **not** a constant-time, side-channel or
capacity claim.

| JDK | old CPU ns/op | new CPU ns/op | paired CPU ratio (median, range) | allocation old/new |
|---|---:|---:|---|---:|
| 21.0.12.1 | 6.01 | 21.36 | 3.73x [3.32, 3.82] | 32 B / 32 B |
| 25.0.5 | 8.16 | 19.29 | 2.35x [2.31, 2.40] | 32 B / 32 B |

The absolute generated overhead was about 11-15 ns per nonce in this run;
allocation is identical because both implementations allocate one 12-byte
array. Absolute timings and ratios vary with shared-host/JIT conditions; the
structured receipt is the authoritative sample. The bytecode
inspection shows constant `BigInteger`/`toInt` array-index helpers and a generic
fresh-array initializer; this benchmark does not isolate their individual
contributions. It is not per-byte boxing or a sequence payload. This is a real
per-packet component cost and root must weigh it in the full-handshake benchmark
and adoption decision. No constant-time conclusion follows from these
measurements.

## Integration notes for root

The functional production adoption is recorded: central generated-source
inventory, 468/84/468 class counts, bundle smoke roots for `PacketKey` and the
generated nonce, the `packet-nonce-functional-production` ledger claim and the
CI nonce job. Remaining work is evidence-bound, not a new design: run the fresh
canonical stage and the actual-artifact class/JAR/bundle validation for the
built artifacts, let the Linux nonce job produce a live pass, and run the full
Maven/JDK21/25 acceptance. The full handshake/capacity decision remains root's.
The POM already supplies `DafnyRuntime:4.9.1`; no dependency change is expected.
