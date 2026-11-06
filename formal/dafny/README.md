# Verified HKDF with generated Java

This is the isolated proof and production-adoption route for RFC 5869 HKDF and
the RFC 8446 `HKDF-Expand-Label` surface used by QUIC. The verified kernel is
`hkdf/Hkdf.dfy`. Pinned Dafny 4.9.1 translates it into the committed production
package `io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf`;
`quic.Hkdf` delegates to that package through the reviewed handwritten
`HkdfBridge` and JCE boundary `JdkHmac`. The full replay separately verifies the
kernel, audits the sole external assumption and rejects negative controls. Its
Java preflight translates the same authenticated frozen source with
`--no-verify`, requires byte equality with the committed package, compiles the
real production facade and tests it with JCE. Translation alone earns no proof
credit; a complete receipt requires the full proof phase and final input/tool
checks to pass.

The current functional and trace checks use the same authenticated eight-root
engine. `formal/dafny/run.py` is its compatibility entry point. Select Python
3.11+, both JDKs, the pinned Dafny/runtime and SDK/offline packs explicitly; the
[source replay guide](../source/hkdf/README.md) describes those inputs.

The direct replay rejects Python's `-O` and `-OO` modes. Proof admission,
helper integrity and process ownership checks use explicit exceptions that remain
active under optimization.

On Ubuntu 24.04, install `libicu74` for the bundled .NET runtime first. The runner
requires the standard POSIX `ps` utility for cancellation cleanup.

```sh
python3 -m unittest discover -s formal/dafny -p 'test_run.py' -v
python3 -I -B -m unittest discover -s formal/source/hkdf -p 'test*.py' -v
python3 -I -B formal/dafny/run.py \
  --manifest "$REPO/formal/source/hkdf/inputs-v2.json" \
  --expected-manifest "$HKDF_INPUTS_SHA256" \
  --profile macos-sdk10.0.400 \
  --dafny "$DAFNY" --dotnet "$DOTNET" \
  --targeting-packs "$OFFLINE_NET6_PACKS" --runtime "$DAFNY_RUNTIME_JAR" \
  --jdk21 "$JDK21" --jdk25 "$JDK25" --output "$FRESH_ABSOLUTE_OUTPUT"
# Isolated old-vs-new key-schedule measurement (writes only a private temp tree):
python3 formal/dafny/bench_hkdf.py --output /tmp/hkdf-benchmark.json
```

The Linux profile is `linux-sdk10.0.400`. Current replay uses caller-supplied,
authenticated tools; it does not restore packages through ambient NuGet settings.
The legacy generation utility retains its pinned Dafny cache and `tools.json`.
Its archive pins identify the official HTTPS downloads used here, not
independently signed release attestations. Local OS/tool execution remains
trusted; no global toolchain is changed.

The selected fresh output contains `report.json`, actual logs, input/tool maps,
generated/class identities and runtime results. Full success also produces
`SOURCE-EVIDENCE-v2.json`; a preflight or incomplete run cannot export a complete
receipt. Current output must be new and disjoint from input/tool roots. Commands
have bounded timeouts, raw exit records and owned-process cancellation cleanup.
Generated code is recreated in a fresh replay directory and compared byte for byte
with the committed production package, never hand-edited. CI uploads the report
for inspection. Source pins are drift gates, not semantic proofs or review
signatures. Current input authority is the externally selected `inputs-v2.json`;
the old manifest and receipts retain their historical subjects.

## Production adoption

| Role | Exact location |
|---|---|
| Generated implementation | `quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/` |
| Translation namespace | `io.github.mahmoudimus.quic.internal.verifiedhkdf`, module `VerifiedHkdf`, output `HkdfCrypto` |
| Reviewed value/error adapter | `io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge` |
| Reviewed JCE boundary | `io.github.mahmoudimus.verifiedcrypto.JdkHmac.compute` (the kernel's extern target) |
| Public API preserved | `io.github.mahmoudimus.quic.Hkdf` (`SHA256`, `SHA384`, `hashLength`, `extract`, `expand`, `expandLabel`, package-private `labelInfo`) |
| Generated receipt | `hkdf/GENERATED.json` (source, class, aggregator and translation-metadata hashes) |

`run.py` uses `--outer-module` during translation, so the committed package is
fresh compiler output rather than a post-processed copy. It requires the committed
package to match that output exactly and compiles the production `Hkdf`,
`HkdfBridge`, `JdkHmac` and generated classes together. `deliver_hkdf.py` is the
current check entry point: `--check`, including optional `--jar`, forwards to the
same full engine and requires the same explicit authority/tool arguments. Its
12-class JAR check supplements whole-library/bundle validation. Deliberate local
generation uses the separate `--legacy-update-only --update` utility with an
externally selected current manifest. It prints exact source changes for review
and renews no current proof receipt or historical input manifest. It never updates
the SHAKE/ML-KEM namespace.

Production source does not depend on `formal/` at runtime. The frozen
`formal/dafny/java/.../ReferenceHkdf.java` is a test-only oracle copied from the
pre-adoption implementation; it is never compiled into the production artifact.
This keeps the formal differential non-circular now that production delegates to
the generated kernel.

The generated package is outside the NativeCrypto generated namespace.
`formal/crypto/delivery.json` pins its nine generated sources and includes
`JdkHmac` as an ordered `existing_generated_dependency`. `HkdfBridge`, `Hkdf`
and `JdkHmac` remain under handwritten-source checks. Source changes require
fresh generated-source, canonical-class and actual-JAR qualification; an earlier
artifact receipt does not qualify a changed build. The POM provides
`DafnyRuntime:4.9.1`.

## Functional proof and domain

The four sequence operations have no caller preconditions. They return `Success` or a
named validation failure, with exact equality to total result specifications.
The positive-domain harness invokes every method on unconstrained mathematical
inputs and proves these equations. Adding a reject-all precondition breaks that
check. Verification includes termination and loop invariants.

| Operation | Proved behavior relative to abstract HMAC |
|---|---|
| Extract | SHA-256/384/512 selection; empty salt becomes HashLen zero octets; exact HMAC result, including empty IKM |
| Expand | Every nonempty PRK; exact RFC 5869 feedback, one-byte counters 1..255, concatenation and truncation; output length 0..255*HashLen |
| LabelInfo | Exact TLS label serialization; uint16 length 0..65535; label up to 249 UTF-16 units, each ASCII; context up to 255 octets |
| ExpandLabel | Composition of label validation/serialization and Expand, including error precedence and bounds |

Two compatibility extensions match the existing Java helper: Expand accepts
nonempty PRKs shorter than HashLen (RFC 5869 specifies at least HashLen), and
LabelInfo accepts an empty suffix label (RFC 8446 requires a nonempty suffix).
These API contracts do not assert that every accepted input is a valid protocol
call. Sequences/integers are mathematical: finite Java heap, allocation failure,
JVM limits and concurrent mutation of caller input arrays are outside the proof.

Production input arrays enter through generated `ExtractArrays`, `ExpandArrays`
and `LabelInfoArray`, which compose the same operations with generated
`CopyInput`. The copy contract returns the entry-state sequence and preserves
the input array. The array harness proves saved snapshots survive subsequent
writes, including calls with aliased inputs; it adds no disjointness precondition.
This moves the input-snapshot algorithm into executable Dafny. The compiler and
runtime implementation of sequence creation remains trusted, as do the remaining
Java value/error adapters. See the
[source-observation replay](../source/hkdf/README.md) for the separate trace,
coverage, adversarial-control and Java-erasure gates.

Negative controls alter feedback, counter, truncation and label prefix. They must
fail actual proof obligations; parsing failures, resource limits, timeouts and
crashes are rejected as evidence. Additional controls narrow a public precondition,
add a trusted axiom, or skip a method proof. Java adapter controls compile
deliberate old `select`-loop, bare-cast and dead-method-decoy mutants of
`JdkHmac`/`HkdfBridge` and require the structural gate to reject every one. The
separate Dafny audit must report exactly the
permitted `VerifiedHkdf.Mac` axiom. The auditor itself does not verify programs;
the runner separately requires completed proof summaries.

The recurrence/invariant approach is credited to the pinned
[AWS HKDF reference](https://github.com/aws/aws-cryptographic-material-providers-library/blob/c787ad12612ac0f35975afe9209e5dbe6b546654/AwsCryptographyPrimitives/src/HKDF/HKDF.dfy).
Our standalone proof has no AWS includes. We have verified the complete local
kernel; we have not replayed the full upstream MPL dependency/submodule graph.
AWS provenance applies to reused HKDF structure; it does not limit the wider
Dafny program to AWS algorithms. See `NOTICE`.

## Java boundary and trust

The sole Dafny assumption is a deterministic external `Mac` implementing the
requested HMAC and returning HashLen bytes for a nonempty key. `JdkHmac` creates
a fresh `javax.crypto.Mac` for every block, so the kernel's feedback loop never
depends on provider `doFinal` reset state. The bridge copies octets without
signed-byte loss, preserves all UTF-16 bits before ASCII validation, maps kernel
failures to the historical `quic.Hkdf` exception surface, and returns fresh arrays.
Input octet snapshots now execute in generated `CopyInput`; the removed
handwritten `HkdfBridge.sequence` helper's bytecode receipts remain historical.
The remaining Java adapters are reviewed and tested, not proved by Dafny.

Production payload bytes are copied with `DafnySequence.toRawArray()` and a
required primitive `byte[]` result. The pinned runtime's `ArrayDafnySequence`
clones its primitive backing array in `toArray()`, while a forced
`ConcatDafnySequence` uses the `ArrayDafnySequence` copier with
`System.arraycopy`; neither payload path calls `select`/`Byte.valueOf`. The
`check_adapter_discipline.py` gate parses the actual compiled method bodies,
rejects either operation in `JdkHmac`/`HkdfBridge`, requires
`JdkHmac.bytes` itself to contain `toRawArray`, a real `instanceof [B`, a
conditional guard, `checkcast [B` and `areturn` (a dead method or bare cast does
not satisfy it), and requires `HkdfBridge.bytes` to delegate to
`JdkHmac.bytes`. The adapters never call `select` on secret byte payloads.
Generated `LabelInfo` still selects public 16-bit label units; labels are public
protocol data, and that generated code is outside this gate. This is a gate on
the owned conversion path and the reviewed runtime ABI, not a call-graph, JVM
constant-time or memory-noninterference proof.

The production facade preserves the previous API and its principal compatibility
behavior: SHA-256/384, empty-salt normalization, empty labels, short and long
nonempty PRKs, zero-length output, 249-unit labels, 255-octet contexts, bounds and
exception classes/messages for length and key failures. As before, a null IKM or
info was silently treated as empty by JCE and remains so; the facade now makes
that choice explicit. A null salt/label/context is a `NullPointerException`; a
null PRK keeps the historical `IllegalArgumentException`. Null-plus-invalid-length
precedence for label/context can differ because the facade checks nulls first;
this difference is documented; the normal null cases are covered by regression tests.

The suite contains RFC 5869/9001 answers, independently derived SHA-384/512 answers,
deterministic comparison with the frozen pre-adoption HKDF, boundary/invalid inputs,
high-bit octets, Unicode/surrogate rejection, ownership, repeated and concurrent
calls, and a `BulkOnlySequence` negative control whose element access throws while
the primitive bulk path succeeds. The replay also inspects the actual compiled
adapter bodies and compiles old select-loop, bare-cast and dead-method-decoy
mutants as controls. Those finite
checks help detect translation/adapter bugs; they do not prove the compiler, JDK,
JCE provider, all Java input lengths or concurrency semantics.

Trust includes Dafny/Boogie/Z3, source specifications and their standards review,
Dafny's Java compiler/runtime, `javac`, JVM and the JCE/provider implementation.
See the [Dafny reference](https://dafny.org/v4.9.1/DafnyRef/DafnyRef).
The separate source component proves equality of its declared logical
observations under equal public inputs. Its resolved-AST coverage checker remains
trusted tooling. No PRF/entropy security reduction, HotSpot/GC/CPU timing proof,
secret-erasure guarantee or whole-crypto trace proof follows from these results.
The generated runtime allocates and copies secret-bearing values; `bench_hkdf.py`
measures the cost on one host only, and JVM timing remains explicitly outside the
proof. Existing fingerprints and APIs remain covered by the QUIC regression suite.

## Measured cost

The measurements below precede the generated array-input route. They are retained
historical component measurements, not qualification of that route's performance.
Changed generated classes require a fresh component and full-handshake comparison.

`bench_hkdf.py` compiles the frozen reference and the generated production facade
into private temporary class directories and runs fresh JVMs alternating mode
order. The workload is a TLS 1.3-shaped key schedule (3 Extract + 21
Expand-Label, including QUIC key/iv/hp) per iteration. The primary metric is
thread CPU time; wall clock and per-thread allocation are also recorded. These
are component measurements on one shared host, not handshake throughput or
capacity claims, and JVM timing remains outside the proof.

On macOS arm64 / JDK 21.0.12.1 with a 2 GiB heap and 5 forks, the post-fix
**generated-vs-ReferenceHkdf** paired CPU ratio median was **2.31x for SHA-256**
(observed range 2.23-2.45x) and **1.92x for SHA-384** (1.71-2.26x). Median CPU
cost per schedule moved from 10.7 (reference) to 24.6 (generated) microseconds
for SHA-256 and 15.7 to 30.7 microseconds for SHA-384.
Allocation moved from about 27-35 kB to 128-137 kB per schedule (roughly 4-5x);
the bulk-copy path clones primitive arrays rather than boxing each byte, so CPU
improved while allocation did not fall. The earlier boxed/select implementation
measured about 3.0-3.6x CPU versus `ReferenceHkdf` in a **separate earlier run**;
that is a diagnostic of the old boxed generated adapter, not a paired
pre-fix/post-fix measurement or a speedup claim. Root must rerun the complete
handshake benchmark on the post-fix classes. Shared-host/JIT/GC variation remains.
The extra CPU is small relative to a
complete handshake, but the allocation delta is not negligible and should be
confirmed by the full-handshake benchmark.
