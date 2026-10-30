# Production crypto delivery evidence

The [full stage](stage-receipt.json) verifies all 18 modules in the final include
graph, audits four declarations for two trusted SHA3 primitives, and generates
Java without rewriting compiler output. Its SHA256 is
`285d7adf775f0f340a820b2a7f4895f5b23d8035785fd4dd28c2324632a17d40`.
The [identity check](measured-stage-identity.json) establishes exact equality of
all 66 generated/provider Java sources, 66 canonical classes and four freshly
compiled facade classes with the compatibility/performance candidate. The
[canonical runtime inspection](canonical-runtime.json) applies the reviewed
native discipline guard to the namespaced stage classes; actual Maven artifact
acceptance is recorded in the [local artifact receipt](ACCEPTANCE.json): all 456
main classes and JAR class entries match exactly, including debug attributes,
and the existing runtime guard passes on the actual final Maven classes.

The [approval](approval.json) separates the user's prior conditional
[authorization](prior-user-authorization.json) from the agent's later evaluation
of this exact stage. It does not claim that the user reviewed a future artifact.
Its performance decision accepts the measured costs of the selected proof route;
it does not authorize a merge or release.

## Compatibility and performance

[Kernel/compatibility measurements](performance-compatibility.json) and the
[original diagnostic receipt](measured-candidate.json) preserve the raw evidence:
13 Java boundary tests on each JDK, including the Go 100/10,000 accumulators,
invalid inputs, segmented SHAKE, ownership and cleanup. `FacadeCompatibility.java`
is the exact driver used for those tests. The historical `stage_status` in that
measurement file describes its earlier proof-receipt hold; it is not the final
stage status. Historical Dafny source/runner pins differ by reviewed proof-only
changes. Reuse depends on the exact generated-source and class identity above.

[Final hybrid measurements](hybrid-performance.json) use the existing
`Handshakes` fixture, identical seeded certificates/configuration and frozen class
overlays. Every iteration checks certificate/Finished agreement, negotiation of
X25519MLKEM768, absence of retry/resumption at both endpoints, and bidirectional
1-RTT application data using the derived AEAD keys. Each backend/JDK has three
fresh JVM forks, 512 warmup handshakes and nine batches of 32 measured handshakes
per fork. Both endpoints execute on the measured main thread. Values below are
medians of the fork medians on macOS ARM64; shared-host, JIT and GC variation
remains possible.

| Runtime | Full handshakes/s, baseline -> generated | CPU ms/handshake | Allocated kB/handshake |
|---|---:|---:|---:|
| JDK 21.0.12.1 | 495.3 -> 362.7 | 1.998 -> 2.435 | 467.3 -> 604.3 |
| JDK 25.0.5 | 421.0 -> 365.1 | 2.179 -> 2.636 | 451.3 -> 588.6 |

Generated execution costs about 21-22% more CPU (0.44-0.46 ms per complete
handshake), allocates about 29-30% more, and has 13-27% lower observed throughput
here. These are complete in-memory TLS handshakes, not network-capacity
measurements or side-channel evidence. The [performance review](performance-review.json)
records the agent's accepted tradeoff. `hybrid-performance-initial.json` retains
the earlier run as provisional lineage; the table and decision use the final
harness with explicit nonresumption assertions.

Kernel CPU medians are about 0.325-0.387 ms for generated keygen/encapsulation
versus 0.185-0.201 ms before adoption, and 0.168-0.191 ms for decapsulation versus
0.122-0.126 ms. Generated operations allocate roughly 93-120 kB versus 51-72 kB.
The uncompressed crypto class-file footprint grows from 23,471 bytes to 250,562
bytes (generated/provider classes plus facades). The separately pinned Maven
DafnyRuntime JAR is 159,922 bytes. These are component sizes, not a whole-JAR delta.

`hybrid_benchmark.py` freezes and checks class/source/JDK/runtime inputs, checks
loaded class origins, rejects a wrong-origin control, and records every fork and
sample. It accepts a prepared diagnostic candidate containing the pinned
baseline, facade and generated class directories plus diagnostic JSON records.
The final run used freshly produced final-stage classes and freshly compiled
facades, after the identity check, rather than an unverified new compilation.

## Maven and minimized bundle checks

The full ordinary [JDK 21 suite](maven21-receipt.json) and
[JDK 25 suite](maven25-receipt.json) passed, including the SIMD execution. Local
optional Python peers/live tests may skip; remote CI enforces its required peer
matrix separately on the exact pushed head.

The actual minimized `microproxy-starlark-0.6.0-all.jar` additionally passes
complete hybrid handshake/application-data smokes under
[JDK 21](fatjar-jdk21-receipt.json) and [JDK 25](fatjar-jdk25-receipt.json).
Class-load logs show both facades, generated/provider classes, and the actual
`dafny.Helpers`/`TypeDescriptor` loaded only from that JAR. External classpaths
contain only the frozen fixtures, harness and JUnit, with no QUIC or DafnyRuntime
fallback. Both helper class bytes match the pinned Maven runtime.

Javac 25 produces [three recorded class-byte differences](jdk25-codegen-differences.json)
from canonical javac 21 output. The [existing runtime guard](jdk25-runtime.json)
passes on the actual JDK 25 native classes without changing its opcode/caller
policy. There is no cross-compiler byte-identity claim. Final packaging uses JDK
21; its minimized bundle again matches all 70 canonical crypto class entries.
The [final physical bundle receipt](final-bundle.json) repeats the smokes under
both runtimes after that refresh, and verifies the Dafny MIT, Go BSD and crypto
notice resources byte for byte in both the QUIC library and minimized bundle.

## Scope and replay

The source refinements establish functional equations, bounded sampler failure,
ownership and cleanup on modeled returns. The small Java facades, Dafny/compiler,
Z3, runtime, javac/JVM and JDK providers remain trusted. Entropy, cryptographic
hardness, physical/JIT erasure and JVM timing are not established by these proofs
or measurements. The [toolchain review](../TOOLCHAIN-REVIEW.md) is a scoped audit
of known issues, not a full Dafny 4.11 replay or verifier-soundness theorem.

The `dafny-native-crypto-delivery` CI job runs the proof/control/JDK matrix,
assembles a complete input envelope, creates a fresh full stage, builds Maven
with JDK 21, compares all main classes and JAR class entries including attributes,
and runs the guard on the actual Maven classes. `delivery.py check` independently
repeats frozen verification/generation and retains the original strict lint for
handwritten Java. The runtime guard does not prove whole-program noninterference.
`publish` requires a stage-bound decision and only installs exact canonical
sources; it cannot silently overwrite changed generated files.
