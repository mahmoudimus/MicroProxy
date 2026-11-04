# Initial generated-HKDF replay

Source component: `73c12c57baa765caeea78971ae8c3a7bc4f17f1d`, including the reviewed
runner cleanup fix. Local replay completed on 2026-10-29 UTC. These are development
checks, not an independent expert audit or a production deployment result.

| Environment | Kernel | Unrestricted-domain harness | Negative controls | JCE integration |
|---|---|---|---|---|
| macOS arm64, Homebrew JDK 21.0.12.1 | 21 verified, 0 errors | 22 verified, 0 errors | All 7 rejected as intended | 43 cases, 2745 assertions |
| Same generated Java 21 classes, Temurin 25.0.5+8 | Same proof/generation | Same harness | Same controls | 43 cases, 2745 assertions |
| Linux x86-64, Temurin 21.0.7+6 | 21 verified, 0 errors | 22 verified, 0 errors | All 7 rejected as intended | 43 cases, 2745 assertions |

All three JCE runs selected SunJCE for HmacSHA256/384/512. The Linux check used
Ubuntu 24.04 in the existing Maven image pinned at
`maven@sha256:3a4ab3276a087bf276f79cae96b1af04f53731bec53fb2e651aca79e4b10211e`,
with Python 3 and libicu74 installed. That older container JDK is additional
portability evidence, not the recommended production patch level. CI repeats on
Temurin 21 and 25 and records their exact version strings; local success does not
stand in for a completed remote CI run.

All 14 runner tests passed on macOS and Linux. Review reproduced cancellation
bugs involving SIGTERM and failed process inspection; their regression tests
failed before the fixes and passed afterward. A second agent reviewed proof
domains, HMAC assumptions, generation/JCE integration, adapters and trust gates.
This is agent-assisted development review, not external cryptographic review.

Both platforms generated the same 10 Java files (16792 source bytes) and 9
implementation classes (16489 class bytes). The per-platform DafnyRuntime.jar
hashes differ and are pinned separately: each is 159920 bytes with 91 classes.
These counts exclude the handwritten facade/HMAC adapter and test/reference
classes. No performance, constant-time, secret-erasure or production integration
claim follows from these measurements.

Replay commands, domains and trust boundaries are in [README](README.md). Full
per-run source/generated/class hashes, commands, provider/JDK identities and logs
are emitted to `target/dafny-hkdf/report.json` and uploaded by CI. The Linux local
check used `--output /evidence` mounted at `target/dafny-hkdf-linux`. Re-running the
commands is required for a fresh claim after a pinned input or tool change.

## Post-adoption local replay

The production adoption reuses the same verified `hkdf/Hkdf.dfy` (source hash
unchanged) and translates it with `--outer-module
io.github.mahmoudimus.quic.internal.verifiedhkdf` into the committed package
`.../internal/verifiedhkdf/VerifiedHkdf`. `run.py` requires fresh output to equal
that package byte for byte, then compiles and exercises the real `quic.Hkdf`,
`HkdfBridge` and `JdkHmac` boundary.

Local macOS arm64 replay (JDK 21.0.12.1, additional Temurin 25.0.5+8 run):
kernel 21 verified/0 errors, unrestricted-domain harness 22 verified/0 errors,
all ten negative/skip/extra-assumption/Java-adapter controls rejected by proof
obligation, audit or the structural gate, exactly the permitted
`VerifiedHkdf.Mac` axiom, 9 generated source files plus the import-only top-level
file, 12 pinned classes, and 45 generated adapter cases / 2766 assertions on each
runtime. Java adapter controls compile old select-loop, bare-cast and
dead-method-decoy mutants of `JdkHmac`/`HkdfBridge` and require
`check_adapter_discipline.py` to reject them; the gate parses the actual compiled
`JdkHmac.bytes` method for `toRawArray`, guarded `instanceof [B`/branch/
`checkcast`/`areturn`, and `HkdfBridge.bytes` delegation. The bulk path uses
`toRawArray()` and a primitive `byte[]`. Generated `LabelInfo` still selects
public 16-bit label units; labels are public and that generated code is outside
the adapter gate. The QUIC-side generated-adoption test adds 13 JUnit cases
covering RFC 5869, RFC 9001, the TLS label/key schedule, bounds, null
compatibility, ownership, determinism and concurrency; it passed on JDK 21 and
JDK 25 in an isolated classpath run.

`hkdf/GENERATED.json` records the exact generated source, class, aggregator and
translation-metadata hashes. `deliver_hkdf.py` reproduced the package unchanged
and matched a locally built JAR's 12 class entries exactly. These are build
reproducibility checks, not whole-bytecode or JVM-equivalence proofs.

`bench_hkdf.py` measured a TLS 1.3-shaped key schedule after the bulk-copy fix at
roughly 2.3x (SHA-256) and 1.9x (SHA-384) the `ReferenceHkdf` CPU cost in paired
medians (thread CPU time), with allocation about 4-5x on a shared host. A separate
earlier run of the boxed/select generated adapter measured about 3.0-3.6x versus
`ReferenceHkdf`; that is a diagnostic, not a paired pre/post or speedup claim. See
the README for exact caveats and observed ranges; root must rerun the
complete-handshake benchmark. No constant-time, secret-erasure, provider-correctness or
JVM-timing theorem follows. The coordinator still needs to update the
`formal/crypto` delivery classification/acceptance inventories for the new
generated prefix and the enlarged main class/JAR set.


## Executable-source trace integration (2026-11-03)

The actual HKDF implementation now carries ghost trace outputs, erased from
its generated Java. A fresh functional replay verifies **248 kernel checks**
and **249 unrestricted-domain checks** at the original 30-second/10-million-
resource functional budget. All ten functional/assumption/adapter controls
reject as intended. The same newly generated classes pass **45 cases and
2,766 assertions** on each Homebrew JDK 21.0.12.1 and Temurin JDK 25.0.5.
`PRODUCTION-EVIDENCE.json` records this replay and its exact inputs.

Every generated Java file, delivered package file, compiled class, aggregator,
translation record and runtime digest is identical to the previous production
receipt. The functional feedback mutant now targets the actual Mac invocation
because its argument expression also occurs in ghost observations; it must
still fail a real proof obligation. The unrestricted harness captures the new
ghost outputs and retains the original general input domain.

The separate [same-body source-trace component](../source/hkdf/README.md) verifies
248 body and 259 paired/domain checks, with an explicitly trusted resolved-AST
coverage adapter. This functional receipt does not prove that adapter correct,
Java/JCE refinement, cryptographic hardness or physical JVM timing. The earlier
21/22 and 43-case records above are preserved as historical evidence.


The shared functional runner is also pinned by the packet and primitive proof
components. After its HKDF-specific domain/control changes, both dependent
manifests were renewed only for that helper and fully replayed: primitive Keccak
122 / Field 15 / domain 139 checks, all nine controls and 40,586 assertions on
each JDK 21/25; packet kernel/trace/extracted proofs and all seven controls on
each JDK 21/25. Their source algorithms, generated Java and proof policies are
unchanged. This closes the two stale-input CI failures; it does not expand the
source-trace or timing claims.
