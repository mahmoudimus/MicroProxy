# Packet kernel verification evidence

Implementation revision: `7be2a23be1d8dfe557b847bd4705f6a18f110340`.
Local validation completed on 2026-10-29 UTC. These are scoped development results,
not an external cryptographic audit, deployment result or whole-record timing proof.

| Environment | Functional kernel | Trace model | Actual-class IR applications | Controls |
|---|---|---|---|---|
| macOS arm64, Homebrew21.0.12.1 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |
| macOS arm64, Temurin25.0.5+8 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |
| Linux x86-64, Temurin21.0.7+6 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |

Counts are Dafny's reported verified checks, not a count of independent security
properties. Source/method/audit/domain controls and the exact theorem statements
matter more than these counts. The trace-model and concrete-application counts
overlap: the concrete harness also rechecks the included generic model.

All33 Python gate tests passed on macOS and Linux. Each replay rebuilt and tested
canonical production classes, including standards vectors, new buffer/boundary
regressions and fingerprint tests. Separate full-root `mvn --batch-mode test`
runs returned BUILD SUCCESS on JDK 21.0.12.1 and25.0.5+8. Platform/external-service
skips remain in those normal suites; no skipped test is counted as proof evidence.
Profile and existing vector fixtures were not changed.

The Linux check used an isolated current-source copy and a local development image
based on `maven@sha256:3a4ab3276a087bf276f79cae96b1af04f53731bec53fb2e651aca79e4b10211e`,
with Python3, libicu74 and procps installed. The older container JDK is portability
evidence, not a production patch recommendation. CI repeats with Temurin21/25;
its current results and downloadable artifacts live in the PR checks.

The extracted scalar programs contain160 SSA nodes for Decode,13 for ReadPrefix
and88 for Unprotect (420,26 and194 expanded bytecode instructions respectively on
the local JDK 21 build). The I/O checker recorded5 packet reads/5 writes for header
unprotection,4 reads for the PN prefix, and a common validation trace for lengths 1..4.
The packaged generated Java is6570 bytes; its JDK 21 class is2970 bytes. It compiles
without DafnyRuntime.jar or another classpath; no runtime dependency was added.

Independent agent review reproduced and fixed an exact-callee admission defect:
a similarly named unproved class/wrong signature could pass the original adapter
gate. The RED fixtures now reject. Additional controls reject implicit synchronized
methods and changes to valid-domain validation. Runner regressions reproduce and
prevent parent clean deleting evidence and metadata serialization escaping the
failure report. A leaked trace mutant initially exhausted resources; that run was
rejected as inconclusive. The final concrete negative witness fails an actual
paired-observation postcondition. This is agent-assisted development review, not
independent external expert review.

[README](README.md) defines the observer, trusted bridges and exclusions. Functional
proofs concern the packed scalar representation. Buffer value packing/domain
propagation remains handwritten, tested and reviewed; only its address/call policy
is checked structurally. Compiler trust includes the explicit two-helper bounded
shift lowering pass. JIT/CPU/provider/GC timing, downstream AEAD/key-phase/metadata
processing, outbound protection and whole-stack security remain open.

Full reports/logs, raw generated source, copied actual classes, SSA programs and
concrete proof harnesses are in `target/packet-verification/`,
`target/packet-verification-jdk25/` and `target/packet-verification-linux/` locally.
CI uploads the default evidence root separately for each JDK. Each report pins the
source/checker/lowerer/tool inputs and exact class hashes. A new source/tool change
requires a fresh replay rather than copying a previous success receipt.
