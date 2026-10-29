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
