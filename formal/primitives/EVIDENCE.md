# Primitive verification evidence

Kernel revision: `6db8424` (Keccak/field specifications and implementations).
Local validation: 2026-10-29. Exact executable/checker/reference/tool inputs are
listed in `inputs.json`; each complete replay records the same hashes, generated
source/class hashes, tool identities, commands and logs. CI evidence belongs to
its particular PR head and environment.

| Check | Local result |
|---|---|
| Keccak kernel | 122 verified checks, 0 errors |
| Field kernel | 15 verified checks, 0 errors |
| General-domain harness including kernels | 139 verified checks, 0 errors |
| Java translation with verification enabled | 55 verified checks, 0 errors |
| Kernel assumption audits | 0 findings for each kernel |
| Negative controls | All 9 rejected by real proof/audit obligations |
| New runner gates | 9 tests passed |
| Shared HKDF/cleanup gates | 16 tests passed |
| Packet gates | 34 tests passed |

These are Dafny-reported checks, not independent security-property counts. The
domain and translation runs overlap kernel verification; do not add them as
separate properties. Controls cover rotation, omitted round, wrong round constant,
narrowed lane domain, incorrect ReduceOnce, wrong Barrett multiplier, narrowed
field domain, extra axiom and skipped verification. Parsing/timeout/resource
failures cannot count as a successful negative control.

The exact generated Java was compiled with Homebrew JDK 21.0.12.1 using release 21,
then executed on that runtime and Temurin 25.0.5+8 on macOS arm64. **Each** runtime
passed 1698 permutation states (including all 1600 one-bit states), 4096 rotation
cases, 31247 field cases and 40586 assertions. The harness checks an independent
LFSR/coordinate recurrence, the pinned XKCP zero-state answer, every ReduceOnce
input, wider Barrett boundaries above 2^24, and canonical-source comparisons.
These finite Java checks do not prove backend/runtime/adapter correctness.

A separate full-root Maven run returned BUILD SUCCESS on JDK 21.0.12.1. Normal
platform/external-service skips remain; they are not formal evidence. Existing
production sources, standards/profile fixtures and runtime dependencies are
unchanged by the new component. Strict MkDocs, generated docs-index and diff checks
passed. Linux JDK 21/25 replays are supplied by the new CI matrix; local macOS
results must not be represented as Linux or deployment results.

Fresh agent review found an initial-marker write failure that could retain a prior
successful report. Regression tests reproduced it in all three runners; each now
removes the old receipt under its lock before marker publication. Shared cleanup
tests also reproduced Darwin EPERM behavior: it is ignored only after confirming
that the owned, unreaped process group has no live member. Live-group signaling
failure and mandatory reaping remain tested. New/legacy proof replays were refreshed
after the reviewed runner pins changed. This is development review and testing,
not independent external cryptographic audit.

The initial unconstrained wrong-theta/omitted-round counterexample attempts hit
solver limits and were rejected as inconclusive. Proved helper lemmas/opaque
definitions make the unchanged functional equations tractable. A ghost counter
tracks actual round iterations; the 23-round mutant now fails its explicit 24-round
assertion, without depending on an expensive permutation counterexample. No axiom
or narrowed input domain was introduced.

Reports are in `target/dafny-primitives/`, with refreshed HKDF and packet reports
in `target/dafny-hkdf/` and `target/packet-verification/`. The [component guide](README.md)
states all trust boundaries and exclusions. Full SHAKE sponge/API refinement,
polynomial/NTT/codecs/sampling/KEM composition, production adoption and secret-trace
or physical timing claims remain open.
