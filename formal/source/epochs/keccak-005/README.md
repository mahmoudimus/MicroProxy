# Keccak epoch005: keccak-004 source evidence on released 0.9.0

keccak-004 bound its delivery project to the released Baf commit
`baf0e693c7d4344c7232ea3c3b9d64e1fac03ab3` (0.8.1). The actual-artifact API recompiles
the handwritten quic sources of that project. A library containing any later handwritten
quic change therefore cannot qualify under keccak-004. That is by design, not a defect.

keccak-005 changes only the delivery base:

- **Historical** stays the complete Baf project (3142 blobs, tree `c62fced9…`). The old
  ledger, Select/polynomial historical evidence and the seven historical CI jobs still run
  against Baf, labelled HISTORICAL, through the unchanged keccak-004 action and selection.
- **Delivery base** is the complete released 0.9.0 Git tree: commit
  `65c9d2e07c523c703a40081cc74e62866e614f3a`, tree `b1ab2d92bb64a02cb15f862083b731485c5c89a5`,
  3748 blobs. The epoch project is that tree plus only the keccak-004 successor
  configuration (`51cae8d5…`) and the five fixture classes. The closed code/overlay
  selection must already be byte-identical in the release; nothing is overlaid.
- **Source epoch** is unchanged: the keccak-004 manifest (`294e28db…`), 85/434 source
  views, and the poly, SHAKE, native, ownership/API, Select, Keccak and coverage evidence.
- **Canonical stage** was regenerated on the 0.9.0 inputs. Relative to the 2026-11-05 stage,
  only `pom.xml`/`quic/pom.xml` (version `0.8.1` -> `0.9.0`), recorded command paths and
  path-bearing parser/audit logs differ. Proof counts (20 roots, 9834), the 66 canonical
  class bytes, sources, JDK maps and external inputs are identical.
- **Artifacts** are the published Maven Central 0.9.0 `quic` and `microproxy-starlark-all` JARs.

| Component | Path | Reviewed authority |
| --- | --- | --- |
| Parent | `parent/parent.py`, `parent/policy.json` | selected by `ci/selection.json` |
| Capsule | `capsule/retained-darwin-arm64.tar.gz` | selected by `ci/selection.json` |
| Extractor | `../keccak-004/capsule/safeextract.py` (unchanged format) | `3ef0b190…` |
| Retained run | `formal/crypto/evidence/2026-11-16-keccak-005/parent` | selected by `ci/selection.json` |
| Selection | `ci/selection.json` | literal SHA256 in `formal-security.yml` |

No helper renews these authorities. Every later change to handwritten quic sources,
test classes, or the published artifacts needs a new reviewed epoch or qualification.
Global V7, physical JVM timing, broader SHAKE/ML-KEM/HKDF/adapter composition,
cryptographic hardness and independent external expert review remain outstanding.
