# Keccak epoch006: keccak-004 source evidence on released 0.10.0

keccak-005 bound its delivery project to the released 0.9.0 tree
(`65c9d2e07c523c703a40081cc74e62866e614f3a`). 0.10.0 changed handwritten quic sources
(`TlsAcceptancePolicy`, the certificate-path fix of PR #170), so the current checkout no longer
matches the keccak-005 seal and no library with that change can qualify under keccak-005.
That is by design, not a defect.

keccak-006 changes only the delivery base, exactly as keccak-005 did:

- **Historical** stays the complete Baf project (3142 blobs, tree `c62fced9…`), labelled
  HISTORICAL. The seven historical CI jobs keep the keccak-004 action and selection.
- **Delivery base** is the complete released 0.10.0 Git tree: commit
  `b80932f387b69b50276fd6a4d87bd65a6156955b` (tag `v0.10.0`), tree
  `8231287a8a3b1c1ccb13a20c5bdfc4cd26169909`, 3791 blobs. The epoch project is that tree plus only
  the keccak-004 successor configuration (`51cae8d5…`) and the five fixture classes. All 58
  code/overlay pins are byte-identical in the release; nothing is overlaid.
- **Source epoch** is unchanged: the keccak-004 manifest (`294e28db…`), 85/434 source
  views, and the poly, SHAKE, native, ownership/API, Select, Keccak and coverage evidence.
- **Canonical stage** was regenerated on the 0.10.0 inputs (receipt `207cba35…`). Relative to
  the keccak-005 stage, only `pom.xml`/`quic/pom.xml` (version `0.9.0` -> `0.10.0`), recorded
  command paths and path-bearing parser/audit logs differ. Proof counts (20 roots, 9834), the 66
  canonical class bytes, sources, JDK maps and external inputs are identical.
- **Fixture classes** are the reviewed keccak-004 pins, unchanged. 0.10.0 added a field and a
  method to the test helper `TestCerts$Authority`, so the 0.10.0 build's `TestCerts.class` and
  `TestCerts$Authority.class` no longer equal these pins. The fixtures are the selected handshake
  harness, not qualified artifacts; the sealed checkout binds the 0.10.0 test classes separately.
- **Artifacts** are the published 0.10.0 `quic` and `microproxy-starlark-all` JARs from GitHub
  Packages. Maven Central blocks the namespace until 2026-12-01, so 0.10.0 is not on Central; see
  `formal/crypto/evidence/2026-11-26-keccak-006/parent/README.md`.

| Component | Path | Reviewed authority |
| --- | --- | --- |
| Parent | `parent/parent.py`, `parent/policy.json` | selected by `ci/selection.json` |
| Capsule | `capsule/retained-darwin-arm64.tar.gz` | selected by `ci/selection.json` |
| Extractor | `../keccak-004/capsule/safeextract.py` (unchanged format) | `3ef0b190…` |
| Retained run | `formal/crypto/evidence/2026-11-26-keccak-006/parent` | selected by `ci/selection.json` |
| Selection | `ci/selection.json` | literal SHA256 in `formal-security.yml` |

No helper renews these authorities. Every later change to handwritten quic sources,
test classes, or the published artifacts needs a new reviewed epoch or qualification.
Global V7, physical JVM timing, broader SHAKE/ML-KEM/HKDF/adapter composition,
cryptographic hardness and independent external expert review remain outstanding.
