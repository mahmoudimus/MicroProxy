# Retained Keccak parent requalification

This retains the Darwin-arm64 keccak-006 parent `qualify` for released commit `b80932f387b69b50276fd6a4d87bd65a6156955b` (tag `v0.10.0`). Its delivery base is that complete released tree. The 2026-11-05 keccak-004 source evidence is reused, and the canonical stage was regenerated on it. The artifact API checked the published 0.10.0 library and bundle.

## Artifact source: GitHub Packages, not Maven Central

0.10.0 is published only to GitHub Packages. Maven Central is blocking the `io.github.mahmoudimus` namespace until 2026-12-01 because of its monthly release-size limit, so `repo1.maven.org` has no 0.10.0 (HTTP 404 on 2026-11-26). The qualified JARs were downloaded with an authenticated `read:packages` token from:

| Artifact | URL | Bytes | SHA256 |
| --- | --- | --- | --- |
| Library | `https://maven.pkg.github.com/mahmoudimus/MicroProxy/io/github/mahmoudimus/quic/0.10.0/quic-0.10.0.jar` | 913464 | `ee86938869c455827305712591b250104f6a47158db198e90baef39782ca20c3` |
| Bundle | `https://maven.pkg.github.com/mahmoudimus/MicroProxy/io/github/mahmoudimus/microproxy-starlark/0.10.0/microproxy-starlark-0.10.0-all.jar` | 6212722 | `63af8d221a75f187b68f1642e0936000245b6e5c3fefb87b7d4ca51288212249` |

Both JARs match the SHA1 files published next to them. The parent API takes explicit `library`/`bundle` paths and has no repository URL, so no tooling was changed. These are the published bytes, not a local build. The 468 classes in the library equal the classes compiled from `v0.10.0` with the pinned JDK 21.0.12.1. `actual-artifacts/report.json` records both SHA256 values. When 0.10.0 reaches Central, its JARs qualify under this epoch only if their SHA256 values equal the two above.

CI authenticates this complete indexed data set, repeats the current cold component checks, and binds the actual checkout sources and fresh JDK21 classes to the sealed maps. It does not claim a fresh Linux proof or artifact execution. Absolute producer locations are unchanged metadata and authorize no file reads. Each later changed source or artifact needs explicit requalification.

The static current-release claim remains deferred. Full SHAKE/ML-KEM/HKDF/adapter trace composition, physical JVM timing and independent external expert review remain outstanding.
