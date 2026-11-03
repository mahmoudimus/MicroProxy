# Published v0.7.0 crypto artifact validation

The existing supplied-artifact gate passed on 2026-11-03 for these downloaded
assets from [release v0.7.0](https://github.com/mahmoudimus/MicroProxy/releases/tag/v0.7.0),
at source commit `e77479a9153a3e408afa46f65a82abd0ae99d8ea`:

| Asset | SHA-256 |
| --- | --- |
| `quic-0.7.0.jar` | `ff8b7ffd74a979e3976a026d641baa63c43ff7ddbdd456f0a374914a4b6030fb` |
| `microproxy-starlark-0.7.0-all.jar` | `fd2e03897d3cfb469ac9a63b97ea4048c40524dad9d964063767eea02359d811` |

All nine downloaded release assets matched GitHub's per-asset digests. The eight
JARs also matched the downloaded `SHA256SUMS`. The crypto gate then validated
the actual library and shaded bundle against a fresh canonical stage.

That stage reran all 18 source-root verifications, totaling 8,905 verified
checks with zero errors, and regenerated/compiled Java with pinned Dafny 4.9.1,
Z3 and JDK 21. The published library matched all 468 classes. Its bundle carried
the expected 84 crypto classes, all 468 retained library classes, 37 runtime
classes and three notices. On each JDK 21 and 25, nine full handshake cases and
nine nonce/seal/open cases passed with class-load origins checked against the
actual bundle. A separate comparison found every library class unchanged in
the bundle.

The [machine-readable validation record](validation.json) binds the exact assets,
source graph, root counts, inventories, smoke counts and underlying receipt
digests. It is a record for these files, not an automatic gate for later files.

## Reused and fresh evidence

The native semantic-control/JDK-replay receipt was reused from an earlier run
whose complete source, additional-input, runner, tool and receipt pins matched.
The existing validator checked those matches before accepting the evidence.
Those native controls were not rerun in this validation. The 18 source-root
proofs, canonical generation/compilation, artifact comparisons and loaded-origin
handshake/nonce checks were fresh. This distinction is recorded in the JSON.

The first bundle attempt lacked the trusted handshake fixture build outputs.
Building them with `mvn -o -q -pl quic -am test-compile -DskipTests` in the
isolated release checkout satisfied that prerequisite; the unchanged gate then
passed. It was not an artifact identity failure.

## Reproduction and scope

Use the release commit and the existing [delivery tooling](../../crypto/README.md)
to create a full canonical stage with a complete, exact-matched native evidence
envelope. Download the release assets, extract the actual QUIC JAR classes, build
the trusted handshake fixtures, then run
`scripts/security/check_crypto_release.py` with explicit `--artifact-stage`,
`--artifact-classes`, `--library`, `--bundle`, `--runtime`, both `--java-home`
values and a fresh `--artifact-output`. The gate must validate the actual input
files again. A recorded status or matching release name is not a substitute.

This invocation supported `current-release-jar-identity` only for its exact
supplied artifacts; the static claim remains deferred for arbitrary later
artifacts. Compiler/runtime, Java-adapter and primitive assumptions remain.
These checks do not establish complete source-trace independence, whole-proxy
security, correctness of non-crypto bundle dependencies, cryptographic hardness,
physical timing/erasure or independent expert review.
