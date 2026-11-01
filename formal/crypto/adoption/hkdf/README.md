# Production HKDF adoption evidence

These are build and performance snapshots from the selected Dafny-to-Java HKDF
adoption. They do not authenticate a later build or establish JVM constant time.
The generated algorithm implements the functional contracts in
[the HKDF component](../../../dafny/README.md); the Java adapters, compiler,
runtime and JCE provider remain explicit trust assumptions.

- `stage-receipt.json`: a fresh frozen 18-root native graph replay and canonical
  generation with the reviewed HKDF/provider compilation configuration. Native
  mathematical inputs and their complete control receipt were unchanged; their
  receipt was reused, and the stage independently reverified every graph root.
- `maven-delivery.json`: a second independent stage replay and strict compilation
  of all handwritten sources. All 467 actual Maven library classes and JAR class
  entries matched canonical bytes, including debug attributes.
- `bundle-receipt.json`: independently reconstructs that full expected class map,
  binds the stage and delivery receipts, checks all 82 scoped crypto classes,
  all 467 retained QUIC-library classes, the 37 packaged Dafny runtime classes
  and all three notices in the minimized
  application. Nine full hybrid handshakes and bidirectional application data
  passed per runtime on JDK 21 and 25, with checked loaded-class origins. JUnit
  assertions, fixtures, compiler and JVM-generated lambda/type-switch classes
  remain trusted test machinery.
- `handshake-performance.json`: only the HKDF facade changes between classpaths;
  SHAKE/ML-KEM, TLS and provider classes are frozen identically. Its 12 HKDF classes
  match the reviewed canonical HKDF receipt. Three fresh forks per backend/runtime,
  4096 warmup handshakes and nine measured batches of 32 produce 52,608 complete
  handshakes including warmup. Inputs, commands, samples and class/tool hashes
  are retained. This is performance evidence, never a timing-security test.

## Compatibility and cost

Full Maven verification passed on JDK 21 and 25: 4,120 test executions per run,
zero failures/errors and 23 skips; captured browser fingerprint tests passed.
Skipped optional peer/live tests are not claimed as exercised locally. Exact-head
CI repeats its configured interoperability and proof jobs.

The post-bulk-copy HKDF experiment measured allocation rising from 594,677 to
775,759 bytes per complete handshake on JDK 21 (+30.45%), and from 583,879 to
746,502 on JDK 25 (+27.85%). Median CPU changed +21.19% and -6.40% respectively,
but baseline/generated fork medians drift substantially on this shared host.
CPU impact is inconclusive; these numbers do not establish a speedup, a stable
CPU bound, deployment throughput or capacity. Earlier boxed-adapter measurements
are separate historical runs, not a paired speedup comparison.

The user selected production integration after compatibility and performance
checks. This record documents the measured allocation cost and uncertainty;
it is not external expert approval or a new claim that the whole proxy is secure.
The broader obligation ledger keeps trace composition, the failed full AWS
reference replay, SAW's alternative array-clone route, external review and
physical JVM timing separate.

## Reproduction

Use the required CI workflow's fresh native proof receipts and stage, then run
`delivery.py check` and `bundle_checks.py --stage ...` against the actual library
and minimized application JARs. Both scripts reject stale source/artifact inputs.
The relative paths in the recorded receipts identify the historical local build;
CI produces new artifacts and hashes rather than treating these snapshots as
current-release proof. See [production delivery](../../README.md#production-delivery)
and [the completion plan](../../../../docs/project/2026-11-01-crypto-117-completion.md).
