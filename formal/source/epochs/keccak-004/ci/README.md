# Retained Darwin qualification and fresh checkout identity

This helper implements only the selected `keccak-004` gate. `selection.json` is
root-owned authority. The workflow must supply its literal reviewed SHA256; never
compute an expected selection/index hash from a caller's replacement data.
The selection fixes parent code `28a891c0…`, policy `8bb7b5d1…`, extractor
`3ef0b190…`, archive `13b4ec1c…`, capsule `fc8f3d1b…`, and both retained-data
index/current-checkout manifest hashes. No helper mode renews these authorities.

`prepare` authenticates and extracts the complete selected capsule, then invokes
the captured unchanged parent constructor with **the actual checkout** as both
Git repository and selected input project. Capsule fixtures supply the five test
class inputs. A capsule's duplicate source copy cannot substitute for the actual
checkout. The complete Baf3142, current85/434, and full successor delivery views
remain distinct. Prepare needs no retained parent/artifact payload to exist.

```sh
"$PYTHON" -I -B "$REPO/formal/source/epochs/keccak-004/ci/run.py" prepare \
  --repository "$REPO" --selection "$SELECTION" \
  --expected-selection-sha256 "$REVIEWED_SELECTION_SHA" --output "$FRESH_PREPARED"
```

All paths must be absolute. Output must be fresh and outside every input.
The output layout is `capsule/`, `views/baf-project`, `views/epoch-project`,
`views/source-views`, `views/receipt.json`, and `receipt.json`. The top receipt
binds the selection, extraction, complete view-receipt hash and map digests.
Stdout is JSON with `capsule`, `views`, `views_sha256`, `historical_root`,
`epoch_project`, and `prepared_receipt_sha256`. Hashing this just-produced receipt
binds its bytes; current admission still independently derives every view map.

After the workflow builds the actual checkout with JDK21 Maven and test
compilation (`-DskipTests`, not `-Dmaven.test.skip=true`), run:

```sh
"$PYTHON" -I -B "$REPO/formal/source/epochs/keccak-004/ci/run.py" check \
  --repository "$REPO" --prepared "$FRESH_PREPARED" \
  --expected-prepared-sha256 "$PREPARED_RECEIPT_SHA" \
  --classes "$REPO/quic/target/classes" \
  --retained-data "$REPO/formal/crypto/evidence/2026-11-05-keccak/parent" \
  --selection "$SELECTION" --expected-selection-sha256 "$REVIEWED_SELECTION_SHA" \
  --output "$FRESH_CHECK_RESULT"
```

Check re-admits the capsule and derived views, verifies the actual current85/434
source/support and helper/overlay pins, and reruns the parent eight-component
cold CLI in isolated Python with a closed child environment. The parent code and
policy used by that child are captured, authenticated copies. Historical ledger
status remains HISTORICAL; old Baf jobs run separately.

The selected retained index authenticates an exact payload map. All report names
are relative nontraversing paths. Original absolute producer paths remain data;
no private cache or producer-path fallback is read. The retained parent report
must say `selected-current-epoch-validated`, `artifact_API_called:true` and
`complete_before_after_maps_match:true`. Its current component result must match
the fresh cold result. The actual artifact API must have completed. The unchanged
API's pure receipt validators check delivery/bundle semantics; this helper links
those receipts to the selected stage/config/runtime, exact canonical and runtime
class maps, fixed fixtures/JDK maps, actual command and class-load logs, and the
externally sealed checkout manifest. No new prover or class-load parser is used.

The entire sealed467 actual-input map is required, including test classes and
resources captured by the retained run. Whole `quic/src/main/java` (269 files),
`quic/src/main/resources` (three), and test-class subtrees must match, so extra
runtime sources/resources cannot hide behind a subset hash check. Fresh output
must contain exactly the sealed468 class files plus the three sealed resources.
Source, helper, artifact-data and class identities are checked before and after
validation. Changed or extra files/classes require explicit fresh qualification;
a coherent locally rewritten receipt/index cannot authorize them.

This is **retained Darwin-arm64 execution evidence plus fresh checkout/class byte
identity**. Running this cold gate on Ubuntu does not qualify a fresh Linux proof
or artifact API instance. Static current-release identity claims remain deferred.
Global V7, physical JVM timing, broader SHAKE/ML-KEM/HKDF/adapter composition,
cryptographic hardness and independent external expert review remain outstanding.
There is no production publication or adoption decision in this helper.

The selection has exactly these fields:

```text
schema: microproxy.keccak004-ci-selection/1
scope: retained-Darwin-arm64-plus-current-checkout-identity
parent_sha256, policy_sha256, extractor_sha256,
capsule_archive_sha256, capsule_sha256,
retained_index_sha256, current_checkout_sha256
```

The retained `index.json` fields are `schema`, `scope`, `files`, `parent_report`,
`api_report`, `delivery_receipt`, `bundle_receipt`, and `current_checkout`.
`files` excludes the index itself and includes every other payload file. Its
schema is `microproxy.keccak004-retained-qualification/1`; scope is
`retained-Darwin-arm64`. The externally selected current-checkout document has
schema `microproxy.keccak004-current-checkout/1` and exact fields `source_files`,
`class_files`, `parent_report_sha256`, `api_report_sha256`, and
`stage_receipt_sha256` in addition to `schema`.

Bounded tests run without provers or artifact API execution:

```sh
"$PYTHON" -I -B -m unittest discover \
  -s "$REPO/formal/source/epochs/keccak-004/ci" -p test_run.py
```
