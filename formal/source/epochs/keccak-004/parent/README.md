# Explicit Keccak epoch parent dispatch

This gate separates three authenticated views: the complete released Baf project
(`baf0e693c7d4344c7232ea3c3b9d64e1fac03ab3`, tree
`c62fced90b167d19bc6bc5a46fb68ba448490abc`, 3142 tracked blobs), the selected
current 85-source/434-file source views (`294e28db…`), and a complete delivery
project derived from Baf plus the closed policy overlay, successor configuration
`51cae8d5…`/manifest `8a4655a0…`, and five explicit test fixture classes.
Admission recomputes the complete Git tree and derives both current project maps;
an operator-supplied hash of a rewritten receipt cannot authorize another map.
The original default configuration `e7d1dce3…` stays historical and unchanged.
The exact current NativeKeccak generated Java is one of four production overlays.

The unchanged Baf `validate_ledger(root, ledger_path)` executes against that full
Baf project, with its ledger inside the project. Its result is labeled
**HISTORICAL**. The authenticated Baf `check_select_source` dependency is captured
under its ordinary import name; ambient Python module search does not supply it.
Select's `155b…` and polynomial's `5ce…` baselines are preserved.

Mandatory current replacements are SHAKE's eight roots, 22 controls and both
JDKs (V4); full native composition/reference/kernel evidence, canonical delivery
and actual artifacts (affected V5/V6); current Select; ownership/API; and full
Keccak method/function observation coverage and body/control replay. Only seven
unchanged polynomial theorem/parser closures are reused, with all 50 actual
parser commands and the seven original raw proof logs checked. Historical ML-KEM
composition, erasure and package-wide linkage never authorize the current epoch.
Raw proof/audit/rejection/parser/JDK records are checked under fixed selected
rules. Ordinary and assertion summary units are distinct; mixed summaries,
crashes and resource failures reject.

## Platform and authority scope

`policy.json` selects one retained Darwin-arm64 instance. `check` performs cold
byte/logic validation and can run on Ubuntu with trusted Python and Git. It does
not execute or qualify the retained macOS compiler on Linux, and it does not
qualify arbitrary fresh CI proof receipts. New instance or tool/profile
selection requires independent review and an external authority update; no code
learns valid hashes, command inventories or proof counts from caller data.

`check` reports current prerequisites only. **It is not an adoption gate.**
`qualify` first performs the same prerequisite checks, then calls the unchanged
`crypto_current_release.validate_current_release` API with the same physical
selected project for `repository_root` and `tool_root`. No old supported-status
dictionary is constructed. Actual artifact qualification currently supports only
the fixed Darwin-arm64/JDK21+25 profile. Global V7, all-complete, broader adapter
trace composition, JVM physical timing, cryptographic hardness and independent
external expert review remain outstanding even when this scoped gate passes.

## Retained capsule and cold CI

All paths below must be explicit absolute paths. `PYTHON` identifies a trusted
interpreter; the recorded instance used Python 3.14.7. Source, helper, receipt,
raw-log, variant, canonical class and two checker DLL inputs are indexed. Full
SDK/JDK/Dafny executables are excluded from the capsule. Their recorded identity
maps remain authenticated evidence. Producer paths inside receipts are unchanged
metadata. An explicit `root-map.json` maps the eight domains into capsule-relative
locations. Cold validation installs an open allowlist and cannot read the old
producer/cache paths.

The maintainer creates the capsule from the explicit eight input roots; these
root arguments do not have defaults or private-cache fallbacks:

```sh
"$PYTHON" -I -B "$PARENT/parent.py" pack \
  --policy "$PARENT/policy.json" --expected-policy-sha256 "$POLICY_SHA" \
  --selected-root "$SELECTED_INPUT_PROJECT" --fixture-root "$FIXTURES" \
  --evidence poly "$POLY" --evidence shake "$SHAKE" \
  --evidence native "$NATIVE" --evidence stage "$STAGE" \
  --evidence ownership-api "$OWNERSHIP_API" --evidence select "$SELECT" \
  --evidence keccak "$KECCAK" --evidence coverage "$COVERAGE" \
  --output "$FRESH_CAPSULE"
```

The capsule is approximately 76 MiB. It must be published/retained as an explicit
CI artifact before the cold CI job is enabled. Merely naming eight private paths
is insufficient. The job must select the reviewed archive/capsule/policy hashes
literally, authenticate extraction, and reject missing/extra/aliased files. The
parent verifies the complete extracted map. No tool executable distribution is
required for this cold job. The Git checkout must contain the pinned Baf commit
and its full blob inventory; an 85-file historical source view cannot replace it.

After downloading the selected capsule to `CAPSULE`, the minimum cold job is:

```sh
"$PYTHON" -I -B "$PARENT/parent.py" construct \
  --repository "$REPO_WITH_BAF_GIT_OBJECTS" \
  --selected-root "$CAPSULE/project-inputs" --fixture-root "$CAPSULE/fixtures" \
  --policy "$PARENT/policy.json" --expected-policy-sha256 "$POLICY_SHA" \
  --output "$FRESH_VIEWS"
"$PYTHON" -I -B "$PARENT/parent.py" check \
  --views "$FRESH_VIEWS" --expected-views-sha256 "$CONSTRUCTED_RECEIPT_SHA" \
  --capsule "$CAPSULE" --expected-capsule-sha256 "$CAPSULE_SHA" \
  --policy "$PARENT/policy.json" --expected-policy-sha256 "$POLICY_SHA" \
  --output "$FRESH_COLD_RESULT"
```

`CONSTRUCTED_RECEIPT_SHA` binds the just-produced receipt location/bytes; admission
still derives and authenticates all project/source maps independently. The policy
and capsule hashes must come from independent selection, never from hashing
arbitrary caller-supplied replacements. Output paths must be fresh, outside every
input, and have existing parents. Aliases, traversal, symlinks and clobbering fail.

The old source-sensitive CI jobs must run separately against `baf-project` and
keep their historical labels. Fresh current Maven jobs run against the current
checkout. A cold prerequisite-only job cannot replace actual current artifact
qualification. Root owns that CI/adoption integration and artifact-retention
selection; this directory changes no workflow or production source.

## Fresh artifact invocation

`qualify` replaces `check` in the second command and additionally requires
`--artifact-request REQUEST.json --expected-artifact-request-sha256 REQUEST_SHA`.
The independently selected request has exactly these keys:

```json
{
  "stage": "/explicit/capsule/evidence/stage",
  "classes": "/explicit/actual/classes",
  "library": "/explicit/published-library.jar",
  "bundle": "/explicit/published-bundle.jar",
  "runtime": "/explicit/DafnyRuntime-4.9.1.jar",
  "java_homes": ["/explicit/JDK21", "/explicit/JDK25"],
  "junit_root": "/explicit/maven-repository",
  "dafny_cache": "/explicit/official-dafny-cache"
}
```

The stage must be the same explicitly supplied evidence stage. It is captured
without source/receipt rewriting. The API also authenticates the two original
absolute input-receipt paths recorded by that stage; these are explicit recorded
API inputs, not cold-validation fallbacks. A fresh artifact environment must
materialize these exact two files or use a separately selected new canonical
stage. Their pins are in `stage.external_inputs` and the fixed policy.

All four JUnit jars, five fixture classes, Maven runtime, both complete JDK maps,
and the official archive/distribution map are checked before API entry. Only the
four pinned JUnit jars and pinned official cache are copied into a fresh private
HOME so unchanged helper defaults cannot fall back to a maintainer's environment.
The fixture classes are already part of the constructed project. Actual classes,
library/bundle/runtime files and JDK trees intentionally remain explicit external
inputs; the unchanged API binds them before and after its checks. No production
publication or adoption decision is performed here.

The request is authenticated and captured before creating any output. Its file,
all artifact paths and both JDK roots participate in output admission, so a
nested output cannot mutate those inputs even when qualification later fails.
JDK21 uses the authenticated stage's complete symlink-aware map; its byte pins
must also equal the fixed policy's SHAKE byte map. Both link text and resolved
target remain exact before and after execution. JDK25 retains its fixed map.

## Bounded verification

```sh
"$PYTHON" -I -B -m unittest discover -s "$PARENT" -p test_parent.py
"$PYTHON" -I -B "$PARENT/verify_boundaries.py" \
  --policy "$PARENT/policy.json" --expected-policy-sha256 "$POLICY_SHA" \
  --capsule "$CAPSULE" --expected-capsule-sha256 "$CAPSULE_SHA" \
  --views "$FRESH_VIEWS" --expected-views-sha256 "$CONSTRUCTED_RECEIPT_SHA" \
  --expected-runner-sha256 "$REVIEWED_PARENT_CODE_SHA" --output "$FRESH_BOUNDARY_RESULT"
```

The boundary replay runs no SMT or artifact proofs. It includes actual selected
receipt/log/source mutations, coherent rewritten-receipt attacks, complete Baf
inventory substitution, omitted parser dependency, unsupported whole-polynomial
reuse, summary-unit confusion and denial of an original private producer file
open. The normal unit suite also exercises process-group cleanup after an exited
wrapper with a stubborn descendant, and the actual artifact API's `complete`
return grammar. This is preflight evidence, not parent acceptance or adoption.
