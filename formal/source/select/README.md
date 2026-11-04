# NativeMlKem.Select source package (production candidate)

**UNADOPTED.** This is a cross-platform component package produced for independent review;
it is not a production adoption, release, GitHub CI result, whole-KEM NI/rho/failure claim,
heap model, JVM-timing claim or security reduction.

## What changed from the portable package

The package now separates immutable source/proof configuration from reviewed tool
profiles, keeps the retained fixture out of the package tree, and refuses unsafe CLI
combinations. The semantic expectations, controls and proof counts are unchanged.

- `package.json` — immutable source/proof manifest: expectation tables, Dafny closure
  bindings, checker source hashes, profile-index binding. **No machine paths, no tool
  hashes.** Externally bound by `--expected-package-sha256`.
- `candidate-sources.json` — the exact **used** candidate closure, bound by
  `package.json["candidate_sources_sha256"]`: the authenticated 85 Dafny files outside
  this package plus `package.json["candidate_inputs"]`, the reviewed explicit inputs
  (`NativeMlKem.dfy`, `native_kem_domain.dfy`, `native_kem_hash.java`,
  `native_kem_test.java`, `native_kem_checks.py`, `reference/provenance.json`,
  `reference/Shake.java`, `reference/MlKem768.java`). This is deliberately **not** a
  global source-extension sweep: unrelated outer Python/Java/C#, docs, evidence JSON,
  logs, receipts and ledgers are outputs of other processes, are not Select inputs, and
  do not invalidate this package. The runner verifies the exact key set and every hash
  before and after the run; extra/omitted keys, a modified/removed/linked Dafny source,
  an escaping path, or a modified provider fails closed. Containment is checked per
component: none of the path components below the resolved candidate root may be a
symlink, even when the target is inside the candidate (a directory link such as
`formal/crypto/reference -> /elsewhere` is rejected, not merely hash-compared).
- `baseline.json` — strict source inventory: 85 baseline and 85 candidate Dafny hashes.
  The baseline `formal/**/*.dfy` set is compared **exactly** (recursive), every baseline
  entry and its ancestor components must be non-symlinked/contained, and the baseline
  `NativeMlKem.dfy` used by codegen is bound explicitly in the before/after input
  signature (baseline 85 + candidate 85 + package + used inputs + profile).
  (diff is exactly `crypto/NativeMlKem.dfy` and `crypto/native_kem_domain.dfy`), 52 control
  files, and a package file inventory that **excludes** `fixtures/retained-native/work/**`,
  `fixtures/retained-native/report.json`, `__pycache__`, `*.pyc`, and the two manifests
  themselves (self-reference). Bound by `package.json`.
- `profiles/<name>.json` — pure expected tool **identities** (no locations):
  `linux-sdk10.0.400`, `macos-sdk10.0.400`. Besides Dafny/DafnyCore/Z3/runtime/SDK/JDK
  versions and the checker DLL, each profile pins the 13 Boogie DLL identities, the JDK
  `bin/java`, `bin/javac`, `bin/javap`, `lib/modules` and `release` files for each JDK,
  and the dotnet launcher hash. `load_profile` enforces the profile's canonical
  `platform` against the actual host (Darwin/arm64 or Linux/x86_64); a foreign profile is
  refused even with a valid external hash. Bound by `profiles/index.json`, which is bound
  by `package.json`; optionally also bound externally by `--expected-profile-sha256`.
- `replay.py` — the runner. Actual tool locations are explicit CLI arguments.

Binding chain (acyclic):
`package.json → baseline.json → source files`
`package.json → profiles/index.json → profiles/*.json`
The package SHA is deliberately **not** written into this README (that would create a
cycle); the caller pins it via `--expected-package-sha256` and its own workflow constant.

## Running a qualification

```sh
python3 formal/source/select/replay.py \
  --package-root formal/source/select \
  --baseline-root "$PWD/baseline-git-155b" \
  --output /tmp/select-full \
  --tool-profile linux-sdk10.0.400 \
  --expected-profile-sha256 <sha256 of profiles/linux-sdk10.0.400.json> \
  --expected-package-sha256 <sha256 of package.json> \
  --dafny /opt/dafny-cache/dafny-4.9.1-linux-x64/dafny/dafny \
  --dotnet /opt/dotnet/dotnet \
  --jdk21 /opt/jdk21 --jdk25 /opt/jdk25 \
  --runtime /opt/DafnyRuntime-4.9.1.jar \
  --mode full
```

`--mode targeted` runs the controls, harness, observed mutant, F2, encoder fixtures and
proofs. The retained Native stage is launched in an out-of-tree copy with explicit
`--dafny` and `--dotnet` (no ambient fallback) and its report must carry the reviewed
checker plugin `2785…` plus the package's checker source/project/policy hashes. The
production verifier also requires the `baseline13` record (exit 0, named
`SOURCE-COVERAGE OK`) and parses the referenced `work/baseline13.log` for the exact 13
reviewed resolved root identities; a missing/wrong/duplicated record or root log fails. `--mode full` additionally runs the full `NativeMlKem` proof, the retained Native
fixture and the dual-JDK codegen/class identity. `--native-kem-checks` is available for
callers that explicitly want the KEM replay; it is not part of Select qualification.

The codegen stage reads the Maven runtime identity from the selected **tool profile**,
never from `package.json` (which deliberately carries no tool hashes), and requires the
class count to equal `expected.jdk_classes` on **both** JDKs. A wrong, missing or
malformed profile runtime hash fails before any translator invocation.

### Report lifecycle

`package-report.json` is written as `status: incomplete` before the first tool work. A
gate failure becomes `status: FAILED` with `error`; an unexpected helper/runner exception
becomes `status: FAILED` with `failure_kind: runner-exception`, `error_type`, `error` and
the preserved Python traceback, and the process exits nonzero. Partial output already
written under `--output` is left in place. Cancellation (`KeyboardInterrupt`, SIGTERM)
is never converted into a qualified/complete status; the last report remains
`incomplete`.

### Output safety

An existing `--output` path (file, directory, or dangling symlink) is refused **without
any mutation**. Choose a fresh path per run. Only Python cache/bytecode is ignored at
admission; an unexpected `bin/`, `obj/`, `work/` directory or retained `report.json`
under the package is rejected **even when empty** (real builds happen outside the source
tree under `--output`); only `__pycache__`/`*.pyc`/`*.pyo` are benign. An output path that
cannot be created (e.g. `PermissionError`) is also a typed `rejected`/`output-admission`
failure with a nonzero exit and no mutation.

### Timeouts

If a tool exceeds its timeout, the captured partial stdout/stderr is preserved and a
single `CASE-TIMEOUT marker` line is appended; the log is never reduced to a synthetic
line.

### Non-qualifying self-test

`--self-test-only --checker-dll <path> --expected-checker-dll-sha256 <sha>` verifies an
explicit DLL and writes a `self-test` report with `"qualification": false`. It cannot be
combined with `--mode full` or `--native-kem-checks`, and `--checker-dll` is rejected
without `--self-test-only`. Negative build tests belong in unit tests, not the
qualification CLI.

### Case context in raw logs

Immediately before every resolver/verify/audit call the runner writes one
`CASE-CONTEXT` line into that command's raw log: case id, operand SHA-256 (before), the
exact argv and cwd, and the plugin SHA-256 where applicable. For case runs the expected
fixture SHA is included and the operand is checked against it before the call; after the
call the operand SHA is re-checked and recorded. The same values are emitted as a typed
`case_context` in `package-report.json`. Tool stdout is unmodified after the prefix and
the log still contains exactly one verifier summary.

### Retained fixture

The retained Native fixture is copied to `<output>/retained-native/fixture/` and run
there, so generated `work/` artifacts and `report.json` never enter the package tree. The
package source before/after hash maps are required to match at the end of the run.

## Tests

```sh
cd formal/source/select && python3 -m unittest -v test_replay
```

Quick unit tests (no Dafny/dotnet): manifests/bindings, strict inventory, profile
identity-only enforcement and hash binding, output refusal and sentinel preservation,
timeout preservation, case-context ordering and drift detection, self-test CLI rules,
retained out-of-tree copy, ambient selector clearing, exact scope, codegen
profile-runtime handoff (translator-boundary sentinel, wrong/missing profile hash
rejected before translation), and the incomplete/FAILED/runner-exception report
lifecycle.

## Profiles

| profile | Dafny | DafnyCore | Z3 | SDK | JDK21 | JDK25 | runtime | checker DLL |
|---|---|---|---|---|---|---|---|---|
| `linux-sdk10.0.400` | `7f6353ce…` | `93ae2dee…` | `0a91d884…` | 10.0.400 | 21.0.13 | 25.0.5 | `dc62d345…` | `2785f06a…` |
| `macos-sdk10.0.400` | `9ae7c1d3…` | `93ae2dee…` | `5eaebf0f…` | 10.0.400 | 21.0.12.1 | 25.0.5 | `dc62d345…` | `2785f06a…` |

`DafnyCore.dll` is managed IL and identical on both platforms; the reviewed checker DLL
is reproducible byte-for-byte on Linux under SDK 10.0.400. A different SDK (e.g. 10.0.403)
is **not** covered by these profiles; there is no any-DLL or any-profile fallback.
