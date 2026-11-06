# HKDF array-input epoch implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Qualify and deliver the generated HKDF input boundary without changing the subject of retained Keccak evidence or published 0.8.1 artifacts.

**Architecture:** A new versioned epoch authenticates retained native evidence, fresh HKDF-v2 evidence and fresh whole-artifact validation. Closed input/class deltas join these layers. Existing artifact APIs retain their checks and execution requirements.

**Tech stack:** Python 3.11+, pinned Dafny 4.9.1/runtime, SDK 10.0.400/offline 577 payloads, JDK 21/25, Maven and existing epoch/artifact validators.

**Spec:** `docs/superpowers/specs/2026-11-05-hkdf-array-epoch-design.md`.

**Checkpoint:** The implementation and 79 combined epoch/CI DATA tests are present.
FULL007 HKDF component evidence is complete; new delivery qualification and
operational cold-CI admission remain pending. The epoch README/CI-CONTRACT record
the reviewed offline-cache, full-clone and qualified Python3.13.9 refinements.
Unchecked execution steps below are not claimed complete by source adoption.

## Global constraints

- Keep `keccak-004`, v1 receipts and published 0.8.1 artifacts unchanged.
- Require completed HKDF-v2 output and full exact input, producer and tool bindings.
- Preserve native proof/control policies, original domains, aliases and public API.
- Source proof counts: body 257, sequence NI 11, array NI 13; mixed 257 each.
- No aggregate/global trace claim from component or finite artifact results.
- No install/deploy/publication; private package outputs only.
- Coordinate the sole local SMT lease before any stage or proof-producing API call.
- No source/class prefix exceptions or broad input exclusions.

## Review focus

- A plausible current receipt paired with old or altered producer/input authority.
- An unlisted class or source change hidden among otherwise permitted HKDF changes.
- Old native composition or erasure evidence substituted for the required current subject.
- Different project/tool roots or class loading from an alternate artifact.
- Input or artifact mutation between validation and use.

## Task 1: Closed epoch authority and delta admission

**Files:** Create `formal/crypto/epochs/hkdf-array-001/admission.py`, `run.py`, `test_run.py` and the selected `inputs.json` when authoritative data is available.

**Interfaces:** `EpochError(ValueError)`; `load_policy(root: Path, policy: Path, expected_sha256: str) -> dict`; `check_delta(before: dict[str, str], after: dict[str, str], allowed: dict) -> dict`. The latter returns exact changed/added/removed entries only after every entry matches the policy.

- [ ] Write and run failing admission tests for unselected policy, stale producer,
  unauthorized third change, omitted/extra entry, invalid path/symlink and a
  coherently repinned unsupported subject.
- [ ] Implement closed schema/path/hash checks and exact delta comparison using
  the repository's existing checked loaders. Require predecessor and candidate
  hashes for each permitted change. Do not manufacture final policy values.
- [ ] Run `python3 -I -B -m unittest discover -s formal/crypto/epochs/hkdf-array-001 -p 'test*.py' -v`; all admission cases must pass.
- [ ] Record source/tool policies and the immutable predecessor identities in the
  epoch README. Root reviews actual complete map deltas before selecting policy.

## Task 2: Layered evidence and actual-artifact qualification

**Files:** Create `formal/crypto/epochs/hkdf-array-001/delivery.json`, `README.md`; extend `run.py` and `test_run.py`.

**Interfaces:** `check_retained(project: Path, policy: dict) -> dict`; `check_hkdf(project: Path, policy: dict) -> dict`; `qualify(project: Path, policy: dict, output: Path, library: Path, bundle: Path, runtime: Path, jdk21: Path, jdk25: Path) -> dict`. Return values retain separate scopes and evidence identities.

- [ ] Write failing tests for whole-Poly fallback, missing current native evidence,
  old HKDF receipt/classes, old configuration stage, different project/tool roots,
  wrong JDK/runtime and treating the old full class map as current.
- [ ] Authenticate the retained original capsule/views and unchanged native
  dependency subject using existing parent cold checks. Construct a new project
  with only the externally selected candidate overlays.
- [ ] Validate completed HKDF-v2 raw derivation and current source/generated/class
  inventory. Keep its original and new runtime suites separate.
- [ ] Derive the delivery configuration with only the selected HKDF source pin
  updates; leave native/compiler/control policy unchanged.
- [ ] Create one new-config stage. Build the library/bundle privately using the
  spec's Maven command; run the HKDF subset hook and native runtime guard.
- [ ] Invoke `crypto_current_release.validate_current_release()` with the same
  new project as repository and tool root. Preserve its required stage
  reproduction, all-class/bundle/notices/runtime checks, loaded origins and both
  JDK executions. Do not add another manual stage replay.
- [ ] Measure and enforce the entire predecessor/candidate class delta. Require
  root selection of actual maps; never assume that only two classes changed.
- [ ] Persist complete before/after maps, raw owned executions and an indexed
  report distinguishing all three evidence layers. Partial/error output cannot
  leave a qualified result.

## Task 3: CI, documentation and reviewed delivery

**Files:** Root coordinates `.github/workflows/formal-security.yml`, assurance documentation and issue #117 with the HKDF integration owner; worker changes remain in the new epoch directory.

- [ ] Test duplicate/multi-release entries, alternate loaded origins and artifact
  mutation using the existing artifact-validator controls and the new wrapper's
  actual input/output contract. Preserve historical/current dispatch tests.
- [ ] Add the new selected current epoch to CI while retaining authenticated
  historical checks. Do not weaken the old fixed-subject checker.
- [ ] Run required regression/fingerprint and artifact gates on the actual final
  tree. Record performance measurements for the changed route.
- [ ] Update assurance/docs and #117 with completed versus outstanding scopes;
  preserve physical JVM timing and independent expert review as open boundaries.
- [ ] Root reviews the complete coherent diff, commits explicit paths, pushes a
  reviewable branch/PR and merges after required exact-head checks pass.

Implementation may prepare code/tests before HKDF-v2 or final artifacts exist,
but admission must fail closed until real reviewed authority is supplied. No
placeholder receipt or digest can stand in for execution evidence.
