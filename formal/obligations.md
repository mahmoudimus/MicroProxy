# Crypto obligation ledger and release-claim gate

`formal/crypto-obligations.json` is the fail-closed V0-V8 obligation ledger for the
Java cryptography work. It is a **provenance and declared-claim gate**, not a
theorem prover, an independent expert review, or a whole-proxy security claim.
Matching hashes establish identity and drift detection only. The underlying
Dafny/Lean/TLC/SAW results keep exactly the domains, controls and trust boundaries
recorded in their component receipts.

The release gate lives in `scripts/security/check_crypto_release.py`; the ledger
validator is `scripts/security/check_crypto_obligations.py`. Their independent
negative-control tests are in `scripts/security/test_crypto_obligations.py`.

## Status model

The fixed inventory is `V0` through `V8`. Removing, renaming or reordering an
entry fails; adding an unlisted entry also fails. Dependencies must be acyclic and
every obligation must be reachable from the V8 root, so deleting a root edge or
introducing a cycle fails. The checker also pins the allowed assumption vocabulary,
claim vocabulary and claim strength rules.

| Status | Meaning |
|---|---|
| `model-proof` | A checked mathematical/model theorem, not a Java implementation proof. |
| `implementation-proof` | A verified source implementation connected to generated Java and checked delivery, under named compiler/runtime/provider/facade trust. |
| `bytecode-proof` | A proof over actual class files, with its exact snapshot and backend scope stated. |
| `finite-tests` | Vectors, differential tests or replay checks; never promoted to a universal proof. |
| `partial` | Some scoped evidence exists but the obligation is not closed. |
| `blocked` | A concrete missing capability or receipt prevents the claim. |
| `deferred` | Not attempted for the current release claim; reported as residual. |
| `not-selected` | An alternate route that is explicitly not the selected completion path. |
| `unsupported` | No evidence is offered for the claim. |

Proof statuses require a named nonvacuity/domain control whose reviewed marker is
present in a pinned evidence file. A proof or production claim cannot be supported
by finite tests alone. V0 is a Python ledger/gate implementation that is tested,
not formally verified; it is classified `finite-tests`, never
`implementation-proof`. The real Dafny proofs remain V4-V6 `implementation-proof`.

## Evidence rules

Each obligation cites relative repository paths with exact SHA-256 values. The
checker rejects:

- absolute paths, `..`, non-normalized paths and path components that are symlinks;
- missing files, null/placeholder hashes and stale/tampered hashes;
- changed manifests, generated sources, facades, providers or runtime pins;
- missing or extra files under the managed generated-source prefixes;
- duplicate JSON keys, duplicate obligation/claim IDs and duplicate assumption refs;
- an assumption ID outside the reviewed vocabulary, or a defined assumption that is
  not used by any obligation;
- unsupported evidence kinds or evidence that a claim's obligations do not declare;
- control inventories that changed, lost a named control, report only success labels,
  or use timeout/resource/crash/parser text or interrupted exit codes as a
  counterexample.

Receipt checks pin exact proof counts, control names/fields, command exits and
schema values where the component receipt supports them. Hash maps validate every
listed source/tool pin in the component manifests. The checker also pins the exact
reviewed key set for each mandatory semantic map, generated file set and delivered
inventory in code, so trimming a receipt map or ledger expected map cannot bless an
omitted dependency. The generated-file inventory compares the recorded
`delivered_sources` with the actual files under the managed production prefixes, so
a missing or newly added generated file fails even when all remaining hashes still
match. HKDF additionally requires the exact 10-control inventory, sole Mac
assumption, 21/22 proof counts, two 45-case/2766-assertion JDK records, adapter
discipline metadata, and full input/generated/class key inventories from constants,
not editable receipt expectations. V4-V6 additionally pin exact positive proof,
audit, generation, vector, assumption, provider, and Java-result records in code;
V7 pins the packet positive/trace text/result markers. Zeroing those values and
renewing the ledger/receipt hashes does not preserve a supported claim.

Validation sections are not optional for a supported claim. A reviewed constant
contract per component pins its required evidence paths/kinds, named control groups
(including every control name and a failure-bearing field), receipt value fields,
source/tool hash maps with their exact include/exclude filters, provider/facade
entry hashes, generated-file inventory, nonvacuity markers and reviewed text checks.
Deleting or narrowing any of them fails, even if the obligation row and unrelated
hashes remain. A checklist entry alone is not accepted as the contract.

The checker does not infer that a hash match proves a theorem, that a historical
JAR receipt authenticates the current JAR, or that a finite Java observation is a
universal refinement. Those distinctions are encoded in claim status and scope.

Some older receipts record only aggregate `verified`/`errors` counts rather than a
per-control exit kind. The ledger consumes those exact named controls, but the
native KEM, Linux composition and native polynomial receipts (explicit semantic
exit 4) carry the stronger distinction between a genuine proof failure and a
timeout/resource/crash. The managed generated-file inventory covers the native
`internal/verifiedcrypto` prefix; the two provider sources are pinned by the
delivery manifest, and concurrent HKDF-owned adapters are outside that component
inventory.

## Claims

Claims have a fixed inventory. Every claim has a reviewed immutable policy that
pins its exact obligations, strength, production marker, assumption set, required
evidence paths/kinds, obligation statuses and mandatory component checks. The
ledger's own `strength`/`production`/dependency/evidence values cannot relax that
policy; `supported` is rejected when any of them differ.

The current supported claims are the generated SHAKE/ML-KEM functional production
claim, the scoped local HKDF functional and production components, the scoped packet
receive trace and the non-timing release gate. The V0 finite fixture cannot be
relabelled as a production implementation claim.

Supported status is fail-closed to the claims that have a reviewed, implemented
semantic evidence validator in the checker. Security proofs, timing/constant-time,
whole-proxy security, independent expert review, AWS full closure, current full-JAR
identity and all-V0-V8 completion have no such validator yet: marking any of them
supported fails even if a JSON file asserts a schema, boolean, status or timestamp.
A future category becomes enabled only by a reviewed code+tests change that validates
the actual artifact/log/receipt, not by a ledger or receipt self-certification. A
12-class component probe is not a full-JAR receipt, and a target-only AWS replay is
not closure.

## Commands

From the repository root:

```sh
python3 -m unittest discover -s scripts/security -p 'test_crypto_obligations.py' -v
python3 scripts/security/check_crypto_obligations.py
python3 scripts/security/check_crypto_release.py
```

Normal validation succeeds while explicitly deferred, blocked or snapshot claims
remain; each is listed in `residual_claims`. A claim-specific release use fails
closed:

```sh
# Accepted for the narrowly supported functional claims.
python3 scripts/security/check_crypto_release.py \
  --require shake-mlkem-functional-production
python3 scripts/security/check_crypto_release.py \
  --require hkdf-production-functional

# Fails while timing/expert/current-JAR/complete claims are open.
python3 scripts/security/check_crypto_release.py --require current-release-jar-identity
python3 scripts/security/check_crypto_release.py --require-all
```

Both commands print machine-readable JSON with `ok`, obligation/claim statuses,
`residual_claims` and, for release requirements, `claim_failures`. `--output FILE`
writes the same JSON atomically. Exit `1` is a validation/requirement failure;
exit `2` is an unexpected internal validator failure.

## Current snapshot scope

At this snapshot:

- SHAKE128/256 and ML-KEM-768 have functional source proofs under explicit Dafny
  compiler/runtime, generated-runtime, JDK SHA3/provider and reviewed-facade trust.
  The generated production source/class inventory matches the recorded delivery.
- SAW `reduceOnce` evidence is a historical pre-adoption bytecode snapshot. The
  actual `PacketKey.nonce` proof remains blocked by unsupported primitive-array
  `clone` translation; the portable SAW route is explicitly `not-selected`, not
  complete.
- The pinned AWS HKDF target replay verifies 9 declarations with 0 errors, but it
  is target-only (`full_dependency_graph_verified=false`). The pinned full closure
  replay failed with exit 134/resource/timeouts/backend errors and discharged no
  obligation. `EXECUTION-INPUTS.json` retains the exact failed execution identity
  (`bc446dbb…`), and the current reference manifest has
  `closure_verified_minimum=null` with exact tool inputs. AWS full-upstream replay
  therefore remains unsupported, not relabelled from the target result.
- Local HKDF functional/production adoption is integrated and bound: unchanged
  `Hkdf.dfy` (21 kernel checks, 22 general-domain checks, 10/10 rejected controls,
  two 45-case/2766-assertion JDK result records), a
  fresh `PRODUCTION-EVIDENCE.json`, exact `formal/dafny/inputs.json` pins, nine
  generated source hashes, twelve canonical production class hashes, the reviewed
  `HkdfBridge`/`JdkHmac` boundary and current production `Hkdf.java`. This is a
  component functional/generation claim; it is not a fresh full-JAR identity, whole
  handwritten-bytecode refinement, JVM timing or security proof. V1 stays partial
  for the failed AWS upstream closure.
- Packet receive-path trace evidence is scoped to its documented observer. There is
  no complete secret-trace proof for HKDF, SHAKE or ML-KEM, no JVM/machine-code
  timing theorem and no constant-time claim.
- Timing measurements are raw local observations with no statistical pass/fail
  threshold. Independent external cryptographic/proof review is absent.
- The original SHAKE/ML-KEM adoption receipts are historical snapshots. The later
  [HKDF adoption build](crypto/adoption/hkdf/README.md) independently checks all 467
  library and retained bundle classes and records a successful actual bundle smoke.
  The static ledger still leaves `current-release-jar-identity` deferred: accepting
  a build snapshot does not authenticate a later artifact or a running deployment,
  and that claim needs its own reviewed validator with actual artifact inputs.

No generic "secure" or exhaustive-verification label follows. Functional
correctness, cryptographic hardness, side-channel behavior and deployment identity
are separate claims.

## Future renewal and residual gates

HKDF integration pins are now current and are not pending repin. Future renewals
must be tied to an actual reviewed receipt, not a label:

1. The actual full-class/JAR checks now have a concrete build snapshot, separate
   from the 12-class HKDF component probe. Before enabling the ledger's
   `current-release-jar-identity`, implement and review a validator that consumes
   the specified actual artifacts and their complete source/stage bindings; a
   schema marker or a historical receipt alone is insufficient.
2. Keep V1 `partial` until a reviewed successful AWS dependency-closure receipt with
   `full_dependency_graph_verified=true` exists. Target-only 9-declaration success
   must not be promoted to closure.
3. Keep V7/V8 partial and all-complete unsupported until trace/timing, current-JAR
   and independent external expert evidence genuinely exist.
4. If the HKDF final delivery store or production adapter changes, renew the exact
   input/tool/generated-source/class/provider/facade pins and their receipt
   validators, then rerun the 62 tests and all normal/narrow/all-required checks.
5. Do not convert agent-assisted development review into an independent external
   expert-review receipt.
