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
whole-proxy security, independent expert review, AWS full closure
and all-V0-V8 completion have no such validator yet: marking any of them
supported fails even if a JSON file asserts a schema, boolean, status or timestamp.
A future category becomes enabled only by a reviewed code+tests change that validates
the actual artifact/log/receipt, not by a ledger or receipt self-certification. A
12-class component probe is not a full-JAR receipt, and a target-only AWS replay is
not closure.

## Commands

From the repository root:

```sh
python3 -m unittest discover -s scripts/security -p 'test_crypto*.py' -v
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

# Fails without actual artifact inputs; the static claim remains deferred.
python3 scripts/security/check_crypto_release.py --require current-release-jar-identity
# Fails while timing/expert/complete claims are open.
python3 scripts/security/check_crypto_release.py --require-all
```

Both commands print machine-readable JSON with `ok`, obligation/claim statuses,
`residual_claims` and, for release requirements, `claim_failures`. `--output FILE`
writes the same JSON atomically. Exit `1` is a validation/requirement failure;
exit `2` is an unexpected internal validator failure.

The output guard also applies in normal mode: `--output` cannot replace the
validated ledger or checkout sources, including aliases. Use top-level `target/`
or a path outside the audited checkout. A different `--root` is protected too.

### Validate a particular release artifact

The release CLI can support `current-release-jar-identity` **for one invocation**
by running the underlying delivery and minimized-bundle checks against explicit
artifacts. The committed ledger remains `deferred`; a historical receipt alone
cannot enable the claim.

```sh
python3 scripts/security/check_crypto_release.py \
  --require current-release-jar-identity \
  --artifact-stage /fresh/canonical-stage \
  --artifact-classes quic/target/classes \
  --library /built/quic.jar --bundle /built/microproxy-all.jar \
  --runtime "$HOME/.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar" \
  --java-home /trusted/jdk21 --java-home /trusted/jdk25 \
  --artifact-output target/fresh-artifact-check \
  --output target/current-release-claims.json
```

Use a new artifact-output directory. Outputs must be outside the audited checkout
or under its top-level `target/`, and cannot overlap input artifacts, stage,
external evidence, classes, ledger or JDKs. The stage compiler must match the
operator's explicit JDK 21 tool tree before a stage-selected tool can run. Both
JDK 21 and 25 are required. The checks freshly replay canonical generation,
compile the complete library, compare every class byte in classes/JAR/bundle,
validate retained runtime classes and notices, and run origin-checked hybrid
handshakes on both JDKs. Their successful reports are bound to unchanged inputs
at the end of this invocation. Missing, altered, stale, malformed or timed-out
inputs fail closed. This authenticates the supplied artifacts under the
documented compiler/runtime/provider assumptions; it does not identify a running
deployment or prove timing or cryptographic hardness.

Stage evidence paths must be absolute. Output protection independently inventories
all receipt references in the input-evidence envelope, even if the stage's external
input map omits them. Malformed or unreadable evidence prevents all output writes.
Reports, logs and copied receipts use exclusive random temporary files and atomic
replacement inside the fresh private artifact directory.

`crypto_current_release.py` and its regression suite are mandatory, pinned V8
gate inputs. The native-delivery CI job invokes this CLI instead of separately
running the same delivery and bundle checks twice.

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
- V7 now catalogues the stable `formal/timing` component as conditional caller/model
  evidence: a two-run `SecretTrace` theorem, five actual-bytecode caller
  certificates (Select 84 checks, Feed 179, Extract 34, Expand 111, LabelInfo 169),
  57 model / 17 HKDF-shape obligations, 14 fixtures (1 positive, 13 policy rejects)
  and 4 genuine certificate mutants. Its report has 15 open owned roots, 19 assumed
  owned helper/adapter trace contracts and 31 unchecked owned callees/labels. Those
  assumptions are explicit; the trusted javap extractor/policy is recorded. V7 is
  not promoted and cannot be promoted while the open roots/assumed callees remain;
  this is not a universal JVM bytecode proof, JVM timing theorem, source functional
  proof of new modules, or complete secret-trace proof for HKDF/SHAKE/ML-KEM. The
  exact reviewed report snapshot SHA-256
  `9782ef72d7a725d12cc1098b88f21506b802a344c6dbcb858549ef2804a2de54` is pinned in
  code; advancing that baseline requires explicit source/policy review as well as a
  data-hash update, not a self-declared ledger/receipt repin.
- Packet receive-path trace evidence remains separately scoped. The existing
  `packet-receive-trace-scoped` claim covers only its documented packet observer; it
  does not claim the new whole-crypto timing-component results.
- Timing measurements are raw local observations with no statistical pass/fail
  threshold. Independent external cryptographic/proof review is absent.
- The original SHAKE/ML-KEM adoption receipts are historical snapshots. The later
  [HKDF adoption build](crypto/adoption/hkdf/README.md) independently checks all 467
  library and retained bundle classes and records a successful actual bundle smoke.
  The static ledger still leaves `current-release-jar-identity` deferred: accepting
  a build snapshot does not authenticate a later artifact or a running deployment,
  and only an actual-artifact invocation can support that claim for its inputs.

No generic "secure" or exhaustive-verification label follows. Functional
correctness, cryptographic hardness, side-channel behavior and deployment identity
are separate claims.

## Future renewal and residual gates

HKDF integration pins are now current and are not pending repin. Future renewals
must be tied to an actual reviewed receipt, not a label:

1. Run the actual-artifact release invocation above for each artifact being
   assessed, separate from the 12-class HKDF component probe. Keep the static
   `current-release-jar-identity` deferred; a schema marker or historical receipt
   cannot substitute for current artifacts and complete source/stage bindings.
2. Keep V1 `partial` until a reviewed successful AWS dependency-closure receipt with
   `full_dependency_graph_verified=true` exists. Target-only 9-declaration success
   must not be promoted to closure.
3. Keep V7/V8 partial and all-complete unsupported until the 15 open owned trace
   roots, 19 assumed owned helper contracts, runtime timing and
   independent external expert evidence genuinely close.
4. If the HKDF final delivery store or production adapter changes, renew the exact
   input/tool/generated-source/class/provider/facade pins and their receipt
   validators, then rerun the gate regressions and all normal/narrow/all-required checks.
5. Do not convert agent-assisted development review into an independent external
   expert-review receipt.
