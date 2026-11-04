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
assumption, 248/249 proof counts, two 45-case/2766-assertion JDK records, adapter
discipline metadata, and full input/generated/class key inventories from constants,
not editable receipt expectations. V4-V6 additionally pin exact positive proof,
audit, generation, vector, assumption, provider, and Java-result records in code;
V7 pins the packet positive/trace text/result markers. Its scoped HKDF source
contribution additionally requires the actual 248/259 source checks, the exact
64 control records (including the accepted bijective relabel), two-file source
closure, sole Mac assumption, 44 pinned inputs, nine generated Java sources,
twelve class/ABI checks and the recorded checker assembly/SDK. The coverage
adapter has its own explicit trusted-source-observation assumption. These source
results do not complete native crypto or Java-adapter trace composition. Zeroing those values and
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

### Native crypto receipts after the polynomial adoption

The V5/V6 native receipts were regenerated from complete actual replays over the
adopted ghost-instrumented source, so the checker no longer accepts the earlier
"unchanged proofs reused by identity" shortcut:

- `NATIVE-CODEC-EVIDENCE.json` carries fresh top-level `proofs` (86 NativeField,
  1503 NativeCodec, 281 NativeSampling, 8/4 domain harnesses), the 15 semantic
  controls and the 8 payload bytecode controls, plus a pinned 16-key `inputs` map.
  The pre-Poly proof-reuse, portability and strict-exit records are retained only
  under `historical` and are not evidence for the current source hashes.
- `NATIVE-KEM-EVIDENCE.json` carries the fresh full receipt: 2776 composition,
  2695 reference-graph, 4097 native-kernel and 162 generation checks, 11 rejected
  semantic controls, both JDK replays and a pinned 27-key `inputs` map. Its
  reviewed generated-caller inventory digest is repinned because two generated
  `NativePolynomial` call sites gained parentheses at platform-value (`.0`) sites;
  the reviewed site set, methods, lines, counts and review text are unchanged.
- `NATIVE-POLYNOMIAL-EVIDENCE.json` carries the fresh actual-A macOS/arm64
  positive, 14-control and dual-JDK replay (`39a1bf11…`; 1092 native checks,
  22865885 assertions on each JDK) and a pinned 13-key `inputs` map including the
  shared `SourceTrace` wrapper and the canonical observation vocabulary. The
  inverse control is now a legal witness rather than an out-of-resource attempt:
  a stage-0 vector (coefficient 2 = 1, others 0) distinguishes the correct lane
  2154 from the swapped 1175, asserted after the actual `F.MulSub` call and before
  any ghost fact; the negative copy reports 9 assertions/1 real error and the
  paired original body 10/0. The only source change is
  `native_polynomial_checks.py` (`ab28bc18…`) plus its test helper
  (`0e775ccc…`); production Dafny/Java, domains, budgets and the other thirteen
  mutation hashes are unchanged. The earlier Linux inverse out-of-resource
  attempts remain disclosed and are not counted, and the v1 macOS receipt is
  retained only under `historical`.
  The Linux sub-block is now the actual linux/amd64 `--phase controls` replay of
  the same reviewed runner (`ab28bc18…`) over the same 13 source pins: exit 0,
  14/14 controls, every per-control summary byte-identical to the mac fixture,
  and the inverse witness again 9 assertions/1 error against a paired original
  10/0. The generated mutant sources are path-relocation-normalized and hash to
  the fixture's recorded templates for all 14 templates and four paired bodies
  (`all_normalized_equal: true`). The authoritative run is exit 0; the two
  observation replays and the failed `poly-out`/`poly-out2` attempts are
  disclosed and are not cited as qualification, and no GitHub-hosted CI
  qualification is claimed here.
- `NATIVE-KEM-LINUX-EVIDENCE.json` now records the actual full-scope linux/amd64
  replay (Ubuntu 24.04.5 under a WSL2-hosted Docker daemon, not a GitHub runner):
  2776 composition obligations with 0 errors, the 21-file source graph, both JDK
  replays, 11 rejected semantic controls and the 3 compiled selector controls.
  The per-run maxima come from an equivalent same-source/same-flags replay that
  adds CSV logging only (`max_resource_count` 10275514 deterministic rlimit
  units; `max_obligation_seconds` 10.1399173 wall-clock). The previous
  control-only composition run is preserved under
  `historical_previous_control_only_run`; no old numbers were carried forward and
  the GitHub-hosted CI replay is still required after push.

The delivered source graph adds `formal/source/SourceTrace.dfy` and
`formal/source/vocabulary/ObservationVocabulary.dfy`, so the stage-receipt source
map and the native input maps are pinned at their new exact key counts (20/13/16/27
and 21 for the Linux source graph). The V5 claim now requires the codec input map
as well, so trimming any of these maps fails instead of quietly narrowing coverage.

Any change to `formal/crypto/delivery.json` also invalidates the nonce functional
receipt's `delivery.manifest_sha256` and the committed delivery stage's
`manifest_sha256`; the coherent change therefore requires a fresh nonce functional
replay and a fresh complete delivery stage in the same commit. Those receipts are
produced by the pinned runners, not edited by hand.

### Scoped poly source-trace claim (V7 contribution)

`poly-source-trace-ni` is a new, explicitly scoped V7 claim for the adopted
NativeField/NativePolynomial ghost-observation work. It is *not* an extension of
the SHAKE/ML-KEM functional claim and it is not "all of V7": Keccak/Shake, full
ML-KEM composition, adapters, invalid-input paths and the KeyGen rho-failure
non-interference path remain open.

Unlike a receipt-only claim, support requires the actual full portable-package
report at `formal/source/polynomial/SOURCE-EVIDENCE.json`
(`microproxy.native-polynomial-central-port/v1`) and the checker
`_validate_poly_source_evidence` re-derives its load-bearing facts from
repository bytes:

- `inputs_before` and `inputs_after` are the same 45 guards (44 pinned files plus
  `inputs.json`); every recorded hash must equal the current repository file, and
  the receipt's map must equal `formal/source/polynomial/inputs.json`, including
  its own manifest hash. Trimming or dropping a guard fails; the receipt cannot
  be renewed without the files.
- the eight proof targets and exact verified counts (86/1001/26/2767/14/17/29/19),
  zero errors, the reviewed 30 s/50M/2-core budget with `O:smt.case_split=0` on
  native targets and `3` only for the composition source, and eight audits with a
  finding count of zero;
- the checker source/project pins, SDK, deterministic/debug-free build, disabled
  directory build imports, a `DafnyHome`-parameterised project with no embedded
  absolute toolchain path, and the assembly/build-log identities as recorded;
- the exact 20 resolved method-root identities and 19 pure function identities
  (uniqueness, not a count), the two cleared ambient selectors
  (`POLY_TRACE_ROOTS`, `POLY_TRACE_FUNCS`), and the four canonical, sixteen
  mutation, decoy instance-class, N1b and repeated-root scope-probe controls.
  The repeated-root probe is the load-bearing scope guard: the checker exits 0
  while reporting twenty copies of one root, and the runner must reject it;
- the ghost erasure result (one changed generated Java text, 66 generated files,
  identical class bytes on both supported JDKs, 65/65 per JDK) with the approved
  Maven runtime and the immutable pre-adoption baseline. The baseline template
  must carry the four pre-adoption component hashes that are in the immutable
  20-file main closure (the poly domain harness is package-owned and is not part
  of that closure), so the adopted candidate (or mutable A after adoption) cannot
  serve as its own baseline;
- every receipt log is bound to a tracked copy by a log index whose hashes must
  match the adopted report byte-for-byte.

Support is additionally refused unless the claim cites every reviewed input path
(including the baseline template/helper/test and the checker project) and both
the V5 and V7 obligation statuses are as reviewed. The C# checker and the Dafny
parser/compiler/verifier remain trusted; roles are method-local, not physical
heap addresses; no JVM timing theorem is implied.

Ingestion is content-bound, not hash-count-bound. Each of the 128 producer log
paths is a reviewed literal; the index must contain exactly that set, each
tracked file must hash to its index entry, and every record that cites a log must
use the pinned producer-relative path (and its recorded digest where the producer
captures one). The gate parses the tracked bytes:

- positive Dafny runs must show exactly one `N verified, 0 errors` summary with
  the claimed count, no `Warning:`/`Error:` diagnostic, no resolution errors and
  no timeout/resource/crash text; audits must report the recorded zero findings;
- negative Dafny controls must show the recorded verified/error counts plus a
  real `(line,col): Error:` diagnostic containing the reviewed anchor, and are
  rejected if the log is green, inconclusive or resource-exhausted (the single
  intentionally `observed-not-used-as-proof` mutation must instead contain the
  resource marker and is never counted as a semantic rejection);
- checker positives must print exactly the recorded resolved-root list (20 unique
  methods, or the reviewed single-root observed control) with the exact positive
  marker; the repeated-root probe must show the checker succeeding while printing
  twenty copies of one root, which the runner records as rejected;
- checker rejections must contain the named coverage diagnostic, the resolution
  summary and no success marker, and must not be a tool crash or resource event;
- the N1b records additionally bind their body/harness/checker/generate logs, the
  body must clear its recorded minimum and the generated-Java identity must hold.

The `checks` list is validated as an exact identity multiset, not a length: every
`proofs`/`audits`/canonical/decoy/mutation/N1b/scope-probe record must appear
verbatim, and the remaining records must match the reviewed inventory of the
default positive run, four observed method/function scopes, twelve named checker
rejections, the LemmaOut green run and four Dafny assertion-failure controls,
each with its exact key set, identity, counts and parsed log. The supplementary
families are additionally required as exact identity *sets with no duplicates*:
each scope selector, each `(selector, needle)` rejection, each Dafny-negative
record and each green `(log, verified)` pair must appear exactly once and the
reviewed set must be fully covered, so duplicating one control while dropping a
sibling fails even when all shape counts and the 64-length are unchanged. Checker
needles, rejection reasons and Dafny anchors are pinned literals rather than
receipt text: a control whose `needle` is replaced by an arbitrary substring, or
whose Dafny log is swapped for an unrelated error with matching counts, fails.
Green records also require their pinned producer-relative log path and digest
(not just matching text). Recorded `log_sha256` fields are mandatory for every
record type that carries one; only the N1b body/harness/generate logs, which the
producer intentionally records without a digest, use an explicit schema-specific
exception while still being path- and index-bound. Dropping a log, relabelling a
proof digest to another proof's log, erasing non-positive records, duplicating a
control identity or rewriting a rejection into a success therefore fails closed;
ROOT's three original probes and the reviewer's duplicate-identity probes are
regression tests.

The claim is now recorded as `supported` on the adopted actual-A report
(`formal/source/polynomial/SOURCE-EVIDENCE.json`, schema
`microproxy.native-polynomial-central-port/v1`, 8 proofs / 8 audits / 64 records,
45 before/after guards over the 44 pinned inputs). The report and all 128 run
logs are copied verbatim under
`formal/crypto/evidence/2026-11-04-poly/source/` and bound by
`log-index.json` (report digest, per-log digests, baseline manifest digest and
its 20-file component map), so the gate can re-derive every receipt log from
tracked bytes instead of trusting an absolute producer path.

Support therefore requires, at validation time, the actual report bytes and all
of: the 44 manifest pins and 45 guards matching the repository, the exact
20 method-root / 19 pure-function identities, the named canonical/mutation/
decoy/N1b controls and the repeated-root rejection, the ghost-erasure
65/65 class identity on both JDKs, the pre-adoption baseline, and the tool and
trust-boundary blocks. A deferred claim would bypass all of this, so demoting the
claim is a gate removal, not a bookkeeping change; `check_crypto_release.py
--require poly-source-trace-ni` makes that visible in CI.

The claim is still subject to the V5 component checks (including the pending
linux/amd64 14-control replay of the native polynomial wrapper) and to the
separate V7 packet/timing gate; it is `supported` as a scoped source claim, not as
a complete V7 result.

## Claims

Claims have a fixed inventory. Every claim has a reviewed immutable policy that
pins its exact obligations, strength, production marker, assumption set, required
evidence paths/kinds, obligation statuses and mandatory component checks. The
ledger's own `strength`/`production`/dependency/evidence values cannot relax that
policy; `supported` is rejected when any of them differ.

The current supported claims are the generated SHAKE/ML-KEM functional production
claim, the scoped local HKDF functional and production components, the narrow
generated nonce functional production claim, the scoped packet receive trace and
the non-timing release gate. The V0 finite fixture cannot be relabelled as a
production implementation claim, and the blocked SAW nonce bytecode route is not
made supported by the generated nonce route.

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
python3 scripts/security/check_crypto_release.py \
  --require packet-nonce-functional-production

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
  complete. V3 stays `blocked`. The original `formal/saw/inputs.json` is
  preserved verbatim and its pre-adoption `PacketKey.java` entry
  (`501999d8...`) is frozen under `formal/saw/historical` and validated through a
  `path_prefix` split; it is never repinned to the current bridge. A current-tree
  SAW replay is expected to fail that historical input check, which is accurate.
- The generated nonce functional route is candidate-integrated separately and narrowly in this worktree (root acceptance/merge and Linux CI pending):
  `PacketKey.nonce` delegates to the Dafny-verified generated
  `VerifiedNonce.__default.Nonce`; `formal/nonce/PRODUCTION-EVIDENCE.json` binds
  the frozen kernel/domain sources, 337/343 proof counts, five genuine
  proof-obligation rejects, bounded `--no-verify` generation, the checked-in
  generated source and the 468/84/468 delivery inventory. `PacketKey.seal/open`
  plus nonce vectors pass 8 JUnit tests on JDK 21 and JDK 25. This is a
  functional component claim under Dafny/javac/JVM/DafnyRuntime trust; it is not
  a SAW bytecode proof, cryptographic-hardness claim, JVM timing/constant-time
  result, full-JAR identity or Linux live CI pass. The claim is an independent
  functional route; advancing the legacy SAW status later requires a reviewed
  policy change and does not retroactively weaken this nonce proof.
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
- V7 records corrected conditional caller/model evidence: five caller certificates
  (Select 84 checks, Feed 179, Extract 34, Expand 111, LabelInfo 169), four owned
  helper certificates and a separate 369-instruction composed Feed. The model and
  HKDF-shape proofs remain 57 and 17; 209 unit tests (two optional replays skipped),
  27 fixtures (four accepted, 23 policy rejects), four Select mutants and twelve
  callee mutants cover the
  extraction/gate controls. A compiled 138-row Apply probe cross-checks the finite
  execution interpreter. Wipe's witness must execute four stores to its secret
  parameter role; Extract must retain a non-parameter private value. These finite
  controls supplement the theorem and do not prove JVM semantics or timing.
  The original five-caller set still assumes 19 owned contracts; the separate
  composed Feed removes three from its own set (ten to seven), with 16 in the
  hypothetical replacement union. Thirteen roots and 31 aggregate unchecked labels remain.
  Two static HKDF helper roots and nine NativeField helpers now supplement that
  evidence: seven private field bodies have their owned calls fully expanded,
  supported by two public constant leaves. The existing shift runtime contract
  is admitted by a trusted audit rule. Required finite private controls cannot
  pass as public-only; the sequence allocation model does not prove copy/alias
  ownership, and arithmetic values do not refine JVM values.
  Seven expanded Keccak helpers add public-oracle trace proofs: all remaining
  calls have public scalar arguments, exact arity, no heap arguments and known
  targets. The completed finite permutation control covers all 24 rounds and
  public-heap equality; actual callee bodies, provider inventories and named
  negative diagnostics have independent gate pins. Sponge and complete KEM/adapter
  trace composition remain open. See [the trace evidence](timing/EVIDENCE.md).
  V7 stays partial. The snapshot
  `dceff6e678f54ffd2679a0db8ff14de9194320824ad619fdf954d7fcb1b18e4b`
  preserves the corrected copy operands and enforces rejection of every declared
  javap exception table, malformed method boundaries and duplicate/backwards
  offsets. Fifteen additional real-javap/malformed-input regression tests cover
  those guards; selected bodies contain no handlers and are unchanged apart
  from the include path.
  The scalar-field store guard also binds the real assigned operand and rejects
  reference writes independently of alias annotations; twelve new controls
  include a live private-return counterexample. Existing certified methods have
  no field instructions, so their bodies and the residual scope are preserved.
  Its source/policy, 139-input inventory, helper contracts, execution controls and residual sets are
  checked independently of a data-only digest renewal. The extractor, splice,
  target-to-model-kind mapping and runtime contracts remain trusted; full value,
  alias/dispatch, implicit-exception and physical-timing refinement remain open.
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
3. Keep V7/V8 partial and all-complete unsupported until the 13 open owned trace
   roots, 19 assumed owned helper contracts, runtime timing and
   independent external expert evidence genuinely close.
4. If the HKDF final delivery store or production adapter changes, renew the exact
   input/tool/generated-source/class/provider/facade pins and their receipt
   validators, then rerun the gate regressions and all normal/narrow/all-required checks.
4a. If the nonce kernel, generated source, delivery inventory or PacketKey bridge
   changes, renew `formal/nonce/PRODUCTION-EVIDENCE.json`, the generated receipt and
   inputs, the typed nonce validator constants and the affected hash pins; do not
   extend the frozen historical SAW receipt to the new bridge.
   The reviewed nonce claim policy currently requires the legacy V3 status to
   remain `blocked`. Advancing that SAW status also requires an explicit policy
   renewal; it does not invalidate the separate nonce functional proof.
5. Do not convert agent-assisted development review into an independent external
   expert-review receipt.
