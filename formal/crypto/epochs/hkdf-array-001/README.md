# HKDF array-input delivery epoch

This epoch keeps three subjects distinct: retained native evidence on the
original Keccak capsule, completed current HKDF v2 evidence, and a fresh finite
whole-library/bundle validation. No epoch result closes global V7, physical JVM
timing, compiler/adapter refinement or independent expert review.

`inputs.json` is intentionally absent until the controller reviews the complete
measured input and class maps. There is no default or placeholder policy digest.
Every command requires its externally selected SHA-256. Missing inputs or a
partial replay fail before a qualifying report can be written.

## Existing authorities

The original source authorities remain under `formal/source/epochs/keccak-004`:

- Parent `parent/parent.py`: `28a891c07dd5f4124343f5d50ac406dd1222d90fa17078e5f45f3ee598d46845`.
- Parent policy: `8bb7b5d157f46db802ce5bd118c79ef365377f708667580bc0d89c1bf1c317d2`.
- Capsule archive: `13b4ec1c9175179c3eddcc42f919ddc838447d413766e1c7ba21239a750d79f1`.
- Capsule index: `fc8f3d1b90bab8af9d40285237c79be60bf802721299594321d4d7abdb5083a3`.
- Selected Keccak delivery config: `51cae8d5ca9f8562dbccda60be3a00818e0d996e5da87afcbc641c6f5857f0ca`.

`check_retained` authenticates the original prepared capsule and full Baf/source/
epoch views, runs the original historical ledger and eight-component cold
checks, and revalidates all indexed retained artifact receipts/raw logs. It binds
every native stage input, generated provider/source and all 66 canonical classes
to the candidate. It preserves the seven-theorem polynomial closure rule and
rejects old whole-Poly, ML-KEM composition or erasure-package reuse.

The old sealed 467-input/468-class identity supplies the predecessor maps. Its
fixed `checkout_identity` and fixed source constructor are never applied to the
new subject. Candidate class counts are measured and checked by the unchanged
whole-artifact API; the epoch does not presume a two-class change.

The historical FULL006 replay used HKDF manifest
`9873d38bc1a98ea8675bbab660f8252be7b6e69acdda30eddd6ce4e7034b2919`.
Its completed portable receipt is
`821a065b12b4454247cac2c8d7eb320eec392e99f7104c70069dd48dffb58d1f`;
the unchanged full tool maps hash to
`5012e1779cea551046c85f7d1bbf6625930cbc0a39af54cc178a025c6807a49a`.
These are historical HKDF component facts, not a new delivery qualification.

Subsequent review found that Python optimization could disable acceptance
assertions in the producer tooling. FULL006 used an unoptimized interpreter;
its actual raw outcomes remain evidence for that original invocation. The
hardened producer uses unconditional acceptance checks, rejects optimized direct
replay before reading the manifest, and requires actual positive-command exits
to be zero. The selected successor manifest is
`e4e184d2449ac3802de24392243cbccafe9e8f88618a45cdab44ef98ba9e041c`.
Fresh FULL007 completed all 340 commands and drained every owned process group.
Its emitted portable receipt is
`76dd675a1b47bb3753fd5112da02213867c67b3480cbc625a2562a1858e3f4ed`.
Independent rederivation matched the emitted and staged receipts, all 78 source
inputs and the 2,358 indexed raw files. This remains bounded component evidence
with `qualification: false`. The retained proposal files below still select the
historical producer and receipt; they cannot qualify the current source by
changing a receipt hash or relabeling old execution.

`check_hkdf` authenticates the complete raw output tree, rederives the portable
receipt using its selected current `source_evidence.py`, and calls the shared
`scripts/security/check_crypto_obligations.py::validate_current_hkdf` on the
explicit candidate root. That validator retains all current V1/V2 component,
claim, source, control, producer and independent ledger receipt-pin checks. Its
`full_ledger`, `globalV7` and `artifactqualification` remain false. The canonical
proof counts are body 257, sequence NI 11 and array NI 13 (281 aggregate), plus
257 in each mixed proof. Domain/audit/control results remain separate. Each JDK
retains the original 45-case/2766-assertion suite and the new 150-case/346-assertion
suite separately.

## Selected delivery successor

`delivery.json` is derived from the selected Keccak configuration above. Its
SHA-256 is `b4bf8bf21e2a4b96ae057f3604cbe6429ab526cc6fc8d6e022ac0f903de9d9ea`.
Exactly one existing generated-source pin changes:

`io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java`:
`e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a`
to `4d44ac808e9f19c40de01c3201d229c265a503a63c7afa8bacf4dbbfe9230891`.

All other native, provider, control, compiler and runtime configuration values
are unchanged. The controller has adopted this `b4bf8bf2` successor as the source
checkout's current canonical config; the original Keccak config remains
`51cae8d5`. Construction maps only the explicit
`formal/crypto/delivery.json` target to this new selected configuration. It does
not rewrite the original capsule, source checkout or published 0.8.1 artifacts.
At the FULL006 checkpoint the candidate ledger, hash
`82ac687837ca790d4b4bea8fcfbf298061537528431842501830153ecf22acc9`,
explicitly pinned this candidate config. The hardened current ledger preserves
that configuration selection and rejects the historical producer receipt.
Independently selected successor input maps, new delivery stages and actual
artifact validation are still required. Neither the interrupted
qualification nor the unqualified class-map measurement supplies that evidence.

## Portable policy contract

The closed top-level schema is `microproxy.hkdf-array-epoch-inputs/1`, with epoch
`hkdf-array-001` and `qualification: false`. Unknown keys, duplicate JSON keys,
unsafe/case-aliased paths, symbolic links, hard links and malformed hashes are
rejected. The policy is authenticated again before every layer. In-memory policy
mutation cannot replace the externally selected authority.

The required fields are:

| Field | Exact contents |
| --- | --- |
| `predecessor`, `candidate` | Each has `inputs` and `classes`, complete relative-path SHA-256 maps. The predecessor must equal the selected old sealed maps. Every source/producer/tool used by the new route belongs to the candidate map. |
| `allowed` | `inputs` and `classes`; each contains exact `changed`, `added`, `removed` maps. Changed entries require both `before` and `after`; added/removed entries require their actual hashes. No prefix exceptions or omitted deltas. |
| `retained` | `ci` and `selection` file references plus `prepared_receipt_sha256`. Original prepared and retained-data locations are runtime operands. |
| `hkdf` | `manifest`, `receipt`, `projector` file references; exact `producers` map; complete `raw_files` map; `tool_map_sha256`. Raw output location is a runtime operand. |
| `delivery` | `predecessor`, `config`, `native_evidence`, `api` file references; `build_outputs` below; integer `timeout` in seconds, at most 7200. The evidence envelope and every referenced receipt must belong to the authenticated constructed project. |
| `tools` | `runtime_sha256`, `python_sha256`, `jdk21_tree_sha256`, `jdk25_tree_sha256`, `maven_tree_sha256`, `maven_repository_tree_sha256`. Tree hashes use canonical `map_sha`; JDK/Maven tool trees use the existing complete typed tree snapshot. |

A file reference is exactly `{"path": <repo-relative path>, "sha256": <hash>}`.
Every reference and producer pin must agree with `candidate.inputs`.
`inputs.json` cannot hash itself. The one constructor mapping for the canonical
delivery config is explicit; every other input is read from its own selected
relative path. No directory or path-prefix exclusions are admitted.

`delivery.build_outputs` has exact `directories` and `files` maps. Each directory
is one selected reactor POM's own `target` directory; its value is the selected
POM reference. An individual `.flattened-pom.xml` may be selected in `files` with
the same POM reference only when the actual build uses that plugin. The current
reactor proposal lists `target`, `zstd-decoder/target`, `http2-codec/target`,
`http3-codec/target`, `quic/target`, `microproxy/target`, `microproxy-otel/target`
and `microproxy-starlark/target`; `files` is empty. There is no general rule for
arbitrary directories named `target`.

The complete project map is partitioned after execution. Every existing file,
including a fixture under a selected output directory, remains an immutable
input. Only newly created files in the finite declared output locations are
build outputs. Any other added source, extension, tool or metadata file fails.
`INPUTS-BEFORE/AFTER.json`, `BUILD-OUTPUTS-AFTER.json` and the complete
`PROJECT-TREE-AFTER.json` are separate. Completion asserts exact input and selected
tool equality; it does not assert that build outputs existed before execution.

The explicit source-only schema `microproxy.hkdf-array-source-inputs/1` retains
the authenticated predecessor maps but has only `candidate.inputs` and
`allowed.inputs`. It has no candidate classes or class delta and omits the
not-yet-collected Maven dependency-cache pin. Its tool operands still pin the
actual Python, runtime JAR, complete JDK trees and Maven installation. Only
`load_source_policy` / `prepare-source` admit this schema. `qualify` rejects it
before creating any output. No old468-plus-two prediction supplies new authority.

Runtime paths are never committed into the policy. `bind_runtime` and the CLI
accept explicit `prepared`, `data`, `hkdf`, `cache`, `junit`, `maven` and
`maven_repository` roots. The report records the actual operands. Qualification
also requires explicit runtime JAR and JDK21/JDK25 homes. Full before/after JDK
trees must match the completed HKDF replay. Maven and dependency contents are
selected and copied to a private child home; the original caches are inputs.

## Execution and output

The public interfaces are `load_policy`, `check_delta`, `check_retained`,
`check_hkdf` and `qualify`. `prepare_project` constructs a new complete isolated
project from authenticated original views plus only selected candidate inputs.
It records the complete project map. All outputs must be fresh and disjoint in
both containment directions from every declared source/evidence/tool root.

CLI modes are `admit`, `prepare`, `prepare-source`, `measure` and `qualify`; run
with Python `-I -B`.
`--help` lists the exact arguments. The policy is never inferred from local
files. The code executes captured pinned Python source bytes; it does not trust
ambient `.pyc` files. The runner also pins its admission bootstrap before using it.

`measure` also requires an explicit controller execution window. It performs one
unqualified private package build on the selected source-only project, with an
initially empty private Maven dependency cache. Explicit private user/global
settings mirror dependencies to HTTPS Maven Central; an explicit
`-Dmaven.repo.local` binds the cache independently of Java's default home.
Complete source, selected tool, class/JAR and dependency-cache maps are saved
with the actual raw output, exit and owned-process records. This establishes no
closed-tool, source proof or whole-artifact qualification. Its entire resulting
cache map, including metadata files, and actual complete class map must be
independently selected in the later full policy.

`qualify` performs proof/compiler/JVM work and requires the controller's execution
window. It creates one stage under the selected new config, packages privately
with JDK21 using `mvn -o -q -pl microproxy-starlark -am -DskipTests package` and
the explicit private settings/cache operands above, compares
the entire actual class map and exact delta, checks the HKDF 12-class JAR subset,
then invokes the unchanged `crypto_current_release.validate_current_release`.
Repository and tool roots are the same new project. The API performs its own
required stage reproduction; there is no third manual replay.

The original whole-artifact checks remain responsible for all library, crypto,
retained-library and runtime classes; notices; duplicate/MR entries; nine
origin-checked handshake fixtures and nonce behavior on both JDKs. The HKDF subset
hook adds no exception to that API. Inputs, tool maps and artifacts are checked
again after validation. Raw child output, exit and confirmed process-group
ownership records are durable before parsing. Failure leaves an incomplete
wrapper report, never a completed qualification.

No command installs, deploys, publishes or overwrites 0.8.1 artifacts.

## Retained qualification and fresh CI identity

The reviewed [cold CI checker](CI.md) has a separate
[operand contract](CI-CONTRACT.md). It preserves the actual Darwin qualification
and its raw paths, while authenticating fresh local preparation, source and
compiled identities independently. Recorded Python invocation spelling and
resolved binary identity have separate authenticated roles. A fresh local
preparation digest cannot replace the retained Darwin preparation authority.

The checker is implemented and its DATA regressions pass, including explicitly
synthetic full-flow tests. Actual successful new Darwin qualification is still
required before selecting a retained index or running the full CI admission.
The static code and unit fixtures supply no qualification receipt themselves.

The original prepared Baf directory acquired exactly two `.simba` metadata
files. It was preserved. New original views were built with the unchanged parent
constructor and authenticated original capsule inputs, keeping controller cwd
outside those views. Their prepared receipt is
`5329abe5b0ed6cd1daca2fe342d7815e1c50ead0451c2a007f749e1dade31823`,
views receipt `31c0349540bcee80c89af30f978044e51f01e73e6130704a849b4ceb12fa5ffb`.
Strict re-admission confirms Baf3142 and original epoch3195 exactly. These are
original-subject preparation facts; the new candidate remains separately selected.

`native-inputs.json` relocates the unchanged selected native receipt
`370c08f6984b3c03d7644377af7ffaeeb4e14962110db69d831f6acebe346827`
to `retained-native/receipt.json`. The receipt bytes are identical to the original
capsule. The new envelope pins its unchanged 20-source native graph and passed
the unchanged native data validator. It does not assert a new proof execution.

## Data-only verification

```sh
python3 -I -B -m unittest discover -s formal/crypto/epochs/hkdf-array-001 -p 'test*.py' -v
python3 -I -B scripts/security/test_crypto_current_release.py
```

These checks do not run the real SMT/compiler/JVM/Maven qualification. Actual
`formal/crypto/test_bundle_checks.py` fixtures require Java and run only in the
controller's permitted tool window.
