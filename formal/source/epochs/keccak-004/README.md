# Keccak epoch004 authenticated source views

This component constructs two byte-authenticated source views. Its receipts are
always `qualification:false`, `scope:source-views-only`. It runs no Dafny parser,
compiler, solver, proof, Java generation or runtime checks.

The source-view constructor and its eight tooling inputs passed independent
engineering review under the recorded macOS profile. The externally reviewed
SHA256 of the unchanged `manifest.json` is
`294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec`.
Every invocation requires this digest explicitly; no manifest success flag
authorizes itself. A future manifest change requires a newly reviewed digest.
The constructor checks the digest before parsing the manifest
or importing its declared validator. It additionally fixes the two reviewed
85-source map digests and the three authorized changed paths in code.

```sh
python3 -B formal/source/epochs/keccak-004/views.py \
  --manifest /absolute/path/to/manifest.json \
  --expected-manifest-sha256 294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec \
  --candidate-root /absolute/path/to/current-candidate \
  --output /absolute/fresh/output
```

The output parent must exist. Output must be outside the candidate, manifest
component and constructor component, and cannot be an ancestor of those inputs.
Overlap checks use physical directory identities along existing ancestor chains,
so case aliases are rejected without treating distinct Linux names as aliases.
The constructor rejects symbolic links, selected-file hard links/identity aliases,
unsafe relative paths, existing output, changed inputs and inventory drift.
It never follows a producer cache path or reads Git during admission.

The predecessor is fixed released Git
`baf0e693c7d4344c7232ea3c3b9d64e1fac03ab3`, tree
`c62fced90b167d19bc6bc5a46fb68ba448490abc`. Only its three changed source files
are stored here, as `.dfy.in` snapshots. Current candidate bytes must contain the
reviewed replacements for NativeKeccak, NativeShake and native_shake_domain,
with every other production source unchanged. The 85-source enumeration excludes
only the exact historical Select package subtree; all 311 files of that package
are authenticated separately. Missing/extra production `.dfy` files fail.

The explicit domains are:

- Distinct predecessor85/current85 source maps, differing at exactly three paths.
- Support files, disjoint from production85: the unchanged Select package,
  helper/profile inputs, historical consumer manifests and their non85 inputs.
- Complete ownership/API/polynomial consumer maps. Every entry must match the
  predecessor85 plus support union, and each original manifest's parsed input
  map must equal its complete declared map.
- Eight separately authenticated current coverage tooling files, including the
  captured build-authority helper and its exact reference-pack catalog.
- The separately authenticated `NativeKeccakTraceHarness.dfy.in` template.

Both views copy only these explicit inputs. `historical/` substitutes the three
old snapshots; `current/` retains the three current sources. The unchanged,
pinned Select `validate_current_inputs()` is imported from the reconstructed
historical view and called through its public explicit-root API. Its admission
must return85 sources,311 package files and8 used inputs, with both old profile
identities. No validator policy or module globals are patched.

The paired harness remains a template in both views. Its declared live target,
`formal/source/NativeKeccakTraceHarness.dfy`, is not materialized here. A later
replay stage must identify itself separately if it adds that 86th file; it cannot
be re-admitted as production85.

A complete receipt records both exact source/full-file maps and deterministic
map hashes, source origins, manifest/constructor/tooling identities, legacy
input admission and before/after input stability. View files are copied into new
inodes and made read-only. Construction failures after output creation leave a
failed receipt; an invalid input detected during admission creates no output.
Historical manifests present in the current view remain historical-only.

Run the real filesystem regression suite against an explicit candidate and a
fresh work directory, with the same externally selected manifest digest:

```sh
python3 -B formal/source/epochs/keccak-004/test_views.py \
  --candidate-root /absolute/authenticated/test-seed \
  --expected-manifest-sha256 EXTERNALLY_SELECTED_TEST_DIGEST \
  --work-root /absolute/fresh/test-output
```

These views do not establish current Select, ownership, SHAKE API, polynomial,
noninterference, functional Java or artifact claims. Those current consumers
still require their separate proof/control receipts, appropriate source/codegen
and delivery checks, and reviewed dispatch. Existing historical packages,
receipts, guards and Keccak fixtures remain unchanged. Physical timing and
compiler/runtime/provider/expert-review boundaries remain outstanding.
