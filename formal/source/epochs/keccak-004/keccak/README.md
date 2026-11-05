# Keccak source replay for epoch keccak-004

This component replays nine actual body proof roots, nine direct audits, the
reviewed fifteen private-address tasks, six private-branch tasks, one owned
included-assumption audit control, and three stale full-result capture tasks.
It also resolves the same actual program with both observation plugins.
The nine proofs contain **1877 overlapping checks**, not 1877 unique theorems.
Every receipt says `qualification:false`: this component alone does not qualify
the parent epoch, Java delivery, physical timing, or production adoption.

`inputs.json` is the externally selected authority for options, exact counts,
errors, probes, mutations, package bytes and consumed authorities. Select its
SHA256 independently before running. A digest computed from the same unreviewed
output being accepted is not an external selection. All CLI paths and expected
digests are mandatory; there is no author-cache or installed-tool fallback.

The source input is the constructor's exact current85 view. The runner checks
its selected manifest and view receipt, freezes new inodes, then materializes the
pinned paired template as `formal/source/NativeKeccakTraceHarness.dfy` in a new
private86-source stage. This is not the production85 inventory. The parent epoch
also stores reviewed candidate source bytes as `candidate/*.dfy.in` so a reviewer
can construct the selected current view before production adoption; this runner
still requires an explicit authenticated `--source-root` and does not read those
candidate files as a fallback. Probes here remain `.dfy.in` and mutations are
unique exact replacements with selected before/after hashes in `mutations.json`.
Canonical frames are unchanged; the stale mutant alone widens the two documented
Theta loop frames so its intended full-tuple equality is the actual failure.

The externally selected coverage receipt is **consumed**, not rerun: all61 method
and18 function cases must be complete, their plain resolves must succeed before
negative plugin results, exact sources/tool sources/DLLs must match, and all354
raw logs must retain their bindings. Receipt bytes, case inputs, source and tool
maps, logs and selected DLLs are checked before and after this replay. Coverage
build provenance remains the separate reviewed receipt's scope; this component
performs no .NET build. The actual plugins run afresh on the base graph and the
specified semantic variants. Faithful secret branches and addresses must be
accepted by coverage while the exact paired trace equality fails. Forged and
omitted address observations must resolve first, then reject by their named KMC
diagnostic. Parse, frame, type, unrelated assertion, zero-match, timeout and
resource failures cannot substitute for a semantic control. Position-filter tasks
explicitly require Dafny's "assertions verified" summary unit; ordinary body and
symbol-filter tasks require the ordinary "verified" unit.

The runner is self-contained. It authenticates the prior source constructor as
provenance data and does not execute external Python helpers. Its captured-byte
`load` primitive and tests retain the reviewed compile/exec discipline; no loader
bytecode lookup is used. Python must be invoked with `-I -B`. Child processes use
fresh private HOME/temp/config directories, a fixed system PATH and only host
locale/TZ settings. No inherited Python, managed/native-loader or compiler
selectors pass through. Commands use explicit authenticated Dafny and solver
paths from a verified fresh copy of the complete Dafny distribution. Plugin and
authority captures are checked against their selected digests at capture time.
The selected official285-file Dafny distribution and archive and selected
Python/hashlib identities are checked before and after; the Python standard
library and host OS remain trusted. Unused Java/runtime entries in the broader
SHAKE tools authority are not claimed as executed evidence here. Only owned
subprocess groups are terminated, including TERM-resistant descendants; direct
children are waited and reaped. Failing/partial logs and a failed
receipt remain available; only all44 exact outcomes yield `status:passed`.

Use explicit paths appropriate to the selected installation, for example:

```sh
PYTHON=/absolute/selected/python3.14
PACKAGE=/absolute/checkout/formal/source/epochs/keccak-004/keccak
"$PYTHON" -I -B "$PACKAGE/test_replay.py"
"$PYTHON" -I -B "$PACKAGE/replay.py" \
  --inputs "$PACKAGE/inputs.json" --expected-inputs-sha256 SELECTED_PACKAGE_MANIFEST_SHA256 \
  --source-root /absolute/authenticated/current \
  --source-manifest /absolute/checkout/formal/source/epochs/keccak-004/manifest.json \
  --expected-source-manifest-sha256 294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec \
  --view-receipt /absolute/source-views/receipt.json \
  --expected-view-receipt-sha256 0205a06e606e02ba1753a1f905c660f8b642b091bf68104dabdd179c29702890 \
  --helper-root /absolute/checkout \
  --tools-manifest /absolute/selected-inputs/tools.json \
  --expected-tools-sha256 18624818cfd48e4854325007a250cf43ef88c5aa332c5dc2de60b27b61adc19e \
  --dafny-root /absolute/dafny-4.9.1-macos-arm64 \
  --dafny-archive /absolute/dafny-4.9.1-arm64-macos-11.zip \
  --coverage-receipt /absolute/coverage-run/result.json \
  --coverage-package-root /absolute/coverage-run/frozen-package \
  --expected-coverage-sha256 cd10f45024d20e2384fd5cb193445da677a7d102fcc0bd0099223bb0dd32f45b \
  --method-dll /absolute/coverage-run/KeccakMethodCoverage.dll \
  --function-dll /absolute/coverage-run/KeccakFunctionCoverage.dll \
  --output /absolute/new-private-run
```

`--admission-only` performs all authority checks and output admission, creates
nothing, and reports `status:admitted`, never a proof pass. Existing outputs,
input/output overlap, aliases, duplicate JSON keys and source/tool drift reject.
The bounded tests exercise actual files, valid poisoned bytecode, raw-log
bindings, immutable copies, closed environments and collected timeout behavior.
