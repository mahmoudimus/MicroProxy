# Keccak epoch 004: current SHAKE ownership and API-state consumers

This versioned successor replays the unchanged ownership and API-state harnesses
against the actual Keccak epoch 004 dependencies. Its authority is an externally
hashed successor manifest and an externally hashed receipt from the approved
source-view constructor. Old manifests remain historical input-domain evidence;
they are never repinned, modified, or used to admit the current production source.

The two consumer source graphs are separately discovered with the pinned Dafny
parser. Included bodies, consumer roots, and each graph member's audit are checked.
The three ownership semantic failures, five API-state semantic failures, two
included-body assumption injections, and the BOM/inline-comment parser controls
are required. Controls require an exact assertion location and a semantic failure;
parse, resolution, resource, timeout, skipped, and internal failures do not count.
All unchanged legacy replay unit tests also run in the frozen input tree.

The first invocation used `observation-inputs.json`, with unknown positive proof
counts, and records status `observed`. Its raw logs and report are retained. Only
a second invocation with the externally pinned successor manifest, containing reviewed
counts and the first report hash, may record `complete`. The preserved observation report and all its raw log hashes are checked before
and after the second replay. Counts are not inferred from old receipts. Both invocations require fresh output directories, explicit
Dafny/solver/archive paths, and the same 30-second/50M-resource/two-core/case_split
policy. The complete extracted tool distribution is authenticated against the
pinned archive before and after execution. No tools are installed or modified.

Interface:

```
python3 -I -B replay.py \
  --manifest /absolute/path/to/inputs-v2.json \
  --expected-manifest-sha256 EXTERNALLY_REVIEWED_SHA256 \
  --view /absolute/path/to/approved/current \
  --view-receipt /absolute/path/to/approved/receipt.json \
  --expected-view-receipt-sha256 EXTERNALLY_REVIEWED_RECEIPT_SHA256 \
  --dafny /absolute/path/to/dafny \
  --solver /absolute/path/to/z3/bin/z3-4.12.1 \
  --archive /absolute/path/to/dafny-4.9.1-arm64-macos-11.zip \
  --observation-report /absolute/path/to/preserved/observation/report.json \
  --output /absolute/path/to/new/output
```

Input aliases, physical hardlinks, symlink components, case aliases, unknown or
omitted source/control inputs, output overlaps, and authority changes are rejected.
All proof commands, statuses, raw log hashes, source maps, package pins, and tool
maps are retained in each report. Source and tool maps must match before/after.

`qualification:false` and `parent_epoch_status:pending` are deliberate. These
results cover Dafny source ownership/freshness/frames and public API state/status.
They do not establish SHAKE operation-trace composition, whole-crypto composition,
current Select assurance, Java/compiler/JVM refinement, exclusive Java ownership,
physical timing/erasure, or qualification of the parent epoch. No Java is generated.

## Execution policy v2

`inputs.json` remains the original selected authority, SHA-256
`2717cd2d974966605629bbc4103b968ffc357f4682836a54c2fa81f4b7a13924`.
`inputs-v2.json` copies every source, count, control, budget, derivation, and tool
field unchanged. Only the three `package_inputs` hashes change to identify this
reviewed execution-policy implementation, tests, and README. Original observation
and replay receipts remain historical evidence; they are not current execution
qualification. A fresh complete replay under the externally selected v2 manifest
is required.

Every imported pinned helper now executes a captured source byte string only
after its expected SHA-256 matches. The loader never consults bytecode caches,
registers the proper module context, and restores any previous registry entry on
failure. Real poisoned-cache and post-capture source-substitution regressions
exercise that boundary.

The successor owns child execution. Every direct Python child receives `-I -B`;
every child receives a fixed environment allowlist and a separate initially empty
0700 HOME, temporary, XDG config/cache/data, and .NET CLI home. Parent environment
values never pass through. PATH and locale are fixed. Python startup/cache,
.NET startup/profiler/dependency/runtime, and native loader selectors are absent.
The stdout/stderr merge, exit statuses, process-group timeout cleanup, command
arguments, proof flags, and semantic failure classification retain their original
behavior. Per-command environment/actual-argv records are hashed in the report.
The unchanged legacy tests run from fresh pinned copies under isolated Python;
their one nested timeout probe inherits this closed environment.

Run the successor regression file directly with isolated Python:
`python3 -I -B test_replay.py`. The regression loader also compiles source bytes,
and real child processes check poisoned PYTHONPATH/hooks, every inherited selector,
private configuration state, merged output/status, and timeout rejection.
The installed Python interpreter and standard library remain a host trust boundary.
