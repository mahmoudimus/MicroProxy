# Keccak source proof and control evidence

This data bundle preserves the final run002 report, all 88 command stdout/stderr
logs, its terminal validation, evidence index and independent input selection.
All copied report and log bytes are unchanged. `files.json` is the exact SHA256
map of the other files in this directory; it excludes itself. No tool, source,
variant, DLL or proof-cache tree is included, and no production `.dfy` is added.

The recorded replay passed all **44 tasks**: nine actual body proof roots with
**1877 overlapping checks and zero errors**, nine clean direct audits, a combined
resolve with exactly 11 method and four function-body coverage roots, 15 private
address tasks, six private branch tasks, one included-owned assumption audit
control, and three stale full-result capture tasks. These are overlapping checks,
not 1877 unique theorems. The assumption control reports exactly one intended
finding; the negative semantic controls fail at their selected diagnostics or
equality assertions. The selected implementation also passed **13 bounded tests
and 14 actual CLI admission controls**. These test counts describe their recorded
validation; their individual logs are not duplicated in this narrow bundle.

`qualification:false` and parent-epoch status **pending** apply throughout. These
records provide component source proof/audit/observation-control evidence. They
do not qualify the parent epoch, physical timing, Java/compiler/JVM behavior,
production adoption, whole-crypto security or cryptographic hardness.

## Selected identities

| Item | SHA256 |
| --- | --- |
| Proof runner, `formal/source/epochs/keccak-004/keccak/replay.py` | `01f59bf24463faa7ebbfbec5dfb0a3b2a9fcd367b9e7e60505281fd2caba6912` |
| Task/input manifest, `formal/source/epochs/keccak-004/keccak/inputs.json` | `8d16aa8af321ab74b1e899ddfb11628efcee1826c4e58854d8090f8820560dcd` |
| Bundled `result.json` | `96ea8f409ed401245961d93e53a86f6f1fe56fb0ca63e3eb1c917774e8b26f56` |
| Bundled `TERMINAL-VALIDATION.json` | `bf35a74a6d522756c6569adf541abd0bb1d86a210344979680240080bcbe4c7c` |
| Bundled `EVIDENCE-INDEX.json` | `9e18bf1fdc81448d7a1219a951f27184c7964497661caf4f5b9a6e839eaa253d` |
| Bundled `ROOT-SUMMARY-UNIT-SELECTION.json` | `79de9513fa958ef35b49b37e21e469ce677939e3ad48f311122721a9b500a534` |

The final source authority contains 85 production source files. The replay
materialized its selected paired harness in a new private 86-source stage, then
added the two explicit private probes to control variants. None of those stages
is published here. The immutable NativeKeccak source identity is
`d1682b1b9f6014d2d8d290841801bd70d4771feaf90581bde6bb0791723d60df`.

The earlier run001 remains failed/historical. Its first 41 tasks passed, but the
old classifier rejected a legitimate position-filter summary saying
`11 assertions verified`. The final selected classifier requires one anchored
summary with an explicitly declared unit, rejects mixed/extra summaries, and the
fresh run002 passed all 44 tasks. No run001 result is relabeled as success.

## Relocation and reproduction boundary

Absolute paths in the unchanged reports and index describe the original
execution. The original result was under
`/Users/mahmoud/.cache/microproxy-formal/issue117-full-composition-20261104/keccak-public-proof/run-002/`;
its command log paths ended in `logs/<label>.stdout.log` or
`logs/<label>.stderr.log`. Those absolute paths are metadata. A relocated log
validator must map each recorded command label and stream to the corresponding
bundled relative `logs/` file, check its selected hash, and run the selected
classifier against those bytes. It must not open an original absolute path as a
fallback. The code and task manifest are source-controlled at the paths above;
they are not copied into this data bundle.

The actual relocated validation used captured, hash-checked current runner bytes
and the independently selected task rules, checked all 88 bundled log hashes and
replayed every actual result classifier. A read-only open allowlist admitted only
the relocated bundle and those two explicit code/manifest inputs; original
private report/log paths were denied. This authenticates historical data after
relocation. It is not a fresh Dafny proof execution in the reader's environment.

The **79 coverage controls and their 354 raw logs remain a separately selected
prerequisite and are not bundled here**. The final proof replay authenticated
that coverage package before and after its run, on the same source graph, and
ran both actual plugins for its selected semantic variants. It did not rerun the
79 controls. The selected coverage result SHA256 is
`cd10f45024d20e2384fd5cb193445da677a7d102fcc0bd0099223bb0dd32f45b`,
with method DLL `a4905de3b46e39fd819dc7ad5e5245bbae449080bc8f2e6039cc2de69f33b3fd`
and function DLL `af1f0fec7e98cd51e4172b8ff98826ed830eee18df4d8beaa91c812d617e68dd`.
The coverage report embedded as metadata in `result.json` is not a replacement for
that complete explicit package or for current-source body proofs.

For a new environment, supply and authenticate the explicit coverage package
with all required source/tool/DLL/raw-log bindings, or replay and requalify
coverage under a supported, independently selected tool profile and review/select
new source-replay authorities for that receipt. The present task manifest fixes
its recorded coverage, source-view and tool authorities. This bundle neither
adapts them silently nor substitutes an old coverage pass for a new proof run.
The proof runner's source-controlled README documents the mandatory CLI inputs;
new proof executions require those explicit authorities, authenticated tools and
a fresh private output directory.
