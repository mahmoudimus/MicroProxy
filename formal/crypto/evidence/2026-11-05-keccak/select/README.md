# Current Select consumer evidence

This collection has scope `current-select-only` and `qualification:false`.
The unchanged producer receipts call the scope `current-select-consumer`.
It contains the final run004 receipts and their complete data closure: 183
command logs (173 semantic logs), five verifier CSVs, and the final 46-test
result. Original producer bytes and absolute path metadata are preserved.
No source, tool, DLL, generated Java/class or package-cache tree is included.

Reconstruct the candidate source from the public
[`epoch004/candidate` templates](../../../../source/epochs/keccak-004/candidate/README.md),
rather than using the unmodified committed production files. The recorded run
used an authenticated current view containing those exact three source bytes. Prepare a fresh private source
copy outside Git, apply exactly the three `.dfy.in` templates to the destinations
declared there, and run the authenticated epoch source-view constructor. The
complete 85 maps must admit exactly those three differences. Use the resulting
explicit current/historical views and externally selected receipt digest for a
new replay; a new output path produces a new receipt digest.

## Fixed identities

| Input or result | SHA256 |
| --- | --- |
| Epoch manifest | `294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec` |
| Recorded source-view receipt | `0205a06e606e02ba1753a1f905c660f8b642b091bf68104dabdd179c29702890` |
| Focused expectation policy | `ca8c5015bdc1733f196e7dcfc114109386651657799bb4201918882afdf6beee` |
| Select replay | `71c96c708525889aca8527a6e0fba14192406ee997b9c55990575070d80d374a` |
| Select regression tests | `ee2a007a0c9b70820044802c0061de4fc97d129e815c0831f1556d44517c2b85` |
| Same-directory build evaluation | `4e249bc51c57f4cd9c5c6bc7b5f08fdc106a758b70ea8684526aa4d3e77c66e4` |
| Fresh SourceCoverage DLL | `2785f06aef69011784a64f7cf5cfbeded0c3722760d9ca4317778b12e932cd67` |
| `run-004/report.json` | `f5607208e759095234f93117c59a6366a1057440aaf901ca3a6cb085ab3f3183` |
| `run-004/semantics.json` | `731fb6ffff937916c1fbf3b725c25964156938dfe621ed4bbf74cafdb2b12377` |
| `FINAL-RESULT-004.json` | `1dbb8e71f96798ba79b6098c295f056619cfd8bfff4e986f1c17fce0341fd780` |
| Original evidence index | `7d830528bb3185dcf5f2863f734e67743bb6f2e129400ea0408b0427b7f12816` |

## Recorded invocation

The following is the exact original invocation. These absolute paths identify
the producer environment; validation of this collection reads the relocated
files and does not require those paths to exist.

```sh
python3 -I -B /Users/mahmoud/.codex/worktrees/crypto-release-artifact/microproxy/formal/source/epochs/keccak-004/select_replay.py \
  --manifest /Users/mahmoud/.codex/worktrees/crypto-release-artifact/microproxy/formal/source/epochs/keccak-004/manifest.json \
  --expected-manifest-sha256 294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec \
  --views-root /Users/mahmoud/.cache/microproxy-formal/issue117-full-composition-20261104/actual-branch-views-001 \
  --expected-views-receipt-sha256 0205a06e606e02ba1753a1f905c660f8b642b091bf68104dabdd179c29702890 \
  --expected-expectations-sha256 ca8c5015bdc1733f196e7dcfc114109386651657799bb4201918882afdf6beee \
  --profile macos-sdk10.0.400 \
  --dafny /Users/mahmoud/.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny \
  --dotnet /usr/local/share/dotnet/dotnet \
  --targeting-packs /Users/mahmoud/.cache/microproxy-formal/issue117-full-composition-20261104/keccak-portable-coverage/run-003/build-authority/archives \
  --output /Users/mahmoud/.cache/microproxy-formal/issue117-full-composition-20261104/keccak-current-select/run-004
```

The exact final regression invocation was:

```sh
python3 -I -B /Users/mahmoud/.codex/worktrees/crypto-release-artifact/microproxy/formal/source/epochs/keccak-004/test_select_replay.py \
  --expected-manifest-sha256 294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec \
  --views-root /Users/mahmoud/.cache/microproxy-formal/issue117-full-composition-20261104/actual-branch-views-001 \
  --expected-views-receipt-sha256 0205a06e606e02ba1753a1f905c660f8b642b091bf68104dabdd179c29702890 \
  --work-root /Users/mahmoud/.cache/microproxy-formal/issue117-full-composition-20261104/keccak-current-select/tests-final-002 \
  --evidence-root /Users/mahmoud/.cache/microproxy-formal/issue117-full-composition-20261104/keccak-current-select/run-004
```

## Outcomes and limits

All 25 typed controls matched: four accepted and 21 named rejections. Each control
first resolved without the plugin. The raw parser records establish the exact 20
native inputs or 21 paired inputs, tied to the current 85 map. All 114 parser
commands and all 173 semantic raw-log references are checked by the fixed consumer.

| Proof | Verified | Intended errors |
| --- | ---: | ---: |
| Focused Select and its four ghost helpers | 8 | 0 |
| Faithfully observed modified Select and helpers | 118 | 0 |
| F2 private loop-bound control | 7 | 1 |
| Original Select paired harness | 6 | 0 |
| Observed paired counterexample | 1 | 1 |

The focused symbol set is exactly `NativeMlKem.Select`, `SelectDiffPrefix`,
`SelectDiffStep`, `SelectOutPrefix`, and `SelectOutStep` in that module. Proofs
retain 30s/50M/2cores and their original case-split/isolation settings. These are
focused counts, not the full NativeMlKem graph. The final 46 tests passed in 12.267s
with no skips or expected failures; copied actual logs cover wrong, mixed,
duplicate and unanchored summary lines for all five proof cases.

`relocation-check.json` records validation of this bundle through the exact
captured `check_semantic_evidence` implementation. Public code, helper, manifest and package bytes are captured and authenticated
before the guarded check. During validation an open audit allows only this
evidence root; private producer/cache reads and process
fallback are denied. All original indexed files and raw references are rehashed.
`files.json` indexes every other shipped file, excluding itself.

The receipts remain a scoped consumer result. They do not establish parent epoch
qualification, full NativeMlKem/kernel or functional/Java/delivery qualification,
whole-proxy composition or physical JVM timing. C#/Python observation coverage,
Dafny/compiler/runtime/provider assumptions and expert review remain explicit
boundaries. Original stage wording in the receipts is retained unchanged.
