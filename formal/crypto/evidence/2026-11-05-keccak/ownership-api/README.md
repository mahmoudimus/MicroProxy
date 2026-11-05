# Keccak 004 ownership/API consumer evidence

This data bundle makes the selected consumer replay independent of private cache
receipts. It contains no tool distributions, compiled classes, bytecode caches,
or duplicate source trees. Receipt bytes and relative raw-log names are unchanged.
Absolute paths inside receipts and the index describe the historical executions;
they are metadata, not paths that a relocated observation admission must open.

`observation-002/` contains the original observation report and its 62 referenced
raw logs. That observation is count-derivation data from the predecessor execution
policy. It is never a v2 pass bit. The v2 runner checks its externally selected
report hash, consumer maps/counts/control inventories, and all 62 relocated logs,
then performs an entirely new proof/audit/control replay.

`final-v2/` contains the v2 report, all 62 raw logs, all 62 corresponding environment
records, and the unchanged `RESULTS-v2.json` index. The recorded v2 replay verified
ownership 1,865 included-body / 20 root obligations and API state 1,871 included-body
/ 51 root obligations, with zero errors; 18 clean audits and all semantic,
included-assumption and parser controls passed. Both consumers have nine sources
and fifteen inputs. The environment records capture the actual argv, fixed
allowlist and private configuration state used for each command.

## Immutable identities

| Item | SHA-256 |
| --- | --- |
| Bundled observation report | `16fc6e0545fbbd57d186fe7497283fd70c9a998c16249766353c09ebe9865db0` |
| Historical observation manifest, `formal/source/epochs/keccak-004/ownership-api/observation-inputs.json` | `b48d2ab7cecd340f0f3131255b981424c6a71c82ebde0be4970295afb2501385` |
| Historical observation runner | `df4d9fc334bb0c8a51cb1ddc8379f6da7a94385a985af5cc5a08971bd8ffc3ac` |
| Selected source/count predecessor, `formal/source/epochs/keccak-004/ownership-api/inputs.json` | `2717cd2d974966605629bbc4103b968ffc357f4682836a54c2fa81f4b7a13924` |
| Selected v2 manifest, `formal/source/epochs/keccak-004/ownership-api/inputs-v2.json` | `dbe32f6fb61e25a1e678e7f6e310edc8bf0e415ed49f99fefe2ff701a9b69426` |
| Current runner, `formal/source/epochs/keccak-004/ownership-api/replay.py` | `83e0f37cac215071e4c5492a57c5ab166f04225191e3672b5bcdcd616bd9c0fb` |
| Bundled v2 report | `59e7e69ceb85d6d6e8feab9f35ac124537ee1d74e99011e66235b9bdbb2d62ec` |
| Bundled v2 index | `58347b16f163daf58cc430580c505cfc30e03f4240fc6dea7d708cd4078024c8` |
| Source-view epoch manifest, `formal/source/epochs/keccak-004/manifest.json` | `294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec` |
| Source-view constructor, `formal/source/epochs/keccak-004/views.py` | `65eb424c4c0b5ce44498ded72cb8600c02252e18122b8d1f28fcfb0b00eaa3eb` |

`files.json` gives the exact SHA-256 map for every other file in this data directory;
it excludes itself to avoid a self-hash cycle. Its digest is separately recorded
by the packaging validation receipt. The original report/index hashes above remain
their selected identities; do not rewrite their absolute metadata for relocation.

## Reproduce the current replay

Use the repository's selected source bytes, the checksum-pinned Darwin-arm64
Dafny 4.9.1 distribution and archive, and an installed trusted Python interpreter.
The Python interpreter/standard library are a host trust boundary. Set these
absolute paths explicitly; WORK must be a fresh directory outside the checkout.

```sh
REPO=/absolute/path/to/microproxy
CANDIDATE=/absolute/path/to/prepared-current-candidate
WORK=/absolute/path/to/fresh-work
PYTHON=/absolute/path/to/trusted/python3
DAFNY=/absolute/path/to/dafny-4.9.1-macos-arm64/dafny/dafny
SOLVER=/absolute/path/to/dafny-4.9.1-macos-arm64/dafny/z3/bin/z3-4.12.1
ARCHIVE=/absolute/path/to/dafny-4.9.1-arm64-macos-11.zip
DATA="$REPO/formal/crypto/evidence/2026-11-05-keccak/ownership-api"
```

First construct authenticated current/historical source views with the approved
constructor. The constructor checks the selected epoch manifest, complete source
and support maps, and source/alias domains before publishing either view.
Before production adoption, prepare CANDIDATE from the
[reviewed source templates](../../../../source/epochs/keccak-004/candidate/README.md)
in a separate source copy. The unmodified production files in this draft do not
yet satisfy the current-candidate map. REPO continues to identify the checkout
containing the replay tools and bundled evidence.

```sh
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C TZ=UTC \
  "$PYTHON" -I -B "$REPO/formal/source/epochs/keccak-004/views.py" \
  --manifest "$REPO/formal/source/epochs/keccak-004/manifest.json" \
  --expected-manifest-sha256 294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec \
  --candidate-root "$CANDIDATE" --output "$WORK/source-views"
```

Set VIEW_RECEIPT_SHA256 to the externally checked digest of the newly constructed
`$WORK/source-views/receipt.json`. A new view location changes that receipt's path
metadata and digest; the original execution's receipt SHA
`0205a06e606e02ba1753a1f905c660f8b642b091bf68104dabdd179c29702890` is historical.
The successor also enforces its fixed 85-source and 434-file view-map identities.
Run the actual successor with the bundled observation:

```sh
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C TZ=UTC \
  "$PYTHON" -I -B "$REPO/formal/source/epochs/keccak-004/ownership-api/replay.py" \
  --manifest "$REPO/formal/source/epochs/keccak-004/ownership-api/inputs-v2.json" \
  --expected-manifest-sha256 dbe32f6fb61e25a1e678e7f6e310edc8bf0e415ed49f99fefe2ff701a9b69426 \
  --view "$WORK/source-views/current" \
  --view-receipt "$WORK/source-views/receipt.json" \
  --expected-view-receipt-sha256 "$VIEW_RECEIPT_SHA256" \
  --dafny "$DAFNY" --solver "$SOLVER" --archive "$ARCHIVE" \
  --observation-report "$DATA/observation-002/report.json" \
  --output "$WORK/ownership-api-replay"
```

The immutable v2 authority changes only the predecessor's three package-input
hashes. Source/count/control/budget/derivation/tool fields are identical. Raw
captured-source loading and isolated child execution are required; old manifests
or historical passes cannot substitute for a current replay.

The scope is Dafny source ownership/freshness/frames and public API state/status.
`qualification:false` and `parent_epoch_status:pending` remain explicit. These
receipts do not qualify the parent epoch, SHAKE operation-trace composition,
whole-crypto composition, Java/compiler/JVM refinement, exclusive Java ownership,
physical timing/erasure, cryptographic hardness, or external expert review.
