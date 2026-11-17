# keccak-005 parent

Same dispatcher as `../../keccak-004/parent` (see its README for `construct`, `pack`,
`check`, `qualify`, the artifact request and bounded tests), with these differences:

- `construct` authenticates two complete Git trees: Baf (`baf-project`, HISTORICAL) and the
  released 0.9.0 tree (`epoch-project`). The views receipt (`microproxy.keccak005-parent-views/1`)
  records both inventories. Admission recomputes both tree identities and every released
  blob's SHA-1 in the epoch project.
- The epoch map is `release + successor delivery.json + five fixture classes`. Every
  `code`/`overlays` pin must equal the released blob; otherwise construction and admission fail.
- `policy.json` adds `delivery_base` and fixes it in code; `epoch` is `keccak-005`. The only
  evidence contract that differs from keccak-004 is `stage` (regenerated on 0.9.0 inputs).
- The capsule format (`microproxy.keccak004-retained-capsule/1`) and extractor are unchanged.

```sh
"$PYTHON" -I -B -m unittest discover -s formal/source/epochs/keccak-005/parent -p test_parent.py
```
