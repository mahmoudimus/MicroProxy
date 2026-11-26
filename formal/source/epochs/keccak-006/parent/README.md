# keccak-006 parent

Same dispatcher as `../../keccak-005/parent` (itself `../../keccak-004/parent`; see its README for
`construct`, `pack`, `check`, `qualify`, the artifact request and bounded tests). The only code
differences from keccak-005 are the fixed release authority and the epoch/schema names:

- `RELEASE` `b80932f387b69b50276fd6a4d87bd65a6156955b`, `RELEASE_TREE`
  `8231287a8a3b1c1ccb13a20c5bdfc4cd26169909`, `RELEASE_FILES` 3791, release `0.10.0`.
- `epoch` is `keccak-006`; policy, report and views schemas are `microproxy.keccak006-*`.
- `policy.json` differs from keccak-005 only in `schema`, `epoch`, `delivery_base` and
  `evidence.stage` (regenerated on 0.10.0 inputs).
- The capsule format (`microproxy.keccak004-retained-capsule/1`) and extractor are unchanged.

```sh
"$PYTHON" -I -B -m unittest discover -s formal/source/epochs/keccak-006/parent -p test_parent.py
```
