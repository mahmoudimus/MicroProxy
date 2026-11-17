# keccak-005 current-epoch CI gate

Same contract as `../../keccak-004/ci/README.md`, with keccak-005 parent, policy and capsule,
the unchanged keccak-004 extractor, and retained data in
`formal/crypto/evidence/2026-11-16-keccak-005/parent`. `selection.json` is root-owned; the
workflow supplies its literal reviewed SHA256. No helper mode renews these authorities.

```sh
"$PYTHON" -I -B "$REPO/formal/source/epochs/keccak-005/ci/run.py" prepare \
  --repository "$REPO" --selection "$REPO/formal/source/epochs/keccak-005/ci/selection.json" \
  --expected-selection-sha256 "$REVIEWED_SELECTION_SHA" --output "$FRESH_PREPARED"
"$PYTHON" -I -B "$REPO/formal/source/epochs/keccak-005/ci/run.py" check \
  --repository "$REPO" --prepared "$FRESH_PREPARED" \
  --expected-prepared-sha256 "$PREPARED_RECEIPT_SHA" \
  --classes "$REPO/quic/target/classes" \
  --retained-data "$REPO/formal/crypto/evidence/2026-11-16-keccak-005/parent" \
  --selection "$REPO/formal/source/epochs/keccak-005/ci/selection.json" \
  --expected-selection-sha256 "$REVIEWED_SELECTION_SHA" --output "$FRESH_CHECK_RESULT"
```

The sealed checkout is the released 0.9.0 tree: 467 inputs (269 main sources, 3 resources,
189 test-class files, 6 tool files) and 468 classes equal to the published Central
`quic-0.9.0.jar`. A checkout whose quic sources, resources or test classes differ fails.
