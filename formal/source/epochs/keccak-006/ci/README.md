# keccak-006 current-epoch CI gate

Same contract as `../../keccak-004/ci/README.md`, with keccak-006 parent, policy and capsule,
the unchanged keccak-004 extractor, and retained data in
`formal/crypto/evidence/2026-11-26-keccak-006/parent`. `selection.json` is root-owned; the
workflow supplies its literal reviewed SHA256. No helper mode renews these authorities.

```sh
"$PYTHON" -I -B "$REPO/formal/source/epochs/keccak-006/ci/run.py" prepare \
  --repository "$REPO" --selection "$REPO/formal/source/epochs/keccak-006/ci/selection.json" \
  --expected-selection-sha256 "$REVIEWED_SELECTION_SHA" --output "$FRESH_PREPARED"
"$PYTHON" -I -B "$REPO/formal/source/epochs/keccak-006/ci/run.py" check \
  --repository "$REPO" --prepared "$FRESH_PREPARED" \
  --expected-prepared-sha256 "$PREPARED_RECEIPT_SHA" \
  --classes "$REPO/quic/target/classes" \
  --retained-data "$REPO/formal/crypto/evidence/2026-11-26-keccak-006/parent" \
  --selection "$REPO/formal/source/epochs/keccak-006/ci/selection.json" \
  --expected-selection-sha256 "$REVIEWED_SELECTION_SHA" --output "$FRESH_CHECK_RESULT"
```

The sealed checkout is the released 0.10.0 tree: 468 inputs (269 main sources, 3 resources,
190 test-class files, 6 tool files) and 468 classes equal to the published GitHub Packages
`quic-0.10.0.jar`. keccak-005 sealed 467 inputs; 0.10.0 adds one test class
(`CertificateIssuerPolicyTest$2`), so `run.py` requires 468. A checkout whose quic sources,
resources or test classes differ fails.
