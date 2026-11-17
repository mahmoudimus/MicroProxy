# keccak-005 retained capsule delivery

`retained-darwin-arm64.tar.gz` transports the keccak-005 capsule: `qualification:false`,
scope `capsule-delivery-only`. Format, extraction rules and the extractor are those of
`../../keccak-004/capsule` (see its README); the extractor is reused unchanged.

| Selected input | SHA256 |
| --- | --- |
| Compressed archive | `308ed6dc10577f2d6f43f165ca5b72e175697654859e3609a8611ace1956fecd` |
| Extracted `capsule.json` | `3dde2d3f961cf6690f2559baab30f59ebd3bf5800824107c35bd9f33ee217ee0` |
| Parent policy | `0c4c3702e8539b6206e9db5bd3ec55d312bc6bdfdf91a64a8a7da9c9692d3fd5` |
| Parent | `fb2f08aa0b45f21c6cc8f80c595f7a1f6c8d96ee9b76112664bc3ed2f6e54650` |
| Extractor (keccak-004) | `3ef0b190bb255cf50dbf6800395b69d39951e6af9c094f8f79ea26f2be4cf182` |

3,194 regular members; 71,857,008 payload bytes; USTAR stream 74,332,160 bytes;
compressed 9,799,746 bytes. `pack_archive.py` implements the documented recipe. It
reproduces the keccak-004 archive `13b4ec1c…` byte-for-byte from that capsule, and two
passes over this capsule produced identical bytes.

Relative to the keccak-004 capsule, exactly 11 of 3,194 files differ: `capsule.json`,
`root-map.json` (stage producer root), and the regenerated stage's `receipt.json`,
`inputs/pom.xml`, `inputs/quic/pom.xml`, `audit.log` and six parser-dependency logs.
All other evidence and project-input bytes are identical.

```sh
python3 -I -B "$CHECKOUT/formal/source/epochs/keccak-004/capsule/safeextract.py" \
  --archive "$CHECKOUT/formal/source/epochs/keccak-005/capsule/retained-darwin-arm64.tar.gz" \
  --expected-archive-sha256 308ed6dc10577f2d6f43f165ca5b72e175697654859e3609a8611ace1956fecd \
  --expected-capsule-sha256 3dde2d3f961cf6690f2559baab30f59ebd3bf5800824107c35bd9f33ee217ee0 \
  --output "$FRESH_OUTPUT"
```
