# keccak-006 retained capsule delivery

`retained-darwin-arm64.tar.gz` transports the keccak-006 capsule: `qualification:false`,
scope `capsule-delivery-only`. Format, extraction rules and the extractor are those of
`../../keccak-004/capsule` (see its README); the extractor is reused unchanged.

| Selected input | SHA256 |
| --- | --- |
| Compressed archive | `b8920cd96e81be5c3fa8acb56064edc077ddd72c43ef0fa955ca260bdcc0b348` |
| Extracted `capsule.json` | `aa292d64793f880429ea38b38a0f0dcbed490afcdf933319d9230345d309bb86` |
| Parent policy | `b359649f8d9ca2e1a546814a7cf49983498129e07e0cc4e660ca8d7ebab831fa` |
| Parent | `33f4da6ee9af660281246f6a32992bae06eb6fc092f58b37ba6a56c3a2cc5477` |
| Extractor (keccak-004) | `3ef0b190bb255cf50dbf6800395b69d39951e6af9c094f8f79ea26f2be4cf182` |

3,194 regular members; 71,852,341 payload bytes; USTAR stream 74,332,160 bytes;
compressed 9,799,699 bytes. `pack_archive.py` is the keccak-005 recipe, unchanged. It
reproduces the keccak-005 archive `308ed6dc…` byte-for-byte from that capsule, and two
passes over this capsule produced identical bytes.

Relative to the keccak-005 capsule, exactly 12 of 3,194 files differ: `capsule.json`,
`root-map.json` (stage producer root), and the regenerated stage's `receipt.json`,
`inputs/pom.xml`, `inputs/quic/pom.xml`, `audit.log` and six parser-dependency logs.
All other evidence, project-input and fixture bytes are identical.

```sh
python3 -I -B "$CHECKOUT/formal/source/epochs/keccak-004/capsule/safeextract.py" \
  --archive "$CHECKOUT/formal/source/epochs/keccak-006/capsule/retained-darwin-arm64.tar.gz" \
  --expected-archive-sha256 b8920cd96e81be5c3fa8acb56064edc077ddd72c43ef0fa955ca260bdcc0b348 \
  --expected-capsule-sha256 aa292d64793f880429ea38b38a0f0dcbed490afcdf933319d9230345d309bb86 \
  --output "$FRESH_OUTPUT"
```
