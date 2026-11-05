# Selected retained capsule delivery

`retained-darwin-arm64.tar.gz` transports the externally selected epoch004
retained capsule. This is `qualification:false`, scope `capsule-delivery-only`.
It does not run proofs, compilers, JVMs, artifact validators or APIs, and it does
not qualify or adopt an epoch. Retained Darwin evidence is not a claim that its
macOS toolchain executes on Linux.

| Selected input | SHA256 |
| --- | --- |
| Compressed archive | `13b4ec1c9175179c3eddcc42f919ddc838447d413766e1c7ba21239a750d79f1` |
| Extracted `capsule.json` | `fc8f3d1b90bab8af9d40285237c79be60bf802721299594321d4d7abdb5083a3` |
| Parent policy | `8bb7b5d157f46db802ce5bd118c79ef365377f708667580bc0d89c1bf1c317d2` |
| Captured parent used for the cold admission check | `28a891c07dd5f4124343f5d50ac406dd1222d90fa17078e5f45f3ee598d46845` |
| Extractor | `3ef0b190bb255cf50dbf6800395b69d39951e6af9c094f8f79ea26f2be4cf182` |

Root independently selected the archive digest after iterating all 3,194 regular
members and matching their bytes against the selected capsule map. The archive
contains 71,872,150 payload bytes; the USTAR stream is 74,342,400 bytes and the
compressed file is 9,799,845 bytes. No installed SDK/JDK executable distribution
is bundled. Source, fixtures and retained evidence remain data until a separate,
explicitly selected consumer uses them.

The archive recipe sorts every indexed relative filename, including
`capsule.json`, and writes regular USTAR members only: mode0644, uid/gid/mtime0,
empty owner/group names, and implicit directories. Gzip uses level9, mtime0 and
an empty filename. Two independent compression passes produced identical bytes.
`archive.json` records the selected archive and raw-stream measurements; it is
metadata, not an alternative source of authority.

## Extraction

Use literal hashes selected outside the downloaded archive. The utility never
learns an expected hash from the file, manifest, environment or cache. Both paths
must be absolute. The output must be fresh, its parent must already exist, and
it must lie outside both the archive's containing directory and the extractor's
source directory. If downloading to a temporary directory, use separate sibling
`download/` and `extracted/` locations rather than putting the archive directly
in the common temporary root.

```sh
python3 -I -B "$CHECKOUT/formal/source/epochs/keccak-004/capsule/safeextract.py" \
  --archive "$CHECKOUT/formal/source/epochs/keccak-004/capsule/retained-darwin-arm64.tar.gz" \
  --expected-archive-sha256 13b4ec1c9175179c3eddcc42f919ddc838447d413766e1c7ba21239a750d79f1 \
  --expected-capsule-sha256 fc8f3d1b90bab8af9d40285237c79be60bf802721299594321d4d7abdb5083a3 \
  --output "$FRESH_OUTPUT"
```

The equivalent captured-code API is:

```python
extract_capsule(absolute_archive, externally_selected_archive_sha256,
                externally_selected_capsule_sha256, fresh_absolute_output)
```

The returned/stdout receipt is not written into the output. The output contains
exactly the 3,194 selected capsule files: `capsule.json`, `root-map.json`,
`project-inputs/`, `fixtures/` and `evidence/`. Callers that execute captured code
must separately authenticate the extractor's source bytes before compilation.

Compressed bytes are authenticated before any output creation. The utility
then validates the complete raw USTAR stream and capsule index in memory before
creating the fresh directory. It rejects unsafe/noncanonical names, traversal,
backslashes, case aliases (including parent components), duplicate members,
file/directory conflicts, every nonregular/symlink/hardlink/special member,
unsupported extension headers, invalid padding/trailing data, duplicate JSON
keys, and missing/extra/changed payloads. Input/output ancestor symlinks and
hardlinked archive files are rejected. Output overlap checks include physical
directory identity, so changing path case cannot bypass them on macOS.

Files are created without tar's extraction APIs, using exclusive creation and
non-executable modes. The final exact file map and unchanged archive are checked.
There is no cache, producer-path, network or external-tool fallback. A filesystem
failure during writing can leave an incomplete output; it must not be reused as
a fresh output or treated as a complete capsule.

## Verification

```sh
python3 -I -B "$CHECKOUT/formal/source/epochs/keccak-004/capsule/test_safeextract.py"
```

All 34 real-file tests passed, with no skips or expected failures. The unsafe,
mismatched-hash and nested-output controls require rejection without modifying
the source archive or creating the output. Case tests use the actual filesystem
identity; distinct case-sensitive directories remain distinct. A separate real
access-time regression showed that a read may update atime; stable inode,
size/mtime/ctime, link count and byte digests remain the input-stability checks.

The selected archive was extracted to a new private cold root. Then the exact
captured parent source shown above called only `admit_capsule`, with the fixed
policy/capsule digests. It admitted all 3,194 files and eight evidence roots.
An open audit allowed reads only from that explicit cold capsule and denied
process/network fallback: there were zero outside reads or tool attempts. This
is capsule admission only; parent prerequisite checking, fresh artifact
qualification, physical JVM timing and broader composition remain separate.
