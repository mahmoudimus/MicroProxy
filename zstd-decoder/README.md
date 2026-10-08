# zstd-decoder

A pure-Java [Zstandard](https://datatracker.ietf.org/doc/html/rfc8878) decoder for JDK 21 and
newer: no dependencies, no `Unsafe`, no native code. It was written from RFC 8878 for
[MicroProxy](../README.md), which uses it to read `Content-Encoding: zstd` bodies, and it has no
dependency on the proxy, so it can live on its own.

```java
byte[] plain = ZstdDecompressor.create().decompress(compressed);

try (InputStream in = new ZstdInputStream(socket.getInputStream())) {
    in.transferTo(out);
}

ZstdDecompressor withDictionary = ZstdDecompressor.builder()
        .dictionary(ZstdDictionary.of(Files.readAllBytes(Path.of("samples.dict"))))
        .maxWindowSize(8 << 20)
        .build();
```

## What it supports

- Every part of the frame format: compressed, raw and RLE blocks; Huffman-coded, raw and RLE
  literals (one or four streams, with direct or FSE-coded weights, and treeless reuse); FSE,
  predefined, RLE and repeated sequence tables; repeat offsets; and windows up to the configured
  limit.
- Concatenated frames, skippable frames, content size checks and XXH64 content checksums.
- Dictionaries: formatted ones made by `zstd --train`, with their own entropy tables and
  starting offsets, and raw-content dictionaries.
- Streaming: `ZstdInputStream` decodes one block (at most 128 KiB) at a time, so a consumer that
  stops reading stops the work.

Not supported: compression, and the legacy pre-1.0 formats.

## Limits and safety

Input is untrusted. Every length, offset and table is checked before use, and malformed input
raises `ZstdException` (an `IOException`).

- **Memory:** bounded by `maxWindowSize` (128 MiB by default, as in the reference decoder). The
  history buffer grows only as output is produced, and at most to about twice the window.
- **Output:** `decompress(data, maxOutputSize)` caps it; with the stream, read only as much as
  you want.
- **Checksums:** verified when a frame has one; turn this off with `verifyChecksums(false)`.

## Tests

- `FixturesTest` decodes output of the reference encoder chosen to reach every part of the format
  (see `src/test/fixtures/generate.py`, which regenerates them), in one call and as a stream fed
  a few bytes at a time.
- `ReferenceEncoderTest` compresses random inputs with random settings using the `zstd` command,
  when it is installed, and checks the round trip.
- `CorruptionTest` mutates the fixtures and requires every failure to be a clean `ZstdException`.
  The same harness was run locally for 300,000 mutations without an internal error.
- `DecoderTest` covers checksums, truncation, limits, dictionaries, malformed headers and the
  stream API.

Throughput is around 100 MB/s on a single core for typical data.

## License

Apache License 2.0.
