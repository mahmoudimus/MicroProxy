# http2-codec

An HTTP/2 codec for JDK 21 and newer: the frame layer of
[RFC 9113](https://datatracker.ietf.org/doc/html/rfc9113), HPACK
([RFC 7541](https://datatracker.ietf.org/doc/html/rfc7541)), the HTTP field rules of HTTP/2, and
flow-control accounting. It has no dependencies and works on blocking streams, so one virtual
thread can read a connection while others write to it. It was written for
[MicroProxy](../README.md) but does not depend on it, so it can be moved to its own repository.

It is a codec, not a connection: it reads, writes and checks frames and field blocks, and leaves
sockets, threads, locking and stream state to the caller.

```java
FrameReader reader = new FrameReader(new BufferedInputStream(socket.getInputStream()));
FrameWriter writer = new FrameWriter(new BufferedOutputStream(socket.getOutputStream()));
HpackDecoder hpack = new HpackDecoder();
FlowController flow = new FlowController();
Http2Settings peer = Http2Settings.DEFAULT;

reader.readClientPreface();                          // server side
writer.writeSettings(Http2Settings.builder().enablePush(false).maxConcurrentStreams(100).build());
writer.flush();

for (Frame frame; (frame = reader.readFrame()) != null; ) {
    switch (frame) {
        case Frame.Headers h -> {
            // The field block is complete: CONTINUATION frames are already joined.
            List<HeaderField> fields = hpack.decode(h.streamId(), h.fieldBlock());
            RequestHeaders request = Http2Headers.toRequest(h.streamId(), fields);
            // request.method(), request.path(), request.authority(), request.fields() ...
        }
        case Frame.Data d -> flow.onDataReceived(d.streamId(), d.flowControlledLength());
        case Frame.Settings s when !s.ack() -> { peer = peer.apply(s); writer.writeSettingsAck(); }
        case Frame.Ping p when !p.ack() -> writer.writePing(true, p.opaqueData());
        case Frame.PushPromise p -> throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "push refused");
        default -> {}
    }
}
```

Every protocol violation is an `Http2Exception` (an `IOException`) carrying the `ErrorCode` to send
and its scope: a connection error means GOAWAY and close; a stream error means RST_STREAM on
`streamId()`, and the reader has already consumed the offending frame, so it can carry on.

## API

- **`Frame`**: a sealed interface of records, one per frame type: `Data`, `Headers`, `Priority`,
  `RstStream`, `Settings`, `PushPromise`, `Ping`, `GoAway`, `WindowUpdate`, `Continuation`, and
  `Unknown` for extension types. Switch over it with patterns.
- **`FrameReader`**: `readClientPreface()`, then `readFrame()` until it returns null (clean end of
  stream). It checks frame lengths against SETTINGS_MAX_FRAME_SIZE before allocating, fixed frame
  lengths, padding, which frames may and may not use stream 0, zero window increments and SETTINGS
  values. It joins HEADERS and PUSH_PROMISE with their CONTINUATION frames, rejecting any other
  frame in between, and skips unknown frame types. PRIORITY is parsed and otherwise ignored.
  PUSH_PROMISE is returned for the caller to refuse: it always comes with a field block that must
  be decoded to keep HPACK in step, and whether it is an error depends on the side.
- **`FrameWriter`**: one method per frame type plus `writeFrame(Frame)`. Each call is one
  `write`, so callers that serialize their calls never interleave frames. Field blocks longer than
  the peer's SETTINGS_MAX_FRAME_SIZE are split into CONTINUATION frames; DATA is never split.
- **`HpackDecoder`, `HpackEncoder`**: static and dynamic tables, size updates, integers, string
  literals and Huffman coding. Never-indexed literals come back as `HeaderField.sensitive()` and the
  encoder sends sensitive fields never-indexed again, as do `authorization`, `cookie`,
  `proxy-authorization` and `set-cookie` unless `setNeverIndexSensitiveNames(false)`.
- **`Http2Headers`**: `toRequest`, `toResponse` and `validateTrailers` check a decoded list
  (RFC 9113 §8.2, §8.3) and return `RequestHeaders` / `ResponseHeaders`, with cookie crumbs joined;
  `checkContentLength` compares DATA with `content-length`; `fromHttp1Request` and
  `fromHttp1Response` build an HTTP/2 list from an HTTP/1 message: lower-case names, no
  connection-specific fields, `te` only as `trailers`, `host` moved to `:authority`, `cookie` split.
- **`FlowController`, `FlowControlWindow`**: connection and stream windows for both directions,
  WINDOW_UPDATE and SETTINGS_INITIAL_WINDOW_SIZE changes, with FLOW_CONTROL_ERROR on overflow past
  2^31-1 or on a peer overrunning a window. They only count, and do no locking.
- **`Http2Settings`**: a record with the protocol defaults, a builder, validation of received
  values (`apply(Frame.Settings)`), and `toFrame()` for the values that differ from the defaults.

None of the classes are thread-safe; a connection's reader, decoder and receive-side accounting
belong to its reading thread, and its writer and encoder to whoever holds its write lock.

## Limits

Input is untrusted. Lengths are checked before anything is allocated, and every limit has a typed
error.

| Limit | Default | Exceeded |
| --- | --- | --- |
| `FrameReader.setMaxFrameSize` (our SETTINGS_MAX_FRAME_SIZE) | 16384 | connection error FRAME_SIZE_ERROR |
| `FrameReader.setMaxHeaderBlockSize` (encoded field block) | 64 KiB | connection error ENHANCE_YOUR_CALM |
| `FrameReader.setMaxContinuationFrames` (per field block) | 128 | connection error ENHANCE_YOUR_CALM |
| `HpackDecoder.setMaxHeaderTableSize` (our SETTINGS_HEADER_TABLE_SIZE) | 4096 | connection error COMPRESSION_ERROR |
| `HpackDecoder.setMaxHeaderListSize` (SETTINGS_MAX_HEADER_LIST_SIZE) | 64 KiB | `HeaderListSizeException`, a stream error |
| `HpackDecoder.setMaxStringLength` (a name or value) | 64 KiB | connection error ENHANCE_YOUR_CALM |
| HPACK integers | 2^31-1 | connection error COMPRESSION_ERROR |

The block size and CONTINUATION count stop a CONTINUATION flood, including one of empty frames.
The header list size stops an HPACK bomb (a large table entry referenced many times): fields past
the limit are dropped while the rest of the block is still decoded, so the dynamic table stays in
step and the connection can go on after the stream is refused (with 431, say). Memory for one
frame is bounded by the frame size, and for a field block by the block size.

## Not included

- The connection and stream state machines: stream states and identifiers (ordering, parity,
  MAX_CONCURRENT_STREAMS), SETTINGS acknowledgement and timeouts, GOAWAY handling, and rate limits
  on cheap frames (PING, SETTINGS, RST_STREAM floods) are the caller's.
- Priority: PRIORITY frames and the HEADERS priority fields are parsed and validated, then
  ignored (RFC 9113 deprecates them); there is no scheduling.
- Server push: the codec writes and reads PUSH_PROMISE but never acts on it; an endpoint that does
  not want pushes sends SETTINGS_ENABLE_PUSH = 0 and treats a PUSH_PROMISE as a connection error.
- Extended CONNECT (`:protocol`, RFC 8441) and the PRIORITY_UPDATE frame (RFC 9218); unknown
  frames are skipped and unknown settings ignored, as the protocol requires.
- TLS, ALPN and the `h2c` upgrade.

## Tests

- `HpackRfcExamplesTest` decodes and encodes every example in RFC 7541 Appendix C (C.2 to C.6,
  with and without Huffman, with eviction), checking the dynamic table after each header list.
- `HuffmanTest` checks the RFC's strings, every octet, and rejection of EOS and bad padding.
- `HpackTest` covers malformed blocks, integer overflow, size updates, the limits, sensitive
  fields and an encoder and decoder kept in step over random sections.
- `FrameRoundTripTest` writes and reads every frame type; `FrameReaderTest` feeds malformed
  frames (lengths, padding, stream ids, interleaved and oversized field blocks, CONTINUATION
  floods) and checks the error code and scope.
- `Http2HeadersTest`, `FlowControlTest` and `Http2SettingsTest` cover the field rules, windows and
  settings.
- `FuzzTest` mutates valid connections and HPACK blocks and feeds random bytes, and requires every
  failure to be an `Http2Exception` or `EOFException`. Pass `-Dhttp2.fuzz.runs=400000` for a longer
  run; that many have run clean.

## License

Apache License 2.0.
