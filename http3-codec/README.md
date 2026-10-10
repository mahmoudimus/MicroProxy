# http3-codec

An HTTP/3 codec for JDK 21 and newer: the frame layer of
[RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114), QPACK
([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204)), the stream rules and HTTP field
rules of HTTP/3, and the settings of extended CONNECT
([RFC 9220](https://datatracker.ietf.org/doc/html/rfc9220)) and HTTP Datagrams
([RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297)). It has no dependencies and works on
the bytes of QUIC streams, blocking or buffered. It is the sibling of [http2-codec](../http2-codec/README.md),
written for [MicroProxy](../README.md) but not dependent on it, so it can be moved to its own
repository.

It is a codec, not a connection, and not QUIC: it reads, writes and checks frames, field sections
and QPACK instructions, and leaves the QUIC transport, threads, locking and stream state to the
caller.

```java
// Our settings, sent first on our control stream.
Http3Settings ours = Http3Settings.builder()
        .qpackMaxTableCapacity(4096).qpackBlockedStreams(16).maxFieldSectionSize(64 * 1024).build();
QpackDecoder qpackIn = new QpackDecoder(4096, 16);   // must match what we advertise
QpackEncoder qpackOut = new QpackEncoder(4096);      // static-only until the peer's SETTINGS
Http3FrameWriter control = new Http3FrameWriter(controlStreamOut);
control.writeStreamType(Http3StreamType.CONTROL);
control.writeSettings(ours);

// The peer's control stream.
Http3FrameReader peerControl = new Http3FrameReader(controlStreamIn);
long type = peerControl.readStreamType();            // checked with Http3StreamValidator.UnidirectionalStreams
Http3StreamValidator controlRules = Http3StreamValidator.forControlStream(Role.SERVER);
Http3Frame first = peerControl.readFrame();
controlRules.onFrame(first);                         // H3_MISSING_SETTINGS unless SETTINGS
qpackOut.applyPeerSettings(Http3Settings.fromFrame((Http3Frame.Settings) first));

// A request stream (server side).
Http3FrameReader reader = new Http3FrameReader(requestStreamIn);
Http3StreamValidator rules = Http3StreamValidator.forRequestStream(streamId, Role.SERVER);
for (Http3Frame frame; (frame = reader.readFrame()) != null; ) {
    rules.onFrame(frame);                            // HEADERS, DATA*, optional trailers
    switch (frame) {
        case Http3Frame.Headers h -> {
            List<HeaderField> fields = qpackIn.decode(streamId, h.fieldSection());
            if (fields == null) { /* blocked: wait for the encoder stream, then qpackIn.resume(streamId) */ }
            RequestHeaders request = Http3Headers.toRequest(streamId, fields);
        }
        case Http3Frame.Data d -> body.write(d.data());
        case Http3Frame.Unknown u -> { /* extension or grease: ignore, or relay as is */ }
        default -> {}
    }
}
rules.onEndOfStream();
decoderStreamOut.write(qpackIn.decoderStreamBytes());   // acknowledgments for the peer's encoder
```

Every protocol violation is an `Http3Exception` (an `IOException`) carrying the `Http3ErrorCode` to
send and its scope: a connection error means closing the QUIC connection with that code; a
stream error means resetting `streamId()` (and stopping reading it) with that code. QUIC stream
IDs start at 0, so a connection error's `streamId()` is -1.

## API

- **`Http3Frame`**: a sealed interface of records, one per frame type: `Data`, `Headers`,
  `CancelPush`, `Settings`, `PushPromise`, `GoAway`, `MaxPushId`, and `Unknown` for extension and
  reserved (greasing, 0x1f * N + 0x21) types, which keeps the type and payload so the frame can be
  inspected, edited and relayed. Switch over it with patterns. Frames carry no stream ID or flags:
  in HTTP/3 the QUIC stream says which stream, and its end ends the message.
- **`Http3FrameReader`**: `readStreamType()` for unidirectional streams, then `readFrame()` until
  it returns null (a clean end between frames). It checks payload sizes before allocating, the
  exact layout of CANCEL_PUSH, GOAWAY, MAX_PUSH_ID, PUSH_PROMISE and SETTINGS, frames cut short by
  the end of the stream, the HTTP/2 types HTTP/3 forbids (0x02, 0x06, 0x08, 0x09:
  H3_FRAME_UNEXPECTED), and SETTINGS rules: no repeated identifier, none of the HTTP/2-only
  identifiers (0x00, 0x02-0x05), 0 or 1 for the boolean settings (H3_SETTINGS_ERROR).
  `Http3FrameReader.of(ByteBuffer)` reads from a buffer, and `parse(ByteBuffer, limit)` takes one
  whole frame from a buffer that collects a stream's bytes, or returns null and leaves the buffer
  alone if the frame is not all there yet.
- **`Http3FrameWriter`**: one method per frame type plus `writeFrame`, and `writeStreamType`;
  each call is one `write`. The static `encode(Http3Frame)` gives a frame's bytes, or puts them in
  a `ByteBuffer`.
- **`QuicVarInt`**: QUIC variable-length integers (RFC 9000 §16), read from and written to
  streams, buffers and arrays, with range and bounds checks.
- **`Http3StreamType`**: the unidirectional stream types: control (0x00), push (0x01), QPACK
  encoder (0x02) and QPACK decoder (0x03), and the reserved ones.
- **`Http3StreamValidator`**: which frames the peer may send on a stream, and in what order. The
  control stream starts with SETTINGS (H3_MISSING_SETTINGS), sends it once, and carries no DATA,
  HEADERS or PUSH_PROMISE; MAX_PUSH_ID comes only from clients and never decreases; GOAWAY never
  increases and, from a server, names a client-initiated bidirectional stream; CANCEL_PUSH to a
  server stays within its MAX_PUSH_ID (H3_ID_ERROR). A request or push stream is HEADERS, DATA*,
  optional trailing HEADERS, with interim (1xx) header sections reported by `interimResponse()`;
  PUSH_PROMISE only from a server on a request stream; no control frames. The end of the control
  stream is H3_CLOSED_CRITICAL_STREAM, and a request that ends before its header section is
  H3_REQUEST_INCOMPLETE. `UnidirectionalStreams` allows the peer one control, one encoder and one
  decoder stream, and push streams only from a server (H3_STREAM_CREATION_ERROR).
- **`QpackEncoder`**: static-only (`new QpackEncoder()`, or before the peer's SETTINGS), which
  never blocks and never writes to the encoder stream; or with a dynamic table up to the smaller
  of its own limit and the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY. It inserts fields with
  encoder-stream instructions (Set Dynamic Table Capacity, Insert With Name Reference, Insert With
  Literal Name, Duplicate; `insert` and `duplicate` for doing it by hand), references unacknowledged
  entries only while fewer than the peer's SETTINGS_QPACK_BLOCKED_STREAMS streams are blocked,
  processes Section Acknowledgment, Stream Cancellation and Insert Count Increment from the
  decoder stream, and evicts only acknowledged entries that no outstanding section references,
  falling back to literals when there is no room. Sensitive fields (`HeaderField.sensitive()`,
  and `authorization`, `cookie`, `proxy-authorization`, `set-cookie` unless turned off) go out as
  literals with the 'N' bit set and stay out of the table.
- **`QpackDecoder`**: every field line representation (indexed, static or dynamic, relative or
  post-base; literal with a static, dynamic or post-base name reference; literal with a literal
  name), with the 'N' bit returned as `HeaderField.sensitive()`. It processes the encoder stream
  in pieces of any size, holds sections whose Required Insert Count is not reached yet as blocked
  (`decode` returns null; `onEncoderStream` reports them once they can go on; `resume` decodes
  them), and queues the decoder-stream instructions (`decoderStreamBytes()`): Section
  Acknowledgment, Stream Cancellation (`cancelStream`) and Insert Count Increment.
- **`Http3Headers`**: `toRequest`, `toResponse` and `validateTrailers` check a decoded list (RFC
  9114 §4.2, §4.3, which are HTTP/2's rules) and return `RequestHeaders` / `ResponseHeaders`, with
  cookie crumbs joined; extended CONNECT with `:protocol` (RFC 9220) needs `:scheme`, `:path` and
  `:authority` and can be refused when SETTINGS_ENABLE_CONNECT_PROTOCOL was not sent;
  `checkContentLength` compares DATA with `content-length`. A malformed message is a stream error
  H3_MESSAGE_ERROR.
- **`Http3Settings`**: a record with QPACK_MAX_TABLE_CAPACITY, MAX_FIELD_SECTION_SIZE,
  QPACK_BLOCKED_STREAMS, ENABLE_CONNECT_PROTOCOL and H3_DATAGRAM, the extension and reserved
  settings kept in order, a builder (with `grease`), `fromFrame` with validation, and `toFrame`.
- **`Http3ErrorCode`**: H3_NO_ERROR to H3_VERSION_FALLBACK, QPACK_DECOMPRESSION_FAILED,
  QPACK_ENCODER_STREAM_ERROR, QPACK_DECODER_STREAM_ERROR and H3_DATAGRAM_ERROR; unknown and
  reserved codes read as H3_NO_ERROR, as RFC 9114 §9 requires.

None of the classes are thread-safe, and none lock. A frame reader or writer belongs to one
stream. The QPACK encoder and decoder are per connection and are fed from several streams (field
sections from request streams, instructions from the encoder and decoder streams), so a caller
with a thread per stream serializes access to each, with a `ReentrantLock` say.

## Limits

Input is untrusted. Lengths are checked before anything is allocated, and every limit has a typed
error.

| Limit | Default | Exceeded |
| --- | --- | --- |
| `Http3FrameReader.setMaxFramePayloadSize` | 64 KiB | connection error H3_EXCESSIVE_LOAD (DATA: returned in pieces of this size instead) |
| `QpackDecoder` max table capacity (our SETTINGS_QPACK_MAX_TABLE_CAPACITY) | 0 | connection error QPACK_ENCODER_STREAM_ERROR |
| `QpackDecoder` max blocked streams (our SETTINGS_QPACK_BLOCKED_STREAMS) | 0 | connection error QPACK_DECOMPRESSION_FAILED |
| `QpackDecoder.setMaxFieldSectionSize` (our SETTINGS_MAX_FIELD_SECTION_SIZE) | 64 KiB | `FieldSectionSizeException`, a stream error H3_EXCESSIVE_LOAD |
| An entry on the encoder stream | the table capacity | connection error QPACK_ENCODER_STREAM_ERROR, as soon as its length is read |
| QPACK integers | 2^62-1 | connection error QPACK_DECOMPRESSION_FAILED, QPACK_ENCODER_STREAM_ERROR or QPACK_DECODER_STREAM_ERROR, by where it arrived |

HTTP/3 attaches no meaning to DATA frame boundaries, so a DATA frame longer than the payload limit
is not an error: the reader returns it as consecutive `Data` records of at most the limit. Memory
for one frame is bounded by the limit either way. The field section size stops a QPACK bomb (a
large table entry referenced many times): fields past the limit are dropped while the rest of the
section is still decoded and acknowledged, so the encoder's state stays in step and the
connection can go on after the request is refused (with 431, say). A blocked section is held
whole, so blocked sections take at most the blocked-streams limit times the frame payload limit.
The encoder rejects (with `IllegalArgumentException`, before changing anything) a section larger
than the peer's SETTINGS_MAX_FIELD_SECTION_SIZE.

## Not included

- QUIC: the transport, TLS, connection IDs, flow control, stream state and the mapping of
  connection and stream errors onto CONNECTION_CLOSE, RESET_STREAM and STOP_SENDING are the
  caller's. This codec works on the bytes the QUIC layer supplies.
- The connection state machine: stream ID ordering and limits, GOAWAY handling and draining,
  what to do before the peer's SETTINGS arrive, and rate limits on cheap frames and grease are
  the caller's.
- Server push beyond frame parsing: PUSH_PROMISE, CANCEL_PUSH, MAX_PUSH_ID and push streams are
  read, written and checked as frames, and nothing more; push IDs are not tracked against
  promises.
- HTTP Datagrams: H3_DATAGRAM is a setting here; the QUIC DATAGRAM frames that carry them, and
  the Capsule Protocol, are not.
- Priority (RFC 9218): PRIORITY_UPDATE frames come through as `Unknown`, and the `priority`
  header is an ordinary field.
- QPACK encoder heuristics: the encoder inserts every field that fits, prefers the newest copy of
  an entry, and never duplicates entries by itself; it has no notion of draining entries. The
  decoder accepts a Required Insert Count larger than the section needs, which RFC 9204 §2.2.1
  allows it to reject.

## Tests

- `QpackRfcExamplesTest` encodes and decodes every example in RFC 9204 Appendix B byte for byte,
  checking both dynamic tables (absolute index, references, size) and the decoder-stream
  instructions after each step, including the blocked and cancelled stream of B.4.
- `QpackStaticTableTest` checks the static table against a digest of RFC 9204 Appendix A and spot
  checks entries, wrapped values in particular.
- `QpackTest` covers every field line representation, the 'N' bit, static-only mode, eviction
  only of acknowledged and unreferenced entries, blocked streams on both sides, acknowledgments
  and cancellation, Required Insert Count wrap-around, malformed sections and instructions, the
  size limits, and random sections with delayed, split encoder streams.
- `HuffmanTest` checks RFC 7541's strings, every octet, and rejection of EOS and bad padding.
- `QuicVarIntTest` covers 63, 64, 16383, 16384, 2^30-1, 2^30 and 2^62-1 and the RFC 9000 examples;
  `FrameRoundTripTest` writes and reads every frame type through streams and buffers;
  `FrameReaderTest` feeds malformed and truncated frames and bad SETTINGS; `StreamValidatorTest`
  covers frames on the wrong stream and out of order; `Http3HeadersTest` and `Http3SettingsTest`
  cover the field and settings rules.
- `FuzzTest` mutates valid request streams, encoder streams, control streams and QPACK sections
  and feeds random bytes, with fixed seeds, and requires every failure to be an `Http3Exception`.
  Pass `-Dhttp3.fuzz.runs=200000` for a longer run; that many have run clean.

## License

Apache License 2.0.
