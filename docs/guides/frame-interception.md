# Frame interception

See, edit, drop and add HTTP/2 and HTTP/3 frames on live connections, on both sides of the proxy,
while the proxy keeps every connection protocol-correct. Use this page to write a Java
`FrameInterceptor`; scripts get the same with [`on_frame`](scripting.md#frames).

## HTTP/2 frame interception

A `FrameInterceptor` (`org.microproxy.frames`) sees every HTTP/2 frame on live connections and may
edit, drop and add frames. It is set once per proxy, not per exchange, because SETTINGS, PING and
GOAWAY belong to a connection:

```java
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withHttp2(true).withHttp2Upstream(true)
        .withFrameInterceptor((frame, direction, ctx) -> switch (frame) {
            case Http2Frame.Headers h when direction == FrameDirection.TO_SERVER -> h.withHeader("x-via-h2", "1");
            case Http2Frame.Data d when direction == FrameDirection.FROM_SERVER && d.text().contains("secret") ->
                    d.withText(d.text().replace("secret", "******"));        // same length: content-length still holds
            case Http2Frame.Priority p -> null;                              // drop
            default -> frame;                                                // pass through
        })
        .start();
```

- **Frames.** `Http2Frame` is a sealed interface of records: `Data`, `Headers` (the decoded field
  list, pseudo-headers included, with CONTINUATION folded in), `Priority`, `RstStream`, `Settings`,
  `PushPromise`, `Ping`, `GoAway`, `WindowUpdate` and `Unknown` (extension frames, which the proxy
  otherwise discards unread). `Http3Frame` has `Data`, `Headers`, `Settings`, `GoAway`,
  `CancelPush`, `MaxPushId`, `PushPromise` and `Unknown`. Edit them with their `with...` methods.
- **Directions.** The proxy terminates HTTP/2 on each side, so each hop has its own frames:
  `FROM_CLIENT` (after decoding, before the proxy acts on them), `TO_CLIENT` (before encoding),
  `FROM_SERVER` and `TO_SERVER`. A request seen `FROM_CLIENT` is a different set of frames from the
  one later seen `TO_SERVER`: other stream ids, header blocks and DATA boundaries.
- **Context.** `FrameContext` gives the protocol, the client connection's id, the client's address,
  the server (`host:port`, on the server side), the stream id, the exchange's `FlowContext` when
  the frame belongs to one, and `send(frame)`, which adds a frame after this one on the same hop
  and in the same direction (going out it is sent next; coming in the proxy processes it as if the
  peer had sent it).
- **Coverage.** Clients on intercepted TLS, `h2c` and the TLS listener; connections to servers
  with all their multiplexed streams; full-duplex gRPC; `CONNECT` tunnels and WebSockets over
  HTTP/2, whose bytes are DATA frames. DATA the proxy sends is shown in pieces of at most 16 KiB.
  And live HTTP/3, on both sides, under the same rules adapted to HTTP/3 (see
  [HTTP/3 frames](#http3-frame-interception)).
- **Cost.** Without an interceptor nothing changes: no conversion, no allocation, no call.

The proxy stays protocol-correct whatever the interceptor returns. What it accepts:

| Frame | May be edited | May be dropped | May be followed by (`ctx.send`) |
|---|---|---|---|
| DATA | the payload, to any size | yes | DATA; HEADERS (trailers), last, when the frame ends the stream; extension frames |
| HEADERS | the fields | no | HEADERS; extension frames |
| PRIORITY | everything but the stream | yes | extension frames |
| RST_STREAM | the error code | no | extension frames |
| SETTINGS | received: values, only to make the proxy stricter; sent: only extension settings | no | extension frames |
| GOAWAY | the error code and debug data | no | extension frames |
| extension (`Unknown`) | everything | yes | extension frames |
| SETTINGS ACK, PING, WINDOW_UPDATE | nothing (the proxy's own flow control and liveness) | no | nothing |

- **Stream ids and END_STREAM are the proxy's.** Frames stay on their stream (extension frames may
  also use stream 0). When the frame ended its stream, the last DATA or HEADERS frame of the result
  does; a dropped DATA frame that ended its stream is replaced by an empty DATA frame with
  END_STREAM. What the interceptor sets is ignored.
- **Header fields** must be valid (`Field.validate`: lower-case token names, known pseudo-headers
  first, no connection-specific fields, no CR, LF or NUL in values). HPACK is never at risk: blocks
  are decoded once on arrival and encoded once on sending. A malformed request or response the
  proxy receives resets its stream, as usual. Changing a body's length while its HEADERS declare
  `content-length`: fix or remove the field in the HEADERS too (the interceptor sees them first),
  or the proxy resets the stream as malformed.
- **SETTINGS received** may lower `HEADER_TABLE_SIZE`, `INITIAL_WINDOW_SIZE`, `MAX_FRAME_SIZE` (not
  below 16384), `MAX_CONCURRENT_STREAMS` and `MAX_HEADER_LIST_SIZE`, or clear `ENABLE_PUSH` and
  `ENABLE_CONNECT_PROTOCOL`; the proxy then uses the edited values (fewer streams to a server, say).
- **Flow control.** Received DATA counts against the windows, and is credited back, at its size on
  the wire, whatever the interceptor makes of it. DATA the proxy sends waits for window at its size
  after interception. Rate limits count frames as they arrive.
- **Illegal results and failures.** A result that breaks a rule is rejected as a whole: it is
  logged (logger `org.microproxy.impl.Http2Frames`, `WARNING`) and the original frame goes on, as
  it does when the interceptor throws. `ctx.send` after the call has returned throws
  `IllegalStateException`.
- **Threads.** The interceptor is called from many threads at once and must be thread-safe. The
  HEADERS that open a stream to a server are intercepted while that connection's writes are held,
  so stream ids stay in order: keep that call short.

Scripts get the same with [`on_frame`](scripting.md#frames).

## HTTP/3 frame interception

The [frame interceptor](#frame-interception) sees HTTP/3 frames live wherever the proxy speaks
HTTP/3: `FROM_CLIENT` and `TO_CLIENT` on the reverse proxy's HTTP/3 listener, on intercepted
transparent QUIC and on HTTP/3 intercepted inside CONNECT-UDP flows, `TO_SERVER` and `FROM_SERVER` on connections to HTTP/3 servers, with the
stream's QUIC id and, from a stream's
first frame on, its exchange's `FlowContext`. `Http3Frame` has `Data`, `Headers`, `Settings`,
`GoAway`, `CancelPush`, `MaxPushId`, `PushPromise` and `Unknown`. The rules are HTTP/2's,
adapted: HTTP/3 frames carry no stream id or END_STREAM (a message ends with its stream), so
results must keep the message's order (HEADERS, DATA, trailers; interim responses first); DATA
may be edited to any size, and QUIC's flow control counts what is actually sent; field sections
are decoded through QPACK before the interceptor sees them and encoded through the connection's
QPACK encoder after it, so QPACK state never depends on it; SETTINGS received may only make the
proxy stricter (a smaller QPACK table, field section or blocked-streams limit, no
ENABLE_CONNECT_PROTOCOL or H3_DATAGRAM turned on), SETTINGS sent may change only in extension
settings; GOAWAY, MAX_PUSH_ID and CANCEL_PUSH are read-only; extension and grease frames may be
edited, dropped and added. Scripts get the same with [`on_frame`](scripting.md#frames).

<a id="http3-frames"></a>For HTTP/3 traffic relayed by other means, `Http3FramePipeline` runs a
frame interceptor over a request stream's or a control stream's bytes, under the same rules, and
writes them back with static-only QPACK, so no encoder stream is needed. It needs only the
`http3-codec` jar (`Http3FramePipeline.available()`).

```java
Http3FramePipeline pipeline = Http3FramePipeline.builder(interceptor)
        .direction(FrameDirection.FROM_CLIENT)            // whose frames these are
        .build();
pipeline.controlStream(2, clientControlStream, out);      // stream type, SETTINGS, ...
pipeline.encoderStream(clientQpackEncoderStream);         // only when the client's QPACK uses its dynamic table
pipeline.requestStream(0, requestStream, rewritten);      // HEADERS, DATA, trailers
```
