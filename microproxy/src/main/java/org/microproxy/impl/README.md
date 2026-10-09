# `org.microproxy.impl`: exchanges and transports

A client connection runs on one virtual thread in `ClientConnection`. Its code has two layers,
split so that HTTP/2 streams ([issue #2](https://github.com/mahmoudimus/MicroProxy/issues/2))
reuse everything but the wire format, on either side:

```
ClientConnection.run / serveRequests     HTTP/1 connection loop   (HTTP/1 only)
        │  request head                  ├─ intercept: ALPN h2 ───────► Http2Connection.serve
        │                                └─ plain listener: preface ──► (frame reader, one thread per stream)
        ▼
ClientConnection.handleRequest(channel, request)   exchange logic   (any transport)
        │  body, interim responses, response head and body, tunnel, close
        ▼
ClientChannel  ◄── Http1ClientChannel (ByteReader, HttpCodec, Framing, PooledOutputStream)
               ◄── Http2StreamChannel (one per HTTP/2 stream, many at once)

ServerConnection ◄── itself: HTTP/1.1 (ByteReader, HttpCodec.HttpWriter), one exchange at a time
                 ◄── Http2UpstreamStream (one stream of a shared Http2UpstreamConnection, from Http2Origins)
```

## The transport: `ClientChannel`

`ClientChannel` is the client side of one exchange. `Http1ClientChannel` implements it for an
HTTP/1.x connection, which carries its exchanges one after another, so one channel serves them all.
The channel owns:

- **The request body.** `requestBody(request)` checks the request's framing and returns a
  `MessageBody`, which is read piece by piece (`next()`) or as raw bytes (`read()`).
  `HttpCodec.BodyReader` is the HTTP/1 implementation.
- **Connection persistence.** `clientKeepAlive(request)` reads the request's `Connection` header.
  `adaptFraming` re-chunks close-delimited bodies, de-chunks for HTTP/1.0 clients and decides
  whether the connection must close. `setKeepAlive` and `setUpgrade` write the `Connection` and
  `Upgrade` headers.
- **Writing the response.** `writeContinue`, `writeInformational` (dropped for HTTP/1.0 clients),
  `writeHead`, `writeComplete` (a whole response, or a bare head given an empty body),
  `writeContent`, and the fast path `writeData` / `flush` / `writeEnd`.
- **Ending the exchange.** `relay` passes bytes both ways for a `CONNECT` tunnel or after a `101`,
  `reject(status)` answers a malformed request, and `close` closes the connection.
- **Waiting.** `awaitUnlessClientLeaves` is the chained-proxy backoff wait, which stops early if
  the client disconnects.
- **The exchange's `ClientFlowContext`** (timings, upstream status). For HTTP/1 it is the
  connection's single one; each HTTP/2 stream has its own (`FlowContext.getStreamId()`).
- **How exchanges share the connection:** `logPrefix()` (`[conn N]` or `[conn N stream S]`),
  `multiplexed()` (exchanges run concurrently and need server connections of their own),
  `supportsTunnels()` (`CONNECT` and `101` are possible), and `serverConnectionInUse` /
  `serverConnectionDone`, through which a transport closes the server connection of an exchange
  the client cancelled. All are constants or no-ops for HTTP/1, which allocates nothing more per
  request.

Write failures surface as `IOException`s, which the exchange logic treats as the client going
away (`ClientFailure`).

## The exchange logic

Everything from `handleRequest` on is the same for any transport, and touches the client only
through `Exchange.channel`:

- proxy authentication, filter creation and every `HttpFilters` hook, including `exchangeEnded`;
- request and response buffering, short-circuit answers, and the failure responder;
- routing, chained proxies with backoff, the server connection pool, stale-connection retries,
  `100-continue` towards the server, and the server side (`ServerConnection`, below);
- response relay, including the choice of the zero-copy body relay when no filter inspects the body;
- the proxy's header rewriting (`Via`, hop-by-hop, `Alt-Svc` h3 stripping), `ResponseSource`,
  timings and trackers.

## The server side: `ServerConnection`

The exchange logic writes the request and reads the response through `ServerConnection`'s methods
(`writeRequestHead`, `writeContent`, `writeData`, `writeEnd`, `awaitResponse`, `readResponse`,
`responseBody`, `exchangeDone`, `retryable`), which the class implements for HTTP/1.1 with its
`ByteReader` and `HttpCodec.HttpWriter`. Response bodies are `MessageBody`s, as request bodies
are. `Http2UpstreamStream` overrides them for one stream of an HTTP/2 connection; its
`multiplexed()` is true, and then:

- the exchange ends the stream when it is done (`close()` resets it if it is still open either
  way) instead of keeping, pooling or closing a connection, and never stores it in
  `serverConnections` or `StreamServerConnections`;
- `retryable(e)` is true only for streams the server never processed (`Unprocessed`: `GOAWAY`,
  `REFUSED_STREAM`), so the stale-connection retry resends only those;
- when the client side is an HTTP/2 stream too, the request body is relayed by a `RequestPump`
  on a thread of its own while the exchange's thread relays the response (`fullDuplex`): only
  when no filter or chained proxy sees the body's pieces, so filters are never called from two
  threads at once. HTTP/1 clients stay half-duplex: their next request is read from the same
  buffer after this one's body.

## HTTP/2: `Http2Connection` and `Http2StreamChannel`

When an intercepted handshake negotiates ALPN `h2` (offered only with `withHttp2`, and only when
the optional `http2-codec` module is present: `Http2Support`), `intercept` hands the TLS socket to
`Http2Connection.serve`, on the connection's own thread. With `withHttp2Cleartext`, `run` does the
same for a plain connection whose first bytes are the connection preface
(`ByteReader.startsWith`, which consumes nothing; the bytes already read are handed over); that
connection has no `CONNECT` target, so its requests are made absolute-form from `:scheme` and
`:authority` and are never answered `421`, and its streams authenticate one by one
(`authenticateStream`, which leaves the connection's authentication state alone).

Writing frames, send flow control, SETTINGS and PING are `Http2Endpoint`'s, which
`Http2UpstreamConnection` shares.

- **Threads.** The connection's thread reads frames (`FrameReader`, `HpackDecoder` are its alone)
  and demultiplexes them. Each stream's request starts a virtual thread that runs
  `ClientConnection.handleStream` (the exchange logic) through the stream's
  `Http2StreamChannel`. A shared timer thread checks every connection for idleness, a missing
  SETTINGS acknowledgement and stalled writes; it never blocks, and starts a thread for anything
  that writes.
- **Locks.** `writeLock` serializes writing: the `FrameWriter`, the `HpackEncoder` (a header block
  is encoded and written under one hold, so blocks reach the client in encoding order) and the
  socket. `stateLock` guards the stream map, the `FlowController` windows and each stream's
  buffered request data; it is never held while writing, and never taken while `writeLock` is
  held. Stream threads wait on its conditions: their own for request data (and resets), the
  connection's `windowOpened` for send window. There is no `synchronized`.
- **Flow control.** DATA from the client is debited from the windows and buffered per stream
  (an `ArrayDeque` of the frames' arrays), at most the stream's window; the stream's body reads
  (`MessageBody`) credit the windows back with WINDOW_UPDATE once half a window has been read.
  Data that will never be read (a stream that ended or was reset) is credited back to the
  connection. Response DATA waits until the stream and the connection both have window, in frames
  of at most 16 KiB (or the client's SETTINGS_MAX_FRAME_SIZE if smaller).
- **Ending streams.** END_STREAM in both directions closes a stream; a stream whose response is
  complete while the client still sends gets `RST_STREAM NO_ERROR`, one abandoned by the exchange
  `CANCEL` or `INTERNAL_ERROR`. A client's RST_STREAM marks the stream reset (its waits and writes
  fail) and closes its server connection, so the exchange stops waiting on the server. Late
  frames for recently reset streams are ignored.
- **Hardening** (`org.microproxy.Http2Options`): the concurrent stream limit, rate limits for
  rapid resets and cheap frames, the SETTINGS ack timeout, stream id parity and ordering, the
  header list limit, and the codec's own limits (frame size, header block size, CONTINUATION
  count, HPACK). See the main README's HTTP/2 section for the table.

`Http2StreamChannel` defines what the HTTP/1-only `ClientChannel` operations mean for a stream:
`clientKeepAlive` is always true; `adaptFraming` only drops `Transfer-Encoding`; `setKeepAlive`
and `setUpgrade` do nothing; `writeContinue` sends `:status 100` only to a client that sent
`expect: 100-continue`, and `writeInformational` forwards other 1xx as interim HEADERS; `writeData`
copies into DATA frames; `relay` and `close` reset the stream; `reject` answers and ends it. A
`CONNECT` inside a stream gets `501` from the exchange logic (`supportsTunnels()` is false), and
a request for an authority other than the intercepted one gets `421` before it gets there.

### The concurrency audit

Everything the exchange logic touches on `ClientConnection`, and what makes it safe with streams
running at once:

| State | Before | Now |
|---|---|---|
| Authentication (`authenticated`, `accepted`, `acceptedUser`, `clientDetails` user) | per connection, one exchange at a time | only touched outside intercepted sessions (HTTP/1, sequential); streams exist only inside one and inherit its authentication (`multiplexed()` skips it) |
| `mitmHostAndPort`, `connectionMitm` / `mitmChosen` | written at the `CONNECT` | unchanged: written before any stream thread starts, only read by streams |
| `serverConnections` (one per target) | one exchange at a time per connection | still HTTP/1's; streams take server connections from `StreamServerConnections` (thread-safe, idle ones per target, never shared by two streams), and a reused one gets the stream's `FullFlowContext`; streams on HTTP/2 connections to servers come from `Http2Origins` (thread-safe, shared by design) and are never kept |
| `ClientFlowContext` timings and upstream status | the connection's | per stream (`new ClientFlowContext(connection, streamId)`) |
| `logPrefix` in exchange log lines | the connection's | the exchange's (`Exchange.log`) |
| `HttpLogger` sequence numbers | keyed by `FlowContext` | keyed by `getConnectionContext()`, an `AtomicLong` per connection |
| `ActivityLogger` maps, user maps keyed by `FlowContext` | one entry per connection | `equals` includes the stream id: one entry per exchange |
| `ConcurrencyLimiter` permits, `exchangeEnded`, `HttpFilters` | per exchange | unchanged: per exchange, already thread-safe across connections |
| `idle`, graceful stop | the HTTP/1 loop's flag | `isIdle()` asks the HTTP/2 connection (no open streams); `stopGracefully()` sends GOAWAY |
| `close()` | closes everything | also fails every stream (`Http2Connection.closed`) and closes busy stream server connections |

## HTTP/2 to servers: `Http2UpstreamConnection` and `Http2Origins`

With `withHttp2Upstream`, `connectVia` offers ALPN `h2` on TLS connections to servers (for
intercepted HTTPS; not for WebSocket upgrades). A connection whose handshake picks `h2` is marked
(`ServerConnection.http2`) and handed to `Http2Origins.adopt`, which runs it as an
`Http2UpstreamConnection` (the "carrier" keeps its socket, pool slot and trackers) and keeps it for
other exchanges. `proxyRequest` first asks `Http2Origins.stream` for a stream; `handleConnect` asks
`Http2Origins.session` whether the session's requests will have a connection, and then makes none.

- **Keys.** `http2Key`: mode, target, route (`routeKey`), MITM manager (`mitmPoolKey`), and the
  client connection (`"|conn" + id`) unless `http2Owner` says the connection may serve every
  client: the shared pool's own rule (`usesPool`: no PROXY header, no MITM manager that sets up
  server TLS per client). Private connections close with their client (`closeOwnedBy`).
- **Making connections.** A connection with room (`reserve`: below the server's
  SETTINGS_MAX_CONCURRENT_STREAMS, which `start` reads before the first stream) is used first.
  Otherwise the exchange claims the making of the next one for its key (`connecting`), and others
  wait for it, once, instead of making their own; the claimant reports how it went (`adopt`,
  `negotiatedHttp1`, `connectFailed`). Keys whose server chose HTTP/1.1 are remembered
  (`http1Only`) so their exchanges stop waiting for each other.
- **Threads.** A virtual thread per connection reads frames (`readFrames`); exchange threads write
  their own requests and wait for their stream's response heads and data. The shared timer closes
  connections idle for the idle timeout, and ones whose writes stall.
- **Locks.** `writeLock` and `stateLock` as in `Http2Endpoint`, with one exception: a stream gets its
  id under `writeLock` as its HEADERS are written (`open`), taking `stateLock` briefly to register
  it, so ids reach the server in order; `writeLock` is never taken under `stateLock`.
  `Http2Origins.lock` may be held while taking a connection's `stateLock` (to reserve a stream),
  never the other way round. No `synchronized`.
- **Flow control.** A stream's response data is buffered up to its window and credited back
  (`consumed`) only as the exchange reads it; the connection's window is credited back as data
  arrives, so a stalled stream holds up no other.
- **Failures.** `GOAWAY` stops new streams and fails those above its last stream id with
  `Unprocessed`; `REFUSED_STREAM` too. Other resets and connection errors fail their streams with
  plain `IOException`s, which the exchange logic turns into `ServerFailure`s (502, or a reset
  client stream once the response has started). Late frames on streams the proxy reset are
  ignored.
- **Bytes.** The connection reads and writes the carrier's raw socket streams (throttled like it)
  and counts bytes per frame, for the stream's `FullFlowContext`.

## What stays HTTP/1-specific, and why

- **The connection loop** (`serveRequests`): waiting for the next request without holding a
  buffer, pipelining (unread requests wait in the buffer), and answering unparseable request
  heads. An HTTP/2 connection reads frames and starts a thread per stream instead.
- **The TLS listener and interception** (`handshakeWithClient`, `intercept`). A `CONNECT` that is
  intercepted turns the whole connection into TLS and serves the decrypted requests with the same
  loop, or with `Http2Connection` when the client negotiates `h2`, which only an HTTP/1
  connection can do. Under HTTP/2, `CONNECT` is per stream (not supported yet: `501`). The `h2c`
  preface is recognized only as the first bytes of a plain connection.
- **`101 Switching Protocols`.** HTTP/2 has no upgrade. Its WebSockets use extended `CONNECT`
  (RFC 8441), which can implement `relay` for a stream.
- **The PROXY protocol header**, which is read when the connection starts.

## Notes for later

- `ALTSVC` frames (RFC 7838 section 4) from HTTP/2 servers are dropped by the frame reader, as a
  frame type the codec does not deliver; forwarding them would need the h3 filtering `Alt-Svc`
  headers get (`AltSvc`).
- Extended `CONNECT` (RFC 8441) would implement `relay` for a stream, and `supportsTunnels()`
  would become true for it.
- TLS for absolute `https://` URIs in plain requests (not made today, whatever the version) would
  let HTTP/2 to servers serve forward-proxy and `h2c` requests too.
- `AllocationTest` guards the allocation per small keep-alive request (about 4 KB with its
  allocation-free client; the README's 4.7 KB includes a simple benchmark client's own); the
  HTTP/2 additions cost HTTP/1 requests nothing.
