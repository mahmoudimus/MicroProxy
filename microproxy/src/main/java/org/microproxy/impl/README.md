# `org.microproxy.impl`: exchanges and transports

A client connection runs on one virtual thread in `ClientConnection`. Its code has two layers,
split so that HTTP/2 streams ([issue #2](https://github.com/mahmoudimus/MicroProxy/issues/2),
Phase 2) reuse everything but the wire format:

```
ClientConnection.run / serveRequests     HTTP/1 connection loop   (HTTP/1 only)
        │  request head                  └─ intercept: ALPN h2 ──► Http2Connection.serve
        ▼                                                          (frame reader, one thread per stream)
ClientConnection.handleRequest(channel, request)   exchange logic   (any transport)
        │  body, interim responses, response head and body, tunnel, close
        ▼
ClientChannel  ◄── Http1ClientChannel (ByteReader, HttpCodec, Framing, PooledOutputStream)
               ◄── Http2StreamChannel (one per HTTP/2 stream, many at once)
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
  `100-continue` towards the server, and server-side HTTP/1 (`ServerConnection`, which this split
  does not touch);
- response relay, including the choice of the zero-copy body relay when no filter inspects the body;
- the proxy's header rewriting (`Via`, hop-by-hop, `Alt-Svc` h3 stripping), `ResponseSource`,
  timings and trackers.

## HTTP/2: `Http2Connection` and `Http2StreamChannel`

When an intercepted handshake negotiates ALPN `h2` (offered only with `withHttp2`, and only when
the optional `http2-codec` module is present: `Http2Support`), `intercept` hands the TLS socket to
`Http2Connection.serve`, on the connection's own thread:

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
| `serverConnections` (one per target) | one exchange at a time per connection | still HTTP/1's; streams take server connections from `StreamServerConnections` (thread-safe, idle ones per target, never shared by two streams), and a reused one gets the stream's `FullFlowContext` |
| `ClientFlowContext` timings and upstream status | the connection's | per stream (`new ClientFlowContext(connection, streamId)`) |
| `logPrefix` in exchange log lines | the connection's | the exchange's (`Exchange.log`) |
| `HttpLogger` sequence numbers | keyed by `FlowContext` | keyed by `getConnectionContext()`, an `AtomicLong` per connection |
| `ActivityLogger` maps, user maps keyed by `FlowContext` | one entry per connection | `equals` includes the stream id: one entry per exchange |
| `ConcurrencyLimiter` permits, `exchangeEnded`, `HttpFilters` | per exchange | unchanged: per exchange, already thread-safe across connections |
| `idle`, graceful stop | the HTTP/1 loop's flag | `isIdle()` asks the HTTP/2 connection (no open streams); `stopGracefully()` sends GOAWAY |
| `close()` | closes everything | also fails every stream (`Http2Connection.closed`) and closes busy stream server connections |

## What stays HTTP/1-specific, and why

- **The connection loop** (`serveRequests`): waiting for the next request without holding a
  buffer, pipelining (unread requests wait in the buffer), and answering unparseable request
  heads. An HTTP/2 connection reads frames and starts a thread per stream instead.
- **The TLS listener and interception** (`handshakeWithClient`, `intercept`). A `CONNECT` that is
  intercepted turns the whole connection into TLS and serves the decrypted requests with the same
  loop, or with `Http2Connection` when the client negotiates `h2`, which only an HTTP/1
  connection can do. Under HTTP/2, `CONNECT` is per stream (not supported yet: `501`).
- **`101 Switching Protocols`.** HTTP/2 has no upgrade. Its WebSockets use extended `CONNECT`
  (RFC 8441), which can implement `relay` for a stream.
- **The PROXY protocol header**, which is read when the connection starts.

## Notes for Phase 3

- HTTP/2 to origins would add a server-side transport next to `ServerConnection`, with one
  multiplexed connection per origin shared by streams; `StreamServerConnections` is where streams
  would take a stream on it instead of a connection.
- `ALTSVC` frames (RFC 7838 section 4) from HTTP/2 origins will need the same h3 filtering as
  `Alt-Svc` headers (`AltSvc`).
- Extended `CONNECT` (RFC 8441) would implement `relay` for a stream, and `supportsTunnels()`
  would become true for it.
- `AllocationTest` guards the allocation per small keep-alive request (about 4 KB with its
  allocation-free client; the README's 4.7 KB includes a simple benchmark client's own); the
  HTTP/2 additions cost HTTP/1 requests nothing.
