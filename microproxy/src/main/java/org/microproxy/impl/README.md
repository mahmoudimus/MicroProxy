# `org.microproxy.impl`: exchanges and transports

A client connection runs on one virtual thread in `ClientConnection`. Its code has two layers,
split so that HTTP/2 streams ([issue #2](https://github.com/mahmoudimus/MicroProxy/issues/2),
Phase 2) can reuse everything but the wire format:

```
ClientConnection.run / serveRequests     HTTP/1 connection loop   (HTTP/1 only)
        │  request head
        ▼
ClientConnection.handleRequest(channel, request)   exchange logic   (any transport)
        │  body, interim responses, response head and body, tunnel, close
        ▼
ClientChannel  ◄── Http1ClientChannel (ByteReader, HttpCodec, Framing, PooledOutputStream)
               ◄── (later) one channel per HTTP/2 stream
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
  connection's single one; an HTTP/2 transport would give each stream its own.

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

## What stays HTTP/1-specific, and why

- **The connection loop** (`serveRequests`): waiting for the next request without holding a
  buffer, pipelining (unread requests wait in the buffer), and answering unparseable request
  heads. An HTTP/2 connection reads frames and starts a thread per stream instead.
- **The TLS listener and interception** (`handshakeWithClient`, `intercept`). A `CONNECT` that is
  intercepted turns the whole connection into TLS and serves the decrypted requests with the same
  loop, which only an HTTP/1 connection can do. Under HTTP/2, `CONNECT` is per stream.
- **`101 Switching Protocols`.** HTTP/2 has no upgrade. Its WebSockets use extended `CONNECT`
  (RFC 8441), which can implement `relay` for a stream.
- **The PROXY protocol header**, which is read when the connection starts.

## Notes for an HTTP/2 transport

- Exchanges on one connection would run concurrently. Connection-level state that the exchange
  logic uses still assumes one exchange at a time: the authentication state
  (`authenticated`, `acceptedUser`), `mitmHostAndPort` and the MITM manager choice. The
  per-client server connections (`serverConnections`) are already a concurrent map.
- `close()` would reset the stream, and `setKeepAlive` / `setUpgrade` would do nothing, since
  connection-specific fields are not allowed in HTTP/2.
- The fast path stays available: `writeData` would frame bytes as DATA frames. Whether to use it
  is still decided by the exchange logic.
- `ALTSVC` frames (RFC 7838 section 4) need the same h3 filtering as `Alt-Svc` headers (`AltSvc`).
- `AllocationTest` guards the allocation per small keep-alive request (about 4 KB with its
  allocation-free client; the README's 4.7 KB includes a simple benchmark client's own).
