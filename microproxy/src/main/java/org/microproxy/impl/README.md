# `org.microproxy.impl`: exchanges and transports

A client connection runs on one virtual thread in `ClientConnection`. Its code has two layers,
split so that HTTP/2 and HTTP/3 streams ([issue #2](https://github.com/mahmoudimus/MicroProxy/issues/2))
reuse everything but the wire format, on either side:

```
ClientConnection.run / serveRequests     HTTP/1 connection loop   (HTTP/1 only)
        │  request head                  ├─ intercept: ALPN h2 ───────► Http2Connection.serve
        │                                └─ plain listener: preface ──► (frame reader, one thread per stream)
        │                                Http3Listener (UDP) ─────────► ClientConnection.serveHttp3
        │                                                                └► Http3Connection (one thread per stream)
        │                                TransparentQuicListener (UDP) ┐
        │                                MasqueQuic (CONNECT-UDP flows)┴► QuicFlows: decideTransparentQuic, then
        │                                                                 serveTransparentQuic (as serveHttp3),
        │                                                                 serveQuicStreams (QuicSession), or a relay
        ▼
ClientConnection.handleRequest(channel, request)   exchange logic   (any transport)
        │  body, interim responses, response head and body, tunnel, close
        ▼
ClientChannel  ◄── Http1ClientChannel (ByteReader, HttpCodec, Framing, PooledOutputStream)
               ◄── Http2StreamChannel (one per HTTP/2 stream, many at once)
               ◄── Http3StreamChannel (one per HTTP/3 request stream, many at once)

ServerConnection ◄── itself: HTTP/1.1 (ByteReader, HttpCodec.HttpWriter), one exchange at a time
                 ◄── Http2UpstreamStream (one stream of a shared Http2UpstreamConnection, from Http2Origins)
                 ◄── Http3UpstreamStream (one stream of a shared Http3UpstreamConnection, from Http3Origins)
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
- **Ending the exchange.** `relay` passes bytes both ways for a `CONNECT` tunnel or after a `101`
  (through a `WebSocketRelay` when filters look at frames or messages: it parses frames, joins
  messages, and inflates and deflates permessage-deflate per hop with `PerMessageDeflate`; or,
  for a raw tunnel with a `TcpInterceptor`, through a `TcpSession` that runs the TCP hooks),
  `reject(status)` answers a malformed request, and `close` closes the connection.
- **Waiting.** `awaitUnlessClientLeaves` is the chained-proxy backoff wait, which stops early if
  the client disconnects.
- **The exchange's `ClientFlowContext`** (timings, upstream status). For HTTP/1 it is the
  connection's single one; each HTTP/2 or HTTP/3 stream has its own (`FlowContext.getStreamId()`,
  `getHttpVersion()`).
- **How exchanges share the connection:** `logPrefix()` (`[conn N]` or `[conn N stream S]`),
  `multiplexed()` (exchanges run concurrently and need server connections of their own),
  `supportsTunnels()` (`CONNECT` and WebSockets are possible), and `serverConnectionInUse` /
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
- `misdirected()` is true for a stream coalesced onto a connection made for another server name
  that the server answered `421`: the connection stops serving that name, and `readResponseHead`
  sends the request again on a connection of its own (`Misdirected`, through the stale-connection
  retry) when no body has been sent or the body can be sent again; any other `421` is relayed;
- when the client side is an HTTP/2 stream too, the request body is relayed by a `RequestPump`
  on a thread of its own while the exchange's thread relays the response (`fullDuplex`): only
  when no filter or chained proxy sees the body's pieces, so filters are never called from two
  threads at once. HTTP/1 clients stay half-duplex: their next request is read from the same
  buffer after this one's body.

`Http2Origins` keeps the HTTP/2 connections by `Key`: the server's authority, and its isolation
(mode, route or hop, MITM manager, and the client connection for private ones). Its index is by
isolation, then by every authority a connection serves: the one it was made for and, with
`Http2Options.coalesceConnections`, those coalesced onto it. `ClientConnection.coalescing` builds
the exchange's `Http2Coalescing.Request` (the TLS context the MITM manager gives the name, and on
direct routes the address, resolved as `connectVia` would and kept for it in `Exchange.preResolve`),
or none, which takes only a connection made for the authority. `Http2Coalescing.Peer` holds what
a connection may serve: its certificate's names, TLS context and address, the origin set of its
ORIGIN frames, and the names it was found to serve or answered `421` for.

## CONNECT: the client's first bytes decide

`handleConnect` decides at the `CONNECT` only what it can without the client: whether
interception is possible at all (a MITM manager, `proxyToServerAllowMitm()`, an ignore rule that
finds the target). When it is, the exchange sets `deferServerTls`, so `connectVia` makes the
connection (TCP, chained proxies, the PROXY header) but leaves its TLS for later: the
`ServerConnection` is `tlsPending`. Pooled TLS connections and a shared HTTP/2 connection
(`Http2Origins.session`, which may be one coalesced for another name) are used as before, and need
no handshake. The `200` is written, and
`serveEstablished` goes on: it relays a tunnel that cannot be intercepted, hands a `CONNECT`
stream to a connection of its own (`interceptStream`, below), and otherwise lets
`interceptOrTunnel` take over (mitmproxy's next-layer decision, `next_layer.py`):

- `peekClient` reads the client's first bytes through the connection's `ByteReader` without
  consuming them (`ensureBuffered`, `peekBuffered`, which grow past one pooled buffer when a
  ClientHello needs it). `TlsClientHello` (ported from mitmproxy's `tls.py` and its
  `tls_client_hello.ksy`) gathers the handshake message from as many records as it spans, up to
  `MAX_MESSAGE_SIZE`, and parses it into the public `ClientHello`. The wait for the first byte
  also watches the server (`serverSpoke`), every `SERVER_FIRST_CHECK_MILLIS`, for protocols where
  the server speaks first; the rest of the ClientHello must come within the TLS handshake
  timeout.
- `ClientStart` says what came: `TLS` (with the ClientHello, which goes into the connection's
  `ClientFlowContext`, where every flow of the connection reads it; inside a `CONNECT` stream, into
  the stream's too), `HTTP`, `OTHER` or `CLOSED`.
- TLS that `declineReason` lets through (host rules, an ALPN offer with no HTTP protocol,
  `MitmManager.shouldIntercept`, `HttpFilters.proxyToServerAllowMitm(ClientHello)`) gets the server
  handshake first (`startServerTls`, offering `upstreamAlpn`: the client's protocols that the proxy
  speaks), then the client's (`intercept`, whose `mirrorAlpn` selector picks the server's choice
  when the server was offered `h2`). The client's buffered bytes start that handshake:
  `Http1ClientChannel.startTls` drains them into `Tls.serverHandshake`, which hands them to
  `SSLSocketFactory.createSocket(socket, consumed, autoClose)`.
- Declined TLS and `OTHER` go to `tunnelAfterPeek`, which relays over the pending connection (or
  a new one when the connection is already TLS, or there is none); the relay reads the buffered
  bytes first. `HTTP` goes to `servePlainSession`: the connection's requests go to the `CONNECT`
  target in `Mode.PLAIN` (`plainSession`), on the pending connection when it is not pooled.
- A failed server handshake does not fail the client: `NotTlsServer` tunnels, and other failures
  intercept without a server connection, so each request reconnects and is answered with the
  failure (a `502`, `TlsFailed`).

Two pieces of the `CONNECT` exchange wait for this: its completion (`connectResponse`, so that
`responseCompleted` and the timings include the server handshake), and the claim on making the
`Http2Origins` connection for its key (`http2Claim`), which is reported once the server handshake
has told whether the server speaks `h2`, so that concurrent `CONNECT`s still share one HTTP/2
connection. Until the ClientHello has come, the claim is marked (`awaitingClientHello`), and
others wait for it at most `CLIENT_HELLO_GRACE_NANOS` (200 ms) from when it was marked: a client
that is slow to send its ClientHello, or never does, cannot hold up other clients' connections. `releaseHttp2Claim` and `completeConnect` run on every path out.

A tunnel that a session's server opened for a forwarded `CONNECT` (`openForwardedTunnel`, below)
goes the same way, with its tunnel as the pending connection.

The same flow serves connections that never sent a `CONNECT`: `serveImplicitConnect` makes one up
(`Exchange.implicit`), for TLS on a transparent listener (`serveTransparentTls`, routed by SNI)
and for `tcp://` reverse proxying. Nothing is written to such a client in HTTP: `respondDirect`
closes the connection instead. Other reverse proxy requests are pointed at the upstream in
`handleRequest` (`reverseProxyTarget`, before the filters) and sent there by
`handleFilteredRequest`, over TLS for `https://` upstreams (`proxyRequest`'s `tls`), unless a
filter gave one an absolute URI of its own (`redirected`), which goes to that URI's server.

SOCKS clients take the same way (`serveSocks`, on a SOCKS listener or when `startsLikeSocks` sees
their first byte). `SocksHandshake` (ported from mitmproxy's `Socks5Proxy`, in `modes.py`) runs the
handshake up to the request through the connection's `ByteReader`, within the TLS handshake
deadline (`ensureBuffered`), asking the authenticator through `socksAuthenticator` (credentials as
Basic on a `CONNECT` to `0.0.0.0:0`; `recordAuthentication` is shared with `authenticate`). The
request becomes an implicit `CONNECT` that knows its SOCKS version (`Exchange.socks`), and SOCKS
replies stand in for the HTTP answers: `answerConnect` writes the success reply where it would
write the `200`, after connecting, and `respondDirect` hands every refusal to `refuseSocks`, which
picks the reply code from the `ProxyFailure` that `respondFailure` noted (`Exchange.socksFailure`)
or from the refusal's status. Without a MITM manager, `handleConnect` still sends a SOCKS
connection through `interceptOrTunnel` (`inspect`), marking its plain connection `tlsPending` so
that `peekClient` watches the server and `tunnelAfterPeek` and `servePlainSession` reuse it;
`declineReason` declines every ClientHello then, and plain HTTP is served as HTTP. Its tunnels
reach `relay` only through `serveEstablished`, `tunnelAfterPeek` and `relayDecrypted`, as a
`CONNECT`'s (forwarded or not) and a `tcp://` reverse proxy's do, so each gets the `TcpSession`
(`tcpSession`) that runs the TCP hooks.

## HTTP/2: `Http2Connection` and `Http2StreamChannel`

When an intercepted handshake or the proxy TLS listener negotiates ALPN `h2` (offered with
`withHttp2`, when the optional `http2-codec` module is present: `Http2Support`), `intercept` hands the TLS socket to
`Http2Connection.serve`, on the connection's own thread; `run` does the same on the TLS listener.
With `withHttp2Cleartext`, `run` does the
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
does nothing; `setUpgrade` adds the upgrade fields to a WebSocket's 101, which filters see as
for HTTP/1, and `writeHead` sends it as the extended CONNECT's `:status 200`; `writeContinue`
sends `:status 100` only to a client that sent `expect: 100-continue`, and `writeInformational` forwards other 1xx as interim HEADERS; `writeData`
copies into DATA frames; `close` resets only the stream; `reject` answers and ends it.
`relay` runs the shared `Tunnel` (and `WebSocketRelay`) on the stream's `MessageBody` input and flow-controlled
DATA output. Successful CONNECT HEADERS leave the stream open even for a FullHttpResponse with
an empty payload. END_STREAM half-closes a direction; RST closes only the stream's server
connection (or server stream), not its carrier. A request for another authority in an
intercepted session gets `421` before reaching the exchange, and so does an extended CONNECT;
a plain CONNECT's authority is a tunnel's target, and a `:scheme http` request's a proxy request's,
which the exchange forwards (below).

RFC 8441 `:protocol websocket` is represented internally as a GET upgrade request, with a generated
HTTP/1 key, so existing exchange and frame filters work unchanged. `tunnelProtocol` and
`secureWebSocket` retain the stream's tunnel intent independently of rewritten request headers.
`:protocol connect-udp` becomes the same kind of GET upgrade (origin-form, its path naming the
UDP target) and, on a connection to the proxy's own listener, the stream is the `UdpFlow.Client`
of a CONNECT-UDP flow ([below](#connect-udp-udpflow)). Unknown extended protocols get 501 without
dialing a TCP tunnel.

A CONNECT stream is intercepted when an HTTP/1 CONNECT would be (`interceptStream`): the stream
is shown as a socket (`tunnelSocket`, a `StreamSocket`: its streams are the tunnel's DATA,
`setSoTimeout` is the read timeout, `shutdownOutput` sends END_STREAM, `close` ends the output and
fails reads), the JDK's `SSLSocket` is layered over it, and a `ClientConnection` of its own serves
it with `serveTunnel`, on the stream's thread. Its server TLS is deferred as for HTTP/1, so
`serveTunnel` runs `interceptOrTunnel` (above) on the stream's bytes, with the stream's exchange:
the ClientHello decides, a declined or non-TLS stream is relayed through the nested connection's
`ByteReader` (which holds the bytes read), and plain HTTP is served by its loop. Then `intercept`:
HTTP/1, or HTTP/2 inside HTTP/2. (So is a forwarded tunnel's stream, below, with its hop.) It
takes the outer connection's client details, PROXY header and MITM manager; its HTTP/2 connections
to servers are keyed and owned by the outermost connection (`owner`). `mitmManager()` chooses under
`mitmLock`, since CONNECT streams may ask at once. A reset of an open tunnel is not a rapid reset.
`StreamSocket` needs only `StreamSocket.Stream` of its stream (read timeout, end of output,
close), which `Http2UpstreamStream` provides too, for TLS through a proxy's tunnel (below).

### Proxy requests inside a session: the session's server as the client's proxy

A client that uses an HTTPS proxy, whose session MicroProxy intercepts, or an HTTP proxy, whose
session MicroProxy serves as plain HTTP (`servePlainSession`, `plainSession`), asks that proxy for
tunnels and plain-HTTP URIs inside the session. Both kinds of session set `mitmHostAndPort`, and
inside one a `CONNECT` or an absolute-form request is a proxy request for that server
(`isProxyRequest`).

`handleConnect` hands a `CONNECT` with `mitmHostAndPort` set to `forwardConnect`, which treats the
session's server as a chained proxy for the tunnel:

- **The hop.** A `Hop` names the proxy (`host:port`), whether it speaks TLS (`tls`: false for a
  plain session's), how it is reached (`parent`: another hop, for sessions nested in forwarded
  tunnels, or null for the usual routes), the `CONNECT` as it was forwarded (whose fields,
  `Proxy-Authorization` included, open every tunnel through it), and the proxy as an
  `InterceptedProxy`, the `ChainedProxy` that server connections through it carry.
- **The connection to the proxy** (`proxyConnection`): an idle HTTP/1.1 connection of the session
  (the first attempt only, and only one that reaches the proxy itself, `nextHopIsOrigin`), a
  stream on an HTTP/2 connection under the key the session's requests use (`Http2Origins.stream`),
  or a new connection made by `connect` with the session's routes (the chained proxy manager is
  asked about `CONNECT proxy:port`): TLS with the MITM manager for an HTTPS proxy, and for an HTTP
  proxy `Mode.TUNNEL`, a plain socket or a tunnel through chained proxies, never a connection
  that hands an HTTP chained proxy its requests (`ServerConnection.reachesOrigin`).
  `Http2UpstreamStream` sends a CONNECT's HEADERS without END_STREAM, with `:authority` its target;
  `Http2UpstreamConnection` frames no body after its 2xx (`StreamState.tunnel`).
- **The exchange.** `forwardConnect` runs `exchange` as for any request (filters, trackers,
  stale-connection retries; a CONNECT never has a streamed body), and `relayResponse` relays a
  refusal as any response, keeping `Proxy-Authenticate`. A 2xx stops there (`Exchange.tunnelOpened`),
  and `openForwardedTunnel` takes over. The tunnel becomes a connection to the target
  (`throughTunnel`: over the HTTP/1.1 connection's socket and reader, or the upstream stream's
  `StreamSocket`; `through` is the tunnel, which closes with it, and `tunnelThroughProxy` keeps
  half-closes), `tlsPending` when MITM applies to the target (and no ignore rule finds it). The
  response filters see the 2xx, and `serveEstablished` goes on with the hop as for a `CONNECT` to
  this proxy: `relay`, or, for an HTTP/2 client, `interceptStream` with the hop (`via`) given to
  the nested connection, while an HTTP/1 connection gives up the proxy's session
  (`releaseSessionConnections`), takes the hop itself, and serves the tunnel. Either way
  `interceptOrTunnel` reads the tunnel's ClientHello: `serverSpoke` watches the server through the
  tunnel (the stream's buffered DATA, over HTTP/2), `startServerTls` runs the proxy's TLS to the
  target inside it (`layerServerTls`), mirroring the client's ALPN and SNI, `tunnelAfterPeek`
  relays it, and `servePlainSession` serves plain HTTP over it.
- **Inside the tunnel** (`via` set), every other server connection is a new tunnel through the
  hop (`connect` → `connectThrough`: `proxyConnection`, CONNECT, `throughTunnel`, then
  `layerServerTls` for TLS, offering what a direct connection would). `lookupRoute` offers only
  that way, `usesPool` is false (the connections carry one client's credentials), and HTTP/2
  connections (the tunnel's own too, when its handshake chose `h2`: `adoptForSession`) are keyed
  by the hop's id and owned by the hop (`http2Owner`), which the connection serving the session
  (`Hop.consumer`) closes when it closes.
- **Half-closes.** Over an HTTP/2 stream, END_STREAM; over an HTTP/1.1 TLS connection, a TLS 1.3
  `close_notify` (`ServerConnection.tunnelThroughProxy`), which leaves the other direction open,
  where other TLS tunnels close the whole socket; over plain TCP, a TCP half-close.

An absolute-form request goes through `handleFilteredRequest`, which tells the client's absolute
URIs from the filters' by `redirected`: an absolute URI other than the one the request arrived
with (`Exchange.originalUri`) is a filter's, and goes straight to its server (the pin lifted);
the client's, unchanged, makes the exchange a proxy request (`Exchange.proxyForm`), pinned to
`mitmHostAndPort`. `proxyRequest` then keeps it in absolute-form (`nextHopOrigin` false), puts
back the client's `Proxy-Authorization` that the hop-by-hop stripping removed, routes it as a
`CONNECT` to the proxy would be (`routeFor`), never leases it from the pool (with a pool, or
plain with a chained proxy manager, its connections are keyed apart: `|proxy`), and connects a
plain one with `Mode.TUNNEL`. `relayResponse` keeps the proxy's `Proxy-Authenticate`. Upstream
HTTP/2 sends it as `:scheme http` (`Http2UpstreamStream.requestFields`), and an HTTP/2 client's
`:scheme http` request in an intercepted session is turned into absolute-form rather than
answered `421` (`Http2Connection`).

`ClientFlowContext.forwardedVia` (set by `handleRequest`, cleared for a filter's redirect) is what
`FlowContext.forwardedVia()` returns for the exchange: the session's server for a forwarded
CONNECT or proxy request, the hop's proxy inside a tunnel.

### Who picks the server

The rule that keeps the paths apart: a client's own `CONNECT` or absolute URI picks the server
only where the client is entitled to, and a filter's absolute URI always may.

- **Forward proxy** (no session): the request's authority is the server, by design, and its
  scheme says how to reach it: an `https://` (or `wss://`) URI, which an HTTP/2 stream's `:scheme
  https` becomes, or a secure WebSocket's extended `CONNECT`, goes over TLS that the proxy opens
  (`proxyRequest`'s `tls`, `Mode.TLS`), exactly as an intercepted session's requests do: the same
  `connectVia` and `serverTls` (the MITM manager's server context, `TlsFailed` and `UF` on
  failure), pool and `Http2Origins` keys, `Http2Coalescing.Request`, HTTP/3, and, through an HTTP
  chained proxy, a `CONNECT` tunnel (`isNextHopOrigin` is true for TLS) rather than absolute-form.
  With `withTlsOrigination(false)`, `handleFilteredRequest` refuses such a request the client sent
  (`originatesTls`: not a filter's `redirected` URI) with `BadRequest` before routing it.
- **Inside a session** (intercepted TLS, or plain HTTP after a `CONNECT`): the session's server,
  which the `CONNECT` chose; the client's proxy requests go there as they are (above).
- **Transparent**: the SNI (or `Host`) chooses, by design; inside an SNI-routed session, as in any
  session.
- **Reverse proxy**: never the client. `reverseProxyTarget` makes an absolute URI origin-form for
  the upstream before any filter runs (its authority survives only as a kept `Host`), so
  `redirected` cannot mistake it for a filter's; HTTP/2's `:authority` is only `Host`; and
  `handleFilteredRequest` refuses `CONNECT` (`400`) unless the proxy made it up (`implicit`, for
  `tcp://`, whose target is the upstream). Only filters and scripts send requests elsewhere.

### The concurrency audit

Everything the exchange logic touches on `ClientConnection`, and what makes it safe with streams
running at once:

| State | Before | Now |
|---|---|---|
| Authentication (`authenticated`, `accepted`, `acceptedUser`, `clientDetails` user) | per connection, one exchange at a time | only touched outside intercepted sessions (HTTP/1, sequential); streams exist only inside one and inherit its authentication (`multiplexed()` skips it) |
| `mitmHostAndPort`, `connectionMitm` / `mitmChosen` | written at the `CONNECT` | unchanged: written before any stream thread starts, only read by streams |
| `via` (a session inside a forwarded tunnel) | none | written before the session's requests start (in the nested connection's constructor, or by an HTTP/1 connection's own thread), only read by streams |
| `serverConnections` (one per target) | one exchange at a time per connection | still HTTP/1's; streams take server connections from `StreamServerConnections` (thread-safe, idle ones per target, never shared by two streams), and a reused one gets the stream's `FullFlowContext`; streams on HTTP/2 connections to servers come from `Http2Origins` (thread-safe, shared by design) and are never kept |
| `ClientFlowContext` timings and upstream status | the connection's | per stream (`new ClientFlowContext(connection, streamId)`) |
| `logPrefix` in exchange log lines | the connection's | the exchange's (`Exchange.log`) |
| `HttpLogger` sequence numbers | keyed by `FlowContext` | keyed by `getConnectionContext()`, an `AtomicLong` per connection |
| `ActivityLogger` maps, user maps keyed by `FlowContext` | one entry per connection | `equals` includes the stream id: one entry per exchange |
| `ConcurrencyLimiter` permits, `exchangeEnded`, `HttpFilters` | per exchange | unchanged: per exchange, already thread-safe across connections |
| `idle`, graceful stop | the HTTP/1 loop's flag | `isIdle()` asks the HTTP/2 or HTTP/3 connection (no open streams); `stopGracefully()` sends GOAWAY |
| `close()` | closes everything | also fails every stream (`Http2Connection.closed`, `Http3Connection.closed`) and closes busy stream server connections |

## HTTP/2 to servers: `Http2UpstreamConnection` and `Http2Origins`

With `withHttp2Upstream`, `connectVia` offers ALPN `h2` on TLS connections to servers (for
intercepted HTTPS, and for the `https://` URIs and secure WebSocket extended CONNECTs of forward-proxy
clients). A connection whose handshake picks `h2` is marked
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

### WebSockets to origin servers

`Http2UpstreamStream` sends a WebSocket GET upgrade as extended CONNECT only after the origin
advertises SETTINGS_ENABLE_CONNECT_PROTOCOL. A successful 2xx response is represented internally
as 101, with the HTTP/1 accept value where needed; `responseStatus` preserves the actual status for
exchange timings. Its tunnel I/O uses DATA and END_STREAM, and `close` resets only that origin
stream. Without the setting, `proxyRequest` releases the reserved stream and opens a separate
HTTP/1 connection while keeping the shared HTTP/2 connection for ordinary requests.

## Frame interception: `Http2Frames`

With a `FrameInterceptor` (`withFrameInterceptor`), each `Http2Endpoint` gets an `Http2Frames`
(`frames`); without one, `frames` is null and every path below is the old one, behind a null
check, so frames cost nothing extra. `Http2Frames` converts between the codec's frames and the
public `org.microproxy.frames.Http2Frame`, runs the interceptor, and checks what it returns
against the rules `FrameInterceptor` documents (`check`), putting END_STREAM where it belongs
(`withEndStream`); a result that breaks a rule, or a throwing interceptor, is logged and the
original frame used.

- **Received frames.** Both connections' `onFrame` count the frame against the rate limits first
  (`countReceived`, on the client side), then `intercepted` shows it to the interceptor and acts on
  what comes back as if the peer had sent it. HEADERS are decoded before interception and the
  result's fields handed to `onHeaders(id, endStream, ..., fields, ...)`, so HPACK state never
  depends on the interceptor; a block over the header list limit skips interception. DATA goes to
  `onData(id, wireLength, data, endStream)`: the first DATA acted on carries the frame's wire
  length (or an empty one does, if none is), and the difference between what the window counted
  and what the stream gets is credited back at once (padding, data removed) or owed from later
  credit (data added, a negative `unacked`). Bytes nobody will read are credited back as soon as
  they are worth a WINDOW_UPDATE, without waiting for reads that may never come. The reader
  delivers extension frames (`setDeliverUnknownFrames`) only when there is an interceptor.
- **Sent frames.** `writeHeaders`, `writeData`, `writeReset`, `writeGoAway`, `writePreface`,
  `sendWindowUpdates`, `applySettings` and `answerPing` show their frame to the interceptor before
  taking `writeLock`, and write what comes back (`writeFrames`, which encodes HEADERS under
  `writeLock` as before). `writeData` cuts data into pieces of at most `MAX_DATA_FRAME` first, and
  each DATA result then waits for window at its own size (`writeDataFrames`), so flow control
  counts what is actually sent. `Http2UpstreamConnection.open` is the exception: the HEADERS that
  open a stream are intercepted under `writeLock`, after the stream got its id, so ids reach the
  server in order.
- **Context.** `flowOf(stream)` and `flowOf(id)` give the exchange's `FlowContext` (the stream
  channel's, or the upstream stream's `FullFlowContext`); `frameConnectionId`,
  `frameClientAddress` and `frameServer` describe the connection for frames that belong to no
  exchange. A private upstream connection reports its owner's client connection; a shared one, -1.
- **SETTINGS received** are checked by `stricterSettings`, which applies both the original and the
  edited frame to the current peer settings and refuses an edit that would make the proxy less
  strict than the original; the edited values are then applied, as received ones would be.

Live HTTP/3 has `Http3Frames` (below). `org.microproxy.frames.Http3FramePipeline` (with
`Http3Streams`, which alone touches `http3-codec`, loaded once the pipeline is built) applies the
same rules to HTTP/3 stream bytes relayed by other means.

## HTTP/3: `Http3Connection` and `Http3StreamChannel`

With `withHttp3` (when the optional `quic` and `http3-codec` modules are both present:
`Http3Support`), `DefaultHttpProxyServer.start` binds an `Http3Listener`, a `QuicServer` on the
UDP port with the TCP listener's number, offering ALPN `h3` with the certificate the TLS
listener's `SslContextSource.getKeyMaterial` gives (or, for a reverse proxy, a
`CertificateAuthorityMitmManager` issues for the SNI). Each established QUIC connection becomes a
`ClientConnection` of its own (a constructor without a socket: its `Http1ClientChannel` is never
attached), served by `serveHttp3` on the server's connection executor, so a graceful stop waits
for it as for TCP clients.

`Http3Connection.Role` says who the client takes the proxy for:

- `REVERSE`: a reverse proxy's listener; requests are origin-form, for the upstream.
- `FORWARD`: a forward proxy's listener, next to its TLS listener (a forward proxy without one,
  and a transparent proxy, refuse to start with HTTP/3). Requests are made absolute-form from
  `:scheme` and `:authority` (`Http3Messages.toHttp1(head, bodyFollows, true)`), as an HTTP/1
  client sends a proxy, and each stream authenticates on its own (`authenticateStream`, a `407`
  on the stream), as `h2c` streams do. Only this listener sends SETTINGS_H3_DATAGRAM and accepts
  QUIC DATAGRAM frames (`Http3Listener.serverConfig(..., datagrams)`: the `max_datagram_frame_size`
  transport parameter), for CONNECT-UDP; the others refuse them, since nothing would read them.
  It advertises no `Alt-Svc`: its responses are its servers'.
- `INTERCEPTED`: a transparent QUIC flow (below), whose `target` is the SNI's host. A request
  for another host gets `421` before any exchange (`misdirected`, by host only: the port is the
  one a firewall redirected), as on an intercepted HTTP/2 connection; a plain `CONNECT` and a
  `:scheme http` request are proxy requests for that server, which the client takes for its
  proxy, and go there (`forwardConnect`, proxy requests), as over HTTP/2.

`Http3Endpoint` is what both ends of an HTTP/3 connection share, as `Http2Endpoint` is for HTTP/2:

- **Streams.** `start` opens the proxy's control stream (SETTINGS: QPACK_MAX_TABLE_CAPACITY,
  MAX_FIELD_SECTION_SIZE and QPACK_BLOCKED_STREAMS, then `extensionSettings`: a client's
  connection adds ENABLE_CONNECT_PROTOCOL, and a forward proxy's H3_DATAGRAM) and its QPACK
  encoder and decoder streams. `awaitPeerSettings` waits, briefly, for the peer's SETTINGS where
  they decide something (an upstream's extended CONNECT, a client's HTTP Datagrams). `acceptStreams`
  takes the peer's streams on the connection's thread: each unidirectional one is read on a
  virtual thread of its own (control: SETTINGS, GOAWAY; QPACK encoder and decoder instructions;
  unknown and reserved types abandoned with `STOP_SENDING H3_STREAM_CREATION_ERROR`, within a
  rate limit; push streams are an error, since the proxy never sends MAX_PUSH_ID), and request
  streams go to `onRequestStream`.
- **QPACK.** One `QpackEncoder` and one `QpackDecoder` per connection, both with the dynamic table
  (`Http3Options.qpackMaxTableCapacity`, 4096 by default). `encodeFields` encodes a section and
  writes the instructions it needs under one hold of `encoderLock`, so they reach the peer in
  order. `decodeFields` decodes under `decoderLock`; a section that waits for the encoder stream
  waits on its condition, at most the idle timeout (H3_REQUEST_REJECTED then), and one blocked
  stream past QPACK_BLOCKED_STREAMS is a connection error. Section acknowledgements, stream
  cancellations and insert count increments go out on the decoder stream as they arise.
- **Locks.** `encoderLock`, `decoderLock`, `stateLock` (the peer's settings and GOAWAY, the rate
  limits) and `controlLock` (writing the control stream) are independent: none is taken while
  another is held, except that applying the peer's SETTINGS takes `encoderLock` and then, after
  releasing it, `stateLock`. No `synchronized`.
- **Errors.** An `Http3Exception` that is a connection error closes the QUIC connection with its
  code (`connectionError`); a stream error resets the stream both ways with its code.

Each request stream has an `Http3StreamReader`, which reads its frames on a virtual thread of its
own (decoding field sections, running the interceptor, checking frame order and
`content-length`) and queues the head, the body and the trailers for the exchange, at most 64 KiB
of body ahead: past that its reading waits, and QUIC, which credits the peer only for what is
read, holds the peer back. An `Http3MessageWriter` writes the stream's HEADERS, DATA and trailers
and ends it with the FIN; its writes wait for QUIC's flow control and send window.

`Http3Connection` serves a client:

- **Threads.** The connection's thread accepts streams. Each request stream starts its reader and
  a virtual thread that waits for the request head, turns it into an HTTP/1-style request
  (`Http3Messages.toHttp1`: origin-form or, by the role, absolute-form, `Host` from `:authority`,
  version `HTTP/3.0`, chunked towards HTTP/1.1 servers when the length is unknown) and runs
  `ClientConnection.handleStream` through the stream's `Http3StreamChannel`. HTTP/3 has no
  END_STREAM flag on HEADERS, so the thread waits up to 20 ms for the stream's end before deciding
  that a request without `content-length` has a body (not for a `CONNECT`, whose stream stays open).
- **CONNECT** (`Http3Messages.toHttp1Connect`). A plain `CONNECT` is an HTTP/1.1 client's, its
  target `:authority`. An extended `CONNECT` becomes the HTTP/1.1 upgrade an HTTP/1.1 client
  sends for its `:protocol`: a `GET` with `Connection: Upgrade` and `Upgrade` (`websocket`, with a
  generated `Sec-WebSocket-Key`, absolute-form on a forward proxy; `connect-udp`, origin-form,
  since its authority is the proxy's own). The stream remembers `:protocol` and `:scheme`
  (`requestRead`). The reader marks a `CONNECT`'s stream: HEADERS after the request's are a
  connection error H3_FRAME_UNEXPECTED (RFC 9114 section 4.4), and an extended one's DATA are no
  message body (`hasBody` is false).
- **Answered before any exchange.** A head over MAX_FIELD_SECTION_SIZE gets `431` (the decoder
  still processed the section, so the connection goes on), a malformed one a stream error
  H3_MESSAGE_ERROR (a WebSocket's `:scheme` must be `http` or `https`, its `:path` absolute), and
  an intercepted connection's request for another host `421`.
- **Limits** (`org.microproxy.Http3Options`): the request streams a client may have open are
  QUIC's limit (`maxConcurrentBidiStreams`), which the transport enforces; MAX_FIELD_SECTION_SIZE
  defaults to the HTTP/1 parser limits; rate limits for unknown and empty frames, unknown streams
  and requests reset before their response (Rapid Reset) end the connection with
  H3_EXCESSIVE_LOAD.
- **Ending streams.** A stream whose response is complete while the request still arrives gets
  `STOP_SENDING H3_NO_ERROR`; one the exchange abandons is reset both ways with
  H3_REQUEST_CANCELLED, one that failed with H3_INTERNAL_ERROR. A client's reset closes the
  exchange's server connection, as an HTTP/2 RST_STREAM does; a reset that ends an open tunnel
  (`tunnelOpen`) is no rapid reset.
- **Graceful stop.** GOAWAY names the first stream not processed; later streams are refused with
  H3_REQUEST_REJECTED, and the connection closes once its streams are done and the client has
  closed it, or after two seconds.
- **Resumption and early data.** `Http3Listener.serverConfig` gives every QUIC server that
  serves HTTP/3 (the HTTP/3 listener, the transparent QUIC listener and `MasqueQuic`'s) session
  tickets sealed with the proxy's `Ticketer` (one per `DefaultHttpProxyServer`, `quicTicketer`,
  typed `Object` so the class loads without the module) and, with `Http3Options.zeroRtt`, 0-RTT
  under one anti-replay `EarlyDataPolicy` they share (`quicEarlyDataPolicy`), so that a ticket's
  early data is accepted once in all. `QuicFlows.streamsConfig`, for QUIC intercepted stream by
  stream, has no ticketer: no resumption, no 0-RTT. A QUIC server hands out a connection that
  accepted 0-RTT before its handshake completes, so `serveHttp3` may start on one still
  handshaking. `readRequest` checks the stream's `receivedEarlyData()`: such a request marks its
  `ClientFlowContext` (`earlyData`, which `FlowContext.isEarlyData()` and `ctx.early_data`
  report), gets `425` if it is a `CONNECT` (extended or not) or not `replaySafe` (`GET`, `HEAD`
  or `OPTIONS` without a body), and otherwise gets `Early-Data: 1` before any filter runs.
  Requests are not held for the handshake.

`Http3StreamChannel` is `Http2StreamChannel` over QUIC: `clientKeepAlive` true, `adaptFraming`
drops `Transfer-Encoding`, `setKeepAlive` does nothing, `writeContinue` answers only `Expect:
100-continue`, `close` resets the stream. Its `ClientFlowContext` has the QUIC stream id and
`HttpVersion.HTTP_3_0`. Tunnels work as HTTP/2's:

- **Opening.** `writeHead` turns the response that opens a tunnel (a `CONNECT`'s 2xx, or the `101`
  of an extended `CONNECT`, which `setUpgrade` gave `Upgrade` and `Connection` for filters) into
  HEADERS `:status 200` without the FIN, minus `Sec-WebSocket-Accept`, `content-length` and
  `transfer-encoding`, and sets `tunnelOpen` before writing it.
- **Relaying.** `relay` runs the shared `Tunnel` between the reader's body (as an input stream,
  with a read timeout of its own: `Http3StreamReader.setReadTimeout`) and a `TunnelOutput` of
  DATA frames, with the WebSocket relay or the TCP hooks; the stream's FIN half-closes one
  direction (`endTunnelOutput` is the writer's `end`). When the tunnel ends with either side
  unfinished, `closeTunnelStream` resets what is left: H3_CONNECT_ERROR for a `CONNECT` (RFC 9114
  section 4.4), H3_REQUEST_CANCELLED for a WebSocket (RFC 9220).
- **As a socket.** `tunnelSocket` gives a `StreamSocket` over the same streams, so
  `interceptStream` serves an intercepted `CONNECT`'s TLS with a `ClientConnection` of its own
  inside the stream, and `interceptOrTunnel` reads its first bytes: the ClientHello peek, the host
  rules, ALPN mirroring, plain HTTP, `--tcp-hosts`, the TCP hooks and forwarded hops, as for
  HTTP/1 and HTTP/2. `closeTunnel` fails reads (`closeInput`) and ends the output, or resets it
  when a write is in progress.

### CONNECT-UDP: `UdpFlow`

On a forward proxy that serves CONNECT-UDP (`DefaultHttpProxyServer.connectUdpTemplate` set: with
HTTP/3, or `withConnectUdp`), an extended `CONNECT` with `:protocol connect-udp` on its HTTP/3
listener or an HTTP/2 connection to its own listener reaches `handleFilteredRequest` as `GET
<path>` with `Upgrade: connect-udp`, after authentication and `clientToProxyRequest`, and goes to
`handleConnectUdp`; so does an HTTP/1.1 request that is that upgrade itself (`connectUdpUpgrade`).
Anywhere else the extended `CONNECT` gets `501`, through the `ClientChannel.udpClient()` being null
or the template. The flow's client (`UdpFlow.Client`) is the transport's: `Http3StreamChannel`,
`Http2StreamChannel`, or `Http1ClientChannel.UdpClient` over the connection.

- **The target.** `ConnectUdpTemplate` matches the request's path (and query) against the URI
  template (`Http3Options.connectUdpTemplate`, by default
  `/.well-known/masque/udp/{target_host}/{target_port}/`), percent-decoding the variables; no match
  is a `400`. The route is looked up as for `CONNECT host:port` (`lookupRoute(connectRequest(..))`):
  chained proxies carry no UDP, so a route without the direct fallback is refused (`502`).
  `proxyToServerRequest` may answer; the bounds (`connectUdpMaxFlows`, in total in
  `DefaultHttpProxyServer.udpFlows`, and per connection in `Http3Connection.addUdpFlow` and
  `Http2Connection.addUdpFlow`; an HTTP/1.1 connection has one) give `503`; `resolveServer`
  resolves the name with the filters' resolution hooks and the server's `HostResolver`; a
  `DatagramChannel` is connected to the address.
- **Accepting.** The flow is attached to the connection (its datagrams are routed from then on),
  then the proxy's `101` with `Upgrade: connect-udp` and `Capsule-Protocol: ?1` goes through
  `serverToProxyResponse` and `proxyToClientResponse` (a filter may refuse with another answer),
  and `writeHead` sends it as `200` on an HTTP/2 or HTTP/3 stream, as it is to an HTTP/1.1
  client. `UdpFlow.run` then relays on the exchange's thread.
- **HTTP Datagrams.** `Http3Connection.receiveDatagrams`, a virtual thread started with the first
  flow, reads the connection's QUIC DATAGRAM frames: a quarter stream ID (one over 2^60 - 1, or
  none, is H3_DATAGRAM_ERROR) and content for that stream's flow; other streams' are dropped.
  `sendHttpDatagram` sends one when the client's SETTINGS (waited for) have H3_DATAGRAM and it fits
  `maxDatagramSize`; otherwise `Http3StreamChannel.sendDatagram` writes a DATAGRAM capsule on the
  stream. Content is a context ID, then for ID 0 a UDP payload; other IDs are dropped.
- **Capsules.** The stream's DATA (for HTTP/1.1, the connection's bytes after the `101`) are
  capsules (RFC 9297 section 3.2), which `UdpFlow` reads with the stream's read timeout set to a
  fraction of the idle timeout (`IdleChecking`): DATAGRAM capsules go the way QUIC datagrams do,
  unknown ones are skipped without being buffered, one too large for a UDP payload ends the flow.
  HTTP/2 and HTTP/1.1 have no datagrams: every payload goes to the client as a capsule
  (`UdpFlow.datagramCapsule`), in `Http2StreamChannel.sendDatagram`'s DATA, which wait for send
  window under the stream's `tunnelOutput` lock, or on the connection under the client's own.
- **Queues and threads.** Each direction has a bounded `Queue` (`connectUdpQueue`: datagrams and
  bytes) that drops what does not fit, and a virtual thread that sends from it (to the target's
  socket; to the client, as QUIC datagrams or capsules, which wait for flow control); a third
  thread receives from the target. The `UdpInterceptor` runs on the sending threads, not the
  connection's datagram thread. ICMP errors (`PortUnreachableException`) are ignored, as UDP
  does.
- **Ending.** The client's FIN ends the flow and is answered with the proxy's FIN (or a reset, when
  a capsule write is blocked: over HTTP/2 and HTTP/1.1 after waiting briefly for the capsule
  being written, which the client may have read before it ended its side); so does the idle
  timeout (`connectUdpIdleTimeout`). A socket failure resets the stream with H3_CONNECT_ERROR
  (HTTP/2: `CANCEL`; HTTP/1.1: the connection closes). `end` closes the queues and the socket,
  once, calls `udpEnd`, and the flow is detached from the connection.

## Transparent QUIC: `TransparentQuicListener` and `QuicFlows`

With `withTransparentQuicPort`, `DefaultHttpProxyServer.start` binds a `TransparentQuicListener`:
a `QuicServer` (offering `h3`, with `Http3Listener.serverConfig`, whose certificate selector asks
the `CertificateAuthorityMitmManager` for the SNI's certificate) whose `QuicServer.DatagramFilter`
is a `QuicFlows`'. The QUIC server's receiving thread routes the datagrams of its own connections
first, by the connection IDs it issued; everything else goes to `QuicFlows.filter`, which keeps
flows by client address.

`QuicFlows` holds the per-flow logic, apart from any socket, so that the transparent listener and
QUIC inside CONNECT-UDP flows (`MasqueQuic`, below) share it. Each flow has an `Origin`, which
says what the flow's server is (`destination`: the SNI's host on the transparent TLS port for the
listener, the CONNECT-UDP target for a flow), where it is (`address`), which `ClientConnection`
decides on it (`connection`), and whether it relays a flow itself (`relay`: a CONNECT-UDP flow
sends the held datagrams to its target and keeps the rest; the listener's flows get a socket of
their own, here). `QuicFlows` takes the QUIC server it serves in `start`, after the server exists,
since the server's filter is its own.

- **Pending.** A client's first Initial (a v1 or v2 long header Initial, in a datagram of 1200
  bytes or more) starts a `Flow` keyed by the client address and the Initial's Destination
  Connection ID, within the pending bounds. Its datagrams are held, and `QuicClientHello` (ported
  from mitmproxy's `quic/_client_hello_parser.py`) reads them: it decrypts each Initial packet on
  a copy with the keys of `Keys.initial(version, dcid, true)`, decodes the frames
  (`FrameDecoder`), puts the CRYPTO data where its offset says (a `TreeMap` of received ranges),
  and once the first `4 + length` bytes are there, hands the message to `TlsClientHello.parse`.
  Anything unreadable drops the flow. A datagram of another version, or not QUIC, with no flow
  goes back to the QUIC server, which answers Version Negotiation or drops it.
- **Deciding**, on a virtual thread per flow: the origin's `ClientConnection` (a new
  `ClientConnection(server, clientAddress)` for the listener) runs `decideTransparentQuic`, which
  marks its `ClientFlowContext` (`transparentQuic`), records the ClientHello, reports the client
  and a made-up `CONNECT` to the origin's destination to trackers, asks the authenticator (unless
  the connection is authenticated already), makes the filters (kept as `quicFilters` until the
  flow ends, for `exchangeEnded`) and applies the same checks as `declineReason` (the host rules
  against the destination and the SNI on its port), then the ALPN: `h3` is `INTERCEPT`; a
  `quicHosts` host, or another ALPN with a `QuicInterceptor`, is `STREAMS`; another ALPN without
  one is `RELAY`; then whether a certificate can be issued, `shouldIntercept` and
  `proxyToServerAllowMitm(hello)`. It answers `INTERCEPT`, `STREAMS`, `RELAY` or `DROP`, with
  why.
- **Stream by stream** (`STREAMS`): still on the deciding thread, `ClientConnection.connectQuic`
  connects to the server (`QuicSession.connect`: a `QuicClient` of the flow's own, the client's
  SNI and ALPN protocols, the manager's `serverTrustManager`), waiting up to the pending timeout.
  The client is then accepted with a `ServerConfig` of its own (`streamsConfig`: an ALPN selector
  answering the server's choice, DATAGRAM frames when the server takes them, room for streams of
  both kinds), which `QuicServer.inject(from, datagram, config)` gives the connection the held
  Initials start. The accepted connection and the server's go to
  `DefaultHttpProxyServer.acceptQuicStreams`, which serves them with `serveQuicStreams`.
- **Intercepting.** The held datagrams are injected into the QUIC server in order, under the
  listener's lock, and the flow stays (state `INTERCEPTED`) for the pending timeout to inject
  stragglers until the endpoint routes them itself. The deciding `ClientConnection` waits in
  `accepting`, keyed by the client address and that Destination Connection ID, which the accepted
  `QuicConnection` names (`initialDestinationId`); `DefaultHttpProxyServer.acceptTransparentQuic`
  then serves it on the connection executor with `serveTransparentQuic`, which is `serveHttp3`
  with `mitmHostAndPort` set: the requests go to the SNI's host as an intercepted session's do,
  and `sessionHello` is null, so servers are offered `h2` and `http/1.1` (the client's ALPN says
  only `h3`). With Retry, the QUIC server answers the injected Initial; the client's next Initial
  (a new Destination Connection ID) starts a pending flow again, whose ClientHello is matched to
  the `accepting` entry of its address and SNI instead of being decided on again.
- **Relaying.** The SNI's host is resolved with the server's `HostResolver`, and a connected
  `DatagramChannel` of the flow's own sends the held datagrams, then each one the filter matches
  to the flow. A virtual thread reads the server's datagrams, learns the server's connection IDs
  (the Source Connection ID of its long header packets) and sends them to the client with
  `QuicServer.send`, from the listener's socket. The filter matches a client's datagram to a
  flow by the Initials' Destination Connection ID or a learned server ID; failing that, anything
  but an Initial goes to the address's most recently active relayed flow.
- **Clients that move.** An intercepted connection follows its client inside the QUIC module (the
  endpoint routes by connection ID, the connection validates the new path and answers there), so
  `QuicFlows` has nothing to do for it. A relayed flow's client that moves sends short header
  packets from an address with no flow: `QuicFlows.moved` looks for the flow in `byServerId` (every
  relayed flow's known server IDs, tried at each length in use, `serverIdLengths`), then among
  `relayedByIp` of the client's IP address by the longest common prefix of at least
  `MIN_CID_PREFIX` (4) bytes with a known server ID (`byPrefix`), then the most recently active
  flow of that IP address. `rekey` moves the flow to the new address in `flows` and
  `relayedByIp` (and the per-IP count when the IP changed), and `Flow.client`, which is volatile,
  is where `relayReplies` sends from then on. `learnClientId` adds the Destination Connection ID
  of a client packet that matched no known ID, at the length all the flow's server IDs share (none
  when they differ), so that later packets match exactly; `remember` keeps at most 8 IDs per flow,
  forgetting the oldest. Long header packets never move a flow (migration comes after the
  handshake), so a new client's 0-RTT packets cannot be taken for another flow's.
- **Ending.** A sweeper thread, every half second or so, forgets pending flows past their
  timeout, intercepted flows past their routing window, `accepting` entries whose handshake never
  completed, and relayed flows idle past `transparentRelayIdleTimeout`, telling their
  `ClientConnection`s (`endTransparentQuic`: filters' `exchangeEnded`, `clientDisconnected`).
- **Locks.** One `ReentrantLock` guards the flows, the indexes, the counts and `accepting`; it is held while
  injecting and while writing to a relay's socket, so datagrams keep their order, and never while
  deciding, resolving, connecting or calling trackers. The QUIC server's endpoint lock is taken
  under it (by `inject`), never the other way round; so are a CONNECT-UDP flow's queue locks (an
  origin relaying a flow). No `synchronized`.

### QUIC relayed stream by stream: `QuicSession`

`QuicSession` pairs the client's connection, accepted by the proxy, with the proxy's connection
to the server, and implements `QuicContext` for the `QuicInterceptor` (when there is none, for a
`quicHosts` host, it relays without hooks).

- **Threads.** Two virtual threads accept the streams each side opens and open each on the other
  connection (`openBidirectionalStream` waits while the peer's stream limit is reached, which
  holds further streams back, and keeps the order, so stream IDs usually match); two relay
  datagrams, dropping one the receiver does not take or that is too large; and each stream has,
  per direction, a pump and a watcher.
- **Pumps.** A pump reads at most 16 KiB (`BUFFER`) from the source, calls `streamData` and
  writes the result to the sink, blocking while the sink's flow control holds it: nothing is
  buffered beyond the one read (and, with framing, a message's bytes), so flow control is end to
  end. The source's FIN calls
  `streamFinished`, then closes the sink's output; a `QuicStreamException` of kind `RESET` calls
  `streamReset` and resets the sink with the same code; one of kind `STOPPED` (the sink's side
  asked to stop) is a stop. Each direction's `Direction` has a lock its writes, and
  `QuicStreamContext.send` from other threads, take; `send` from the hook's own thread queues the
  bytes until the hook's result is written, as `TcpSession` does.
- **Messages.** The session's framer is chosen once, in the constructor: only when the
  interceptor's class overrides `streamMessage` (checked by reflection, cached in a `ClassValue`,
  as `ClientConnection` checks filters' WebSocket hooks), by `QuicFraming.framerFor(alpn, host,
  sni)`. Then each `Direction` has a `MessageAssembler`, and the pump hands it each read instead
  of calling `streamData`: it keeps the bytes that do not make a whole message (asking the
  `MessageFramer` for the length of the next one, which a length prefix gives before the rest has
  arrived), and returns the whole ones. Each goes through `streamMessage`; what it returns is
  framed again (`MessageFramer.frame`) and written under the direction's lock, or, for a message
  whose `fromClient` names the other direction, sent there as `QuicStreamContext.send` sends.
  A hook that throws, or a payload that cannot be framed, passes the message on as it came. The
  bytes kept when the source finishes are written as they are, before the FIN. When the
  assembler fails (a message over `maxMessageSize`, or a framer that throws or says a length below
  1), `Stream.abort` marks both directions ended under their locks first, so that neither pump
  passes on what a peer does in answer (a server that finishes its side when its input is reset),
  then resets both sinks and stops both sources with the framing's error code; the hooks are not
  told. Without a framer nothing is kept, and the pump is as before.
- **Watchers.** A sink's STOP_SENDING shows only when a write fails, so a watcher waits for it
  with `QuicStream.awaitStopped()` and then, once per direction, calls `streamStopped`, asks the
  source to stop with the same code (which ends the pump's read) and resets the sink.
- **Ending.** Either accept loop ending (its connection gone) ends the session: the other
  connection is closed with the same application code and reason (an application close) or with
  code 0, both are closed, the threads joined, and `quicEnd` or `quicError` called.
  `ClientConnection.close` closes a session that is running, for the proxy's stop.

### QUIC inside CONNECT-UDP flows: `MasqueQuic`

With `Http3Options.connectUdpInterceptQuic`, a forward proxy serving CONNECT-UDP (over any
transport, with or without its HTTP/3 listener) makes one `MasqueQuic`:
a `QuicFlows` over `QuicServer.unbound`, a QUIC server without a socket. `serveUdpFlow` attaches
each flow to a port of `connectUdpQuicPorts` (`MasqueQuic.attach`), giving it an address of its
own (an IPv6 unique local address with a counter) and an `Inner`, the flow's `Origin`:

- **The first datagram** the client sends decides (`Inner.fromClient`, called by
  `UdpFlow.fromClient` before it queues a payload): a QUIC Initial of a version the proxy reads
  puts the flow in `QUIC` mode, and so does a packet of a connection the unbound server knows
  (`QuicServer.knows`, by connection ID): an intercepted connection its client carried over from
  another flow, which follows it here as to a new address. Anything else puts it in `RELAYED`
  mode, for good.
- **QUIC mode.** Payloads go to the unbound server's `receive` under the flow's address: those of
  an intercepted connection reach it by connection ID, others go through the server's filter to
  `QuicFlows.filter`, which holds and decides as for the listener. The server's datagrams for the
  address go back into the flow (`UdpFlow.toClientFromProxy`), past the UDP hooks.
- **Relaying.** `Inner.relay`, under the flows' lock, switches the flow to `RELAYED` and queues
  the held datagrams for the target (`UdpFlow.toTargetFromProxy`, through the UDP hooks); a
  datagram that raced the switch reaches `QuicFlows.filter` and is handed back
  (`Origin.takeRelayed`), after them.
- **Deciding** uses a `ClientConnection(parent, targetAddress)`: the MASQUE client's address,
  user, PROXY header and MITM manager, authenticated already, and `pinnedServer`, the flow's
  address, which `resolveServer` returns for the session's server. An intercepted HTTP/3
  connection's `mitmHostAndPort` is the target, or, for an IP address, the SNI on the target's
  port, so the server's certificate is checked against the name.
- **Ending.** `UdpFlow.end` calls `Inner.ended`: the flow's address is forgotten, its pending flows
  and handshakes too (`QuicFlows.forget(origin)`), the intercepted connections still on the
  flow's address are closed (`Origin.intercepted` hands each to `MasqueQuic`; one that moved to
  another flow stays), and a relaying client connection is told.

## HTTP/3 to servers: `Http3UpstreamConnection` and `Http3Origins`

With `withHttp3Upstream`, `proxyRequest` asks `Http3Origins.stream` for a stream before any TCP
connection, when the server is known to speak HTTP/3 (`http3Port`) and the request goes there
directly (`directRoute`: no chained proxy, no hop, no PROXY header, not a proxy request); even a
TCP connection at hand (the one an intercepted `CONNECT` made) waits for later. Requests from any
client, HTTP/1, HTTP/2 or HTTP/3, take this way. A WebSocket does when the server's SETTINGS
(waited for up to the handshake timeout) enable extended CONNECT: `Http3UpstreamStream` sends it
as `CONNECT` with `:protocol websocket` and shows its 2xx as an HTTP/1.1 server's `101`, and its
DATA are the tunnel's (`tunnelInput`, `tunnelOutput`); otherwise the WebSocket takes an HTTP/1.1
connection of its own, as without HTTP/2's RFC 8441.

- **Learning.** `relayResponse` hands every response from a TLS server to `Http3Origins.learn`
  before filters or the h3 stripping see it: an `h3` alternative on the server's own host
  (`AltSvc.http3`; other hosts are never used) is remembered for its `ma`, and `clear` or `ma=0`
  forgets it. `withHttp3UpstreamHosts` patterns name servers reached over HTTP/3 without an
  advertisement, on their URI's port. An intercepted transparent QUIC flow tells it that its host
  speaks HTTP/3 on its own port (`spoke`), unless an advertisement says otherwise.
- **Keys and sharing.** One `Http3UpstreamConnection` per server, port and trust (the MITM
  manager's `serverTrustManager`, or the JDK's default trust store; a manager whose context the
  proxy cannot reproduce keeps the server on TCP), shared by every client: nothing about a QUIC
  connection is particular to one. A `QuicClient` endpoint per trust and address family makes them.
- **Making a connection** (happy eyeballs, lite). The exchange that needs one claims its making;
  others for the same key wait for it, once, up to the handshake timeout. A handshake that fails
  or outlasts `upstreamHandshakeTimeout` (1 s) sends them all over TCP, and the key stays on TCP
  for `upstreamFailureTimeout` (5 minutes).
- **Streams.** `Http3UpstreamConnection.open` opens a request stream, waiting while the server's
  stream limit is reached; `Http3UpstreamStream` writes the request through an
  `Http3MessageWriter` and reads the response through an `Http3StreamReader`, on the exchange's
  thread, as `Http2UpstreamStream` does. Its `close` resets what is still open of the stream.
- **Failures.** A GOAWAY stops new streams and fails those it did not process with `Unprocessed`,
  as does a reset with H3_REQUEST_REJECTED: the exchange logic sends those again. The QUIC idle
  timeout is a `SocketTimeoutException` (`504`); other resets and connection errors are
  `IOException`s (`502`, or a reset client stream once the response has started).
- **Resumption and 0-RTT.** All `QuicClient`s of an `Http3Origins` share one `SessionCache`
  (`sessions`), so a new connection to a server resumes with the last ticket it sent (and skips
  its Retry with a NEW_TOKEN token). `proxyRequest` passes `replaySafe` (`Http3Connection.replaySafe`:
  `GET`, `HEAD`, `OPTIONS` without a body); with `upstreamZeroRtt`, a connection made for such a
  request comes from `connectEarly` and may still be handshaking, sending 0-RTT data.
  `Http3UpstreamConnection.open` lets only replay-safe requests take a stream before the
  handshake completes; others wait for it (`Unprocessed` past the handshake timeout).
  `Http3UpstreamStream` notes whether it sent its request early on its own initiative (no
  `Early-Data` field): a `425` to such a request is `Unprocessed`, sent again after the
  handshake; a `425` to a request that arrived early from its client goes back to the client.

### HTTP/3 frames: `Http3Frames`

With a `FrameInterceptor`, each `Http3Endpoint` gets an `Http3Frames` (`frames`), as each
`Http2Endpoint` gets an `Http2Frames`; without one, `frames` is null and nothing is converted.
`Http3StreamReader` shows each received frame to `onStream` after decoding its field section and
acts on what comes back; `Http3MessageWriter` shows each frame it is about to write (DATA in
pieces of at most 16 KiB) and writes what comes back, encoding field sections through the
connection's QPACK encoder; the control streams' SETTINGS and GOAWAY go through `onControl`.
`State` keeps each message's order (HEADERS, DATA, trailers; interim responses first); SETTINGS
received may only become stricter, SETTINGS sent may change only in extension settings, GOAWAY,
MAX_PUSH_ID and CANCEL_PUSH are read-only, and extension frames may be added and dropped. QUIC's
flow control counts what is on the wire, whatever the interceptor makes of it.

## What stays HTTP/1-specific, and why

- **The connection loop** (`serveRequests`): waiting for the next request without holding a
  buffer, pipelining (unread requests wait in the buffer), and answering unparseable request
  heads. An HTTP/2 connection reads frames and starts a thread per stream instead.
- **Connection-wide CONNECT interception** (`interceptOrTunnel`, `intercept`). An HTTP/1
  `CONNECT` that is intercepted turns the whole connection into TLS and serves the decrypted
  requests with the same loop, or with `Http2Connection` when the client negotiates `h2`. The
  session's requests go to the `CONNECT` target (`mitmHostAndPort`; without TLS in a plain HTTP
  session), unless a filter gives one an absolute URI it did not arrive with (`redirected`:
  map_remote, a script assigning `req.uri`). That request goes to the URI's server, over TLS for
  `https://`, with a server connection keyed by its own target (`Mode|host:port`), so pooling,
  HTTP/2 to servers and `Host` follow the new server; the session's ALPN mirroring still applies to
  it. A reverse proxy's requests leave its upstream the same way. Absolute `https://` URIs outside
  interception (forward requests, client replay, `h2c` streams) are fetched over TLS too, with the
  MITM manager's server trust when one is configured. Under HTTP/2, `CONNECT` is per stream, and an
  intercepted one gets a `ClientConnection` of its own over the stream (above), which runs the same
  `interceptOrTunnel`. The `h2c`
  preface is recognized only as the first bytes of a plain connection.
- **`101 Switching Protocols`.** HTTP/2 and HTTP/3 have no upgrade. Their WebSockets use extended
  `CONNECT` (RFC 8441, RFC 9220), and so does CONNECT-UDP (RFC 9298). The bridge translates
  handshake fields/status and uses the same relay and frame hooks.
- **The PROXY protocol header**, which is read when the connection starts.

## Stats: `ProxyStats`, `ProtocolStats` and `QuicStats`

`ProxyStats` resolves every metric of the proxy once, when it starts, from its `StatsRegistry`
(`StatsRegistry.NOOP` without metrics, whose metrics do nothing): the `http`, `listener`,
`tls_inspector` and `cluster` stats, and `ProtocolStats`' holders, one field each for the HTTP/2
and HTTP/3 codecs by direction, transparent QUIC, SOCKS, MASQUE, tunnels, WebSockets and each hook
family. Code counts through those fields: an endpoint keeps its direction's codec stats
(`Http2Endpoint.stats`, `Http3Endpoint.stats`), a server connection its cluster, a session its
hook stats. A hook's call is timed only with metrics on (`HookStats.start` returns 0 otherwise).

QUIC is counted per connection, not per packet: the quic module keeps a connection's counts as
plain fields (`QuicConnection.stats()`), and `QuicStats`, one per scope (`downstream`,
`transparent`, `masque`, `upstream`), observes the endpoints (`QuicServer.observe`,
`QuicClient.observe`) and adds a connection's counts to the registry when it closes. It is the only
stats class that needs the quic module, so `ProxyStats` keeps the scopes as plain objects
(`quicScope`), and only HTTP/3 code makes them (`QuicStats.of`). `QlogWriter` writes the qlog files
(`Http3Options.qlogDirectory`): the `TransportConfig` of every QUIC endpoint the proxy makes gets
its sink (`QlogWriter.sink`), and `QuicStats` closes a connection's file when it ends, so it
observes the endpoints with qlog on even without metrics. CONNECT-UDP flows (`UdpFlow.countInto`)
and transparent QUIC relays (`QuicFlows.endRelay`) also count their datagrams in fields of their
own, added when they end.

## Tracing: `FlowTracer`

A `FlowTracer` (`withTracer`, `DefaultHttpProxyServer.tracer`) is asked for a `FlowTrace` first
thing in `handleRequest`, before the trackers' snapshot, authentication and the filters, so a
request id it adds is seen by all of them; the trace is kept on the `Exchange` and on the
`ClientFlowContext` (`FlowContext.trace()`, reset by `startExchange`). The exchange logic tells it
of each attempt to reach the server: `connect` starts one per candidate of the route and ends it
when the candidate fails; `exchange` starts one when the connection was at hand (a pooled or
reused connection, a stream on a shared HTTP/2 or HTTP/3 connection), and ends it however `send`
ended (a `StaleConnection` ends it before the retry starts the next). Each attempt says whether
the proxy speaks TLS to the server (the exchange's `Mode.TLS`, or a stream of an HTTP/2 or HTTP/3
connection), and `send` reports the connection's real protocol (`upstreamRequest`) before the
request goes out, so a tracer never guesses the scheme from a port. `traceUpstream` runs right
after `stripRequestHeaders` on every request head written upstream, the `CONNECT`s to chained
proxies and through hops included, so a tracer's headers survive the stripping and say whether it
happened. Every record that reaches `flowEnded` goes to the tracer first (`flowEnded(FlowRecord)`),
which builds the record even without trackers; `FlowRecord.trace()` carries the trace, and its
request id becomes the record's unique id. With `FlowTracer.NOOP` every call is skipped behind one
comparison. The `microproxy-otel` module implements the hook.

## Notes for later

- CONNECT-UDP to an upstream MASQUE proxy (HTTP/3 chained proxies).
- QUIC stream hooks that open streams of their own, which `QuicSession` would pair as it pairs the
  peers' streams.
- `ALTSVC` frames (RFC 7838 section 4) from HTTP/2 servers are dropped by the frame reader, as a
  frame type the codec does not deliver; forwarding them would need the h3 filtering `Alt-Svc`
  headers get (`AltSvc`).
- `AllocationTest` guards the allocation per small keep-alive request (about 4 KB with its
  allocation-free client; the README's 4.7 KB includes a simple benchmark client's own); the
  HTTP/2 additions cost HTTP/1 requests nothing.
