# HTTP/2

Speak HTTP/2 to clients (inside intercepted TLS, on the proxy's TLS listener, and with prior
knowledge on the plain listener) and to servers, with connection sharing and coalescing, trailers
and gRPC, CONNECT and WebSockets over HTTP/2, and hardened limits. Use this page to turn HTTP/2 on
and to understand how streams map to exchanges; frame-level hooks are in [Frame
interception](frame-interception.md).

MicroProxy can speak HTTP/2 to clients inside intercepted TLS sessions and, with prior knowledge
(`h2c`), on its plain listener, and to origin servers that negotiate it. Each HTTP/2 stream is an
exchange like any HTTP/1 request: it gets its own `HttpFilters`, cache lookup, failure answers,
trackers and log lines. The client side and the server side are independent: an HTTP/1 client
can reach an HTTP/2 server and the other way round.

```java
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withHttp2(true)                                  // to clients: --http2, http2=true
        .withHttp2Upstream(true)                          // to servers: --http2-upstream, http2_upstream=true
        .withHttp2Cleartext(true)                         // h2c: --http2-cleartext, http2_cleartext=true
        .withHttp2Options(Http2Options.builder().maxConcurrentStreams(200).build())   // optional
        .start();
```

```bash
java -cp microproxy.jar:http2-codec.jar org.microproxy.Launcher --port 8080 --mitm --http2 --http2-upstream
java -jar microproxy-starlark-all.jar --port 8080 --http2-cleartext       # h2c on the plain listener
```

All three are off by default. They need the optional `http2-codec` module on the class path (see
[Install](../getting-started/install.md#modules-and-artifacts); the `microproxy-starlark` `-all` jar bundles it). A proxy started with any of
them enabled but without the module fails at startup with an `IllegalStateException` that says
so; without them, nothing loads the module.

## HTTP/2 to clients

### Negotiation

With HTTP/2 on, both intercepted TLS and the proxy's own TLS listener
(`withSslContextSource`) offer `h2` and
`http/1.1` through ALPN. A client that offers `h2` gets it, unless an intercepted server that was
offered `h2` chose `http/1.1` (see [ALPN mirroring](mitm.md#alpn-mirroring)). Any other client keeps HTTP/1.1 as
before: one that offers only `http/1.1`, one that offers protocols the proxy does not know, and
one that sends no ALPN at all (the handshake never fails over ALPN). The TLS log line for the
handshake shows the result (`alpn=h2`). The TLS listener retains its configured certificate,
client authentication and socket settings. Its HTTP/2 streams are forward-proxy requests, like
`h2c`, and authenticate separately when proxy authentication is configured.

### What a stream looks like to filters

- The request is an `HttpRequest` with version `HTTP/2.0` and an origin-form URI (absolute-form
  on an `h2c` connection or the proxy TLS listener, which are forward proxies). `:authority` becomes `Host`, split `cookie`
  fields are joined, and trailers arrive in the `LastHttpContent`. `FlowContext.getStreamId()` is
  the stream's id (0 for HTTP/1), and each stream has its own `FlowContext` and timings.
- Towards an HTTP/1.1 server the request becomes HTTP/1.1: the request line says `HTTP/1.1`, `Via`
  says `2 <alias>`, and a body without a `Content-Length` is sent chunked, with its trailers.
- Responses lose HTTP/1's connection-specific fields (`Connection`, `Keep-Alive`,
  `Transfer-Encoding`, `Upgrade`, ...). `Content-Length` is kept, and chunked trailers become a
  trailing HEADERS frame; a response with `Content-Length: 0` is a single HEADERS frame that ends
  the stream. A `100 Continue` is sent only to a client that asked for one; other 1xx responses
  (such as `103 Early Hints`) are forwarded as interim responses.
- Proxy authentication happens once, on the `CONNECT` that started the session. Its streams
  inherit it, as HTTP/1 requests inside an intercepted session do. On `h2c` or the proxy TLS listener, each
  stream authenticates on its own (`Proxy-Authorization` per request).

### Concurrency

The connection's thread reads frames; each stream runs on a virtual thread of its
own, so a slow stream never holds up the others. Towards HTTP/1.1 servers, which cannot multiplex,
each stream takes a server connection of its own; idle ones are reused by later streams of the
same client connection, and the `CONNECT`'s server connection serves the first stream. Because
streams run at the same time, `ActivityTracker` callbacks and filters for one client connection
may run concurrently, on the streams' threads.

## HTTP/2 to servers

With `withHttp2Upstream(true)` (`--http2-upstream`, `http2_upstream=true`), the proxy's TLS
connections to servers, for intercepted HTTPS and the `https://` and secure WebSocket requests it
[originates TLS](forward-proxy.md#tls-origination-https-uris-without-connect) for, offer `h2` and `http/1.1`
through
ALPN (before `MitmManager.configureServerSocket`, which may change that). An intercepted client
that sent ALPN has its own offer mirrored instead: one that offered only `http/1.1` never gets
HTTP/2 upstream (see [ALPN mirroring](mitm.md#alpn-mirroring)). A server that picks `h2`
is spoken to in HTTP/2; any other keeps HTTP/1.1, so turning it on is safe for servers without
HTTP/2. WebSockets use extended `CONNECT` when the origin advertises
`SETTINGS_ENABLE_CONNECT_PROTOCOL`; otherwise they use a separate HTTP/1.1 connection.
Plain-HTTP requests (`http://`
through the proxy, and plain HTTP chained proxies) stay HTTP/1.1; HTTP/2 inside the tunnel of an
HTTP `CONNECT` chained proxy (or through SOCKS) works like a direct connection.

- **Multiplexing.** An HTTP/2 connection to a server carries many exchanges at once, one stream
  each: the streams of an HTTP/2 client, the requests of an intercepted HTTP/1 session, and, with
  the shared pool (`withSharedServerConnectionPool` and `withPoolSharedMitmConnections`), the
  exchanges of every client connection. A burst of exchanges waits for the connection one of them
  is making instead of making their own, and an intercepted `CONNECT` whose requests will use an
  existing connection makes none (like a reused pooled connection, it fires no connection hooks).
- **Stream limits.** The proxy reads the server's SETTINGS before the first stream and never opens
  more streams than its `SETTINGS_MAX_CONCURRENT_STREAMS`; when every connection to the server is
  full, another one is made (counted against the shared pool's limits).
- **Isolation.** Connections are shared only between exchanges with the same target, route
  (direct, or which chained proxy) and MITM manager, and between client connections only where a
  pooled connection would be: with the shared pool on, and nothing about the connection particular
  to one client. A connection that carries a PROXY protocol header, or whose TLS a MITM manager set
  up for one client (one that overrides `serverSslContext` or `configureServerSocket` with a
  `FlowContext`), serves only its own client connection. Private connections close with their
  client; shared ones after the idle timeout without streams. With
  [connection coalescing](#connection-coalescing) on, exchanges for other targets may share a
  connection too, but never across the rest.
- **Translation.** The request line and `Host` become `:method`, `:scheme https`, `:authority`
  and `:path`; connection-specific fields (`Connection` and what it names, `Keep-Alive`,
  `Proxy-Connection`, `Transfer-Encoding`, `Upgrade`) are dropped, `cookie` is split into crumbs,
  and `te` is sent only as `te: trailers`, when the client sent it. Responses reach filters as
  `HTTP/2.0` responses; without a `content-length`, their body is chunked (`Transfer-Encoding:
  chunked`), so HTTP/1 clients get trailers too, and they reach HTTP/1 clients with an `HTTP/1.1`
  status line and `Via: 2 <alias>`.
- **Failures.** A stream the server refuses (`REFUSED_STREAM`) or did not process before its
  `GOAWAY` (an id above the last one it names) is retried on another connection when the request
  can be sent again (no body, or a buffered one), up to three times. A `GOAWAY` lets the streams
  in progress finish and starts no new ones. Any other reset fails the exchange like a broken
  server connection: `proxyToServerFailure` with `ProxyFailure.BadServerResponse` and a `502`, or,
  once the response has started, a reset client stream (HTTP/2) or a closed connection (HTTP/1).
  Connection errors fail every stream of the connection. `PUSH_PROMISE` is refused (push is off).
- **Flow control.** A stream's response data is buffered up to its window (`initialWindowSize`,
  256 KiB), which is credited back only as the exchange passes the data on to the client: a slow
  client stops its server stream instead of growing the proxy's buffers. The connection's window
  (`connectionWindowSize`) is credited back as data arrives, so one slow client does not hold up
  the other streams. Request bodies wait for the server's windows.
- **Hooks.** Filters, `proxyToServerConnection*` hooks, timings, `upstreamStatus`, `ActivityTracker`
  callbacks, `HttpLogger` and the WARC recorder work per exchange as with HTTP/1.1. A new
  connection fires the connection hooks for the exchange that made it; exchanges that take a stream
  on an existing one look like exchanges on a reused pooled connection. Bytes sent and received are
  counted per stream (each frame to its stream's exchange).

## Connection coalescing

A connection made for `a.example.com` normally carries only `a.example.com`'s exchanges. With
coalescing on, an exchange for `b.example.com` that finds no connection of its own with room may
take a stream on it instead, as RFC 9113 section 9.1.1 allows, when:

- the certificate the server presented on it is valid for `b.example.com`: a DNS subject
  alternative name matches it, as the JDK's HTTPS hostname verification matches them (one
  wildcard, in the left-most label only; no fallback to the common name); and
- `b.example.com` resolves, with the proxy's own resolver (`withServerResolver`, DNSSEC, and the
  `proxyToServerResolution*` filter hooks, as for connecting), to the address the connection went
  to; or the server named `https://b.example.com` in an ORIGIN frame (RFC 8336). Once a server has
  sent an ORIGIN frame, its origin set (its own name and those it named) says which names the
  connection serves, and DNS is no longer asked. Through a chained proxy, which resolves names
  itself, only an ORIGIN frame lets a connection serve another name.

| Flag | Property | Bootstrap |
|---|---|---|
| `--http2-coalesce` | `http2_coalesce=true` | `withHttp2Options(Http2Options.builder().coalesceConnections(true).build())` |

It is off by default, and needs HTTP/2 to servers (`--http2-upstream`). It applies to intercepted
`CONNECT`s too: a `CONNECT` for a name an existing connection serves makes no connection of its
own, and the certificate the client gets is made from that server's. What the client sees does
not change.

- **Never across isolation.** Connections are coalesced only among those that could be shared
  anyway (same route, MITM manager, and client connection for private ones), and only when TLS
  would be set up the same way: the MITM manager gives both names the same `SSLContext` (trust,
  client certificate, pinned versions and ciphers), the connection sent its own name as SNI (as a
  connection for the other name would send that one), the proxy presented no client certificate
  on it (an identity given to one name), and the manager does not configure server sockets itself
  (`configureServerSocket`, whose settings may differ by name). An IP address target is never
  coalesced.
- **Resolving once.** The address check resolves the name the way connecting would, and a request
  that goes on to make its own connection connects to that address, without resolving it again.
  Names a connection was found to serve are remembered for its lifetime, so later requests take a
  stream at once. With coalescing off, nothing more is resolved than before.
- **`421 Misdirected Request`.** A server that answers `421` to a request on a coalesced
  connection is not sent that name on that connection again. The request goes again on a
  connection of its own when it can be: no body, a buffered one, or one the server refused before
  it was read (`Expect: 100-continue`). A request whose body was already streamed gets the `421`,
  as a client would from the server. A `421` on a connection made for the request's own name is
  relayed as always.
- **Stats.** `http2.upstream.coalesced_streams` counts the streams opened on a connection made for
  another name, and `http2.upstream.misdirected_421_retry` the requests sent again after a `421`
  (also counted in their cluster's `upstream_rq_retry`). A coalesced stream's requests count in
  its own name's cluster (with `--stats-per-host`), its connection in the other's.

## Trailers and gRPC

Trailers go end to end: request trailers from HTTP/2 clients (and from HTTP/1 clients' chunked
bodies) reach HTTP/2 servers as a trailing HEADERS frame, and response trailers such as
`grpc-status` and `grpc-message` come back to HTTP/2 clients the same way, and to HTTP/1 clients
in the chunked body. When both the client and the server side of an exchange are HTTP/2 streams
and no filter looks at the request body's pieces, the request body is relayed on a thread of its
own while the response comes back, so bidirectional streaming works; otherwise a request body is
sent whole before the response is read, as with HTTP/1.1. So gRPC (`application/grpc`, `te:
trailers`, length-prefixed messages, unary and streaming calls, Trailers-Only error responses)
works through the intercepting proxy with `--mitm --http2 --http2-upstream`. To read the calls,
log them with [content views](content-views.md#content-views) (`--log-http-view auto`), which decode each
message and the status trailers; scripts can decode and rewrite messages with the
[`protobuf` and `grpc` modules](scripting.md).

## gRPC interop (grpcio)

`GrpcInteropTest` runs real gRPC peers on either side of the proxy: grpcio's client and server
(the scripts in `microproxy/src/test/resources/interop/`, with generic handlers on raw bytes, so
no generated code). The client reaches the server through the proxy as a forward proxy, with
`CONNECT` (grpcio's `grpc.http_proxy`), and trusts the proxy's MITM CA; the proxy speaks HTTP/2 on
both sides, as with `--mitm --http2 --http2-upstream`, and trusts the server's CA. The calls:

- unary, with text and binary metadata both ways;
- server, client and bidirectional streaming, each bidirectional message answered while the
  request stream stays open;
- an error: `INVALID_ARGUMENT` with its message and a `google.rpc.Status` in
  `grpc-status-details-bin`, decoded on arrival;
- a deadline: `grpc-timeout` reaches the server, which sees it and ends the call;
- a cancellation: the client's `RST_STREAM` `CANCEL` reaches the server, whose handler sees the
  call end;
- large messages, far across the flow-control windows of both hops: 8 MiB each way, 4 x 2 MiB
  streamed from the server, and 6 MiB and 1 MiB streamed to it.

They run as they are, through a Java `FrameInterceptor` that passes every frame on unchanged
(and checks that the deadline, the cancellations and the trailers crossed both hops), and, in
`microproxy-starlark`'s `ScriptedGrpcInteropTest`, through an `on_frame` script that does the
same. CI runs them on every push and pull request (the `grpc-interop` job of
[`.github/workflows/ci.yml`](https://github.com/mahmoudimus/MicroProxy/blob/main/.github/workflows/ci.yml), with `grpcio==1.84.0`). Elsewhere they
are skipped unless Python has grpcio:

```bash
python3 -m pip install grpcio==1.84.0
mvn -pl microproxy,microproxy-starlark -am verify -Dtest=GrpcInteropTest,ScriptedGrpcInteropTest \
    -Dsurefire.failIfNoSpecifiedTests=false -Dgrpc.interop.python=python3
```

## h2c with prior knowledge

With `withHttp2Cleartext(true)` (`--http2-cleartext`, `http2_cleartext=true`), a connection to the
plain listener whose first bytes are the HTTP/2 connection preface (`PRI * HTTP/2.0`, RFC 9113
section 3.4) is served as HTTP/2. The first bytes are compared without consuming anything, and an
HTTP/1 request is told apart by its first byte or two, so HTTP/1 clients are unaffected. Its
streams are proxy requests: `:scheme` and `:authority` name the target, so any authority is valid
(the `421` check applies only to intercepted sessions), and they reach servers as HTTP/1.1 (HTTP/2
to servers needs TLS). A `:scheme https` stream, a secure WebSocket's extended `CONNECT`
included, is fetched over TLS the proxy opens to the server ([TLS
origination](forward-proxy.md#tls-origination-https-uris-without-connect)), and may use HTTP/2 or HTTP/3 there.
`Upgrade: h2c` (deprecated by RFC 9113) is ignored, as
before: the request is answered in HTTP/1.1. The same limits as for intercepted HTTP/2 apply.

## CONNECT and WebSockets

A normal HTTP/2 `CONNECT` (`:method CONNECT`, `:authority host:port`, no `:scheme` or `:path`)
opens a byte tunnel on that stream. The successful `200` HEADERS leave it open; DATA carry tunnel
bytes, and END_STREAM half-closes one direction. RST_STREAM closes the tunnel's origin connection
and wakes its waits, without closing the client HTTP/2 connection or other streams. A reset that
ends an open tunnel is not counted as a rapid reset. A `CONNECT` stream to a chained HTTP proxy
reaches it as an HTTP/1.1 `CONNECT`.

With a MITM manager, a `CONNECT` stream on `h2c` or the proxy TLS listener is intercepted as an
HTTP/1 `CONNECT` is: the client's TLS session runs over the stream's DATA frames, and its decrypted
requests (HTTP/1.1, or HTTP/2 inside the stream when the client negotiates `h2`) are exchanges of a
client connection of their own, with the same filters, hooks and server connections; the
`CONNECT`'s credentials cover them. The stream's first bytes decide as an HTTP/1 connection's do:
its ClientHello goes through the host rules and the ClientHello hooks, ALPN is mirrored, and plain
HTTP or another protocol is served or tunnelled
([Deciding what to intercept](mitm.md#deciding-what-to-intercept-the-clienthello)). A server that does not speak
TLS gets a plain tunnel instead. A
`CONNECT` inside an intercepted session, for any authority, goes to the intercepted server, which
the client takes for its HTTPS proxy ([In front of an HTTP or HTTPS proxy](chained-proxies.md#in-front-of-an-http-or-https-proxy)).

The proxy advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`. A WebSocket client can open a stream
with `:method CONNECT`, `:protocol websocket`, `:scheme http` (ws) or `https` (wss), `:authority`
and `:path`. A successful response is `200`, without END_STREAM; WebSocket frames travel in DATA,
independently of DATA frame boundaries. HTTP/1 `Connection` and `Upgrade` fields remain forbidden
on the HTTP/2 wire. On a forward proxy that serves CONNECT-UDP (`--masque`, or `--http3`),
`:protocol connect-udp` opens a UDP flow whose datagrams travel in capsules in the stream's DATA
([CONNECT-UDP](masque.md)); elsewhere it gets `501`, and so do other extended protocols.

WebSockets can use HTTP/1 or HTTP/2 independently on either side. With HTTP/2 to origins enabled,
a TLS origin that advertises extended CONNECT gets a WebSocket stream on the existing shared
HTTP/2 connection. An origin that does not advertise it gets a separate HTTP/1.1 upgrade connection.
The proxy translates `101` and `200` handshakes, and generates the HTTP/1 nonce/accept fields where
needed. For secure extended CONNECT on a forward-proxy connection, origin TLS uses the configured
MITM manager's server TLS settings, or the default JVM trust context when there is no manager, as
for any `https://` request the proxy [originates TLS](forward-proxy.md#tls-origination-https-uris-without-connect)
for.

Request filters see an extended WebSocket CONNECT as a GET upgrade request, with version
`HTTP/2.0`, its resource URI and generated HTTP/1 upgrade headers. Response filters and trackers
see the handshake's answer as a `101` with `Upgrade: websocket` and `Connection: Upgrade`, as for an
HTTP/1.1 client, whichever protocol the origin speaks; the proxy sends it to an HTTP/2 client as
`200`, and `upstreamStatus` retains the origin's actual status.
`webSocketFrameReceived`, `filterWebSocketFrame` and `filterWebSocketMessage` use the same parser
and relay as HTTP/1, including masking, rewriting, dropping, fragmentation, message joining,
permessage-deflate and the buffer and message limits (see [WebSocket frames and
messages](websockets.md#websocket-frames-and-messages)).
A filter that rejects the handshake finishes the exchange without starting the relay.

### Remaining limits

A request for an authority other than the intercepted one gets `421
Misdirected Request`, which makes the client retry on a connection of its own; so does an extended
`CONNECT` (`:protocol websocket`) for another authority. A plain `CONNECT`, and a `:scheme http`
request, are proxy requests, forwarded instead ([In front of an HTTP or HTTPS proxy](chained-proxies.md#in-front-of-an-http-or-https-proxy)). On a
forward-proxy HTTP/2 connection (`h2c`, or the proxy's TLS listener), a `:scheme https` request is
fetched over TLS the proxy opens itself ([TLS origination](forward-proxy.md#tls-origination-https-uris-without-connect)),
as an absolute `https://` URI sent in plain HTTP is. HTTP/2 chained proxies are not supported.

## Limits

Input is untrusted; every limit has a default, and the configurable ones are set with
`Http2Options` (or the `http2_*` properties and `--http2-max-streams`). Rate limits count frames
per window of 10 seconds (`rateWindow`). The window sizes apply to both sides: what the proxy
buffers of a client's request bodies, and of a server's responses.

| Limit | Default | When exceeded | Setting |
|---|---|---|---|
| Open streams per connection | 100 | the stream is refused (`REFUSED_STREAM`); clients retry | `maxConcurrentStreams` |
| Request bytes buffered per stream | 256 KiB (its flow-control window) | stream reset `FLOW_CONTROL_ERROR` | `initialWindowSize` |
| Request bytes buffered per connection | 1 MiB (the connection window) | `GOAWAY FLOW_CONTROL_ERROR` | `connectionWindowSize` |
| Request header list (names and values plus 32 per field) | `max_header_size` + `max_initial_line_length` (24 KiB) | stream reset | `maxHeaderListSize` |
| Encoded header block (with CONTINUATION frames) | 64 KiB, or the header list limit plus 4 KiB if larger | `GOAWAY ENHANCE_YOUR_CALM` | |
| CONTINUATION frames per header block | 128 | `GOAWAY ENHANCE_YOUR_CALM` | |
| HPACK dynamic table / frame size | 4096 / 16384 bytes | `GOAWAY COMPRESSION_ERROR` / `FRAME_SIZE_ERROR` | |
| Streams reset by the client before their response completed, or refused (Rapid Reset, CVE-2023-44487) | 100 per window | `GOAWAY ENHANCE_YOUR_CALM` | `maxRapidResets` |
| PING / SETTINGS frames | 100 / 100 per window | `GOAWAY ENHANCE_YOUR_CALM` | `maxPings` / `maxSettings` |
| RST_STREAM and PRIORITY frames | 1000 per window | `GOAWAY ENHANCE_YOUR_CALM` | `maxResets` |
| WINDOW_UPDATE frames | 10000 per window | `GOAWAY ENHANCE_YOUR_CALM` | `maxWindowUpdates` |
| Empty DATA frames (no data, no END_STREAM) | 1000 per window | `GOAWAY ENHANCE_YOUR_CALM` | `maxEmptyFrames` |
| Acknowledging the proxy's SETTINGS | 10 seconds | `GOAWAY SETTINGS_TIMEOUT` | `settingsAckTimeout` |
| A connection with no open streams | `idle_connection_timeout` (70 s) | `GOAWAY NO_ERROR`, then closed | `withIdleConnectionTimeout` |
| A stream waiting for request data or for flow-control window, a write the client does not read | `idle_connection_timeout` | the stream is reset / the connection closed | `withIdleConnectionTimeout` |
| Response bytes buffered per server stream | 256 KiB (its window) | the server waits for window | `initialWindowSize` |
| A connection to a server with no streams, a server that sends nothing for a stream, a write it does not read | `idle_connection_timeout` | `GOAWAY NO_ERROR` and closed / `504` / the connection closed | `withIdleConnectionTimeout` |

Protocol violations end the connection with `GOAWAY` and the error RFC 9113 names: a bad preface,
frames other than SETTINGS first, even or decreasing stream ids (`PROTOCOL_ERROR` /
`STREAM_CLOSED`), frames on idle streams, `PUSH_PROMISE` from a client. Malformed requests
(missing or repeated pseudo-headers, upper-case or connection-specific fields, a `content-length`
the DATA does not match, a stream that depends on itself) only reset their stream, as do frames a
client sends on a stream after resetting it (`STREAM_CLOSED`). Request bodies are buffered only
within the flow-control windows the proxy granted, so a connection holds at most its connection
window of request data, plus two 16 KiB I/O buffers and its HPACK tables. Malformed responses
from servers reset their stream and fail its exchange with a `502`.

## Shutting down

A graceful stop (`stop()`) sends `GOAWAY` to HTTP/2 clients, finishes the
streams already open (for up to the graceful stop timeout), and refuses new ones. An idle
connection is sent `GOAWAY` and closed. Connections to servers are sent `GOAWAY` and closed once
the client connections are done.

## Compatibility

Nothing changes unless HTTP/2 is enabled, with two small exceptions in the
API: `FlowContext.equals` (and `hashCode`) now also compare the stream id, which is 0 for every
HTTP/1 context, so HTTP/1 behaviour is the same; and `HttpProxyServerBootstrap` gains
`withHttp2`, `withHttp2Upstream`, `withHttp2Cleartext`, `withHttp2Options` and `getHttp2Options`
as default methods, so other implementations still compile. Trackers and filters keyed by
`FlowContext` keep one entry per stream; state meant per client connection can be keyed by
`ctx.getConnectionContext()`.

## Conformance (h2spec)

CI runs [h2spec](https://github.com/summerwind/h2spec) v2.6.0 in strict mode against the `h2c`
listener (`.github/scripts/h2spec.sh`, with `org.microproxy.H2specTarget` from the test sources:
the proxy with `h2c` on and a filter that answers every request with `200`). All 147 cases pass
except one, which CI leaves out:

- `http2/3.5/2` (*Sends invalid connection preface*): h2spec expects `GOAWAY` or a closed
  connection. The `h2c` listener is shared with HTTP/1, so a connection that does not start with
  the preface is an HTTP/1 connection, and gets an HTTP/1 error response before it is closed.

To run it locally, build the classes (`mvn -DskipTests test-compile -pl microproxy -am`) and run
`.github/scripts/h2spec.sh --strict` (it downloads h2spec, or uses `$H2SPEC`).

HTTP/3 has its own section: [HTTP/3 and QUIC](http3.md).
