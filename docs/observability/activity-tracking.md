# Activity tracking and timings

Follow connections, exchanges, tunnels and flows from Java with `ActivityTracker` callbacks: where
each response came from, per-exchange timings, failures, TLS handshakes and one record per exchange
or flow. Use this page to build your own logging or metrics; the [access log](access-logs.md),
[metrics](metrics.md) and [OpenTelemetry](opentelemetry.md) are built on the same data.

<a id="observability"></a>

## `ActivityTracker` callbacks

`ActivityTracker` callbacks run on the connection's virtual thread. Besides LittleProxy's events:

- **Where a response came from:** `responseSentToClient(ctx, response, source)` receives a
  `ResponseSource`: `SERVER` (relayed, maybe with headers or body edited in place), `PROXY` (the
  proxy's error answers, `407`, the `CONNECT` `200`), `FILTER` (a short-circuit, a failure answer
  from a filter, or a server or proxy response a filter replaced or gave another status), `CACHE`
  or `REPLAY` (a recorded response from `ServerReplay`).
  `ctx.upstreamStatus()` is the status the server sent, so a `500` a filter turned into a `200`
  still shows. The two-argument callback keeps working.
- **Timings:** `ctx.timings()` returns a `FlowTimings` snapshot for the exchange in progress:
  `dnsLookup()`, `connect()`, `tlsHandshake()` (towards the server or a TLS chained proxy),
  `clientTlsHandshake()`, `timeToFirstByte()` and `total()`, plus the raw offsets from the first
  byte of the request. A request on a reused connection has no lookup or connect; when intercepting,
  the server handshake belongs to the `CONNECT` exchange. Take the snapshot in
  `responseCompleted(ctx, response)`, which follows the last byte of the response. Recording costs
  a few `System.nanoTime()` calls and no allocation per request.
- **Server-side failures:** `serverConnectionExceptionCaught(serverContext, cause)` reports each
  failed connection attempt, server timeout or bad response once, with the server (or chained
  proxy) it concerned. Client-side errors still go to `connectionExceptionCaught`.
- **TLS handshakes:** `tlsHandshakeFailed(ctx, clientSide, cause)` reports each failed or timed-out
  handshake: with a client (TLS listener or interception) or with a server or TLS chained proxy
  (then `ctx` is a `FullFlowContext` naming it).
- **Server TLS session:** `FullFlowContext.getServerSslSession()` is the session with the origin
  server of the connection a request is sent on, already established in `requestSentToServer`;
  `null` without TLS with the server ([details](../guides/filters.md#the-servers-tls-session)).
- **Correlation:** `ctx.getConnectionId()` and `ctx.acceptedAt()` identify the client connection,
  and the proxy's log lines about it start with `[conn <id>]`.
- **HTTP/2 streams:** `ctx.getStreamId()` names the stream (0 for HTTP/1), and log lines about it
  start with `[conn <id> stream <id>]`. Each stream has its own context, with its own timings and
  upstream status; contexts are equal only for the same connection and stream, and
  `ctx.getConnectionContext()` is the connection's. Callbacks for one connection's streams run
  concurrently, on the streams' threads. A stream that ends without a complete response (the
  client reset it, or the connection closed) is reported with `connectionExceptionCaught(streamCtx,
  cause)`. The request's `protocolVersion()` is `HTTP/2.0`; access logs say `HTTP/2`, as Envoy does.
- **Transparent QUIC:** each flow of the [transparent QUIC](../guides/transparent-mode.md#transparent-quic) listener is a
  client connection of its own (`clientConnected` ... `clientDisconnected`, with
  `ctx.isTransparentQuic()` true), whose made-up `CONNECT` is reported as a request.
  `transparentQuicFlowDecided(ctx, clientHello, intercepted, reason)` says whether it is
  intercepted or relayed, and why; a relayed flow then reports `serverConnected`, the bytes both
  ways and `serverDisconnected`. The logger `org.microproxy.impl.TransparentQuicListener` writes
  each decision, and why a new client was dropped, at DEBUG.
- **Why an exchange ended as it did:** `ctx.failure()` (the `ProxyFailure` the proxy answered, set
  before filters see it), `ctx.responseFlags()` (Envoy's flags: `UF`, `DC`, `UT`, ...) and
  `ctx.responseCodeDetails()` (`via_upstream`, `proxy_failure:connect_failed`, ...); see
  [Response flags and details](../reference/response-flags.md#response-flags-and-details). Filters may add their own with
  `ctx.addResponseFlag(flag)` and `ctx.setResponseCodeDetails(details)`.
- **One record per exchange or flow:** `flowEnded(record)` comes once per HTTP exchange, when it
  has ended however it ended, and once per tunnel (`CONNECT`, SOCKS, WebSocket, TCP hooks),
  CONNECT-UDP flow and relayed or stream-intercepted QUIC flow when it closes. The `FlowRecord`
  has the request and response heads, the bytes each way (to the client and on the server's
  wire), the upstream and local addresses and TLS sessions, the duration, the flags and details,
  and what kind of flow it was; the [access log](access-logs.md#access-logs-envoy-compatible) is made of them.
- **In filters:** `HttpFilters.proxyToClientResponseSent(response, source)` is called once a
  response has been written in full, whoever made it, with the head as sent and its
  `ResponseSource`; `ctx.timings()` covers the whole exchange by then.
  `HttpFilters.exchangeEnded(completed)` follows exactly once however the exchange ended (also
  when the client left half-way, the server failed or a filter aborted; for tunnels when they
  close), so filters can release what they hold per exchange.

## TLS handshake log lines

The logger `org.microproxy.impl.Tls` writes one line per handshake event, without stack traces:

| event | level | contents |
|---|---|---|
| started | DEBUG | peer address, host, the proxy's TLS role (`mode=client` / `server`), whether a client certificate is required |
| succeeded | DEBUG | the same, the duration, negotiated protocol and cipher suite, the ALPN protocol (`alpn=h2`) when one was negotiated, and the SNI name a client asked for |
| failed with a client | DEBUG | the error and its root cause (`certificate_unknown`, `no cipher suites in common`, `TLS handshake not finished within 10000 ms`, ...), and a certificate summary: the proxy's own certificate, then the peer's chain (subject, issuer, `notAfter`, SANs) |
| failed with a server or chained proxy | WARNING for certificate problems (untrusted, expired, wrong name, client certificate refused), DEBUG when the server does not speak TLS (the `CONNECT` is tunnelled instead), INFO otherwise (timeouts, protocol mismatches) | the same |

Client handshakes fail routinely (clients giving up, scanners, clients that do not trust the
interception CA), hence DEBUG. The JDK discards a peer chain it rejected for an unknown issuer, so
for that failure the summary has no peer chain. Turn the lines on with, for example,
`-Djava.util.logging.config.file=...` setting `org.microproxy.impl.Tls.level = FINE`.
