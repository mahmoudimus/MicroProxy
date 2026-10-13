# Forward proxy

The default mode: clients are configured to use MicroProxy as their HTTP proxy and send it
absolute-form requests and `CONNECT`s. This page covers what plain HTTP/1 proxying does, the TLS
listener (an HTTPS proxy), TLS origination for `https://` URIs sent without `CONNECT`, the PROXY
protocol, bandwidth throttling, removing tracing headers and the shared server connection pool.
Interception of HTTPS is in [MITM, certificates and TLS](mitm.md).

## Running a forward proxy

```bash
java -jar microproxy.jar --port 8080                 # loopback only
java -jar microproxy.jar --port 8080 --server        # every interface
curl -x http://127.0.0.1:8080 http://example.com/
curl -x http://127.0.0.1:8080 https://example.com/   # a CONNECT tunnel, untouched without --mitm
```

```java
HttpProxyServer proxy = MicroProxy.bootstrap()
        .withPort(8080)
        .withAllowLocalOnly(false)          // --server
        .start();
```

## HTTP/1.0 and 1.1 proxying

Keep-alive on both sides, pipelining, chunked bodies and trailers, `Expect: 100-continue` (a
`100` is sent for servers that ignore it), 1xx pass-through, re-chunking of close-delimited
responses, de-chunking for HTTP/1.0 clients, and a retry when a kept-alive server connection
turns out to be stale. The proxy adds `Via` (named by `--proxy-alias`, `proxy_alias`,
`withProxyAlias`; the host name by default) and removes hop-by-hop headers, except in
[transparent mode](transparent-mode.md). Requests in origin form (`GET /path`) are refused unless
`--allow-requests-to-origin-server` (`allow_requests_to_origin_server`) allows them.

Requests are parsed strictly ([Security](../security.md#request-parsing)), and when the proxy has
to answer itself it sends a short plain-text answer ([Failure responses](filters.md#failure-responses)).

## CONNECT tunnels

A `CONNECT` opens a byte tunnel, with an idle timeout (`--idle-timeout`, 70 seconds by default)
and half-close. Without a MITM manager the tunnel is relayed untouched; with one, the client's
first bytes decide whether it is intercepted ([Deciding what to
intercept](mitm.md#deciding-what-to-intercept-the-clienthello)). [TCP hooks](tcp-hooks.md) can see
and rewrite the bytes of tunnels that are not intercepted.

## TLS listener

`withSslContextSource(...)` serves the proxy itself over TLS (an "HTTPS proxy"), and
`withAuthenticateSslClients(true)` requires client certificates on it. From the command line,
`--listener-keystore <file>` and `--listener-keystore-password <pw>` (`listener_keystore`,
`listener_keystore_password`) serve TLS with a PKCS#12 or JKS key store's first key entry. The
listener also offers HTTP/2 (unless `--no-http2`), and with `--http3` a forward proxy serves HTTP/3 next to
it ([An HTTP/3 forward-proxy listener](http3.md#an-http3-forward-proxy-listener)).

```java
MicroProxy.bootstrap()
        .withPort(8443)
        .withSslContextSource(new KeyStoreSslContextSource(Path.of("proxy.p12"), password))
        .start();
```

## PROXY protocol

`--accept-proxy-protocol` (`allow_proxy_protocol=true`, `withAcceptProxyProtocol(true)`) requires a
PROXY protocol header (v1 or v2) on every inbound connection, read before anything else: before
TLS on a TLS listener, and before SOCKS, HTTP/2 prior knowledge or transparent TLS are told apart.
The source it names is the client from then on: `FlowContext.getClientAddress()`, `ClientDetails`,
access logs and traces (`%DOWNSTREAM_REMOTE_ADDRESS%`, `client.address`), and the header sent on
with `--send-proxy-protocol`. The load balancer's own address stays in
`%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%` (`FlowContext.getDirectClientAddress()`). A v1 `UNKNOWN`
header, and a v2 `LOCAL` one or one without addresses, leave the TCP peer as the client.

`--proxy-protocol-mode optional` (`allow_proxy_protocol=optional`,
`withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL)`) reads a header only when the connection
starts with one, for a listener that load balancers and clients reach directly, or during a
migration. The proxy looks at the first bytes without consuming them: `PROXY ` starts a v1
header and the 12-byte v2 signature a v2 one; anything else (an HTTP request, a TLS ClientHello, a
SOCKS greeting) is served as if PROXY protocol were off, its bytes untouched. A request is told
apart by its first byte or few, so it is not delayed.

> **Optional PROXY protocol lets any client choose its address.** In optional mode any client
> that can reach the listener can send a header and be logged, rate-limited and authorized as
> whatever address it names. Use it only where the clients that can connect directly are trusted
> (behind a load balancer, on a private network), and name the load balancers with
> `--proxy-protocol-trusted-sources 10.0.0.0/8,192.0.2.10` (`proxy_protocol_trusted_sources`,
> `withProxyProtocolTrustedSources(...)`).

With trusted sources, only those peers' headers count. A connection from another peer that starts
with a header is closed rather than served (with its header ignored, a misrouted or forged header
would go unnoticed, and the client would still get through); with a required header, every
connection from another peer is closed. Without trusted sources, every peer's header counts.

Once a connection's first byte has come (which may take the idle timeout, as a request's would),
the rest of the header must arrive within 5 seconds, or the idle timeout if that is shorter,
however slowly it trickles in; a connection that sends part of a signature or header and stalls is
closed then. The `proxy_proto.*` [stats](../reference/stats.md) count the headers read, the
connections without one, malformed headers and untrusted peers.
`--send-proxy-protocol` (`send_proxy_protocol`, `withSendProxyProtocol(true)`) sends a PROXY
protocol v1 header to the final server: first on a direct connection, or through the tunnel once
an HTTP chained proxy has accepted the `CONNECT`. It is not sent where there is no tunnel to the
final server: through SOCKS chained proxies, or with plain requests forwarded to an HTTP chained
proxy. Server connections that carry the header belong to one client, so the shared server
connection pool is not used while sending is on.

## Throttling

A global token bucket limits the bandwidth of server reads and writes, in bytes per second (`0`
means unlimited): `--throttle <read> <write>`, `throttle_read_bytes_per_second` and
`throttle_write_bytes_per_second`, or `withThrottling(read, write)`. `HttpProxyServer.setThrottle`
changes the limits while the proxy runs.

## TLS origination: `https://` URIs without `CONNECT`

Browsers ask a forward proxy for `https://` pages with `CONNECT` and speak TLS to the server
themselves. Some clients instead hand the proxy the URI in plain HTTP and leave TLS to it: `GET
https://example.com/ HTTP/1.1` in absolute-form, an HTTP/2 stream with `:scheme https` on an
[h2c](http2.md#h2c-with-prior-knowledge) connection or on the proxy's TLS listener, or a secure WebSocket
(`wss://`, or extended `CONNECT` with `:scheme https`). A forward proxy fetches these over TLS
that it opens to the server itself, as it does for the requests of an intercepted session:

- **Trust.** The server's certificate and name are checked with the MITM manager's server TLS
  context (`CertificateAuthorityMitmManager`'s upstream trust, `--mitm-trust-all` included; a
  manager chosen per client connection is asked as for interception), or with the JVM's default
  trust store when there is no manager. A failed handshake is `ProxyFailure.TlsFailed`: a `502`
  from the [failure responder](filters.md#failure-responses), the `UF` response flag with
  `proxy_failure:tls_failed` details, the handshake's error in `%UPSTREAM_TRANSPORT_FAILURE_REASON%`
  (an untrusted issuer, a name the certificate does not cover), `on_failure` in scripts, and the
  cluster's `ssl.connection_error`, as for an intercepted session's server.
- **Connections.** They are the same kind of connection an intercepted session's requests use, and
  pooled with them under the same keys, kept apart by target, route (direct, or which chained
  proxy) and MITM manager: a client connection keeps its own, or, with the [shared
  pool](#shared-server-connection-pool) and `pool_shared_mitm_connections`, every client shares
  them, whether they were made for an intercepted session or for a client's `https://` URI.
- **HTTP/2 and HTTP/3.** Unless `--no-http2-upstream`, the handshake offers `h2` and `http/1.1`, and a
  server that picks `h2` gets the requests as streams on a shared connection, with [connection
  coalescing](http2.md#connection-coalescing) when it is on; with `--http3-upstream`, a server known to
  speak HTTP/3 gets them over QUIC, on direct routes.
- **Chained proxies.** Through an HTTP chained proxy the request does not go in absolute-form, as
  an `http://` one does: the proxy asks it for a tunnel to the server (`CONNECT host:443`) and runs
  TLS inside, as a browser would, so the chained proxy never sees the request. SOCKS proxies give
  a tunnel the same way, and `UpstreamProxyManager` picks its HTTPS upstream
  (`--upstream-https-proxy`) for an `https://` URI.
- **What everyone sees.** Filters get the request as the client sent it, `https://...` included;
  scripts see `req.scheme == "https"` and the `https://` URL in every hook; the server gets it in
  origin-form with `Host` from the URI. Access logs record the `https://` request with the
  server's TLS session (`%UPSTREAM_TLS_VERSION%`, `%UPSTREAM_PEER_SUBJECT%`, ...), stats count the
  handshakes in the route's cluster (`cluster.direct.ssl.handshake`, ...), and the OpenTelemetry
  SERVER span (`url.scheme`, `url.full`) and CLIENT span (`url.full`) say `https`.

This is on by default, as it has been since 0.2.0 (before, such a request went to the server's
port in plain text). `withTlsOrigination(false)` (`--no-originate-tls`, `originate_tls=false`)
turns it off: such requests are refused with `ProxyFailure.BadRequest` (`400 Bad Request:
https:// URIs need CONNECT (TLS origination is off)`, flag `DPE`) before any connection is made.
Turn it off when plain-HTTP clients should reach TLS servers only through tunnels, as operators
may expect of them: with TLS origination the proxy reads and handles in the clear what host rules
(`--ignore-hosts`, `--allow-hosts`) and `proxyToServerAllowMitm` would have kept from it on a
`CONNECT`, and on the plain listener the request, cookies and credentials included, crosses the
network between client and proxy in plain text. An `https://` URI that a filter or script gives
a request (`MapRemote`, `req.uri = ...`) is fetched over TLS either way: that is the operator's
choice, not the client's. So are the requests of intercepted sessions, and a reverse proxy's
`https://` upstream.

## Removing tracing headers

Clients and services often send distributed tracing headers that carry trace ids, sampling
decisions and baggage (sometimes user ids) to whatever server they talk to. To keep them from
leaving through the proxy:

```java
MicroProxy.bootstrap()
        .withoutTracingHeadersUpstream()                 // HttpHeaderNames.TRACING_HEADERS
        .plusStrippedRequestHeaders("X-Request-Id")      // and any others
        .start();
```

- **The list:** `traceparent`, `tracestate`, `baggage`, `b3`, `X-B3-TraceId`, `X-B3-SpanId`,
  `X-B3-ParentSpanId`, `X-B3-Sampled`, `X-B3-Flags`, `uber-trace-id`, `X-Amzn-Trace-Id`,
  `X-Cloud-Trace-Context`, `grpc-trace-bin` and `sentry-trace`. `X-Request-Id` is not on it,
  because servers often want it; add it with `plusStrippedRequestHeaders` if yours do not.
- **When:** right before a request is written to the server or chained proxy, after every filter,
  so headers a filter added are removed too. Filters, `HttpLogger`'s "forwarded as" view and
  `ActivityTracker.requestReceivedFromClient` still see them; `requestSentToServer` does not.
- **Where:** plain requests, requests inside intercepted (MITM) sessions, WebSocket upgrade
  requests, and the `CONNECT` requests sent to HTTP chained proxies. The bytes of a tunnel that is
  not intercepted cannot be touched.
- `withStrippedRequestHeaders(names...)` replaces the list instead of adding to it; names are
  matched case-insensitively.
- On the command line: `--strip-tracing-headers` and `--strip-request-headers a,b`; in properties
  files: `strip_tracing_headers=true` and `strip_request_headers=a,b`.

## Shared server connection pool

By default, as in LittleProxy, server connections are kept per client connection. Calling
`withSharedServerConnectionPool(true)` shares them between all clients:

- **Leasing:** a connection is leased for one request and returned when the response completes
  with keep-alive.
- **Pool keys:** idle connections are kept per target and route, so direct, via-proxy and
  intercepted connections never mix.
- **Limits:** `withMaxConnections` (default 200) and `withMaxConnectionsPerHost` (default 10).
  When the pool is full, a request waits up to the connect timeout for a connection, then gets
  `503`. LittleProxy returned `502` immediately.
- **Idle eviction:** `withPoolIdleTimeout` closes connections idle for too long. A pooled
  connection the server closed while idle is retried transparently.
- **Intercepted TLS:** `withPoolSharedMitmConnections(true)` lets intercepted sessions take their
  upstream TLS connection from the pool and return it when the client leaves.
  `withPoolPerRequestInMitm(true)` leases it per request instead. Managers chosen per client
  connection only share with clients given the same manager (see
  [Interception per client connection](mitm.md#interception-per-client-connection)).
- **Metrics:** `HttpProxyServer.getServerConnectionPoolMetrics()` reports counts.
