# Filters and failure responses

Filters are Java hooks that see, change, answer or drop each exchange as it passes the proxy, with
LittleProxy's API. This page lists the hooks, shows the lambda builder and the per-request
connection settings (connect timeout, TLS handshake timeout, retry backoff), and explains how the
proxy answers when it cannot reach the server. Start with [Your first
filter](../getting-started/first-filter.md) for a runnable example.

## The filter API

An `HttpFiltersSource` returns an `HttpFilters` for each request (or `null` to proxy it
unfiltered). The `HttpFilters` overrides the hooks it needs; every method has a default, so the
`*Adapter` classes are only conveniences. Install a source with `withFiltersSource(...)`, and add
more with `plusFiltersSource(...)`: several sources run in order as an `HttpFiltersChain`
(`HttpFiltersChain.of(a, b, c)` builds one by hand).

| Hook | When it runs | What it may do |
|---|---|---|
| `clientToProxyRequest(HttpObject)` | for the request head and each body piece from the client | return a response for the head to answer without contacting the server (a short-circuit), or `null` to go on |
| `proxyToServerRequest(HttpObject)` | after the proxy has rewritten the headers, before the server is resolved and connected (after it is resolved with the [protocol policy](protocol-policies.md) field `resolve_before_proxy_to_server_request`, as in the LittleProxy preset) | the same |
| `serverToProxyResponse(HttpObject)` | for the response head and each body piece from the server | return it (changed or replaced), or `null` to abort and disconnect the client |
| `proxyToClientResponse(HttpObject)` | before each piece is written to the client, also for the proxy's own responses (a `CONNECT`'s `200` passes `serverToProxyResponse` first; with the [protocol policy](protocol-policies.md) field `filter_connect_answer` off, as in the LittleProxy preset, neither hook sees it) | the same |
| `proxyToServerFailure(ProxyFailure)` | when the proxy has to answer itself ([below](#failure-responses)) | return the answer, or `null` for the default |
| `proxyToServerAllowMitm()`, `proxyToServerAllowMitm(ClientHello)` | for a `CONNECT`, and once its ClientHello is read | decline interception ([MITM](mitm.md#deciding-what-to-intercept-the-clienthello)) |
| `proxyToServerMitmHandshake()` | for a `CONNECT` the proxy intercepts, after authentication and `clientToProxyRequest` | run the server's TLS handshake before answering it (`EAGER`) or after the ClientHello (`DEFERRED`), over the [protocol policy](protocol-policies.md); `builder().mitmServerHandshake(...)` ([MITM](mitm.md#server-tls-failures)) |
| `proxyToServerTlsIdentity(hostAndPort)` | before a request that reaches its server over TLS chooses a connection | return the server name (SNI) and verification host for it; `builder().tlsIdentity(...)` ([MITM](mitm.md#server-name-and-verification-host)) |
| `proxyToServerResolutionStarted(hostAndPort)` | before the server's name is resolved | return an address to use instead |
| `proxyToServerConnectTimeout()` | when a new server connection is needed | change the connect timeout ([below](#per-request-connect-timeout)) |
| `proxyToServerTlsHandshakeTimeout()` | when a new server connection is needed | change the upstream TLS handshake timeout ([below](#per-request-tls-handshake-timeout)) |
| `chainedProxyRetryBackoff()` | when an attempt failed and another route remains | change the wait before the next chained proxy ([below](#per-request-retry-backoff)) |
| `requestBufferSizeInBytes(request)`, `responseBufferSizeInBytes(response)` | after a message's head | buffer that message whole ([Rewriting bodies](rewriting-bodies.md)) |
| `webSocketFrameReceived`, `filterWebSocketFrame`, `filterWebSocketMessage(s)` | after a WebSocket upgrade | watch, rewrite or drop frames and messages ([WebSockets](websockets.md)) |
| `proxyToClientResponseSent(response, source)`, `exchangeEnded(completed)` | once the response is written / once the exchange ends however it ended | release what the filter holds per exchange ([Activity tracking](../observability/activity-tracking.md)) |

The notification hooks (`proxyToServerRequestSending`, `proxyToServerRequestSent`,
`serverToProxyResponseReceiving`, `serverToProxyResponseReceived`,
`serverToProxyResponseTimedOut`, `proxyToServerResolutionSucceeded` / `Failed`,
`proxyToServerConnectionStarted` / `SSLHandshakeStarted` / `Failed` / `Succeeded`) report
progress and return nothing. The Javadoc of [`HttpFilters`](https://mahmoudimus.github.io/MicroProxy/api/org/microproxy/HttpFilters.html) describes each one.

A source can ask for whole messages with `getMaximumRequestBufferSizeInBytes()` /
`getMaximumResponseBufferSizeInBytes()`, as in LittleProxy; otherwise bodies stream through in
pieces. Bodies that no filter inspects skip the message objects entirely (see
[Architecture](../architecture.md#why-virtual-threads-instead-of-netty)).

### Addresses of a flow

The `FlowContext` a source and its filters get names four addresses of the client connection,
for logging, or for a filter that answers or resolves a request by the address the client came
in on:

| Method | The address |
|---|---|
| `getClientAddress()` | the client: the PROXY protocol header's source when one was accepted, else the TCP peer |
| `getDirectClientAddress()` | the TCP peer: the load balancer that sent the PROXY header, or the client |
| `getLocalAddress()` | the proxy's own address that the client connected to: the TCP socket's local address on every TCP listener (plain, TLS, h2c, SOCKS, transparent, reverse), the UDP address for HTTP/3 and transparent QUIC, the outer connection's inside an intercepted `CONNECT` stream |
| `getProxyProtocolDestinationAddress()` | the PROXY header's destination, the address the client reached at the load balancer; `null` without a header |

`getHttpVersion()` says which protocol the client speaks to the proxy (HTTP/1.1 for HTTP/1.x,
HTTP/2 or HTTP/3), the one whose [protocol policy](protocol-policies.md) applies, so a filter can
branch on it too.

A `FullFlowContext` has the same, plus the server side (`getRemoteAddress()`, the server or
chained proxy connected to). In LittleProxy the local address came from the
`ChannelHandlerContext` (`ctx.channel().localAddress()`) and the PROXY header's destination from
`ClientToProxyConnection.getHaProxyMessage()`.

## Filters from lambdas

`HttpFilters` keeps LittleProxy's shape: a class that overrides the hooks it needs. For small
filters, `HttpFilters.builder()` takes one lambda per hook instead, and `HttpFiltersSource` is a
functional interface:

```java
HttpFilters filters = HttpFilters.builder()
        .onRequest(req -> req.uri().contains("/admin") ? forbidden() : null)   // short-circuit
        .beforeSending(req -> { req.headers().set("X-Trace", traceId()); return null; })
        .onResponse(res -> { res.headers().remove("Server"); return res; })
        .onWebSocketFrame((frame, fromClient) -> frame.isPing() ? null : frame)
        .build();
MicroProxy.bootstrap().withFiltersSource((request, ctx) -> filters).start();
```

Other hooks: `onRequestBody`, `onResponseBody`, `beforeResponding`, `onFailure`, `onWebSocketMessage`,
`resolveWith`, `allowMitm`, `connectTimeout`, `tlsHandshakeTimeout`, `retryBackoff`, `bufferRequests` and
`bufferResponses`. Registering a hook twice runs both in order.
`log(httpLogger)` logs each exchange around the lambdas (see [Request/response
logging](../observability/request-logging.md)), whether a lambda source returns the built filters, as above,
or they are the source themselves: they are also an `HttpFiltersSource` that returns them for every
request, so `withFiltersSource(filters)` works as well.

### Per-request connect timeout

`HttpFilters.proxyToServerConnectTimeout()` (or `connectTimeout(Duration)`
in the builder) bounds the TCP connect of the request's new connections, direct or to each chained
proxy tried, instead of the server's `withConnectTimeout`. `null` (the default) or a non-positive
duration keeps the server's; in a chain the shortest timeout wins. It is asked only when a new
connection is needed, and does not cover name resolution or TLS handshakes:

```java
HttpFilters.builder()
        .connectTimeout(Duration.ofMillis(500))   // fail fast, e.g. to fall back to the next upstream
        .build();
```

### Per-request TLS handshake timeout

`HttpFilters.proxyToServerTlsHandshakeTimeout()` (or `tlsHandshakeTimeout(Duration)` in the
builder) bounds each upstream TLS handshake of the request's new connections instead of the server's
`withTlsHandshakeTimeout` (10 s by default): with the server when the proxy speaks TLS to it (an
intercepted `CONNECT`, an absolute `https://` URL, HTTP/2 to the server), and with each TLS chained
proxy tried (`https://` and `h2://` ones), including the server's handshake through a tunnel. `null`
(the default) or a non-positive duration keeps the server's, so a request cannot turn the limit
off; in a chain the shortest timeout wins. A handshake that runs out of time is a
`ProxyFailure.TlsFailed` whose cause is a `SocketTimeoutException` (response flag `UF`), and the
next chained proxy, if any, is tried:

```java
HttpFilters.builder()
        .tlsHandshakeTimeout(Duration.ofMillis(200))   // a server that accepts but never handshakes fails fast
        .build();
```

Upstream HTTP/3 (QUIC) handshakes keep `Http3Options.upstreamHandshakeTimeout()`: those
connections are shared by every client, and one that is not made in time sends the request over
TCP rather than failing it, where this timeout bounds the TLS handshake.

### Per-request retry backoff

`HttpFilters.chainedProxyRetryBackoff()` (or `retryBackoff(RetryBackoff)` in the builder) chooses
the wait between the request's attempts at its chained proxies instead of the server's
[`withChainedProxyRetryBackoff`](chained-proxies.md#retries-and-backoff): `RetryBackoff.exponential`
for exact doubling waits, `exponentialWithJitter`, `fixed`, or `none()` to try the next route at
once. `null` (the default) keeps the server's; in a chain the first filter that names a backoff
wins. It is asked only after an attempt failed, so requests that connect at once never ask:

```java
HttpFilters.builder()
        .retryBackoff(RetryBackoff.exponential(Duration.ofMillis(100), Duration.ofSeconds(1)))   // 100, 200, 400, 800, 1000 ms
        .build();
```

The policy carries the budget for all of the request's waits too: by default the connect timeout,
at most 30 seconds; `.withBudget(Duration)` sets another, and `.unbudgeted()` waits every time the
policy names (see [Retries and backoff](chained-proxies.md#retries-and-backoff)).

Bodies and frames are only split into pieces when a body or frame hook is registered; otherwise they
take the fast path, as they do for a filters class that doesn't override those hooks. A filters
class that overrides `clientToProxyRequest` or `serverToProxyResponse` only to read heads can say so
by implementing `SelectiveFilters`: the proxy then asks its `sees(Body)` instead of guessing from the
class.

## Failure responses

When the proxy has to answer a request itself, it sends a short plain-text body (`Bad Gateway`,
`Gateway Timeout`, ...) that never echoes the request. The cause is a sealed `ProxyFailure`:

| `ProxyFailure` | when | default |
|---|---|---|
| `UnresolvedHost` | the server's name did not resolve | `502` |
| `ConnectFailed` | connection refused, unreachable or timed out; a chained proxy refused, or its own name did not resolve | `502` |
| `TlsFailed` | the TLS handshake with the server (MITM, or [TLS origination](forward-proxy.md#tls-origination-https-uris-without-connect)) or a TLS chained proxy failed or timed out | `502` |
| `ServerTimeout` | no response within the idle timeout | `504` |
| `BadServerResponse` | malformed response, or the server closed or failed before the head was complete | `502` |
| `NoRoute` | the request names no host, or the chained proxy manager offered no route | `502` |
| `NoConnectionAvailable` | the shared connection pool had no connection to spare | `503` |
| `BadRequest` | an origin-form request (unless allowed), a client's `https://` request with TLS origination off, or an invalid `CONNECT` target | `400` |
| `RequestTooLarge` | the body exceeds what the filters asked to buffer | `413` |

Filters can answer first (`HttpFilters.proxyToServerFailure`, or `onFailure` in the builder; in a
chain the first answer wins), then a `FailureResponder`; returning `null` keeps the default:

```java
MicroProxy.bootstrap()
        .withFailureResponder((request, failure) -> switch (failure) {
            case ProxyFailure.TlsFailed f -> errorPage(502, "The site's certificate is not trusted");
            case ProxyFailure.ServerTimeout f -> errorPage(504, "The site took too long to answer");
            default -> null;
        })
        .start();
```

Starlark scripts answer through `on_failure` (see [Scripting with Starlark](scripting.md)).
The proxy frames whatever is returned (`Content-Length`, keep-alive, no body for `HEAD`), and it
passes `proxyToClientResponse` like the default answers. A responder that throws is logged and the
default is sent. Requests the proxy cannot parse at all are answered with a plain `4xx` without
asking anyone. `HttpCache` uses the filter hook to serve stale entries when servers are
unreachable.

Customising the proxy's own error pages belongs here, in `proxyToServerFailure` or a
`FailureResponder`, which get the failure itself, rather than in `proxyToClientResponse`.

### The proxy's responses in proxyToClientResponse

`proxyToClientResponse` sees the server's responses, and also the responses the proxy answers with
itself: its failure answers above (a `FailureResponder`'s included) and the short-circuit
responses filters returned from `clientToProxyRequest` or `proxyToServerRequest` (the
`HttpCache`'s answers too). No filter sees the `407` authentication challenge, which is sent
before the request's filters are made. What the hook may do with the proxy's responses is the
[protocol policy](protocol-policies.md) field `generated_responses`:

| `GeneratedResponses` | `proxyToClientResponse` | For |
|---|---|---|
| `REPLACEABLE` (the default; LittleProxy 2.x) | sees them, may return another response or `null` (close without an answer) | filters that brand every response: their own error pages, `503` with `Retry-After` in place of `502`, CORS or request-id headers on every response |
| `IN_PLACE` (LittleProxy 1.x and its forks) | sees them, may change them in place or return `null`; another response it returns is ignored | filters written for the server's responses, which must not turn the proxy's own errors into something else (a filter that answers some responses `400` would otherwise turn an unreachable server's `502` into `400`) |
| `SKIP` | never sees them; trackers and `proxyToClientResponseSent` still do | filters that must only ever see the server's responses |

```java
MicroProxy.bootstrap()
        .onHttp1(p -> p.generatedResponses(GeneratedResponses.IN_PLACE))
        .start();
```

Inside the hooks, `FlowContext.responseSource()` says where the response at hand came from:
`SERVER`, `PROXY` (the proxy's answers, and the `200` that opens a `CONNECT` tunnel), `FILTER`
(a short-circuit response, or one a filter replaced or restatused in `serverToProxyResponse`),
`CACHE` or `REPLAY`; once the response is sent, where the response the client got came from, as
`proxyToClientResponseSent` is told.
