# Filters and failure responses

Filters are Java hooks that see, change, answer or drop each exchange as it passes the proxy, with
LittleProxy's API. This page lists the hooks, shows the lambda builder and the per-request connect
timeout, and explains how the proxy answers when it cannot reach the server. Start with [Your first
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
| `proxyToServerRequest(HttpObject)` | after the proxy has rewritten the headers, before the server is resolved and connected | the same |
| `serverToProxyResponse(HttpObject)` | for the response head and each body piece from the server | return it (changed or replaced), or `null` to abort and disconnect the client |
| `proxyToClientResponse(HttpObject)` | before each piece is written to the client, also for the proxy's own responses | the same |
| `proxyToServerFailure(ProxyFailure)` | when the proxy has to answer itself ([below](#failure-responses)) | return the answer, or `null` for the default |
| `proxyToServerAllowMitm()`, `proxyToServerAllowMitm(ClientHello)` | for a `CONNECT`, and once its ClientHello is read | decline interception ([MITM](mitm.md#deciding-what-to-intercept-the-clienthello)) |
| `proxyToServerTlsIdentity(hostAndPort)` | before a request that reaches its server over TLS chooses a connection | return the server name (SNI) and verification host for it; `builder().tlsIdentity(...)` ([MITM](mitm.md#server-name-and-verification-host)) |
| `proxyToServerResolutionStarted(hostAndPort)` | before the server's name is resolved | return an address to use instead |
| `proxyToServerConnectTimeout()` | when a new server connection is needed | shorten the connect timeout ([below](#filters-from-lambdas)) |
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
`resolveWith`, `allowMitm`, `connectTimeout`, `bufferRequests` and `bufferResponses`. Registering a hook twice runs both in order.
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
