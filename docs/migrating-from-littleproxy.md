# Migrating from LittleProxy

How to move a LittleProxy deployment or embedding to MicroProxy: the command line, the
configuration file, embedding, filters, MITM and activity logging, mapped topic by topic to their
MicroProxy equivalents, then the API renames and the behaviour that differs. Use this page if you
run or embed LittleProxy today.

## At a glance

| LittleProxy | MicroProxy |
|---|---|
| `io.github.littleproxy:littleproxy` | `io.github.mahmoudimus:microproxy` ([Install](getting-started/install.md)) |
| Netty event loops and thread pools | one virtual thread per connection ([Architecture](architecture.md#why-virtual-threads-instead-of-netty)) |
| `org.littleshoot.proxy` | `org.microproxy` |
| `DefaultHttpProxyServer.bootstrap()` | `MicroProxy.bootstrap()` |
| `./run.bash [options]` | `java -jar microproxy.jar [options]` ([Command-line flags](reference/cli.md)) |
| `littleproxy.properties` (`--config`) | the same keys, mostly ([Configuration properties](reference/properties.md)) |
| log4j configuration (`--log_config`) | `System.Logger`: `java.util.logging`, or SLF4J/Log4j through their bridges |

`withLittleProxyCompatibility()` (`--littleproxy-compat`, `littleproxy_compatibility=true`)
restores LittleProxy's behaviour for HTTP/1 clients where MicroProxy deliberately differs, as a
[protocol policy](guides/protocol-policies.md) preset whose fields can be set one by one; see
[Behaviour differences](#behaviour-differences).

## Command line

LittleProxy's options are underscore-separated and take `true` for booleans
(`--dnssec true`); MicroProxy's are dash-separated, and boolean flags take no value
(`--dnssec`). LittleProxy's `./run.bash` becomes `java -jar microproxy.jar` (or the `-all` jar).

| LittleProxy option | MicroProxy |
|---|---|
| `--config <file>` | `--config <file>`; flags override the file in both |
| `--port <port>` | `--port <port>` |
| `--address <host:port>` | `--address <host:port>` |
| `--name <name>` | `--name <name>` |
| `--nic <nic>` | no flag; the `nic` property takes a local address (not an interface name) for outbound connections |
| `--proxy_alias <alias>` | `--proxy-alias <alias>` |
| `--allow_local_only true` | the default: MicroProxy listens on loopback only unless given `--server` |
| `--server` (keep running) | the launcher always keeps running; MicroProxy's `--server` listens on all interfaces instead of loopback |
| `--dnssec true` | `--dnssec` (a validating resolver; see [DNSSEC](guides/dnssec.md)) |
| `--mitm` (`SelfSignedMitmManager`) | `--mitm`: a CA kept in `microproxy-ca.p12`, its certificate in `microproxy-ca.pem` ([MITM](guides/mitm.md)) |
| `--log_config <file>` | none: `-Djava.util.logging.config.file=<file>`, or your SLF4J/Log4j configuration through their bridges |
| `--activity_log_format <fmt>` | `--activity-log-format <fmt>`, or `--access-log <path\|->` with `--access-log-format <fmt>` ([Access logs](observability/access-logs.md)) |
| `--authenticate_ssl_clients true` | `withAuthenticateSslClients(true)` on a TLS listener (`--listener-keystore`) |
| `--trust_all_servers true` | `--mitm-trust-all` |
| `--send_certs true`, `--ssl_client_keystore_path`, `--ssl_client_keystore_alias`, `--ssl_client_keystore_password` | no flags: an upstream context with a key, `SslContexts.withKey(key, chain, trustManagers)`, presents a client certificate ([Interception per client connection](guides/mitm.md#interception-per-client-connection)) |
| `--throttle_read_bytes_per_second <n>`, `--throttle_write_bytes_per_second <n>` | `--throttle <read> <write>` |
| `--allow_request_to_origin_server true` | `--allow-requests-to-origin-server` |
| `--allow_proxy_protocol true` | `--accept-proxy-protocol`; `--proxy-protocol-mode optional` reads a header only when a connection starts with one, as some LittleProxy forks did ([PROXY protocol](guides/forward-proxy.md#proxy-protocol)) |
| `--send_proxy_protocol true` | `--send-proxy-protocol` |
| `--client_to_proxy_worker_threads`, `--proxy_to_server_worker_threads`, `--acceptor_threads` | none: virtual threads replace event-loop sizing |
| `--help` | `--help` |

## Configuration file

MicroProxy reads the same kind of properties file, and most of LittleProxy's keys mean the same:
`dnssec`, `transparent`, `max_initial_line_length`, `max_header_size`, `max_chunk_size`,
`server_connection_pool_type`, `max_total_connections`, `max_connections_per_host`, `name`,
`address`, `port`, `nic`, `proxy_alias`, `allow_local_only`, `throttle_read_bytes_per_second`,
`throttle_write_bytes_per_second`, `allow_requests_to_origin_server`, `allow_proxy_protocol`,
`send_proxy_protocol` and `activity_log_format`. The differences:

| LittleProxy key | MicroProxy |
|---|---|
| `idleConnectionTimeout` | `idle_connection_timeout` (seconds; default 70) |
| `connect_timeout` | `connect_timeout`, in milliseconds (default 40000) |
| `allow_local_only` (default `false`) | the same key, default `true` |
| `allow_proxy_protocol` | the same key; it also takes `optional` (and `required`, `off`), and any value other than those and the booleans is an error |
| `nic` (an interface name) | a local address to connect from |
| `authenticate_ssl_clients`, `ssl_clients_trust_all_servers`, `ssl_clients_send_certs`, `ssl_clients_key_store_file_path`, `ssl_clients_key_store_alias`, `ssl_clients_key_store_password` | not read: use `listener_keystore` for a TLS listener, `--mitm-trust-all`, and the Java API for client certificates |

Every key MicroProxy reads is in [Configuration properties](reference/properties.md).

## Embedding

```java
// LittleProxy
HttpProxyServer server = DefaultHttpProxyServer.bootstrap().withPort(8080).start();
// MicroProxy
HttpProxyServer server = MicroProxy.bootstrap().withPort(8080).start();
```

The bootstrap keeps LittleProxy's methods, including the shared server connection pool's
(`withSharedServerConnectionPool`, `withMaxConnections`, `withMaxConnectionsPerHost`,
`withPoolIdleTimeout`, `withServerConnectionPoolType`) and `clone()`, which makes another server
with the same configuration (`existingServer.clone().withPort(8081).start()`). Pool metrics are
`org.microproxy.PoolMetrics`, a record with LittleProxy's fields (`totalConnections`,
`activeConnections`, `idleConnections`, `borrowCount`, `returnCount`, `evictionCount`,
`validationFailureCount`), from `HttpProxyServer.getServerConnectionPoolMetrics()`; see
[Shared server connection pool](guides/forward-proxy.md#shared-server-connection-pool), where
MicroProxy's limits and its `503` (LittleProxy: `502`) are described.

## Filters

Filters port with the type renames below: `filterRequest(HttpRequest, ChannelHandlerContext)`
becomes `filterRequest(HttpRequest, FlowContext)`, and `HttpFiltersAdapter(originalRequest)` and
`HttpFiltersAdapter(originalRequest, ctx)` keep both constructors. Content is a `byte[]` instead of
a `ByteBuf`, so an answer is `new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
HttpResponseStatus.OK, "<html>...</html>")`, with `Content-Length` set when it is written.

- **Buffering:** `getMaximumRequestBufferSizeInBytes()` / `getMaximumResponseBufferSizeInBytes()`
  work as in LittleProxy, and bodies are decoded for you with
  [`HttpBodies`](guides/rewriting-bodies.md). There is no Netty pipeline to strip an inflater or
  aggregator from: to buffer some responses and stream others (large downloads), override
  `responseBufferSizeInBytes(response)` per message instead.
- **Direct requests to the proxy:** an origin-form request (no scheme, host or port) is answered
  `400` unless `--allow-requests-to-origin-server` is given; a filter can answer it from
  `clientToProxyRequest`, as in LittleProxy.
- **New hooks:** lambdas (`HttpFilters.builder()`), failure answers, per-request connect and
  upstream TLS handshake timeouts (`proxyToServerConnectTimeout`,
  `proxyToServerTlsHandshakeTimeout`), a per-request retry backoff (`chainedProxyRetryBackoff`),
  WebSocket frames and messages: see [Filters and failure responses](guides/filters.md).

## MITM

LittleProxy's `SelfSignedMitmManager` (and the LittleProxy-mitm extension) become
`org.microproxy.tls.CertificateAuthorityMitmManager`: a persistent CA, per-host EC certificates
whose SANs copy the real server's names, a bounded certificate cache, and upstream trust of your
choice. `MitmManager.serverSslEngine` / `clientSslEngineFor` become `serverSslContext` /
`clientSslContextFor`, returning an `SSLContext`. See [MITM, certificates and TLS](guides/mitm.md).

## TLS to servers

LittleProxy forks commonly patched how the proxy's own TLS with servers behaves. MicroProxy has
these as options:

- **Retry without SNI.** Some servers answer a server name (SNI) they do not recognize with a
  fatal `unrecognized_name` alert. Forks retried the handshake once without SNI, as the JDK's
  `HttpsURLConnection` once did. `withTlsRetryWithoutSni(true)` (`--tls-retry-without-sni`,
  `tls_retry_without_sni=true`) does the same, on a new connection; it is on by default for
  HTTP/1 clients with `withLittleProxyCompatibility()`, and `withTlsRetryWithoutSni(false)` keeps
  it off there too. It is a [protocol policy](guides/protocol-policies.md) field, so it can be set
  for one client protocol alone (`onHttp2(p -> p.tlsRetryWithoutSni(true))`).
  The certificate is still checked against the host the request is for. See
  [Server TLS failures](guides/mitm.md#server-tls-failures).
- **SNI and verification host apart from the address.** Forks that connected to an IP address or
  an internal load balancer patched the SSL engine to send another server name. Override
  `HttpFilters.proxyToServerTlsIdentity(serverHostAndPort)` (or
  `HttpFilters.builder().tlsIdentity(...)`) to return a `TlsServerIdentity` with the SNI name and
  the host the certificate is checked against; see
  [Server name and verification host](guides/mitm.md#server-name-and-verification-host).
- **Why a handshake failed.** `ProxyFailure.TlsFailed.cause()` is the JDK's own exception with its
  whole cause chain (for a revoked certificate, the `CertPathValidatorException` with reason
  `REVOKED` is in it), and `TlsFailed.reason()` classifies it: `CERTIFICATE_REVOKED`,
  `CERTIFICATE_EXPIRED`, `CERTIFICATE_UNTRUSTED`, `HOSTNAME_MISMATCH`, `ALERT_RECEIVED` (with
  `alert()`), ... The access log's `%UPSTREAM_TRANSPORT_FAILURE_REASON%` starts with the same
  name.

## Activity logging

`org.littleshoot.proxy.extras.ActivityLogger` and `LogFormat` are
`org.microproxy.extras.ActivityLogger` and `LogFormat`, with the same formats (`CLF`, `ELF`,
`JSON`, `SQUID`, `W3C`, `LTSV`, `CSV`, `HAPROXY`), now presets of an Envoy-compatible formatter,
plus `JSON_EXTENDED` and `ENVOY`:

```java
MicroProxy.bootstrap()
        .withPort(8080)
        .plusActivityTracker(new ActivityLogger(LogFormat.CLF))
        .start();
```

Lines go to the `System.Logger` named `org.microproxy.extras.ActivityLogger`, as LittleProxy's go to
its logger; instead of a log4j appender per file, `--access-log access.log` (or `-` for standard
output) writes them directly. See [Access logs](observability/access-logs.md) and
[Presets](reference/access-log-format.md#presets).

## API renames

The public API keeps LittleProxy's shape (`HttpProxyServerBootstrap`, `HttpFilters`,
`HttpFiltersSource`, `ActivityTracker`, `ChainedProxy`, `ChainedProxyManager`, `MitmManager`,
`ProxyAuthenticator`, `HostResolver`, `FlowContext`). The packages changed from
`org.littleshoot.proxy` to `org.microproxy`. The Netty types are replaced like this:

| LittleProxy / Netty | MicroProxy |
|---|---|
| `io.netty.handler.codec.http.*` (`HttpRequest`, `HttpResponse`, `HttpContent`, `LastHttpContent`, `FullHttpRequest`, `FullHttpResponse`, `HttpHeaders`, `HttpMethod`, `HttpVersion`, `HttpResponseStatus`, `HttpUtil`) | `org.microproxy.http.*` with the same names and similar methods |
| `ByteBuf content()` | `byte[] content()` / `setContent(byte[])` / `contentAsString()` |
| `DefaultHttpProxyServer.bootstrap()` | `MicroProxy.bootstrap()` |
| `HttpFiltersSource.filterRequest(req, ChannelHandlerContext)` | `filterRequest(req, FlowContext)` |
| `HttpFiltersAdapter(req, ctx)` | `HttpFiltersAdapter(req, flowContext)` |
| `proxyToServerConnectionSucceeded(ChannelHandlerContext)` | `proxyToServerConnectionSucceeded(FullFlowContext)` |
| `ctx.channel().localAddress()` (the proxy's address the client connected to) | `FlowContext.getLocalAddress()` ([Addresses of a flow](guides/filters.md#addresses-of-a-flow)) |
| `ClientToProxyConnection.getHaProxyMessage()` destination | `FlowContext.getProxyProtocolDestinationAddress()`; its source is `getClientAddress()`, the TCP peer `getDirectClientAddress()` |
| `SslEngineSource` (`SSLEngine`) | `SslContextSource` (`SSLContext`, plus a `configure(SSLSocket, clientMode)` hook) |
| `MitmManager.serverSslEngine / clientSslEngineFor` | `serverSslContext / clientSslContextFor` (return `SSLContext`) |
| `withSslEngineSource` | `withSslContextSource` |
| `SelfSignedSslEngineSource` (keytool, JKS file) | `org.microproxy.tls.SelfSignedSslContextSource` (generated in memory) |
| `SelfSignedMitmManager` | `org.microproxy.tls.CertificateAuthorityMitmManager` |
| `HttpProxyServer.getIdleConnectionTimeout()` (seconds) | returns a `Duration` |
| `DnsSecServerResolver` (dnssec4j) | `org.microproxy.dns.DnssecHostResolver` |
| `org.littleshoot.proxy.extras.ActivityLogger` / `LogFormat` | `org.microproxy.extras.ActivityLogger` / `LogFormat` |
| `impl.PoolMetrics` | `org.microproxy.PoolMetrics` (a record) |

## Behaviour differences

Where MicroProxy deliberately behaves otherwise than LittleProxy and a filter may depend on it,
a [protocol policy](guides/protocol-policies.md) field chooses, for HTTP/1, HTTP/2 or HTTP/3
clients separately. `ProtocolPolicy.littleProxy()` sets the behavior fields below to LittleProxy's
values; MicroProxy's 30-second `request_head_timeout` remains enabled because LittleProxy has no
separate setting for it (its idle timer, which sees only whole messages, ends a head that is still
arriving at the idle timeout instead; see the table). `withLittleProxyCompatibility()` (`--littleproxy-compat`,
`littleproxy_compatibility=true`) makes the preset the default of HTTP/1 clients, the only ones
LittleProxy ever served. Any field can still be set
on its own, for HTTP/1 (`onHttp1`, `--http1-policy`, `policy.http1.<field>`) or for every protocol
(`onAllProtocols`, `--policy`, `policy.<field>`), over the preset:

```java
MicroProxy.bootstrap()
        .withLittleProxyCompatibility()                // LittleProxy's behaviour for HTTP/1 clients
        .onHttp1(p -> p.filterConnectAnswer(true))     // except: filters see the CONNECT's 200
        .start();                                      // HTTP/2 and HTTP/3 clients: MicroProxy's
```

| Field | LittleProxy 2.9.1 (`ProtocolPolicy.littleProxy()`) | MicroProxy's default |
|---|---|---|
| `resolve_before_proxy_to_server_request` | `true`: `ClientToProxyConnection.doReadHTTPInitial` creates the server connection (`ProxyToServerConnection.create`, whose `setupConnectionParameters` resolves the server) before it calls `proxyToServerRequest`, and answers `502` without calling it when the name does not resolve | `false`: `proxyToServerRequest` runs before the server is resolved and connected, so a filter can answer or redirect without a DNS lookup |
| `filter_connect_answer` | `false`: `ClientToProxyConnection.RespondCONNECTSuccessful` writes the `200 Connection established` straight to the client; no response filter runs, and only trackers hear of it (`responseSentToClient`) | `true`: it goes through `serverToProxyResponse` and `proxyToClientResponse`, so a filter can see it or turn it into a refusal |
| `serve_plain_http_after_connect` | `false`: with interception on, a `CONNECT` to a server that does not speak TLS is answered and relayed as it is (`ProxyToServerConnection.initializeConnectionFlow` after `shouldRetryWithoutSsl`); the client's bytes are only looked at for a TLS handshake (`checkAndPerformTlsDetection`) | `true`: plain HTTP after a `CONNECT` (a `ws://` WebSocket) is served as HTTP, through the filters |
| `proxy_protocol_destination` | `server_address`: `ProxyToServerConnection.SendProxyProtocolHeader` names the server connection's remote address as the destination, and no header is sent when the client and that address are of different address families | `local_address`: the address the client connected to, as HAProxy names it |
| `generated_responses` | `replaceable`: `ClientToProxyConnection.respondWithShortCircuitResponse`, which writes the proxy's error responses (`writeBadGateway`, `writeBadRequest`, `writeGatewayTimeout`) and filters' short-circuit responses, passes them through `proxyToClientResponse` and writes the response it returns. LittleProxy 1.x (`org.littleshoot:littleproxy` 1.1.2) wrote the response it was given, so a filter could only change it in place or drop it: forks descended from it want `in_place` | `replaceable` |
| `mitm_server_handshake` | `eager`: `ProxyToServerConnection.initializeConnectionFlow` runs the server's `EncryptChannel` step before `ClientToProxyConnection.RespondCONNECTSuccessful`, so that `MitmManager.clientSslEngineFor(HttpRequest, SSLSession)` gets the server's session; a server TLS failure goes through `ConnectionFlow.fail` and `ProxyToServerConnection.connectionFailed` to the next chained proxy, and the last one answers the `CONNECT` `502` (`writeBadGateway`) | `deferred`: the server's handshake waits for the client's ClientHello so it can mirror its ALPN and SNI; a failure fails over just the same, and the last one answers the session's first request `502` (see [Server TLS failures](guides/mitm.md#server-tls-failures)) |
| `tls_retry_without_sni` | `true`: `ProxyToServerConnection.connectionFailed` connects again without SNI after an `unrecognized_name` handshake failure (see [TLS to servers](#tls-to-servers)) | `false` |
| `request_head_timeout` | no setting of its own: the idle timeout's `IdleStateHandler` comes after the `HttpRequestDecoder` in `ClientToProxyConnection.initChannelPipeline`, so it sees only whole messages, and a request head still arriving when the idle timeout passes is closed, however steadily its bytes come | 30 seconds for an HTTP/1 request head, whatever the idle timeout; a timeout receives `408` and closes the connection, including under the LittleProxy preset |

With `filter_connect_answer` off, trackers and the hooks LittleProxy does not have
(`proxyToClientResponseSent`, `exchangeEnded`) still see the `CONNECT`'s answer. An HTTP chained
proxy's answer to the proxy's own `CONNECT`, which LittleProxy passes through
`serverToProxyResponse`, reaches no filter in MicroProxy either way.

LittleProxy's `407` challenge (`writeAuthenticationRequired`) reaches no filter, and MicroProxy's
reaches none either, whatever the policy. A filter written against a fork that kept LittleProxy
1.x's in-place semantics wants the preset with that one field changed:

```java
MicroProxy.bootstrap()
        .onHttp1(p -> p.preset(ProtocolPolicy.littleProxy())
                       .generatedResponses(GeneratedResponses.IN_PLACE))
        .start();
```

`withLittleProxyCompatibility()` used to change these fields for every client protocol; it now
changes HTTP/1's defaults only, and HTTP/2 and HTTP/3 clients keep MicroProxy's unless their own
policies say otherwise. Fields set explicitly for every protocol, such as
`withTlsRetryWithoutSni(false)`, still win over it.

Security fixes (strict request parsing, error pages that do not echo the request) are not
affected by any policy, and the following differences remain either way:

- HTTP/2 is on by default, and LittleProxy never spoke it: a client that offers `h2` on
  intercepted TLS (or the proxy's TLS listener) now gets HTTP/2, and so does a server that picks
  `h2` when the proxy reaches it over TLS. Filters see each HTTP/2 stream as an exchange of its
  own, with version `HTTP/2.0`, and the streams of one client connection run concurrently, so
  filter and tracker callbacks for that connection may too (see
  [HTTP/2](guides/http2.md#http2-to-clients)). Clients and servers that offer only HTTP/1.1 are
  unaffected. `--no-http2` and `--no-http2-upstream` (`http2=false`, `http2_upstream=false`,
  `withHttp2(false)`, `withHttp2Upstream(false)`) keep HTTP/1.1 on both sides, as in LittleProxy;
  compatibility mode leaves HTTP/2 as configured.
- Chained proxy retries: LittleProxy 2.9.1 tries the next chained proxy as soon as one fails,
  without waiting, and so does MicroProxy by default (`RetryBackoff.none()`); compatibility mode
  leaves the backoff as configured. Forks of LittleProxy that added a wait between attempts
  doubled it without jitter; `withChainedProxyRetryBackoff(RetryBackoff.exponential(initial,
  max))` (`chained_proxy_backoff_jitter=false`, `--chained-proxy-backoff-deterministic`) waits the
  same exact times, while the `withChainedProxyRetryBackoff(initial, max)` shorthand and
  `--chained-proxy-backoff` add full jitter (see
  [Retries and backoff](guides/chained-proxies.md#retries-and-backoff)). MicroProxy also caps the
  waits of one request at the connect timeout (at most 30 s) by default, where those forks waited
  every time; `RetryBackoff.exponential(initial, max).unbudgeted()`
  (`chained_proxy_backoff_budget_ms=unlimited`) lifts the cap, and `withBudget(Duration)` sets
  another. Compatibility mode leaves the budget alone too, since LittleProxy itself never waits.
  A filter can choose the backoff per request with `chainedProxyRetryBackoff()`.
- TLS handshakes are bounded by `withTlsHandshakeTimeout` (10 s by default, the same as Netty's
  `SslHandler` default that LittleProxy left in place); a filter can change it per request for the
  upstream handshakes with `proxyToServerTlsHandshakeTimeout()`.
- The proxy does not fill `FlowContext`'s string-keyed timing map (LittleProxy's
  `dns_resolution_*_time_ms`); `FlowContext.timings()` has typed timings for every phase instead
  (see [Observability](observability/activity-tracking.md#observability)).
- Full messages are written with a `Content-Length` that matches their actual body. Filters that
  replace a body don't need to fix the header themselves.
- `ProxyAuthenticator` and `MitmManager` keep LittleProxy's methods. The overloads that take the
  request or a `FlowContext` are optional additions: other authentication schemes and challenges,
  per-request checks, and MITM decisions per user or client (see
  [Proxy authentication](guides/authentication.md) and
  [Interception per client connection](guides/mitm.md#interception-per-client-connection)).
- With an authenticator configured, `Proxy-Authorization` is removed from every request before
  filters run, not only from the one that authenticated the connection.
- All interface methods have defaults, so the `*Adapter` classes are only conveniences.
- The listener is on loopback only unless `--server` (`allow_local_only=false`,
  `withAllowLocalOnly(false)`) is given; LittleProxy's `allow_local_only` defaults to `false`.
- When the shared server connection pool is full, a request waits up to the connect timeout for a
  connection, then gets `503`; LittleProxy returned `502` immediately.
- A request with both `Transfer-Encoding` and `Content-Length` gets `400`, as from LittleProxy
  2.9 (Netty rejects it); some LittleProxy forks accepted it. `--allow-chunked-length`
  (`allow_chunked_length`, `withAllowChunkedLength(true)`) accepts it as RFC 9112 allows, and closes
  the connection after the response; compatibility mode leaves it off (see
  [Security](security.md#request-parsing)).
- PROXY protocol headers can be optional (`--proxy-protocol-mode optional`), for a listener that
  load balancers and clients both reach; LittleProxy only requires them. Read the warning in
  [PROXY protocol](guides/forward-proxy.md#proxy-protocol) first.
- The `org.microproxy.http` message types are a sealed hierarchy. Filters create (and may subclass)
  the `Default*` classes but cannot implement `HttpRequest` and the other interfaces from scratch,
  and a `switch` over them can be exhaustive (see `HttpObject`).

## Not ported

Not ported, because they only exist to manage Netty:

- `ThreadPoolConfiguration` and `ServerGroup`: virtual threads replace event-loop sizing.
- `connectionSaturated` / `connectionWritable` tracker events: blocking writes are the backpressure.
- `proxyToServerConnectionQueued`.
