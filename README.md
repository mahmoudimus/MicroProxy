# MicroProxy

[![CI](https://github.com/mahmoudimus/MicroProxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mahmoudimus/MicroProxy/actions/workflows/ci.yml)
[![Release](https://github.com/mahmoudimus/MicroProxy/actions/workflows/release.yml/badge.svg)](https://github.com/mahmoudimus/MicroProxy/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/mahmoudimus/MicroProxy?include_prereleases&sort=semver)](https://github.com/mahmoudimus/MicroProxy/releases)
[![Java 21+](https://img.shields.io/badge/Java-21%2B-blue)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/github/license/mahmoudimus/MicroProxy)](LICENSE)

MicroProxy is an HTTP/HTTPS proxy for Java that can intercept and rewrite traffic. It is a
port of [LittleProxy](https://github.com/LittleProxy/LittleProxy) that drops Netty. Each
connection runs on its own **virtual thread** (Project Loom) and uses plain blocking socket I/O.

- **Runtime:** JDK 21 or newer (also tested on JDK 25).
- **Dependencies:** none at runtime. Logging goes through `System.Logger`, which can be routed to
  SLF4J/Log4j with the usual bridges. Put the `zstd-decoder` jar on the class path as well to
  decode `zstd` bodies, and the `http2-codec` jar for [HTTP/2](#http2) to clients and servers.
- **Size:** about 10k lines of main code (including Javadoc and a DNSSEC resolver) plus a vendored
  Brotli decoder, compared with LittleProxy's 11k lines plus Netty and dnssec4j.
- **Scripting (optional):** the `microproxy-starlark` module drives the proxy from a
  [Starlark](https://github.com/bazelbuild/starlark) script (see [Scripting](#scripting-with-starlark)).

| Module | Artifact | Contents |
|---|---|---|
| `zstd-decoder/` | `io.github.mahmoudimus:zstd-decoder` | a standalone pure-Java Zstandard decoder ([README](zstd-decoder/README.md)) |
| `http2-codec/` | `io.github.mahmoudimus:http2-codec` | a standalone HTTP/2 frame codec and HPACK implementation ([README](http2-codec/README.md)) |
| `microproxy/` | `io.github.mahmoudimus:microproxy` | the proxy; no required dependencies (`zstd-decoder` and `http2-codec` are optional) |
| `microproxy-starlark/` | `io.github.mahmoudimus:microproxy-starlark` | Starlark scripting; depends on the core and Guava |

```java
HttpProxyServer proxy = MicroProxy.bootstrap()
        .withPort(8080)
        .withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFiltersAdapter(originalRequest, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                        if (httpObject instanceof HttpRequest r && r.uri().contains("/blocked")) {
                            return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                                    HttpResponseStatus.FORBIDDEN, "blocked by proxy");
                        }
                        return null; // continue proxying
                    }
                };
            }
        })
        .start();
```

## Why virtual threads instead of Netty

LittleProxy relies on Netty's event loops, so all of its logic runs as callbacks: pipelines,
handler swapping, a `ConnectionFlow` state machine, and manual backpressure through
`channelWritabilityChanged`. MicroProxy writes the same logic as a straight-line loop:

```
read request → filters → connect (or reuse) → write request → stream body → read response → stream back
```

Each connection gets one cheap virtual thread, so blocking calls only park that thread. A slow
peer applies backpressure simply by blocking a write. The CONNECT tunnel is two loops copying
bytes, one per direction. Tens of thousands of concurrent connections are fine.

Bodies that no filter inspects skip the message objects entirely. They are copied between the
sockets through one reusable 64 KiB buffer per connection, re-framed only when one side uses
chunked coding, and flushed only when no more input is buffered. A filter that overrides a
content hook (`clientToProxyRequest` / `proxyToServerRequest` for requests,
`serverToProxyResponse` / `proxyToClientResponse` for responses), checked through chains as
well, gets every piece as before. On loopback with a 256 MiB body this relays about 1.2 GB/s
with `Content-Length` and 0.6 GB/s chunked, against 0.47 and 0.25 GB/s through per-chunk
objects, and allocates under 3 MB instead of about 270 MB.

Idle connections hold almost no memory. Socket buffers are lent from a bounded per-server
pool only while bytes are moving. Between requests, a connection waits for the next byte without
a buffer, and tunnels give theirs back whenever the peer goes quiet. With 2,000 idle keep-alive
connections, each client and server connection pair costs about 11 KiB of heap, down from 141
KiB. An idle `CONNECT` tunnel costs about 15 KiB, down from 113 KiB.

Per request, header handling avoids throwaway objects:

- Heads are written straight into the pooled buffer.
- Header lines are parsed into one string each, and then a single name and value.
- List-valued fields are checked in place, and URIs are checked without regular expressions.
- The `Date` value is formatted once per second.
- The request copy that the filters API hands to filters is made only when filters are configured.

A small keep-alive GET through the proxy now allocates about 4.7 KB, down from 12.1 KB, at
10-20% higher throughput. Both figures include the benchmark client's own allocations.

A few rules keep this safe on JDK 21, where a virtual thread that blocks inside `synchronized`
pins its carrier thread:

- Blocking code paths use `ReentrantLock` instead of `synchronized`.
- The tests run with `-Djdk.tracePinnedThreads=short` to catch pinning.
- On JDK 24+ (JEP 491), `synchronized` no longer pins, so user filters written with
  `synchronized` are fine there too.

## Running

<!-- x-release-please-start-version -->
```bash
mvn package
java -jar microproxy/target/microproxy-0.1.0 --port 8080
java -jar microproxy/target/microproxy-0.1.0 --port 8080 --mitm   # intercept HTTPS
java -jar microproxy/target/microproxy-0.1.0 --port 8080 --dnssec --activity-log-format clf
java -jar microproxy/target/microproxy-0.1.0 --port 8080 --mitm --log-http headers   # dump traffic
java -jar microproxy/target/microproxy-0.1.0 --help

# With zstd decoding:
java -cp microproxy/target/microproxy-0.1.0:\
zstd-decoder/target/zstd-decoder-0.1.0 org.microproxy.Launcher --port 8080

# With HTTP/2 to clients on intercepted TLS and to servers (needs the http2-codec jar):
java -cp microproxy/target/microproxy-0.1.0:\
http2-codec/target/http2-codec-0.1.0 org.microproxy.Launcher --port 8080 --mitm --http2 --http2-upstream

# The same launcher with scripting, zstd and HTTP/2 built in (one self-contained jar):
java -jar microproxy-starlark/target/microproxy-starlark-0.1.0-all.jar --port 8080 --script proxy.star
java -jar microproxy-starlark/target/microproxy-starlark-0.1.0-all.jar --port 8080 --mitm --http2
```
<!-- x-release-please-end -->

`--mitm` creates (or reuses) a CA in `microproxy-ca.p12` and writes its certificate to
`microproxy-ca.pem`. To intercept HTTPS without errors, add that certificate to your client's
trust store.

### SIMD (optional)

A few byte loops can use the JDK's Vector API: WebSocket payload unmasking and the line scanning
in the HTTP parser. The API is still an incubating module (JDK 21 through 26), so it is off unless
you ask for it:

```bash
java --add-modules jdk.incubator.vector -jar microproxy.jar ...   # prints "SIMD: vector 512-bit"
```

The JVM then warns that it is using an incubator module. `-Dmicroproxy.simd=false` turns SIMD off
again, and `-Dmicroproxy.simd=true` warns if the module is missing. Without the module, the
scalar code runs, and it now works eight bytes at a time.

Measured on a 4-core AVX-512 machine:

| | before | scalar | vector |
|---|---|---|---|
| unmask a 1 KiB WebSocket payload | 1.0 GB/s | 5.9 GB/s | 41.7 GB/s |
| unmask a 64 KiB payload | 1.3 GB/s | 5.7 GB/s | 35.5 GB/s |
| find the end of a 400-byte header line | — | 7.1 GB/s | 25.8 GB/s |

Inputs shorter than two vectors (128 bytes with AVX-512) use the scalar code, which is faster
there. The build runs the parser, WebSocket and SIMD tests a second time with the module, so
both paths are tested.

### Value classes (Project Valhalla, experimental)

Value classes (JEP 401) are a preview feature of JDK 28. Preview class files run only on that
exact JDK, with `--enable-preview`, so they cannot ship in a JDK 21 jar. Instead, a build profile
turns the small immutable records marked `// @value-candidate` into value classes:
`HttpVersion`, `HttpResponseStatus`, `HostAndPort`, `Framing`, the DNS record types, cache and
pool records, and so on (19 in all).

<!-- x-release-please-start-version -->
```bash
# JAVA_HOME = a JDK 28 early-access build (https://jdk.java.net/28/)
mvn -Pvalhalla -pl zstd-decoder,microproxy verify     # all tests pass with value classes
java --enable-preview -cp microproxy/target/microproxy-0.1.0-valhalla.jar org.microproxy.Launcher
```
<!-- x-release-please-end -->

Measured on JDK 28 EA (build 18), with identical code apart from the `value` modifier:

| | identity records | value records |
|---|---|---|
| allocation per small keep-alive request (before the header work above) | 10,224 bytes | 10,135 bytes |
| throughput, 16 clients | ~36,500 req/s | ~34,700 req/s (within noise) |
| heap per idle connection pair | 10.3 KiB | 11.8 KiB (within noise) |

The difference is under 1%. These records are short-lived, and escape analysis already
removes most of them. Allocation per request is mostly strings and arrays from header
handling, which value classes do not change. The profile stays useful for tracking Valhalla
as it matures (null-restricted types and flattened arrays would matter for header storage),
but it is not worth running in production today.

### Properties file

Pass a properties file with `--config file.properties` or `MicroProxy.bootstrapFromFile(path)`.
Command-line flags override values from the file.

| key | meaning | default |
|---|---|---|
| `name` | thread / log name | `MicroProxy` |
| `port` / `address` | listen port / `host:port` | `8080` |
| `allow_local_only` | listen on loopback only | `true` |
| `transparent` | don't add `Via` or strip hop-by-hop headers | `false` |
| `idle_connection_timeout` | seconds, 0 = none | `70` |
| `connect_timeout` | milliseconds; filters can shorten it per request (`proxyToServerConnectTimeout`) | `40000` |
| `littleproxy_compatibility` | behave like LittleProxy where MicroProxy differs | `false` |
| `tls_handshake_timeout` | milliseconds for a whole TLS handshake, with clients or servers (`0` = none) | `10000` |
| `tls_protocols` | TLS versions allowed on every TLS connection the proxy makes (empty = each context's defaults; see [TLS protocol versions](#tls-protocol-versions)) | `TLSv1.3,TLSv1.2` |
| `max_initial_line_length` / `max_header_size` / `max_chunk_size` | parser limits in bytes | `8192` / `16384` / `16384` |
| `nic` | local address for outbound connections | any |
| `proxy_alias` | name in `Via` | host name |
| `allow_requests_to_origin_server` | accept origin-form requests | `false` |
| `allow_proxy_protocol` / `send_proxy_protocol` | PROXY protocol in / out | `false` |
| `throttle_read_bytes_per_second` / `throttle_write_bytes_per_second` | global server bandwidth | `0` (unlimited) |
| `use_shared_server_connection_pool` | share server connections between clients | `false` |
| `server_connection_pool_type` | pool implementation (`CONCURRENT_MAP`) | `CONCURRENT_MAP` |
| `max_connections_per_host` / `max_total_connections` | pool limits | `10` / `200` |
| `max_concurrent_per_client` | exchanges each client IP may run at once; more get `429` (see [Concurrency limiting](#concurrency-limiting)) | off |
| `pool_idle_timeout` | seconds before idle pooled connections close | none |
| `pool_shared_mitm_connections` / `pool_per_request_in_mitm` | pool intercepted TLS connections, per session / per request | `false` |
| `upstream_proxy` / `upstream_https_proxy` | chain to `http(s)://[user:pw@]host:port` or `socks4/5://...` (HTTPS / CONNECT may use a different upstream) | none |
| `no_proxy` | hosts reached directly, curl `NO_PROXY` syntax | none |
| `use_env_proxy` | take upstreams from `http_proxy` / `https_proxy` / `all_proxy` / `no_proxy` | `false` |
| `upstream_fallback_to_direct` | connect directly if the upstream is unreachable | `false` |
| `chained_proxy_backoff_initial_ms` / `chained_proxy_backoff_max_ms` | wait between failed chained proxy attempts, doubling from the initial value up to the maximum, with full jitter (see [Retries and backoff](#retries-and-backoff)) | off / 8 × initial |
| `strip_tracing_headers` | remove `traceparent`, `tracestate`, `baggage`, B3 and other tracing headers from requests sent upstream (see [Removing tracing headers](#removing-tracing-headers)) | `false` |
| `strip_request_headers` | comma-separated request headers to remove as well | none |
| `strip_alt_svc_h3` | remove `h3` (HTTP/3) alternatives from `Alt-Svc` response headers (see [HTTP/3 and QUIC](#http3-and-quic)) | `true` with interception or `transparent`, else `false` |
| `http2` | serve HTTP/2 to clients on intercepted TLS and the proxy TLS listener (needs the `http2-codec` jar; see [HTTP/2](#http2)) | `false` |
| `http2_upstream` | speak HTTP/2 to servers that negotiate `h2` on TLS, sharing connections between exchanges (see [HTTP/2 to servers](#http2-to-servers)) | `false` |
| `http2_cleartext` | serve HTTP/2 with prior knowledge (`h2c`) on the plain listener (see [h2c](#h2c-with-prior-knowledge)) | `false` |
| `http2_max_concurrent_streams` | streams an HTTP/2 client may have open at once | `100` |
| `http2_initial_window_size` / `http2_connection_window_size` | request bytes buffered per HTTP/2 stream / per connection | `262144` / `1048576` |
| `dnssec` | resolve server names with DNSSEC validation | `false` |
| `dnssec_resolver` | DoH URL or comma-separated resolver IPs for `dnssec` | `/etc/resolv.conf` |
| `activity_log_format` | access log: `CLF`, `ELF`, `JSON`, `JSON_EXTENDED`, `SQUID`, `W3C`, `LTSV`, `CSV`, `HAPROXY` | off |
| `log_http` | log whole requests and responses: `basic`, `headers` or `body` (see [Request/response logging](#requestresponse-logging)) | off |
| `log_http_format` | `text` or `json` (one object per line) for `log_http` | `text` |
| `cache_dir` / `cache_max_mb` | cache responses on disk (see [HTTP cache](#http-cache)) / its size | off / `1024` |
| `cache_memory_mb` | cache responses in memory instead | off |
| `cache_max_entry_mb` | largest response body cached | `8` |
| `offline` | answer only from the cache | `false` |

## Features

| | |
|---|---|
| HTTP/1.0 and 1.1 proxying | keep-alive on both sides, pipelining, chunked bodies and trailers, `Expect: 100-continue` (a `100` is sent for servers that ignore it), 1xx pass-through, re-chunking of close-delimited responses, de-chunking for HTTP/1.0 clients, stale keep-alive retry |
| HTTP/2 to clients | optional (`--http2`): clients that negotiate `h2` on intercepted TLS or the proxy TLS listener get HTTP/2, each stream an exchange of its own with the same filters, cache, failure answers and logging; hardened against stream, reset and frame floods (see below). `--http2-cleartext` adds `h2c` with prior knowledge on the plain listener |
| HTTP/2 to servers | optional (`--http2-upstream`): servers that negotiate `h2` get every exchange for them as a stream on a shared connection, within their stream limit; trailers end to end and bidirectional streaming, so gRPC works through the proxy |
| Filters | `HttpFilters` / `HttpFiltersSource` with the same hooks as LittleProxy, streaming or buffered (`getMaximumRequestBufferSizeInBytes` / `getMaximumResponseBufferSizeInBytes`); several sources run in order as an `HttpFiltersChain` (`plusFiltersSource`) |
| CONNECT | byte tunnel with idle timeout and half-close |
| MITM | `MitmManager`; `CertificateAuthorityMitmManager` issues per-host certificates on demand (EC P-256). Its SANs copy the real server's DNS names. Only the JDK is used, through a small built-in X.509/DER encoder (`org.microproxy.tls.CertificateBuilder`). CA, upstream trust and client certificate can be chosen per client connection (see below) |
| Chained proxies | HTTP (with Basic credentials, optionally over TLS), SOCKS4a, SOCKS5 (with username/password); falls back to the next proxy or a direct connection, optionally with exponential backoff between attempts. `UpstreamProxyManager` configures them from proxy URLs, `NO_PROXY` rules or the environment |
| HTTP cache | RFC 9111 shared cache in memory or on disk, with revalidation, `Vary`, stale responses when servers are unreachable, and an offline mode (see below) |
| WARC recording | `WarcRecorder` archives traffic with servers as WARC 1.1 files for replay tools (see below) |
| Body rewriting | `HttpBodies` decodes gzip, deflate, Brotli and (with `zstd-decoder`) zstd bodies and re-encodes them with the right charset; `RewriteRules` edits headers and text bodies declaratively, buffering only the responses it rewrites |
| Scripting | optional module: `on_request` / `on_response` / `upstream` / `allow_mitm` / `on_failure` / `authenticate` hooks in Starlark, sandboxed, with hot reload (see below) |
| Proxy authentication | `ProxyAuthenticator`: Basic by default, or any scheme (Bearer tokens, API keys) with custom challenges; per connection or per request (see below) |
| TLS listener | `withSslContextSource(...)`, optional client-certificate auth |
| TLS protocol pinning | every TLS connection (listener, both sides of interception, TLS chained proxies) allows only TLS 1.3 and 1.2 by default; `withTlsProtocols(...)` changes it (see below) |
| PROXY protocol | accept v1 and v2 (read before TLS on a TLS listener), send v1 to the final server: first on a direct connection, through the tunnel after an HTTP chained proxy accepts the CONNECT; not sent through SOCKS chained proxies or with plain requests to an HTTP chained proxy |
| WebSockets | HTTP/1 `Upgrade` and HTTP/2 extended `CONNECT` (RFC 8441), with the same frame observation and rewriting hooks in both directions (see below) |
| Shared connection pool | optional server connection reuse across clients, with limits and idle eviction (see below) |
| DNSSEC | optional validating resolver, with no dependencies (see below) |
| Access logs | `ActivityLogger` in nine formats, one with per-phase timings |
| Request/response logging | `HttpLogger` dumps whole messages (heads, the changes the proxy and filters made, bodies on request) as readable blocks or JSON lines, with redaction (see below) |
| Throttling | global token bucket for server reads and writes, adjustable at runtime |
| Concurrency limiting | `ConcurrencyLimiter` caps the exchanges in progress per client, user, target host or any key, with a bounded wait queue, `429` answers, a shadow mode and metrics (see below) |
| Activity tracking | `ActivityTracker` for connections, requests, responses (with their source), bytes, per-exchange timings and server failures (see below) |
| HTTP/3 bypass | removes `h3` alternatives from `Alt-Svc` by default when intercepting or transparent, so clients stay on TCP through the proxy rather than move to QUIC (see below) |
| Privacy | optionally removes distributed tracing headers (W3C Trace Context and Baggage, B3 and other common trace headers) and any other named headers from requests sent upstream, after all filters (see below) |
| Hardening | rejects `Transfer-Encoding` + `Content-Length`, conflicting lengths, obs-fold in requests, and oversized lines and headers; header values are validated against CR/LF injection; Host is replaced by the absolute-form authority |

### Filters from lambdas

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

Other hooks: `onRequestBody`, `onResponseBody`, `beforeResponding`, `onFailure`, `resolveWith`,
`allowMitm`, `connectTimeout`, `bufferRequests` and `bufferResponses`. Registering a hook twice runs both in order.
`log(httpLogger)` logs each exchange around the lambdas (see [Request/response
logging](#requestresponse-logging)), whether a lambda source returns the built filters, as above,
or they are the source themselves: they are also an `HttpFiltersSource` that returns them for every
request, so `withFiltersSource(filters)` works as well.

**Per-request connect timeout:** `HttpFilters.proxyToServerConnectTimeout()` (or `connectTimeout(Duration)`
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

### Failure responses

When the proxy has to answer a request itself, it sends a short plain-text body (`Bad Gateway`,
`Gateway Timeout`, ...) that never echoes the request. The cause is a sealed `ProxyFailure`:

| `ProxyFailure` | when | default |
|---|---|---|
| `UnresolvedHost` | the server's name did not resolve | `502` |
| `ConnectFailed` | connection refused, unreachable or timed out; a chained proxy refused, or its own name did not resolve | `502` |
| `TlsFailed` | the TLS handshake with the server (MITM) or a TLS chained proxy failed or timed out | `502` |
| `ServerTimeout` | no response within the idle timeout | `504` |
| `BadServerResponse` | malformed response, or the server closed or failed before the head was complete | `502` |
| `NoRoute` | the request names no host, or the chained proxy manager offered no route | `502` |
| `NoConnectionAvailable` | the shared connection pool had no connection to spare | `503` |
| `BadRequest` | an origin-form request (unless allowed) or an invalid `CONNECT` target | `400` |
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

Starlark scripts answer through `on_failure` (see [Scripting with Starlark](#scripting-with-starlark)).
The proxy frames whatever is returned (`Content-Length`, keep-alive, no body for `HEAD`), and it
passes `proxyToClientResponse` like the default answers. A responder that throws is logged and the
default is sent. Requests the proxy cannot parse at all are answered with a plain `4xx` without
asking anyone. `HttpCache` uses the filter hook to serve stale entries when servers are
unreachable.

### Upstream proxies and NO_PROXY

`UpstreamProxyManager` is a `ChainedProxyManager` configured the way command-line clients are:

- **Upstreams:** one proxy URL for plain HTTP and optionally another for HTTPS/CONNECT:
  `http://user:pw@proxy:3128`, `https://...` (TLS to the proxy), `socks4://`, `socks5://`.
- **Bypass:** `NoProxyRules` takes curl's `NO_PROXY` syntax: `*`, domain suffixes
  (`example.com`, `.example.com`, `*.example.com`), IP literals, CIDR ranges and `:port`
  qualifiers. Addresses are only compared when the request names an IP literal, so no DNS
  lookups happen.
- **Environment:** `UpstreamProxyManager.fromEnvironment(System.getenv())`, `--env-proxy` or
  `use_env_proxy=true` read `http_proxy`, `https_proxy`, `all_proxy` and `no_proxy` like curl
  does. Upper-case `HTTP_PROXY` is ignored, as curl ignores it, because CGI servers set it from a
  request header.

```bash
java -jar microproxy.jar --upstream-proxy http://proxy.corp:3128 --no-proxy "localhost,.corp,10.0.0.0/8"
```

For servers or proxies signed by a private CA, `SslContexts.systemDefaultPlus(caCert)` trusts the
JDK's roots plus extra anchors and keeps host-name checks. Use it as the MITM manager's upstream
context, or as a chained proxy's.

#### Retries and backoff

When a connection through one chained proxy fails (refused, timed out, its name does not resolve,
its TLS handshake or `CONNECT` fails), the proxy tries the next candidate the
`ChainedProxyManager` offered, which may be a direct connection. By default it moves on at once.
`withChainedProxyRetryBackoff(initial, max)` (or `chained_proxy_backoff_initial_ms` and
`chained_proxy_backoff_max_ms`, or `--chained-proxy-backoff <initial-ms>[:<max-ms>]`) waits in
between, so a flapping upstream is not hammered:

```java
MicroProxy.bootstrap()
        .withChainProxyManager(upstreams)
        .withChainedProxyRetryBackoff(Duration.ofMillis(100), Duration.ofSeconds(2))
        .start();
```

```bash
java -jar microproxy.jar --upstream-proxy http://proxy.corp:3128 --chained-proxy-backoff 100:2000
java -jar microproxy.jar --config proxy.properties --chained-proxy-backoff 0   # turn off the file's backoff
```

Without a maximum, the property and the flag cap the wait at 8 × the initial one; `0` on the
command line turns waiting off, overriding a properties file.

- Before attempt `n + 1` it waits a random time between zero and `initial * 2^(n-1)`, capped at
  `max` ("full jitter", so clients that failed together do not retry together).
- It never waits before the first attempt or after the last one.
- It stops waiting, and gives up on the request, if the client disconnects meanwhile. Once the
  client has sent more bytes (a request body, a pipelined request) a disconnect can no longer be
  seen, and the rest of the wait is a plain sleep.
- The waits of one request add up to at most 30 seconds or the connect timeout, whichever is
  less, so a long candidate list cannot hold a request for minutes. Once that budget is spent,
  the remaining candidates are tried without waiting.
- The waiting counts towards the connect phase of `FlowContext.timings()`; it fires no callbacks,
  only a `DEBUG` log line.

### Proxy authentication

`withProxyAuthenticator` makes clients authenticate. A `ProxyAuthenticator` that only implements
`authenticate(user, password)` checks `Proxy-Authorization: Basic` and answers failures with
`407` and `Proxy-Authenticate: Basic realm="..."` (`getRealm()`). For other schemes, override
`authenticate(HttpRequest, FlowContext)`, which sees the whole request and the client connection
and returns an `AuthResult`:

- `AuthResult.accept(user)`: the request proceeds, and `user` (which may be `null`) becomes
  `ClientDetails.getUserName()` for filters, trackers, access logs, the `ChainedProxyManager`,
  MITM decisions and Starlark's `ctx.user`.
- `AuthResult.reject(response)`: the client gets `response`, for instance a `407` with your own
  `Proxy-Authenticate` header and body, or a `403`. `AuthResult.reject()` sends the default
  Basic `407`.

```java
MicroProxy.bootstrap()
        .withProxyAuthenticator(new ProxyAuthenticator() {
            @Override
            public AuthResult authenticate(HttpRequest request, FlowContext flow) {
                String value = request.headers().get(HttpHeaderNames.PROXY_AUTHORIZATION);
                if (value != null && value.startsWith("Bearer ")) {
                    String user = tokens.userFor(value.substring(7));   // your token check
                    if (user != null) return AuthResult.accept(user);
                }
                FullHttpResponse challenge = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                        HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED, "{\"error\":\"invalid_token\"}");
                challenge.headers().set(HttpHeaderNames.PROXY_AUTHENTICATE, "Bearer realm=\"proxy\"");
                return AuthResult.reject(challenge);
            }

            @Override
            public boolean authenticate(String userName, String password) {
                return false;   // no Basic credentials
            }

            @Override
            public boolean authenticateEveryRequest() {
                return true;    // tokens expire
            }
        })
        .start();
```

- **Once per connection:** by default the first accepted request authenticates its client
  connection, and later requests on it are not checked. `authenticateEveryRequest()` checks every
  request instead. When the accepted user changes on a connection, the server connections made
  for the previous user are given up, so routing is decided again.
- **CONNECT and interception:** a `CONNECT` is authenticated like any request. The requests inside
  an intercepted session carry no proxy credentials and are covered by their `CONNECT`, even with
  `authenticateEveryRequest()`.
- **Credentials stay here:** whatever the scheme, `Proxy-Authorization` is removed from every
  request before filters see it, so it is never forwarded, even by a transparent proxy.
- To accept Basic as well, fall back to `ProxyAuthenticator.super.authenticate(request, flow)`.
- A Starlark script can be the authenticator, with an `authenticate` hook (see
  [Scripting with Starlark](#scripting-with-starlark)).

### Concurrency limiting

`org.microproxy.extras.ConcurrencyLimiter` is a filters source that caps how many exchanges run at
once per key. Requests over the limit wait in a bounded queue, or are answered with `429 Too Many
Requests` (plain text, `Retry-After: 1` by default):

```java
ConcurrencyLimiter limiter = ConcurrencyLimiter.builder()
        .key(ConcurrencyLimiter.byUser())              // default: byClientIp(); also byTargetHost()
        .permits(8)                                     // per key
        .permits(user -> user.equals("batch") ? 32 : null)   // null: the default
        .queue(16, Duration.ofSeconds(2))               // default: refuse at once
        .onReject((key, request, flow) -> metrics.increment("limited", key))
        .build();
MicroProxy.bootstrap().withFiltersSource(HttpFiltersChain.of(limiter, myFilters)).start();
```

- **Key:** any `(request, flow) -> String`, for example `flow.getClientDetails().getUserName()` or
  the target host; a `null` key leaves the request unlimited.
- **When a permit is held:** it is taken in `clientToProxyRequest`, which runs after proxy
  authentication (requests answered with `407` are never counted), and released exactly once in
  `HttpFilters.exchangeEnded`: after the response is written, or when the exchange was abandoned
  (client gone, server failure, a filter's answer or abort, the proxy stopping). Put the limiter
  first among the filters so the others do no work for refused requests.
- **Tunnels:** a `CONNECT` tunnel and an upgraded (WebSocket) connection hold their permit until
  they close; `countTunnels(false)` stops counting `CONNECT`s and releases an upgrade's permit
  after its `101`. An intercepted `CONNECT` holds its permit only until interception starts, and
  the requests inside the session are counted one by one.
- **Safety net:** a permit held for longer than `permitTimeout` (10 minutes by default) is
  reclaimed and logged at `WARNING`; established tunnels are exempt.
- **Shadow mode:** `shadow(true)` counts and reports requests over the limit but lets them
  through, to try a limit out first.
- **Answers:** `retryAfter(Duration)` (or `null` for none) and `response((key, request, flow) ->
  ...)` replace the default `429`.
- **Metrics:** `snapshot()` returns the permits in use, waiting and refused per busy key, plus
  totals (granted, refused, reclaimed). A key is forgotten as soon as none of its permits are in
  use, so memory stays bounded by the exchanges in progress.

Waiting blocks only the client connection's virtual thread. The limiter reads request heads only,
so bodies keep the fast path. Lambda-built filters keep no state per exchange, so combine them
with a limiter in a chain rather than inside the builder. On the command line,
`--max-concurrent-per-client N` (or `max_concurrent_per_client=N`) installs one keyed by client IP.

### Removing tracing headers

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

### Interception per client connection

The proxy hands every `MitmManager` call the client connection's `FlowContext`, with its
authenticated user (`getClientDetails().getUserName()`) and address (`getClientAddress()`). Two
ways to use it:

- **One manager per tenant:** `MitmManager.perConnection(flow -> ...)` picks a manager when a
  connection is first intercepted and keeps it for that connection. Return the same instance for
  clients that may share server connections; `null` tunnels without interception.

  ```java
  Map<String, MitmManager> byTenant = Map.of(
          "alice", new CertificateAuthorityMitmManager(aliceCa, aliceUpstreamContext),
          "bob", new CertificateAuthorityMitmManager(bobCa, bobUpstreamContext));
  MicroProxy.bootstrap()
          .withProxyAuthenticator(authenticator)
          .withManInTheMiddle(MitmManager.perConnection(
                  flow -> byTenant.get(flow.getClientDetails().getUserName())))
          .start();
  ```

- **One manager deciding per call:** override the `FlowContext` overloads,
  `serverSslContext(host, port, flow)` (upstream trust store and client certificate; `flow` is a
  `FullFlowContext` naming the server and route), `clientSslContextFor(connect, session, flow)`
  (the certificate shown to the client) or `configureServerSocket(socket, flow)`. They default to
  the methods without `FlowContext`, so existing managers work unchanged.

An upstream context with a key (`SslContexts.withKey(key, chain, trustManagers)`) presents that
client certificate to servers that ask for one.

With `withPoolSharedMitmConnections(true)`, a pooled TLS connection carries the trust and client
certificate it was made with, so the pool keeps them apart. Connections made by a manager chosen
with `forConnection` (which `perConnection` uses) are pooled under that manager and only reused by
clients given the same one. A manager overriding `serverSslContext(host, port, flow)` or
`configureServerSocket(socket, flow)` may decide differently for every client, so its server
connections are not pooled: each client connection keeps its own. Overriding only
`clientSslContextFor(..., flow)` does not affect pooling.

### TLS protocol versions

Every TLS socket the proxy creates allows only `TLSv1.3` and `TLSv1.2` by default: the TLS
listener (`withSslContextSource`), both sides of an intercepted session (towards the client and
towards the server) and connections to TLS chained proxies. `withTlsProtocols(...)` (or
`tls_protocols=...`, `--tls-protocols ...`) changes the list:

```java
MicroProxy.bootstrap().withTlsProtocols("TLSv1.3").start();   // TLS 1.3 only
MicroProxy.bootstrap().withTlsProtocols().start();            // each SSLContext's own defaults
```

- **Per socket:** each socket enables the listed versions its `SSLContext` supports, in the order
  given. If it supports none of them, the handshake fails with an error naming both lists (a
  `TlsFailed` towards servers, a failed handshake towards clients).
- **Order:** the versions are set right after the socket is created, before
  `SslContextSource.configure`, `MitmManager.configureServerSocket` and `ChainedProxy.configure`
  run. A hook that sets its own protocols therefore wins.
- **The JDK still applies** `jdk.tls.disabledAlgorithms`, which turns off TLS 1.1 and older,
  whatever is listed here.
- A server that refuses the proxy's versions with a `protocol_version` alert gets a `502`
  (`TlsFailed`). One that just closes the connection on the proxy's `ClientHello` looks like a
  server that does not speak TLS, and the `CONNECT` is tunnelled without interception, as for
  any non-TLS server.

### HTTP/2

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

All three are off by default. They need the optional `http2-codec` module on the class path (see
[Running](#running); the `microproxy-starlark` `-all` jar bundles it). A proxy started with any of
them enabled but without the module fails at startup with an `IllegalStateException` that says
so; without them, nothing loads the module.

**Negotiation.** With HTTP/2 on, both intercepted TLS and the proxy's own TLS listener
(`withSslContextSource`) offer `h2` and
`http/1.1` through ALPN. A client that offers `h2` gets it. Any other client keeps HTTP/1.1 as
before: one that offers only `http/1.1`, one that offers protocols the proxy does not know, and
one that sends no ALPN at all (the handshake never fails over ALPN). The TLS log line for the
handshake shows the result (`alpn=h2`). The TLS listener retains its configured certificate,
client authentication and socket settings. Its HTTP/2 streams are forward-proxy requests, like
`h2c`, and authenticate separately when proxy authentication is configured.

**What a stream looks like to filters.**

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

**Concurrency.** The connection's thread reads frames; each stream runs on a virtual thread of its
own, so a slow stream never holds up the others. Towards HTTP/1.1 servers, which cannot multiplex,
each stream takes a server connection of its own; idle ones are reused by later streams of the
same client connection, and the `CONNECT`'s server connection serves the first stream. Because
streams run at the same time, `ActivityTracker` callbacks and filters for one client connection
may run concurrently, on the streams' threads.

#### HTTP/2 to servers

With `withHttp2Upstream(true)` (`--http2-upstream`, `http2_upstream=true`), the proxy's TLS
connections to servers, for intercepted HTTPS and secure WebSocket extended `CONNECT`, offer
`h2` and `http/1.1` through
ALPN (before `MitmManager.configureServerSocket`, which may change that). A server that picks `h2`
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
  client; shared ones after the idle timeout without streams.
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

#### Trailers and gRPC

Trailers go end to end: request trailers from HTTP/2 clients (and from HTTP/1 clients' chunked
bodies) reach HTTP/2 servers as a trailing HEADERS frame, and response trailers such as
`grpc-status` and `grpc-message` come back to HTTP/2 clients the same way, and to HTTP/1 clients
in the chunked body. When both the client and the server side of an exchange are HTTP/2 streams
and no filter looks at the request body's pieces, the request body is relayed on a thread of its
own while the response comes back, so bidirectional streaming works; otherwise a request body is
sent whole before the response is read, as with HTTP/1.1. So gRPC (`application/grpc`, `te:
trailers`, length-prefixed messages, unary and streaming calls, Trailers-Only error responses)
works through the intercepting proxy with `--mitm --http2 --http2-upstream`.

#### h2c with prior knowledge

With `withHttp2Cleartext(true)` (`--http2-cleartext`, `http2_cleartext=true`), a connection to the
plain listener whose first bytes are the HTTP/2 connection preface (`PRI * HTTP/2.0`, RFC 9113
section 3.4) is served as HTTP/2. The first bytes are compared without consuming anything, and an
HTTP/1 request is told apart by its first byte or two, so HTTP/1 clients are unaffected. Its
streams are proxy requests: `:scheme` and `:authority` name the target, so any authority is valid
(the `421` check applies only to intercepted sessions), and they reach servers as HTTP/1.1 (HTTP/2
to servers needs TLS; secure WebSocket extended `CONNECT` also establishes origin TLS).
`Upgrade: h2c` (deprecated by RFC 9113) is ignored, as
before: the request is answered in HTTP/1.1. The same limits as for intercepted HTTP/2 apply.

#### CONNECT and WebSockets

A normal HTTP/2 `CONNECT` (`:method CONNECT`, `:authority host:port`, no `:scheme` or `:path`)
opens a byte tunnel on that stream. The successful `200` HEADERS leave it open; DATA carry tunnel
bytes, and END_STREAM half-closes one direction. RST_STREAM closes the tunnel's origin connection
and wakes its waits, without closing the client HTTP/2 connection or other streams. These are raw
tunnels, including when a MITM manager is configured: TLS interception inside an HTTP/2 CONNECT
stream is not implemented. HTTP/1 CONNECT interception is unchanged.

The proxy advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`. A WebSocket client can open a stream
with `:method CONNECT`, `:protocol websocket`, `:scheme http` (ws) or `https` (wss), `:authority`
and `:path`. A successful response is `200`, without END_STREAM; WebSocket frames travel in DATA,
independently of DATA frame boundaries. HTTP/1 `Connection` and `Upgrade` fields remain forbidden
on the HTTP/2 wire. Other extended protocols get `501`.

WebSockets can use HTTP/1 or HTTP/2 independently on either side. With HTTP/2 to origins enabled,
a TLS origin that advertises extended CONNECT gets a WebSocket stream on the existing shared
HTTP/2 connection. An origin that does not advertise it gets a separate HTTP/1.1 upgrade connection.
The proxy translates `101` and `200` handshakes, and generates the HTTP/1 nonce/accept fields where
needed. For secure extended CONNECT on a forward-proxy connection, origin TLS uses the configured
MITM manager's server TLS settings, or the default JVM trust context when there is no manager.

Request filters see an extended WebSocket CONNECT as a GET upgrade request, with version
`HTTP/2.0`, its resource URI and generated HTTP/1 upgrade headers. Origin HTTP/2 WebSocket response
heads use `101` internally so the existing exchange and upgrade hooks run; the client's response
hook sees `200` for an HTTP/2 client, and `upstreamStatus` retains the origin's actual status.
`webSocketFrameReceived` and `filterWebSocketFrame` use the same parser and relay as HTTP/1,
including masking, rewriting, dropping, fragmentation and the large-frame buffer limit. Filters
that rewrite frames remove `Sec-WebSocket-Extensions` before the request reaches the origin.
A filter that rejects the handshake finishes the exchange without starting the relay.

**Remaining limits.** A request for an authority other than the intercepted one (including
CONNECT) gets `421 Misdirected Request`, which makes the client retry on a connection of its own.
The proxy does not originate TLS for ordinary absolute `https://` URLs sent in plain HTTP (or
ordinary `:scheme https` requests on a forward-proxy HTTP/2 connection); secure WebSocket extended
CONNECT is the exception described above. HTTP/2 chained proxies are not supported.

**Limits.** Input is untrusted; every limit has a default, and the configurable ones are set with
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

**Shutting down.** A graceful stop (`stop()`) sends `GOAWAY` to HTTP/2 clients, finishes the
streams already open (for up to the graceful stop timeout), and refuses new ones. An idle
connection is sent `GOAWAY` and closed. Connections to servers are sent `GOAWAY` and closed once
the client connections are done.

**Compatibility.** Nothing changes unless HTTP/2 is enabled, with two small exceptions in the
API: `FlowContext.equals` (and `hashCode`) now also compare the stream id, which is 0 for every
HTTP/1 context, so HTTP/1 behaviour is the same; and `HttpProxyServerBootstrap` gains
`withHttp2`, `withHttp2Upstream`, `withHttp2Cleartext`, `withHttp2Options` and `getHttp2Options`
as default methods, so other implementations still compile. Trackers and filters keyed by
`FlowContext` keep one entry per stream; state meant per client connection can be keyed by
`ctx.getConnectionContext()`.

#### Conformance (h2spec)

CI runs [h2spec](https://github.com/summerwind/h2spec) v2.6.0 in strict mode against the `h2c`
listener (`.github/scripts/h2spec.sh`, with `org.microproxy.H2specTarget` from the test sources:
the proxy with `h2c` on and a filter that answers every request with `200`). All 147 cases pass
except one, which CI leaves out:

- `http2/3.5/2` (*Sends invalid connection preface*): h2spec expects `GOAWAY` or a closed
  connection. The `h2c` listener is shared with HTTP/1, so a connection that does not start with
  the preface is an HTTP/1 connection, and gets an HTTP/1 error response before it is closed.

To run it locally, build the classes (`mvn -DskipTests test-compile -pl microproxy -am`) and run
`.github/scripts/h2spec.sh --strict` (it downloads h2spec, or uses `$H2SPEC`).

**What is next** ([issue #2](https://github.com/mahmoudimus/MicroProxy/issues/2)): HTTP/2 and
HTTP/3 frame editing for Starlark, followed by HTTP/3 transport integration.

### HTTP/3 and QUIC

MicroProxy speaks HTTP/1.x, and [HTTP/2](#http2) on intercepted TLS, the proxy TLS listener and
optional h2c; HTTP/3 transport is planned
in [issue #2](https://github.com/mahmoudimus/MicroProxy/issues/2). HTTP/3 runs over QUIC, on UDP,
and that matters even now. Browsers never send QUIC through an HTTP proxy, and a transparent
setup usually redirects only TCP. So a client that learns that an origin speaks HTTP/3 can
switch to it and bypass the proxy, and with it interception, filters and logging.

Clients learn about HTTP/3 in two ways:

- **From `Alt-Svc` response headers** such as `Alt-Svc: h3=":443"; ma=86400, h2=":443"`. The
  proxy removes the `h3` alternatives, including the draft versions (`h3-29`, `h3-Q050`, ...)
  and Google QUIC's `quic`. Other alternatives such as `h2=":443"` are kept with their
  parameters (`ma`, `persist`), a header left empty is removed, and `Alt-Svc: clear` is passed
  on. This is **on by default with interception (`--mitm`, `withManInTheMiddle`) or
  `--transparent`**, and off for a plain forward proxy. `--no-alt-svc-h3`,
  `withoutHttp3Advertisement()` or `strip_alt_svc_h3=true` turn it on, and `--keep-alt-svc-h3`,
  `withAltSvcH3Stripping(false)` or `strip_alt_svc_h3=false` turn it off. Filters see server
  responses unchanged in `serverToProxyResponse` and already stripped in
  `proxyToClientResponse`. Short-circuit responses (including cache answers) are stripped as
  they are sent.
- **From DNS `HTTPS` records**, which the proxy never sees. In transparent deployments,
  **block UDP port 443** (for example `iptables -A FORWARD -p udp --dport 443 -j REJECT`).
  Clients then fall back to TCP, which the proxy does see.

HTTP/2 can also announce alternatives in `ALTSVC` frames. The proxy never sends them, and drops
any that HTTP/2 servers send (as frames of a type it does not handle), so alternatives reach
HTTP/2 clients only as `Alt-Svc` headers, which are stripped the same way.

### Rewriting bodies

`org.microproxy.http.HttpBodies` handles the parts of body editing that are easy to get wrong:

- **Decoding:** gzip, x-gzip, deflate (zlib-wrapped or raw), `br` (Brotli, through a vendored
  copy of Google's pure-Java decoder) and, when `zstd-decoder` is on the class path, `zstd`.
  Decoding is capped at 64 MiB by default to defuse compression bombs. `canDecode` reports
  codings that can't be decoded, such as the dictionary codings `dcb` and `dcz`.
- **Negotiation:** `restrictAcceptEncoding(request)` trims a request's `Accept-Encoding` to the
  codings above (keeping q-values), so the server never picks one the proxy can't read.
  `RewriteRules` and scripts that define `on_response` do this automatically.
- **Charset:** taken from the *response's* `Content-Type`, defaulting to UTF-8.
- **Rewriting:** the original coding is re-applied, except that Brotli and zstd are re-encoded as
  gzip because there are no pure-Java encoders for them. `ETag`/`Content-MD5` are dropped because they no longer
  match. `Content-Length` is fixed when the message is written.

Filters can also ask to buffer one message at a time, after seeing its head:

- `HttpFilters.responseBufferSizeInBytes(response)`: a body larger than requested simply streams
  through.
- `HttpFilters.requestBufferSizeInBytes(request)`: a body larger than requested is answered with
  `413`, since part of it has already been read.

`org.microproxy.extras.RewriteRules` builds on both. It is a filters source with an ordered list
of rules. Each rule matches a URL regex (absolute form, `https://` inside intercepted sessions)
and edits request headers, response headers and textual response bodies:

```java
bootstrap.withFiltersSource(RewriteRules.builder()
        .add(RewriteRules.Rule.matching("https://example\\.com/.*")
                .replaceInBody("Example Domain", "Rewritten Domain")
                .removeResponseHeader("Content-Security-Policy"))
        .build());
```

Only matching text responses are buffered; everything else streams.

### HTTP cache

`org.microproxy.cache.HttpCache` is a shared cache following RFC 9111. Put it on disk to keep
cached pages across restarts and to browse them offline:

```bash
java -jar microproxy.jar --cache-dir ~/.microproxy-cache --cache-size 2048
java -jar microproxy.jar --cache-dir ~/.microproxy-cache --offline   # never contact servers
```

```java
HttpCache cache = HttpCache.builder()
        .store(new DiskCacheStore(Path.of("cache"), 2L << 30))   // or new MemoryCacheStore(bytes)
        .build();
MicroProxy.bootstrap().withHttpCache(cache).start();
```

What it does:

- **Storing:** complete `GET` responses up to 8 MiB that a shared cache may store. That excludes
  `no-store`, `private`, `Vary: *`, responses to requests with `Authorization` (unless
  `public`, `s-maxage` or `must-revalidate`), and responses setting cookies (unless `public`).
- **Freshness:** from `s-maxage`, `max-age`, `Expires`, or 10% of the time since
  `Last-Modified` (at most a day). Ages follow the RFC, including `Age` and the response delay.
  The request directives `max-age`, `min-fresh`, `max-stale`, `no-cache` (and `Pragma: no-cache`),
  `no-store` and `only-if-cached` are honoured.
- **Revalidation:** a stale entry with an `ETag` or `Last-Modified` is checked with a conditional
  request. A `304` refreshes the entry, and the client still gets the full response.
- **Variants:** `Vary` is matched on normalized request values, and a URL may have several
  variants. `HEAD` is answered from a stored `GET`.
- **Invalidation:** a successful `POST`, `PUT`, `DELETE`, etc. removes the URL, and same-origin
  `Location` / `Content-Location`.
- **When servers are unreachable:** a stale entry is served instead of the proxy's `502`/`504`,
  unless it is marked `must-revalidate`, `proxy-revalidate`, `no-cache` or `s-maxage`. A server's
  `5xx` is replaced only within `stale-if-error`.
  - With `--mitm`, intercepted HTTPS keeps working: a `CONNECT` to a dead server is still
    intercepted, through the `proxyToServerAllowOfflineMitm` filter hook, and the cache answers
    inside the session.
- **Offline mode:** everything is answered from the cache, whatever its age; anything else gets
  `504`.
- **Reporting:** responses carry `Cache-Status` (RFC 9211), e.g. `MicroProxy; hit; ttl=42` or
  `MicroProxy; fwd=stale; fwd-status=304`. `HttpCache.stats()` counts hits, misses, stores,
  revalidations and stale responses served.

The cache always runs after the other filters (`withFiltersSource`, `plusFiltersSource`, scripts).
So filters and scripts see a request before the cache can answer it, and the cache stores
responses after they have been rewritten.

Not implemented: `stale-while-revalidate`, `Range` requests (they bypass the cache) and caching
`POST` responses.

### WARC recording

`org.microproxy.warc.WarcRecorder` records what passes between the proxy and servers as WARC 1.1
files (ISO 28500), the format web archives use. Replay or inspect them with tools such as
[pywb](https://github.com/webrecorder/pywb) and [warcio](https://github.com/webrecorder/warcio).

```bash
java -jar microproxy.jar --mitm --warc-dir warcs      # browse; HTTPS is recorded too
warcio index warcs/*.warc.gz
```

```java
WarcRecorder recorder = WarcRecorder.builder(Path.of("warcs")).maxFileSize(1L << 30).build();
MicroProxy.bootstrap().withFiltersSource(recorder).start();
// ... recorder.close() finishes the current file.
```

What gets written:

- **Records:** each exchange becomes a `response` record and a `request` record, linked by
  `WARC-Concurrent-To`, with block and payload digests (`sha1:` base32), the target URI
  (`https://` inside intercepted sessions) and the server's IP address. Every file starts with a
  `warcinfo` record.
- **Files:** each record is its own gzip member, so readers can seek to any record. Files are
  named `microproxy-<timestamp>-<serial>.warc.gz`, carry an `.open` suffix while being written,
  and roll over at 1 GiB by default.
- **Bodies:** captured as they stream past, without buffering the exchange (large ones spill to a
  temporary file), up to 512 MiB per body. Beyond that the record says `WARC-Truncated: length`.
  Chunked transfer coding is removed and `Content-Length` gives the recorded length; content
  codings such as gzip are kept as received.
- **Not recorded:** responses from the cache or produced by filters, and `CONNECT` tunnels that
  are not intercepted.
- **Ordering:** put the recorder first among the filters, as `--warc-dir` does, to record
  messages before other filters change them.

The output is checked with `warcio check` (all digests pass) and indexed by `warcio index`.

### Scripting with Starlark

The optional `microproxy-starlark` module runs proxy logic written in
[Starlark](https://github.com/bazelbuild/starlark/blob/master/spec.md), the Python dialect Bazel
uses for configuration. Scripts are sandboxed: they have no file, network or process access,
cannot change global state after loading, and each hook call is limited in steps and wall-clock
time (10 million steps and 5 seconds by default). One loaded script is shared by every
connection.

```python
# proxy.star
BLOCKED = ["ads.example.com", "tracker.example.net"]

def on_request(req, ctx):
    if req.host in BLOCKED:
        return response(403, "blocked\n")
    req.headers["X-Client"] = ctx.client_ip
    ctx.vars["started"] = time.monotonic()

def on_response(req, res, ctx):
    res.headers["X-Elapsed-Ms"] = str(int((time.monotonic() - ctx.vars["started"]) * 1000))
    if res.text != None and "Example Domain" in res.text:
        res.text = res.text.replace("Example Domain", "Scripted Domain")

def upstream(req, ctx):
    if req.host.endswith(".onion"):
        return "socks5://127.0.0.1:9050"
    return None  # the default route (--upstream-proxy, or direct)

def allow_mitm(req, ctx):
    return not req.host.endswith(".bank.example")
```

<!-- x-release-please-start-version -->
```bash
java -jar microproxy-starlark/target/microproxy-starlark-0.1.0-all.jar --mitm --script proxy.star
```
<!-- x-release-please-end -->

Or from Java, install one `ScriptedProxy` as both the filters source and the chained proxy
manager, and as the authenticator when the script defines `authenticate` (`--script` does this
by itself):

```java
ScriptedProxy script = ScriptedProxy.builder(Path.of("proxy.star")).build();
HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withFiltersSource(script).withChainProxyManager(script);
if (script.definesAuthenticate()) bootstrap.withProxyAuthenticator(script);
bootstrap.start();
```

**Hooks.** All are optional.

| Hook | Called | Returns |
|---|---|---|
| `on_request(req, ctx)` | for every request, including `CONNECT` and requests inside intercepted HTTPS | `None` to continue, or `response(...)` to answer without contacting the server |
| `on_response(req, res, ctx)` | for every response head (the whole response when buffered) | `None`, or a new `response(...)` to replace it |
| `upstream(req, ctx)` | when a server connection is needed | `None` for the default route, `"DIRECT"`, a proxy URL (`http://`, `https://`, `socks4://`, `socks5://`), or a list to try in order |
| `allow_mitm(req, ctx)` | for `CONNECT` when `--mitm` is on | whether to intercept |
| `buffer_request(req, ctx)` | before `on_request`, for requests with a body | whether to buffer it so `req.body` is available (default: no) |
| `buffer_response(req, res, ctx)` | before `on_response` | whether to buffer it (default: text in a decodable coding, except `text/event-stream`) |
| `on_websocket_frame(req, frame, ctx)` | for each frame of an upgraded WebSocket, in both directions | `None` to forward the frame (with any changes), `False` to drop it |
| `on_failure(req, failure, ctx)` | when the proxy has to answer the request itself (see [Failure responses](#failure-responses)) | `response(...)` to answer, or `None` for the `FailureResponder`'s answer or the default |
| `authenticate(req, ctx)` | before the other hooks, for requests and `CONNECT`s from clients that have not authenticated (every request with `AUTHENTICATE_EVERY_REQUEST = True`); only when the script is the proxy authenticator | the user name or `True` to accept; `False` or `None` for the default `407`; `response(...)` to reject with that answer |

**Objects.**

- `req`: `method`, `uri` (assignable), `url`, `scheme`, `host`, `port`, `path`, `query`, and
  `headers`, `body`, `text`, plus `http_version`: the version the client used, `"HTTP/1.1"`,
  `"HTTP/1.0"` or `"HTTP/2"` (requests reach servers as HTTP/1.1, or as HTTP/2 to servers that
  negotiate it with `http2_upstream`).
- `res`: `status`, `reason` (assignable), and `headers`, `body`, `text`, plus `source` and
  `upstream_status` (below).
- `body` and `text`: the decoded body as bytes or as a string. Both are `None` when the body was
  streamed rather than buffered. Assigning either re-encodes the body.
- `headers`: case-insensitive. `h["name"]` (first value), `h["name"] = v`, `"name" in h`,
  `get`, `get_all`, `set`, `add`, `remove`, `keys`, `items`.
- `ctx`: `client_ip`, `client_port`, `user` (from proxy authentication), `connection_id`, `tls`,
  `timings` (below), and `vars`, a dict that lives for one request so `on_request` can pass
  values to `on_response`. For a WebSocket it lives as long as the connection.
- `failure`: `kind` (`"unresolved_host"`, `"connect_failed"`, `"tls_failed"`,
  `"server_timeout"`, `"bad_server_response"`, `"no_route"`, `"no_connection_available"`,
  `"bad_request"`, `"request_too_large"`), `status` (of the default answer), `host` (the server's
  name without the port; `None` for `bad_request`, `request_too_large` and a request that names
  no host), and `message`: the cause's message
  (`Connection refused`, ...) or the reason, never a stack trace.
- `frame`: `type` (`"text"`, `"binary"`, `"continuation"`, `"close"`, `"ping"`, `"pong"`),
  `opcode`, `fin`, `from_client`, `length`, `truncated`, and `text` and `payload`, which can be
  assigned. `text` is `None` for a payload that is not UTF-8; both are `None` for a truncated
  frame.

**Built-ins.**

- From Starlark: everything in the language spec, including `json.encode`/`json.decode`.
- `response(status=200, body="", headers=None, content_type=None)`.
- `re`: `match`, `search`, `fullmatch`, `findall`, `sub` (template or function), `split`,
  `escape`. Patterns use java.util.regex syntax plus Python's `(?P<name>...)`, and are
  abandoned at the call's deadline.
- `base64.encode`/`decode` (`urlsafe=True`), `codecs.encode`/`decode`.
- `digest.md5`/`sha1`/`sha256`/`sha512`/`hmac_sha256` (all return hex), and `digest.equal(a, b)`,
  which compares bytes or strings (as UTF-8) in constant time. Use it, not `==`, for tokens and
  signatures: `==` stops at the first difference, so how long a guess takes to fail tells an
  attacker how much of it was right. Compare digests of both sides (as below) so the length does
  not leak either.
- `url.quote`/`unquote`/`parse_query`/`encode_query`.
- `time.now`/`monotonic`, and `log.debug`/`info`/`warn`/`error`. `print` also goes to the log.
- More with `load()`: Python's `hashlib`, `hmac`, `re`, `urllib.parse`, `json`, `zlib`, ... (see
  **Standard library** below).

**Where a response came from, and how long it took.** `res.source` tells the server's responses
from the others, like the `source` of the [access log](#access-logs), and `res.upstream_status`
is the status the server sent (`None` if it sent none). They describe the response as the hook
received it, not the script's own changes:

| where | `res.source` |
|---|---|
| `on_response`, `buffer_response` | `"server"`; `"proxy"` for the `200` that opens a `CONNECT` tunnel; `"cache"` for an `HttpCache` answer (a revalidated or stale entry) when the cache runs before the script in a filter chain; `"filter"` when an earlier filter in the chain gave the response another status; `None` when it cannot be told |
| `response(...)` | `"filter"` |

The script never sees the proxy's own answers or other filters' short-circuits as `res`
(`on_failure` makes the former), and filters after it (including a cache placed last, as
`--cache-dir` does) may still replace the response: `ActivityTracker`s and the access log report
the final source.

`ctx.timings` is a read-only snapshot, taken when read, of the exchange's
[timings](#observability) in milliseconds: `dns_ms`, `connect_ms`, `tls_ms` (towards the server),
`client_tls_ms`, `ttfb_ms` (to the first byte of the server's response) and `total_ms` (to the
last byte sent to the client). Each is a float, or `None` for a phase that did not happen or has
not happened yet: in `on_request` only `client_tls_ms` can be known, in `on_response` and
`on_failure` the server phases so far, and `total_ms` only in `on_websocket_frame` (after the
upgrade's response). A request on a reused connection has no `dns_ms`, `connect_ms` or `tls_ms`;
inside an intercepted session they belong to the `CONNECT`.

Log slow servers, and tell the client how long the server took:

```python
def on_response(req, res, ctx):
    t = ctx.timings
    if t.ttfb_ms == None:
        return None
    if t.ttfb_ms > 1000:
        log.warn("%s: first byte after %d ms (dns %s, connect %s, tls %s), %s from the %s" % (
            req.url, t.ttfb_ms, t.dns_ms, t.connect_ms, t.tls_ms, res.upstream_status, res.source))
    res.headers["Server-Timing"] = "upstream;dur=%d" % t.ttfb_ms
    return None
```

**Answering failures.** `on_failure` replaces the proxy's plain-text answers, and leaves the rest
to the [`FailureResponder`](#failure-responses) or the default by returning `None`:

```python
def on_failure(req, failure, ctx):
    if failure.kind in ["unresolved_host", "connect_failed"]:
        return response(502, "%s is unreachable: %s\n" % (failure.host, failure.message),
                        headers={"Retry-After": "30"})
    if failure.kind == "server_timeout":
        return response(504, json.encode({"error": "timeout", "host": failure.host}),
                        content_type="application/json")
    return None  # the FailureResponder's answer, or the proxy's default
```

**Authenticating clients.** A script that defines `authenticate` decides who may use the proxy
(see [Proxy authentication](#proxy-authentication)). `req` is read-only there, and still carries
`Proxy-Authorization`, which the proxy removes before the other hooks see the request. `ctx.user`
is the user the connection authenticated as before, if any; `ctx.vars` is not shared with the
other hooks, whose `ctx.user` is the user it accepts. It fails closed: a failing or timed-out
call, an empty string or any other value rejects the request with the default `407` and is
logged, and so is every request if a reload removes `authenticate`. By default the first
accepted request authenticates its connection; `AUTHENTICATE_EVERY_REQUEST = True` checks every
request.

Bearer tokens, compared in constant time. Never write secrets into a script: here they come from
constants (below), and only their SHA-256 digests are given to the proxy:

```python
# TOKENS = "alice:<sha256 of alice's token>,bob:<sha256 of bob's token>", from --script-var(-file)
USERS = [entry.split(":") for entry in TOKENS.split(",")]

def authenticate(req, ctx):
    value = req.headers.get("Proxy-Authorization", "")
    if value.startswith("Bearer "):
        presented = digest.sha256(value[len("Bearer "):].strip())
        for user, expected in USERS:
            if digest.equal(presented, expected):
                return user
    return response(407, "a valid token is required\n",
                    headers={"Proxy-Authenticate": 'Bearer realm="proxy"'})
```

<!-- x-release-please-start-version -->
```bash
echo "TOKENS=alice:$(printf %s "$ALICE_TOKEN" | sha256sum | cut -d' ' -f1)" > tokens.properties
java -jar microproxy-starlark/target/microproxy-starlark-0.1.0-all.jar --script auth.star --script-var-file tokens.properties
```
<!-- x-release-please-end -->

**Constants.** Values a script needs but should not contain (tokens, host lists, per-site
settings) come from outside as read-only globals. On the command line, `--script-var NAME=VALUE`
(repeatable) gives a string, and `--script-var-file file.properties` reads a properties file;
later options win. Arguments are visible to other local users (`ps`), so put secrets in a file.
From Java, `ScriptedProxy.Builder.constants(Map)` also takes ints, booleans, and lists and dicts
of these:

```java
ScriptedProxy script = ScriptedProxy.builder(Path.of("auth.star"))
        .constants(Map.of("TOKENS", System.getenv("PROXY_TOKENS"), "MAX_BODY", 1 << 20,
                "ALLOWED", List.of("example.com", "example.org")))
        .build();
```

Constants are frozen, predeclared like the built-ins (so the type checker knows their types),
and cannot be assigned by the script. A name must be an identifier that does not hide a built-in
(`len`, `json`, `Request`, ...); a script that uses a constant nobody set does not load. They
are kept when the script reloads.

**WebSocket examples.** `on_websocket_frame` gets the upgrade request, the frame and the
context. Frames from the client and from the server come through the same hook (`frame.from_client`
tells them apart) and share `ctx.vars`, so a script can keep state for the whole connection.

Redact a field in a JSON protocol, both ways:

```python
def on_websocket_frame(req, frame, ctx):
    if frame.type != "text" or not frame.text.startswith("{"):
        return None
    msg = json.decode(frame.text)
    if "token" in msg:
        msg["token"] = "<redacted>"
        frame.text = json.encode(msg)
```

Block client commands on one endpoint, and drop pings the server sends:

```python
def on_websocket_frame(req, frame, ctx):
    if req.path == "/admin/ws" and frame.from_client and frame.type == "text":
        if frame.text.startswith("DELETE "):
            log.warn("blocked %s from %s" % (frame.text, ctx.client_ip))
            return False
    if frame.type == "ping" and not frame.from_client:
        return False  # the proxy forwards nothing; the client simply never sees it
```

Number the messages in a chat, with types (see below):

```python
def on_websocket_frame(req: Request, frame: WebSocketFrame, ctx: Context) -> bool | None:
    if frame.type != "text" or frame.from_client:
        return None
    n: int = ctx.vars.get("n", 0) + 1
    ctx.vars["n"] = n
    frame.text = "#%d %s" % (n, cast(str, frame.text))
    return None
```

Binary protocols work on `frame.payload` (bytes): for example, replace a magic prefix with
`frame.payload = b"v2" + frame.payload[2:]`. Frames over the buffer limit
(`withMaxWebSocketFrameBufferSize`, 1 MiB by default) arrive with `truncated` set and no payload;
they can be forwarded or dropped but not rewritten. A failing hook is logged and the frame is
forwarded unchanged.

**Typed scripts.** Scripts may use Starlark's type annotations, which are checked when the
script loads and again on each call. Unannotated code is not checked, so annotations can be added
one function at a time. The proxy's objects are named `Request`, `Response`, `Headers`,
`Context`, `WebSocketFrame`, `Failure` and `Timings`:

```python
ALLOWED: list[str] = ["example.com", "example.org"]

def on_request(req: Request, ctx: Context) -> Response | None:
    if req.host not in ALLOWED:
        return response(403, "not allowed\n")
    req.headers["X-Client"] = ctx.client_ip
    return None

def on_response(req: Request, res: Response, ctx: Context) -> None:
    if res.text != None:
        text = cast(str, res.text)  # the checker does not narrow `str | None` after a test
        res.text = text.replace("http://", "https://")
```

A misspelt field (`req.hots`), an assignment of the wrong type (`req.uri = 3`), or a return of
the wrong type stops the script from loading, with the line and column. Arguments of the wrong
type to an annotated function fail the call. `body` and `text` are typed `bytes | None` and
`str | None`, since a streamed body has neither; `ctx.user`, `res.source` and `failure.host` are
`str | None`, `res.upstream_status` is `int | None`, and the fields of `ctx.timings` are
`float | None`.

**Standard library.** Scripts can `load()` a Python-compatible standard library, ported from
[starlarky](https://github.com/verygoodsecurity/starlarky) and running on the JDK alone (no
dependency besides the interpreter's Guava). Load a module by its label, `@stdlib//<module>` or
`@vendor//<module>`, and name the bindings to take from it:

```python
load("@stdlib//hmac", "hmac")
load("@stdlib//urllib/parse", "parse")

# SECRET, from --script-var(-file), signs links as hmac_sha256(SECRET, path + expires)
def on_request(req, ctx):
    query = parse.parse_qs(req.query)
    expires = query.get("expires", ["0"])[0]
    signature = query.get("signature", [""])[0]
    expected = hmac.new(bytes(SECRET), bytes(req.path + expires), "sha256").hexdigest()
    if not hmac.compare_digest(signature, expected):
        return response(403, "bad signature\n")
    if int(expires) < time.now():
        return response(410, "link expired\n")
    return None
```

| Module | |
|---|---|
| `base64`, `binascii`, `codecs`, `struct`, `zlib` | Python's APIs over bytes (`zlib` on `java.util.zip`, including gzip and raw deflate streams) |
| `hashlib`, `hmac` | `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512_224`, `sha512_256`, `sha3_224`…`sha3_512`, `new(name)`, `pbkdf2_hmac`; `hmac.new`/`digest`/`compare_digest` (the JDK's `MessageDigest` and `Mac`) |
| `json` | `dumps`/`loads` and `encode`/`decode`/`indent` (the predeclared `json`, plus Python's names; keys are sorted) |
| `re` | Python's `re`: `compile`, `match`, `search`, `fullmatch`, `findall`, `finditer`, `sub`/`subn`, `split`, `escape`, flags, match objects (see below) |
| `urllib/parse`, `urllib/request` | `urlparse`, `urlsplit`, `urljoin`, `quote`, `unquote`, `urlencode`, `parse_qs`, ...; `Request` objects (no network access) |
| `collections`, `dicts`, `enum`, `functools`, `itertools`, `operator`, `sets`, `types` | containers and functional helpers |
| `string`, `textwrap`, `reprlib`, `csv`, `io` (`StringIO`, `BytesIO`) | text |
| `math`, `random`, `uuid` | `random` and `uuid4` use `SecureRandom` (no seeding) |
| `xml/etree/ElementTree` | parsing, building, `find`/`findall` with ElementPath, serializing (a pure-Starlark parser) |
| `zipfile` | reading and writing archives in memory (stored and deflated; `bz2` is a stub) |
| `builtins`, `larky`, `sys` | Python builtins that Starlark lacks (`builtins.bytes(s, "latin-1")`, ...), and starlarky's helpers (`larky.struct`, `larky.mutablestruct`, ...) |
| `@vendor//option/result` | Rust-style `Ok`/`Error` results, which the library returns internally |
| `@vendor//asserts`, `six`, `escapes`, `multidict`, `luhn` | test assertions, compatibility helpers, case-insensitive multi-dicts, Luhn checksums |

What loading changes, and what it does not:

- A module is compiled and run once per process, frozen, and shared by every script and
  connection; loading it costs nothing after the first time. Its functions run in the calling
  hook, within the hook's step and time limits, under the same sandbox (no files, network or
  processes). A module's own top level is bounded too (200 million steps, 60 seconds).
- A script that loads anything runs with Python's string semantics, which the library relies on:
  `"%5.2f" % x` and the other printf flags, Unicode-aware `upper()`/`isalpha()`/..., Python's
  bounds for `find`/`count`, and CPython's codec names for `bytes.decode`. Scripts without
  `load` statements behave exactly as before.
- The predeclared built-ins (`re`, `json`, `base64`, `digest`, ...) stay available without
  `load`. A loaded name may hide one: after `load("@stdlib//json", "json")`, `json` is the
  library's; `load("@stdlib//json", py_json="json")` keeps both.
- Typed scripts are checked as usual; values from the library are untyped (`Any`).
- Only the library can be loaded: `load("helpers.star", ...)` is an error, as are unknown modules
  (the message lists the available ones) and cycles.
- The library's `re` translates Python patterns to `java.util.regex`. Unlike starlarky's (RE2),
  it supports look-ahead, look-behind, backreferences, atomic groups and possessive quantifiers;
  conditional groups (`(?(1)a|b)`) are rejected. `\d`, `\w`, `\s` and `\b` are Unicode-aware
  for str patterns (ASCII with `re.ASCII` or for bytes), and `.`, `^` and `$` treat only `\n` as
  a line end, as in Python. Java's engine backtracks, so a pathological pattern can take
  exponential time: matching is abandoned at the hook's deadline with
  `re.error: regular expression ran past the deadline`. Matches on bytes are returned as str
  (Latin-1), as in starlarky.

Not included: starlarky's cryptography, JOSE/JWT, OpenSSL, OpenPGP and XML-signature modules
(`Crypto`, `cryptography`, `jose`, `OpenSSL`, `OpenPGP`, `xmlsig`, `lxml`), which need
BouncyCastle, Tink or WSS4J; `iso8583`, `jks` and the company-specific modules of its `vgs`
namespace; and `hashlib`'s BLAKE2 and SHAKE, which the JDK lacks (`hashlib.blake2b(...)` fails
with `unsupported hash type`). starlarky's own tests run in the build against the port
(`StarlarkyStdlibTest`), with the few known differences listed there.

**Errors and reloading.**

- A hook that fails is logged with its Starlark stack trace, and the client gets a bare `500`.
  A failing `allow_mitm` declines interception; a failing `upstream` gives `502`; a failing
  `on_failure` leaves the answer to the `FailureResponder` or the default; a failing
  `authenticate` rejects the request.
- A script file is re-read when it changes (checked at most once a second). An edit that does
  not compile is logged and the previous version stays in use. `--script-no-reload` turns this
  off.
- As in Bazel, `if` and `for` statements must be inside functions, and global values are frozen
  once the file has loaded.

### Shared server connection pool

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
  [Interception per client connection](#interception-per-client-connection)).
- **Metrics:** `HttpProxyServer.getServerConnectionPoolMetrics()` reports counts.

### DNSSEC

`withUseDnsSec(true)` (or `--dnssec`) resolves server names with
`org.microproxy.dns.DnssecHostResolver`, a validating resolver written for this project:

- **Validation:** queries go to a recursive resolver with the DO and CD bits set, and every answer
  is validated locally from the IANA root trust anchors (KSK-2017 and KSK-2024) down through DS
  records.
- **Algorithms:** RSA/SHA-1/256/512, ECDSA P-256/P-384, Ed25519 and Ed448.
- **Unsigned zones:** names in unsigned zones resolve only with a validated NSEC or NSEC3
  (including opt-out) proof that their delegation is unsigned. Signed wildcards need their
  denial proof.
- **Rejection:** anything else is *bogus* and fails with `DnssecValidationException`. Stripping
  signatures therefore cannot downgrade a signed zone. `Policy.REQUIRE_SECURE` also rejects
  unsigned zones.
- **Failure behaviour:** network failures fail the lookup. Unlike dnssec4j, there is no silent
  fallback to unvalidated DNS.
- **Transport:** UDP/TCP to the resolvers in `/etc/resolv.conf` by default, or DNS over HTTPS:
  `DnssecHostResolver.builder().resolver("https://cloudflare-dns.com/dns-query").build()`.
  Use DoH where port 53 is intercepted or blocked.

LittleProxy used dnssec4j, which checked signatures where present but never anchored them to the
root key or compared DS digests. It fell back to plain DNS on network errors.

### WebSocket frames

After a `101` upgrade or HTTP/2 WebSocket extended CONNECT, filters can watch and rewrite every frame, in both
directions and inside intercepted TLS:

- **Watching:** `webSocketFrameReceived(WebSocketFrame frame, boolean fromClient)` sees the
  opcode, FIN, masking and the unmasked payload. LittleProxy's
  `webSocketFrameReceived(Supplier<byte[]>, boolean)` still works and receives each frame's raw
  bytes (LittleProxy delivered raw TCP reads rather than frames).
- **Rewriting:** `filterWebSocketFrame(WebSocketFrame frame, boolean fromClient)` returns the
  frame to forward: `frame` itself, a replacement (`frame.withText(...)`,
  `WebSocketFrame.text(...)`, `binary(...)`, `close(code, reason)`), or `null` to drop it. The
  proxy masks frames it sends towards the server, as RFC 6455 requires. When a filter rewrites
  frames, the proxy removes `Sec-WebSocket-Extensions` from the upgrade request so that payloads
  are not compressed (permessage-deflate). Messages split into continuation frames are seen one
  frame at a time.
- **Large frames:** frames larger than `withMaxWebSocketFrameBufferSize` (default 1 MiB) arrive
  truncated, without a payload: returning them streams them through, `null` discards them.
- **No listener:** if no filter overrides any of these methods, the connection is relayed as raw
  bytes.

```java
@Override
public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
    if (!frame.isText()) return frame;
    String text = frame.payloadAsText();
    if (fromClient && text.contains("\"password\"")) return null;        // drop it
    return frame.withText(text.replace("staging.example", "prod.example")); // or rewrite it
}
```

### Access logs

`bootstrap.plusActivityTracker(new ActivityLogger(LogFormat.CLF))` writes one line per response
to the `System.Logger` named `org.microproxy.extras.ActivityLogger`, or to a `Consumer<String>`
you pass. The formats are `CLF`, `ELF` (combined), `JSON`, `SQUID`, `W3C`, `LTSV`, `CSV` and
`HAPROXY`. These are LittleProxy's formats, with three of its bugs fixed: JSON escaping, Squid
timestamps and RFC 4180 CSV quoting. Lines also include the authenticated user, and URLs inside
intercepted sessions are logged as `https://`.

`JSON_EXTENDED` adds fields to the `JSON` line: `source` (`SERVER`, `PROXY`, `FILTER` or `CACHE`),
`upstream_status` (what the server sent, when a filter or the cache changed it), and `ttfb_ms`,
`total_ms`, `dns_ms`, `connect_ms` and `tls_ms`. Its lines are written when the response is
complete rather than when its head is sent; see [Observability](#observability).

Three ways to keep a record of traffic:

- **`ActivityLogger`:** one line per exchange, in an access-log format. Cheap enough to leave on.
- **`HttpLogger`:** whole messages, with their headers, what the proxy and filters changed, and
  optionally bodies, as readable blocks or JSON lines. For debugging and audits (see
  [Request/response logging](#requestresponse-logging)).
- **`WarcRecorder`:** an archive of the exchanges with servers as binary WARC records, complete and
  unredacted, for replay tools (see [WARC recording](#warc-recording)).

### Request/response logging

`HttpLogger` logs whole requests and responses, like OkHttp's `HttpLoggingInterceptor` or a
mitmproxy flow dump. It is a filters source:

```java
HttpLogger logger = HttpLogger.builder()
        .level(HttpLogger.Level.HEADERS)          // BASIC, HEADERS (the default) or BODY
        .redact("X-Api-Key")                       // besides Authorization, Cookie, Set-Cookie, Proxy-Authorization
        .redactQueryParams("token", "api_key")
        .maxBodyBytes(4096)                        // BODY: bytes kept per body (the default)
        .only((request, ctx) -> request.uri().contains("/api/"))   // optional
        .build();
MicroProxy.bootstrap().plusFiltersSource(logger).start();
```

- **Levels:** `BASIC` logs the request line, the status line, timings and the sizes the heads
  declare. `HEADERS` adds the headers. `BODY` adds the bodies.
- **Both sides of the proxy:** the request as the client sent it, then, when the proxy or a filter
  changed it, a `forwarded as` section with the request line as sent and the headers removed (`-`)
  and added (`+`). The response as the server sent it, then a `delivered as` section in the same
  form. The response line shows the status the client got, how long the exchange took (`ttfb` is
  the wait for the server's first byte), where the response came from (`source=server`, `proxy`,
  `filter` or `cache`) and the server's status (`upstream=`) when a filter or the cache answered or
  changed it.
- **Correlation:** each message is handed to the sink as one string, so concurrent connections do
  not interleave their lines. Every line starts with `[conn <id> #<n>]`: the client connection, as
  in the proxy's own log lines, and the exchange's number on it. Requests inside an intercepted
  TLS session are numbered after their `CONNECT`. An HTTP/2 stream's lines add its id
  (`[conn 3 #2 stream 5]`, and `"stream": 5` in JSON); its request line shows `HTTP/2.0` and its
  `forwarded as` line `HTTP/1.1`.
- **When:** a request is logged once it has been sent to the server (or answered without it), a
  response once it has been delivered in full. An exchange that fails half-way through its response
  logs no response.
- **Redaction:** the values of `Authorization`, `Cookie`, `Set-Cookie` and `Proxy-Authorization`
  are replaced with `██`, in any case and on both sides. `redact(...)` adds header names,
  `redactQueryParams(...)` redacts query parameters in logged URLs, and `redactNothing()` turns
  redaction off (later `redact` calls add to that). Bodies are never redacted.
- **Bodies (`BODY`):** each body is kept up to `maxBodyBytes`; the rest is counted, never buffered,
  and what is forwarded does not change. A body seen whole is decoded (`gzip`, `deflate`, `br`,
  `zstd`, as in [Rewriting bodies](#rewriting-bodies)) and shown as text in the charset of its
  `Content-Type`. Binary bodies are summarised (`<1000 bytes of image/png>`). A request body is
  shown as the client sent it, a response body as the server sent it (and the delivered body too
  when a filter replaced the response).
- **WebSocket frames:** `.webSocketFrames(true)` at `BODY` also logs each frame after an upgrade:
  text frames' text (up to `maxBodyBytes`), other frames' sizes. It is off by default because it
  makes the proxy parse every frame. Frames are only watched, so the extension negotiation is left
  alone and compressed frames are logged as such.
- **Cost:** `BASIC` and `HEADERS` read only heads, so bodies keep the proxy's fast path. When the
  `System.Logger` is off at INFO (and no `sink` was given), no filters are created at all.
- **Failures:** a sink that throws, or a bug in the logger, is reported once to the
  `org.microproxy.extras.HttpLogger` logger and never reaches the proxy.

> **`BODY` logs payloads.** Bodies carry passwords, tokens, session data and personal data, and
> redaction does not touch them. Use `BODY` while developing, or narrowed with `only(...)` to the
> traffic you are debugging, and not in production without deciding where the logs go and who can
> read them. `HEADERS` also logs URLs and every header that is not redacted.

To log from filters built with lambdas, add the logger to the builder. It sees the request before
the lambdas and the response after them, so their changes show in the diffs:

```java
HttpFiltersBuilder.Built filters = HttpFilters.builder()
        .log(logger)
        .beforeSending(req -> { req.headers().set("X-Trace", traceId()); return null; })
        .build();
MicroProxy.bootstrap().withFiltersSource(filters).start();
// or, the same: .withFiltersSource((request, ctx) -> filters)
```

One built instance can serve every connection: the logger's state is per exchange. When the proxy
(or an `HttpFiltersChain`) gets built filters from a source, whether they are the source or a
lambda returned them, it asks them for a copy bound to that exchange, which holds the logger's state
and goes away with the exchange. Only built filters wrapped in filters of your own that delegate to
them cannot be bound; they run their hooks but log nothing, and a warning says so once.

In a chain, put the logger first: `HttpFiltersChain.of(logger, rewriter, script)`. It still sees
requests as clients sent them and responses as delivered wherever it is, but it reads server
responses (and request bodies) when they reach it. Starlark scripts chain the same way.

From the command line, `--log-http basic|headers|body` installs a logger first among the filters,
and `--log-http-json` writes JSON lines (at `headers` unless a level is given). Properties files
take `log_http` and `log_http_format=json`.

Without a `sink`, messages go to the `System.Logger` named `org.microproxy.http` at INFO. With the
JDK's default `java.util.logging` setup they appear on standard error with a date line before each.
To keep only the messages, or to send them to a file, pass a configuration with
`-Djava.util.logging.config.file=http-logging.properties`:

```properties
handlers = java.util.logging.ConsoleHandler
java.util.logging.ConsoleHandler.level = ALL
.level = WARNING
org.microproxy.http.level = INFO
# just the message: one block, or one JSON object per line
java.util.logging.SimpleFormatter.format = %5$s%n
# or write them to a file instead of the console:
# org.microproxy.http.handlers = java.util.logging.FileHandler
# org.microproxy.http.useParentHandlers = false
# java.util.logging.FileHandler.pattern = http-%u.log
# java.util.logging.FileHandler.formatter = java.util.logging.SimpleFormatter
```

With SLF4J or Log4j bridges, configure the logger `org.microproxy.http` there. A `sink(line -> ...)`
receives each message directly instead.

`HEADERS` output for a `POST` through the proxy (`--log-http headers`):

```text
[conn 3 #1] --> POST http://api.example.com/items?token=██&page=2 HTTP/1.1
[conn 3 #1] Content-Length: 17
[conn 3 #1] Host: api.example.com
[conn 3 #1] User-Agent: curl/8.9.1
[conn 3 #1] Authorization: ██
[conn 3 #1] Content-Type: application/json
[conn 3 #1] Proxy-Connection: Keep-Alive
[conn 3 #1] --> forwarded as POST /items?token=██&page=2 HTTP/1.1
[conn 3 #1] - Proxy-Connection: Keep-Alive
[conn 3 #1] + Via: 1.1 gateway
[conn 3 #1] --> END POST (17-byte body)
[conn 3 #1] <-- 201 Created http://api.example.com/items?token=██&page=2 (48 ms, ttfb 47 ms, source=server)
[conn 3 #1] Content-Type: application/json
[conn 3 #1] Content-Length: 25
[conn 3 #1] Set-Cookie: ██
[conn 3 #1] <-- delivered as HTTP/1.1 201 Created
[conn 3 #1] + Via: 1.1 gateway
[conn 3 #1] <-- END HTTP (25-byte body)
```

`BODY` adds the bodies after a blank line, before the `END` lines. With `--log-http-json`, each
message is one object (wrapped here):

```json
{"type":"request","conn":3,"seq":1,"time":"2026-10-09T02:44:26.372Z","method":"POST",
 "url":"http://api.example.com/items?token=██&page=2","version":"HTTP/1.1",
 "headers":[["Content-Length","17"],["Host","api.example.com"],["Authorization","██"],["Content-Type","application/json"]],
 "forwarded":{"method":"POST","uri":"/items?token=██&page=2","version":"HTTP/1.1","removed":[],"added":[["Via","1.1 gateway"]]},
 "body_bytes":17}
{"type":"response","conn":3,"seq":1,"time":"2026-10-09T02:44:26.372Z","status":201,"reason":"Created",
 "url":"http://api.example.com/items?token=██&page=2","version":"HTTP/1.1","source":"SERVER","upstream_status":201,
 "ttfb_ms":47.112,"total_ms":48.003,"headers":[["Content-Type","application/json"],["Content-Length","25"],["Set-Cookie","██"]],
 "delivered":{"status":201,"reason":"Created","version":"HTTP/1.1","removed":[],"added":[["Via","1.1 gateway"]]},
 "body_bytes":25}
```

At `BODY`, JSON messages add `body` (the text, or `null` with a `body_note` for binary or
undecodable bodies) and `body_remarks` (`gzip-decoded`, `first 4096 bytes shown`, ...); WebSocket
frames are `{"type":"websocket","from":"client","opcode":"text","fin":true,"bytes":4,"payload":"ping",...}`.

### Observability

`ActivityTracker` callbacks run on the connection's virtual thread. Besides LittleProxy's events:

- **Where a response came from:** `responseSentToClient(ctx, response, source)` receives a
  `ResponseSource`: `SERVER` (relayed, maybe with headers or body edited in place), `PROXY` (the
  proxy's error answers, `407`, the `CONNECT` `200`), `FILTER` (a short-circuit, a failure answer
  from a filter, or a server or proxy response a filter replaced or gave another status) or `CACHE`.
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
- **Correlation:** `ctx.getConnectionId()` and `ctx.acceptedAt()` identify the client connection,
  and the proxy's log lines about it start with `[conn <id>]`.
- **HTTP/2 streams:** `ctx.getStreamId()` names the stream (0 for HTTP/1), and log lines about it
  start with `[conn <id> stream <id>]`. Each stream has its own context, with its own timings and
  upstream status; contexts are equal only for the same connection and stream, and
  `ctx.getConnectionContext()` is the connection's. Callbacks for one connection's streams run
  concurrently, on the streams' threads. A stream that ends without a complete response (the
  client reset it, or the connection closed) is reported with `connectionExceptionCaught(streamCtx,
  cause)`. The request's `protocolVersion()` is `HTTP/2.0`, so access log lines show it.
- **In filters:** `HttpFilters.proxyToClientResponseSent(response, source)` is called once a
  response has been written in full, whoever made it, with the head as sent and its
  `ResponseSource`; `ctx.timings()` covers the whole exchange by then.
  `HttpFilters.exchangeEnded(completed)` follows exactly once however the exchange ended (also
  when the client left half-way, the server failed or a filter aborted; for tunnels when they
  close), so filters can release what they hold per exchange.

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

## Migrating from LittleProxy

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
| `SslEngineSource` (`SSLEngine`) | `SslContextSource` (`SSLContext`, plus a `configure(SSLSocket, clientMode)` hook) |
| `MitmManager.serverSslEngine / clientSslEngineFor` | `serverSslContext / clientSslContextFor` (return `SSLContext`) |
| `withSslEngineSource` | `withSslContextSource` |
| `SelfSignedSslEngineSource` (keytool, JKS file) | `org.microproxy.tls.SelfSignedSslContextSource` (generated in memory) |
| `SelfSignedMitmManager` | `org.microproxy.tls.CertificateAuthorityMitmManager` |
| `HttpProxyServer.getIdleConnectionTimeout()` (seconds) | returns a `Duration` |
| `DnsSecServerResolver` (dnssec4j) | `org.microproxy.dns.DnssecHostResolver` |
| `org.littleshoot.proxy.extras.ActivityLogger` / `LogFormat` | `org.microproxy.extras.ActivityLogger` / `LogFormat` |
| `impl.PoolMetrics` | `org.microproxy.PoolMetrics` (a record) |

Other behaviour differences. Where a filter depends on LittleProxy's behaviour,
`withLittleProxyCompatibility()` (`--littleproxy-compat`, `littleproxy_compatibility=true`) restores
it; see that method's Javadoc for the list:

- `proxyToServerRequest` runs before the server is resolved and connected, so a filter can answer
  or redirect without a DNS lookup. LittleProxy resolves first (and with compatibility on, so does
  MicroProxy).

- The proxy does not fill `FlowContext`'s string-keyed timing map (LittleProxy's
  `dns_resolution_*_time_ms`); `FlowContext.timings()` has typed timings for every phase instead
  (see [Observability](#observability)).
- Full messages are written with a `Content-Length` that matches their actual body. Filters that
  replace a body don't need to fix the header themselves.
- `ProxyAuthenticator` and `MitmManager` keep LittleProxy's methods. The overloads that take the
  request or a `FlowContext` are optional additions: other authentication schemes and challenges,
  per-request checks, and MITM decisions per user or client (see
  [Proxy authentication](#proxy-authentication) and
  [Interception per client connection](#interception-per-client-connection)).
- With an authenticator configured, `Proxy-Authorization` is removed from every request before
  filters run, not only from the one that authenticated the connection.
- All interface methods have defaults, so the `*Adapter` classes are only conveniences.
- The `org.microproxy.http` message types are a sealed hierarchy. Filters create (and may subclass)
  the `Default*` classes but cannot implement `HttpRequest` and the other interfaces from scratch,
  and a `switch` over them can be exhaustive (see `HttpObject`).

Not ported, because they only exist to manage Netty:

- `ThreadPoolConfiguration` and `ServerGroup`: virtual threads replace event-loop sizing.
- `connectionSaturated` / `connectionWritable` tracker events: blocking writes are the backpressure.
- `proxyToServerConnectionQueued`.

## Building and testing

```bash
mvn verify                      # both modules
mvn -pl microproxy test         # just the core
```

`microproxy-starlark` reuses the core's test helpers through its `tests` jar.

How a request flows through the proxy, which parts are HTTP/1-specific and how HTTP/2 streams run
the same exchange logic concurrently, is described in
[`microproxy/src/main/java/org/microproxy/impl/README.md`](microproxy/src/main/java/org/microproxy/impl/README.md).
`AllocationTest` fails if a small keep-alive request starts allocating much more than it does now.

### Releases

Releases are cut by [release-please](https://github.com/googleapis/release-please). It reads
[Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `feat!:`) on
`main` and keeps a release pull request open that bumps every `pom.xml`, the versions in this
README and `CHANGELOG.md`. Merging it tags `vX.Y.Z`, publishes a GitHub release with the jars
and their `SHA256SUMS` attached, and opens a follow-up pull request that moves `main` to the
next `-SNAPSHOT` version.

The tests use JUnit 5, the JDK's `HttpClient` as the client, `com.sun.net.httpserver` as origin
servers, and raw sockets for wire-level checks. They cover proxying, filters, authentication,
CONNECT, MITM, chaining (HTTP, TLS, SOCKS4/5, fallback), timeouts, PROXY protocol, throttling,
lifecycle, the codec, certificate generation, the shared pool, WebSocket frames, access logs,
HTTP/2 (with the JDK's HTTP/2 client, frame-by-frame protocol tests, a codec-based HTTP/2 origin
for the server side and gRPC-style streaming, and, when installed, `curl --http2`; CI also runs
[h2spec](#conformance-h2spec)),
content codings (Brotli against the upstream test vectors) and the scripting hooks, sandbox
limits and reloading.

DNSSEC is tested in three ways, all offline:

- **Real responses:** responses recorded from real signed, unsigned and deliberately broken zones
  are replayed with the clock fixed at recording time, then tampered with.
- **Synthetic zones:** a signed hierarchy built in the test covers wildcards, unsigned delegations
  and forgeries.
- **Published values:** the IANA root key's tag and digest, and the RFC 5155 hash vectors.

Live validation and re-recording are opt-in:

```bash
mvn test -Dtest=DnssecLiveTest -Dmicroproxy.dns.live=true [-Dmicroproxy.dns.record=true]
```

## Acknowledgements

The Zstandard decoder in `zstd-decoder` was written from RFC 8878 and is tested against the
reference `zstd` tool. Vendored code, with licenses and changes listed in [NOTICE](NOTICE) and
the `README.md` next to each copy:

- Google's [Brotli](https://github.com/google/brotli) decoder (MIT), in the core.
- The Java [Starlark](https://github.com/bazelbuild/bazel) interpreter from Bazel, as extended by
  [starlarky](https://github.com/verygoodsecurity/starlarky) (Apache-2.0), in
  `microproxy-starlark`.
- starlarky's Larky runtime and Python-compatible standard library (Apache-2.0, with CPython and
  ElementTree notices in some files), in `microproxy-starlark`.

Besides LittleProxy, these projects contributed ideas only; no code was copied:

- [baloise/proxy](https://github.com/baloise/proxy): `NO_PROXY` bypass and proxy settings from
  the environment.
- [littleproxy-response-modifier](https://github.com/MichielCM/littleproxy-response-modifier):
  declarative rewrite rules.
- [MoCuishle](https://github.com/ganskef/MoCuishle): content decoding and merged trust stores.
- [LittleProxy-mitm](https://github.com/ganskef/LittleProxy-mitm): a bounded certificate cache
  and copying IP SANs.

## License

Apache License 2.0, like LittleProxy, from which this project is derived.
