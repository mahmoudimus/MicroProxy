# MicroProxy

MicroProxy is an HTTP/HTTPS proxy for Java that can intercept and rewrite traffic. It is a
port of [LittleProxy](https://github.com/LittleProxy/LittleProxy) that drops Netty. Each
connection runs on its own **virtual thread** (Project Loom) and uses plain blocking socket I/O.

- **Runtime:** JDK 21 or newer (also tested on JDK 25).
- **Dependencies:** none at runtime. Logging goes through `System.Logger`, which can be routed to
  SLF4J/Log4j with the usual bridges. Put the `zstd-decoder` jar on the class path as well to
  decode `zstd` bodies.
- **Size:** about 10k lines of main code (including Javadoc and a DNSSEC resolver) plus a vendored
  Brotli decoder, compared with LittleProxy's 11k lines plus Netty and dnssec4j.
- **Scripting (optional):** the `microproxy-starlark` module drives the proxy from a
  [Starlark](https://github.com/bazelbuild/starlark) script (see [Scripting](#scripting-with-starlark)).

| Module | Artifact | Contents |
|---|---|---|
| `zstd-decoder/` | `io.github.mahmoudimus:zstd-decoder` | a standalone pure-Java Zstandard decoder ([README](zstd-decoder/README.md)) |
| `microproxy/` | `io.github.mahmoudimus:microproxy` | the proxy; no required dependencies (`zstd-decoder` is optional) |
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

A few rules keep this safe on JDK 21, where a virtual thread that blocks inside `synchronized`
pins its carrier thread:

- Blocking code paths use `ReentrantLock` instead of `synchronized`.
- The tests run with `-Djdk.tracePinnedThreads=short` to catch pinning.
- On JDK 24+ (JEP 491), `synchronized` no longer pins, so user filters written with
  `synchronized` are fine there too.

## Running

```bash
mvn package
java -jar microproxy/target/microproxy-0.1.0-SNAPSHOT.jar --port 8080
java -jar microproxy/target/microproxy-0.1.0-SNAPSHOT.jar --port 8080 --mitm   # intercept HTTPS
java -jar microproxy/target/microproxy-0.1.0-SNAPSHOT.jar --port 8080 --dnssec --activity-log-format clf
java -jar microproxy/target/microproxy-0.1.0-SNAPSHOT.jar --help

# With zstd decoding:
java -cp microproxy/target/microproxy-0.1.0-SNAPSHOT.jar:zstd-decoder/target/zstd-decoder-0.1.0-SNAPSHOT.jar \
    org.microproxy.Launcher --port 8080

# The same launcher with scripting and zstd built in (one self-contained jar):
java -jar microproxy-starlark/target/microproxy-starlark-0.1.0-SNAPSHOT-all.jar --port 8080 --script proxy.star
```

`--mitm` creates (or reuses) a CA in `microproxy-ca.p12` and writes its certificate to
`microproxy-ca.pem`. To intercept HTTPS without errors, add that certificate to your client's
trust store.

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
| `connect_timeout` | milliseconds | `40000` |
| `max_initial_line_length` / `max_header_size` / `max_chunk_size` | parser limits in bytes | `8192` / `16384` / `16384` |
| `nic` | local address for outbound connections | any |
| `proxy_alias` | name in `Via` | host name |
| `allow_requests_to_origin_server` | accept origin-form requests | `false` |
| `allow_proxy_protocol` / `send_proxy_protocol` | PROXY protocol in / out | `false` |
| `throttle_read_bytes_per_second` / `throttle_write_bytes_per_second` | global server bandwidth | `0` (unlimited) |
| `use_shared_server_connection_pool` | share server connections between clients | `false` |
| `server_connection_pool_type` | pool implementation (`CONCURRENT_MAP`) | `CONCURRENT_MAP` |
| `max_connections_per_host` / `max_total_connections` | pool limits | `10` / `200` |
| `pool_idle_timeout` | seconds before idle pooled connections close | none |
| `pool_shared_mitm_connections` / `pool_per_request_in_mitm` | pool intercepted TLS connections, per session / per request | `false` |
| `upstream_proxy` / `upstream_https_proxy` | chain to `http(s)://[user:pw@]host:port` or `socks4/5://...` (HTTPS / CONNECT may use a different upstream) | none |
| `no_proxy` | hosts reached directly, curl `NO_PROXY` syntax | none |
| `use_env_proxy` | take upstreams from `http_proxy` / `https_proxy` / `all_proxy` / `no_proxy` | `false` |
| `upstream_fallback_to_direct` | connect directly if the upstream is unreachable | `false` |
| `dnssec` | resolve server names with DNSSEC validation | `false` |
| `dnssec_resolver` | DoH URL or comma-separated resolver IPs for `dnssec` | `/etc/resolv.conf` |
| `activity_log_format` | access log: `CLF`, `ELF`, `JSON`, `SQUID`, `W3C`, `LTSV`, `CSV`, `HAPROXY` | off |

## Features

| | |
|---|---|
| HTTP/1.0 and 1.1 proxying | keep-alive on both sides, pipelining, chunked bodies and trailers, `Expect: 100-continue` (a `100` is sent for servers that ignore it), 1xx pass-through, re-chunking of close-delimited responses, de-chunking for HTTP/1.0 clients, stale keep-alive retry |
| Filters | `HttpFilters` / `HttpFiltersSource` with the same hooks as LittleProxy, streaming or buffered (`getMaximumRequestBufferSizeInBytes` / `getMaximumResponseBufferSizeInBytes`) |
| CONNECT | byte tunnel with idle timeout and half-close |
| MITM | `MitmManager`; `CertificateAuthorityMitmManager` issues per-host certificates on demand (EC P-256). Its SANs copy the real server's DNS names. Only the JDK is used, through a small built-in X.509/DER encoder (`org.microproxy.tls.CertificateBuilder`) |
| Chained proxies | HTTP (with Basic credentials, optionally over TLS), SOCKS4a, SOCKS5 (with username/password); falls back to the next proxy or a direct connection. `UpstreamProxyManager` configures them from proxy URLs, `NO_PROXY` rules or the environment |
| Body rewriting | `HttpBodies` decodes gzip, deflate, Brotli and (with `zstd-decoder`) zstd bodies and re-encodes them with the right charset; `RewriteRules` edits headers and text bodies declaratively, buffering only the responses it rewrites |
| Scripting | optional module: `on_request` / `on_response` / `upstream` / `allow_mitm` hooks in Starlark, sandboxed, with hot reload (see below) |
| Proxy authentication | `ProxyAuthenticator` (Basic) |
| TLS listener | `withSslContextSource(...)`, optional client-certificate auth |
| PROXY protocol | accept v1 and v2, send v1 |
| WebSockets | `Upgrade` is preserved and the connection becomes a tunnel after `101`; filters can observe each frame (see below) |
| Shared connection pool | optional server connection reuse across clients, with limits and idle eviction (see below) |
| DNSSEC | optional validating resolver, with no dependencies (see below) |
| Access logs | `ActivityLogger` in eight formats |
| Throttling | global token bucket for server reads and writes, adjustable at runtime |
| Activity tracking | `ActivityTracker` for connections, requests, responses and bytes |
| Hardening | rejects `Transfer-Encoding` + `Content-Length`, conflicting lengths, obs-fold in requests, and oversized lines and headers; header values are validated against CR/LF injection; Host is replaced by the absolute-form authority |

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

```bash
java -jar microproxy-starlark/target/microproxy-starlark-0.1.0-SNAPSHOT-all.jar --mitm --script proxy.star
```

Or from Java, install one `ScriptedProxy` as both the filters source and the chained proxy
manager:

```java
ScriptedProxy script = ScriptedProxy.builder(Path.of("proxy.star")).build();
MicroProxy.bootstrap().withFiltersSource(script).withChainProxyManager(script).start();
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

**Objects.**

- `req`: `method`, `uri` (assignable), `url`, `scheme`, `host`, `port`, `path`, `query`, and
  `headers`, `body`, `text`.
- `res`: `status`, `reason` (assignable), and `headers`, `body`, `text`.
- `body` and `text`: the decoded body as bytes or as a string. Both are `None` when the body was
  streamed rather than buffered. Assigning either re-encodes the body.
- `headers`: case-insensitive. `h["name"]` (first value), `h["name"] = v`, `"name" in h`,
  `get`, `get_all`, `set`, `add`, `remove`, `keys`, `items`.
- `ctx`: `client_ip`, `client_port`, `user` (from proxy authentication), `connection_id`, `tls`,
  and `vars`, a dict that lives for one request so `on_request` can pass values to
  `on_response`.

**Built-ins.**

- From Starlark: everything in the language spec, including `json.encode`/`json.decode`.
- `response(status=200, body="", headers=None, content_type=None)`.
- `re`: `match`, `search`, `fullmatch`, `findall`, `sub` (template or function), `split`,
  `escape`. Patterns use java.util.regex syntax plus Python's `(?P<name>...)`, and are
  abandoned at the call's deadline.
- `base64.encode`/`decode` (`urlsafe=True`), `codecs.encode`/`decode`.
- `digest.md5`/`sha1`/`sha256`/`sha512`/`hmac_sha256` (all return hex).
- `url.quote`/`unquote`/`parse_query`/`encode_query`.
- `time.now`/`monotonic`, and `log.debug`/`info`/`warn`/`error`. `print` also goes to the log.

**Errors and reloading.**

- A hook that fails is logged with its Starlark stack trace, and the client gets a bare `500`.
  A failing `allow_mitm` declines interception; a failing `upstream` gives `502`.
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
  `withPoolPerRequestInMitm(true)` leases it per request instead.
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

After a `101` upgrade to `websocket`, filters that override
`webSocketFrameReceived(WebSocketFrame frame, boolean fromClient)` see every frame:

- **What they get:** opcode, FIN, masking and the unmasked payload, from both directions,
  including inside intercepted TLS.
- **Compatibility:** LittleProxy's `webSocketFrameReceived(Supplier<byte[]>, boolean)` still
  works and receives each frame's raw bytes. LittleProxy delivered raw TCP reads rather than
  frames.
- **Forwarding:** frames are observed, not modified, and forwarded unchanged.
- **Large frames:** frames larger than `withMaxWebSocketFrameBufferSize` (default 1 MiB) are
  streamed and reported as truncated.
- **No listener:** if no filter overrides either method, the connection is relayed as raw bytes.

### Access logs

`bootstrap.plusActivityTracker(new ActivityLogger(LogFormat.CLF))` writes one line per response
to the `System.Logger` named `org.microproxy.extras.ActivityLogger`, or to a `Consumer<String>`
you pass. The formats are `CLF`, `ELF` (combined), `JSON`, `SQUID`, `W3C`, `LTSV`, `CSV` and
`HAPROXY`. These are LittleProxy's formats, with three of its bugs fixed: JSON escaping, Squid
timestamps and RFC 4180 CSV quoting. Lines also include the authenticated user, and URLs inside
intercepted sessions are logged as `https://`.

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

Other behaviour differences:

- Full messages are written with a `Content-Length` that matches their actual body. Filters that
  replace a body don't need to fix the header themselves.
- All interface methods have defaults, so the `*Adapter` classes are only conveniences.

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

The tests use JUnit 5, the JDK's `HttpClient` as the client, `com.sun.net.httpserver` as origin
servers, and raw sockets for wire-level checks. They cover proxying, filters, authentication,
CONNECT, MITM, chaining (HTTP, TLS, SOCKS4/5, fallback), timeouts, PROXY protocol, throttling,
lifecycle, the codec, certificate generation, the shared pool, WebSocket frames, access logs,
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
