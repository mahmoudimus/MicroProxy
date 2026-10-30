# MicroProxy

MicroProxy is a Java 21 proxy for HTTP/1, HTTP/2, HTTP/3 over QUIC, SOCKS and TLS
interception (MITM), built on virtual threads and blocking I/O. This page says what it is, lists
every feature with a link to its guide, and explains the design; start with [Getting
started](getting-started/install.md) to run it.

MicroProxy is an HTTP/HTTPS proxy for Java that can intercept and rewrite traffic. It is a
port of [LittleProxy](https://github.com/LittleProxy/LittleProxy) that drops Netty. Each
connection runs on its own **virtual thread** (Project Loom) and uses plain blocking socket I/O.

## Functionally verified cryptographic implementations with documented trust assumptions

SHAKE128/256 and ML-KEM-768 use Java generated from functionally verified Dafny implementations,
with checks that the packaged Java matches the generated artifacts. Compiler/runtime,
reviewed Java facades and selected JDK primitives remain trusted. Whole-stack TLS/QUIC security
and constant-time JVM execution remain outside these proofs. See the
[verification scope and assumptions](formal-security.md).

- **Runtime:** JDK 21 or newer (also tested on JDK 25).
- **Dependencies:** the core has no required runtime dependencies. QUIC uses the pinned
  `org.dafny:DafnyRuntime:4.9.1` runtime for its generated crypto. Logging goes through
  `System.Logger`, which can be routed to
  SLF4J/Log4j with the usual bridges. Put the `zstd-decoder` jar on the class path as well to
  decode `zstd` bodies, the `http2-codec` jar for [HTTP/2](guides/http2.md) to clients and servers, and
  the `quic` and `http3-codec` jars for [HTTP/3](guides/http3.md) to clients of a reverse proxy
  and to servers (`http3-codec` alone runs [frame interceptors over HTTP/3 streams](guides/frame-interception.md#http3-frames)).
- **Size:** about 10k lines of main code (including Javadoc and a DNSSEC resolver) plus a vendored
  Brotli codec, compared with LittleProxy's 11k lines plus Netty and dnssec4j.
- **Scripting (optional):** the `microproxy-starlark` module drives the proxy from a
  [Starlark](https://github.com/bazelbuild/starlark) script (see [Scripting](guides/scripting.md)).
- **OpenTelemetry (optional):** the `microproxy-otel` module traces exchanges and exports traces,
  metrics and logs over OTLP, with no dependencies either (see [OpenTelemetry](observability/opentelemetry.md)).

The modules, their Maven coordinates and the self-contained `-all` jar are listed in
[Install](getting-started/install.md#modules-and-artifacts).

## Design principles

- **Minimal dependencies.** The core, codecs, OpenTelemetry export and DNSSEC resolver use
  only the JDK. Optional features are jars found on the class path when present. QUIC adds
  the Dafny runtime for generated SHAKE/ML-KEM; Starlark adds the interpreter's Guava.
- **Virtual threads, not event loops.** Each connection is one virtual thread running a
  straight-line loop; blocking a write is the backpressure. See
  [Why virtual threads instead of Netty](architecture.md#why-virtual-threads-instead-of-netty)
  for the design and its measured costs.
- **LittleProxy's filter API.** `HttpFiltersSource`, `HttpFilters`, `ActivityTracker`,
  `ChainedProxyManager`, `MitmManager` and `ProxyAuthenticator` keep LittleProxy's shape, so
  existing filters port with a package rename; `withLittleProxyCompatibility()` restores
  LittleProxy's behaviour for HTTP/1 clients where MicroProxy differs, one
  [protocol policy](guides/protocol-policies.md) field at a time if need be. See
  [Migrating from LittleProxy](migrating-from-littleproxy.md).
- **Envoy's and mitmproxy's vocabularies.** Access logs, stats, response flags and the admin API
  use Envoy's names; interception rules, addons, flow filters, HAR and replay follow mitmproxy.

## Features

Each feature links to the guide that describes it.

| | |
|---|---|
| [HTTP/1.0 and 1.1 proxying](guides/forward-proxy.md) | keep-alive on both sides, pipelining, chunked bodies and trailers, `Expect: 100-continue` (a `100` is sent for servers that ignore it), 1xx pass-through, re-chunking of close-delimited responses, de-chunking for HTTP/1.0 clients, stale keep-alive retry |
| [HTTP/2 to clients](guides/http2.md) | on by default (`--no-http2` turns it off; needs the `http2-codec` jar, else HTTP/1.1): clients that negotiate `h2` on intercepted TLS or the proxy TLS listener get HTTP/2, each stream an exchange of its own with the same filters, cache, failure answers and logging; hardened against stream, reset and frame floods. `--http2-cleartext` adds `h2c` with prior knowledge on the plain listener, and `--http2-cleartext-only` makes it an `h2c`-only listener. A forward proxy with `--masque` or `--http3` takes CONNECT-UDP (RFC 9298) over extended `CONNECT`, its datagrams in capsules |
| [HTTP/2 to servers](guides/http2.md#http2-to-servers) | on by default (`--no-http2-upstream` turns it off): servers that negotiate `h2` get every exchange for them as a stream on a shared connection, within their stream limit; trailers end to end and bidirectional streaming, so gRPC works through the proxy ([tested with grpcio](guides/http2.md#grpc-interop-grpcio)); connection coalescing across names a server's certificate covers (`--http2-coalesce`, RFC 9113 and RFC 8336's ORIGIN frame) |
| [HTTP/3](guides/http3.md) | optional, over the proxy's own QUIC (`quic` module): a reverse proxy serves HTTP/3 on UDP (`--http3`), each request stream an exchange of its own, advertised with `Alt-Svc`; a forward proxy serves it next to its TLS listener, with `CONNECT`, WebSockets (RFC 9220) and MASQUE's CONNECT-UDP (RFC 9298); servers that advertise `h3` get their exchanges, WebSockets included, over one shared QUIC connection (`--http3-upstream`), falling back to TCP; QPACK with dynamic tables, hardened limits, live frame interception |
| [Filters](guides/filters.md) | `HttpFilters` / `HttpFiltersSource` with the same hooks as LittleProxy, streaming or buffered (`getMaximumRequestBufferSizeInBytes` / `getMaximumResponseBufferSizeInBytes`); several sources run in order as an `HttpFiltersChain` (`plusFiltersSource`) |
| [Protocol policies](guides/protocol-policies.md) | where MicroProxy can behave in more than one way (the order of the filter hooks, the `CONNECT` answer, TLS to servers), a policy per client protocol chooses: LittleProxy's behaviour for HTTP/1.1 clients, say, and MicroProxy's for HTTP/2 and HTTP/3 |
| [TLS origination](guides/forward-proxy.md#tls-origination-https-uris-without-connect) | `https://` URIs asked for without `CONNECT` (absolute-form over plain HTTP, `:scheme https` on `h2c`) are fetched over TLS the proxy opens, with the upstream trust, pooling, HTTP/2 and HTTP/3 of intercepted sessions, and through chained proxies' tunnels; `--no-originate-tls` refuses them |
| [CONNECT](guides/tcp-hooks.md) | byte tunnel with idle timeout and half-close; optional TCP hooks see, rewrite, drop and add the bytes of every raw tunnel, and of intercepted TLS that does not carry HTTP (SMTPS, IMAPS, MQTT over TLS), as mitmproxy's `tcp_message` |
| [MITM](guides/mitm.md) | `MitmManager`; `CertificateAuthorityMitmManager` issues per-host certificates on demand (EC P-256). Its SANs copy the real server's DNS names. Only the JDK is used, through a small built-in X.509/DER encoder (`org.microproxy.tls.CertificateBuilder`). CA, upstream trust and client certificate can be chosen per client connection |
| [ClientHello inspection](guides/mitm.md#deciding-what-to-intercept-the-clienthello) | after `CONNECT`, the client's ClientHello is read without consuming it (SNI, ALPN, versions, cipher suites), and interception is decided by it: ignore / allow host rules as in mitmproxy, `MitmManager` and filter hooks; plain HTTP after `CONNECT` is served as HTTP, other protocols are tunnelled; ALPN is mirrored between client and server |
| [Transparent](guides/transparent-mode.md) and [reverse](guides/reverse-proxy.md) modes | TLS redirected to the proxy without `CONNECT` is routed by SNI; `--mode reverse:https://host` serves one upstream over HTTP, HTTPS or raw TCP |
| [SOCKS server](guides/socks.md) | `--mode socks5` serves SOCKS5 (no authentication, or username/password through the `ProxyAuthenticator`) and SOCKS4a clients, whose requests go through the same flow as a `CONNECT`: filters, chained proxies, ClientHello inspection, interception, plain HTTP served as HTTP; `--socks` serves them on the regular listener too |
| [Chained proxies](guides/chained-proxies.md) | HTTP (with Basic credentials, optionally over TLS, over HTTP/1.1 or [HTTP/2](guides/chained-proxies.md#http2-to-chained-proxies)), SOCKS4a, SOCKS5 (with username/password); falls back to the next proxy or a direct connection, optionally with exponential backoff between attempts. `UpstreamProxyManager` configures them from proxy URLs, `NO_PROXY` rules or the environment |
| [HTTP cache](guides/caching.md) | RFC 9111 shared cache in memory or on disk, with revalidation, `Vary`, stale responses when servers are unreachable, and an offline mode |
| [WARC recording](guides/warc.md) | `WarcRecorder` archives traffic with servers as WARC 1.1 files for replay tools, and `WarcReader` reads them back |
| [mitmproxy-style addons](guides/addons.md) | `MapLocal`, `MapRemote`, `ModifyBody`, `ModifyHeaders`, `BlockList`, `AntiCache` and `StickyCookie`, with mitmproxy's option syntax and flow filter expressions (`~d example.com & !~m GET`), from Java or the command line |
| [HAR export and replay](guides/addons.md#har-files) | `HarRecorder` writes HAR 1.2 files; `ServerReplay` answers requests from recorded HAR or WARC responses, `ClientReplay` sends recorded requests again through the proxy |
| [Body rewriting](guides/rewriting-bodies.md) | `HttpBodies` decodes gzip, deflate, Brotli and (with `zstd-decoder`) zstd bodies and re-encodes them with the right charset; `RewriteRules` edits headers and text bodies declaratively, buffering only the responses it rewrites |
| [Scripting](guides/scripting.md) | optional module: `on_request` / `on_response` / `upstream` / `allow_mitm` / `on_failure` / `authenticate` / `on_tcp_message` hooks in Starlark, sandboxed, with hot reload |
| [Proxy authentication](guides/authentication.md) | `ProxyAuthenticator`: Basic by default, or any scheme (Bearer tokens, API keys) with custom challenges; per connection or per request |
| [TLS listener](guides/forward-proxy.md#tls-listener) | `withSslContextSource(...)`, optional client-certificate auth |
| [TLS protocol pinning](guides/mitm.md#tls-protocol-versions) | every TLS connection (listener, both sides of interception, TLS chained proxies) allows only TLS 1.3 and 1.2 by default; `withTlsProtocols(...)` changes it |
| [PROXY protocol](guides/forward-proxy.md#proxy-protocol) | accept v1 and v2 (read before TLS on a TLS listener), send v1 to the final server: first on a direct connection, through the tunnel after an HTTP chained proxy accepts the CONNECT; not sent through SOCKS chained proxies or with plain requests to an HTTP chained proxy |
| [WebSockets](guides/websockets.md) | HTTP/1 `Upgrade` and HTTP/2 extended `CONNECT` (RFC 8441), with the same frame and whole-message hooks in both directions, reading through permessage-deflate |
| [Shared connection pool](guides/forward-proxy.md#shared-server-connection-pool) | optional server connection reuse across clients, with limits and idle eviction |
| [DNSSEC](guides/dnssec.md) | optional validating resolver, with no dependencies |
| [Access logs](observability/access-logs.md) | `ActivityLogger`: Envoy-compatible format strings and JSON, Envoy's response flags, filters, and one line per exchange, tunnel or UDP and QUIC flow; LittleProxy's nine formats as presets |
| [Metrics](observability/metrics.md) | Envoy's stat names and tags (`http.*`, `cluster.*`, `listener.*`, `server.*`, `http2.*`, `http3.*`, ...) in a `StatsRegistry`, as Prometheus text, Envoy's `/stats` text and JSON, or pushed to statsd and DogStatsD; per-protocol stats (QUIC, transparent QUIC, SOCKS, CONNECT-UDP, tunnels, WebSockets) and the hooks'; bounded clusters; scripts' own `stats`; qlog files per QUIC connection |
| [OpenTelemetry](observability/opentelemetry.md) | optional module: W3C Trace Context (and B3, Jaeger) propagation and `X-Request-Id`, a SERVER span per HTTP/1, HTTP/2 and HTTP/3 exchange, a CLIENT span per attempt to reach the server (retries and chained proxy failover included), INTERNAL spans for tunnels and flows, sampling, and OTLP/HTTP export (protobuf or JSON) of traces, the stats as metrics and access logs as log records, from `OTEL_*` variables or `--otel` |
| [Admin interface](observability/admin.md) | Envoy's admin API on a listener of its own: `/stats`, `/stats/prometheus`, `/ready`, `/server_info`, `/listeners`, `/clusters`, `/config_dump` (secrets redacted), `/logging`, health check, `/drain_listeners` and `/quitquitquit`, with an optional token; server states, gradual or immediate draining, and a drain time for graceful shutdown |
| [Request/response logging](observability/request-logging.md) | `HttpLogger` dumps whole messages (heads, the changes the proxy and filters made, bodies on request) as readable blocks or JSON lines, with redaction |
| [Content views](guides/content-views.md) | `org.microproxy.contentviews` renders bodies readably: protobuf without a schema (YAML with field numbers, as mitmproxy shows it), gRPC message by message with its trailers and `google.rpc.Status` details, msgpack, form data, GraphQL, Socket.IO; field names from a `protoc` descriptor set; `protobuf` and `grpc` modules for scripts |
| [Throttling](guides/forward-proxy.md#throttling) | global token bucket for server reads and writes, adjustable at runtime |
| [Concurrency limiting](guides/concurrency-limiting.md) | `ConcurrencyLimiter` caps the exchanges in progress per client, user, target host or any key, with a bounded wait queue, `429` answers, a shadow mode and metrics |
| [Activity tracking](observability/activity-tracking.md) | `ActivityTracker` for connections, requests, responses (with their source), bytes, per-exchange timings and server failures |
| [HTTP/3 bypass](guides/http3.md#alt-svc-which-clients-may-move-to-http3) | removes `h3` alternatives from `Alt-Svc` by default when intercepting or transparent, so clients of an explicit or transparent proxy stay on TCP through it rather than move to QUIC |
| [Privacy](guides/forward-proxy.md#removing-tracing-headers) | optionally removes distributed tracing headers (W3C Trace Context and Baggage, B3 and other common trace headers) and any other named headers from requests sent upstream, after all filters |
| [Hardening](security.md) | rejects `Transfer-Encoding` + `Content-Length`, conflicting lengths, obs-fold in requests, and oversized lines and headers; header values are validated against CR/LF injection; Host is replaced by the absolute-form authority |

## Where to go next

- **Run it:** [Install](getting-started/install.md), then the [Quick start](getting-started/quick-start.md).
- **Embed it:** [Your first filter](getting-started/first-filter.md) and the
  [Java API (Javadoc)](java-api.md).
- **Script it:** [Your first Starlark script](getting-started/first-script.md), then
  [Scripting with Starlark](guides/scripting.md) and the [Starlark API](reference/starlark-api.md).
- **Look things up:** [command-line flags](reference/cli.md),
  [configuration properties](reference/properties.md), [stats](reference/stats.md),
  [access-log operators](reference/access-log-format.md), [response flags](reference/response-flags.md)
  and [admin endpoints](reference/admin-api.md).
- **Operate it:** [Observability](observability/access-logs.md) and [Security](security.md).
- **Compare it:** [Performance against other proxies](project/performance.md) measures MicroProxy
  against LittleProxy, Envoy, a Go and a Rust proxy and Squid, with interactive charts and the raw
  data.
- **For AI coding agents:** [`llms.txt`](https://mahmoudimus.github.io/MicroProxy/llms.txt) lists
  every page with a one-line description, and
  [`llms-full.txt`](https://mahmoudimus.github.io/MicroProxy/llms-full.txt) is the whole site as
  one Markdown file.
