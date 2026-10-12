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
  decode `zstd` bodies, the `http2-codec` jar for [HTTP/2](#http2) to clients and servers, and
  the `quic` and `http3-codec` jars for [HTTP/3](#http3-and-quic) to clients of a reverse proxy
  and to servers (`http3-codec` alone runs [frame interceptors over HTTP/3 streams](#http3-frames)).
- **Size:** about 10k lines of main code (including Javadoc and a DNSSEC resolver) plus a vendored
  Brotli decoder, compared with LittleProxy's 11k lines plus Netty and dnssec4j.
- **Scripting (optional):** the `microproxy-starlark` module drives the proxy from a
  [Starlark](https://github.com/bazelbuild/starlark) script (see [Scripting](#scripting-with-starlark)).
- **OpenTelemetry (optional):** the `microproxy-otel` module traces exchanges and exports traces,
  metrics and logs over OTLP, with no dependencies either (see [OpenTelemetry](#opentelemetry)).

| Module | Artifact | Contents |
|---|---|---|
| `zstd-decoder/` | `io.github.mahmoudimus:zstd-decoder` | a standalone pure-Java Zstandard decoder ([README](zstd-decoder/README.md)) |
| `http2-codec/` | `io.github.mahmoudimus:http2-codec` | a standalone HTTP/2 frame codec and HPACK implementation ([README](http2-codec/README.md)) |
| `http3-codec/` | `io.github.mahmoudimus:http3-codec` | a standalone HTTP/3 frame codec and QPACK implementation, used by HTTP/3 and the HTTP/3 frame pipeline ([README](http3-codec/README.md)) |
| `quic/` | `io.github.mahmoudimus:quic` | a standalone QUIC transport with its own TLS 1.3 handshake, ported from quinn and rustls, used by HTTP/3 ([README](quic/README.md)) |
| `microproxy/` | `io.github.mahmoudimus:microproxy` | the proxy; no required dependencies (`zstd-decoder`, `http2-codec`, `http3-codec` and `quic` are optional) |
| `microproxy-otel/` | `io.github.mahmoudimus:microproxy-otel` | OpenTelemetry: W3C, B3 and Jaeger propagation, spans per exchange and attempt, and OTLP/HTTP export of traces, metrics and access logs; depends on the core only ([OpenTelemetry](#opentelemetry)) |
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
MICROPROXY_VERSION=0.1.2-SNAPSHOT
mvn package
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm   # intercept HTTPS
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --dnssec --activity-log-format clf
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm --log-http headers   # dump traffic
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm --save-har flows.har    # record, then
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm --server-replay flows.har   # replay offline
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm --ignore-hosts '\.bank\.example:443$'
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8443 --reverse https://example.com   # reverse proxy
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 1080 --mode socks5 --mitm   # SOCKS5 server
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --help

# With zstd decoding:
java -cp microproxy/target/microproxy-${MICROPROXY_VERSION}.jar:\
zstd-decoder/target/zstd-decoder-${MICROPROXY_VERSION}.jar org.microproxy.Launcher --port 8080

# With HTTP/2 to clients on intercepted TLS and to servers (needs the http2-codec jar):
java -cp microproxy/target/microproxy-${MICROPROXY_VERSION}.jar:\
http2-codec/target/http2-codec-${MICROPROXY_VERSION}.jar org.microproxy.Launcher --port 8080 --mitm --http2 --http2-upstream

# The same launcher with scripting, zstd, HTTP/2, QUIC and HTTP/3 built in (one self-contained jar):
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 --script proxy.star
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 --mitm --http2

# Traces, metrics and access logs to an OpenTelemetry Collector (OTLP/HTTP on 4318):
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
    java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080

# A reverse proxy serving HTTPS, HTTP/2 and HTTP/3 (on UDP 8443), speaking HTTP/3 to servers that offer it:
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8443 \
    --mode reverse:https://example.com --listener-keystore site.p12 --listener-keystore-password secret \
    --http2 --http3 --http3-upstream

# A forward proxy on TLS (8443) that also serves HTTP/3 on UDP 8443: CONNECT, WebSockets and
# CONNECT-UDP (MASQUE) for HTTP/3 clients, the QUIC inside their UDP flows intercepted too:
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8443 \
    --listener-keystore proxy.p12 --listener-keystore-password secret --http2 --http3 \
    --mitm --masque-intercept-quic

# A transparent proxy for redirected TCP (8080) and QUIC (UDP 8443), intercepting HTTP/3 too, and
# other QUIC stream by stream through a script's on_quic_*() hooks:
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 --server \
    --transparent --transparent-quic-port 8443 --mitm --http2 --http3-upstream --script quic.star
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
MICROPROXY_VERSION=0.1.2-SNAPSHOT
# JAVA_HOME = a JDK 28 early-access build (https://jdk.java.net/28/)
mvn -Pvalhalla -pl zstd-decoder,microproxy verify     # all tests pass with value classes
java --enable-preview -cp microproxy/target/microproxy-${MICROPROXY_VERSION}-valhalla.jar org.microproxy.Launcher
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
| `transparent` | don't add `Via` or strip hop-by-hop headers, and route TLS that arrives without `CONNECT` by its SNI (see [Transparent mode](#transparent-mode)) | `false` |
| `transparent_tls_port` | the port SNI-routed transparent TLS (and QUIC) goes to | `443` |
| `transparent_quic_port` | with `transparent`, a UDP port for redirected QUIC, intercepted or relayed by its SNI (see [Transparent QUIC](#transparent-quic)) | none |
| `transparent_quic_relay_idle_timeout` | seconds a relayed QUIC flow lives without a datagram | `60` |
| `mode` | `regular`, `transparent`, `socks5` (see [SOCKS5 mode](#socks5-mode)), or `reverse:<scheme>://<host>[:<port>]` with `http`, `https` or `tcp` (see [Reverse proxy mode](#reverse-proxy-mode)) | `regular` |
| `socks` | also serve SOCKS5 and SOCKS4(a) clients on the regular listener, told apart by their first byte | `false` |
| `keep_host_header` | in reverse mode, keep the client's `Host` | `false` |
| `ignore_hosts` / `allow_hosts` | comma-separated regular expressions for `host:port` names (CONNECT target, SNI) whose TLS is tunnelled untouched / the only ones intercepted (see [Ignoring and allowing hosts](#ignoring-and-allowing-hosts)) | none |
| `tcp_hosts` | comma-separated regular expressions for host names (CONNECT target, SNI) relayed as raw TCP even when they look like HTTP (see [Raw TCP streams](#raw-tcp-streams)) | none |
| `quic_hosts` | comma-separated regular expressions for host names (server, SNI) whose intercepted QUIC is relayed stream by stream, even HTTP/3 (see [QUIC stream hooks](#quic-stream-hooks)) | none |
| `quic_framing` | comma-separated `key=framer` rules choosing, by ALPN or host, how the streams of QUIC intercepted stream by stream are cut into messages for the message hooks (see [QUIC message framing](#quic-message-framing)); added to the default | `doq=u16` |
| `quic_max_message_size` / `quic_message_error_code` | the largest framed QUIC message, in bytes, and the error code of the reset of a stream that sends a larger one | `1048576` / `2` |
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
| `strip_alt_svc_h3` | remove `h3` (HTTP/3) alternatives from `Alt-Svc` response headers (see [Alt-Svc](#alt-svc-which-clients-may-move-to-http3)) | `true` with interception or `transparent`, except for redirected clients with `transparent_quic_port`; else `false` |
| `http2` | serve HTTP/2 to clients on intercepted TLS and the proxy TLS listener (needs the `http2-codec` jar; see [HTTP/2](#http2)) | `false` |
| `http2_upstream` | speak HTTP/2 to servers that negotiate `h2` on TLS, sharing connections between exchanges (see [HTTP/2 to servers](#http2-to-servers)) | `false` |
| `http2_cleartext` | serve HTTP/2 with prior knowledge (`h2c`) on the plain listener (see [h2c](#h2c-with-prior-knowledge)) | `false` |
| `http2_max_concurrent_streams` | streams an HTTP/2 client may have open at once | `100` |
| `http2_initial_window_size` / `http2_connection_window_size` | request bytes buffered per HTTP/2 stream / per connection | `262144` / `1048576` |
| `http3` | serve HTTP/3 on the UDP port with the listener's number: in reverse mode, or in forward mode next to the TLS listener (`listener_keystore`) for `CONNECT`, WebSockets and CONNECT-UDP (needs the `quic` and `http3-codec` jars and a certificate; see [HTTP/3 and QUIC](#http3-and-quic)) | `false` |
| `http3_upstream` | speak HTTP/3 to servers known to support it, from `Alt-Svc` or `http3_upstream_hosts` (see [HTTP/3 to servers](#http3-to-servers)) | `false` |
| `http3_upstream_hosts` | comma-separated regular expressions for `host:port` names reached over HTTP/3 without waiting for `Alt-Svc` | none |
| `http3_max_concurrent_streams` | request streams an HTTP/3 client may have open at once | `100` |
| `http3_alt_svc` | with `http3`, advertise it with `Alt-Svc: h3=":<port>"` on TCP responses | `true` |
| `http3_retry` | validate QUIC clients' addresses with a Retry first (`http3` and intercepted `transparent_quic_port` clients) | `false` |
| `masque_udp_template` | the URI template CONNECT-UDP requests name their target with (see [CONNECT-UDP](#connect-udp-masque)) | `/.well-known/masque/udp/{target_host}/{target_port}/` |
| `masque_udp_idle_timeout` | seconds a CONNECT-UDP flow lives without a datagram either way | `60` |
| `masque_max_udp_flows` / `masque_max_udp_flows_per_connection` | CONNECT-UDP flows at once, and per client connection | `4096` / `64` |
| `masque_intercept_quic` | decide on the QUIC inside CONNECT-UDP flows as on transparent QUIC (see [QUIC inside CONNECT-UDP flows](#quic-inside-connect-udp-flows)) | `false` |
| `masque_quic_ports` | the target ports of the flows `masque_intercept_quic` inspects: comma-separated, or `any` | `443` |
| `http3_0rtt` | accept 0-RTT early data from resuming HTTP/3 clients (`http3`, and HTTP/3 intercepted from `transparent_quic_port` clients or inside CONNECT-UDP flows; see [Session resumption and 0-RTT](#session-resumption-and-0-rtt)) | `false` |
| `http3_upstream_0rtt` | send requests safe to replay (`GET`, `HEAD`, `OPTIONS` without a body) to HTTP/3 servers as 0-RTT data when resuming | `true` |
| `quic_congestion` | congestion control of the proxy's QUIC connections, to clients and to servers: `cubic`, `newreno` or `bbr` (experimental; see [Congestion control](#http3-congestion-control)) | `cubic` |
| `qlog_dir` / `qlog_max_files` | write a qlog file per QUIC connection into this directory (see [qlog](#qlog-files)) / how many it keeps | off / `1000` |
| `listener_keystore` / `listener_keystore_password` | serve TLS on the listener with this PKCS#12 or JKS key store's first key entry (HTTPS, HTTP/2 with `http2`, and the certificate `http3` presents) | none / empty |
| `dnssec` | resolve server names with DNSSEC validation | `false` |
| `dnssec_resolver` | DoH URL or comma-separated resolver IPs for `dnssec` | `/etc/resolv.conf` |
| `activity_log_format` | access log to the `System.Logger`: `CLF`, `ELF`, `JSON`, `JSON_EXTENDED`, `SQUID`, `W3C`, `LTSV`, `CSV`, `HAPROXY`, `ENVOY` | off |
| `access_log` | write the access log to this file, or `-` for standard output (see [Access logs](#access-logs-envoy-compatible)) | off |
| `access_log_format` | an Envoy format string, or a preset's name, for the access log | Envoy's default |
| `access_log_json` | a JSON object of keys and Envoy format strings: one JSON line per exchange | off |
| `access_log_filter` | log only what passes, e.g. `status>=500 \|\| response_flag` | everything |
| `metrics` | keep Envoy-style stats for Prometheus and statsd (see [Metrics](#metrics-envoy-compatible-stats)) | `false` |
| `stats_prefix` | prefix of exported stat names (implies `metrics`) | `envoy` |
| `admin_port` / `admin_address` | serve the [admin API](#admin-interface) on this port of `127.0.0.1` / on this `host:port` (implies `metrics`) | off |
| `admin_token` | the token the admin API requires on every path but `/ready` | none |
| `drain_time` | seconds a drain lasts, and stopping lets exchanges finish (see [Lifecycle, draining and shutdown](#lifecycle-draining-and-shutdown)) | `10` |
| `drain_strategy` | `gradual` or `immediate` | `gradual` |
| `health_check_path` / `health_check_pass_through` | answer health checks on the proxy's listener / forward healthy ones to the server | off / `false` |
| `log_http` | log whole requests and responses: `basic`, `headers` or `body` (see [Request/response logging](#requestresponse-logging)) | off |
| `log_http_format` | `text` or `json` (one object per line) for `log_http` | `text` |
| `log_http_view` | render bodies logged by `log_http` through [content views](#content-views): `auto` or a view's name | off |
| `proto_descriptors` | a protobuf `FileDescriptorSet` (`protoc --descriptor_set_out`) for field names in the protobuf and gRPC views of `log_http` (turns `log_http_view` on) | none |
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
| HTTP/3 | optional, over the proxy's own QUIC (`quic` module): a reverse proxy serves HTTP/3 on UDP (`--http3`), each request stream an exchange of its own, advertised with `Alt-Svc`; a forward proxy serves it next to its TLS listener, with `CONNECT`, WebSockets (RFC 9220) and MASQUE's CONNECT-UDP (RFC 9298); servers that advertise `h3` get their exchanges, WebSockets included, over one shared QUIC connection (`--http3-upstream`), falling back to TCP; QPACK with dynamic tables, hardened limits, live frame interception (see below) |
| Filters | `HttpFilters` / `HttpFiltersSource` with the same hooks as LittleProxy, streaming or buffered (`getMaximumRequestBufferSizeInBytes` / `getMaximumResponseBufferSizeInBytes`); several sources run in order as an `HttpFiltersChain` (`plusFiltersSource`) |
| CONNECT | byte tunnel with idle timeout and half-close; optional TCP hooks see, rewrite, drop and add the bytes of every raw tunnel, and of intercepted TLS that does not carry HTTP (SMTPS, IMAPS, MQTT over TLS), as mitmproxy's `tcp_message` (see below) |
| MITM | `MitmManager`; `CertificateAuthorityMitmManager` issues per-host certificates on demand (EC P-256). Its SANs copy the real server's DNS names. Only the JDK is used, through a small built-in X.509/DER encoder (`org.microproxy.tls.CertificateBuilder`). CA, upstream trust and client certificate can be chosen per client connection (see below) |
| ClientHello inspection | after `CONNECT`, the client's ClientHello is read without consuming it (SNI, ALPN, versions, cipher suites), and interception is decided by it: ignore / allow host rules as in mitmproxy, `MitmManager` and filter hooks; plain HTTP after `CONNECT` is served as HTTP, other protocols are tunnelled; ALPN is mirrored between client and server (see below) |
| Transparent and reverse modes | TLS redirected to the proxy without `CONNECT` is routed by SNI; `--mode reverse:https://host` serves one upstream over HTTP, HTTPS or raw TCP (see below) |
| SOCKS server | `--mode socks5` serves SOCKS5 (no authentication, or username/password through the `ProxyAuthenticator`) and SOCKS4a clients, whose requests go through the same flow as a `CONNECT`: filters, chained proxies, ClientHello inspection, interception, plain HTTP served as HTTP; `--socks` serves them on the regular listener too (see below) |
| Chained proxies | HTTP (with Basic credentials, optionally over TLS), SOCKS4a, SOCKS5 (with username/password); falls back to the next proxy or a direct connection, optionally with exponential backoff between attempts. `UpstreamProxyManager` configures them from proxy URLs, `NO_PROXY` rules or the environment |
| HTTP cache | RFC 9111 shared cache in memory or on disk, with revalidation, `Vary`, stale responses when servers are unreachable, and an offline mode (see below) |
| WARC recording | `WarcRecorder` archives traffic with servers as WARC 1.1 files for replay tools, and `WarcReader` reads them back (see below) |
| mitmproxy-style addons | `MapLocal`, `MapRemote`, `ModifyBody`, `ModifyHeaders`, `BlockList`, `AntiCache` and `StickyCookie`, with mitmproxy's option syntax and flow filter expressions (`~d example.com & !~m GET`), from Java or the command line (see below) |
| HAR export and replay | `HarRecorder` writes HAR 1.2 files; `ServerReplay` answers requests from recorded HAR or WARC responses, `ClientReplay` sends recorded requests again through the proxy (see below) |
| Body rewriting | `HttpBodies` decodes gzip, deflate, Brotli and (with `zstd-decoder`) zstd bodies and re-encodes them with the right charset; `RewriteRules` edits headers and text bodies declaratively, buffering only the responses it rewrites |
| Scripting | optional module: `on_request` / `on_response` / `upstream` / `allow_mitm` / `on_failure` / `authenticate` / `on_tcp_message` hooks in Starlark, sandboxed, with hot reload (see below) |
| Proxy authentication | `ProxyAuthenticator`: Basic by default, or any scheme (Bearer tokens, API keys) with custom challenges; per connection or per request (see below) |
| TLS listener | `withSslContextSource(...)`, optional client-certificate auth |
| TLS protocol pinning | every TLS connection (listener, both sides of interception, TLS chained proxies) allows only TLS 1.3 and 1.2 by default; `withTlsProtocols(...)` changes it (see below) |
| PROXY protocol | accept v1 and v2 (read before TLS on a TLS listener), send v1 to the final server: first on a direct connection, through the tunnel after an HTTP chained proxy accepts the CONNECT; not sent through SOCKS chained proxies or with plain requests to an HTTP chained proxy |
| WebSockets | HTTP/1 `Upgrade` and HTTP/2 extended `CONNECT` (RFC 8441), with the same frame and whole-message hooks in both directions, reading through permessage-deflate (see below) |
| Shared connection pool | optional server connection reuse across clients, with limits and idle eviction (see below) |
| DNSSEC | optional validating resolver, with no dependencies (see below) |
| Access logs | `ActivityLogger`: Envoy-compatible format strings and JSON, Envoy's response flags, filters, and one line per exchange, tunnel or UDP and QUIC flow; LittleProxy's nine formats as presets (see below) |
| Metrics | Envoy's stat names and tags (`http.*`, `cluster.*`, `listener.*`, `server.*`, `http2.*`, `http3.*`, ...) in a `StatsRegistry`, as Prometheus text, Envoy's `/stats` text and JSON, or pushed to statsd and DogStatsD; per-protocol stats (QUIC, transparent QUIC, SOCKS, CONNECT-UDP, tunnels, WebSockets) and the hooks'; bounded clusters; scripts' own `stats`; qlog files per QUIC connection (see below) |
| OpenTelemetry | optional module: W3C Trace Context (and B3, Jaeger) propagation and `X-Request-Id`, a SERVER span per HTTP/1, HTTP/2 and HTTP/3 exchange, a CLIENT span per attempt to reach the server (retries and chained proxy failover included), INTERNAL spans for tunnels and flows, sampling, and OTLP/HTTP export (protobuf or JSON) of traces, the stats as metrics and access logs as log records, from `OTEL_*` variables or `--otel` (see below) |
| Admin interface | Envoy's admin API on a listener of its own: `/stats`, `/stats/prometheus`, `/ready`, `/server_info`, `/listeners`, `/clusters`, `/config_dump` (secrets redacted), `/logging`, health check, `/drain_listeners` and `/quitquitquit`, with an optional token; server states, gradual or immediate draining, and a drain time for graceful shutdown (see below) |
| Request/response logging | `HttpLogger` dumps whole messages (heads, the changes the proxy and filters made, bodies on request) as readable blocks or JSON lines, with redaction (see below) |
| Content views | `org.microproxy.contentviews` renders bodies readably: protobuf without a schema (YAML with field numbers, as mitmproxy shows it), gRPC message by message with its trailers and `google.rpc.Status` details, msgpack, form data, GraphQL, Socket.IO; field names from a `protoc` descriptor set; `protobuf` and `grpc` modules for scripts (see below) |
| Throttling | global token bucket for server reads and writes, adjustable at runtime |
| Concurrency limiting | `ConcurrencyLimiter` caps the exchanges in progress per client, user, target host or any key, with a bounded wait queue, `429` answers, a shadow mode and metrics (see below) |
| Activity tracking | `ActivityTracker` for connections, requests, responses (with their source), bytes, per-exchange timings and server failures (see below) |
| HTTP/3 bypass | removes `h3` alternatives from `Alt-Svc` by default when intercepting or transparent, so clients of an explicit or transparent proxy stay on TCP through it rather than move to QUIC (see below) |
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

Other hooks: `onRequestBody`, `onResponseBody`, `beforeResponding`, `onFailure`, `onWebSocketMessage`,
`resolveWith`, `allowMitm`, `connectTimeout`, `bufferRequests` and `bufferResponses`. Registering a hook twice runs both in order.
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
  the methods without `FlowContext`, so existing managers work unchanged. `shouldIntercept(hello,
  flow)` decides by the client's ClientHello whether to intercept at all (see
  [below](#deciding-what-to-intercept-the-clienthello)).

An upstream context with a key (`SslContexts.withKey(key, chain, trustManagers)`) presents that
client certificate to servers that ask for one.

With `withPoolSharedMitmConnections(true)`, a pooled TLS connection carries the trust and client
certificate it was made with, so the pool keeps them apart. Connections made by a manager chosen
with `forConnection` (which `perConnection` uses) are pooled under that manager and only reused by
clients given the same one. A manager overriding `serverSslContext(host, port, flow)` or
`configureServerSocket(socket, flow)` may decide differently for every client, so its server
connections are not pooled: each client connection keeps its own. Overriding only
`clientSslContextFor(..., flow)` does not affect pooling.

### Deciding what to intercept: the ClientHello

With a MITM manager, a `CONNECT` is not intercepted blindly. The proxy connects to the server (TCP,
and through any chained proxy), answers `200`, and reads what the client sends first without
consuming it, as mitmproxy does:

- **A TLS ClientHello** is read across as many TLS records as it spans (post-quantum key shares
  make it several), up to 64 KiB and within the TLS handshake timeout, and parsed into a
  `ClientHello`: the server name (SNI), the ALPN protocols, the TLS versions and the cipher
  suites, GREASE values included. The rules below decide whether to intercept. If they do, the
  proxy shakes hands with the server first and then with the client, replaying the bytes it read
  into the JDK's handshake with `SSLSocketFactory.createSocket(socket, consumed, autoClose)`. If
  not, the bytes are relayed to the server first and the connection is a plain tunnel, so the
  client sees the real server's certificate.
- **Plain HTTP** (a request line, as a `ws://` WebSocket through a proxy sends) is served as
  HTTP: its requests go to the `CONNECT` target through the filters, as in an intercepted session
  but without TLS. Absolute-form requests and `CONNECT`s in it are proxy requests for that target,
  which the client takes for its HTTP proxy ([In front of an HTTP or HTTPS
  proxy](#in-front-of-an-http-or-https-proxy)). With `--littleproxy-compat` it is tunnelled, as
  LittleProxy does.
- **Anything else** is tunnelled, the bytes read so far first: other protocols, HTTP/2 with prior
  knowledge, and a malformed or oversized ClientHello. A server that speaks first (SMTP, SSH) is
  noticed while the proxy waits for the client, and its connection is tunnelled as well.

So it goes, too, for a tunnel that a client asks its own proxy for inside a session MicroProxy
serves, once that proxy has opened it: everything then reaches the target through that proxy's
tunnels ([In front of an HTTP or HTTPS proxy](#in-front-of-an-http-or-https-proxy)).

Interception is decided in this order; the first "no" tunnels the connection untouched:

1. `HttpFilters.proxyToServerAllowMitm()` and the [ignore rules](#ignoring-and-allowing-hosts)
   against the `CONNECT` target, when the `CONNECT` arrives. Nothing is read from the client
   then, as before.
2. With the ClientHello: the host rules against the `CONNECT` target and the SNI; a client whose
   ALPN offers no protocol the proxy speaks (only `acme-tls/1`, say; with a
   [TCP interceptor](#raw-tcp-streams), such clients are intercepted, except `acme-tls/1`, and
   their sessions relayed as raw TCP); then `MitmManager.shouldIntercept(clientHello, flow)` and
   `HttpFilters.proxyToServerAllowMitm(clientHello)`.

```java
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withIgnoreHosts("\\.bank\\.example:443$")                  // --ignore-hosts, ignore_hosts
        .withFiltersSource((request, flow) -> HttpFilters.builder()
                .allowMitmFor(hello -> !"pinned.example.com".equals(hello.sni()))
                .build())
        .start();
```

`FlowContext.getClientHello()` then returns the ClientHello to the session's requests, and to
`MitmManager.clientSslContextFor(connect, session, flow)`. Scripts get `on_client_hello` and
`ctx.client_hello` (see [Scripting](#scripting-with-starlark)).

The same applies to a `CONNECT` stream of an HTTP/2 client ([CONNECT and
WebSockets](#connect-and-websockets)). A `CONNECT` inside an intercepted session, or inside a plain
HTTP one, goes to the session's server instead ([In front of an HTTP or HTTPS
proxy](#in-front-of-an-http-or-https-proxy)): the tunnel it opens is intercepted without reading
its ClientHello, unless the host rules ignore its target.

**Server TLS failures.** As the server handshake waits for the ClientHello, it now happens after
the `CONNECT` is answered. A server whose certificate fails validation, or that refuses the
proxy's TLS versions, no longer fails the `CONNECT` with `502`. The client's handshake completes
with a certificate made from the host name, and each request inside the session is answered
`502` (`ProxyFailure.TlsFailed`, through `proxyToServerFailure` and the `FailureResponder`), as
mitmproxy answers. A server that turns out not to speak TLS gets the client's bytes tunnelled.
Unreachable servers still fail the `CONNECT`, since it is connected before it is answered. For
filters, `proxyToServerConnectionSSLHandshakeStarted` comes after the `CONNECT`'s `200`, and the
`CONNECT` exchange completes (`proxyToClientResponseSent`, `responseCompleted`) once the server
handshake is over, so its timings include that handshake.

#### Ignoring and allowing hosts

`withIgnoreHosts(...)` (`--ignore-hosts`, `ignore_hosts`) and `withAllowHosts(...)`
(`--allow-hosts`, `allow_hosts`) work as mitmproxy's options of the same names. Each pattern is a
regular expression searched for (not matched whole), ignoring case, in the connection's `host:port`
names: the `CONNECT` target, and the client's SNI with the same port. An ignored connection is
tunnelled untouched. With allow patterns, only connections that one of them finds are
intercepted, and the ignore patterns still apply to those.

| Pattern | Ignores |
|---|---|
| `example\.com` | `example.com:443`, `www.example.com:443`, `example.com.evil.test:443` |
| `^(.+\.)?example\.com:443$` | `example.com` and its subdomains, on port 443 only |
| `^10\.` | `CONNECT`s to `10.x.x.x` addresses, whatever their SNI |

On the command line each flag takes one pattern and may be repeated; in a properties file the
patterns are separated by commas (commas inside `{...}` belong to the pattern). A `CONNECT` whose
target an ignore pattern finds is tunnelled without reading its ClientHello at all. The rules
apply to TLS and QUIC only: plain HTTP requests are proxied as usual. For QUIC the names are the
server and the SNI on the server's port: [transparent QUIC](#transparent-quic)'s flows, and, with
[`--masque-intercept-quic`](#quic-inside-connect-udp-flows), the QUIC inside CONNECT-UDP flows, an
ignored one being relayed as any UDP flow is.

#### ALPN mirroring

When intercepting, the server is offered only the ALPN protocols the client offered, of those the
proxy speaks and has enabled: `http/1.1`, `http/1.0`, and `h2` only with
[HTTP/2 to servers](#http2-to-servers) on. The client's own handshake then mirrors the server's
choice when that choice tells what the server speaks, that is, when the server was offered `h2`.

| Client offers | Server offered | Server picks | Client gets |
|---|---|---|---|
| `http/1.1` | `http/1.1` | `http/1.1` | `http/1.1`: never HTTP/2 upstream |
| `h2`, `http/1.1` | `h2`, `http/1.1` | `h2` | `h2` (with `--http2`): HTTP/2 end to end |
| `h2`, `http/1.1` | `h2`, `http/1.1` | `http/1.1` | `http/1.1`, the same as the server |
| `h2`, `http/1.1` (no `--http2-upstream`) | `http/1.1` | `http/1.1` | `h2` with `--http2`: the proxy translates |
| no ALPN | `h2`, `http/1.1` with `--http2-upstream`, else none | either | no protocol (HTTP/1.1) |

This follows mitmproxy's order (`tlsconfig.py`: the server's handshake first, with the client's
offers, then the client's with the server's choice). Two differences: a client that sends no ALPN
keeps the proxy's old offer, so HTTP/1.1 clients without ALPN (such as the JDK's `HttpClient`)
still reach HTTP/2 servers; and where the server was not offered `h2`,
clients still get HTTP/2 when `--http2` allows it. Without a server connection of its own, the
session mirrors nothing: an existing HTTP/2 connection the session shares (a client that did not
offer `h2` gets none of it, and its requests connect with its own offers), a reused pooled
connection, or offline interception. The session's requests that connect later offer the same
protocols.

### Transparent mode

`--transparent` (`withTransparent(true)`, `transparent=true` or `mode=transparent`) is for
traffic redirected to the proxy rather than sent to it, by a firewall rule or a gateway. Besides
leaving out `Via` and keeping hop-by-hop headers, the listener then accepts:

- **TLS without `CONNECT`.** A connection that starts with a TLS record is routed by its
  ClientHello's SNI, to that host's port 443 (`--transparent-tls-port`, `transparent_tls_port`),
  and treated like a `CONNECT` to it: filters see a `CONNECT` the proxy made up (it gets no answer
  on the wire), and the host rules, hooks and interception apply. Without a MITM manager, such
  connections are tunnelled: an SNI proxy.
- **Plain HTTP**, routed by its `Host` field, when origin-form requests are allowed
  (`--allow-requests-to-origin-server`, `allow_requests_to_origin_server=true`), as before.
- **QUIC** on a UDP port of its own, with `--transparent-quic-port <port>`
  (`withTransparentQuicPort`, `transparent_quic_port`): routed by the SNI of the ClientHello in
  its first packets, then intercepted (HTTP/3, or other protocols stream by stream) or relayed by
  the same rules (see [Transparent QUIC](#transparent-quic)).

Java cannot read a redirected connection's original destination (Linux's `SO_ORIGINAL_DST`), so
the server is the one the SNI or the `Host` field names, not the address the client connected to.
The client choosing the server is by design here, as it is for any forward proxy: a transparent
proxy takes the client where it was going. Put it where only the clients it serves can reach it.
Inside an SNI-routed session, an absolute URI is a request for that session's server (as for a
proxy, [below](#in-front-of-an-http-or-https-proxy)), never for the URI's authority.
A ClientHello without SNI (clients connecting to an IP address send none) cannot be routed: the
proxy answers with a TLS `unrecognized_name` alert, closes the connection and reports it to
`ActivityTracker.connectionExceptionCaught`. Such clients cannot send proxy credentials: with
proxy authentication, their connections are closed unless the authenticator accepts them without.

Redirecting a machine's outgoing web traffic to a proxy on port 8080, running as the user `proxy`
so that its own connections are not redirected again:

```bash
iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner proxy --dport 80 -j REDIRECT --to-ports 8080
iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner proxy --dport 443 -j REDIRECT --to-ports 8080
# On a gateway, for the clients behind it (eth1), use PREROUTING instead:
#   iptables -t nat -A PREROUTING -i eth1 -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8080
sudo -u proxy java -jar microproxy.jar --server --port 8080 --transparent --mitm \
    --allow-requests-to-origin-server --ignore-hosts '\.bank\.example:443$'
```

Clients must trust the proxy's CA (`microproxy-ca.pem`) for the hosts that are intercepted. QUIC
(UDP 443) is not redirected by these rules: redirect it to a [transparent QUIC](#transparent-quic)
port too, or block it so that browsers fall back to TCP.

### Reverse proxy mode

`--mode reverse:https://example.com` (or `--reverse https://example.com`,
`withReverseProxy("https://example.com")`, `mode=reverse:https://example.com`) makes the proxy a
server for one upstream, in mitmproxy's specification syntax: `[scheme://]host[:port]`, the
scheme `https` by default, the port 443 for `https` and 80 for `http`.

- Every request goes to the upstream, whatever it names. Origin-form requests (`GET /path`) are
  accepted, and absolute-form ones are made origin-form. As in an intercepted session, a filter
  that gives a request an absolute URI of its own (`MapRemote`, a script assigning `req.uri`)
  sends it to that URI's server instead.
- **The client never picks the server.** Nothing a client sends chooses where its request goes,
  so a reverse proxy cannot be used to reach other hosts (server-side request forgery): an
  absolute-form URI (`GET http://127.0.0.1:6379/`) is made origin-form for the upstream before
  any filter sees it, as mitmproxy's reverse mode sets the upstream's address on every request,
  and its authority survives only as the `Host` that `--keep-host-header` keeps; an HTTP/2
  `:authority` chooses nothing either; and `CONNECT` is refused with `400`, with or without a
  MITM manager, as mitmproxy refuses it outside its regular and upstream modes. Only filters and
  scripts may send a request elsewhere: an absolute URI that a filter sets is followed, the one
  the client sent never is.
- `Host` is set to the upstream's (`example.com`, with the port unless it is the scheme's
  default) before any filter sees the request, unless `--keep-host-header` (`keep_host_header`,
  `withKeepHostHeader(true)`) keeps the client's.
- `https://` upstreams are reached over TLS, validated with the MITM manager's server context
  when one is configured (`--mitm-trust-all` works too) and the JVM's trust store otherwise; with
  `--http2-upstream`, over HTTP/2 when the upstream offers it. `http://` upstreams get plain HTTP.
- `tcp://host:port` relays each client connection to the upstream as raw bytes.
- With a TLS listener (`withSslContextSource`, `--listener-keystore`), the proxy terminates TLS,
  and with `--http2` serves HTTP/2 to clients that offer it. With `--http3`, it serves HTTP/3 on
  the UDP port with the same number, and advertises it with `Alt-Svc` (see
  [HTTP/3 and QUIC](#http3-and-quic)); with `--http3-upstream`, it speaks HTTP/3 to an upstream
  that offers it.
- Filters, scripts, the cache, logging and failure answers work as for any request.

### SOCKS5 mode

`--mode socks5` (`withSocksServer(true)`, `mode=socks5`) makes the listener a SOCKS server, as
mitmproxy's `socks5` mode does: SOCKS5 ([RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)), and
SOCKS4 and 4a as well. `--socks` (`withSocksDetection(true)`, `socks=true`) serves SOCKS clients on
the regular listener besides HTTP ones, told apart by their first byte: `0x05` for SOCKS5, `0x04`
for SOCKS4 and 4a, which no HTTP request, TLS record or HTTP/2 preface starts with.

```bash
java -jar microproxy.jar --port 1080 --mode socks5 --mitm
curl --socks5-hostname 127.0.0.1:1080 http://example.com/              # the proxy resolves the name
curl --proxy socks5h://127.0.0.1:1080 --cacert microproxy-ca.pem https://example.com/   # intercepted
curl --socks5 127.0.0.1:1080 http://example.com/                       # curl resolves, sends an address
curl --socks4a 127.0.0.1:1080 http://example.com/

java -jar microproxy.jar --port 8080 --socks --mitm   # HTTP and SOCKS clients on one port
curl --proxy socks5h://127.0.0.1:8080 https://example.com/ --cacert microproxy-ca.pem
curl --proxy http://127.0.0.1:8080 https://example.com/ --cacert microproxy-ca.pem
```

With proxy authentication, SOCKS5 clients give a username and password:

```java
MicroProxy.bootstrap()
        .withPort(1080)
        .withSocksServer(true)
        .withProxyAuthenticator((user, password) -> "alice".equals(user) && "secret".equals(password))
        .start();
```

```bash
curl --proxy socks5h://alice:secret@127.0.0.1:1080 http://example.com/
```

| Flag | Property | Bootstrap | |
|---|---|---|---|
| `--mode socks5` | `mode=socks5` | `withSocksServer(true)` | the listener serves SOCKS clients only; others are closed |
| `--socks` | `socks=true` | `withSocksDetection(true)` | the regular listener serves SOCKS clients too |
| `--tls-handshake-timeout` | `tls_handshake_timeout` | `withTlsHandshakeTimeout` | also bounds the SOCKS handshake, up to the request |

**One request, one `CONNECT`.** Only the `CONNECT` command is served; `BIND` and `UDP ASSOCIATE`
are answered "command not supported". The destination (an IPv4 or IPv6 address, or a host name,
which the proxy resolves) becomes a `CONNECT` the proxy makes up, which then goes exactly where an
HTTP client's `CONNECT` goes:

- the filters see it (`clientToProxyRequest`, `proxyToServerRequest`, `proxyToServerAllowMitm`,
  ...), and so do `ActivityTracker`s, the access and request logs, `FlowContext.timings()` and
  scripts; its answer is the `200` the client would have got, or the failure;
- routing: the `ChainedProxyManager`, chained HTTP and SOCKS proxies, `NO_PROXY` rules, backoff;
- then the client's first bytes decide, as after a `CONNECT`
  ([Deciding what to intercept](#deciding-what-to-intercept-the-clienthello)): a ClientHello is
  intercepted with the MITM manager unless the [host rules](#ignoring-and-allowing-hosts), its SNI
  and ALPN, the manager or a filter decline it; plain HTTP is served as HTTP, its requests going to
  the destination through the filters; anything else is tunnelled;
- the [TCP hooks](#raw-tcp-streams) see its tunnels as they see a `CONNECT`'s, and an intercepted
  TLS session that does not carry HTTP (or one with a [TCP host](#raw-tcp-streams)) is relayed
  decrypted through them.

A SOCKS client has no other way to send plain HTTP through the proxy, so its first bytes are read
even without `--mitm`: its HTTP requests are filtered and logged, and its TLS is tunnelled.
`FlowContext.socksVersion()` (5, or 4 for SOCKS4 and 4a; empty for HTTP clients) and Starlark's
`ctx.socks_version` tell SOCKS clients apart.

**Connected, then answered.** As mitmproxy does, the proxy connects to the server (or through its
chained proxy) before it answers the request, so the client learns why a connection failed. The
ClientHello is read only after the answer, since a client sends it only then; this is the order of
an HTTP `CONNECT`, whose `200` is written once the server is connected and whose server handshake
waits for the ClientHello (ALPN mirroring included).

| Failure | SOCKS5 reply |
|---|---|
| The host name does not resolve (`UnresolvedHost`) | `0x04` host unreachable |
| The connection is refused | `0x05` connection refused |
| No route to the host / the network | `0x04` host unreachable / `0x03` network unreachable |
| The connect timeout passed | `0x06` TTL expired |
| The authenticator (checking every request), a filter or the `ChainedProxyManager` refused it | `0x02` not allowed by ruleset |
| Anything else (a chained proxy failed, the pool is exhausted, a filter answered with a `5xx`) | `0x01` general failure |

SOCKS4 replies have only "granted" (90) and "rejected" (91).

**Authentication.** Without a [proxy authenticator](#proxy-authentication), SOCKS5 clients must
offer "no authentication". With one, they authenticate with a username and password
([RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)), which the authenticator sees as
`Proxy-Authorization: Basic` on a made-up `CONNECT` whose target is not known yet (`0.0.0.0:0`),
so `authenticate(user, password)`, request-aware authenticators and a script's `authenticate` hook
all work, and the accepted user is `ClientDetails.getUserName()`. A client that offers no
credentials, SOCKS4's included (its user id is not a credential), is let in only if the
authenticator accepts that request without them; otherwise SOCKS5 clients get "no acceptable
methods" (`0xFF`) and SOCKS4 clients a rejection. With `authenticateEveryRequest()`, the request's
own `CONNECT`, with its destination and the same credentials, is authenticated again.

**Hardening.** The handshake, from the first byte to the request, must finish within the TLS
handshake timeout (`--tls-handshake-timeout`, 10 seconds by default; with `0`, each read within the
idle timeout). SOCKS5 fields are bounded by their one-byte lengths, SOCKS4's user id and host name
by 255 bytes; host names may hold only letters, digits, `.`, `-` and `_` (or an IP literal).

Not supported: `BIND`, `UDP ASSOCIATE` (and so DNS or QUIC through SOCKS), GSSAPI authentication,
SOCKS on a TLS listener or together with a reverse proxy, and mitmproxy's `@port` listen suffix
(use `--port`).

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
- **Resumption over TCP is the JDK's.** TLS over TCP (HTTPS, HTTP/2, intercepted sessions, TLS
  chained proxies) runs on the JDK's `SSLEngine`, which resumes sessions on its own: each
  `SSLContext` caches sessions (`SSLSessionContext`, `javax.net.ssl.sessionCacheSize`,
  `jdk.tls.server.enableSessionTicketExtension` for stateless TLS 1.3 tickets) and offers them
  when it connects to the same server again. The proxy adds nothing to it, and the JDK sends and
  accepts no 0-RTT data. QUIC's TLS is the `quic` module's own, with its own tickets and 0-RTT
  ([Session resumption and 0-RTT](#session-resumption-and-0-rtt)).
- A server that refuses the proxy's versions with a `protocol_version` alert gets the requests
  inside the session a `502` (`TlsFailed`; see [server TLS
  failures](#deciding-what-to-intercept-the-clienthello)). One that just closes the connection on
  the proxy's `ClientHello` looks like a server that does not speak TLS, and the client's bytes
  are tunnelled without interception, as for any non-TLS server.

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
`http/1.1` through ALPN. A client that offers `h2` gets it, unless an intercepted server that was
offered `h2` chose `http/1.1` (see [ALPN mirroring](#alpn-mirroring)). Any other client keeps HTTP/1.1 as
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
ALPN (before `MitmManager.configureServerSocket`, which may change that). An intercepted client
that sent ALPN has its own offer mirrored instead: one that offered only `http/1.1` never gets
HTTP/2 upstream (see [ALPN mirroring](#alpn-mirroring)). A server that picks `h2`
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
works through the intercepting proxy with `--mitm --http2 --http2-upstream`. To read the calls,
log them with [content views](#content-views) (`--log-http-view auto`), which decode each
message and the status trailers; scripts can decode and rewrite messages with the
[`protobuf` and `grpc` modules](#scripting-with-starlark).

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
([Deciding what to intercept](#deciding-what-to-intercept-the-clienthello)). A server that does not speak
TLS gets a plain tunnel instead. A
`CONNECT` inside an intercepted session, for any authority, goes to the intercepted server, which
the client takes for its HTTPS proxy ([below](#in-front-of-an-http-or-https-proxy)).

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
`HTTP/2.0`, its resource URI and generated HTTP/1 upgrade headers. Response filters and trackers
see the handshake's answer as a `101` with `Upgrade: websocket` and `Connection: Upgrade`, as for an
HTTP/1.1 client, whichever protocol the origin speaks; the proxy sends it to an HTTP/2 client as
`200`, and `upstreamStatus` retains the origin's actual status.
`webSocketFrameReceived`, `filterWebSocketFrame` and `filterWebSocketMessage` use the same parser
and relay as HTTP/1, including masking, rewriting, dropping, fragmentation, message joining,
permessage-deflate and the buffer and message limits (see [WebSocket frames and
messages](#websocket-frames-and-messages)).
A filter that rejects the handshake finishes the exchange without starting the relay.

**Remaining limits.** A request for an authority other than the intercepted one gets `421
Misdirected Request`, which makes the client retry on a connection of its own; so does an extended
`CONNECT` (`:protocol websocket`) for another authority. A plain `CONNECT`, and a `:scheme http`
request, are proxy requests, forwarded instead ([below](#in-front-of-an-http-or-https-proxy)). The proxy does not originate TLS for ordinary absolute `https://` URLs sent in plain HTTP (or
ordinary `:scheme https` requests on a forward-proxy HTTP/2 connection); secure WebSocket extended
CONNECT is the exception described above. HTTP/2 chained proxies are not supported.

#### In front of an HTTP or HTTPS proxy

A client may be set up to use an HTTPS proxy, such as a corporate egress proxy `corp.example:443`
that speaks TLS (and often HTTP/2) on its listener, with MicroProxy in front of it intercepting
the client's `CONNECT corp.example:443`. Inside that session the client asks what it takes for its
proxy for a tunnel per site: a `CONNECT` stream over HTTP/2 (`:authority github.com:443`, no
`:protocol`), or `CONNECT github.com:443 HTTP/1.1` over HTTP/1.1, and plain-HTTP URIs as proxy
requests: `GET http://example.com/ HTTP/1.1` (absolute-form), or a stream with `:scheme http` and
`:authority example.com`.

A client may use a plain-HTTP forward proxy the same way, such as a Squid at `corp.example:3128`:
it sends `CONNECT corp.example:3128`, then speaks plain HTTP in the tunnel, which MicroProxy (with
a MITM manager) serves as a plain session ([Deciding what to
intercept](#deciding-what-to-intercept-the-clienthello)). Inside it the client sends what it would
send that proxy: absolute-form requests, and `CONNECT github.com:443 HTTP/1.1`.

In both cases MicroProxy forwards these proxy requests to the session's server, as the client
intended, rather than to `github.com` or `example.com` itself, which would bypass the proxy the
client chose. (Without a MITM manager, the `CONNECT` to the proxy is a tunnel, and everything in it
reaches the proxy untouched.)

```java
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withHttp2(true)
        .withHttp2Upstream(true)              // CONNECT streams on the HTTP/2 connection to the proxy
        .withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
            @Override
            public boolean proxyToServerAllowMitm() {
                // Intercept the session with the proxy, but not the tunnels through it.
                return ctx.forwardedVia().isEmpty();
            }
        })
        .start();
```

- **Upstream.** The session's server is a chained proxy for the tunnel. When MicroProxy's
  connection to an HTTPS proxy negotiated HTTP/2 (`withHttp2Upstream`), the `CONNECT` is a stream
  on that connection, multiplexed with the session's requests. Otherwise it goes on an HTTP/1.1
  connection to it, over TLS to an HTTPS proxy and plain TCP to an HTTP one: an idle one of the
  session's, or one made as the session's are (the same routes, the MITM manager's trust and
  `configureServerSocket`, the same isolation; through an HTTP chained proxy, a tunnel to it).
  Connections that carry a client's credentials for the proxy are never pooled or shared with
  other clients.
- **Proxy requests.** An absolute-form request goes to the proxy as it was sent: absolute-form,
  with `Host` from its URI; over HTTP/2 to an HTTPS proxy, as `:scheme http` and the target's
  `:authority`. It goes on the session's own connections to the proxy, never pooled ones (nor ones
  that hand an HTTP chained proxy its requests), by the routes to the proxy.
- **Fields, both ways.** The client's fields go with the `CONNECT` or the proxy request,
  `Proxy-Authorization` included (those credentials are for the proxy; MicroProxy's own
  authentication covered the outer `CONNECT`), without hop-by-hop fields and with `Via`. The
  proxy's answer reaches the client as it was sent: a `407` with its `Proxy-Authenticate`
  challenge, a `403`, the response it fetched, or the `2xx` that opens the tunnel. An HTTP/1.1
  client can retry on the same session after a refusal.
- **Filters.** A proxy request is a request of the session: `clientToProxyRequest`,
  `proxyToServerRequest` (which may rewrite a `CONNECT`'s target), then `serverToProxyResponse`
  and `proxyToClientResponse` for the proxy's answer; a short-circuit response (a `403`, say)
  rejects it. `FlowContext.forwardedVia()` names the proxy (`host:port`) for it and for the
  requests inside the tunnel a `CONNECT` opens; scripts see `ctx.forwarded_via`.
- **The client's URIs, and the filters'.** Only an absolute URI the client sent itself makes a
  proxy request. A filter or script that gives a request an absolute URI of its own (`MapRemote`,
  `req.uri = "https://..."`) sends it straight to that URI's server, as in any intercepted
  session, and `forwardedVia()` is then empty; one that leaves the client's URI as it was keeps it
  a proxy request. A client's absolute-form request to a server that is not a proxy is legal, if
  rare, and goes there as sent too: the client chose that server.
- **The tunnel.** Once the proxy has opened it, the tunnel goes on as a `CONNECT` to MicroProxy
  would ([Deciding what to intercept](#deciding-what-to-intercept-the-clienthello)), with the
  proxy's tunnel as the way to the target. Without interception for the target
  (`proxyToServerAllowMitm`, `allow_mitm` in scripts, an ignore rule for the target, or a MITM
  manager that declines), its bytes are relayed as they are. Otherwise the client's first bytes
  decide: a ClientHello goes through the host rules (with its SNI), `shouldIntercept` and
  `proxyToServerAllowMitm(clientHello)`, and when intercepted, MicroProxy's own TLS to the target
  runs inside the tunnel, offering the client's ALPN protocols, and the client gets the target's
  choice; plain HTTP is served as HTTP, its requests going through the filters; anything else, a
  declined ClientHello, a [TCP host](#raw-tcp-streams) or a server that speaks first (noticed
  through the tunnel) is relayed as it is, through the TCP hooks, as is intercepted TLS that does
  not carry HTTP. Relayed bytes go under flow control both ways; END_STREAM and half-closes go
  through (over an HTTP/1.1 TLS connection to the proxy, where TLS 1.3 allows one). Every other
  connection to the target, for the requests of an intercepted or plain session in the tunnel, is
  a tunnel through the same proxy, opened with the same `CONNECT` fields, never pooled;
  `FullFlowContext.getChainedProxy()` names the proxy. A target that does not speak TLS to a
  client that does gets a plain tunnel, a new one.
- **Resets.** A client's reset of the stream resets the stream to the proxy (or closes the
  connection to it), and once the tunnel is open it is not a rapid reset. A reset from the proxy,
  or its connection closing, resets the client's stream.

Over HTTP/2, `:scheme https` requests for another authority still get `421` (connection
coalescing, above), and so does a WebSocket's extended `CONNECT`, which is not forwarded.

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

HTTP/3 has its own section: [HTTP/3 and QUIC](#http3-and-quic).

#### Frame interception

A `FrameInterceptor` (`org.microproxy.frames`) sees every HTTP/2 frame on live connections and may
edit, drop and add frames. It is set once per proxy, not per exchange, because SETTINGS, PING and
GOAWAY belong to a connection:

```java
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withHttp2(true).withHttp2Upstream(true)
        .withFrameInterceptor((frame, direction, ctx) -> switch (frame) {
            case Http2Frame.Headers h when direction == FrameDirection.TO_SERVER -> h.withHeader("x-via-h2", "1");
            case Http2Frame.Data d when direction == FrameDirection.FROM_SERVER && d.text().contains("secret") ->
                    d.withText(d.text().replace("secret", "******"));        // same length: content-length still holds
            case Http2Frame.Priority p -> null;                              // drop
            default -> frame;                                                // pass through
        })
        .start();
```

- **Frames.** `Http2Frame` is a sealed interface of records: `Data`, `Headers` (the decoded field
  list, pseudo-headers included, with CONTINUATION folded in), `Priority`, `RstStream`, `Settings`,
  `PushPromise`, `Ping`, `GoAway`, `WindowUpdate` and `Unknown` (extension frames, which the proxy
  otherwise discards unread). `Http3Frame` has `Data`, `Headers`, `Settings`, `GoAway`,
  `CancelPush`, `MaxPushId`, `PushPromise` and `Unknown`. Edit them with their `with...` methods.
- **Directions.** The proxy terminates HTTP/2 on each side, so each hop has its own frames:
  `FROM_CLIENT` (after decoding, before the proxy acts on them), `TO_CLIENT` (before encoding),
  `FROM_SERVER` and `TO_SERVER`. A request seen `FROM_CLIENT` is a different set of frames from the
  one later seen `TO_SERVER`: other stream ids, header blocks and DATA boundaries.
- **Context.** `FrameContext` gives the protocol, the client connection's id, the client's address,
  the server (`host:port`, on the server side), the stream id, the exchange's `FlowContext` when
  the frame belongs to one, and `send(frame)`, which adds a frame after this one on the same hop
  and in the same direction (going out it is sent next; coming in the proxy processes it as if the
  peer had sent it).
- **Coverage.** Clients on intercepted TLS, `h2c` and the TLS listener; connections to servers
  with all their multiplexed streams; full-duplex gRPC; `CONNECT` tunnels and WebSockets over
  HTTP/2, whose bytes are DATA frames. DATA the proxy sends is shown in pieces of at most 16 KiB.
  And live HTTP/3, on both sides, under the same rules adapted to HTTP/3 (see
  [HTTP/3 frames](#http3-frame-interception)).
- **Cost.** Without an interceptor nothing changes: no conversion, no allocation, no call.

The proxy stays protocol-correct whatever the interceptor returns. What it accepts:

| Frame | May be edited | May be dropped | May be followed by (`ctx.send`) |
|---|---|---|---|
| DATA | the payload, to any size | yes | DATA; HEADERS (trailers), last, when the frame ends the stream; extension frames |
| HEADERS | the fields | no | HEADERS; extension frames |
| PRIORITY | everything but the stream | yes | extension frames |
| RST_STREAM | the error code | no | extension frames |
| SETTINGS | received: values, only to make the proxy stricter; sent: only extension settings | no | extension frames |
| GOAWAY | the error code and debug data | no | extension frames |
| extension (`Unknown`) | everything | yes | extension frames |
| SETTINGS ACK, PING, WINDOW_UPDATE | nothing (the proxy's own flow control and liveness) | no | nothing |

- **Stream ids and END_STREAM are the proxy's.** Frames stay on their stream (extension frames may
  also use stream 0). When the frame ended its stream, the last DATA or HEADERS frame of the result
  does; a dropped DATA frame that ended its stream is replaced by an empty DATA frame with
  END_STREAM. What the interceptor sets is ignored.
- **Header fields** must be valid (`Field.validate`: lower-case token names, known pseudo-headers
  first, no connection-specific fields, no CR, LF or NUL in values). HPACK is never at risk: blocks
  are decoded once on arrival and encoded once on sending. A malformed request or response the
  proxy receives resets its stream, as usual. Changing a body's length while its HEADERS declare
  `content-length`: fix or remove the field in the HEADERS too (the interceptor sees them first),
  or the proxy resets the stream as malformed.
- **SETTINGS received** may lower `HEADER_TABLE_SIZE`, `INITIAL_WINDOW_SIZE`, `MAX_FRAME_SIZE` (not
  below 16384), `MAX_CONCURRENT_STREAMS` and `MAX_HEADER_LIST_SIZE`, or clear `ENABLE_PUSH` and
  `ENABLE_CONNECT_PROTOCOL`; the proxy then uses the edited values (fewer streams to a server, say).
- **Flow control.** Received DATA counts against the windows, and is credited back, at its size on
  the wire, whatever the interceptor makes of it. DATA the proxy sends waits for window at its size
  after interception. Rate limits count frames as they arrive.
- **Illegal results and failures.** A result that breaks a rule is rejected as a whole: it is
  logged (logger `org.microproxy.impl.Http2Frames`, `WARNING`) and the original frame goes on, as
  it does when the interceptor throws. `ctx.send` after the call has returned throws
  `IllegalStateException`.
- **Threads.** The interceptor is called from many threads at once and must be thread-safe. The
  HEADERS that open a stream to a server are intercepted while that connection's writes are held,
  so stream ids stay in order: keep that call short.

Scripts get the same with [`on_frame`](#frames).

### HTTP/3 and QUIC

MicroProxy speaks HTTP/3 ([RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114)) over its own
QUIC transport, the [`quic`](quic/README.md) module (ported from quinn and rustls), with
[`http3-codec`](http3-codec/README.md) for frames and QPACK. It does so in four places: to the
clients of a reverse proxy, to the clients of a [forward proxy](#an-http3-forward-proxy-listener)
that serves it next to its TLS listener (for `CONNECT`, WebSockets and MASQUE), to clients whose
QUIC is redirected to a [transparent proxy](#transparent-quic) or carried in a
[CONNECT-UDP flow](#quic-inside-connect-udp-flows), and to origin servers known to support it. QUIC
that carries another protocol can be intercepted too, its streams relayed through
[hooks](#quic-stream-hooks). All need the optional
`quic` and `http3-codec` jars on the class path (the `microproxy-starlark` `-all` jar bundles
them); a proxy started with HTTP/3 enabled without them fails at startup with an
`IllegalStateException` that says so, and without HTTP/3 nothing loads them.

```java
MicroProxy.bootstrap()
        .withReverseProxy("https://backend.internal")                     // --mode reverse:https://backend.internal
        .withSslContextSource(new KeyStoreSslContextSource(Path.of("site.p12"), password))  // --listener-keystore site.p12
        .withHttp3(true)                                                   // to clients: --http3, http3=true
        .withHttp3Upstream(true)                                           // to servers: --http3-upstream, http3_upstream=true
        .withHttp3UpstreamHosts("\\.internal:")                            // --http3-upstream-hosts, http3_upstream_hosts
        .withHttp3Options(Http3Options.builder().maxConcurrentStreams(200).build())   // optional
        .start();
```

```bash
java -jar microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8443 --mode reverse:https://backend.internal \
    --listener-keystore site.p12 --listener-keystore-password secret --http3 --http3-upstream
```

#### Serving HTTP/3 in reverse mode

With `--http3` (`withHttp3(true)`, `http3=true`) and `--mode reverse:...`, the proxy opens a UDP
listener on the TCP listener's port number and serves HTTP/3 there (ALPN `h3`).

- **Certificate.** The HTTP/3 listener presents the TLS listener's certificate: its
  `SslContextSource` gives it as `KeyMaterial` (`getKeyMaterial`), which
  `KeyStoreSslContextSource` (`--listener-keystore`, `listener_keystore`) and
  `SelfSignedSslContextSource` do; QUIC runs its own TLS 1.3 handshake and needs the key itself,
  not an `SSLContext`. Without a TLS listener, a `CertificateAuthorityMitmManager` (`--mitm`)
  issues one for the name the client asks for. With neither, the proxy fails at startup.
- **Exchanges.** Each request stream is an exchange like any HTTP/1 or HTTP/2 request, on a
  virtual thread of its own: filters, the cache, authentication (per stream, as on `h2c`),
  logging, WARC and HAR recording, timings and trackers all apply. The request is an
  `HttpRequest` with version `HTTP/3.0` (`HttpVersion.HTTP_3_0`), `FlowContext.getHttpVersion()`
  says `HTTP/3.0` and `getStreamId()` gives the QUIC stream id, and scripts see
  `req.http_version == "HTTP/3"`. The upstream gets it as HTTP/1.1, HTTP/2 (`--http2-upstream`)
  or HTTP/3 (`--http3-upstream`), whichever it speaks: a body without `content-length` goes chunked
  to an HTTP/1.1 server, trailers go through end to end where both sides carry them, and
  `100-continue` and `103 Early Hints` reach the client as interim responses.
- **Advertising.** Responses sent over TCP get `Alt-Svc: h3=":<port>"; ma=86400`, so that clients
  find the HTTP/3 listener, unless the server's own `Alt-Svc` field is left after the `h3`
  stripping (below), which then goes to the client as it is; a `proxyToClientResponse` filter may
  remove the field. `Http3Options.altSvc(false)` (`--no-http3-alt-svc`, `http3_alt_svc=false`)
  turns it off, and `altSvcMaxAge` sets `ma`. Browsers act on `Alt-Svc` only over HTTPS, so pair
  HTTP/3 with a TLS listener.
- **WebSockets** over extended `CONNECT` (RFC 9220) reach the upstream as described
  [below](#websockets-over-http3); `CONNECT` is refused with `400`, as over HTTP/1 and HTTP/2, and
  CONNECT-UDP with `501`. There is no server push, and no HTTP datagrams (SETTINGS_H3_DATAGRAM is
  not sent, nor QUIC DATAGRAM frames accepted).

**Limits** (of every HTTP/3 connection to clients). Much of HTTP/2's defence is QUIC's in HTTP/3: the stream limit and flow control are
the transport's, which a peer cannot exceed without a QUIC error. The proxy's own limits are set
with `Http3Options` (or `http3_*` properties and `--http3-max-streams`); rate limits count per
window of 10 seconds (`rateWindow`).

| Limit | Default | When exceeded | Setting |
|---|---|---|---|
| Request streams open per connection | 100 | QUIC holds new streams back until one ends | `maxConcurrentStreams` |
| Bytes a peer sends ahead of the proxy, per stream / per connection | 256 KiB / 1 MiB (QUIC flow control) plus 64 KiB read ahead per stream | QUIC `FLOW_CONTROL_ERROR` | `streamReceiveWindow` / `connectionReceiveWindow` |
| Field section (names and values plus 32 per field), SETTINGS_MAX_FIELD_SECTION_SIZE | `max_header_size` + `max_initial_line_length` (24 KiB) | `431` for a request (the connection goes on), `502` for a response | `maxFieldSectionSize` |
| QPACK dynamic table, each way | 4096 bytes | `QPACK_ENCODER_STREAM_ERROR` | `qpackMaxTableCapacity` |
| Streams blocked on the peer's QPACK encoder stream | 16, each for at most `idle_connection_timeout` | `QPACK_DECOMPRESSION_FAILED` / the stream is rejected | `qpackBlockedStreams` |
| Frames of unknown and reserved types, and empty DATA frames | 1000 per window | `H3_EXCESSIVE_LOAD` | `maxUnknownFrames` |
| Unidirectional streams of unknown and reserved types | 100 per window (each abandoned with `STOP_SENDING`) | `H3_EXCESSIVE_LOAD` | `maxUnknownStreams` |
| Requests reset by the client before their response completed (Rapid Reset) | 100 per window | `H3_EXCESSIVE_LOAD` | `maxRapidResets` |
| A connection with nothing to do | `idle_connection_timeout` (70 s) | QUIC's idle timeout closes it | `withIdleConnectionTimeout` |
| Client address validation (QUIC Retry) | off | | `retry` |

<a id="http3-congestion-control"></a>**Congestion control.** The proxy's QUIC connections, those
its HTTP/3 and transparent QUIC listeners accept and those it opens to servers, use CUBIC by
default. `--quic-congestion newreno` or `bbr` (`quic_congestion`,
`Http3Options.quicCongestionControl`) chooses NewReno or BBR. BBR, ported from quinn and
experimental there too, paces at its estimate of the path's bandwidth rather than backing off on
every loss, so it keeps its throughput on paths with random loss (wireless links, long distances)
where CUBIC collapses; it is not tuned for sharing a bottleneck fairly. See the [quic
module](quic/README.md#connection-internals) for its behaviour and limits.

Protocol violations close the connection with the code RFC 9114 or RFC 9204 names: a second
control or QPACK stream or a push stream from a client (`H3_STREAM_CREATION_ERROR`), frames out of
place (`H3_FRAME_UNEXPECTED`, `H3_MISSING_SETTINGS`), a critical stream that ends
(`H3_CLOSED_CRITICAL_STREAM`), bad settings (`H3_SETTINGS_ERROR`), bad QPACK. Malformed requests
(missing or repeated pseudo-headers, upper-case or connection-specific fields, a
`content-length` the DATA does not match) only reset their stream, with `H3_MESSAGE_ERROR`.

**Shutting down.** A graceful stop (`stop()`) sends `GOAWAY` naming the first stream the proxy
will not process; streams opened after it are refused with `H3_REQUEST_REJECTED`, which clients
retry elsewhere, the streams in progress finish (for up to the graceful stop timeout), and the
connection closes once the client has closed it, or after two seconds.

#### An HTTP/3 forward-proxy listener

With `--http3` (`withHttp3(true)`, `http3=true`) on a forward proxy whose own TLS listener is on
(`--listener-keystore`, `withSslContextSource`), the proxy also serves HTTP/3 on UDP at the TCP
listener's port, with the same certificate. Browsers send HTTP/3 only to origins, never to a
proxy; this listener is for clients configured to use an HTTP/3 proxy, MASQUE clients first:
they tunnel TCP with `CONNECT`, WebSockets with extended `CONNECT`, and UDP (QUIC included) with
CONNECT-UDP, all over one QUIC connection to the proxy.

- **Proxy requests.** A request names its target with `:scheme` and `:authority`, and goes on as
  an HTTP/1 client's absolute-form proxy request does: filters see `http://host:port/path` with
  version `HTTP/3.0`. Every authority is served (no `421`: a forward proxy's requests name their
  targets), and no `Alt-Svc` is added (a forward proxy's responses are its servers').
- **Proxy authentication** applies per stream, as on `h2c`: a stream without valid credentials
  gets `407` with `proxy-authenticate`, and the connection goes on.
- **SETTINGS.** The listener sends SETTINGS_ENABLE_CONNECT_PROTOCOL and SETTINGS_H3_DATAGRAM,
  and accepts QUIC DATAGRAM frames (the `max_datagram_frame_size` transport parameter). The
  reverse proxy's listener and intercepted transparent QUIC send neither datagram setting and
  refuse DATAGRAM frames.
- **Not served.** A forward proxy without a TLS listener, and a transparent proxy (whose clients'
  QUIC goes to `--transparent-quic-port`), fail at startup with `--http3`.

```java
MicroProxy.bootstrap()
        .withPort(8443)
        .withSslContextSource(new KeyStoreSslContextSource(Path.of("proxy.p12"), password))  // --listener-keystore
        .withHttp3(true)                                                   // --http3: UDP 8443 too
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))       // intercept CONNECT streams (optional)
        .withHttp3Options(Http3Options.builder()
                .connectUdpIdleTimeout(Duration.ofSeconds(30))             // --masque-udp-idle-timeout 30
                .connectUdpMaxFlows(4096, 64)                              // --masque-max-udp-flows(-per-connection)
                .build())
        .start();
```

#### CONNECT over HTTP/3

A `CONNECT` stream (RFC 9114 section 4.4: `:method CONNECT` and `:authority host:port` only)
opens a byte tunnel, as an HTTP/2 `CONNECT` stream does ([CONNECT and
WebSockets](#connect-and-websockets)): its `200` leaves the stream open, DATA frames carry the
tunnel's bytes, and the stream's FIN half-closes one direction. A reset ends the tunnel and
closes its server connection, and is not counted as a rapid reset; a server connection that fails
resets the stream with H3_CONNECT_ERROR. HEADERS after the `CONNECT`'s are a connection error
(H3_FRAME_UNEXPECTED).

The stream goes the way an HTTP/1 or HTTP/2 `CONNECT` does, because it is shown to the same code
as a socket: with a MITM manager, the stream's first bytes decide ([Deciding what to
intercept](#deciding-what-to-intercept-the-clienthello)): a ClientHello goes through the host
rules and the ClientHello hooks, and an intercepted session is a client connection of its own
inside the stream (HTTP/1.1, or HTTP/2 when the client negotiates `h2`), whose requests filters
see; plain HTTP is served as HTTP; anything else is tunnelled, through the [TCP
hooks](#raw-tcp-streams) and `--tcp-hosts`. Chained proxies and NO_PROXY apply as to any
`CONNECT`. Inside an intercepted HTTP/3 session (transparent QUIC), a `CONNECT` goes to the
intercepted server, which the client takes for its HTTPS proxy ([below](#in-front-of-an-http-or-https-proxy)),
and a request for another host gets `421`.

<a id="websockets-over-http3"></a>**WebSockets over HTTP/3** (RFC 9220) work on every HTTP/3
connection to clients, as over HTTP/2: an extended `CONNECT` with `:protocol websocket`, `:scheme`
`http` or `https`, `:authority` and `:path` becomes the HTTP/1.1 upgrade an HTTP/1.1 client would
send. Filters see a `GET` with `Upgrade: websocket` (absolute-form on a forward proxy) and the
answer as a `101`, which the client gets as a `200`; the frame and message hooks, the WebSocket
limits and permessage-deflate apply as for HTTP/1 and HTTP/2 ([WebSocket frames and
messages](#websocket-frames-and-messages)). Towards the server the WebSocket goes as an HTTP/1.1
upgrade, as an extended `CONNECT` to an HTTP/2 server that enables RFC 8441, or, with
`--http3-upstream`, as an extended `CONNECT` on the shared QUIC connection to an HTTP/3 server
whose SETTINGS enable it. A server that resets the connection cancels the stream
(H3_REQUEST_CANCELLED). Other `:protocol`s get `501`.

```python
# aioquic's H3Connection, a WebSocket through the proxy's HTTP/3 listener:
http.send_headers(stream_id, [(b":method", b"CONNECT"), (b":protocol", b"websocket"),
                              (b":scheme", b"https"), (b":authority", b"chat.example:443"),
                              (b":path", b"/socket"), (b"sec-websocket-version", b"13")])
```

#### CONNECT-UDP (MASQUE)

On the forward-proxy listener, CONNECT-UDP (RFC 9298) proxies UDP: an extended `CONNECT` with
`:protocol connect-udp` whose `:path` names the target by the URI template, by default the
well-known `/.well-known/masque/udp/{target_host}/{target_port}/` (`--masque-udp-template`,
`Http3Options.connectUdpTemplate`, `masque_udp_template`: a path with an optional query, or an
absolute URI, whose authority is the proxy's own, with each variable once; values are
percent-decoded, so an IPv6 address's colons may be encoded).

- **Policy.** The request is an exchange like any other: authentication applies (`407`), filters
  see it as the HTTP/1.1 upgrade an HTTP/1.1 client would send (`GET` of the path with `Upgrade:
  connect-udp`) and may answer it, the target is routed as `CONNECT host:port` would be (chained
  proxies carry no UDP, so a route through them only gets `502`), `proxyToServerRequest` may
  answer, and the target's name is resolved by the proxy's resolver and the filters' resolution
  hooks (`502` when it does not resolve). A path that does not match the template gets `400`. The
  acceptance is a `101` with `Upgrade: connect-udp` for filters and trackers, and a `200` with
  `capsule-protocol: ?1` for the client. CONNECT-UDP elsewhere (a reverse proxy, an intercepted
  session) gets `501`.
- **HTTP Datagrams** (RFC 9297). UDP payloads travel as HTTP Datagrams with context ID 0: in QUIC
  DATAGRAM frames, whose payload starts with the stream's quarter stream ID, or in DATAGRAM
  capsules on the request stream (the capsule protocol, RFC 9297 section 3), which the proxy reads
  whatever the client negotiated, skipping capsules of unknown types. Towards the client the
  proxy uses DATAGRAM frames when the client's SETTINGS_H3_DATAGRAM and QUIC transport parameters
  allow them and the payload fits, else capsules. Payloads with other context IDs are dropped.
- **Relaying.** Each flow has a UDP socket of its own, connected to the target; datagrams go both
  ways, one for one, until the client ends or resets its stream, or the flow is idle for
  `--masque-udp-idle-timeout` (60 s), after which the proxy ends the stream.
- **Bounds** (`Http3Options`). Flows at once, in total (4096) and per client connection (64;
  `--masque-max-udp-flows`, `--masque-max-udp-flows-per-connection`): a request past either gets
  `503`. Each direction of a flow queues at most 128 datagrams and 512 KiB
  (`connectUdpQueue`); past that datagrams are dropped, as a network drops what it cannot carry,
  so a client that does not read its stream, or a slow target, holds up nothing else.
- **Hooks.** `withUdpInterceptor(UdpInterceptor)` sees every datagram, both ways: `udpStart`,
  `udpMessage` (return the payload to send, changed or not, or `null` to drop it), `udpEnd`, and
  `UdpContext.send` to add datagrams; scripts get [`on_udp_message`](#udp-hooks). A flow whose
  QUIC the proxy intercepts ([below](#quic-inside-connect-udp-flows)) shows the hooks no
  datagrams: its QUIC ends at the proxy.
- **QUIC.** With `--masque-intercept-quic`, the QUIC inside a flow is decided on as transparent
  QUIC is ([QUIC inside CONNECT-UDP flows](#quic-inside-connect-udp-flows)); without it, it is
  relayed like any UDP.

```java
bootstrap.withUdpInterceptor((msg, ctx) ->
        msg.fromClient() && ctx.port() == 53 && msg.text().contains("blocked") ? null : msg.data());
```

A MASQUE client, such as aioquic's `H3Connection` (with HTTP/3 datagrams on), opens a flow and
sends a DNS query through it:

```python
http = H3Connection(quic, enable_webtransport=True)   # sends SETTINGS_H3_DATAGRAM
http.send_headers(stream_id, [(b":method", b"CONNECT"), (b":protocol", b"connect-udp"),
                              (b":scheme", b"https"), (b":authority", b"proxy.example:8443"),
                              (b":path", b"/.well-known/masque/udp/192.0.2.53/53/"),
                              (b"capsule-protocol", b"?1")])
# once the 200 arrives: context ID 0, then the UDP payload
http.send_datagram(stream_id, b"\x00" + dns_query)
```

#### Session resumption and 0-RTT

The proxy's QUIC servers that serve HTTP/3 (`--http3`, the clients the [transparent
QUIC](#transparent-quic) listener intercepts as HTTP/3, and HTTP/3 intercepted inside CONNECT-UDP
flows with `--masque-intercept-quic`) send each client two TLS session tickets after its
handshake, sealed with a key of the proxy's that rotates every six hours, and two NEW_TOKEN tokens.
A returning client resumes its session (no certificate exchange: a fresh key exchange and a PSK)
and skips the Retry round trip of `--http3-retry`. Tickets work across all the QUIC servers of one
proxy, but not across proxy processes: each has its own key. QUIC intercepted stream by stream
(the [QUIC stream hooks](#quic-stream-hooks)) gets no tickets, so no resumption and no 0-RTT: its
streams are opaque, and the proxy could not tell what in them is safe to replay.

**0-RTT to the proxy** is off by default. `--http3-0rtt` (`Http3Options.zeroRtt(true)`,
`http3_0rtt=true`) lets a resuming client send its first requests as early data, before its
handshake completes, saving a round trip. Early data is not protected against replay: whoever
captures a client's first flight can send it again, and the proxy would act on it twice ([RFC
8446 section 8](https://datatracker.ietf.org/doc/html/rfc8446#section-8)). So:

- **The QUIC layer** accepts a ticket's early data at most once, and only while the ticket age the
  client reports agrees with the proxy's within 10 seconds, which a stale capture fails. Its record
  of used tickets is in memory, one per process that all its QUIC servers share, and bounded
  (refusing early data when full); rejected early data costs the client nothing but the round
  trip, as it sends it again.
- **The proxy** treats a request any part of which arrived as early data as
  [RFC 8470](https://datatracker.ietf.org/doc/html/rfc8470) says. A method that is not safe to
  repeat (anything but `GET`, `HEAD` and `OPTIONS` without a body, and so any `CONNECT`, extended
  or not) gets `425 Too Early`, and the client sends it again once its handshake completes. Others go on with `Early-Data: 1`, so the
  server (or another proxy behind) can answer `425` itself, which the proxy relays.
- **Filters** see `FlowContext.isEarlyData()` (`ctx.early_data` in scripts) and may answer `425`
  to requests they deem unsafe, `GET`s with side effects for instance:

  ```python
  def on_request(req, ctx):
      if ctx.early_data and "/checkout" in req.uri:
          return response(425, "too early\n")
  ```

The proxy does not hold early requests back until the handshake completes; one that arrived early
is marked even when the handshake has completed by the time it goes on.

**0-RTT to servers** is on with `--http3-upstream` (`Http3Options.upstreamZeroRtt`,
`http3_upstream_0rtt`; `--no-http3-upstream-0rtt` turns it off). The proxy keeps the tickets
servers send, per server name, for as long as it runs, and resumes when it opens a new QUIC
connection to one. If the request that opens the connection is safe to replay (`GET`, `HEAD`,
`OPTIONS` without a body) and the ticket allows it, the request goes as 0-RTT data; requests that
are not wait for the handshake. A server that rejects the early data gets it again in 1-RTT
packets; one that answers `425 Too Early` gets the request again after the handshake, unless the
request itself arrived as early data (`Early-Data: 1`), whose `425` goes back to its client.

#### HTTP/3 to servers

With `--http3-upstream` (`withHttp3Upstream(true)`, `http3_upstream=true`), the proxy speaks
HTTP/3 to servers known to support it, whatever protocol the client spoke (HTTP/1, HTTP/2 or
HTTP/3), in any mode.

- **Knowing.** A server is known to speak HTTP/3 once one of its responses over TLS advertised
  `h3` on its own host (`Alt-Svc: h3=":443"`), remembered for the advertisement's `ma` (24 hours
  without one) and forgotten on `Alt-Svc: clear` or `ma=0`. The proxy learns before it strips
  `h3` for the client, so stripping stays on. Alternatives on other hosts, and draft versions
  (`h3-29`), are never used. `--http3-upstream-hosts <regex>` (`withHttp3UpstreamHosts`,
  `http3_upstream_hosts`) names servers to reach over HTTP/3 at once, on their URI's port.
- **Sharing.** One QUIC connection per server, shared by every exchange for it, of every client,
  as streams, within the server's stream limit. Nothing about a QUIC connection is particular to
  one client.
- **Trust.** Servers are validated as TLS connections to them are: with the MITM manager's
  server trust (`MitmManager.serverTrustManager`, which `CertificateAuthorityMitmManager` and
  every context from `SslContexts` provide, so `--mitm-trust-all` works too), or the JDK's default
  trust store without a manager, checking the host name as HTTPS does. A manager whose trust the
  proxy cannot reproduce keeps its servers on TCP.
- **Falling back** (happy eyeballs, lite). A QUIC handshake that fails, or does not complete
  within `upstreamHandshakeTimeout` (1 second), sends the exchange over TCP, and the server stays
  on TCP for `upstreamFailureTimeout` (5 minutes). Exchanges for the same server wait for a
  handshake in progress rather than start their own.
- **Failures.** A `GOAWAY` from the server, or a stream it refuses with `H3_REQUEST_REJECTED`,
  makes the request safe to send again, on a new connection. QUIC's idle timeout answers `504`
  (`ProxyFailure.ServerTimeout`); other resets and connection errors `502`
  (`ProxyFailure.BadServerResponse`), or reset the client's stream once the response has started.
- **Only direct connections.** Requests through chained proxies (UDP does not go through them),
  through a tunnel a session's server opened, with a PROXY protocol header, and proxy requests
  keep using TCP.
- **WebSockets** go over HTTP/3 to a server whose SETTINGS enable extended `CONNECT` (RFC 9220),
  waited for up to `upstreamHandshakeTimeout`; to other servers on an HTTP/1.1 connection of their
  own.

#### Transparent QUIC

`--transparent-quic-port <port>` (`withTransparentQuicPort(port)`, `transparent_quic_port`, with
`--transparent`) opens a UDP listener for QUIC that a firewall redirects to the proxy: the UDP
counterpart of [transparent TLS](#transparent-mode). Java cannot read a redirected datagram's
original destination either, so each new client flow (a client address and the Destination
Connection ID of its first Initial packets) is routed by its SNI, to that host's
`--transparent-tls-port` (443).

- **Reading the ClientHello.** The proxy holds a new client's datagrams and decrypts its Initial
  packets with the keys their Destination Connection ID gives (RFC 9001 section 5.2, QUIC v1 and
  v2), without a handshake, as mitmproxy does. It puts the CRYPTO frames back together across
  packets and datagrams, in any order (browsers' post-quantum ClientHellos take two packets, their
  frames shuffled), and parses the same `ClientHello` that TLS over TCP gives.
- **Deciding**, as for transparent TLS: a `CONNECT sni:443` is made up for the flow (filters see
  it; `clientToProxyRequest` answering it drops the flow; `proxyToServerAllowMitm()` and
  `allow_mitm` may decline), then the [ignore and allow rules](#ignoring-and-allowing-hosts),
  the client's ALPN (`h3` is served as HTTP/3; other protocols are intercepted
  [stream by stream](#quic-stream-hooks) with a `QuicInterceptor` or for the `--quic-hosts`, and
  relayed otherwise), `MitmManager.shouldIntercept(hello, flow)`, and
  `proxyToServerAllowMitm(hello)` / `on_client_hello` (the table below). A redirected client
  sends no proxy credentials: with an authenticator, it must accept clients without.
- **Intercepted** (HTTP/3 with a MITM manager, which must be a `CertificateAuthorityMitmManager`
  to issue QUIC's certificates): the held datagrams go to the proxy's QUIC server, whose handshake
  presents a certificate the CA issues for the SNI, and the connection is served HTTP/3 like a
  [reverse proxy's](#serving-http3-in-reverse-mode) clients, with its requests going to the SNI's
  host: over HTTP/3 with `--http3-upstream` (the proxy takes the client's HTTP/3 as the origin's
  advertisement, and falls back to TCP if its QUIC handshake fails), else over HTTP/2 or
  HTTP/1.1. Filters, scripts (`on_request`, `on_frame`, ...), logging and trackers see the
  requests, with `FlowContext.isTransparentQuic()` (and `ctx.transparent_quic`) true.
- **Intercepted stream by stream** (another ALPN such as DNS over QUIC's `doq` with a
  `QuicInterceptor`, or a `--quic-hosts` host): the proxy connects to the server first, then
  completes the client's handshake with the server's choice of ALPN, and relays the two
  connections' streams and datagrams through the [QUIC stream hooks](#quic-stream-hooks).
- **Relayed** (no MITM manager, an ignored or declined host, another ALPN without a
  `QuicInterceptor`): the datagrams go to the server untouched from a UDP socket of the flow's
  own, and the server's back to the client from the listener's socket, until the flow is idle for
  `--transparent-quic-relay-idle-timeout` (60 s). The client completes its handshake with the
  real server.
- **Demultiplexing.** One socket serves every client. Intercepted connections are routed by the
  connection IDs the proxy issued (so they survive the client moving to new ones); relayed flows
  by the client address and the connection IDs seen in their long headers, and otherwise to the
  client address's most recently active flow (servers issue more IDs in encrypted frames).
- **Clients that move** (QUIC connection migration, RFC 9000 section 9: a NAT that rebinds the
  client to a new port, a phone that goes from Wi-Fi to cellular, a client that migrates on
  purpose). An intercepted connection, HTTP/3 or [stream by stream](#quic-stream-hooks), follows
  its client as any QUIC server does: its datagrams are routed by connection ID from any address,
  the proxy validates the new path with PATH_CHALLENGE, sends there no more than three times what
  it received until the client answers, keeps the congestion state for a new port and starts it
  over for a new address, goes back to the old path if the new one does not answer, and answers
  from the new path. The proxy's own connection to the server (stream by stream, and HTTP/3 to
  origins) stays where it is. A relayed flow is harder: the proxy cannot read the client's packets,
  nor the encrypted frames in which the server gives the client the connection IDs it moves to.
  A short header packet from an address with no flow goes to the relayed flow that knows its
  connection ID (from any address), else to the flow of the same client IP address whose known
  server IDs share the longest prefix of at least 4 bytes with it (servers that encode routing in
  their IDs), else to that IP address's most recently active relayed flow, which is what a NAT
  rebinding needs. The flow then sends the server's datagrams to the new address, as a NAT sends
  replies to its latest mapping, and learns the client's new ID when the server's IDs all have
  one length. Limits: a relayed client that changes both IP address and connection ID is found
  only by an ID prefix; with several relayed flows from one IP address the fallback may pick the
  wrong one; and since the proxy can neither validate the new address nor tell a newer packet from
  a replayed one, a sender that can spoof the client's IP address with one of the flow's
  connection IDs can turn its replies elsewhere until the client sends again (the end-to-end
  connection stays the client's: the server, whose path to the proxy does not change, validates
  nothing). A server that sends `disable_active_migration` is not migrated away from by clients
  that honour it.
- **Versions.** A new client offering a version the proxy cannot read gets Version Negotiation
  (v1, v2), since its destination is in a ClientHello the proxy cannot decrypt; on an existing
  relayed flow, other versions are relayed like anything else.
- **Retry.** `--http3-retry` (`Http3Options.retry`) makes intercepted clients prove their address
  first. Relayed clients never get one: their server would refuse the proxy's token.

The decision, in order; the first row that applies decides:

| The flow | Becomes |
|---|---|
| A `clientToProxyRequest` answers the made-up `CONNECT`, or the authenticator refuses a client without credentials | dropped |
| No MITM manager, or `proxyToServerAllowMitm()` / `allow_mitm` declines | relayed |
| An [ignore or allow rule](#ignoring-and-allowing-hosts) leaves out the server or the SNI | relayed |
| ALPN without `h3`, not a `--quic-hosts` host, and no `QuicInterceptor` (`on_quic_*`) | relayed |
| No SNI (only inside a CONNECT-UDP flow to an IP address), or no `CertificateAuthorityMitmManager` to issue the certificate | relayed |
| `MitmManager.shouldIntercept(hello, flow)` or `proxyToServerAllowMitm(hello)` / `on_client_hello` declines | relayed |
| A `--quic-hosts` host (whatever its ALPN, `h3` included) | intercepted [stream by stream](#quic-stream-hooks) |
| ALPN offering `h3` | intercepted as HTTP/3 |
| Any other ALPN (`doq`, `hq-interop`, a protocol of its own), with a `QuicInterceptor` | intercepted [stream by stream](#quic-stream-hooks) |

`ActivityTracker.transparentQuicFlowDecided` reports each decision (`intercepted` is true for
both kinds of interception, the reason saying why for stream by stream).
- **Bounds** (`Http3Options`): new clients held at once (1024, and 32 per client IP address, each
  holding 16 datagrams and 64 KiB at most, all together 8 MiB), how long one may take to send its
  ClientHello and be decided on (5 s), relayed flows (4096, and 256 per client IP address).
  Datagrams past a bound are dropped, as a full socket buffer would drop them.

```java
MicroProxy.bootstrap()
        .withTransparent(true)
        .withTransparentQuicPort(8443)                                   // --transparent-quic-port 8443
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withHttp3Upstream(true)                                         // HTTP/3 to origins too
        .withIgnoreHosts("\\.bank\\.example:443$")                         // relayed untouched
        .start();
```

Redirecting a gateway's clients' QUIC (`eth1`) to UDP port 8443, next to their TCP:

```bash
# REDIRECT (NAT): the proxy answers from its listener socket, and the kernel's connection
# tracking turns the replies' source back into the address the client sent to.
iptables -t nat -A PREROUTING -i eth1 -p udp --dport 443 -j REDIRECT --to-ports 8443
# On the proxy's own machine, its own QUIC (relays, HTTP/3 to origins) must not be redirected:
iptables -t nat -A OUTPUT -p udp -m owner ! --uid-owner proxy --dport 443 -j REDIRECT --to-ports 8443

# TPROXY keeps the original destination on the packet instead of rewriting it:
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A PREROUTING -i eth1 -p udp --dport 443 -j TPROXY --on-port 8443 --tproxy-mark 1
```

**NAT.** Use REDIRECT. With it, replies must leave from the socket the client's datagrams arrived
at, as the proxy's do, so that connection tracking maps them back; and the conntrack entry of a
UDP flow (`nf_conntrack_udp_timeout_stream`, 120 s by default) should outlive the relay's idle
timeout. TPROXY needs a listening socket with `IP_TRANSPARENT`, which the JDK cannot set, and
replies sent from the original destination address, which the JDK cannot do either: it does not
work with MicroProxy as it is. Relayed flows reach servers from a new UDP socket each, so a
firewall in front of the proxy sees each as a flow of its own. A client the NAT maps to a new port
is followed (see **Clients that move** above).

#### QUIC stream hooks

QUIC that does not carry HTTP/3 can be intercepted too, stream by stream:
`withQuicInterceptor(QuicInterceptor)` (or a script's [`on_quic_*`](#quic-hooks) hooks) makes the
proxy intercept the [transparent QUIC](#transparent-quic) flows, and the QUIC inside
[CONNECT-UDP flows](#quic-inside-connect-udp-flows) with `--masque-intercept-quic`, whose ALPN
offers no `h3` (`doq`, `hq-interop`, a protocol of its own), once the other rules allow it, as the
[TCP hooks](#raw-tcp-streams) do for TLS that carries no HTTP. `withQuicHosts(...)` (`--quic-hosts`,
`quic_hosts`) names hosts, by regular expressions searched for in the server's host name and the
SNI, whose QUIC is relayed this way whatever its ALPN: their HTTP/3 too, which filters and frame
hooks then do not see, and their other QUIC even without an interceptor.

```java
MicroProxy.bootstrap()
        .withTransparent(true)
        .withTransparentQuicPort(8443)
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withQuicHosts("^quic\\.example\\.com$")                         // --quic-hosts, quic_hosts
        .withQuicInterceptor(new QuicInterceptor() {
            @Override
            public void quicStart(QuicContext ctx) {
                log("QUIC " + ctx.alpn() + " to " + ctx.host() + ":" + ctx.port() + " (" + ctx.sni() + ")");
            }

            @Override
            public byte[] streamData(QuicStreamMessage msg, QuicStreamContext stream) {
                return stream.clientInitiated() && !msg.fromClient()
                        ? msg.text().replace("secret", "******").getBytes(UTF_8) : msg.data();
            }

            @Override
            public byte[] datagram(QuicDatagram datagram, QuicContext ctx) {
                return datagram.length() > 1000 ? null : datagram.data();   // drop large ones
            }
        })
        .start();
```

- **Pairing the connections.** The proxy first connects to the server, from a UDP socket of the
  flow's own, with the client's SNI and ALPN protocols, validating the server as it validates
  [HTTP/3 servers](#http3-to-servers) (the MITM manager's server trust). Then it completes the
  client's handshake with a certificate its CA issues for the SNI, choosing the protocol the
  server chose, and taking DATAGRAM frames only when the server does. A server that cannot be
  reached drops the flow, as a relay that cannot be made does.
- **Streams.** Each stream one side opens, bidirectional or unidirectional, is opened on the
  other connection when the peers' stream limits allow it, in order, so the stream IDs on both
  connections are usually the same (`QuicStreamContext.streamId()` is the client's,
  `serverStreamId()` the server's). The hooks: `quicStart`; `streamOpened`; `streamData` for the
  bytes of each read, which returns the bytes to pass on (`msg.data()` as it is or changed in
  place, others, or `null` or an empty array to drop them); `streamFinished` before a FIN is passed
  on; `streamReset` (RESET_STREAM, passed on with its code) and `streamStopped` (STOP_SENDING:
  the other side is asked the same, and the stream reset towards the side that asked); `datagram`
  for each datagram, which returns the payload or `null`; then `quicEnd`, or `quicError` when a
  connection timed out, was reset or failed with a transport error, never both. When one side
  closes its connection, the other is closed with the same application error code and reason.
- **Adding data.** `QuicStreamContext.send(fromClient, bytes)` writes bytes to a stream as if that
  side had sent them, after the message being handled when called from a `streamData` of the same
  direction; `QuicContext.sendDatagram(fromClient, bytes)` sends a datagram. Neither passes
  through the hooks.
- **Messages.** A stream is a byte stream, as TCP is: a `QuicStreamMessage` is whatever one read
  returned (at most 16 KiB), so a peer's write may show up in pieces, or joined with the next one.
  Hooks that look for a protocol's messages keep the start of one until its end arrives, or let
  the proxy cut the stream into messages for `streamMessage`
  ([QUIC message framing](#quic-message-framing)).
- **Flow control.** End to end: each direction of each stream is read only as fast as the other
  side takes the bytes, so QUIC's flow control holds a fast sender back while a slow receiver
  reads, and the proxy keeps at most one read per direction. The proxy's receive windows are
  HTTP/3's (`Http3Options.streamReceiveWindow`, `connectionReceiveWindow`).
- **Threads.** Each direction of each stream, and of datagrams, has a virtual thread of its own:
  the interceptor must be thread-safe; within one direction of one stream, calls come in order.
  The context names the client connection (`connectionId`, `clientAddress`, `flowContext`), the
  server (`host`, `port`, `serverAddress`), `sni`, `alpn` and `masque()`.

#### QUIC message framing

A stream's bytes come to `streamData` in reads, without the protocol's message boundaries. Many
protocols over QUIC frame their messages simply, and the proxy can cut their streams into whole
messages for a hook: `QuicInterceptor.streamMessage(QuicMessage msg, QuicStreamContext stream)`
(or a script's [`on_quic_message`](#quic-hooks)) sees each message's payload, without its length
prefix or delimiter, and returns the messages to send in its place. What it returns is framed
again, so an edited payload gets a length prefix of its new length.

`--quic-framing` (`quic_framing`, `withQuicFraming(QuicFraming)`) chooses a framer by ALPN or by
host: comma-separated `key=framer` rules, where a key is an ALPN protocol (`doq`), a host name
matched against the server's host and the SNI (`dns.example.com`, or `*.example.com` for it and
the names below it), or `*` for any connection. A host rule wins over an ALPN rule, which wins
over `*`. DNS over QUIC (`doq`) is framed with `u16` by default; `doq=none` turns that off.

| Framer | Messages |
|---|---|
| `u16` | a two-byte big-endian length, then the payload: DNS over QUIC (RFC 9250), DNS over TCP |
| `u32` | a four-byte big-endian length, then the payload |
| `varint` | a QUIC variable-length integer (RFC 9000 section 16) as the length; written in its shortest form |
| `lf` | a line ending with a line feed, which the payload leaves out (a carriage return before it stays) |
| `crlf` | a line ending with a carriage return and a line feed |
| `none` | not framed: `streamData` sees the reads |
| `script` | a script's `quic_message_length(data)` (see [QUIC](#quic-hooks)) |
| a `MessageFramer` | from Java: `framing.withRule("myproto", framer)` or `withFramer(name, framer)` |

```bash
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 \
    --transparent --transparent-quic-port 8443 --mitm --script doq.star \
    --quic-framing doq=u16,myproto=varint,*=none --quic-max-message-size 65537
```

- **Which streams.** Every stream of a connection whose framing rule names a framer, when the
  interceptor overrides `streamMessage` (a script, when it defines `on_quic_message`). Framing
  replaces the chunk hook there: `streamData` (`on_quic_stream_data`) is not called on those
  streams, and is called as before on the streams of other connections. An interceptor that does
  not override `streamMessage` is never framed, whatever the rules say: **without framing, or
  without a message hook, nothing is kept**, and each read goes on as it came.
- **What a hook returns.** `List.of(msg)` passes the message on (changed in place or not); other
  messages replace it, in order; `null` or an empty list drops it. A message whose `fromClient()`
  is the other direction's (`msg.withFromClient(false)`) goes to the side that sent `msg`, on the
  same stream, as if the other side had answered. `QuicStreamContext.send` still writes bytes as
  they are, not framed. A hook that throws, or returns a payload its framer cannot frame (more
  than 65535 bytes for `u16`), has the message passed on unchanged.
- **Limits.** A message larger than `--quic-max-message-size` (`quic_max_message_size`,
  `QuicFraming.withMaxMessageSize`; 1 MiB, the prefix or delimiter included), known from a length
  prefix as soon as it arrives or from a delimiter that does not come in time, and bytes a framer
  cannot read (a custom framer that throws), **reset the stream** in both directions on both
  connections, and ask both sides to stop sending, with `--quic-message-error-code`
  (`quic_message_error_code`, `withErrorCode`; 2, DNS over QUIC's `DOQ_PROTOCOL_ERROR`), as a
  WebSocket message too big closes its connection with 1009. The connection and its other
  streams go on. Bytes left over when a side finishes its stream, not a whole message, are passed
  on as they are, before the FIN.
- **Flow control** stays end to end: a direction keeps at most one message's bytes and a read.
- **Datagrams** are whole messages already: `datagram` (`on_quic_datagram`) sees them as before.
- **Decoding.** `QuicMessage` has `data()`, `text()`, `fromClient()`, `streamId()`, `alpn()`,
  `timestamp()`, the copies `withData`, `withText`, `withFromClient` and `withDns`, and decoders:
  `dns()` reads the payload as a DNS message (`org.microproxy.dns.DnsMessage`: the header, the
  questions, and records with typed data for A, AAAA, NS, CNAME, PTR, DNAME, MX, SRV, TXT and
  SOA; it encodes back, names compressed); `protobuf()` and `protobuf(schema, type)` decode
  protobuf as the [content views](#content-views) do; `render()` renders the payload with the
  best content view, as `dig` shows it for DNS over QUIC (the `dns` view), for logging.

DNS over QUIC, logging each query and answering a blocked name with `0.0.0.0` by rewriting the
server's answer:

```java
Set<String> blocked = Set.of("ads.example", "tracker.example");
bootstrap.withQuicInterceptor(new QuicInterceptor() {
    @Override
    public byte[] streamData(QuicStreamMessage msg, QuicStreamContext stream) {
        return msg.data();                                  // streams that are not framed
    }

    @Override
    public List<QuicMessage> streamMessage(QuicMessage msg, QuicStreamContext stream) {
        DnsMessage dns = msg.dns();
        DnsMessage.Question q = dns.questions().getFirst();
        if (msg.fromClient()) {
            log(stream.clientAddress() + " asks for " + q.name() + " " + q.typeName());
            return List.of(msg);
        }
        if (!blocked.contains(q.name().toLowerCase(Locale.ROOT))) return List.of(msg);
        List<DnsMessage.ResourceRecord> answers = dns.answers().stream()
                .map(r -> r.type() == DnsMessage.A ? r.withData(DnsMessage.Address.of("0.0.0.0")) : r)
                .toList();
        return List.of(msg.withDns(dns.withAnswers(answers)));   // framed again, its length recomputed
    }
});
```

#### QUIC inside CONNECT-UDP flows

With `--masque-intercept-quic` (`Http3Options.Builder.connectUdpInterceptQuic(true)`,
`masque_intercept_quic=true`), the QUIC that a [MASQUE client](#connect-udp-masque) sends through
a CONNECT-UDP flow is decided on as [transparent QUIC](#transparent-quic) is, with the flow's
target as the server, instead of being relayed as any UDP:

- **Which flows.** Those to a UDP port of `--masque-quic-ports` (`connectUdpQuicPorts`,
  `masque_quic_ports`; 443 by default, `any` for every port) whose first datagram from the client
  is a QUIC Initial. Other flows, and flows whose first datagram is something else, are relayed as
  before, through the [UDP hooks](#udp-hooks).
- **Deciding.** The proxy holds the flow's datagrams, reads the ClientHello from its Initials,
  and runs the [same decision](#transparent-quic): a `CONNECT target` is made up for it, the
  [ignore and allow rules](#ignoring-and-allowing-hosts) apply to the target and the SNI, then
  the ALPN, `shouldIntercept` and `on_client_hello`. The MASQUE client's CONNECT-UDP request was
  authenticated already, so the inner flow is not asked again, and its client connection has the
  MASQUE client's address and user.
- **Intercepted.** HTTP/3 is served as HTTP/3, its requests going to the target (by the SNI's
  name when the target is an IP address, so that the server's certificate is checked against it,
  at the target's address): filters, scripts (`on_request`, `on_frame`, ...) and trackers see
  them, with `FlowContext.isTransparentQuic()` true. Other QUIC goes through the
  [QUIC stream hooks](#quic-stream-hooks), with `QuicContext.masque()` true. The proxy's
  replies travel back in the flow, as HTTP Datagrams or capsules.
- **Relayed.** An ignored or declined host, or QUIC that is not intercepted, goes to the target
  from the flow's own socket, the held datagrams first, as without the option.
- **How.** A virtual listener: the transparent listener's per-flow logic (`QuicFlows`) over a
  QUIC server without a socket (`QuicServer.unbound`), fed the flows' datagrams under addresses
  it makes up for each flow, and handing its replies back to the flows.

```java
MicroProxy.bootstrap()
        .withSslContextSource(new KeyStoreSslContextSource(Path.of("proxy.p12"), password))
        .withHttp3(true)
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withHttp3Options(Http3Options.builder()
                .connectUdpInterceptQuic(true)                           // --masque-intercept-quic
                .connectUdpQuicPorts(443, 8443)                          // --masque-quic-ports 443,8443
                .build())
        .withIgnoreHosts("\\.bank\\.example:443$")                         // relayed untouched
        .start();
```

#### Alt-Svc: which clients may move to HTTP/3

HTTP/3 runs over QUIC, on UDP. Browsers never send QUIC through an HTTP proxy, and a transparent
setup may redirect only TCP. So a client that learns that an origin speaks HTTP/3 can switch to it
and bypass the proxy, and with it interception, filters and logging, unless its UDP is redirected
to a [transparent QUIC](#transparent-quic) port. Clients learn about HTTP/3 in two ways:

- **From `Alt-Svc` response headers** such as `Alt-Svc: h3=":443"; ma=86400, h2=":443"`. The
  proxy removes the `h3` alternatives, including the draft versions (`h3-29`, `h3-Q050`, ...)
  and Google QUIC's `quic`. Other alternatives such as `h2=":443"` are kept with their
  parameters (`ma`, `persist`), a header left empty is removed, and `Alt-Svc: clear` is passed
  on. This is **on by default with interception (`--mitm`, `withManInTheMiddle`) or
  `--transparent`**, and off for a plain forward proxy; **with `--transparent-quic-port`, it is
  off by default for clients whose traffic was redirected to the proxy**, whose QUIC reaches the
  proxy too (table below). `--no-alt-svc-h3`, `withoutHttp3Advertisement()` or
  `strip_alt_svc_h3=true` turn it on for every client, and `--keep-alt-svc-h3`,
  `withAltSvcH3Stripping(false)` or `strip_alt_svc_h3=false` off for every client. Filters see server
  responses unchanged in `serverToProxyResponse` and already stripped in
  `proxyToClientResponse`. Short-circuit responses (including cache answers) are stripped as
  they are sent. With `--http3-upstream`, the proxy itself learns from the advertisement first.
- **From DNS `HTTPS` records**, which the proxy never sees. In transparent deployments without
  a transparent QUIC port, **block UDP port 443** (for example `iptables -A FORWARD -p udp
  --dport 443 -j REJECT`). Clients then fall back to TCP, which the proxy does see.

Who keeps `h3` alternatives, by default (an explicit `strip_alt_svc_h3` applies to every row):

| Client | Configuration | `h3` in `Alt-Svc` | Its HTTP/3 then |
|---|---|---|---|
| Explicit proxy client (`CONNECT`, absolute-form) | plain forward proxy | kept | goes around the proxy |
| Explicit proxy client | `--mitm` or `--transparent` (with or without `--transparent-quic-port`) | stripped | stays on TCP through the proxy; a client whose UDP is redirected to the QUIC port anyway may turn stripping off (`--keep-alt-svc-h3`) |
| Redirected client (SNI-routed TLS, HTTP routed by `Host`) | `--transparent`, no QUIC port | stripped | stays on TCP; block UDP 443 for DNS `HTTPS` records |
| Redirected client | `--transparent --transparent-quic-port` | kept | redirected to the QUIC port: intercepted (`h3` with `--mitm`) or relayed |
| HTTP/3 client of the transparent QUIC port | `--transparent-quic-port` | kept | already on HTTP/3 through the proxy |
| Reverse proxy client | `--http3` | the proxy's own `h3` | the proxy's HTTP/3 listener |

HTTP/2 can also announce alternatives in `ALTSVC` frames. The proxy never sends them, and drops
any that HTTP/2 servers send (as frames of a type it does not handle), so alternatives reach
HTTP/2 clients only as `Alt-Svc` headers, which are stripped the same way.

#### HTTP/3 frame interception

The [frame interceptor](#frame-interception) sees HTTP/3 frames live wherever the proxy speaks
HTTP/3: `FROM_CLIENT` and `TO_CLIENT` on the reverse proxy's HTTP/3 listener, on intercepted
transparent QUIC and on HTTP/3 intercepted inside CONNECT-UDP flows, `TO_SERVER` and `FROM_SERVER` on connections to HTTP/3 servers, with the
stream's QUIC id and, from a stream's
first frame on, its exchange's `FlowContext`. `Http3Frame` has `Data`, `Headers`, `Settings`,
`GoAway`, `CancelPush`, `MaxPushId`, `PushPromise` and `Unknown`. The rules are HTTP/2's,
adapted: HTTP/3 frames carry no stream id or END_STREAM (a message ends with its stream), so
results must keep the message's order (HEADERS, DATA, trailers; interim responses first); DATA
may be edited to any size, and QUIC's flow control counts what is actually sent; field sections
are decoded through QPACK before the interceptor sees them and encoded through the connection's
QPACK encoder after it, so QPACK state never depends on it; SETTINGS received may only make the
proxy stricter (a smaller QPACK table, field section or blocked-streams limit, no
ENABLE_CONNECT_PROTOCOL or H3_DATAGRAM turned on), SETTINGS sent may change only in extension
settings; GOAWAY, MAX_PUSH_ID and CANCEL_PUSH are read-only; extension and grease frames may be
edited, dropped and added. Scripts get the same with [`on_frame`](#frames).

<a id="http3-frames"></a>For HTTP/3 traffic relayed by other means, `Http3FramePipeline` runs a
frame interceptor over a request stream's or a control stream's bytes, under the same rules, and
writes them back with static-only QPACK, so no encoder stream is needed. It needs only the
`http3-codec` jar (`Http3FramePipeline.available()`).

```java
Http3FramePipeline pipeline = Http3FramePipeline.builder(interceptor)
        .direction(FrameDirection.FROM_CLIENT)            // whose frames these are
        .build();
pipeline.controlStream(2, clientControlStream, out);      // stream type, SETTINGS, ...
pipeline.encoderStream(clientQpackEncoderStream);         // only when the client's QPACK uses its dynamic table
pipeline.requestStream(0, requestStream, rewritten);      // HEADERS, DATA, trailers
```

#### Limitations and what is next

- **Transparent QUIC**'s original destination is the SNI's host (no TPROXY, no
  `SO_ORIGINAL_DST`). Clients of an explicit proxy are still steered to TCP, unless they use the
  forward proxy's HTTP/3 listener.
- **QUIC stream hooks.** Streams are paired as they open, so the hooks cannot open streams of
  their own, nor see QUIC frames (only stream bytes and datagrams). The server's handshake comes
  before the client's, so a server that is slow to answer delays the client's, which may
  retransmit its Initials meanwhile; one that cannot be reached drops the flow rather than relay
  it. 0-RTT is not offered, as the QUIC module has none.
- **QUIC message framing.** A connection's streams all get the framer its ALPN or host chooses,
  each carrying that protocol's messages from its start (a stream type or a header before them,
  as HTTP/3's unidirectional streams have, needs a framer of one's own). Framers keep no state
  between calls, and a script's framer is called with all the bytes kept so far each time. Bytes
  a framer cannot read reset the stream rather than fall back to the reads, and the hooks are not
  told of the resets framing makes.
- **MASQUE.** QUIC inside a CONNECT-UDP flow is intercepted only with `--masque-intercept-quic`,
  and a flow is inspected from its first datagram: one that starts with anything but a QUIC
  Initial is relayed as UDP throughout, and once one of its QUIC connections is relayed, so is the
  rest of the flow. An intercepted connection that its client carries over to another CONNECT-UDP
  flow to the same target follows it there (a flow whose first datagram belongs to the connection
  goes to the proxy's QUIC server, which validates the path through the new flow), and closes when
  the flow it is on ends, not one it left; relayed QUIC that moves between flows is not followed.
  CONNECT-UDP to an upstream MASQUE proxy (HTTP/3
  chained proxies), CONNECT-UDP over HTTP/2 and HTTP/1.1, and CONNECT-IP are not done.
- Server push (never requested: the proxy sends no MAX_PUSH_ID).
- The proxy's own QUIC connections to servers (stream by stream, HTTP/3 to origins) never move to
  a new local address, having no reason to; they move to a server's preferred address as any
  client does, and do not follow a server that moves to another address of its own accord (see
  the QUIC module's [README](quic/README.md)).
- HTTP/3 to servers only over direct connections, and without client certificates.

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

### mitmproxy-style addons

`org.microproxy.extras` has ports of mitmproxy's request and response addons. Each is an
`HttpFiltersSource`, so they compose with each other, with your own filters and with scripts
through `HttpFiltersChain`, and each reads the same option syntax as mitmproxy:
`[|flow-filter]|subject|replacement`, where the first character is the separator (any character;
`/` in mitmproxy's documentation) and the filter is optional.

```java
bootstrap.withFiltersSource(HttpFiltersChain.of(
        BlockList.of("|~d ads\\.example\\.com|404", "|~u /beacon|444"),     // 444: close, no response
        AntiCache.create(),
        MapRemote.of("|https://api\\.example\\.com/|http://localhost:8000/"),
        MapLocal.of("|example.com/static/|/srv/static"),
        ModifyBody.of("|~s & ~t html|Example Domain|Local Domain"),
        ModifyHeaders.of("|~q|User-Agent|MicroProxy", "|~s|Server|"),      // empty value: remove
        StickyCookie.of("~d example.com")));
```

```bash
java -jar microproxy.jar --mitm --map-remote '|https://api\.example\.com/|http://localhost:8000/' \
    --map-local '|example.com/static/|/srv/static' --block-list '|~u /beacon|444' --anticache
```

| addon | command line | what it does |
|---|---|---|
| `MapLocal` | `--map-local [\|filter]\|url-regex\|file-or-dir` | answers from a file, or from a directory: the URL after the match (or the regex's first group) names the file; `index.html` for directories; a `Content-Type` from the extension; `404` when nothing matches; never outside the directory (`..`, absolute parts, links pointing out) |
| `MapRemote` | `--map-remote [\|filter]\|url-regex\|replacement` | replaces matches in the absolute URL (`\1` or `$1` for groups) and sends the request there, with `Host` to match; inside intercepted sessions too |
| `ModifyBody` | `--modify-body [\|filter]\|regex\|[@]replacement` | replaces matches in decoded request and response bodies (`~q` / `~s` pick one side); the replacement is literal, `@file` reads it from a file |
| `ModifyHeaders` | `--modify-headers [\|filter]\|name\|[@]value` | removes the header, then adds the value (none if empty), on requests and on server responses |
| `BlockList` | `--block-list \|filter\|status` | answers with an empty response of that status; `444` closes the connection without one (resets an HTTP/2 stream) |
| `AntiCache` | `--anticache` | removes `If-None-Match` and `If-Modified-Since`, so servers send whole responses |
| `StickyCookie` | `--stickycookie filter` | remembers every `Set-Cookie` (RFC 6265 `Domain`, `Path`, `Max-Age`/`Expires`, `Secure`) in one jar for all clients, and adds the cookies to requests the filter matches, keeping the client's own |

**Filter expressions** are a compact subset of mitmproxy's (`org.microproxy.extras.FlowFilter`):

| expression | matches |
|---|---|
| `~u regex`, or a bare `regex` | the URL (absolute; `https://` inside intercepted sessions) |
| `~d regex`, `~m regex` | the host, the method |
| `~h regex`, `~hq regex`, `~hs regex` | a `Name: value` header line of the request or response, the request, the response |
| `~t regex`, `~tq regex`, `~ts regex` | the `Content-Type` of either, the request, the response |
| `~b regex`, `~bq regex`, `~bs regex` | the decoded body of either, the request, the response |
| `~c code`, `~q`, `~s`, `~a`, `~all` | the response status; no response yet; a response; an asset (CSS, JavaScript, images, fonts); everything |
| `!x`, `x & y`, `x \| y`, `(x)` | not, and, or, grouping |

`!` binds tightest, then `&`, then `|`; expressions side by side are joined by "and" with the lowest
precedence, as in mitmproxy (`a b | c` is `a & (b | c)`). Regexes are `java.util.regex`, searched
anywhere and ignoring case; put one with spaces or `()~'"` in quotes. A backslash in quotes only
escapes the quote and itself, so `"\d+"` keeps its `\d` (pyparsing would drop it).

**Cost.** The addons read heads only, so bodies keep the proxy's zero-copy relay. A body is buffered
only when a rule might need it, which the heads decide: `ModifyBody` buffers the messages a rule
might edit (and that it can decode; never event streams), and a filter that looks at a body
(`~bq secret`) buffers that body when the rest of the filter could still match. Body filters are
evaluated lazily, with three-valued logic: `~m GET & ~bq x` never buffers a `POST`. Request bodies
over the limit (10 MiB by default, `maxBodySize`) get `413`, as for any filter that buffers
requests; response bodies over it stream through unchanged.

The addon, HAR and replay options are command-line flags (and Java builders); properties files
do not take them.

**Order.** The command line chains them as mitmproxy does: `--save-har`, `--warc-dir` and
`--log-http` first, then `--block-list` and `--anticache`, then a `--script`, then
`--server-replay`, `--map-remote`, `--map-local`, `--modify-body`, `--modify-headers` and
`--stickycookie`; the cache comes last. The first short-circuit wins, so a blocked request is never
replayed, and a script sees requests before they are mapped elsewhere.

**Leaving an intercepted session.** Requests inside a `CONNECT` that the proxy intercepts normally
go to the `CONNECT` target. When a filter gives one an absolute URI of its own, as `MapRemote` does
and as a script does by assigning `req.uri = "https://other.example/..."`, the request goes to that
server instead: over TLS for `https://` (with the MITM manager's trust), with `Host` set to the new
authority, and on a server connection kept and pooled under the new target. Changing only `Host`
or an origin-form path keeps the request on the session's server. The session's
[ALPN mirroring](#alpn-mirroring) still applies to the new server, and a plain HTTP session after
`CONNECT` and a [reverse proxy](#reverse-proxy-mode) are left the same way. Absolute `https://`
URIs in plain forward requests are fetched over TLS too.

### HAR files

`org.microproxy.extras.HarRecorder` writes the exchanges it sees as an HTTP Archive (HAR 1.2), as
mitmproxy's `--set hardump=` and `save.har` do, for browser developer tools, HAR viewers and
[replay](#replaying-traffic):

```bash
java -jar microproxy.jar --mitm --save-har flows.har                         # written on exit
java -jar microproxy.jar --mitm --save-har flows.har --save-har-stream --save-har-filter '~d example.com'
```

```java
HarRecorder har = HarRecorder.builder(Path.of("flows.har")).filter(FlowFilter.parse("!~a")).build();
MicroProxy.bootstrap().withFiltersSource(HttpFiltersChain.of(har, otherFilters)).start();
// ... har.close() writes the file; har.save(path) writes a snapshot at any time.
```

- **Entries:** the request as the client sent it (method, absolute URL, version, headers, cookies,
  query string, `postData` with form `params`) and the response as the client received it (status,
  headers, cookies with `expires`, `redirectURL`, decoded content as text, or base64 with
  `"encoding": "base64"` for binary bodies). Also `serverIPAddress`, the client `connection` id,
  and `_source` (`server`, `filter`, `cache`, `replay` or `proxy`). Responses from filters, the
  cache and replays are recorded too; `CONNECT` tunnels are not. An exchange that ends without a
  response has status `0` and an `_error`.
- **Timings** come from [`FlowTimings`](#observability): `dns`, `connect` (including `ssl`, as HAR
  says), `send`, `wait` and `receive`, and `-1` for a phase that did not happen (no lookup or
  connect on a reused connection; inside an intercepted session the server handshake belongs to the
  `CONNECT`).
- **Bodies** are captured as they stream past, up to `maxBodySize` each (1 MiB by default,
  `--save-har-max-body`); a longer one is cut short and marked `_truncated`, and is not replayed.
  Capturing bodies turns off the zero-copy relay for recorded exchanges; `content(false)`
  (`--save-har-max-body 0`) records heads only and keeps it.
- **Memory:** by default every entry, bodies included, stays in memory until the file is written on
  exit (or `close()`), as with mitmproxy's `hardump`: plan for up to twice `maxBodySize` per
  exchange (a third more for base64). `stream(true)` (`--save-har-stream`) appends each entry to the
  file as it completes and keeps nothing; the file is valid JSON once closed. A name ending in
  `.zhar` is written zlib-compressed.

The JSON is written and read by a small package-private writer and parser shared with
`HttpLogger` and `ActivityLogger`; there is no JSON dependency.

### Replaying traffic

**Server replay** (`ServerReplay`, `--server-replay path`) answers requests from recorded
responses instead of contacting servers, as mitmproxy's `server_replay`. Recordings are HAR files
(from `HarRecorder`, browsers or mitmproxy, `.har` or `.zhar`), WARC files (from `WarcRecorder`:
`--server-replay warcs/` takes the whole directory) or both:

```bash
java -jar microproxy.jar --mitm --server-replay flows.har --server-replay-ignore-params _,cb \
    --server-replay-extra 404
```

```java
ServerReplay replay = ServerReplay.builder().load(Path.of("warcs")).ignoreHost(true).reuse(true).build();
MicroProxy.bootstrap().withFiltersSource(replay).start();
```

- **Matching** ports mitmproxy's `_hash`: scheme, method, path, request body, host, port and query
  parameters (in order) must be equal. `--server-replay-ignore-content`, `-ignore-host`,
  `-ignore-port`, `-ignore-params a,b` and `-ignore-payload-params a,b` (form bodies) loosen it;
  `--server-replay-use-headers a,b` adds headers. Request bodies are buffered to compare them (16
  MiB at most).
- **Use:** recordings answer once each, in recorded order, so a repeated request gets the recorded
  sequence of responses; `--server-replay-reuse` lets them answer again and again. Requests without
  a recording are forwarded (the default), killed (`--server-replay-extra kill`, the connection is
  closed) or answered with an empty response (`--server-replay-extra 404`).
- **Refresh:** `Date`, `Expires`, `Last-Modified` and cookie expiry move forward by the time since
  the recording (`--server-replay-no-refresh` keeps them).
- **Bodies:** HAR content is decoded, so it is served without its `Content-Encoding`; WARC bodies
  keep the coding they arrived with. The proxy sets `Content-Length`.
- **Source:** replayed answers are `ResponseSource.REPLAY` to trackers, access logs (`REPLAY`),
  `HttpLogger` (`source=replay`) and `HarRecorder` (`_source`).
- All recordings are held in memory.

**Client replay** (`ClientReplay`, `--client-replay path`) sends recorded requests again, as
mitmproxy's `client_replay`. They go to the proxy's own listener as ordinary client requests in
absolute form, so every filter, addon, script, cache and recorder applies, and the proxy fetches
`https://` URLs over TLS. `--client-replay-concurrency n` (default 1) bounds the requests in
flight; the proxy stops when they are done, unless `--keepserving` is given. Recorded framing and
hop-by-hop headers are not sent, and a proxy that requires authentication answers them `407`.

```bash
java -jar microproxy.jar --client-replay flows.har --save-har replayed.har   # replay, record, exit
```

**With scripts.** The command-line addons and recorders compose with `--script`: the script runs
after `--block-list` and `--anticache` and before the other addons (as in mitmproxy), its
`on_request` can move a request elsewhere by assigning `req.uri`, and recorders and loggers placed
first see what the script changed. From Java, put a `ScriptedProxy` anywhere in an
`HttpFiltersChain` with the addons; a script that wants to keep a HAR of its own traffic can be
chained after a `HarRecorder` and the HAR written with `har.save(path)`.

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

`org.microproxy.warc.WarcReader` reads WARC files back, record by record (plain or gzip, one member
per record or one for the file), and `--server-replay warcs` answers requests from the responses
in a directory of them (see [Replaying traffic](#replaying-traffic)).

### Scripting with Starlark

The optional `microproxy-starlark` module runs proxy logic written in
[Starlark](https://github.com/bazelbuild/starlark/blob/master/spec.md), the Python dialect Bazel
uses for configuration. Scripts are sandboxed: they have no file, network or process access,
cannot change global state after loading, and each hook call is limited in steps, wall-clock
time and the bytes of values it creates (10 million steps, 5 seconds and 256 MiB by default; see
[Budgets and measurements](#script-budgets)). One loaded script is shared by every connection.

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
MICROPROXY_VERSION=0.1.2-SNAPSHOT
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --mitm --script proxy.star
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
| `on_client_hello(hello, ctx)` | once a client that may be intercepted has sent its TLS ClientHello (after `allow_mitm` and the host rules), over TCP or in the Initial packets of a [transparent QUIC](#transparent-quic) flow | `False` to tunnel (or relay) the connection untouched; `True` or `None` to intercept |
| `buffer_request(req, ctx)` | before `on_request`, for requests with a body | whether to buffer it so `req.body` is available (default: no) |
| `buffer_response(req, res, ctx)` | before `on_response` | whether to buffer it (default: text in a decodable coding, except `text/event-stream`) |
| `on_websocket_frame(req, frame, ctx)` | for each frame of an upgraded WebSocket, in both directions | `None` to forward the frame (with any changes), `False` to drop it |
| `on_websocket_message(msg, ctx)` | for each whole text or binary message of an upgraded WebSocket, in both directions, joined from its frames and inflated (after `on_websocket_frame`, if defined, has seen the frames) | `None` (or `msg`) to send the message with any changes, `False` to drop it, another message to replace it, or a list of messages to send instead (`[]` drops it) |
| `on_failure(req, failure, ctx)` | when the proxy has to answer the request itself (see [Failure responses](#failure-responses)) | `response(...)` to answer, or `None` for the `FailureResponder`'s answer or the default |
| `on_frame(frame, ctx)` | for each HTTP/2 and HTTP/3 frame, in each direction and on each side, when the script defines it (see [Frames](#frames)); and for HTTP/3 frames run through an `Http3FramePipeline` | `None` (or the frame) to pass the frame on with any changes, `False` to drop it, another frame to replace it, or a list of frames to replace it with |
| `on_tcp_start(ctx)`, `on_tcp_message(msg, ctx)`, `on_tcp_end(ctx)` | for raw TCP tunnels, when the script defines one of them (see [Raw TCP](#tcp-hooks)): when a tunnel opens, for the bytes of each read, and when it ends | `on_tcp_message`: `None` (or `True`, or the message) to pass the bytes on with any changes, `False` to drop them, or bytes, a string or another message to replace them |
| `on_udp_start(ctx)`, `on_udp_message(msg, ctx)`, `on_udp_end(ctx)` | for CONNECT-UDP flows, when the script defines one of them (see [UDP](#udp-hooks)): when a flow opens, for each datagram, and when it ends | `on_udp_message`: as `on_tcp_message`, for one datagram |
| `on_quic_start(ctx)`, `on_quic_stream_data(msg, ctx)`, `on_quic_datagram(msg, ctx)`, `on_quic_end(ctx)` | for QUIC that is not HTTP/3, intercepted stream by stream, when the script defines one of them (see [QUIC](#quic-hooks)): when a connection is intercepted, for the bytes of each read of a stream, for each datagram, and when it ends | `on_quic_stream_data`: as `on_tcp_message`; `on_quic_datagram`: as `on_udp_message` |
| `on_quic_message(msg, ctx)` | for each whole message of a stream that [QUIC message framing](#quic-message-framing) cuts into messages (DNS over QUIC by default), instead of `on_quic_stream_data` | as `on_websocket_message`: `None` (or `msg`) to send the message with any changes, `False` to drop it, another message (or bytes, or a string) to replace it, or a list of them to send instead (`[]` drops it); each is framed again |
| `quic_message_length(data)` | a framer of the script's own, for the streams `--quic-framing` gives to `script`: given the bytes kept of a stream direction | the length of the whole message they start with, or `None` until the bytes say |
| `authenticate(req, ctx)` | before the other hooks, for requests and `CONNECT`s from clients that have not authenticated (every request with `AUTHENTICATE_EVERY_REQUEST = True`); only when the script is the proxy authenticator | the user name or `True` to accept; `False` or `None` for the default `407`; `response(...)` to reject with that answer |

**Objects.**

- `req`: `method`, `uri` (assignable), `url`, `scheme`, `host`, `port`, `path`, `query`, and
  `headers`, `body`, `text`, plus `http_version`: the version the client used, `"HTTP/1.1"`,
  `"HTTP/1.0"`, `"HTTP/2"` or `"HTTP/3"` (requests reach servers as HTTP/1.1, or as HTTP/2 or
  HTTP/3 to servers that speak it with `http2_upstream` or `http3_upstream`).
- `res`: `status`, `reason` (assignable), and `headers`, `body`, `text`, plus `source` and
  `upstream_status` (below).
- `body` and `text`: the decoded body as bytes or as a string. Both are `None` when the body was
  streamed rather than buffered. Assigning either re-encodes the body.
- `headers`: case-insensitive. `h["name"]` (first value), `h["name"] = v`, `"name" in h`,
  `get`, `get_all`, `set`, `add`, `remove`, `keys`, `items`.
- `ctx`: `client_ip`, `client_port`, `user` (from proxy authentication), `connection_id`, `tls`,
  `timings` (below), `client_hello` (the ClientHello that started the intercepted session, or
  `None`), `forwarded_via` (the client's HTTPS or HTTP proxy, `host:port`, that a `CONNECT` or an
  absolute-form request inside its session, or a request inside the tunnel one opened, goes
  through, else `None`; see
  [In front of an HTTP or HTTPS proxy](#in-front-of-an-http-or-https-proxy)), `socks_version` (5
  or 4 for a [SOCKS client](#socks5-mode), else `None`), `transparent_quic` (whether the client's
  QUIC came to the [transparent QUIC](#transparent-quic) listener), `early_data` (whether the
  HTTP/3 request arrived as 0-RTT early data, which may be a replay; see
  [Session resumption and 0-RTT](#session-resumption-and-0-rtt)), `failure` (why the proxy has to
  answer the request itself, a `Failure` as `on_failure` gets it, else `None`), `response_flags`
  (the exchange's [response flags](#response-flags-and-details) so far, as short codes: `["UF"]`),
  `response_code_details` (`"proxy_failure:connect_failed"`, ..., or `None`), `script_stats`
  (what the calls into scripts for the exchange added up to before this one: `calls`, `time_ms`,
  `steps` and `alloc_bytes`; see [Budgets and measurements](#script-budgets)), and `vars`, a dict that lives for
  one request so `on_request` can pass values to `on_response`. For a WebSocket it lives as long
  as the connection.
- `hello` (and `ctx.client_hello`): `sni` (`None` without one), `alpn` (the offered protocols, in
  the client's order), `versions` (`"TLSv1.3"`, `"TLSv1.2"`, ...) and `cipher_suites` (numbers).
  Its type is `ClientHello`.
- `failure`: `kind` (`"unresolved_host"`, `"connect_failed"`, `"tls_failed"`,
  `"server_timeout"`, `"bad_server_response"`, `"no_route"`, `"no_connection_available"`,
  `"bad_request"`, `"request_too_large"`), `status` (of the default answer), `host` (the server's
  name without the port; `None` for `bad_request`, `request_too_large` and a request that names
  no host), and `message`: the cause's message
  (`Connection refused`, ...) or the reason, never a stack trace.
- `frame`: `type` (`"text"`, `"binary"`, `"continuation"`, `"close"`, `"ping"`, `"pong"`),
  `opcode`, `fin`, `from_client`, `length`, `truncated`, and `text` and `payload`, which can be
  assigned. `text` is `None` for a payload that is not UTF-8; both are `None` for a truncated
  frame. (In `on_frame`, `frame` is an HTTP/2 or HTTP/3 frame: see [Frames](#frames).)
- `msg`: `type` (`"text"` or `"binary"`), `from_client`, `length`, and `text` and `payload`, which
  can be assigned. `text` is `None` for a payload that is not UTF-8. Its type is `WebSocketMessage`.

**Built-ins.**

- From Starlark: everything in the language spec, including `json.encode`/`json.decode`.
- `response(status=200, body="", headers=None, content_type=None)`.
- `websocket_message(content, from_client=...)`: a message for `on_websocket_message` to return,
  text from a string or binary from bytes; `from_client=True` sends it towards the server,
  `False` towards the client.
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
- `h2.data(stream_id, payload, end_stream=False)`, `h2.headers(stream_id, headers,
  end_stream=False)`, `h2.unknown(type, stream_id, payload, flags=0)`, and `h3.data(payload)`,
  `h3.headers(headers)`, `h3.unknown(type, payload)`: frames for `on_frame` to return. `headers`
  is a dict, a list of `(name, value)` pairs, or a `Headers`; `payload` is bytes or a string.
- `time.now`/`monotonic`, and `log.debug`/`info`/`warn`/`error`. `print` also goes to the log.
- `protobuf` and `grpc`: protobuf messages as dicts, and gRPC's framing (see **Protobuf and
  gRPC** below).
- `dns`: DNS messages as dicts, for DNS over QUIC, DNS over HTTPS bodies and DNS in UDP flows
  (see **DNS** below).
- More with `load()`: Python's `hashlib`, `hmac`, `re`, `urllib.parse`, `json`, `zlib`, ... (see
  **Standard library** below).

**Protobuf and gRPC.** `protobuf.decode(data)` turns a message into a dict keyed by field number,
decoded as the [protobuf view](#protobuf-without-a-schema) decodes it: varints are ints (negative
when the top bit is set), text is `str`, other bytes `bytes`, nested messages dicts, and a field
that occurs more than once a list. `protobuf.encode(fields)` turns such a dict back into bytes, the
same bytes for what `decode` made. Fixed-width values decode to `ProtoFixed` values (`.value`,
`.signed`, `.float`, `.bits`) and groups to `ProtoGroup` values (`.fields`), so that they encode
back as they were; `protobuf.fixed32(x)`, `fixed64(x)` and `group(fields)` make new ones. A float
encodes as a `fixed64` double.

| Function | |
|---|---|
| `protobuf.decode(data, type=None)`, `protobuf.encode(fields, type=None)` | bytes to dict and back; with `type`, by field name |
| `protobuf.render(data, type=None)` | the YAML the protobuf view shows |
| `protobuf.fixed32(x)`, `protobuf.fixed64(x)`, `protobuf.group(fields)` | fixed-width values (from an int or a float) and groups |
| `protobuf.pack(ints)`, `protobuf.unpack(data)`, `protobuf.zigzag_encode(n)`, `protobuf.zigzag_decode(n)` | packed repeated integers, and `sint32`/`sint64` values |
| `grpc.messages(body, encoding=None)`, `grpc.frame(messages, encoding=None)` | a gRPC body to its messages (bytes, decompressed) and back (compressed when an encoding is given: `gzip` or `deflate`) |
| `grpc.decode(body, encoding=None, type=None)`, `grpc.encode(dicts, encoding=None, type=None)` | the same, with `protobuf.decode` and `encode` of each message |
| `grpc.status(details)`, `grpc.status_details(code, message, details=[])` | `grpc-status-details-bin` to a dict (`code`, `name`, `message`, `details`) and back |
| `grpc.code_name(code)` | `INVALID_ARGUMENT` for 3, ... |

Rewrite every message of a gRPC response (the call's body must be buffered, so streaming calls
wait for the whole stream):

```python
def buffer_response(req, res, ctx):
    return res.headers.get("content-type", "").startswith("application/grpc")

def on_response(req, res, ctx):
    if res.body == None:
        return None
    encoding = res.headers.get("grpc-encoding")
    messages = grpc.decode(res.body, encoding=encoding)
    for m in messages:
        m[1] = m[1].upper()
        m[2] = m[2] + 41
    res.body = grpc.encode(messages, encoding=encoding)
    return None
```

Requests work the same with `buffer_request` and `on_request`. A hook for single HTTP/2 frames
(`on_frame`) is being added separately; the same functions apply to each frame's bytes there. With
a schema from Java, `ScriptedProxy.builder(path).protoSchema(ProtoSchema.load(Path.of("api.desc")))`,
`protobuf.decode(data, type="shop.Order")` keys fields by name (enum values by name too) and
`protobuf.encode(fields, type="shop.Order")` takes names. Typed scripts can annotate with
`ProtoFixed` and `ProtoGroup`; the dicts are untyped.

**DNS.** `dns.decode(data)` turns a DNS message (wire format) into a dict, and `dns.encode(m)`
turns such a dict back into bytes, owner names compressed; `dns.render(data)` is the text `dig`
would show. The dict:

| Key | Value |
|---|---|
| `id`, `flags` | the message ID, and the header's 16 bits of flags |
| `response`, `opcode`, `authoritative`, `truncated`, `recursion_desired`, `recursion_available`, `rcode` | the flags by name; `encode` lets them win over `flags` |
| `questions` | dicts with `name`, `type` and `class` |
| `answers`, `authorities`, `additionals` | dicts with `name`, `type`, `class`, `ttl` and `data` |

Names are written without the final dot. Types are names (`"A"`, `"AAAA"`, `"MX"`, `"TYPE65280"`
for a type without one), and `encode` also takes numbers. The `data` of A and AAAA records is the
address (`"192.0.2.1"`, `"2001:db8::1"`), of NS, CNAME, PTR and DNAME records the name, of TXT
records a list of strings, of MX, SRV and SOA records a dict of their fields (`preference` and
`exchange`; `priority`, `weight`, `port` and `target`; `mname`, `rname`, `serial`, `refresh`,
`retry`, `expire` and `minimum`), and of other types (an EDNS `OPT` record included) its bytes;
`encode` takes bytes for any type. `encode` fills in what is left out: `id` 0, `class` 1 (IN),
`ttl` 0, no flags.

**Where a response came from, and how long it took.** `res.source` tells the server's responses
from the others, like the `source` of the [access log](#access-logs-envoy-compatible), and `res.upstream_status`
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

**The exchange's trace.** With a tracer ([OpenTelemetry](#opentelemetry)), `ctx.trace_id` and
`ctx.span_id` are the exchange's trace id and the proxy's span id for it, in hex (`None` without
one), and the `trace` module adds to that span: `trace.set_attribute(key, value)` (a string, bool,
int, float or a list of those), `trace.add_event(name, attributes={})`, and
`trace.is_recording()`, false when the exchange is not sampled and the calls would be ignored. In
the TCP, UDP and QUIC hooks they add to the span of the tunnel or flow; in hooks that run for no
exchange (`upstream`, `quic_message_length`) they do nothing. The span's
[limits](#opentelemetry) bound what a script adds.

Each hook call for a sampled exchange is also a span of its own, `starlark <hook>` (INTERNAL, a
child of the exchange's, tunnel's or flow's span), with `starlark.hook`, `starlark.script`,
`starlark.steps`, `starlark.alloc_bytes` and, when a [budget](#script-budgets) stopped it,
`starlark.budget_exceeded` (`steps`, `memory` or `time`); a call that failed has an error status
with its message. What `trace.set_attribute` and `trace.add_event` add goes on the exchange's span,
not on the hook call's: it describes the exchange, and stays in one place however many hooks see
it. Exchanges that are not sampled, and proxies without a tracer, get no hook spans and pay nothing
for them.

```python
def on_request(req, ctx):
    trace.set_attribute("tenant", req.headers.get("x-tenant", "none"))
    if trace.is_recording() and req.path.startswith("/admin"):
        trace.add_event("admin.access", {"user": ctx.user or "anonymous"})
    req.headers["X-Trace-Id"] = ctx.trace_id or "untraced"
```

**Deciding by the ClientHello.** `allow_mitm` runs when the `CONNECT` arrives, before the client
has said which server name it wants. `on_client_hello` runs once it has, and later hooks of the
session see the same ClientHello as `ctx.client_hello`:

```python
def on_client_hello(hello, ctx):
    # Banks keep their own certificates: tunnel them untouched.
    return not (hello.sni or "").endswith(".bank.example")

def on_request(req, ctx):
    hello = ctx.client_hello
    if hello != None:
        req.headers["X-Client-Alpn"] = ",".join(hello.alpn)
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
MICROPROXY_VERSION=0.1.2-SNAPSHOT
echo "TOKENS=alice:$(printf %s "$ALICE_TOKEN" | sha256sum | cut -d' ' -f1)" > tokens.properties
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --script auth.star --script-var-file tokens.properties
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

**WebSocket message examples.** `on_websocket_message(msg, ctx)` sees whole messages: a message
split into continuation frames arrives joined, and one compressed with permessage-deflate arrives
inflated, so a hook never has to reassemble or decompress anything. It follows `on_frame`'s
convention: change `msg.text` or `msg.payload` in place and return `None` (or `msg`) to send it,
`False` to drop it, another message to replace it, or a list of messages to send in its place.
Each message in a list goes the way its `from_client` says, so a script can answer a peer itself
with `websocket_message(..., from_client=not msg.from_client)`. `ctx.vars` is shared with
`on_request` and `on_websocket_frame` for the life of the connection; the hook does not get the
request, so keep what you need from it in `ctx.vars`. When a script defines both hooks, each frame
goes through `on_websocket_frame` first and `on_websocket_message` sees the message joined from
what that returned. A failing hook is logged and the message is sent unchanged.

Rewrite a field in JSON text messages from the client:

```python
def on_websocket_message(msg, ctx):
    if msg.type != "text" or not msg.from_client or not msg.text.startswith("{"):
        return None
    data = json.decode(msg.text)
    if data.get("room") == "staging":
        data["room"] = "production"
        msg.text = json.encode(data)
```

Drop binary messages over 64 KiB, and tell the client why:

```python
MAX_UPLOAD = 64 * 1024

def on_websocket_message(msg, ctx):
    if msg.type == "binary" and msg.length > MAX_UPLOAD:
        log.warn("dropped a %d-byte upload from %s" % (msg.length, ctx.client_ip))
        return [websocket_message('{"error": "upload too large"}', from_client=False)]
    return None
```

Log a compressed chat as plain text, with types:

```python
def on_request(req: Request, ctx: Context) -> Response | None:
    ctx.vars["chat"] = req.path
    return None

def on_websocket_message(msg: WebSocketMessage, ctx: Context) -> None:
    if msg.type == "text":
        sender = "client" if msg.from_client else "server"
        log.info("%s %s: %s" % (ctx.vars["chat"], sender, cast(str, msg.text)))
    return None
```

Messages larger than `withMaxWebSocketMessageSize` (16 MiB by default), joined or inflated, fail
the connection with close code 1009; see [WebSocket frames and
messages](#websocket-frames-and-messages) for the rest of the rules.

<a id="frames"></a>**Frames.** A script that defines `on_frame(frame, ctx)` sees HTTP/2 and
HTTP/3 frames on live connections ([Frame interception](#frame-interception) and
[HTTP/3 frames](#http3-frame-interception) describe where, and which changes the proxy accepts) and HTTP/3
frames run through an `Http3FramePipeline`. `--script` installs it
as the proxy's frame interceptor only when the script defines `on_frame` when it loads, so other
scripts cost nothing per frame (a reload that removes the hook passes frames on unchanged; one
that adds it takes effect after a restart). From Java: `bootstrap.withFrameInterceptor(script.frameInterceptor())`
when `script.definesFrameHook()`, and `Http3FramePipeline.builder(script.frameInterceptor())` for
HTTP/3. Like `on_websocket_frame`, the hook edits the frame in place: returning `None` (or the
frame) passes it on with its changes, so a hook that only looks drops nothing; `False` drops it,
and a list of frames replaces it (`[frame, extra]` adds a frame after it; `[]` drops it).

- `frame`: `protocol` (`"h2"` or `"h3"`), `type` (`"DATA"`, `"HEADERS"`, `"PRIORITY"`,
  `"RST_STREAM"`, `"SETTINGS"`, `"PUSH_PROMISE"`, `"PING"`, `"GOAWAY"`, `"WINDOW_UPDATE"`,
  `"CANCEL_PUSH"`, `"MAX_PUSH_ID"`, or `"UNKNOWN"` for extension and grease frames), `type_code`,
  `stream_id`, `end_stream`, `ack`, `direction` (`"from_client"`, `"to_client"`, `"from_server"`,
  `"to_server"`; `None` for frames the script made), and, where the frame type has them:
  `payload` and `text` (DATA and extension frames; assignable; `text` is `None` for a payload that
  is not UTF-8), `headers` (HEADERS: a `Headers`, live, pseudo-headers included, names lower-cased
  as they are set), `settings` (a live dict of name to value: `"MAX_CONCURRENT_STREAMS"`, ...,
  `"0x..."` for others), `error_code` (assignable) and `error` (its name, RST_STREAM and GOAWAY),
  `debug_data` (GOAWAY, assignable) and `last_stream_id` (GOAWAY). The others are `None`.
- `ctx`: `protocol`, `connection_id`, `stream_id`, `client_ip`, `client_port`, and `server` (the
  server's `host:port` for frames to and from servers, else `None`). Frames from the two
  directions and from many streams are seen concurrently; there is no `ctx.vars`.
- A failing hook, a wrong return value or a result that breaks the rules is logged, and the frame
  passed on unchanged.

Rewrite a header in the HEADERS frames clients send:

```python
def on_frame(frame, ctx):
    if frame.type == "HEADERS" and frame.direction == "from_client":
        frame.headers["user-agent"] = "MicroProxy"
        frame.headers.remove("x-debug")
```

Redact card numbers in DATA frames, in both directions. A pattern split across two frames is not
seen; a body whose length changes needs its `content-length` gone:

```python
def on_frame(frame, ctx):
    if frame.type == "HEADERS":
        frame.headers.remove("content-length")  # redacting changes the body's length
    elif frame.type == "DATA" and frame.text != None:
        frame.text = re.sub(r"\b[0-9]{13,16}\b", "<card>", frame.text)
```

Drop PRIORITY and extension frames:

```python
def on_frame(frame, ctx):
    if frame.type in ("PRIORITY", "UNKNOWN"):
        return False
```

Log what servers say about their connections:

```python
def on_frame(frame, ctx):
    if frame.direction != "from_server":
        return None
    if frame.type == "SETTINGS" and not frame.ack:
        log.info("%s settings: %s" % (ctx.server, frame.settings))
    elif frame.type == "GOAWAY":
        log.warn("%s goes away: %s after stream %d (%s)" % (
            ctx.server, frame.error, frame.last_stream_id, frame.debug_data))
```

Add frames: trailers after every response's last DATA frame (END_STREAM moves to them), and an
extension frame:

```python
def on_frame(frame, ctx):
    # Trailers after the last DATA frame of every response, and a hint before it.
    if frame.type == "DATA" and frame.direction == "to_client" and frame.end_stream:
        hint = h2.unknown(0xf0, 0, "checked")
        return [frame, hint, h2.headers(frame.stream_id, {"x-proxied-by": "MicroProxy"})]
```

Live HTTP/3, on a reverse proxy serving it (`--http3`): the client's requests get a field, and
the responses' bodies are redacted, so their `content-length` goes:

```python
def on_frame(frame, ctx):
    if frame.protocol != "h3":
        return None
    if frame.type == "HEADERS" and frame.direction == "from_client" and ":method" in frame.headers:
        frame.headers["x-from-frame"] = "stream %d" % ctx.stream_id
    elif frame.type == "HEADERS" and frame.direction == "to_client" and ":status" in frame.headers:
        frame.headers.remove("content-length")  # the DATA below changes the body's length
        frame.headers["x-h3-frame"] = "edited"
    elif frame.type == "DATA" and frame.direction == "to_client" and frame.text != None:
        frame.text = frame.text.replace("secret", "[redacted]")
```

The same kind of hook over HTTP/3 relayed by other means, through the pipeline:

```python
def on_frame(frame, ctx):
    if frame.protocol != "h3":
        return None
    if frame.type == "HEADERS" and ":method" in frame.headers:
        frame.headers["x-seen-by"] = "MicroProxy"
    elif frame.type == "DATA" and frame.text != None:
        return [frame, h3.data(" (checked)")]
    elif frame.type == "SETTINGS":
        frame.settings["MAX_FIELD_SECTION_SIZE"] = 16384
```

```java
ScriptedProxy script = ScriptedProxy.builder(Path.of("frames.star")).build();
Http3FramePipeline pipeline = Http3FramePipeline.builder(script.frameInterceptor()).build();
pipeline.requestStream(0, capturedRequestStream, rewritten);
```

With types: `Frame` and `FrameContext`. `headers`, `settings`, `payload` and the like are typed
`... | None`, so typed code casts them:

```python
def on_frame(frame: Frame, ctx: FrameContext) -> list[Frame] | bool | None:
    if frame.type == "UNKNOWN":
        return False
    if frame.type == "HEADERS" and frame.direction == "from_client":
        headers = cast(Headers, frame.headers)
        headers["x-stream"] = str(ctx.stream_id)
    return None
```

<a id="tcp-hooks"></a>**Raw TCP.** A script that defines `on_tcp_start(ctx)`, `on_tcp_message(msg, ctx)` or
`on_tcp_end(ctx)` sees the bytes of raw TCP tunnels, decrypted where the proxy intercepted TLS
that does not carry HTTP ([Raw TCP streams](#raw-tcp-streams) describes which tunnels). As with
`on_frame`, `--script` installs the TCP interceptor only when the script defines one of these
hooks when it loads, so other scripts leave tunnels on their fast path. From Java:
`bootstrap.withTcpInterceptor(script.tcpInterceptor())` when `script.definesTcpHooks()`.

- `msg`: `data` (bytes) and `text` (`None` when the bytes are not UTF-8), both assignable,
  `from_client` and `timestamp` (seconds since the epoch); `msg.with_data(data)` and
  `msg.with_text(text)` make changed copies. Its type is `TcpMessage`. TCP has no message
  boundaries: a message is whatever one read returned, so a line or a command may arrive in
  pieces, or several in one message.
- `ctx`: `connection_id`, `client_ip`, `client_port`, `host`, `port`, `server` (`host:port`),
  `tls` (whether the proxy decrypted the client's TLS), `sni` and `alpn` (or `None`), `vars`, a
  dict that lives as long as the tunnel, and `error`, why the tunnel failed (`None` otherwise, and
  before `on_tcp_end`). `ctx.send(from_client, data)` adds bytes as if that side had sent them
  (to the server when `from_client` is `True`), after the message being handled when sent in the
  same direction. Its type is `TcpContext`.
- The hooks of one tunnel run one at a time, though its two directions are read concurrently. A
  failing `on_tcp_message`, or one returning something else, is logged and the bytes passed on
  unchanged.

Rewrite a server's greeting, such as an SMTP banner, which arrives before the client says
anything:

```python
def on_tcp_message(msg, ctx):
    # The server's first message is its greeting.
    if not msg.from_client and not ctx.vars.get("greeted"):
        ctx.vars["greeted"] = True
        if msg.text != None:
            return msg.text.replace("ESMTP", "ESMTP (via MicroProxy)")
```

Log a line-based protocol (POP3, SMTP, IMAP, Redis), a line at a time whatever the reads:

```python
def on_tcp_start(ctx):
    log.info("%s opened by %s (tls %s, sni %s)" % (ctx.server, ctx.client_ip, ctx.tls, ctx.sni))

def on_tcp_message(msg, ctx):
    # TCP has no message boundaries: keep a line's start until its end arrives.
    side = "C" if msg.from_client else "S"
    lines = (ctx.vars.get(side, "") + (msg.text or "")).split("\n")
    for line in lines[:-1]:
        log.info("%s: %s" % (side, line.rstrip("\r")))
    ctx.vars[side] = lines[-1]

def on_tcp_end(ctx):
    log.info("%s closed%s" % (ctx.server, "" if ctx.error == None else ": " + ctx.error))
```

Drop a command, answering it in the server's place:

```python
def on_tcp_message(msg, ctx):
    # Never let a POP3 client delete mail: answer DELE in the server's place.
    if msg.from_client and msg.text != None and msg.text.upper().startswith("DELE "):
        ctx.send(False, "-ERR deleting is disabled here\r\n")
        return False
```

With types: `TcpMessage` and `TcpContext`. `text` is typed `str | None`, so typed code casts it; a
returned message replaces the bytes with its own:

```python
def on_tcp_message(msg: TcpMessage, ctx: TcpContext) -> TcpMessage | str | bool | None:
    if msg.text == None:
        return None
    text = cast(str, msg.text)
    if msg.from_client:
        return msg.with_text(text.upper())
    ctx.vars["lines"] = ctx.vars.get("lines", 0) + text.count("\n")
    return text + "!"
```

<a id="udp-hooks"></a>**UDP.** A script that defines `on_udp_start(ctx)`, `on_udp_message(msg, ctx)` or
`on_udp_end(ctx)` sees the datagrams of [CONNECT-UDP flows](#connect-udp-masque), which `--script`
then installs the UDP interceptor for (from Java: `bootstrap.withUdpInterceptor(script.udpInterceptor())`
when `script.definesUdpHooks()`). `msg` is a `UdpMessage`, one datagram, with the fields,
methods and results of a `TcpMessage` (`False` drops the datagram); `ctx` is a `UdpContext`:
`connection_id`, `client_ip`, `client_port`, `host`, `port`, `server`, `address` (what the
target's name resolved to) and `vars`, with `ctx.send(from_client, data)` to add a datagram.

```python
def on_udp_start(ctx):
    log.info("UDP flow to %s (%s) from %s" % (ctx.server, ctx.address, ctx.client_ip))

def on_udp_message(msg, ctx):
    # Drop the client's datagrams that mention "blocked"; tag the target's answers.
    if msg.text == None:
        return None
    if msg.from_client and "blocked" in msg.text:
        return False
    if not msg.from_client:
        return msg.text + " (via MicroProxy)"
```

<a id="quic-hooks"></a>**QUIC.** A script that defines `on_quic_start(ctx)`, `on_quic_stream_data(msg,
ctx)`, `on_quic_message(msg, ctx)`, `on_quic_datagram(msg, ctx)` or `on_quic_end(ctx)` sees the
streams and datagrams of QUIC that the proxy intercepts without speaking its protocol
([QUIC stream hooks](#quic-stream-hooks)).
`--script` installs the QUIC interceptor only when the script defines one of these hooks when it
loads, and only then is QUIC that offers no HTTP/3 intercepted rather than relayed (from Java:
`bootstrap.withQuicInterceptor(script.quicInterceptor())` when `script.definesQuicHooks()`).

- `msg`: a `QuicMessage`, with the fields, methods and results of a `TcpMessage`, and `stream_id`
  (`None` for a datagram) and `with_from_client`: the bytes of one read of a stream for
  `on_quic_stream_data` (a stream has no message boundaries either), one datagram for
  `on_quic_datagram`.
- `ctx`: a `QuicContext`: `connection_id`, `client_ip`, `client_port`, `host`, `port`, `server`,
  `address` (where the proxy connected), `sni`, `alpn`, `masque` (whether the QUIC came inside a
  CONNECT-UDP flow), `vars`, a dict that lives as long as the connection and that its streams
  share, and `error` in `on_quic_end` after a failure. In `on_quic_stream_data`, `stream_id` (on
  the client's connection), `bidirectional` and `client_initiated` name the stream (`None`
  elsewhere), and `ctx.send(from_client, data)` adds bytes to it. `ctx.send_datagram(from_client,
  data)` adds a datagram.
- The hooks of one connection run one at a time, though its streams are read concurrently. A
  failing hook is logged and the bytes passed on unchanged.
- `on_quic_message(msg, ctx)` sees the whole messages of the streams that
  [QUIC message framing](#quic-message-framing) cuts into messages: by default those of DNS over
  QUIC (ALPN `doq`), whose messages have a two-byte length, and those `--quic-framing` names
  (`--quic-framing myproto=varint,chat=lf`). `--script` frames streams only when the script
  defines `on_quic_message` when it loads (from Java: `script.quicInterceptor()` overrides
  `streamMessage` only then), and on those streams `on_quic_stream_data` is not called. `msg` is a
  `QuicMessage` whose `data` is the payload, without its length prefix or delimiter, with
  `stream_id` (`None` only for datagrams); `with_data`, `with_text` and `with_from_client` make
  copies. It returns as `on_websocket_message` does, each message going the way its
  `from_client` says (`msg.with_from_client(False)` answers the client on the same stream), and
  what it returns is framed again, with a length prefix computed for the new payload. A message
  larger than `--quic-max-message-size` (1 MiB) resets the stream with
  `--quic-message-error-code` (2). `ctx.send(from_client, data)` still sends bytes unframed.

```python
def on_quic_start(ctx):
    log.info("QUIC %s to %s for %s" % (ctx.alpn, ctx.server, ctx.client_ip))

def on_quic_stream_data(msg, ctx):
    # A stream is a byte stream, as TCP is: a message is whatever one read returned.
    if not msg.from_client and msg.text != None:
        return msg.text.replace("secret", "******")

def on_quic_datagram(msg, ctx):
    if msg.from_client and msg.text == "blocked":
        return False
```

DNS over QUIC through a transparent QUIC port, logging each query and answering a blocked name
with `0.0.0.0` by rewriting the server's answer (`--script doq.star`; `doq` is framed by default):

```python
BLOCKED = ["ads.example", "tracker.example"]

def on_quic_message(msg, ctx):
    # DNS over QUIC (ALPN doq): one DNS message each way on each stream.
    if ctx.alpn != "doq":
        return None
    m = dns.decode(msg.data)
    q = m["questions"][0]
    if msg.from_client:
        log.info("%s asks for %s %s" % (ctx.client_ip, q["name"], q["type"]))
    elif q["name"].lower() in BLOCKED:
        for answer in m["answers"]:
            if answer["type"] == "A":
                answer["data"] = "0.0.0.0"
                answer["ttl"] = 60
        msg.data = dns.encode(m)
```

A protocol of one's own, framed by the script (`--quic-framing tiny=script`): `quic_message_length`
gets the bytes kept of a stream direction and returns the length of the message they start with,
or `None` until it can tell; the message, its prefix included, goes to `on_quic_message` as it is,
and what that returns is sent as it is. A framer that fails resets the stream.

```python
def quic_message_length(data):
    # Each message: a byte with the length of what follows, then that many bytes.
    return 1 + data[0]

def on_quic_message(msg, ctx):
    # The message as quic_message_length cut it, its length byte included.
    if msg.from_client and msg.text != None:
        return msg.text.upper()
```

**Typed scripts.** Scripts may use Starlark's type annotations, which are checked when the
script loads and again on each call. Unannotated code is not checked, so annotations can be added
one function at a time. The proxy's objects are named `Request`, `Response`, `Headers`,
`Context`, `WebSocketFrame`, `WebSocketMessage`, `Failure`, `Timings`, `Frame`, `FrameContext`,
`TcpMessage`, `TcpContext`, `UdpMessage`, `UdpContext`, `QuicMessage` and `QuicContext`:

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

<a id="script-budgets"></a>
**Budgets and measurements.** Every hook call is bounded, and measured, three ways:

| budget | option (`StarlarkScript.Limits`) | default | checked |
|---|---|---|---|
| interpreter steps | `--script-max-steps <n>` (`maxSteps`) | 10000000 | at every statement and expression |
| wall-clock time | `--script-max-time <time>`, as `250ms`, `5s` or `1m` (`timeout`); `0` for none | `5s` | every 64 steps, and as they go by long-running builtins (`re`, the standard library's `re`, `hashlib.pbkdf2_hmac`) |
| bytes of values created | `--script-max-alloc <bytes>`, as `512k`, `64m` or `1g` (`maxAllocBytes`); `0` for none | `256m` | where values are made |

A call past a budget fails with an error (`too many steps`, `past expiration date` or `memory
budget exceeded`), which is handled as any failing hook is (below): the call stops at its next
check, cooperatively, and no thread is killed. Once past a budget, every later step of the call
fails too, so a script cannot catch the error and go on. `--script-name <name>`
(`ScriptedProxy.Builder.statsName`) names the script in its stats; by default it is the file name
without `.star`.

The bytes are an **estimate of what a call creates, not a measure of the heap**: the JVM cannot
count a virtual thread's allocations, so the interpreter counts the values it makes, at about
what they take on a 64-bit JVM: a string two bytes a character plus its objects (a Latin-1 string
takes half that), bytes their length, lists and tuples a reference a slot (a list each time its
array grows), dicts about 48 bytes an entry, structs and objects their fields; the strings and
objects builtins return (`json`, `re`, `base64`, `digest`, `codecs`, `url`, `protobuf`, `grpc`,
`dns`, the standard library's natives) count too, and ints, floats and booleans do not. Values
that become garbage stay counted, so the budget bounds the work a call does with memory rather
than what it keeps. A size known in advance is counted before the value is made, so
`"x" * 10**9`, `[0] * 10**9` or `list(range(10**9))` fail at once without allocating; `replace`,
`re.sub` and `json.encode` check as their output grows. The default leaves room for a buffered
10 MiB body (about 20 MiB as a string) to be copied several times, and for the heaviest tests of
the standard library (about 150 MB in one call), while stopping runaway allocation long before it
fills a heap.

With metrics, each script's calls are counted per hook, in `hooks.starlark.<script>.<hook>.*`
(see [Metrics](#metrics-envoy-compatible-stats)): `invocations`, `errors`, `latency_us`, the
histograms `steps` (in powers of ten up to the step limit) and `alloc_bytes` (in powers of four
from 1 KiB), and `budget_exceeded.steps`, `.memory` and `.time`. Each exchange adds its calls up
(`FlowContext.scriptStats()`: calls, time, steps and bytes), which a script reads as
`ctx.script_stats` and the access log shows with `%MP_SCRIPT_CALLS%`, `%MP_SCRIPT_TIME%`
(milliseconds), `%MP_SCRIPT_STEPS%` and `%MP_SCRIPT_ALLOC%`. A `ScriptCallObserver`
(`HttpProxyServerBootstrap.withScriptCallObserver`, or `ScriptedProxy.Builder.observer`) sees
each call start, and end with its steps, bytes, time, exhausted budget and error: the place for
tracing to make a span of each call.

```python
def on_response(req, res, ctx):
    s = ctx.script_stats  # the calls before this one, here on_request's
    res.headers["X-Script"] = "%d calls, %d steps, %d bytes" % (s.calls, s.steps, s.alloc_bytes)
```

Measuring costs little: without metrics, an exchange, an observer or budgets, a call reads a few
fields more, and counting allocations is a field addition where values are made (a thread-local
lookup where the interpreter does not hand its code the thread: list growth, tuples, dicts and
bytes); a representative hook (80 steps, 1 KB of values) runs within a few percent of its speed
before counting.

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

### WebSocket frames and messages

After a `101` upgrade or HTTP/2 WebSocket extended CONNECT, filters can watch and rewrite every
frame, or every whole message, in both directions and inside intercepted TLS:

- **Watching:** `webSocketFrameReceived(WebSocketFrame frame, boolean fromClient)` sees the
  opcode, FIN, masking and the unmasked payload. LittleProxy's
  `webSocketFrameReceived(Supplier<byte[]>, boolean)` still works and receives each frame's raw
  bytes (LittleProxy delivered raw TCP reads rather than frames).
- **Rewriting frames:** `filterWebSocketFrame(WebSocketFrame frame, boolean fromClient)` returns
  the frame to forward: `frame` itself, a replacement (`frame.withText(...)`,
  `WebSocketFrame.text(...)`, `binary(...)`, `close(code, reason)`), or `null` to drop it. The
  proxy masks frames it sends towards the server, as RFC 6455 requires. Messages split into
  continuation frames are seen one frame at a time.
- **Rewriting messages:** `filterWebSocketMessage(WebSocketMessage message, boolean fromClient)`
  sees a whole text or binary message, its frames joined. `WebSocketMessage` is a record (`type`
  `TEXT` or `BINARY`, `payload`, `fromClient`) with `text()`, `withText(...)`,
  `withPayload(...)`, `withFromClient(...)` and the factories `WebSocketMessage.text(...)` and
  `binary(...)`. Return the message, a replacement, or `null` to drop it. Override
  `filterWebSocketMessages` instead to return a list: each message goes towards the server when
  its `fromClient()` is true and towards the client otherwise, so a filter can answer a message
  itself or add messages in either direction. `HttpFilters.builder().onWebSocketMessage(...)`
  takes a lambda.
- **Order:** with both hooks, each frame goes through `filterWebSocketFrame` first, and
  `filterWebSocketMessage` sees the message joined from what it returned (a dropped frame adds
  nothing). Control frames (ping, pong, close) that arrive between a message's frames reach the
  frame hook and are forwarded at once; they never wait for the message.
- **Fragmentation:** a message returned unchanged goes out split as it arrived; an edited one
  goes out as a single frame.
- **Limits:** frames larger than `withMaxWebSocketFrameBufferSize` (default 1 MiB) arrive at the
  frame hook truncated, without a payload: returning them streams them through, `null` discards
  them. Frames of a message being joined, and compressed frames, are buffered whole instead, up
  to `withMaxWebSocketMessageSize` (default 16 MiB). A message larger than that, joined or
  inflated (a decompression bomb), fails the connection: both peers get a close frame with status
  1009 (message too big), as mitmproxy does. Frames out of order (a continuation outside a
  message, a new message before the last one ended) and invalid compressed data fail it with
  1002.
- **No listener:** if no filter overrides any of these methods, the connection is relayed as raw
  bytes. Frames are only joined into messages for filters that override a message hook, so frame
  filters keep relaying frame by frame, and filters that only watch frames leave compressed
  frames as they are (RSV1 set).

```java
@Override
public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
    if (!frame.isText()) return frame;
    String text = frame.payloadAsText();
    if (fromClient && text.contains("\"password\"")) return null;        // drop it
    return frame.withText(text.replace("staging.example", "prod.example")); // or rewrite it
}

@Override
public WebSocketMessage filterWebSocketMessage(WebSocketMessage message, boolean fromClient) {
    if (message.isBinary() && message.length() > 1 << 20) return null;    // drop big uploads
    return message.isText() ? message.withText(message.text().strip()) : message;
}
```

**permessage-deflate (RFC 7692).** Filters that rewrite frames or messages read compressed
traffic as plain text: the proxy inflates what each peer sends and compresses what it forwards
again. Each direction has two compression contexts, one per hop (client to proxy, proxy to
server), because a hook may change payloads, so the proxy cannot pass compressed bytes on and keep
the receiver's history in step with the sender's. The proxy keeps only the permessage-deflate
offers in the upgrade request's `Sec-WebSocket-Extensions` (it could not read frames of other
extensions) and otherwise leaves the negotiation to the client and server; it then applies what
the server's answer says to the server's hop and what the client received to the client's hop.

- `client_no_context_takeover` and `server_no_context_takeover` are honoured per direction: the
  proxy resets its compressor after each message when it is the sender that agreed to it, and its
  decompressor when the peer is.
- `server_max_window_bits` and `client_max_window_bits`: the JDK's `Inflater` always uses a 32
  KiB window, which reads anything a peer sends whatever window it agreed to. The JDK's `Deflater`
  cannot use a smaller window, and a peer that agreed to a smaller one may keep only that much
  history, so a back-reference further back would corrupt what it reads. Resetting the compressor
  after each message would not help, since one message longer than the window can refer back
  across it. Towards a peer whose window is under 15 bits the proxy therefore compresses with
  Huffman coding only (`Deflater.HUFFMAN_ONLY`): no back-references at all, which any window
  decodes. The parameters stay as the peers agreed them; only the proxy's own output compresses
  less.
- A message goes out compressed when its sender compressed it and the hop agreed to compression;
  a message a filter sends back to a peer is compressed whenever that hop agreed to it.
- `java.net.http.WebSocket` never offers extensions, so the tests use peers built on `Deflater`
  and `Inflater`.

### Raw TCP streams

`withTcpInterceptor(TcpInterceptor)` shows the bytes of every raw TCP tunnel to one interceptor,
with mitmproxy's TCP hooks: `tcpStart(ctx)`; `tcpMessage(msg, ctx)` for the bytes of each read,
which returns the bytes to pass on (`msg.data()` as it is or changed in place, others, or `null`
or an empty array to drop them); `tcpHalfClose(ctx, fromClient)` when one side finishes sending,
before the end is passed on; then `tcpEnd(ctx)`, or `tcpError(ctx, error)` when a read or write
failed, never both. `ctx.send(fromClient, bytes)` adds bytes as if that side had sent them, at any
time while that direction is open; sent from a `tcpMessage` call in the same direction, they
follow the message. `TcpContext` also gives the client connection's id and address, the target's
host and port, whether the proxy decrypted the client's TLS (`tlsIntercepted()`), the SNI and the
negotiated ALPN protocol.

```java
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withTcpHosts("^mail\\.example\\.com$")                      // --tcp-hosts, tcp_hosts
        .withTcpInterceptor((msg, ctx) -> {
            if (!msg.fromClient() && msg.text().startsWith("220 ")) {
                return msg.text().replace("ESMTP", "ESMTP (via MicroProxy)").getBytes(UTF_8);
            }
            return msg.data();
        })
        .start();
```

- **Which tunnels.** A `CONNECT` that is not intercepted (no MITM manager, an ignored host, a
  declined ClientHello, a protocol that is neither TLS nor HTTP, a server that speaks first), on
  an HTTP/1 connection or as a stream of an HTTP/2 one; whether the server is reached directly,
  through a chained proxy, on a stream of an HTTP/2 connection, or through the HTTP or HTTPS proxy
  of a session ([In front of an HTTP or HTTPS proxy](#in-front-of-an-http-or-https-proxy));
  `reverse:tcp://` connections; and a [SOCKS client](#socks5-mode)'s connection that is not
  intercepted or served as HTTP, which goes the way of a `CONNECT`. Upgraded WebSockets are not
  tunnels: their frames and messages go to the
  [WebSocket hooks](#websocket-frames-and-messages).
- **Messages.** TCP has no message boundaries. A `TcpMessage` is whatever one read returned (up
  to a buffer, 16 KiB by default), with `fromClient()` and a timestamp; a peer's write may show
  up in pieces, or joined with the next one. Hooks that look for lines or commands keep the start
  of one until its end arrives.
- **Threads.** Each direction is read by a thread of its own, so a tunnel's hooks are called
  from two threads at once: the interceptor must be thread-safe. Within a direction calls come in
  order, and the direction waits for each.
- **Half-close.** The end of one direction is reported, then passed on; the other direction goes
  on, as without hooks. (Intercepted TLS closes the whole connection there instead, as before:
  TLS peers differ in their support for half-close.)
- **The fast path.** Without an interceptor, tunnels copy bytes through pooled buffers without
  copying them again, as before; with one, each message gets an array of its own.

**TLS that does not carry HTTP.** Once the client's TLS is intercepted, the proxy decides what
the session is, as mitmproxy's next layer does inside TLS: an `h2` client is served as HTTP/2;
the [TCP hosts](#raw-tcp-streams) are raw TCP; an ALPN protocol of HTTP/1 is HTTP and any other
(`imap`, `mqtt`, ...) raw TCP; without ALPN, a server that speaks first (an SMTP banner) makes the
session raw at once, while the proxy waits for the client's first bytes, and otherwise those bytes
decide: a request line is HTTP, anything else raw TCP. A raw session is relayed between the
decrypted streams through the TCP hooks, whose context says `tlsIntercepted()`, with the SNI and
ALPN. With an interceptor, a client whose ALPN offers no HTTP protocol (an MQTT client offering
`mqtt`, say) is intercepted rather than tunnelled: the server is offered the client's protocols
and the client gets the server's choice. `acme-tls/1` (the ACME TLS-ALPN challenge) is never
intercepted, since no certificate the proxy makes could answer it. Without an interceptor such
clients are tunnelled untouched, as before.

**TCP hosts.** `withTcpHosts(...)` (`--tcp-hosts`, `tcp_hosts`) is mitmproxy's `tcp_hosts`: each
pattern is a regular expression searched for, ignoring case, in the target's host name and the
client's SNI (without ports). Their connections are raw TCP even when they speak HTTP: plain
bytes after a `CONNECT` are tunnelled rather than served as HTTP, and an intercepted TLS session
is relayed decrypted. TLS is still intercepted, unlike with `--ignore-hosts`.

**Limitations.** A session can be relayed as raw TCP only over a server connection of its own:
one shared as an HTTP/2 connection, a pooled one or none at all (offline interception) leaves it
served as HTTP. Bytes added with `send` do not pass through `tcpMessage`, unlike mitmproxy's
injected messages. UDP flows ([CONNECT-UDP](#connect-udp-masque)) have hooks of their own,
`withUdpInterceptor`, and so do the streams of intercepted QUIC, `withQuicInterceptor`
([QUIC stream hooks](#quic-stream-hooks)).

### Access logs (Envoy-compatible)

`ActivityLogger` writes one access-log line per finished exchange or flow. Its format strings are
compatible with Envoy's access-log command operators, so `%START_TIME%`, `%REQ(:PATH)%`,
`%RESPONSE_FLAGS%` and the rest mean what they mean in Envoy, and tools that read Envoy's logs
read these. Formats are parsed once, into an array of pieces that each render one literal or one
operator: rendering a line uses no regular expressions and allocates a few small strings.

```java
MicroProxy.bootstrap()
        .plusActivityTracker(ActivityLogger.builder()
                .format(LogFormat.envoy("[%START_TIME%] %REQ(:METHOD)% %REQ(:AUTHORITY)%%REQ(:PATH)%"
                        + " %RESPONSE_CODE% %RESPONSE_FLAGS% %DURATION%ms %UPSTREAM_HOST%"))
                .filter(AccessLogFilter.parse("status>=500 || response_flag"))
                .sink(AccessLogWriter.open(Path.of("access.log")))   // default: the System.Logger
                .build())
        .start();
```

From the command line, `--access-log <path|->` writes to a file (appended, a line flushed at a
time) or to standard output, in Envoy's default format unless `--access-log-format` (a format
string, or a preset's name) or `--access-log-json` (a JSON object of keys and format strings) says
otherwise; `--access-log-filter` (repeatable, all must pass) leaves lines out. Without
`--access-log`, the lines go to the `System.Logger` named `org.microproxy.extras.ActivityLogger`.
The properties file takes `access_log`, `access_log_format`, `access_log_json` and
`access_log_filter`.

```sh
java -jar microproxy.jar --port 8080 --access-log - \
    --access-log-format '[%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%" %RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS%'
# [2026-10-08T12:34:56.789Z] "GET /api HTTP/1.1" 502 UF proxy_failure:connect_failed

java -jar microproxy.jar --port 8080 --access-log access.jsonl \
    --access-log-json '{"start":"%START_TIME%","status":"%RESPONSE_CODE%","flags":"%RESPONSE_FLAGS%","ms":"%DURATION%","flow":"%MP_FLOW%"}' \
    --access-log-filter 'not_health_check && (status>=400 || duration>=1s)'
# {"start":"2026-10-08T12:34:56.789Z","status":504,"flags":"UT","ms":10003,"flow":"h2"}
```

**When lines are written.** Once per HTTP exchange, when its response has been written or it was
abandoned (then with the flag that says why); once per `CONNECT` tunnel (over HTTP/1, HTTP/2 or
HTTP/3), SOCKS client, WebSocket session, TCP-hook tunnel, CONNECT-UDP flow, QUIC flow
intercepted stream by stream and relayed transparent QUIC flow, when it closes, with its bytes,
duration and flags. A `CONNECT` the proxy intercepts is a line of its own, which ends when the
session inside starts; the requests inside are lines of their own. Trackers get the same records
from `ActivityTracker.flowEnded(FlowRecord)`.

**Text and JSON.** An operator whose value is unavailable renders `-`, as does an operator this
proxy does not know; `%%` is a literal `%`; `%OPERATOR(...):N%` keeps the first `N` characters. In
text formats, control characters in values are escaped (`\n`, `\t`, `\u0001`), so a header cannot
break a line. A trailing newline (Envoy's formats end with one) is dropped. In the JSON form a value
that is a single operator keeps the operator's type, as in Envoy: numbers for codes, sizes and
durations, `true` or `false` for flags, `null` when unavailable; other values are JSON strings.
Nested objects, numbers and booleans in the dictionary are written as they are.

#### Operators

| operator | value |
|---|---|
| `%START_TIME%`, `%START_TIME(fmt)%` | when the request started, UTC; default `2026-10-08T12:34:56.789Z`. `fmt` takes `%Y %y %C %m %d %e %j %H %I %M %S %p %b %B %a %A %u %w %z %Z %s %T %F %D %R`, and `%f` or `%1f`..`%9f` for fractions of a second |
| `%REQ(X?Y):N%`, `%REQUEST_HEADER(...)%` | the request header `X`, else `Y`; pseudo-headers `:method`, `:path` (no scheme or authority), `:authority`, `:scheme`, `:protocol`. The request as the client sent it |
| `%RESP(X?Y):N%`, `%RESPONSE_HEADER(...)%` | the response header (`:status` too) |
| `%TRAILER(X?Y):N%`, `%RESPONSE_TRAILER(...)%` | the response trailer |
| `%PROTOCOL%` | `HTTP/1.1`, `HTTP/1.0`, `HTTP/2` or `HTTP/3`: the client's |
| `%RESPONSE_CODE%` | the status the client got; `0` for none (a reset, a refused SOCKS client, a QUIC flow) |
| `%RESPONSE_CODE_DETAILS%` | why: see below |
| `%RESPONSE_FLAGS%`, `%RESPONSE_FLAGS_LONG%` | the flags, as `UF,URX` or `UpstreamConnectionFailure,UpstreamRetryLimitExceeded` |
| `%DURATION%` | milliseconds from the first byte of the request to the last of the response; for tunnels and flows, until they closed |
| `%REQUEST_DURATION%` | until the request was sent on to the server |
| `%RESPONSE_DURATION%` | until the first byte of the server's response |
| `%RESPONSE_TX_DURATION%` | from the first byte of the server's response to the last byte to the client |
| `%COMMON_DURATION(A:B:P)%` | between two points, in `ms`, `us` or `ns`: `START_TIME`, `DS_RX_BEG`, `DS_RX_END`, `US_CX_BEG`, `US_CX_END`, `US_HS_END`, `US_TX_END`, `US_RX_BEG`, `US_RX_END`, `DS_TX_END` |
| `%DOWNSTREAM_HANDSHAKE_DURATION%` | milliseconds of the TLS handshake with the client |
| `%BYTES_RECEIVED%`, `%BYTES_SENT%` | body bytes from and to the client; for tunnels and flows, the payload each way |
| `%UPSTREAM_WIRE_BYTES_SENT%`, `%UPSTREAM_WIRE_BYTES_RECEIVED%` | bytes to and from the server connection, heads and framing included |
| `%UPSTREAM_HOST%`, `%UPSTREAM_REMOTE_ADDRESS%` (`_WITHOUT_PORT`) | the server or chained proxy connected to |
| `%UPSTREAM_CLUSTER%` | the chained proxy's `host:port`, else the server's |
| `%UPSTREAM_LOCAL_ADDRESS%` (`_WITHOUT_PORT`) | the proxy's end of that connection |
| `%UPSTREAM_TRANSPORT_FAILURE_REASON%` | why the TLS handshake with the server failed |
| `%UPSTREAM_TLS_VERSION%`, `%UPSTREAM_TLS_CIPHER%`, `%UPSTREAM_PEER_SUBJECT%`, `%UPSTREAM_PEER_ISSUER%` | the TLS session with the server |
| `%DOWNSTREAM_REMOTE_ADDRESS%` (`_WITHOUT_PORT`), `%DOWNSTREAM_REMOTE_PORT%` | the client (the PROXY protocol's source, when one was accepted) |
| `%DOWNSTREAM_LOCAL_ADDRESS%` (`_WITHOUT_PORT`), `%DOWNSTREAM_LOCAL_PORT%` | the proxy's end of the client connection |
| `%DOWNSTREAM_TLS_VERSION%`, `%DOWNSTREAM_TLS_CIPHER%`, `%DOWNSTREAM_PEER_SUBJECT%`, `%DOWNSTREAM_PEER_ISSUER%`, `%DOWNSTREAM_PEER_FINGERPRINT_256%` | the TLS session with the client (listener or interception) and its certificate |
| `%REQUESTED_SERVER_NAME%` | the SNI the client sent |
| `%CONNECTION_ID%`, `%STREAM_ID%` | the client connection (as in `[conn <id>]` log lines) and the HTTP/2 or HTTP/3 stream |
| `%UNIQUE_ID%` | a random UUID per exchange, made only when a format asks for it; with [OpenTelemetry](#opentelemetry), the exchange's `X-Request-Id` |
| `%TRACE_ID%`, `%SPAN_ID%` | the exchange's trace id and the id of the proxy's span for it, with a tracer ([OpenTelemetry](#opentelemetry)) |
| `%HOSTNAME%` | this host's name |
| `%TLS_JA3_FINGERPRINT%`, `%TLS_JA4_FINGERPRINT%` | JA3 and JA4 of the client's ClientHello (JA4 starts with `q` for QUIC); `-` when the proxy read none |
| `%MP_RESPONSE_SOURCE%` | `SERVER`, `PROXY`, `FILTER`, `CACHE` or `REPLAY` |
| `%MP_FLOW%` | `h1`, `h2`, `h3`, `tunnel`, `socks`, `websocket`, `tcp`, `udp`, `quic` or `quic_relay` |
| `%MP_EARLY_DATA%`, `%MP_TRANSPARENT_QUIC%` | whether the request came as 0-RTT data; whether the client came to the transparent QUIC listener |
| `%MP_SOCKS_VERSION%`, `%MP_FORWARDED_VIA%` | the SOCKS version; the client's own proxy the request went through |
| `%MP_USER%`, `%MP_URL%`, `%MP_UPSTREAM_STATUS%` | the authenticated user; the absolute URL; the status the server sent (before a filter changed it) |
| `%MP_TIMING(phase)%` | `dns`, `connect`, `tls`, `client_tls`, `ttfb` or `total`, in milliseconds with three decimals |
| `%MP_SCRIPT_CALLS%`, `%MP_SCRIPT_TIME%` | the exchange's calls into [scripts](#script-budgets), and the milliseconds they took together, with three decimals |
| `%MP_SCRIPT_STEPS%`, `%MP_SCRIPT_ALLOC%` | the interpreter steps those calls ran, and about how many bytes of values they created (an estimate) |

#### Response flags and details

`FlowContext.failure()`, `responseFlags()` and `responseCodeDetails()` tell why an exchange ended
as it did; trackers, filters, scripts (`ctx.failure`, `ctx.response_flags`,
`ctx.response_code_details`) and `HttpLogger` lines see them. The proxy sets these flags (the
`ResponseFlag` enum names Envoy's flags, and a filter can add one with `ctx.addResponseFlag`):

| cause | flag | details |
|---|---|---|
| connection refused, unreachable or timed out (`ConnectFailed`) | `UF` | `proxy_failure:connect_failed` |
| the server's name did not resolve (`UnresolvedHost`) | `DF` | `proxy_failure:unresolved_host` |
| TLS with the server or a chained proxy failed (`TlsFailed`) | `UF`, and `%UPSTREAM_TRANSPORT_FAILURE_REASON%` | `proxy_failure:tls_failed` |
| the server did not answer in time (`ServerTimeout`) | `UT` | `proxy_failure:server_timeout` (`upstream_response_timeout` mid-response) |
| a malformed response (`BadServerResponse`) | `UPE` | `proxy_failure:bad_server_response` |
| the server closed before its response head was complete | `UC` | `proxy_failure:bad_server_response` |
| the server reset or closed mid-response | `UR` | `upstream_reset_after_response_started` |
| nowhere to send it (`NoRoute`) | `NR` | `proxy_failure:no_route` |
| the shared pool was exhausted (`NoConnectionAvailable`) | `UO` | `proxy_failure:no_connection_available` |
| a refused or malformed request (`BadRequest`), or one too large (`RequestTooLarge`) | `DPE` | `proxy_failure:bad_request`, `proxy_failure:request_too_large`, `downstream_protocol_error` |
| the client left before the response was complete | `DC` | `downstream_remote_disconnect` |
| the client reset its HTTP/2 or HTTP/3 stream | `DR` | `downstream_remote_reset` |
| a `ConcurrencyLimiter` refused it | `RL` | `concurrency_limited` |
| every chained proxy (with backoff between them) failed | `URX`, with the last one's flag | as the last failure |
| an exchange, tunnel or CONNECT-UDP flow sat idle for the idle timeout | `SI` | `stream_idle_timeout` |
| the proxy authenticator refused the client (`407`) | `UAEX` | `auth_rejected` |
| a filter aborted the exchange (returned `null`) | `LR` | `filter_aborted` |
| `425 Too Early` for a request in 0-RTT data | none | `too_early` |
| served from the cache, or by a filter's short-circuit, or from a replay | none | `cache`, `filter`, `replay` |
| the server's response, relayed | none | `via_upstream` |
| a transparent QUIC flow | none (`UAEX` when the authenticator refused it) | `quic_relayed`, `quic_dropped`, `quic_streams` |

The `ConcurrencyLimiter` answers `429` by default, as a rate limit does, so it sets `RL` rather
than `UO` (Envoy's circuit-breaker overflow, which this proxy keeps for its exhausted pool). A
`425 Too Early` has no flag: Envoy has none for it, and a custom one would be meaningless to its
tools; `too_early` in the details tells it apart. A response from the cache gets no `RFCF` either,
since the cache is no filter of Envoy's: `cache` in the details and `%MP_RESPONSE_SOURCE%` say it.

#### Filters

| filter | Java | compact syntax |
|---|---|---|
| status code | `statusCode(Comparison.GE, 500)` | `status>=500` (also `=`, `!=`, `<=`, `>`, `<`) |
| duration | `duration(Comparison.GE, 1000)` | `duration>=1000`, `duration>=1s` |
| not a health check | `notHealthCheck()` (`/healthz`, or Envoy's `User-Agent: Envoy/HC`), `notHealthCheckPath("/ready")`, `notHealthCheckHeader("X-Health-Check")` | `not_health_check`, `not_health_check(/ready)`, `not_health_check(header=x-health-check)` |
| response flags | `responseFlag()` (any), `responseFlag(UPSTREAM_OVERFLOW, ...)` | `response_flag`, `response_flag(UO,UF)` |
| request header | `header("x-debug")` (present), `header("user-agent", "curl/.*")` (whole value), `headerEquals(...)` | `header(x-debug)`, `header(user-agent~curl/.*)`, `header(x-env=prod)` |
| sampling | `runtime(10)` (by `X-Request-ID` when there is one, else at random) | `runtime(10)`, `sample(10%)` |
| combinators | `allOf(...)`, `anyOf(...)`, `a.and(b)`, `a.or(b)`, `a.negate()` | `&&` / `and`, `\|\|` / `or`, `!` / `not`, parentheses |

#### Presets

`LogFormat` names nine formats from LittleProxy, now presets of the same formatter, and Envoy's
default: `CLF`, `ELF` (combined), `JSON`, `SQUID`, `W3C`, `LTSV`, `CSV`, `HAPROXY`,
`JSON_EXTENDED` and `ENVOY`. `new ActivityLogger(LogFormat.CLF)` (or `--activity-log-format clf`,
or `--access-log-format clf`) uses one; each constant's documentation shows its format string.
`JSON_EXTENDED` adds `source`, `upstream_status`, `ttfb_ms`, `total_ms`, `dns_ms`, `connect_ms`,
`tls_ms`, `response_flags`, `response_code_details` and `flow` to the `JSON` line.

**Limitations.** Times are milliseconds: `%f` digits beyond them are zeros. `%REQUEST_DURATION%`
ends when the request was sent on to the server, and `DS_RX_END` is that point too.
`%BYTES_RECEIVED%` and `%BYTES_SENT%` count body bytes, not heads. Upstream wire bytes are what
passes the proxy's connection to the server: over TLS, the decrypted bytes.
`%DOWNSTREAM_LOCAL_ADDRESS%` is unknown for clients of the HTTP/3 listener. `%HOSTNAME%` is looked
up once. A transparent QUIC flow that is intercepted as HTTP/3 has a line per request, none of its
own.

Three ways to keep a record of traffic:

- **`ActivityLogger`:** one line per exchange or flow, in an access-log format. Cheap enough to
  leave on.
- **`HttpLogger`:** whole messages, with their headers, what the proxy and filters changed, and
  optionally bodies, as readable blocks or JSON lines. For debugging and audits (see
  [Request/response logging](#requestresponse-logging)).
- **`WarcRecorder`:** an archive of the exchanges with servers as binary WARC records, complete and
  unredacted, for replay tools (see [WARC recording](#warc-recording)).

### Metrics (Envoy-compatible stats)

With metrics on, the proxy keeps counters, gauges and histograms under Envoy's stat names, so
dashboards and alerts written for Envoy read them: `http.<name>.downstream_rq_5xx`,
`cluster.<cluster>.upstream_cx_connect_fail`, `listener.<address>.downstream_cx_active`, and so on.
They live in a `StatsRegistry` (package `org.microproxy.stats`); `StatsFormatter` renders them as
Prometheus's text exposition format, Envoy's `/stats` text dump, or its JSON form, and
`StatsdSink` pushes them to statsd. The [admin interface](#admin-interface) serves them over HTTP
(`/stats`, `/stats/prometheus`).

```java
StatsRegistry stats = StatsRegistry.builder().prefix("envoy").build();   // or .withMetrics(true)
HttpProxyServer proxy = MicroProxy.bootstrap().withName("edge").withStats(stats).start();
...
String scrape = StatsFormatter.prometheus(proxy.getStats());
// # TYPE envoy_http_downstream_rq_xx counter
// envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="edge",envoy_response_code_class="2"} 1042
// envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="edge",envoy_response_code_class="5"} 3
StatsdSink sink = StatsdSink.builder(stats, "127.0.0.1:8125").start();     // every 5 s; close() stops it
```

```sh
java -jar microproxy.jar --port 8080 --name edge --metrics
java -jar microproxy.jar --port 8080 --statsd 127.0.0.1:8125            # implies --metrics
java -jar microproxy.jar --port 8080 --dogstatsd 127.0.0.1:8125 --stats-prefix microproxy
```

| flag | property | meaning |
|---|---|---|
| `--metrics` | `metrics` | keep the stats |
| `--statsd <host:port>` | | push them to statsd over UDP every 5 seconds, and once more when the proxy stops (implies `--metrics`) |
| `--dogstatsd <host:port>` | | the same with DogStatsD tags (`name:1\|c\|#tag:value`) and tag-extracted names |
| `--stats-prefix <prefix>` | `stats_prefix` | prefix of exported names: `envoy` (the default) gives `envoy_http_downstream_rq_total` and `envoy.http.edge.downstream_rq_total`; `microproxy` gives `microproxy_...` |
| `--stats-max-clusters <n>` | | clusters with stats of their own, besides the fixed ones (default 100) |
| `--stats-cluster-lru` | | past that, evict the least recently used cluster's stats rather than counting new ones in `other` |
| `--stats-per-host` | | a cluster per server of direct connections (`host_port`) instead of one `direct` cluster |
| `--qlog-dir <dir>` | `qlog_dir` | write a qlog file per QUIC connection into `<dir>` ([qlog](#qlog-files)) |
| `--qlog-max-files <n>` | `qlog_max_files` | qlog files the directory keeps; past it, the oldest are deleted (default 1000) |

**Names and tags.** Every stat has Envoy's flat name, with its values in it, which the text dump and
statsd show. When it is registered, Envoy's tag extraction takes those values out as tags, which
Prometheus shows as labels on the tag-extracted name: `cluster.direct.upstream_rq_2xx` is
`envoy_cluster_upstream_rq_xx{envoy_cluster_name="direct",envoy_response_code_class="2"}`. The
tags are Envoy's `envoy_http_conn_manager_prefix` (the proxy's name, `withName`, `--name`),
`envoy_cluster_name`, `envoy_listener_address` (`0.0.0.0_8080`, `[__1]_8080`) and
`envoy_response_code_class`, and MicroProxy's `microproxy_response_flag`, plus those of the
per-protocol stats below: `microproxy_direction` (`downstream`, `upstream`), `microproxy_quic_scope`,
`microproxy_quic_error`, `microproxy_congestion_controller`, `microproxy_drop_reason`,
`microproxy_socks_version`, `microproxy_socks_reply`, `microproxy_reject_reason`,
`microproxy_tunnel_kind`, `microproxy_close_code`, `microproxy_hook`, and for scripts'
calls `microproxy_script`, `microproxy_script_hook` and `microproxy_budget`. Histograms are in
milliseconds, with Envoy's buckets (0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000,
30000, 60000, 300000, 600000, 1800000, 3600000), shown as `_bucket{le="..."}`, `_sum` and `_count`.

| stat | type | meaning |
|---|---|---|
| `http.<name>.downstream_rq_total` | counter | requests from clients (a `CONNECT` is one request, until its tunnel closes) |
| `http.<name>.downstream_rq_active` | gauge | requests in progress |
| `http.<name>.downstream_rq_1xx` ... `_5xx` | counter | responses by class (tag `envoy_response_code_class`) |
| `http.<name>.downstream_rq_time` | histogram | from a request's first byte to its response's last |
| `http.<name>.downstream_rq_http1_total`, `_http2_total`, `_http3_total` | counter | requests by protocol |
| `http.<name>.downstream_rq_rx_reset` / `_tx_reset` | counter | requests the client reset (`DR`) / the proxy reset or cut off after its response started |
| `http.<name>.downstream_rq_too_large` | counter | requests the proxy answered `413` |
| `http.<name>.downstream_rq_response_flag.<flag>` | counter | MicroProxy's: requests that ended with a 4xx or 5xx response, or none, by [response flag](#response-flags-and-details) (tag `microproxy_response_flag`: `UF`, `UT`, `DC`, ...) |
| `http.<name>.downstream_cx_total`, `_active` | counter, gauge | client connections (TCP, and QUIC connections of the HTTP/3 listener) |
| `http.<name>.downstream_cx_http1_total`, `_http2_total`, `_http3_total` | counter | connections by the protocols they carried (once each) |
| `http.<name>.downstream_cx_ssl_total` | counter | connections that completed a TLS handshake (TLS listener or interception) |
| `http.<name>.downstream_cx_destroy`, `_destroy_remote`, `_destroy_local` | counter | connections closed: by the client, or by the proxy (timeouts, `Connection: close`, stopping) |
| `http.<name>.downstream_cx_length_ms` | histogram | how long connections were open |
| `http.<name>.downstream_cx_rx_bytes_total`, `_tx_bytes_total` | counter | bytes read from / written to clients (decrypted, over TLS; HTTP/1 and HTTP/2) |
| `listener.<address>.downstream_cx_total`, `_active`, `_destroy` | counter, gauge | the TCP listener's connections |
| `listener.<address>.downstream_pre_cx_active` | gauge | connections not yet past the PROXY header, the TLS listener's handshake or protocol detection |
| `listener.<address>.ssl.handshake`, `ssl.connection_error` | counter | TLS handshakes with clients that succeeded / failed (the TLS listener and intercepted sessions) |
| `cluster.<cluster>.upstream_cx_total`, `_active` | counter, gauge | connections to servers or chained proxies |
| `cluster.<cluster>.upstream_cx_connect_fail`, `_connect_timeout` | counter | connection attempts that failed (TCP, TLS, a chained proxy's refusal) / timed out |
| `cluster.<cluster>.upstream_cx_connect_ms` | histogram | TCP connect time (QUIC: the handshake) |
| `cluster.<cluster>.upstream_cx_http1_total`, `_http2_total`, `_http3_total` | counter | connections by protocol |
| `cluster.<cluster>.upstream_cx_destroy`, `_destroy_local`, `_destroy_remote`, `upstream_cx_length_ms` | counter, histogram | connections closed, by whom, and how long they were open |
| `cluster.<cluster>.upstream_cx_pool_overflow` | counter | requests refused for want of a pooled connection (`UO`) |
| `cluster.<cluster>.upstream_rq_total`, `_active` | counter, gauge | requests sent to the cluster (each attempt) |
| `cluster.<cluster>.upstream_rq_1xx` ... `_5xx`, `upstream_rq_time` | counter, histogram | the server's responses by class, and request time |
| `cluster.<cluster>.upstream_rq_retry`, `_timeout`, `_rx_reset` | counter | requests sent again after a stale keep-alive connection; that timed out (`UT`); that the server reset or cut off (`UR`, `UC`) |
| `cluster.<cluster>.ssl.handshake`, `ssl.connection_error` | counter | TLS handshakes with servers and TLS chained proxies |
| `cluster.<cluster>.upstream_cx_rx_bytes_total`, `_tx_bytes_total` | counter | bytes read from / written to the cluster (decrypted over TLS, as the downstream ones; tunnels included; over QUIC, the datagrams' bytes, added when the connection closes) |
| `cluster.<cluster>.failover` | counter | connection attempts through the cluster that failed and moved on to the route's next choice |
| `cluster.<cluster>.backoff_engaged` | counter | waits ([retries and backoff](#retries-and-backoff)) before trying the cluster after earlier choices failed |
| `cluster.<cluster>.backoff_active` | gauge | requests waiting to try the cluster now: a lighter kind of outlier detection |
| `tls_inspector.tls_found`, `tls_not_found`, `sni_found`, `sni_not_found`, `alpn_found`, `alpn_not_found`, `client_hello_too_large` | counter | the ClientHellos the proxy reads to decide on a session (transparent TLS, interception) |
| `cache.hits`, `misses`, `stores`, `revalidations`, `stale_served` | counter | the [HTTP cache](#http-cache)'s counts (`HttpCache.stats()`) |
| `concurrency_limit.in_use`, `waiting` / `acquired`, `rq_blocked`, `reclaimed` | gauge / counter | the [concurrency limiter](#concurrency-limiting) among the filters |
| `connection_pool.total_connections`, `active_connections`, `idle_connections` / `borrow`, `return`, `eviction`, `validation_failure` | gauge / counter | the [shared pool](#shared-server-connection-pool) (`getServerConnectionPoolMetrics()`) |
| `server.uptime`, `live`, `concurrency`, `memory_allocated`, `memory_heap_size`, `total_connections` | gauge | seconds running, 1 while `LIVE` (0 once draining or stopping), processors, heap used and committed (`MemoryMXBean`), client connections open |
| `server.state` | gauge | Envoy's numbers: 0 live, 1 draining, 2 pre-initializing, 3 initializing (4 stopped) |
| `http.<name>.downstream_cx_drain_close` | counter | client connections told to go away while draining or with a failed health check (`Connection: close`, GOAWAY) |
| `listener_manager.total_listeners_active`, `total_listeners_draining` / `listener_stopped` | gauge / counter | listeners accepting, those accepting while the proxy drains / listeners closed |

**HTTP/2 and HTTP/3 codecs.** `http2.<direction>.*` and `http3.<direction>.*`, where the
direction is `downstream` (connections from clients) or `upstream` (to servers), Prometheus's
`microproxy_direction`. The names are Envoy's codec stats where Envoy has them; the floods are the
hardening limits of [`Http2Options`](#http2) and [`Http3Options`](#http3-and-quic) being hit,
each of which ends the connection.

| stat | type | meaning |
|---|---|---|
| `http2.<dir>.rx_reset`, `tx_reset` | counter | RST_STREAM received / sent |
| `http2.<dir>.goaway_sent`, `goaway_received` | counter | GOAWAY sent / received |
| `http2.<dir>.streams_active` | gauge | streams open |
| `http2.<dir>.header_overflow` | counter | header lists over SETTINGS_MAX_HEADER_LIST_SIZE (the stream is reset) |
| `http2.<dir>.headers_cb_no_stream` | counter | HEADERS for a stream already closed |
| `http2.<dir>.inbound_empty_frames_flood`, `inbound_priority_frames_flood`, `inbound_window_update_frames_flood` | counter | connections closed for too many empty DATA frames or trailers, PRIORITY and RST_STREAM frames, WINDOW_UPDATE frames |
| `http2.<dir>.outbound_control_flood` | counter | connections closed for too many PINGs or SETTINGS, each of which needs an answer |
| `http2.<dir>.inbound_rapid_reset_flood` | counter | MicroProxy's: connections closed for too many streams reset (or refused) before their response (Rapid Reset) |
| `http2.<dir>.settings_timeout` | counter | MicroProxy's: connections closed because the proxy's SETTINGS went unacknowledged |
| `http2.<dir>.rx_messaging_error` | counter | malformed frames, header blocks or messages received |
| `http2.<dir>.trailers` | counter | trailers received |
| `http2.<dir>.tx_flush_timeout` | counter | connections closed because writes made no progress for the idle timeout (a peer that stopped reading) |
| `http2.<dir>.stream_flow_control_blocked`, `connection_flow_control_blocked` | counter | MicroProxy's: times DATA waited for a stream's, or the connection's, send window |
| `http3.<dir>.rx_reset`, `tx_reset` | counter | request streams the peer reset / the proxy reset |
| `http3.<dir>.goaway_sent`, `goaway_received`, `streams_active` | counter, gauge | GOAWAY, and request streams open |
| `http3.<dir>.qpack_blocked_streams`, `qpack_decoder_errors` | counter | field sections that waited for the QPACK encoder stream / that QPACK could not decode |
| `http3.<dir>.unknown_frames`, `unknown_stream_types` | counter | frames of unknown types (and empty DATA) / unidirectional streams of unknown types received |
| `http3.downstream.early_data_requests`, `too_early_425` | counter | requests that arrived in 0-RTT data / that were answered `425 Too Early` |
| `http3.upstream.tcp_fallback` | counter | requests to a server known to speak HTTP/3 that went over TCP (its QUIC handshake failed, now or recently, or it took no new streams) |
| `http3.alt_svc_origins` | gauge | origins remembered as offering HTTP/3 in `Alt-Svc` |

**QUIC.** `quic.<scope>.*` counts the proxy's QUIC connections by scope (`microproxy_quic_scope`):
`downstream` (the HTTP/3 listener's), `transparent` (those the transparent QUIC listener
intercepts), `masque` (QUIC intercepted inside CONNECT-UDP flows) and `upstream` (the proxy's own,
to HTTP/3 servers and to the servers of QUIC intercepted stream by stream). A connection counts
its packets in plain fields of its own (`QuicConnection.stats()`, see the
[quic module](quic/README.md)); they are added to these counters once, when it closes.

| stat | type | meaning |
|---|---|---|
| `quic.<scope>.connections_active`, `connections_total` | gauge, counter | connections open / started |
| `quic.<scope>.handshake_failures.<error>` | counter | connections that ended before their handshake, by error (`microproxy_quic_error`): `timed_out`, `crypto_error` (TLS alerts), `connection_refused`, `protocol_violation`, `transport_error`, `peer_closed`, `application_closed`, `local_close`, `stateless_reset`, `version_mismatch` |
| `quic.<scope>.handshake_ms` | histogram | from a connection's start to its handshake's end |
| `quic.<scope>.rtt_ms` | histogram | smoothed RTT of connections when they closed |
| `quic.<scope>.packets_sent_total`, `packets_received_total`, `packets_lost_total` | counter | packets, counted at close |
| `quic.<scope>.bytes_sent_total`, `bytes_received_total`, `bytes_lost_total` | counter | UDP payload bytes, counted at close |
| `quic.<scope>.pto_total`, `congestion_events_total`, `key_updates_total` | counter | probe timeouts, congestion events, key updates, counted at close |
| `quic.<scope>.zero_rtt_accepted`, `zero_rtt_rejected` | counter | connections whose 0-RTT data was accepted / rejected |
| `quic.<scope>.migrations`, `nat_rebindings` | counter | moves to a new path, counted at close: the proxy following a client to its new address (a NAT rebinding, a migration, the preferred address; not a return to the old path after a failed validation), or the proxy's own connection switching to a path it probed / of those, the proxy following a client to a new port of the same address |
| `quic.<scope>.path_validations`, `path_validation_failures` | counter | PATH_CHALLENGEs answered / validations that got no PATH_RESPONSE in time: a client's new path the proxy then left for the old one, or a path the proxy probed |
| `quic.<scope>.stray_datagrams` | counter | datagrams from an address a connection takes no packets from, dropped: a client's new address during the handshake, or a server's that is not the one it connected to |
| `quic.<scope>.stateless_reset_received`, `dropped_datagrams` | counter | connections ended by a stateless reset; datagrams dropped because a connection fell behind |
| `quic.<scope>.congestion_controller.<name>` | counter | connections by congestion controller (`microproxy_congestion_controller`: `cubic`, `new_reno`, `bbr`) |
| `quic.<scope>.version_negotiation_sent`, `retry_sent`, `stateless_reset_sent`, `connections_refused` | counter | what the scope's server endpoints answered without a connection |

**Transparent QUIC and CONNECT-UDP.**

| stat | type | meaning |
|---|---|---|
| `quic_transparent.flows_active`, `pending_initials` | gauge | client flows known / whose ClientHello is being read or decided on |
| `quic_transparent.intercepted_total`, `relayed_total` | counter | flows intercepted (as HTTP/3, or stream by stream) / relayed untouched |
| `quic_transparent.dropped_initials.<reason>` | counter | datagrams of client flows dropped (`microproxy_drop_reason`): `cap` (a bound on pending or relayed flows, or held bytes), `malformed` (no readable ClientHello, too small), `timeout` (still pending), `refused` (no SNI, a `DROP` decision, a server that cannot be reached) |
| `quic_transparent.relay_rx_bytes_total`, `relay_tx_bytes_total` | counter | bytes relayed from clients / from servers, counted when relays end |
| `masque.udp_flows_active`, `udp_flows_total` | gauge, counter | CONNECT-UDP flows open / accepted |
| `masque.datagrams_rx`, `datagrams_tx`, `capsules_rx`, `capsules_tx` | counter | UDP payloads from / to clients, and those of them in DATAGRAM capsules, counted when flows end |
| `masque.rx_bytes_total`, `tx_bytes_total`, `datagrams_dropped` | counter | payload bytes from / to clients, datagrams dropped by a full queue, counted when flows end |
| `masque.flow_rejected.<reason>` | counter | CONNECT-UDP requests refused (`microproxy_reject_reason`): `limit` (too many flows) or `policy` (no direct route, a filter's answer) |
| `masque.quic.*` | | as `quic_transparent.*`, for the QUIC inside CONNECT-UDP flows (`masque.quic.intercepted_total`, ...) |
| `quic.messages_rx`, `messages_tx` | counter | whole messages cut from the streams of QUIC intercepted stream by stream for the message hook (`streamMessage`, `on_quic_message`), and the messages it returned that the proxy framed and sent |
| `quic.framing_errors` | counter | such streams reset because a peer sent a message over the framing's limit, or bytes its framer cannot read |

**SOCKS, tunnels and WebSockets.**

| stat | type | meaning |
|---|---|---|
| `socks.<version>.connections_total` | counter | SOCKS clients by version (`microproxy_socks_version`: `v4`, `v5`) |
| `socks.auth_failures`, `command_not_supported` | counter | clients refused by authentication / requests for a command other than CONNECT |
| `socks.replies.<reply>` | counter | replies by SOCKS5 code (`microproxy_socks_reply`: `succeeded`, `general_failure`, `not_allowed`, `network_unreachable`, `host_unreachable`, `connection_refused`, `ttl_expired`, `command_not_supported`, `address_type_not_supported`); a SOCKS4 client's by the code it stands for |
| `tunnel.active` | gauge | tunnels open |
| `tunnel.<kind>.total` | counter | tunnels opened by kind (`microproxy_tunnel_kind`): `h1_connect`, `h2_connect`, `h3_connect`, `socks`, `forwarded` (through a chained proxy, or a session's server), `raw` (TLS relayed undecrypted, `tcp://` reverse proxying, other upgrades) |
| `tunnel.rx_bytes_total`, `tx_bytes_total`, `tunnel.duration_ms` | counter, histogram | bytes from / to clients and how long tunnels were open, counted when they close |
| `websocket.sessions_active`, `sessions_total` | gauge, counter | WebSocket sessions open / opened |
| `websocket.frames_rx`, `frames_tx`, `messages_rx`, `messages_tx` | counter | frames read and written, and messages joined for and sent after the message hook, of the sessions whose frames are parsed (those with frame or message hooks) |
| `websocket.deflate_bytes_saved` | counter | bytes permessage-deflate saved on what the proxy compressed again |
| `websocket.close_codes.<code>` | counter | Close frames by status code, `1000` to `1015` (`1005` when there is none) or `other` (`microproxy_close_code`) |

**Hooks.** `hooks.<family>.*` for each family of hooks (`microproxy_hook`): `http_filters` (the
head hooks `clientToProxyRequest`, `proxyToServerRequest`, `serverToProxyResponse` and
`proxyToClientResponse`), `frame_interceptor`, `tcp` (`tcpMessage`), `udp` (`udpMessage`),
`quic_stream` (`streamData`), `quic_message` (`streamMessage`), `quic_datagram` (`datagram`),
`websocket_frame`, `websocket_message`, and `starlark` (every call into a script). The `starlark`
family is kept per script and hook function, as `hooks.starlark.<script>.<hook>.*`, tagged
`microproxy_script` (the file name without `.star`, or `--script-name`) and
`microproxy_script_hook` (`on_request`, `on_response`, `on_frame`, `on_tcp_message`, ...); a
script's stats for a hook are made on its first call.

| stat | type | meaning |
|---|---|---|
| `hooks.<family>.invocations`, `errors` | counter | calls, and calls that threw |
| `hooks.<family>.drops`, `rewrites` | counter | calls that dropped what they were given (returned null or nothing) / replaced it, or answered for the server (not for `starlark`) |
| `hooks.<family>.latency_us` | histogram | microseconds calls took, in buckets of 1, 5, 10, 25, ... 1000000 µs |
| `hooks.starlark.<script>.<hook>.steps` | histogram | interpreter steps each call ran, in buckets of 10, 100, ... up to the step limit |
| `hooks.starlark.<script>.<hook>.alloc_bytes` | histogram | about how many bytes of values each call created (an [estimate](#script-budgets)), in buckets of 1 KiB, 4 KiB, 16 KiB, ... up to the budget |
| `hooks.starlark.<script>.<hook>.budget_exceeded.<kind>` | counter | calls stopped by a budget: `steps`, `memory` or `time` (`microproxy_budget`) |

The clock is read only with metrics on (a script call also reads it for its deadline and its
exchange's totals). A hook that changes what it was given in place, rather than returning
something else, counts as neither a drop nor a rewrite.

<a id="qlog-files"></a>
**qlog.** With `--qlog-dir <dir>` (`Http3Options.Builder.qlogDirectory`, `qlog_dir`), each of the
proxy's QUIC connections, to clients and to servers, writes a qlog trace into `<dir>`, whether or
not metrics are on: `<ODCID>_server.sqlog` or `<ODCID>_client.sqlog`, named after the connection's
original Destination Connection ID and the proxy's side of it. A file is JSON-SEQ (RFC 7464), as the
qlog main schema serializes a trace: each record starts with the record separator (0x1E) and ends
with a newline. The first is the header (`"qlog_version":"0.3"`, `"qlog_format":"JSON-SEQ"`, the
vantage point, and `ODCID` and `group_id` in `common_fields`, with `"time_format":"relative"` and
the wall-clock `reference_time`); then one record per event, `{"time":<ms since the first
event>,"name":"transport:packet_sent","data":{...}}`, with the quic module's events: packets sent,
received and lost, key updates, state changes and the connection's close. The directory keeps at
most `--qlog-max-files` files (1000 by default; the oldest the proxy wrote are deleted), and a file
stops at 64 MiB (`qlogMaxFileBytes`). qlog builds an event for every packet, so it is for debugging.

```sh
java -jar microproxy.jar --port 8443 --http3 --listener-keystore proxy.p12 --qlog-dir /tmp/qlog
# Open the files in qvis (https://qvis.quictools.info), or read them with jq --seq:
jq --seq -c 'select(.name == "recovery:packet_lost")' /tmp/qlog/*_server.sqlog
```

**Clusters and cardinality.** A forward proxy's servers are any number, so they are not clusters
by default. A request's cluster is `direct` for a direct connection, the chained proxy for one
through a chained proxy (`host_port` of its address, such as `proxy_example_com_3128`), `cache`
for a response from the HTTP cache, and `replay` for one from server replay. With
`perHostClusters(true)` (`--stats-per-host`) each server of a direct connection is a cluster of its
own (`api_example_com_443`). Chained proxies and servers together are bounded by `maxClusters`
(`--stats-max-clusters`, default 100): past it, new ones count in the cluster `other`, or, with
`clusterOverflow(Overflow.LRU)` (`--stats-cluster-lru`), the least recently used cluster loses its
stats (which start from zero if it comes back). A cluster is looked up once per server
connection, never per request.

**Script stats.** A script's `stats` module makes metrics of its own, named `script.<name>`:

```python
BLOCKED = stats.counter("blocked")          # looked up once, at load time

def on_request(req, ctx):
    stats.histogram("path_length").record(len(req.path))
    if req.path.startswith("/admin"):
        BLOCKED.inc()
        return response(403)
```

A script makes at most `maxScriptStats` of them (100 by default); past that, new names count
nothing (a warning is logged once), so names made from requests cannot grow the registry without
bound. Without metrics, the module's metrics count nothing. Counters have `inc(n=1)` and `value`,
gauges `set(v)`, `inc(n=1)`, `dec(n=1)` and `value`, histograms `record(x)` and `count`.

**Cost.** Each metric is resolved once and kept in a field: per proxy for the `http`, `listener`,
per-protocol, hook and fixed `cluster` stats, per server connection for its cluster, per client
connection for its own. Counting a request is a few `LongAdder` adds and a histogram bucket search;
nothing is allocated per request, and nothing goes through `ActivityTracker`s. Nothing is counted
in the registry per QUIC packet: a connection counts in plain fields of its own, added once when
it closes, and CONNECT-UDP flows and transparent QUIC relays count their datagrams the same way.
Without metrics the registry is `StatsRegistry.NOOP`, whose metrics do nothing, and the call sites
that would read a clock (the hooks', for one) check first; `AllocationTest` (HTTP/1, and HTTP/2
and HTTP/3 with metrics against without) and `StatsFastPathTest` guard both.

**Limitations.** QUIC connections are counted when they close, so `quic.*` counters lag a
long-lived connection (`connections_active` and `QuicConnection.stats()` are live). The proxy's own
connections to servers do not move, so `quic.upstream.migrations` counts only moves to a server's
preferred address, and a relayed transparent flow whose client moves is no QUIC connection of the
proxy's: it counts in none of these. `http2.*.outbound_flood` and `requests_rejected_with_underscores_in_headers` have no
equivalent: writes block rather than queue, and underscores in header names are not refused.
Envoy's `upstream_cx_destroy_*` and
`downstream_cx_destroy_*` tell who closed first only where the proxy saw it (an end of stream
before a request, a server that closed its connection). Statsd gets a histogram as one timer per
flush, the mean of its new values sampled at `1/n`, which keeps the count and mean, not the spread.

### OpenTelemetry

The optional `microproxy-otel` module (`io.github.mahmoudimus:microproxy-otel`) traces the proxy
with [OpenTelemetry](https://opentelemetry.io) and exports traces, metrics and logs over OTLP,
using nothing but the JDK: W3C Trace Context (and B3 or Jaeger) propagation, a SERVER span per
exchange with a CLIENT span per attempt to reach the server, and OTLP/HTTP export, as protobuf or
JSON, through the JDK's `HttpClient` on virtual threads.

It is a module of its own, like the codecs, and not a package of the core: the core only defines
a small hook, `FlowTracer` (`withTracer`), which costs nothing when unused, and calls it where an
exchange starts, where each attempt to reach the server starts, where the request head is about to
go upstream (after the stripped headers are gone) and where the exchange's record is made. The
module implements it, so the core stays free of OTLP, and the launcher finds the module by class
presence (`ServiceLoader`, as it finds the Starlark module): with its jar on the class path,
`--otel` and the `OTEL_*` variables work. The `microproxy-starlark` `-all` jar bundles it.

**Setup with an OpenTelemetry Collector.** The collector receives OTLP/HTTP on port 4318 and
forwards to whatever backends it is configured for (Jaeger, Tempo, Prometheus, a vendor):

```yaml
# otel-collector.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug:
    verbosity: detailed
  otlp/jaeger:
    endpoint: jaeger:4317
    tls:
      insecure: true
service:
  pipelines:
    traces: {receivers: [otlp], exporters: [otlp/jaeger, debug]}
    metrics: {receivers: [otlp], exporters: [debug]}
    logs: {receivers: [otlp], exporters: [debug]}
```

```sh
docker run -p 4318:4318 -v $PWD/otel-collector.yaml:/etc/otelcol/config.yaml otel/opentelemetry-collector

# OTEL_EXPORTER_OTLP_ENDPOINT alone turns the export on:
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 OTEL_SERVICE_NAME=edge \
    java -cp microproxy.jar:microproxy-otel.jar org.microproxy.Launcher --port 8080
# or with flags, from the -all jar:
java -jar microproxy-starlark-all.jar --port 8080 --otel --otel-endpoint http://localhost:4318 \
    --otel-sampler parentbased_traceidratio:0.1 --otel-propagators tracecontext,b3multi
```

```java
Telemetry otel = Telemetry.fromEnvironment()                 // the OTEL_* variables, then:
        .serviceName("edge")
        .sampler(Sampler.parentBased(Sampler.traceIdRatio(0.1)))
        .propagators(List.of(Propagators.TRACE_CONTEXT, Propagators.B3_MULTI))
        .header("authorization", "Bearer " + token)
        .build();
HttpProxyServer proxy = otel.install(MicroProxy.bootstrap().withPort(8080)).start();
```

`install` sets the tracer, turns the proxy's metrics on when they are exported, and adds the
access-log exporter as an `ActivityTracker`. The proxy closes the telemetry when it stops, after
its exchanges ended: what is queued is exported then.

| variable | meaning | default |
|---|---|---|
| `OTEL_SDK_DISABLED` | `true`: nothing at all, even with `--otel` | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | the collector's base URL; signals go to `<endpoint>/v1/traces`, `/v1/metrics`, `/v1/logs` | `http://localhost:4318` |
| `OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_ENDPOINT` | one signal's full URL, used as it is | |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` or `http/json` (`grpc` is refused) | `http/protobuf` |
| `OTEL_EXPORTER_OTLP_HEADERS` | `key=value,...` (percent-decoded) on every export, e.g. `authorization=Bearer%20...` | |
| `OTEL_EXPORTER_OTLP_COMPRESSION` | `gzip` or `none` | `none` |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | milliseconds for one export attempt | `10000` |
| `OTEL_SERVICE_NAME` | `service.name` | `microproxy` |
| `OTEL_RESOURCE_ATTRIBUTES` | `key=value,...` more resource attributes | |
| `OTEL_{TRACES,METRICS,LOGS}_EXPORTER` | `otlp` or `none` per signal (without traces, the proxy still propagates) | `otlp` |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | see Sampling | `parentbased_always_on` |
| `OTEL_PROPAGATORS` | `tracecontext`, `b3`, `b3multi`, `jaeger`, `baggage`, `none` | `tracecontext` |
| `OTEL_METRIC_EXPORT_INTERVAL` | milliseconds between metric exports | `60000` |
| `OTEL_BSP_SCHEDULE_DELAY`, `_MAX_QUEUE_SIZE`, `_MAX_EXPORT_BATCH_SIZE` | the span queue | `5000`, `2048`, `512` |
| `OTEL_BLRP_SCHEDULE_DELAY`, `_MAX_QUEUE_SIZE`, `_MAX_EXPORT_BATCH_SIZE` | the log record queue | `1000`, `2048`, `512` |
| `OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT`, `OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT`, `OTEL_SPAN_EVENT_COUNT_LIMIT`, `OTEL_EVENT_ATTRIBUTE_COUNT_LIMIT` (and `OTEL_ATTRIBUTE_*`) | span limits | `128`, `4096`, `128`, `128` |

| flag | meaning |
|---|---|
| `--otel` | turn it on (the variables above configure it; the flags below override them) |
| `--otel-endpoint <url>`, `--otel-protocol <p>`, `--otel-header <k=v>`, `--otel-compression <c>` | the export |
| `--otel-service-name <name>`, `--otel-resource <k=v,...>` | the resource |
| `--otel-signals traces,metrics,logs` | what is exported |
| `--otel-sampler <name>[:<arg>]`, `--otel-force-trace-header <h>` | sampling |
| `--otel-propagators <list>`, `--otel-ignore-incoming`, `--otel-when-stripped own\|none` | propagation |
| `--otel-request-id keep\|replace\|off` | `X-Request-Id` |
| `--otel-metric-interval <ms>`, `--otel-log-format <format>` | metrics, and the body of log records |

**What is traced.**

| span | kind | name | when |
|---|---|---|---|
| an HTTP exchange (HTTP/1.x, an HTTP/2 or HTTP/3 stream) | SERVER | the method (`GET`) | from its request head to the end of its response, or until it was abandoned |
| an attempt to reach the server, a child of the exchange's span | CLIENT | the method | from the connection attempt (directly, or through a chained proxy) or, on a connection at hand, from the request, to the response; each chained proxy tried and each request sent again after a stale keep-alive connection is one more, with `http.request.resend_count` |
| a `CONNECT` tunnel, a SOCKS client, a WebSocket session, a TCP-hook tunnel, a CONNECT-UDP flow | INTERNAL | `tunnel example.com:443`, `socks ...`, `websocket ...`, `udp ...` | until it closes; its connection's CLIENT span lasts as long |
| a QUIC flow relayed or intercepted stream by stream, a request a transport answered itself | INTERNAL (SERVER for HTTP) | `quic_relay ...`, `quic ...` | a span of its own, under the context its request carried |
| a call into a [script's](#scripting-with-starlark) hook, a child of its exchange's (tunnel's, flow's) span | INTERNAL | `starlark on_request`, `starlark on_tcp_message`, ... | the call, with `starlark.hook`, `starlark.script`, `starlark.steps`, `starlark.alloc_bytes` and `starlark.budget_exceeded` |

The server sees the CLIENT span as its parent: the proxy writes its own `traceparent` (and the
configured propagators' headers) on each request it sends, after the filters, so the trace goes
client → proxy SERVER span → proxy CLIENT span → server. Requests inside an intercepted session
are exchanges of their own, with the context they carry.

| attribute | on | value |
|---|---|---|
| `http.request.method` (`_OTHER` and `http.request.method_original` for others) | all | the method |
| `url.full` | CLIENT; SERVER for absolute-form (proxy) requests | the URL; a CLIENT span's scheme is `https` when the proxy speaks TLS to the server itself (an `https` origin, an intercepted session's server, a reverse proxy's `https://` upstream, HTTP/2 and HTTP/3), on any port, and `http` otherwise |
| `url.scheme`, `url.path`, `url.query` | SERVER | the request target |
| `server.address`, `server.port` | all | the target (CLIENT: the server the attempt was for) |
| `client.address`, `client.port` | SERVER, INTERNAL | the client (the PROXY protocol's source, when there was one) |
| `user_agent.original` | SERVER | `User-Agent` |
| `network.protocol.name`, `network.protocol.version` | SERVER; CLIENT once its request went out | `http`, `1.1`, `2`, `3`: the client's; a CLIENT span's, the connection's to the server |
| `http.response.status_code` | all | the status the client got (CLIENT: the server's) |
| `http.request.body.size`, `http.response.body.size` | SERVER | body bytes from and to the client |
| `error.type` | all | the status for a 5xx (CLIENT: 4xx too), else the failure (`connect_failed`, `server_timeout`, `unresolved_host`, `tls_failed`, `stale_connection`, ...) |
| `response_flags`, `upstream_cluster`, `upstream_address`, `guid:x-request-id` | as Envoy's tracing tags | `UF,URX`; the chained proxy or server; its address; the request id |
| `microproxy.response_source`, `microproxy.response_code_details`, `microproxy.flow` | SERVER, INTERNAL | `SERVER`, `PROXY`, ...; `via_upstream`, `proxy_failure:connect_failed`, ...; `h1`, `h2`, `tunnel`, ... |
| `microproxy.connection_id`, `microproxy.stream_id`, `microproxy.socks_version`, `microproxy.chained_proxy` | | the client connection and stream; the SOCKS version; a CLIENT span's chained proxy |
| `network.transport`, `microproxy.bytes_received`, `microproxy.bytes_sent`, `microproxy.upstream_bytes_sent`, `microproxy.upstream_bytes_received` | INTERNAL | `tcp` or `udp`, and the payload each way |

The SERVER (or INTERNAL) span's events come from the exchange's [timings](#observability):
`dns_lookup`, `connect` and `tls_handshake` at the end of each phase, with
`microproxy.duration_ms`; `request_sent`; `first_byte`; and `downstream_tls_handshake` for the
client's handshake. Its status is ERROR on a 5xx, on a failure of the proxy's (`ctx.failure()`),
and on the flags that say the server or the proxy failed (`UF`, `UT`, `UR`, `UC`, `UO`, `NR`,
`URX`, `UPE`, `DF`, ...), with the response code details as its message; a CLIENT span's is ERROR
on a 4xx or 5xx and on a failed attempt. A client that went away (`DC`, `DR`) is not an error of
the proxy's. Filters and scripts add attributes and events with `ctx.trace().setAttribute(key,
value)` and `addEvent(name, attributes)` (Starlark's `trace` module); the span limits bound them:
past them attributes and events are dropped and counted (`droppedAttributesCount`), and strings
are cut.

**Propagation.** The configured propagators work as OpenTelemetry's composite propagator: they
extract in the configured order, each over what the ones before it found, so when a request
carries several contexts the last propagator that finds a valid one gives the parent (with
`OTEL_PROPAGATORS=b3multi,tracecontext`, a valid `traceparent` wins over `X-B3-*`); every
configured propagator writes the proxy's context upstream, replacing the client's headers it
owns. `tracecontext` follows the W3C specification: version `00` and later
versions, lower-case hex only, no all-zero ids, two `traceparent` headers restart the trace, and a
`tracestate` that is not valid (a bad key or value, a duplicate key, more than 32 members) is
dropped while the `traceparent` is kept; a valid one is sent on as it came. `b3` is B3's single
header (`{trace}-{span}-{1|0|d}`, 64-bit trace ids padded), `b3multi` its `X-B3-*` headers, and
`jaeger` `uber-trace-id` (separators URL-encoded or not). `baggage` is accepted and leaves the
`baggage` header alone. `--otel-ignore-incoming` (`trustIncoming(false)`) makes the proxy a trust
boundary: each request starts a new trace.

`X-Request-Id`: kept when the client sent one and made (a random UUID, version 4) when it did not,
before filters, trackers and the access log see the request, so the server, the span
(`guid:x-request-id`), the log record and the access log's `%REQ(X-REQUEST-ID)%` and
`%UNIQUE_ID%` all show the same id; `replace` always makes a new one, `off` leaves the header
alone. `%TRACE_ID%` and `%SPAN_ID%` put the ids in access-log lines.

With [`withoutTracingHeadersUpstream()`](#removing-tracing-headers) (`--strip-tracing-headers`),
the client's tracing headers are removed first; then the proxy writes only its own span context
(`own`, the default: the propagators' headers with the trace id, the proxy's span id and the
sampled flag, and no `tracestate` or `baggage` of the client's) or nothing at all (`none`,
`--otel-when-stripped none`, `whenStripped(WhenStripped.NONE)`): the server then never learns of
the trace, which is still recorded. With `own`, the trace id continues the client's; add
`--otel-ignore-incoming` to keep even that inside.

**Sampling.** `parentbased_always_on` (the default) follows the sampled flag of the context that
came with the request, and samples new traces; `parentbased_traceidratio` with an argument of
`0.1` samples a tenth of the new ones, deciding by the trace id, so every process of a trace
decides alike; `always_on`, `always_off`, `traceidratio` and `parentbased_always_off` are the
others. `--otel-force-trace-header x-envoy-force-trace` (`forceTraceHeader`) samples every request
that has the header, whatever the sampler says. A request that is not sampled is still given ids
and propagated, with the sampled flag off, so the servers behind follow the decision.

**Export.** Spans and log records wait in bounded queues and leave in batches, as soon as a batch
is full or after the schedule delay, one virtual thread per signal; metrics are read from the
registry every interval. Each batch is one POST with the configured headers, gzipped when asked,
within the timeout; `429`, `502`, `503`, `504` and failed connections are retried, up to five
attempts, with exponential backoff and jitter (1 s, growing by half, up to 5 s), waiting at least
what `Retry-After` says (up to 30 s). Other answers fail the batch. When the collector is down or
slow and a queue is full, new spans and records are dropped, never waited for, and counted. With
metrics on, the module's own stats are in the registry: `otel.spans_exported`,
`otel.spans_dropped`, `otel.spans_failed`, `otel.spans_queued`, `otel.spans_export_retries`, the
same for `otel.logs_*`, and `otel.metrics_exports`, `otel.metrics_failed`.

- **Resource:** `service.name`, `service.version` (the proxy's), `host.name`, `process.pid`,
  `process.runtime.name`, `process.runtime.version`, `process.runtime.description`,
  `telemetry.sdk.*`, and `OTEL_RESOURCE_ATTRIBUTES`; the instrumentation scope is
  `org.microproxy`.
- **Metrics:** the [stats](#metrics-envoy-compatible-stats) as Prometheus sees them: one metric per
  tag-extracted name, prefixed (`envoy.cluster.upstream_rq_xx`), with the tags as attributes
  (`envoy_cluster_name`, `envoy_response_code_class`); counters are monotonic cumulative sums,
  gauges are gauges, histograms are cumulative histograms with the registry's explicit bounds
  (Envoy's, in milliseconds; `ms`, `us` or `By` units by name). Exporting metrics turns the stats
  on.
- **Logs:** one log record per access-log record (exchange, tunnel or flow): the body is the
  access-log line (Envoy's default format, or `--otel-log-format`), the attributes are the span's,
  plus `microproxy.duration_ms`; the severity is ERROR when the span would be an error, WARN for a
  4xx, INFO otherwise; the trace and span ids tie it to the SERVER span.
- **Encodings:** the OTLP messages are written by hand with opentelemetry-proto's field numbers
  (protobuf), or in the OTLP/JSON mapping (ids in hex, 64-bit numbers as strings). The tests
  decode both with the core's [schema-less protobuf decoder](#protobuf-without-a-schema) and JSON
  parser, and, when Python has `opentelemetry-proto`, with its generated classes, which must
  accept every field and find both encodings equal (CI runs this with the interop job).

**Overhead.** Without the module, or disabled (`OTEL_SDK_DISABLED=true`, `enabled(false)`), the
tracer is `FlowTracer.NOOP` and the proxy skips every call: no work, no allocation. Enabled, a
request that is not sampled costs its ids, a small object and the headers written upstream (and
the request id); only sampled exchanges allocate spans, attributes and events, and the request
head's attributes are read once, when it arrives. Spans are built when the exchange ends, on its
thread, and handed to the queue; encoding and sending happen on the exporters' threads.

**Limitations.** OTLP over gRPC is not supported (it needs gRPC's framing over HTTP/2; the proxy's
own HTTP/2 client could carry it later); use the collector's OTLP/HTTP receiver. Metrics are
cumulative only, without exemplars; spans have no links; baggage is passed on, not read. The
partial-success part of a collector's answer is not read. A span starts when the proxy has read
the request head, a few microseconds after its first byte.

### Admin interface

The admin listener serves Envoy's admin API (the same paths and semantics, reimplemented) on a
listener of its own, apart from the proxy's: metrics for Prometheus, readiness for load balancers
and orchestrators, the configuration in effect, log levels, and draining. It runs on the JDK's
built-in HTTP server (`com.sun.net.httpserver`, module `jdk.httpserver`), so it adds no dependency;
a `jlink`ed runtime needs `--add-modules jdk.httpserver`. It turns [metrics](#metrics-envoy-compatible-stats) on.

```sh
java -jar microproxy.jar --port 8080 --admin-port 9901            # admin on 127.0.0.1:9901

curl -s localhost:9901/ready                                       # LIVE
curl -s 'localhost:9901/stats?filter=^cluster\.&usedonly'
curl -s localhost:9901/stats/prometheus
curl -s -X POST 'localhost:9901/logging?org.microproxy.impl.Tls=debug'
curl -s -X POST 'localhost:9901/drain_listeners?graceful'         # drain for --drain-time
```

```java
HttpProxyServer proxy = MicroProxy.bootstrap()
        .withAdmin(new InetSocketAddress(InetAddress.getLoopbackAddress(), 9901))
        .withAdminToken(System.getenv("MICROPROXY_ADMIN_TOKEN"))   // optional
        .withDrainTime(Duration.ofSeconds(20))
        .start();
proxy.state();                          // LIVE
proxy.drain(Duration.ofSeconds(20));    // returns when the drain is over
proxy.stop();                           // STOPPED
```

| path | method | answer |
|---|---|---|
| `/`, `/help` | GET | the paths and what they do |
| `/stats` | GET | the stats as `name: value` lines, histograms as their quantiles (Envoy's text dump); `?filter=<regex>` keeps the names it finds, `?usedonly` the stats with a value, `?format=json` or `?format=prometheus` changes the form |
| `/stats/prometheus` | GET | Prometheus's text exposition format 0.0.4 (`text/plain; version=0.0.4; charset=utf-8`), with `?filter=` and `?usedonly` too |
| `/ready` | GET | `200 LIVE`, or `503` and the state: `DRAINING`, `INITIALIZING`, `PRE_INITIALIZING`, or `HEALTH_CHECK_FAILED` after `/healthcheck/fail`; needs no token |
| `/server_info` | GET | JSON: the version, state, uptime (`uptime_current_epoch`), listeners, the features in use (`h2`, `h2c`, `h3`, `quic`, `socks`, `masque`, `mitm`, `transparent`, `reverse_proxy`, `cache`, `replay`, `scripting`, `tracing`, ...), the drain settings, the JVM, and the command line, secrets redacted |
| `/listeners` | GET | a line per listener, `name::address::transport::protocols` (`edge::127.0.0.1:8080::tcp::http/1.1,h2c`); `?format=json` |
| `/clusters` | GET | a line per cluster stat, `cluster::stat::value`, for `direct`, the chained proxies, `cache`, `replay` and, with `--stats-per-host`, each server; with the shared pool's state on `direct`; `?format=json` (histograms as count, p50 and p99) |
| `/config_dump` | GET | JSON: the configuration in effect (listener, modes, timeouts, limits, pool, chained proxies, HTTP/2 and HTTP/3 options, TLS, interception, filters, trackers, tracer, stats, drain, health check, admin, command line), every secret `[redacted]` |
| `/logging` | GET, POST | GET lists the proxy's loggers and their levels; `POST /logging?level=<level>` sets them all, `POST /logging?<logger>=<level>` one (and its children) |
| `/healthcheck/fail` | POST | fails the health check: `/ready` and the [health-check path](#lifecycle-draining-and-shutdown) answer `503`, and connections drain as their next request comes |
| `/healthcheck/ok` | POST | restores it |
| `/drain_listeners` | POST | stops accepting connections now (open ones are left alone); with `?graceful`, drains for the drain time first, still accepting; `?inboundonly` is accepted, every proxy listener being inbound |
| `/quitquitquit` | POST | stops the proxy gracefully, as `stop()` does |

Reads are `GET` (and `HEAD`); what changes the proxy takes `POST` only, so that a link or a
prefetch cannot change it; any other method gets `405` with an `Allow` header. An unknown path
gets `404` and the list. Envoy's other paths (`/certs`, `/memory`, `/runtime`,
`/stats/recentlookups`, `/reset_counters`, `/heap_dump`, `/hot_restart_version`, ...) are not
served: MicroProxy has no runtime-overridable settings, hot restarts or certificates to list.

| flag | property | meaning |
|---|---|---|
| `--admin-port <port>` | `admin_port` | serve the admin API on this port of `127.0.0.1` (0 for any free port) |
| `--admin-address <host:port>` | `admin_address` | on another address, such as `0.0.0.0:9901` or `[::1]:9901` |
| `--admin-token <token>` | `admin_token` | require the token on every path but `/ready` |
| `--admin-token-file <file>` | | the same, from the file's first line (kept out of the process list) |
| `--drain-time <seconds>` | `drain_time` | how long a drain lasts, and how long stopping lets exchanges finish (default 10) |
| `--drain-strategy <strategy>` | `drain_strategy` | `gradual` (the default) or `immediate` |
| `--health-check-path <path>` | `health_check_path` | answer health checks on the proxy's listener |
| `--health-check-pass-through` | `health_check_pass_through` | forward a healthy health check to the server instead |

**Security.** The admin API can drain and stop the proxy, so it listens on `127.0.0.1` unless told
otherwise. A token (`withAdminToken`, `--admin-token`) is then required on every path but
`/ready`: as `Authorization: Bearer <token>`, or as the password of basic authentication with
any user name (or as `user:password` itself, when the token has a colon); it is compared in
constant time. Bound to a loopback address, the listener also answers only requests whose `Host`
is `localhost` or a loopback address, so a web page cannot reach it through DNS rebinding, and it
refuses every `POST` that carries an `Origin`, as a browser's would. It speaks plain HTTP: to reach
it from elsewhere, bind it to a private address with a token, or tunnel to it (`kubectl
port-forward`, SSH). `/config_dump` and `/server_info` redact the secrets they would show: key
store passwords, the admin token, proxy authentication credentials and those in chained proxy
URLs, the interception CA's private key and its key store password, `--script-var` values, and any
option named for a password, token, secret or credential.

**Threads.** The JDK's server reads requests and writes responses inside `synchronized` methods
(`sun.net.httpserver.Request.ReadStream.read` and `WriteStream.write`). On JDK 21 a virtual thread
blocked in one pins its carrier, so a client sending its request or reading the answer slowly
would hold one of the few carriers every virtual thread of the proxy shares. The admin listener
therefore runs on four platform threads of its own (idle keep-alive connections hold none: they
wait in the server's selector). `HttpsServer` pins the same way, and more, which is why the admin
listener has no TLS. JDK 24 (JEP 491) no longer pins on monitors.

**Logging levels.** The proxy logs through `System.Logger`, which the JDK backs with
`java.util.logging` unless another backend is on the class path (SLF4J's
`slf4j-jdk-platform-logging`, Log4j's `log4j-jpl`). With `java.util.logging`, `/logging` lists the
loggers under `org.microproxy` and `io.github.mahmoudimus` with their effective levels, and sets
them with Envoy's names (`trace`, `debug`, `info`, `warning`, `error`, `critical`, `off`) or
`java.util.logging`'s (`FINE`, `ALL`, ...); a root handler that would drop the records of a lower
level is lowered to it. With another backend, `/logging` says which one, and levels are set there:
the JDK gives no portable way to change them.

### Lifecycle, draining and shutdown

A proxy is `INITIALIZING` while it starts (the admin listener first, then the proxy's own),
`LIVE` once it serves, `DRAINING` once it drains, stops accepting or stops, and `STOPPED` at the
end: `HttpProxyServer.state()`, the admin's `/ready`, and the `server.state` gauge with Envoy's
numbers (0 live, 1 draining, 2 pre-initializing, 3 initializing; 4 stopped, which Envoy has not).

- **Drain** (`drain(time)`, `POST /drain_listeners?graceful`): `/ready` fails at once, and the
  listeners keep accepting, so that clients a load balancer still sends are served. Each new
  request is told to go elsewhere: an HTTP/1 response gets `Connection: close` and its connection
  closes after it; an HTTP/2 or HTTP/3 connection is sent GOAWAY (the request is served, and named
  the last one). With the `gradual` strategy (Envoy's default) the chance that a request does so
  grows from 0 at the start of the drain to 1 at its end, so clients move away gradually; with
  `immediate`, every connection is told at once (idle ones close now). Exchanges in progress get
  until the drain time is over; then the listeners close and so does every connection still open.
  The proxy stays `DRAINING`, its admin listener up, until it is stopped.
- **Stop accepting** (`stopListeners()`, `POST /drain_listeners`): the TCP listener closes, the UDP
  ones (HTTP/3, transparent QUIC) refuse new QUIC connections, and open connections are left
  alone.
- **Stop** (`stop()`, `POST /quitquitquit`, and the launcher's SIGTERM or Ctrl-C): the listeners
  close, idle connections close, HTTP/2 and HTTP/3 ones get GOAWAY, HTTP/1 ones close after their
  exchange in progress; exchanges get up to the drain time to finish (`withDrainTime`,
  `--drain-time`, 10 seconds by default), then everything is closed, resources added with
  `closeOnStop` are closed, and last the admin listener. `abort()` closes everything at once.
- **Health check** (`setHealthCheckFailed`, `POST /healthcheck/fail` and `/healthcheck/ok`): while
  it fails, `/ready` answers `503 HEALTH_CHECK_FAILED`, and every new request drains its
  connection, as Envoy does. `withHealthCheckPath("/healthz", passThrough)` (`--health-check-path`)
  answers health checks on the proxy's own listener, before authentication and the filters, as
  Envoy's health check filter: an origin-form request for the path gets `200`, or `503` with
  `x-envoy-immediate-health-check-fail: true` while the health check fails or the proxy is not
  `LIVE`. With pass-through, a healthy check goes on to the server (in reverse mode, the
  upstream's own health) and only failures are answered by the proxy.

The drain counts `http.<name>.downstream_cx_drain_close` (connections told to go away),
`listener_manager.listener_stopped`, and the gauges `listener_manager.total_listeners_active` and
`total_listeners_draining`; `server.live` is 1 only while `LIVE`.

**Kubernetes.** Readiness follows `/ready`; on deletion, a `preStop` hook drains while the
endpoints controller and the load balancers forget the pod, then the kubelet's SIGTERM stops the
proxy, which finishes the exchanges still in progress:

```yaml
spec:
  terminationGracePeriodSeconds: 45          # > preStop sleep + drain time
  containers:
    - name: microproxy
      image: example/microproxy
      args: ["--port", "8080", "--server", "--admin-address", "0.0.0.0:9901",
             "--admin-token-file", "/etc/microproxy/admin-token", "--drain-time", "15"]
      ports: [{containerPort: 8080}, {containerPort: 9901}]
      readinessProbe:
        httpGet: {path: /ready, port: 9901}  # /ready needs no token
        periodSeconds: 2
      lifecycle:
        preStop:
          exec:
            command:
              - sh
              - -c
              - |
                curl -sf -X POST -H "Authorization: Bearer $(cat /etc/microproxy/admin-token)" \
                  'http://127.0.0.1:9901/drain_listeners?graceful&inboundonly'
                sleep 15
      volumeMounts: [{name: admin-token, mountPath: /etc/microproxy, readOnly: true}]
  volumes:
    - name: admin-token
      secret: {secretName: microproxy-admin-token}
```

The kubelet probes the pod's address, so this binds the admin listener to every interface, with a
token. To keep it on loopback instead, probe with `exec` (`curl -sf localhost:9901/ready`), or
give the proxy `--health-check-path /healthz` and probe `httpGet: {path: /healthz, port: 8080}`,
which also fails while draining. Without a `preStop` hook (an image without `curl` or `sh`),
SIGTERM alone stops accepting at once and lets the exchanges in progress finish for up to
`--drain-time`; a `preStop` of `sleep 5` covers most of the time endpoints take to update.

**Limitations.** `/clusters` lists the clusters that have stats so far, so a chained proxy shows
once it has been used; every cluster is reported `healthy`, as the proxy runs no active health
checks. `?usedonly` keeps what is not zero, where Envoy keeps what was ever written (a gauge back
at zero shows there). A gradual drain is a matter of chance per request, so an HTTP/1 client that
sends few requests may keep its connection until the drain ends. Envoy's `?inboundonly` and
`traffic_direction` distinction has nothing to choose from here, and the admin listener itself is
never drained. Scripts do not see the state: they run per request, and a draining proxy's own
answers (`Connection: close`, GOAWAY) need nothing from them.

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
  `filter`, `cache` or `replay`) and the server's status (`upstream=`) when a filter or the cache answered or
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
- **Content views:** `.contentViews(ContentViews.defaults())` (or `.contentView("auto")`) renders
  bodies at `BODY` through [content views](#content-views) where one applies: protobuf and gRPC
  (message by message) as YAML with field numbers, JSON indented, form data, GraphQL, msgpack.
  The `END` line names the view (`grpc view`), and JSON messages add `body_view`. A named view
  (`.contentView("hex")`) renders every body it can. With views, `grpc-status`,
  `grpc-message` and `grpc-status-details-bin` are explained wherever they appear, in headers
  (Trailers-Only responses) and trailers. A body cut at `maxBodyBytes` shows its complete gRPC
  messages and how much of the last one there is; raise the cap for long streams.
- **Trailers:** at `BODY`, request and response trailers (`grpc-status`, ...) follow the body
  (`<-- trailers`), redacted like headers; JSON messages add `trailers`.
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
and `--log-http-json` writes JSON lines (at `headers` unless a level is given). `--log-http-view
auto` (or a view's name) adds content views, at `body` unless a level is given, and
`--proto-descriptors api.desc` gives them field names. Properties files take `log_http`,
`log_http_format=json`, `log_http_view` and `proto_descriptors`.

Logging bodies (or any filter that reads request body pieces) makes the proxy send an HTTP/2
request body whole before it reads the response, so a bidirectional gRPC stream waits for the
client to finish sending; unary and server-streaming calls are unaffected.

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

### Content views

`org.microproxy.contentviews` turns message bodies into readable text, after mitmproxy's content
views. A `ContentView` has a name, rates how well it suits a body (`priority`, from the
`Content-Type`, the request path and the bytes) and renders it. `ContentViews` holds a set of
views and, in `auto` mode, renders each body with the best view that can; when none can, there
is no rendering and callers show the body as before. `HttpLogger` uses them (see
[Request/response logging](#requestresponse-logging)); they also work on their own:

```java
ContentViews views = ContentViews.defaults();
views.render(body, ContentView.Metadata.forResponse(request, response))
        .ifPresent(r -> System.out.println(r.view() + ":\n" + r.text()));
```

| View | Bodies | Rendering |
|---|---|---|
| `protobuf` | `application/x-protobuf`, `application/protobuf`, `application/vnd.google.protobuf`, ... | YAML with field numbers (names with a schema) |
| `grpc` | `application/grpc`, `application/grpc+proto`, gRPC-Web (`application/grpc-web`, `-web-text`) | each message, decompressed as `grpc-encoding` says (`gzip`, `deflate`, and `zstd` with `zstd-decoder`), separated by `---`, then the trailers |
| `json` | `application/json`, `text/json`, `+json` | indented by two spaces |
| `graphql` | JSON with a `query` (or a batch of them) | the other members as JSON, then `---` and the query, one field per line |
| `msgpack` | `application/msgpack`, `application/x-msgpack` | YAML: every format of the specification, extensions as `!ext<type>`, timestamps as instants |
| `urlencoded`, `multipart` | `application/x-www-form-urlencoded`, `multipart/form-data` | the fields (a repeated name as a list), files' names, types and sizes |
| `query` | requests without a body | the query parameters |
| `socketio` | paths with `/socket.io/` or `/engine.io/` | one line per Engine.IO or Socket.IO packet |
| `dns` | `application/dns-message` (DNS over HTTPS, and [DNS over QUIC](#quic-message-framing)'s messages) | as `dig` shows it: the header, then each section's records |
| `hex` | anything, when named | a hex dump |

`views.with(myView)` adds a view (or replaces one of the same name); a view that fails on a body
is skipped. Views get bodies with their `Content-Encoding` removed, and must throw nothing but
`DecodeException` for data they cannot render.

#### Protobuf without a schema

```text
1: 150  # !sint: 75
2: hello
3: !fixed32 3.14159  # u32: 1078530000
5:
  1: 42  # !sint: 21
6: !binary 038e029ea705  # packed: [3, 270, 86942]
```

The decoding follows mitmproxy's (ported from mitmproxy_rs):

- **Numbers.** Varints and fixed-width values are what the wire says; each is shown in its
  shortest reading, with the others as a comment: unsigned, signed when the top bit is set (a
  negative `int32` or `int64`, which take ten bytes), zigzag (`!sint`, for `sint32` and
  `sint64`), and as a float or double for `!fixed32` and `!fixed64`. Which one the field really
  is cannot be told from the bytes.
- **Length-delimited values** are guessed per field number, over all of the field's values:
  text when every value is UTF-8 without control characters (other than whitespace); else a
  nested message when every value parses as one (minimal varints, field numbers in range, one
  wire type per field number); else bytes, with a `packed:` comment when they read as two or more
  packed varints. Ambiguity is inherent: `08 96 01` is a message with field 1 = 150 and also the
  packed values 8 and 150; the message wins, as in mitmproxy.
- **Repetition.** A field that occurs more than once is a list. Groups (wire types 3 and 4) are
  `!group` mappings. Fields are sorted by number.
- **Limits.** Messages nest at most 64 deep (deeper values stay bytes), groups too (deeper ones
  are an error), and lengths are checked against the input before anything is allocated. Bad
  input is a `DecodeException`, never anything else; the build fuzzes the decoders with a fixed
  seed.

The same in Java, with editing:

```java
ProtoMessage m = Protobuf.decode(bytes);
Map<Object, Object> fields = m.toPlain();             // {1=150, 2=hello, 5={1=42}}
fields.put(2, "goodbye");
byte[] edited = Protobuf.encode(fields);

List<byte[]> messages = Grpc.messages(body, "gzip");  // split and decompress
byte[] framed = Grpc.join(messages, "gzip");           // frame and compress
Grpc.Status status = Grpc.statusFromTrailer(trailers.get("grpc-status-details-bin"));
```

Encoding a decoded `ProtoMessage` gives back its bytes, except where the input used non-minimal
varints at the top level. The plain form (`toPlain`) re-encodes to the same bytes when each
field's values were together on the wire, as encoders write them; fixed-width values and groups
stay `ProtoValue.Fixed32`, `Fixed64` and `Group` in it, so that they keep their wire types.

#### gRPC

A unary call logged with `--mitm --http2 --http2-upstream --log-http-view auto` (headers
shortened):

```text
[conn 4 #2 stream 1] --> POST https://api.example.com/echo.Echo/Chat HTTP/2.0
[conn 4 #2 stream 1] content-type: application/grpc
[conn 4 #2 stream 1] te: trailers
[conn 4 #2 stream 1]
[conn 4 #2 stream 1] 1: unary
[conn 4 #2 stream 1] 2: 7  # !sint: -4
[conn 4 #2 stream 1] --> END POST (14-byte body, grpc view)
[conn 4 #2 stream 1] <-- 200 OK https://api.example.com/echo.Echo/Chat (21 ms, ttfb 9 ms, source=server)
[conn 4 #2 stream 1] content-type: application/grpc
[conn 4 #2 stream 1]
[conn 4 #2 stream 1] 1: UNARY
[conn 4 #2 stream 1] 2: 7  # !sint: -4
[conn 4 #2 stream 1] <-- trailers
[conn 4 #2 stream 1] grpc-status: 0  # OK
[conn 4 #2 stream 1] grpc-message: echoed 1
[conn 4 #2 stream 1] <-- END HTTP (14-byte body, grpc view)
```

Streams show each message in turn, separated by `---`; compressed ones say so (`#
gzip-compressed, 23 bytes`). An error's `grpc-status-details-bin` is decoded as a
`google.rpc.Status`, with the standard error details (`BadRequest`, `ErrorInfo`, `RetryInfo`,
...) by name, and `grpc-message` is percent-decoded:

```text
grpc-status: 3  # INVALID_ARGUMENT
grpc-message: invalid%20name  # invalid name
grpc-status-details-bin: CAMSDGludmFsaWQgbmFtZRo...
  code: 3
  message: invalid name
  details:
  - type_url: type.googleapis.com/google.rpc.BadRequest
    value:
      field_violations:
      - field: name
        description: must not be empty
```

#### Field names from a descriptor set

With the `FileDescriptorSet` that `protoc` writes, messages decode with field names, enum names
and declared types:

```bash
protoc --include_imports --descriptor_set_out=api.desc -I protos protos/*.proto
java -jar microproxy.jar --mitm --http2 --http2-upstream --proto-descriptors api.desc
```

```java
ProtoSchema schema = ProtoSchema.load(Path.of("api.desc"));
HttpLogger logger = HttpLogger.builder().level(HttpLogger.Level.BODY)
        .contentViews(ContentViews.defaults().withSchema(schema)).build();
ProtoMessage order = Protobuf.decode(bytes, schema, "shop.Order");
byte[] encoded = Protobuf.encode(Map.of("id", 42L, "status", "SHIPPED"), schema, "shop.Order");
```

- gRPC requests decode as their method's input type and responses as its output type, found by
  the request path (`/shop.Shop/GetOrder`). Protobuf bodies use a `messageType` (or `proto`,
  `type`) parameter of their `Content-Type`.
- Declared fields show their names and types: enum value names, zigzag-decoded `sint`s, `bool`s,
  floats, packed fields as lists, map fields as mappings, `Any` as the type its `type_url` names.
  Fields the schema does not declare, or whose wire type does not match, are decoded as without a
  schema.
- The descriptor set is parsed with the package's own decoder; nothing else is needed at run time.
  Extensions, default values and options other than `packed` and `map_entry` are ignored.
- Every schema knows `google.rpc.Status` and its error details, `google.protobuf.Any`,
  `Duration` and `Timestamp`, so status details have names even without one.

### Observability

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
- **Correlation:** `ctx.getConnectionId()` and `ctx.acceptedAt()` identify the client connection,
  and the proxy's log lines about it start with `[conn <id>]`.
- **HTTP/2 streams:** `ctx.getStreamId()` names the stream (0 for HTTP/1), and log lines about it
  start with `[conn <id> stream <id>]`. Each stream has its own context, with its own timings and
  upstream status; contexts are equal only for the same connection and stream, and
  `ctx.getConnectionContext()` is the connection's. Callbacks for one connection's streams run
  concurrently, on the streams' threads. A stream that ends without a complete response (the
  client reset it, or the connection closed) is reported with `connectionExceptionCaught(streamCtx,
  cause)`. The request's `protocolVersion()` is `HTTP/2.0`; access logs say `HTTP/2`, as Envoy does.
- **Transparent QUIC:** each flow of the [transparent QUIC](#transparent-quic) listener is a
  client connection of its own (`clientConnected` ... `clientDisconnected`, with
  `ctx.isTransparentQuic()` true), whose made-up `CONNECT` is reported as a request.
  `transparentQuicFlowDecided(ctx, clientHello, intercepted, reason)` says whether it is
  intercepted or relayed, and why; a relayed flow then reports `serverConnected`, the bytes both
  ways and `serverDisconnected`. The logger `org.microproxy.impl.TransparentQuicListener` writes
  each decision, and why a new client was dropped, at DEBUG.
- **Why an exchange ended as it did:** `ctx.failure()` (the `ProxyFailure` the proxy answered, set
  before filters see it), `ctx.responseFlags()` (Envoy's flags: `UF`, `DC`, `UT`, ...) and
  `ctx.responseCodeDetails()` (`via_upstream`, `proxy_failure:connect_failed`, ...); see
  [Response flags and details](#response-flags-and-details). Filters may add their own with
  `ctx.addResponseFlag(flag)` and `ctx.setResponseCodeDetails(details)`.
- **One record per exchange or flow:** `flowEnded(record)` comes once per HTTP exchange, when it
  has ended however it ended, and once per tunnel (`CONNECT`, SOCKS, WebSocket, TCP hooks),
  CONNECT-UDP flow and relayed or stream-intercepted QUIC flow when it closes. The `FlowRecord`
  has the request and response heads, the bytes each way (to the client and on the server's
  wire), the upstream and local addresses and TLS sessions, the duration, the flags and details,
  and what kind of flow it was; the [access log](#access-logs-envoy-compatible) is made of them.
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

Starting with 0.1.1, the release workflow also publishes signed artifacts, sources, and Javadoc
to Maven Central under `io.github.mahmoudimus`. See [publishing setup and retries](docs/PUBLISHING.md)
for the required secrets and manual recovery command.

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
- Logic ported from [mitmproxy](https://github.com/mitmproxy/mitmproxy) and
  [mitmproxy_rs](https://github.com/mitmproxy/mitmproxy_rs) (MIT): in the core, ClientHello
  parsing (from TLS records and from QUIC Initial packets), the ignore / allow host rules and the
  reverse mode specification; in
  `org.microproxy.extras`, the addons, flow filter expressions, HAR export and reading, and server
  and client replay; and for the content views in `org.microproxy.contentviews`, the schema-less
  protobuf heuristics and rendering, the gRPC view, the choice of views by priority, and the
  GraphQL, Socket.IO and form views. The ported files name their sources in their header comments,
  and the content views' test vectors run in the build.

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
