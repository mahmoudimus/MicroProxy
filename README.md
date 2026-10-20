# MicroProxy

[![CI](https://github.com/mahmoudimus/MicroProxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mahmoudimus/MicroProxy/actions/workflows/ci.yml)
[![Release](https://github.com/mahmoudimus/MicroProxy/actions/workflows/release.yml/badge.svg)](https://github.com/mahmoudimus/MicroProxy/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/mahmoudimus/MicroProxy?include_prereleases&sort=semver)](https://github.com/mahmoudimus/MicroProxy/releases)
[![Java 21+](https://img.shields.io/badge/Java-21%2B-blue)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/github/license/mahmoudimus/MicroProxy)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-mahmoudimus.github.io%2FMicroProxy-blue)](https://mahmoudimus.github.io/MicroProxy/)

MicroProxy is an HTTP/HTTPS proxy for Java that can intercept and rewrite traffic: HTTP/1,
HTTP/2, HTTP/3 over its own QUIC, SOCKS, CONNECT-UDP and TLS interception, with Envoy-compatible
access logs, stats and admin API, mitmproxy-style addons, and Starlark scripting. It is a port of
[LittleProxy](https://github.com/LittleProxy/LittleProxy) that drops Netty: each connection runs
on its own **virtual thread** (Project Loom) with plain blocking socket I/O, on JDK 21 or newer,
with **no runtime dependencies**, and LittleProxy's filter API.

- **Documentation:** <https://mahmoudimus.github.io/MicroProxy/> (the same pages are in
  [`docs/`](docs/index.md))
- **Java API:** [Javadoc](https://mahmoudimus.github.io/MicroProxy/api/), also on
  [javadoc.io](https://javadoc.io/doc/io.github.mahmoudimus/microproxy)
- **Changes:** [CHANGELOG.md](CHANGELOG.md) and the [releases](https://github.com/mahmoudimus/MicroProxy/releases)
- **For AI coding agents:** [`llms.txt`](https://mahmoudimus.github.io/MicroProxy/llms.txt) and
  [`llms-full.txt`](https://mahmoudimus.github.io/MicroProxy/llms-full.txt)

## Features

| Area | What you get |
|---|---|
| [Forward proxy](docs/guides/forward-proxy.md) | HTTP/1.0 and 1.1 with keep-alive, pipelining, chunked bodies and trailers; `CONNECT` tunnels; a TLS listener; TLS origination for `https://` URIs; PROXY protocol; throttling; a shared connection pool |
| [Filters](docs/guides/filters.md) | LittleProxy's `HttpFilters` / `HttpFiltersSource` hooks, a lambda builder, failure answers, [body rewriting](docs/guides/rewriting-bodies.md) |
| [MITM](docs/guides/mitm.md) | a built-in CA, per-host certificates, interception decided by the ClientHello, mitmproxy's ignore/allow host rules, ALPN mirroring, per-client CAs and trust |
| [HTTP/2](docs/guides/http2.md) | on by default to clients (intercepted TLS, TLS listener) and servers that offer it, `h2c` on request, connection coalescing, trailers and gRPC, CONNECT and WebSockets, hardened limits |
| [HTTP/3 and QUIC](docs/guides/http3.md) | a reverse proxy's and a forward proxy's HTTP/3 listener, HTTP/3 to servers, 0-RTT, [transparent QUIC](docs/guides/transparent-mode.md#transparent-quic), [CONNECT-UDP (MASQUE)](docs/guides/masque.md), [QUIC stream hooks](docs/guides/quic-hooks.md) |
| Modes | [transparent](docs/guides/transparent-mode.md), [reverse proxy](docs/guides/reverse-proxy.md), [SOCKS4/5 server](docs/guides/socks.md), [chained proxies](docs/guides/chained-proxies.md) with `NO_PROXY` and backoff |
| Hooks | [WebSocket frames and messages](docs/guides/websockets.md), [HTTP/2 and HTTP/3 frames](docs/guides/frame-interception.md), [raw TCP and decrypted TLS](docs/guides/tcp-hooks.md), UDP datagrams, QUIC streams |
| Tools | [mitmproxy-style addons, HAR and replay](docs/guides/addons.md), an [RFC 9111 cache](docs/guides/caching.md), [WARC recording](docs/guides/warc.md), [content views for protobuf and gRPC](docs/guides/content-views.md), [DNSSEC](docs/guides/dnssec.md) |
| Access control | [proxy authentication](docs/guides/authentication.md) (Basic, Bearer, any scheme), [concurrency limiting](docs/guides/concurrency-limiting.md), [hardening](docs/security.md) |
| [Scripting](docs/guides/scripting.md) | sandboxed Starlark hooks for requests, responses, routing, interception, failures, authentication, frames, TCP, UDP and QUIC, with hot reload |
| Observability | Envoy-compatible [access logs](docs/observability/access-logs.md), [stats for Prometheus and statsd](docs/observability/metrics.md), [admin API with draining](docs/observability/admin.md), [OpenTelemetry](docs/observability/opentelemetry.md), [request logging](docs/observability/request-logging.md), [qlog](docs/observability/qlog.md) |

The [feature matrix](docs/index.md#features) lists every feature in detail.

## Quick start

From the command line (build with `mvn package`, or download the jars from the
[releases](https://github.com/mahmoudimus/MicroProxy/releases)):

<!-- x-release-please-start-version -->
```bash
MICROPROXY_VERSION=0.5.1-SNAPSHOT
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080                  # a forward proxy
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm           # intercept HTTPS
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8443 --reverse https://example.com
# Everything built in (scripting, zstd, HTTP/2, QUIC, HTTP/3, OpenTelemetry), one jar:
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 --mitm --script proxy.star
```
<!-- x-release-please-end -->

```bash
curl -x http://127.0.0.1:8080 http://example.com/
curl -x http://127.0.0.1:8080 --cacert microproxy-ca.pem https://example.com/   # with --mitm
```

`--mitm` creates (or reuses) a CA in `microproxy-ca.p12` and writes its certificate to
`microproxy-ca.pem`; clients must trust it. `--help` lists every option, as does the
[command-line reference](docs/reference/cli.md).

Embedded, with a filter that answers some requests itself:

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

Next: the [Quick start](docs/getting-started/quick-start.md), [Your first
filter](docs/getting-started/first-filter.md) (with the imports) and [Your first Starlark
script](docs/getting-started/first-script.md).

## Install

All modules are on Maven Central under `io.github.mahmoudimus`, at the same version. The core
needs nothing else; the other modules are optional.

<!-- x-release-please-start-version -->
```xml
<dependency>
    <groupId>io.github.mahmoudimus</groupId>
    <artifactId>microproxy</artifactId>
    <version>0.5.1-SNAPSHOT</version>
</dependency>
```

```kotlin
implementation("io.github.mahmoudimus:microproxy:0.5.1-SNAPSHOT")
```
<!-- x-release-please-end -->

| Module | Artifact | Contents |
|---|---|---|
| `zstd-decoder/` | `io.github.mahmoudimus:zstd-decoder` | a standalone pure-Java Zstandard decoder ([README](zstd-decoder/README.md)) |
| `http2-codec/` | `io.github.mahmoudimus:http2-codec` | a standalone HTTP/2 frame codec and HPACK ([README](http2-codec/README.md)) |
| `http3-codec/` | `io.github.mahmoudimus:http3-codec` | a standalone HTTP/3 frame codec and QPACK ([README](http3-codec/README.md)) |
| `quic/` | `io.github.mahmoudimus:quic` | a standalone QUIC transport with its own TLS 1.3 handshake, ported from quinn and rustls ([README](quic/README.md)) |
| `microproxy/` | `io.github.mahmoudimus:microproxy` | the proxy; no required dependencies |
| `microproxy-otel/` | `io.github.mahmoudimus:microproxy-otel` | OpenTelemetry tracing and OTLP/HTTP export; depends on the core only |
| `microproxy-starlark/` | `io.github.mahmoudimus:microproxy-starlark` | Starlark scripting, and the self-contained `-all` launcher jar; depends on the core and Guava |

See [Install](docs/getting-started/install.md) for which jars each feature needs, and the `-all`
jar.

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started/install.md) | install, quick start, a first filter, a first script |
| [Guides](docs/guides/forward-proxy.md) | one page per feature: modes, MITM, HTTP/2, HTTP/3, hooks, addons, scripting, ... |
| [Observability](docs/observability/access-logs.md) | access logs, metrics, admin and draining, OpenTelemetry, request logging, qlog |
| [Reference](docs/reference/cli.md) | [flags](docs/reference/cli.md), [properties](docs/reference/properties.md), [stats](docs/reference/stats.md), [access-log operators](docs/reference/access-log-format.md), [response flags](docs/reference/response-flags.md), [admin endpoints](docs/reference/admin-api.md), [Starlark API](docs/reference/starlark-api.md) |
| [Security](docs/security.md) | exposure, hardening limits, SSRF, trust settings |
| [Migrating from LittleProxy](docs/migrating-from-littleproxy.md) | the command line, config file, API and behaviour, mapped |
| [Architecture](docs/architecture.md) | why virtual threads instead of Netty, and the internals |
| [Performance](docs/project/performance.md) | measured against LittleProxy, Envoy, a Go and a Rust proxy, and Squid: throughput, latency and memory, with the raw data |
| [Benchmarks](docs/project/benchmarks.md) | JMH benchmarks against LittleProxy: what they measure, how fairly, how to run them |

## Building and testing

```bash
mvn verify                      # every module, with the tests
mvn -pl microproxy test         # just the core
```

Requires JDK 21 or newer. See [Building and testing](docs/project/building-and-testing.md) for the
interop and conformance suites, and [Writing documentation](docs/CONTRIBUTING-DOCS.md) before
changing the docs. Releases are cut by release-please; Maven Central publishing is described in
[docs/PUBLISHING.md](docs/PUBLISHING.md).

## Acknowledgements

MicroProxy is derived from LittleProxy. It vendors the jaybrotli Brotli codec and Bazel's Starlark
interpreter as extended by starlarky, and ports logic from mitmproxy and mitmproxy_rs; their
licenses and changes are listed in [NOTICE](NOTICE). The full list, including the projects that
contributed ideas, is in [Acknowledgements and license](docs/project/acknowledgements.md).

## License

Apache License 2.0, like LittleProxy, from which this project is derived.
