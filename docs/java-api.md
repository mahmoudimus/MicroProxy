# Java API (Javadoc)

Where to find the Javadoc of MicroProxy's published modules: the aggregated API on this site, and
each release's Javadoc on javadoc.io. Use it for the exact signatures of the bootstrap, filters,
trackers and extras that the guides describe.

## On this site

The aggregated Javadoc of every published module, built from `main` with the site, is at
**[api/](https://mahmoudimus.github.io/MicroProxy/api/)**. Its packages are grouped by module:

| Module | Packages |
|---|---|
| `microproxy` | `org.microproxy` (the bootstrap, `HttpFilters`, `ActivityTracker`, `MitmManager`, `FlowContext`, ...), `org.microproxy.http`, `.extras`, `.cache`, `.contentviews`, `.dns`, `.frames`, `.quic`, `.simd`, `.stats`, `.tcp`, `.tls`, `.udp`, `.warc` |
| `microproxy-otel` | `org.microproxy.otel` |
| `microproxy-starlark` | `org.microproxy.starlark`, `org.microproxy.starlark.stdlib` |
| `zstd-decoder`, `http2-codec`, `http3-codec`, `quic` | `io.github.mahmoudimus.zstd`, `.http2`, `.http3`, `.quic` and its subpackages |

The internals (`org.microproxy.impl`, described in [Architecture](architecture.md)) and the
vendored code (`org.microproxy.thirdparty`) are not part of the public API and are left out.

To build the same pages locally:

```bash
mvn -B -DskipTests install
mvn -B javadoc:aggregate-no-fork@api-docs -Dmaven.javadoc.skip=true
# open target/reports/apidocs/index.html
```

## On javadoc.io

The jars on Maven Central ship with their Javadoc, so every released version of every module is
browsable on javadoc.io:

- [io.github.mahmoudimus:microproxy](https://javadoc.io/doc/io.github.mahmoudimus/microproxy)
- [io.github.mahmoudimus:microproxy-otel](https://javadoc.io/doc/io.github.mahmoudimus/microproxy-otel)
- [io.github.mahmoudimus:microproxy-starlark](https://javadoc.io/doc/io.github.mahmoudimus/microproxy-starlark)
- [io.github.mahmoudimus:http2-codec](https://javadoc.io/doc/io.github.mahmoudimus/http2-codec),
  [http3-codec](https://javadoc.io/doc/io.github.mahmoudimus/http3-codec),
  [quic](https://javadoc.io/doc/io.github.mahmoudimus/quic) and
  [zstd-decoder](https://javadoc.io/doc/io.github.mahmoudimus/zstd-decoder)

Your IDE shows the same Javadoc when it downloads the sources and Javadoc jars.

## Where to start

- `org.microproxy.MicroProxy.bootstrap()` returns an `HttpProxyServerBootstrap`, whose `with...`
  methods are the Java side of every [command-line flag](reference/cli.md).
- `org.microproxy.HttpFilters` and `HttpFiltersSource`: see [Filters](guides/filters.md).
- `org.microproxy.ActivityTracker`: see [Activity tracking](observability/activity-tracking.md).
- `org.microproxy.MitmManager` and `org.microproxy.tls`: see [MITM](guides/mitm.md).
- `org.microproxy.extras`: the addons, loggers, recorders and limiter.
