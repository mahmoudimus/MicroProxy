# Install

How to get MicroProxy: the Maven and Gradle coordinates of each module, the self-contained `-all`
jar with every optional feature built in, and how to build the launcher from source. Read this
first, then follow the [Quick start](quick-start.md).

## Requirements

- **Java:** JDK 21 or newer (also tested on JDK 25). The proxy uses virtual threads, which are
  final in JDK 21.
- **Dependencies:** none at runtime. Logging goes through `System.Logger`, which can be routed to
  SLF4J/Log4j with the usual bridges (`slf4j-jdk-platform-logging`, `log4j-jpl`).

## Modules and artifacts

Every module is published to Maven Central under the `io.github.mahmoudimus` group, at the same
version. The core has no required dependencies; the codecs and QUIC are optional jars it uses
when they are on the class path.

| Module | Artifact | Contents |
|---|---|---|
| `zstd-decoder/` | `io.github.mahmoudimus:zstd-decoder` | a standalone pure-Java Zstandard decoder ([README](https://github.com/mahmoudimus/MicroProxy/blob/main/zstd-decoder/README.md)) |
| `http2-codec/` | `io.github.mahmoudimus:http2-codec` | a standalone HTTP/2 frame codec and HPACK implementation ([README](https://github.com/mahmoudimus/MicroProxy/blob/main/http2-codec/README.md)) |
| `http3-codec/` | `io.github.mahmoudimus:http3-codec` | a standalone HTTP/3 frame codec and QPACK implementation, used by HTTP/3 and the HTTP/3 frame pipeline ([README](https://github.com/mahmoudimus/MicroProxy/blob/main/http3-codec/README.md)) |
| `quic/` | `io.github.mahmoudimus:quic` | a standalone QUIC transport with its own TLS 1.3 handshake, ported from quinn and rustls, used by HTTP/3 ([README](https://github.com/mahmoudimus/MicroProxy/blob/main/quic/README.md)) |
| `microproxy/` | `io.github.mahmoudimus:microproxy` | the proxy; no required dependencies (`zstd-decoder`, `http2-codec`, `http3-codec` and `quic` are optional) |
| `microproxy-otel/` | `io.github.mahmoudimus:microproxy-otel` | OpenTelemetry: W3C, B3 and Jaeger propagation, spans per exchange and attempt, and OTLP/HTTP export of traces, metrics and access logs; depends on the core only ([OpenTelemetry](../observability/opentelemetry.md)) |
| `microproxy-starlark/` | `io.github.mahmoudimus:microproxy-starlark` | Starlark scripting; depends on the core and Guava |

Which optional jars a feature needs:

| Feature | Jars besides `microproxy` |
|---|---|
| `zstd` bodies (`Content-Encoding: zstd`, gRPC's `zstd` encoding in content views) | `zstd-decoder` |
| [HTTP/2](../guides/http2.md) to clients and servers (on by default: `--http2`, `--http2-upstream`; and `--http2-cleartext`) | `http2-codec` |
| [HTTP/3 and QUIC](../guides/http3.md), [CONNECT-UDP](../guides/masque.md), [transparent QUIC](../guides/transparent-mode.md#transparent-quic) | `quic` and `http3-codec` |
| [Frame interceptors over HTTP/3 streams](../guides/frame-interception.md#http3-frames) (`Http3FramePipeline`) | `http3-codec` |
| [OpenTelemetry](../observability/opentelemetry.md) (`--otel`, `OTEL_*`) | `microproxy-otel` |
| [Starlark scripting](../guides/scripting.md) (`--script`) | `microproxy-starlark` (and its Guava dependency) |

A proxy started with HTTP/2 or HTTP/3 enabled but without the jars it needs fails at startup with
an `IllegalStateException` that says so; without those features, nothing loads them. HTTP/2 to
clients and servers, on by default, is the exception: left at its default without `http2-codec`,
it falls back to HTTP/1.1 (logged once at `INFO`), so the `microproxy` jar alone still runs with
`--mitm`; only `--http2`, `--http2-upstream` or `--http2-cleartext` given explicitly fail.

## Maven

<!-- x-release-please-start-version -->
```xml
<dependency>
    <groupId>io.github.mahmoudimus</groupId>
    <artifactId>microproxy</artifactId>
    <version>0.4.0</version>
</dependency>
<!-- Optional: HTTP/2 to clients and servers. -->
<dependency>
    <groupId>io.github.mahmoudimus</groupId>
    <artifactId>http2-codec</artifactId>
    <version>0.4.0</version>
</dependency>
```
<!-- x-release-please-end -->

Add `quic` and `http3-codec` for HTTP/3, `zstd-decoder` for `zstd` bodies, `microproxy-otel` for
OpenTelemetry and `microproxy-starlark` for scripting, all at the same version.

## Gradle

<!-- x-release-please-start-version -->
```kotlin
dependencies {
    implementation("io.github.mahmoudimus:microproxy:0.4.0")
    // Optional, at the same version:
    implementation("io.github.mahmoudimus:http2-codec:0.4.0")
    implementation("io.github.mahmoudimus:http3-codec:0.4.0")
    implementation("io.github.mahmoudimus:quic:0.4.0")
}
```
<!-- x-release-please-end -->

## The self-contained all jar

`microproxy-starlark` also builds an executable jar with the classifier `all` that bundles the
launcher, scripting, zstd, HTTP/2, QUIC, HTTP/3 and OpenTelemetry: one file to run with
`java -jar`. It is attached to every [GitHub release](https://github.com/mahmoudimus/MicroProxy/releases)
(with a `SHA256SUMS` file) and published to Maven Central as
`io.github.mahmoudimus:microproxy-starlark:<version>:all`.

<!-- x-release-please-start-version -->
```bash
MICROPROXY_VERSION=0.4.0
curl -LO https://github.com/mahmoudimus/MicroProxy/releases/download/v${MICROPROXY_VERSION}/microproxy-starlark-${MICROPROXY_VERSION}-all.jar
java -jar microproxy-starlark-${MICROPROXY_VERSION}-all.jar --help
```
<!-- x-release-please-end -->

## The launcher

`org.microproxy.Launcher` is the command-line entry point, and the `Main-Class` of both the
`microproxy` jar and the `-all` jar. `--help` prints every option; the
[command-line reference](../reference/cli.md) lists them with links to their guides, and
[configuration properties](../reference/properties.md) lists the keys of a `--config` file.
Optional modules add their own options when their jars are on the class path (`--script` from
`microproxy-starlark`, `--otel` from `microproxy-otel`).

## Building from source

<!-- x-release-please-start-version -->
```bash
git clone https://github.com/mahmoudimus/MicroProxy.git && cd MicroProxy
MICROPROXY_VERSION=0.4.0
mvn package                                   # every module, with the tests
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080
```
<!-- x-release-please-end -->

`mvn -DskipTests package` skips the tests. See [Building and testing](../project/building-and-testing.md)
for the test suites and the release process.

## API documentation

The Javadoc of every published module is on this site at [`/api/`](https://mahmoudimus.github.io/MicroProxy/api/) ([Java API](../java-api.md)), and each release's
Javadoc is also on [javadoc.io](https://javadoc.io/doc/io.github.mahmoudimus/microproxy), since
the jars on Maven Central ship with their Javadoc.
