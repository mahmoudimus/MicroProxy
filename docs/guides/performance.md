# Performance options

Two optional JVM-level switches: SIMD byte loops through the JDK's incubating Vector API, and an
experimental build with Project Valhalla value classes. Neither is needed; use this page to decide
whether to turn SIMD on, or to track Valhalla. The design that makes the proxy fast by default is
in [Architecture](../architecture.md#why-virtual-threads-instead-of-netty).

## SIMD (optional)

A few byte loops can use the JDK's Vector API: WebSocket payload unmasking, the line scanning in
the HTTP parser, and the match comparisons of the Brotli encoder (used when a filter rewrites a
`br` body). The API is still an incubating module (JDK 21 through 26), so it is off unless
you ask for it:

```bash
java --add-modules jdk.incubator.vector -jar microproxy.jar ...   # prints "SIMD: vector 512-bit"
```

The JVM then warns that it is using an incubator module. `-Dmicroproxy.simd=false` turns SIMD off
again, and `-Dmicroproxy.simd=true` warns if the module is missing. Without the module, the
scalar code runs, and it now works eight bytes at a time. The Brotli encoder follows the same
choice unless jaybrotli's own `-Djaybrotli.simd` (`false`, `arrays` or `true`) is set.

Measured on a 4-core AVX-512 machine:

| | before | scalar | vector |
|---|---|---|---|
| unmask a 1 KiB WebSocket payload | 1.0 GB/s | 5.9 GB/s | 41.7 GB/s |
| unmask a 64 KiB payload | 1.3 GB/s | 5.7 GB/s | 35.5 GB/s |
| find the end of a 400-byte header line | — | 7.1 GB/s | 25.8 GB/s |

Inputs shorter than two vectors (128 bytes with AVX-512) use the scalar code, which is faster
there. The build runs the parser, WebSocket and SIMD tests a second time with the module, so
both paths are tested.

## Value classes (Project Valhalla, experimental)

Value classes (JEP 401) are a preview feature of JDK 28. Preview class files run only on that
exact JDK, with `--enable-preview`, so they cannot ship in a JDK 21 jar. Instead, a build profile
turns the small immutable records marked `// @value-candidate` into value classes:
`HttpVersion`, `HttpResponseStatus`, `HostAndPort`, `Framing`, the DNS record types, cache and
pool records, and so on (19 in all).

<!-- x-release-please-start-version -->
```bash
MICROPROXY_VERSION=0.2.0
# JAVA_HOME = a JDK 28 early-access build (https://jdk.java.net/28/)
mvn -Pvalhalla -pl zstd-decoder,microproxy verify     # all tests pass with value classes
java --enable-preview -cp microproxy/target/microproxy-${MICROPROXY_VERSION}-valhalla.jar org.microproxy.Launcher
```
<!-- x-release-please-end -->

Measured on JDK 28 EA (build 18), with identical code apart from the `value` modifier:

| | identity records | value records |
|---|---|---|
| allocation per small keep-alive request (before the [header work](../architecture.md#why-virtual-threads-instead-of-netty)) | 10,224 bytes | 10,135 bytes |
| throughput, 16 clients | ~36,500 req/s | ~34,700 req/s (within noise) |
| heap per idle connection pair | 10.3 KiB | 11.8 KiB (within noise) |

The difference is under 1%. These records are short-lived, and escape analysis already
removes most of them. Allocation per request is mostly strings and arrays from header
handling, which value classes do not change. The profile stays useful for tracking Valhalla
as it matures (null-restricted types and flattened arrays would matter for header storage),
but it is not worth running in production today.
