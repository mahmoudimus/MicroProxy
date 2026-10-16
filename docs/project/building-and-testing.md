# Building and testing

Build MicroProxy from source, run its test suites (unit, interop, conformance, DNSSEC), and cut
releases. Use this page when contributing code; documentation changes are described in [Writing
documentation](../CONTRIBUTING-DOCS.md).

## Building

```bash
mvn verify                      # every module, with the tests
mvn -pl microproxy test         # just the core
```

`microproxy-starlark` reuses the core's test helpers through its `tests` jar. The build needs
JDK 21 or newer, and runs the parser, WebSocket and SIMD tests a second time with the Vector API
module ([SIMD](../guides/performance.md#simd-optional)).

How a request flows through the proxy, which parts are HTTP/1-specific and how HTTP/2 streams run
the same exchange logic concurrently, is described in
[`microproxy/src/main/java/org/microproxy/impl/README.md`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md).
`AllocationTest` fails if a small keep-alive request starts allocating much more than it does now.

The JMH benchmarks against LittleProxy are a separate module built only with `-Pbench`; see
[Benchmarks against LittleProxy](benchmarks.md).

## Releases

Releases are cut by [release-please](https://github.com/googleapis/release-please). It reads
[Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `feat!:`) on
`main` and keeps a release pull request open that bumps every `pom.xml`, the versions in the
README and the docs (the files listed in `release-please-config.json`) and `CHANGELOG.md`. Merging it tags `vX.Y.Z`, publishes a GitHub release with the jars
and their `SHA256SUMS` attached, and opens a follow-up pull request that moves `main` to the
next `-SNAPSHOT` version.

Starting with 0.1.1, the release workflow also publishes signed artifacts, sources, and Javadoc
to Maven Central under `io.github.mahmoudimus`. See [publishing setup and retries](../PUBLISHING.md)
for the required secrets and manual recovery command.

## Tests

The tests use JUnit 5, the JDK's `HttpClient` as the client, `com.sun.net.httpserver` as origin
servers, and raw sockets for wire-level checks. They cover proxying, filters, authentication,
CONNECT, MITM, chaining (HTTP, TLS, SOCKS4/5, fallback), timeouts, PROXY protocol, throttling,
lifecycle, the codec, certificate generation, the shared pool, WebSocket frames, access logs,
HTTP/2 (with the JDK's HTTP/2 client, frame-by-frame protocol tests, a codec-based HTTP/2 origin
for the server side and gRPC-style streaming, and, when installed, `curl --http2`; CI also runs
[h2spec](../guides/http2.md#conformance-h2spec) and [grpcio's client and server](../guides/http2.md#grpc-interop-grpcio)),
content codings (Brotli against streams from the reference encoder, and malformed streams that it
rejects) and the scripting hooks, sandbox limits and reloading.

DNSSEC is tested in three ways, all offline:

- **Real responses:** responses recorded from real signed, unsigned and deliberately broken zones
  are replayed with the clock fixed at recording time, then tampered with.
- **Synthetic zones:** a signed hierarchy built in the test covers wildcards, unsigned delegations
  and forgeries.
- **Published values:** the IANA root key's tag and digest, and the RFC 5155 hash vectors.

Live validation is opt-in locally (CI runs it on every push and pull request), and so is
re-recording. It asks Cloudflare, Google and Quad9 over DNS over HTTPS, by name and then by
address (1.1.1.1, 8.8.8.8, 8.8.4.4, 9.9.9.9), each in turn when the one before cannot answer
(`DnsTransport.failover`); a comma-separated `-Dmicroproxy.dns.doh` replaces the list:

```bash
mvn test -Dtest=DnssecLiveTest -Dmicroproxy.dns.live=true [-Dmicroproxy.dns.record=true]
```

## Interop and conformance in CI

CI (`.github/workflows/ci.yml`) runs `mvn verify` on JDK 21 and 25 with every test, skipping
none: its Python peers are installed (aioquic for QUIC and HTTP/3 interop, opentelemetry-proto
for the OTLP encodings, grpcio for [gRPC interop](../guides/http2.md#grpc-interop-grpcio)) and
required (`-Dquic.interop.required=true`, `-Dotel.interop.required=true`,
`-Dgrpc.interop.required=true`, so a missing peer fails the build), and the live DNSSEC test runs
too (`-Dmicroproxy.dns.live=true`). It also runs [h2spec](../guides/http2.md#conformance-h2spec)
against the `h2c` listener, a check of the Maven Central sources and Javadoc, and the documentation build (`mkdocs build --strict`, the link check and the
`llms.txt` check; see [Writing documentation](../CONTRIBUTING-DOCS.md)). `DocsDriftTest` fails
when a launcher flag or a properties key is missing from the reference pages.
