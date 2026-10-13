# Benchmarks against LittleProxy

JMH benchmarks that measure MicroProxy and LittleProxy side by side, through the same origin
server and the same client, in JVMs started with the same settings. Use this page to run them,
to check what they compare and how fairly, and to read the comparison they print.

These benchmarks are the first of two layers of performance testing. They measure the hot path
inside one JVM; the system-level [load and capacity harness](load-testing.md) measures the proxies
as separate processes under open-loop load, for sustainable rate, memory per connection, limits,
adversarial clients, soak and faults. Both pin the same LittleProxy.

The benchmarks live in the `benchmarks/` module, which only the `bench` Maven profile builds: a
normal `mvn verify` neither compiles it nor downloads JMH, LittleProxy or Netty, and the module is
never installed, deployed or published. The published modules stay dependency-free.

No numbers are published here. Shared CI runners and development containers are too noisy for
them, so results worth quoting come from a manual run on a quiet machine, with the command line
and the JSON alongside.

## What is measured

Every scenario runs once per proxy, as the JMH parameter `proxy` (`microproxy` or
`littleproxy`), so the two are always measured as a pair.

| Scenario | Benchmark | What it measures |
|---|---|---|
| Small GET | `SmallGetBenchmark.throughput`, `.latency` | a 1 KB `GET` over one keep-alive connection: requests per second, and each request's time sampled with percentiles |
| Large bodies | `LargeBodyBenchmark.download`, `.upload` | a 1 MB and a 16 MB response, and a request body of the same sizes, streamed over keep-alive: time per transfer |
| Concurrency | `ConcurrencyBenchmark.requests` | 16, 256 and 4096 keep-alive connections, each with a request in flight, driven by a fixed set of client threads: requests per second |
| Connection churn | `ConnectionChurnBenchmark.throughput`, `.latency` | a new connection per request (`Connection: close`), no keep-alive anywhere |
| `CONNECT` tunnel | `ConnectTunnelBenchmark.throughput` | one tunnel per thread to the origin, then plain bytes relayed unparsed: 1 KB and 1 MB per exchange |
| MITM HTTPS | `MitmBenchmark.request`, `.newSession` | requests over one intercepted TLS session; and whole sessions (`CONNECT`, both handshakes, one request) per second |
| Filter overhead | `FilterBenchmark.throughput`, `.latency` | the small GET through an `HttpFiltersSource` whose filter adds a request header and a response header; compare with the small GET |
| Allocation | any benchmark with `-prof gc` | bytes allocated per operation (`gc.alloc.rate.norm`) |
| Idle footprint | `Footprint` (not JMH) | heap, direct memory, resident memory and platform threads each proxy keeps per idle keep-alive client connection |

### How the concurrency benchmark works

JMH's `@Threads` does not scale to thousands of threads, and thousands of client threads would
measure the client. So `ConcurrencyBenchmark` runs 4 benchmark threads (`-t` changes that), splits
the `connections` between them, and has each thread keep one request outstanding on every one of
its connections. One operation reads and checks the oldest connection's response and sends that
connection's next request. The score is therefore requests per second at a concurrency of exactly
`connections`. The count must be a multiple of the thread count. One connection is the small GET.

## Fairness

### Same JVM settings, one proxy per trial

Each proxy runs inside the benchmark's own JVM, started in `@Setup(Level.Trial)` and stopped in
`@TearDown`. JMH forks fresh JVMs for every parameter set, so neither
proxy inherits the other's JIT profile or heap. Both get the same JMH settings from one class,
`BenchConfig`: 2 forks, 5 warm-up iterations of 2 s, 5 measured iterations of 3 s, and a fixed
2 GB heap (`-Xms2g -Xmx2g`). Command-line overrides (`-f`, `-wi`, `-i`, `-jvmArgsAppend`) apply to
both alike.

### One shared origin

`Origin` is a minimal blocking HTTP/1.1 server on its own pool of platform threads, one per
connection, with no MicroProxy or Netty code. It serves `GET /b/<n>` with an `n`-byte body from
responses prebuilt once per size (large bodies are written in slices of one shared array), reads
and discards request bodies (answering with `X-Received: <bytes>`), and also listens for TLS with a
certificate from the shared test CA for the MITM scenario.

### One shared client

`HttpConnection` speaks HTTP/1.1 over a raw `Socket`: requests are built once, responses are read
up to their `Content-Length` and discarded, and nothing is allocated per request after the first.
The JDK's `HttpClient` would weigh more than either proxy. For MITM, one `SSLContext` trusts only
the shared test CA and checks the certificate's name.

Every response is checked: its status and its `Content-Length` (a response without one fails),
plus `X-Received` for uploads and the filter's headers for the filter benchmark. A check that
fails throws, which fails the benchmark, so a broken proxy cannot post fast numbers.

### Equivalent configuration

Both proxies are configured from `ProxyUnderTest` with the same values:

| Setting | Both proxies |
|---|---|
| Listen address | loopback, an ephemeral port |
| Idle connection timeout | 70 s (both defaults) |
| Connect timeout | 40 s (both defaults) |
| Initial line, header and chunk limits | 8192, 16384 and 16384 bytes |
| `Via` alias | `bench`, so both forward the same header |
| Access logs, metrics, activity trackers, authentication, chaining, caching | none |
| Server connections | per client connection (both defaults); neither shares a pool between clients |
| Filter (filter scenario only) | the same filter against each API: `clientToProxyRequest` adds `X-Bench-Req`, `proxyToClientResponse` adds `X-Bench-Res` |
| MITM (MITM scenario only) | the same CA; leaf certificates for the `CONNECT` host plus the server's names, one EC P-256 key, cached per host; servers validated against the test CA with SNI and HTTPS host-name checks |

LittleProxy's own `SelfSignedMitmManager` presents one self-signed certificate for every host and
trusts every server, which is not the same work. So the module has a minimal LittleProxy
`MitmManager`, `LittleProxyMitmManager`, that delegates to MicroProxy's
`CertificateAuthorityMitmManager`: both proxies sign and cache leaf certificates with the same
code and the same CA.

### Settings that cannot be made equal

- **Threads.** MicroProxy runs a virtual thread per connection on the JDK's scheduler (as many
  carrier threads as cores). LittleProxy runs Netty event loops: its defaults are 2 acceptor
  threads and 8 client-to-proxy and 8 proxy-to-server worker threads, whatever the core count.
  `-jvmArgsAppend -Dbench.littleproxy.workers=N` sets both of LittleProxy's worker pools to `N`.
- **Buffers.** LittleProxy reads into Netty's pooled (mostly direct) buffers; MicroProxy into heap
  buffers lent from a per-server pool. Netty's direct memory does not show in heap figures, which
  is why the footprint harness reports direct and resident memory too.
- **Transport.** LittleProxy uses Netty's NIO transport, its default; no native transport (epoll)
  is on the class path. No Netty-specific JVM flags are set.
- **Protocols.** Both speak HTTP/1.1 only: the benchmarks jar does not include `http2-codec`, so
  MicroProxy offers no HTTP/2 to clients or servers, and LittleProxy has none.
- **TLS plumbing.** MicroProxy uses `SSLSocket`, LittleProxy `SSLEngine` through Netty's
  `SslHandler`; both negotiate TLS 1.3 with the JDK's provider.
- **Alt-Svc.** MicroProxy strips HTTP/3 from `Alt-Svc` by default when intercepting; it is turned
  off here (the origin sends none anyway), as LittleProxy has no such rewrite.
- **Logging.** LittleProxy logs through SLF4J, bound to the no-op provider; Netty, which skips that
  provider, and MicroProxy log through `java.util.logging`, set to warnings only. None of them
  writes anything during a healthy run.
- **TLS handshake timeout.** MicroProxy bounds handshakes (10 s by default); LittleProxy has no
  such setting. No handshake comes near it.

## Running the benchmarks

Build the executable `benchmarks/target/benchmarks.jar` (JDK 21 or newer):

```bash
mvn -B -Pbench -DskipTests package -pl benchmarks -am
```

`benchmarks/run.sh` builds the jar when it is missing (or always, with `BUILD=1`), runs JMH with a
preset, writes JMH's JSON and the Markdown comparison to `benchmarks/target/results/`, and prints
the comparison. Options after the preset go to JMH and override the preset's:

```bash
benchmarks/run.sh smoke                        # every benchmark once, small parameters (what CI runs)
benchmarks/run.sh quick                        # 1 fork, 3 x 2 s warm-up and measurement
benchmarks/run.sh full                         # the annotations' settings: 2 forks, 5 x 2 s + 5 x 3 s
benchmarks/run.sh quick SmallGet Concurrency   # only the benchmarks matching these regexps
benchmarks/run.sh full -p connections=4096 Concurrency
```

The same with JMH directly:

```bash
java -jar benchmarks/target/benchmarks.jar -l                          # list the benchmarks
java -jar benchmarks/target/benchmarks.jar -f 1 -wi 3 -i 3 -rf json -rff quick.json
java -jar benchmarks/target/benchmarks.jar -rf json -rff full.json     # full settings
python3 benchmarks/compare.py full.json
```

The concurrency benchmark with 4096 connections holds 16,384 sockets in one JVM (the client's,
both sides of the proxy, and the origin's). `run.sh` raises the open-file limit when it can; otherwise raise it
first (`ulimit -n 32768`). Run on an otherwise idle machine, with frequency scaling and turbo
settled if you can, and keep the JSON with the numbers.

### Allocation per operation

JMH's GC profiler reports the bytes allocated per operation (`gc.alloc.rate.norm`), which
`compare.py` shows as a row of its own:

```bash
benchmarks/run.sh quick -prof gc SmallGet Filter
```

The count covers every thread in the JVM: the proxy's (MicroProxy's virtual threads included,
counted on their carrier threads), the origin's and the client's. The origin and client allocate
the same for both proxies, so the difference between the two rows is the proxies'.

### Footprint per idle connection

`Footprint` runs each proxy alone in a child JVM, so its figures hold nothing but the proxy. It
warms the proxy up, records a baseline after garbage collection, opens `N` keep-alive connections
with one request each (so the proxy also holds a server connection for each), collects again and
divides the difference by `N`:

```bash
java -cp benchmarks/target/benchmarks.jar org.microproxy.bench.Footprint --connections 2000
```

It prints a Markdown table of heap, direct memory, resident memory (`VmRSS`, Linux only) and
platform threads per connection. Resident memory is an upper bound: the JVM rarely gives memory
back. `--proxies` picks the proxies and `--jvm-arg` adds JVM options to the children (both get
the same).

## Reading the comparison

`compare.py` reads JMH's JSON (any number of files) and prints one row per benchmark, mode and
parameter set:

| Column | Meaning |
|---|---|
| MicroProxy, LittleProxy | the score with JMH's error, the half-width of its 99.9% confidence interval |
| Ratio | MicroProxy's score divided by LittleProxy's |
| Better | which proxy did better; "within error" when the two confidence intervals overlap |

For throughput (`thrpt`, operations per second) higher is better. For average time (`avgt`, the
large bodies), sampled time (`sample`) and bytes per operation, lower is better. Sampled latency
gets extra rows for the 50th, 99th and 99.9th percentiles; tail percentiles from short runs rest on
a handful of samples. A ratio from one fork with few iterations, or with "within error", says
little. Keep the JVM version, the machine and the command line with any numbers, as the table's
header line does.

```bash
python3 benchmarks/compare.py results.json --output results.md
python3 benchmarks/compare.py results.json --all-secondary   # every profiler metric
```

## LittleProxy version

The benchmarks pin **LittleProxy 2.9.1**, `io.github.littleproxy:littleproxy:2.9.1` on Maven
Central, the latest release of the maintained fork ([LittleProxy/LittleProxy](https://github.com/LittleProxy/LittleProxy))
when they were written. It targets Java 11 and runs on 21, and brings Netty 4.2 with it. Earlier
releases were published as `org.littleshoot:littleproxy` (up to 1.1.2) and
`xyz.rogfam:littleproxy` (2.0 to 2.2.0). The version is `littleproxy.version` in
`benchmarks/pom.xml`, and `compare.py` prints it with the results.

## In CI

- **`bench-smoke`** (in `ci.yml`, on every push): builds with `-Pbench`, runs every benchmark once
  against both proxies with small parameters (`benchmarks/run.sh smoke`: `-f 1 -wi 0 -i 1 -r 1s`),
  and runs the footprint harness with 100 connections. It checks that the benchmarks work, not how
  fast anything is.
- **`bench.yml`** (manual, `workflow_dispatch`): runs a preset (full by default) with an optional
  benchmark filter and JMH options, then the footprint harness, and uploads the JSON and the
  Markdown comparison as artifacts. Hosted runners are shared, so treat its numbers as indicative.
