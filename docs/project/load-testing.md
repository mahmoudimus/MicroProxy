# Load and capacity testing

The system-level load and capacity harness runs MicroProxy and LittleProxy as separate processes
under open-loop load, to find each proxy's sustainable rate, its memory per connection, its limits
and its behaviour under adversarial clients, soak and faults. Use this page to run the harness, to
understand what each scenario proves, to tune the OS for high connection counts, and to read the
report.

This is the second of two layers of performance testing. The first, the JMH
[benchmarks against LittleProxy](benchmarks.md), measures the hot path inside one JVM. This harness
covers what JMH cannot: separate processes, open-loop load corrected for coordinated omission,
connection and memory limits, adversarial clients, long soaks and injected faults.

The harness lives in the `loadtest/` module, which only the `bench` Maven profile builds (the same
profile the benchmarks use): a normal `mvn verify` neither compiles it nor downloads HdrHistogram,
LittleProxy or Netty, and the module is never installed, deployed or published. The published
modules stay dependency-free.

No numbers are published here. Shared CI runners and development containers are too noisy for them,
so results worth quoting come from a manual run on a quiet machine, with the command line and the
JSON alongside.

## The two layers

| Layer | Where | What it answers |
|---|---|---|
| JMH microbenchmarks ([benchmarks](benchmarks.md)) | one JVM, closed loop | how fast is the request path, how much does it allocate, what does an idle connection cost |
| This harness | three processes, open loop | what rate is sustainable end to end, how does memory grow with connections, where is the limit, what happens under attack, soak and faults |

Both pin the same LittleProxy ([below](#the-littleproxy-baseline)) and configure the two proxies the
same way, so their results are about the proxies, not the setup.

## Open-loop testing and coordinated omission

A **closed-loop** client sends the next request only after the previous response arrives. When the
server stalls, such a client stops sending, so the requests that *would* have been sent during the
stall are never measured. The stall is undercounted: its latency is hidden, because the client
colludes with the server by waiting. This is **coordinated omission**, and it makes closed-loop
latency percentiles look far better than what a real client, which keeps sending on its own
schedule, would see.

An **open-loop** client sends at a fixed rate, scheduled independently of responses. The load
generator here fixes the schedule before the first request: request *k* is due at
`start + k / rate`. Latency is measured from each request's **intended** send time, not from when it
was actually sent, exactly as [wrk2](https://github.com/giltene/wrk2) does. A stall then shows as the
latency every request scheduled during it would have seen, which is the point of the measurement.

The load generator uses many keep-alive connections, each driven by its own virtual thread, so the
client is not itself the bottleneck. It reports its own health: when a free connection wakes up late
for a due time (the generator is short of CPU), the lag is recorded, and a step where too many sends
are late is flagged `clientSaturated` and its numbers are discarded. Every response is validated by
status and body length.

## Architecture: three processes

A run starts three kinds of process, each its own JVM, and (where `taskset` is present) pins each to
its own CPUs with a configurable split; without `taskset` they run unpinned and the report says so.

- **The proxy under test**, a fresh JVM per run. MicroProxy starts through its real launcher
  (`org.microproxy.Launcher`, from the project's own jars); LittleProxy through a small launcher in
  the module. Both are started with Native Memory Tracking (`-XX:NativeMemoryTracking=summary`), a
  GC log, an out-of-memory marker and, optionally, a JFR recording, and with a configurable heap,
  `-XX:MaxDirectMemorySize`, `-XX:MaxRAM` and memory-cgroup cap.
- **The origin**, one shared JVM: a minimal HTTP/1.1 server on virtual threads that shares no code
  with either proxy. It serves sized, chunked, slow, stalling and resetting responses and an upload
  endpoint, and hosts the built-in fault relays.
- **The load generator**, a JVM driven over a line protocol, so connections stay open across steps
  while the orchestrator samples the proxy between them.

## The scenarios

Each scenario runs once for MicroProxy and once for LittleProxy, each in a fresh proxy JVM.

| Scenario | What it does | What it proves | Pass/fail |
|---|---|---|---|
| **Rate sweep** | open-loop load over keep-alive connections with small responses, the rate multiplied each step | the maximum sustainable rate (the knee) and the latency curve | the knee is where p99 passes the SLO or errors start; the max sustainable rate is the last good step |
| **Connection ramp** | idle keep-alive connections held in steps (1k, 5k, 10k …), from many loopback source addresses | memory per idle connection, the connection limit, and how it is reached | records RSS, NMT, heap-after-GC, fds, threads and a probe's latency; stops at the first step it cannot complete and says how (refused, unresponsive, crashed, OOM) |
| **Memory under adversarial clients** | the proxy capped in memory, then slowloris, slow readers, parallel large up/down, and an h2c rapid-reset flood | whether backpressure and per-connection caps keep memory bounded | pass is **bounded** (memory levels off) or **shedding** (the proxy refuses or closes the bad connections and stays up); OOM or crash fails |
| **Soak** | a fixed moderate rate held for a configurable duration | leaks: memory, fds or threads that climb monotonically | a least-squares slope that fits well and grows meaningfully is flagged as a possible leak |
| **Fault injection** | a Toxiproxy-style TCP relay between proxy and origin adds latency, caps bandwidth, resets mid-response, stalls and blackholes | that the proxy turns faults into sensible errors without leaking connections or memory | pass is bounded: no hang past the request timeout, the relay's connections return to zero, fds return to the baseline, the proxy survives |

The rapid-reset flood needs HTTP/2 over cleartext (h2c), which the harness enables on MicroProxy for
that workload only (`--http2-cleartext`); LittleProxy serves HTTP/1 only, so it is skipped there and
the report says so.

## Metrics collected

The proxy process is sampled every second, and at each scenario step:

- **OS level**, from `/proc/<pid>`: resident memory (RSS) and its peak (`VmHWM`), the open
  file-descriptor count, the thread count and CPU time. The origin's and the load generator's CPU
  are sampled too, so a saturated origin or client shows in the results.
- **NMT**, from `jcmd <pid> VM.native_memory summary`: committed memory in total, plus the Java
  heap, thread, class, GC and "other" sections (where direct buffers are counted).
- **Heap after a forced GC**, from `jcmd GC.run` then `GC.heap_info`: the live set, without waiting
  for a natural collection.
- **GC**, parsed from the proxy's GC log: each pause and the heap after each collection.
- **MicroProxy's own stats**, when its admin listener is enabled: `/stats?format=json`.

## Reading the report

Each run writes to `loadtest/results/<timestamp>/` (git-ignored): one JSON file per proxy and
scenario with the full time series and settings, a combined `results.json`, a Markdown `report.md`
comparing the two proxies per scenario, and optional SVG charts (written with plain Java when no
plotting library is present). A `latest` symlink points at the newest run. Re-render a report from
its JSON with `java -jar loadtest/target/microproxy-loadtest.jar report loadtest/results/<timestamp>`.

**RSS and NMT, not heap, are the fair memory measure.** Heap alone is misleading across these two
proxies: MicroProxy runs a virtual thread per connection, whose stacks live on the Java heap, while
LittleProxy keeps its buffers in Netty's pooled **direct** memory, which never appears in heap
figures. Comparing their heaps would flatter LittleProxy and overstate MicroProxy. The report
therefore leads with RSS (what the OS accounts) and NMT committed total (what the JVM reserves
across heap and native), and shows heap and the NMT "other" (direct) section alongside. Memory per
idle connection is the slope of RSS and of NMT total against the connection count, which separates
the proxy's fixed cost from its cost per connection.

Every report ends with the harness's **self-checks**: these verify the harness worked (each scenario
ran and responses validated), not how well a proxy did. The CI smoke job fails if any self-check
fails.

## Equal settings, and the ones that cannot be equal

Both proxies are configured the same way, matching the JMH benchmarks' equal settings:

| Setting | Both proxies |
|---|---|
| Listen address | loopback, an ephemeral port; forward proxy |
| Idle connection timeout | 70 s (overridden per scenario: 3600 s in the ramp, short in the fault scenario) |
| Upstream connect timeout | 40 s |
| Initial line, header and chunk limits | 8192, 16384 and 16384 bytes (MicroProxy's defaults; set the same on LittleProxy) |
| `Via` alias | `loadtest`, so both forward the same header |
| Access logs, metrics, filters, auth, chaining, caching | none (MicroProxy's admin listener is optional, read-only, and off by default outside smoke) |
| Server connections | per client connection (both defaults); no shared pool |
| MITM | off (not exercised by these scenarios) |

The settings that [cannot be made equal](benchmarks.md#settings-that-cannot-be-made-equal) are the
same as the benchmarks document: MicroProxy's virtual threads versus LittleProxy's Netty event loops
(whose worker count the `--lp-workers` setting can fix), heap buffers versus Netty's pooled direct
buffers (the reason RSS and NMT lead the report), NIO transport, HTTP/1.1 only on both, and
`Alt-Svc` HTTP/3 stripping left off in MicroProxy. Any setting a run cannot make equal is noted in
the report.

## OS tuning for high connection counts

The connection ramp opens tens or hundreds of thousands of sockets in one machine (the client's,
both sides of the proxy, and the origin's), so the machine's limits, not the proxy, are often what a
run hits first. The harness reads the limits in effect, reports them, and stops gracefully with a
clear message when it reaches the client process's own. Raise them before a large run:

```bash
# Open files (per shell; the hard limit may need privileges or /etc/security/limits.conf).
ulimit -n 1048576

# Accept-queue depth, so bursts of connects are not dropped.
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Ephemeral port range, so one source address offers more outbound ports.
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# Reuse TIME_WAIT sockets for new outbound connections (safe on loopback).
sudo sysctl -w net.ipv4.tcp_tw_reuse=1

# System-wide file-descriptor ceiling.
sudo sysctl -w fs.file-max=2097152
```

**Loopback source addresses.** One source address has at most ~28,000 ephemeral ports, so no single
address can open 100k connections to one destination. On Linux the whole `127.0.0.0/8` block reaches
the loopback interface, so the load generator binds its connections across `127.0.0.2`, `127.0.0.3`,
… (and the origin listens on `127.0.0.1`, `127.0.1.1`, … for the proxy's upstream side), each with
its own ephemeral-port space. The harness picks the number of addresses from the ramp's largest step
and the `--ramp-per-source` setting. On a system where this does not hold (not Linux, or a locked-down
loopback), the ramp is bounded by one address's ports and the report says where it stopped.

## Running

Build the harness and run a preset:

```bash
mvn -Pbench -DskipTests package -pl loadtest -am
java -jar loadtest/target/microproxy-loadtest.jar run --preset smoke
```

Presets: `smoke` (about two minutes, small numbers, for a sanity check and CI), `standard`, and
`full` (long, big numbers, for a real measurement). Override any setting with `--<name> <value>`;
`help` lists them all:

```bash
java -jar loadtest/target/microproxy-loadtest.jar help
java -jar loadtest/target/microproxy-loadtest.jar run --preset standard \
    --scenarios sweep,ramp --sweep-max-rate 200000 --ramp-steps 1000,10000,50000,100000
java -jar loadtest/target/microproxy-loadtest.jar env     # the machine's limits and tools found
```

**External cross-checks.** When [wrk2](https://github.com/giltene/wrk2) (`wrk`),
[h2load](https://nghttp2.org/documentation/h2load-howto.html) or
[Fortio](https://github.com/fortio/fortio) are on the `PATH`, the rate sweep also runs them as a
cross-check and parses their output into the same report; they are skipped when absent. h2load drives
HTTP/2 over h2c and so runs against MicroProxy only.

**In a container with a memory cap.** Give the proxy a cgroup limit so an out-of-memory is contained
and observable, for example `--proxy-cgroup-limit 2g` (every scenario) or `--attack-cgroup-limit 512m`
(the adversarial scenario); where no writable cgroup is available the harness falls back to
`-XX:MaxRAM` and notes it. The proxy's heap and direct-memory caps are `--proxy-heap`, `--proxy-direct`,
`--attack-heap` and `--attack-direct`.

**On a big runner.** The [`loadtest.yml`](https://github.com/mahmoudimus/MicroProxy/blob/main/.github/workflows/loadtest.yml)
workflow runs on demand (`workflow_dispatch`) with inputs for the preset, the scenarios, the proxies,
the `runs-on` label (so a bigger or self-hosted runner can be chosen) and extra settings. It raises
`ulimit -n` and sets the sysctls it is allowed to (the ones above need privileges, which hosted
runners grant through `sudo` and self-hosted ones may not), runs the harness, appends the report to
the run summary and uploads the results directory. The [`ci.yml`](https://github.com/mahmoudimus/MicroProxy/blob/main/.github/workflows/ci.yml)
`loadtest-smoke` job runs the smoke preset on every push as a check that the harness works; it does
not check thresholds, since hosted runners are too noisy.

## The LittleProxy baseline

The baseline is the maintained LittleProxy fork, pinned to **`io.github.littleproxy:littleproxy:2.9.1`**
(the latest on Maven Central), the same coordinates and version the [JMH benchmarks](benchmarks.md)
use, so both layers compare the same LittleProxy. It brings Netty 4.2.17.Final. The older
`xyz.rogfam:littleproxy` coordinates stop at 2.2.0 and `org.littleshoot:littleproxy` at 1.1.2; this
fork continues as `io.github.littleproxy` from 2.2.0 on. LittleProxy and Netty are confined to the
`loadtest` module.
