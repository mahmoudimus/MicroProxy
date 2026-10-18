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

This page publishes no numbers of its own, and CI checks none: shared CI runners are too noisy for
them. The one published set is [Performance against other proxies](performance.md): a dated
snapshot from one stated machine, with the raw JSON, every command line and every configuration
beside it. Read it as relative, not absolute (the same proxies on other hardware will post other
numbers, and their order can change), and reproduce it with the commands on that page.

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

| Scenario | What it does | What it proves | Verdicts |
|---|---|---|---|
| **Rate sweep** | open-loop load over keep-alive connections with small responses, the rate multiplied each step | the maximum sustainable rate (the knee) and the latency curve | the knee is where p99 passes the SLO or errors start; the max sustainable rate is the last good step, refined by bisecting between it and the knee (data), with the proxy's CPU time per request at every step. Verdict: the proxy survived, or crashed / ran out of memory |
| **Connection ramp** | idle keep-alive connections held in steps (1k, 5k, 10k …), from many loopback source addresses | memory per idle connection, the connection limit, and how it is reached | records RSS, NMT, heap-after-GC, fds, threads and a probe's latency; stops at the first step it cannot complete and says how (refused, unresponsive, crashed, OOM, or the client's own limit). The limit is data; the verdict is whether the proxy survived |
| **Memory under adversarial clients** | the proxy capped in memory, then slowloris, slow readers, parallel large up/down, and an h2c rapid-reset flood | whether backpressure and per-connection caps keep memory bounded | **bounded** or **shedding** pass; **unbounded-growth**, **oom** or **crashed** fail; **inconclusive** when the window is too short (see [below](#how-memory-growth-is-judged)) |
| **Soak** | a fixed moderate rate held for a configurable duration | leaks: memory, fds or threads that climb monotonically | **possible-leak** (fail) when a series climbs steadily after the warm-up, **no-leak** (pass), or **inconclusive** for a soak too short to judge |
| **Fault injection** | a Toxiproxy-style TCP relay between proxy and origin adds latency, caps bandwidth, resets mid-response, stalls and blackholes | that the proxy turns faults into sensible errors without leaking connections or memory | per fault, **bounded** (pass): no hang past the request timeout, the relay's connections return to zero and fds to the baseline within the proxy's idle timeout (a proxy that pools upstream connections may keep one until then), the proxy survives; and across the faults, the heap after GC and NMT total return near the baseline |

The rapid-reset flood needs HTTP/2 over cleartext (h2c), which the harness enables on MicroProxy for
that workload only (`--http2-cleartext`); LittleProxy serves HTTP/1 only, so it is skipped there and
the report says so.

## External proxies

Besides MicroProxy and LittleProxy, the harness can test any proxy that runs as its own process: a
native binary such as Envoy, or a proxy written in Go or Rust. A JSON file named by
`--external-proxies` describes each one: its command line, an optional configuration template, its
environment, a command that prints its version, and the scenarios or workloads it cannot run.
Placeholders in the command and the template (`{{port}}`, `{{idleSeconds}}`, `{{headSeconds}}`,
`{{connectTimeoutMs}}`, `{{connectTimeoutSeconds}}`, `{{workers}}`, `{{config}}`, `{{logs}}`,
`{{name}}`, `{{home}}` and `{{tools}}`) are filled in per run, so every proxy gets the same port
handling, timeouts and worker count (`{{workers}}` is the number of CPUs the proxy is pinned to, and
`{{headSeconds}}` the limit on a whole request head, `--head-timeout`, which is the idle timeout
unless set; LittleProxy has no such limit).

An external proxy is started like the JVM proxies: pinned to the proxy's CPUs, inside the memory
cgroup when a scenario caps memory, and ready once its port accepts connections. Its memory comes
from `/proc` only, so RSS, file descriptors, threads and CPU time are measured as for the JVMs, while
the JVM-only figures (NMT, the heap after a forced GC, the GC log) are n/a. Of the memory caps, only
the cgroup limit applies to it; the fault scenario's retained-memory verdict uses RSS for it. A
scenario or workload the proxy cannot run is reported as not supported, never dropped.
[`loadtest/competitors/`](https://github.com/mahmoudimus/MicroProxy/blob/main/loadtest/competitors/proxies.json)
defines Envoy, goproxy, g3proxy and Squid this way, with a setup script that downloads or builds
them; see [Performance against other proxies](performance.md).

```bash
loadtest/competitors/setup.sh            # the external proxies, into loadtest/competitors/.tools/
java -jar loadtest/target/microproxy-loadtest.jar run --preset smoke \
    --external-proxies loadtest/competitors/proxies.json --proxies microproxy,envoy,goproxy
```

### How memory growth is judged

A proxy's memory rises at the start of a workload whatever it does: buffer pools fill, the JIT
compiles, per-connection state is allocated. A rising peak is therefore not growth. Each workload's
first 10 s, or its first quarter if that is longer, is a warm-up the verdict ignores. Over the rest,
a least-squares line is fitted to RSS and to NMT total. The verdict is **unbounded-growth** only if
one of them climbs steadily: the line fits with R² of at least 0.8, *and* memory grows along it by
more than 32 MB *and* by more than a quarter of the window's mean. Otherwise the verdict is
**bounded**. If the proxy closed or refused at least a tenth of the adversarial connections and
stayed up, the verdict is **shedding**. If fewer than 5 samples or 20 s remain after the warm-up,
the window cannot tell growth from warm-up, so the verdict is **inconclusive**. An out-of-memory error
(in the proxy's log, or a cgroup OOM kill) is **oom**, even if the process kept running, and an exit
is **crashed**.

**Socket buffers.** cgroup v2 charges a group for its sockets' TCP buffers as well as for its
processes' memory, and a kernel limit covers both. How much a slow client leaves in those buffers
is set mostly by the kernel (`tcp_rmem`, `tcp_wmem` and their autotuning; newer kernels let a
receive buffer grow to 32 MB), and with a few hundred slow readers the buffers alone can fill a
512 MB limit and have the OOM killer end the proxy whatever the proxy holds. So by default
(`--attack-cgroup-sockets exclude`) the cgroup gets no kernel limit: the harness reads its
`memory.current` and `memory.stat` every 100 ms, holds the memory other than the socket buffers
(the processes' own, and the kernel's on their behalf) to `--attack-cgroup-limit`, killing the
proxy as the OOM killer would when it passes it (verdict **oom**, saying so), and reports the
socket buffers' peak beside the proxy's memory. `--attack-cgroup-sockets include` keeps the
kernel's limit over both, which is what a proxy in a container with that memory limit lives
under. cgroup v1 keeps TCP buffers out of its memory limit either way, and reports them apart
(`memory.kmem.tcp.usage_in_bytes`). The run records the machine's `tcp_rmem` and `tcp_wmem`.

The smoke preset's workloads last a few seconds, shorter than the warm-up, so its memory verdicts are
always inconclusive (the same holds for its 10 s soak). They are reported, never gating, and they do
not flip from run to run. Real growth verdicts come from the standard and full presets.

### What the slow readers show about LittleProxy

The slow-reader workload asks for large responses and reads them a few kilobytes a second, so a
proxy must either stop reading from the origin (backpressure) or hold the response. Measured with
this harness, LittleProxy does stop reading: with direct memory uncapped, its NMT "other" section
(where Netty's pooled direct buffers are counted) rises to a plateau within seconds and stays flat
while the readers drain. It never comes near holding the whole response. But at that plateau it
holds a sizeable buffer per slow reader, a little under a megabyte of direct memory in these runs,
which is consistent with Netty reading a full read loop's worth before writability turns reading off.
The direct memory LittleProxy needs therefore grows with the number of slow readers. With the
standard preset's settings (200 readers, a 128 MB direct-memory cap) it exceeds the cap and reports
out-of-memory ("Cannot reserve … bytes of direct buffer memory"). It keeps running, and honest probes
time out for a while before they recover. MicroProxy holds no extra direct memory per slow reader,
and its RSS stays flat. The report's "direct per reader" column shows the figure for each run.

The smoke preset's 20 readers stay well under its 64 MB cap. LittleProxy's RSS there jumps to its
plateau during the first seconds, which an earlier, naive rule ("the last sample is the peak and still
rising") misread as unbounded growth on some runs and not on others. The warm-up and fit rules above
replace that rule.

## Self-checks, verdicts and the gate

Every run keeps two kinds of result apart:

- **Harness self-checks** say the harness itself worked: each scenario ran without error, responses
  through the proxy validated by status and length, the proxy's metrics were sampled (`/proc` and
  NMT), and the JSON and Markdown reports were written. A failed self-check always fails the run.
- **Verdicts** judge the proxy under test: survived, crashed or oom in the sweep and the ramp;
  bounded, shedding, unbounded-growth, oom or crashed for each memory workload; no-leak or
  possible-leak in the soak; bounded, leak-or-hang or memory-retained for the faults. A verdict can
  also be **inconclusive** (or n/a), which never fails a run.

`--gate` decides which failed verdicts fail the run (exit code 1):

| `--gate` | Fails the run on |
|---|---|
| `microproxy` (default) | a failed self-check, or a failed verdict on MicroProxy, the system under development |
| `all` | a failed self-check, or a failed verdict on either proxy |
| `none` | a failed self-check only |

LittleProxy's verdicts are comparison data. Under the default gate they appear in the report's
**Verdicts** section, at the top, marked "no (comparison)", and in the CI job summary, but they never
fail the run. A regression in MicroProxy, such as an out-of-memory, a crash, or a fault that hangs or
leaks, does fail it.

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

The report opens with the **Verdicts** table, one row per proxy, scenario and subject, saying whether
each verdict gates the run. It ends with the harness's **self-checks**, which verify that the harness
worked rather than how well a proxy did (see [Self-checks, verdicts and the gate](#self-checks-verdicts-and-the-gate)).

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
# Open files, per shell. Raising the soft limit up to the hard one needs no privileges; going past
# the hard limit does (sudo prlimit, or /etc/security/limits.conf).
ulimit -n "$(ulimit -Hn)"
sudo prlimit --pid $$ --nofile=1048576:1048576 && ulimit -n 1048576

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

**When a limit cannot be raised.** On a hosted CI runner, or in a container without privileges,
`ulimit -n` cannot exceed the hard limit ("cannot modify limit: Operation not permitted"), and the
sysctls are read-only. That is fine for the smoke preset, which needs about 2,500 descriptors per
process. For the larger presets, the harness reads the limits in effect and prints them. The ramp
then stops gracefully at the first one it meets: when the load generator runs out of descriptors,
ports or heap, the report says `client-bound` and names the setting to raise, rather than counting
the limit against the proxy.

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
(the adversarial scenario, whose limit leaves the kernel's socket buffers out unless
`--attack-cgroup-sockets include`; see [socket buffers](#how-memory-growth-is-judged)); where no
writable cgroup is available the harness falls back to `-XX:MaxRAM` and notes it. The proxy's heap and direct-memory caps are `--proxy-heap`, `--proxy-direct`,
`--attack-heap` and `--attack-direct`.

**On a shared machine.** Other work on the same machine competes for the CPUs the harness pins its
processes to. Every sample records each CPU's busy time and the *foreign* CPU, the machine's busy
time beyond the proxy, origin and load generator, and the rate sweep reports it per step, so a run
shows when something else interfered. `--nice -20` runs the proxy, origin and load generator at that
nice value, and also sets the harness's scheduling autogroup to it: with autogroup scheduling (the
default of most Linux kernels) the CPU is first shared equally between sessions, so a per-process
nice value alone does not make other sessions yield. A single noisy step can still spike a step's
p99; `--sweep-knee-confirm 2` makes the knee the first of two unsustained steps in a row, so one
step that the next recovers from is recorded as unsustained but does not end the sweep.

**Knee refinement.** The sweep's steps multiply the rate (by 1.5, or 1.25 in the comparison runs),
so on their own they bracket the maximum sustainable rate only to within one step. Once the proxy
has made the knee, the sweep bisects between the last sustained step and the knee with up to
`--sweep-refine-steps` more recorded steps, judged by the same rules, until the bracket is within
`--sweep-refine-precision` (2%). Each probe follows `--sweep-refine-settle-seconds` of unrecorded
load at the bracket's lower rate, and an unsustained probe is repeated like a knee step (up to
`--sweep-knee-confirm` times in all). The results keep every probe (`refine.probes`), the refined
`maxSustainableRate`, its `maxSustainableBracket` and the unrefined `maxSustainableRateCoarse`.
Every step and probe also records the proxy's CPU time over it, read from `/proc`, and per
completed request (`proxy.cpuUsPerRequest`).

**On a big runner.** The [`loadtest.yml`](https://github.com/mahmoudimus/MicroProxy/blob/main/.github/workflows/loadtest.yml)
workflow runs on demand (`workflow_dispatch`) with inputs for the preset, the scenarios, the proxies,
the `runs-on` label (so a bigger or self-hosted runner can be chosen) and extra settings. It raises
`ulimit -n` and sets the sysctls it is allowed to (the ones above need privileges, which hosted
runners grant through `sudo` and self-hosted ones may not), runs the harness with the chosen `--gate`,
appends the report to the run summary and uploads the results directory. The [`ci.yml`](https://github.com/mahmoudimus/MicroProxy/blob/main/.github/workflows/ci.yml)
`loadtest-smoke` job runs the smoke preset on every push. It raises the open-file limit only as far
as the hard limit (which needs no privileges), prints the limits, and gates with `--gate microproxy`.
So it fails on a broken harness, or on a MicroProxy verdict such as an out-of-memory, a crash, or a
fault that hangs or leaks. It never fails on LittleProxy's verdicts, and it checks no latency or
throughput thresholds, since hosted runners are too noisy. The report, with its Verdicts table, is
added to the job summary.

## The LittleProxy baseline

The baseline is the maintained LittleProxy fork, pinned to **`io.github.littleproxy:littleproxy:2.9.1`**
(the latest on Maven Central), the same coordinates and version the [JMH benchmarks](benchmarks.md)
use, so both layers compare the same LittleProxy. It brings Netty 4.2.17.Final. The older
`xyz.rogfam:littleproxy` coordinates stop at 2.2.0 and `org.littleshoot:littleproxy` at 1.1.2; this
fork continues as `io.github.littleproxy` from 2.2.0 on. LittleProxy and Netty are confined to the
`loadtest` module.
