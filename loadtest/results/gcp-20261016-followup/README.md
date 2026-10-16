# GCP dedicated-core follow-up, 20261016, JDK 25

Follow-up runs on the same machine and checkout as `gcp-20261016-jdk25/`. Two questions:
why the memory scenario's slow-reader attack ends in "oom" for most proxies, and whether the
single-core origin limits the rate sweep. The harness and MicroProxy source were not changed.

## Machine and settings

- Google Cloud **c3-standard-22** with threads-per-core=1 (11 vCPUs, one per physical core), zone **us-central1-a**.
- Ubuntu 24.04.5 LTS, kernel **7.0.0-1014-gcp**. A dedicated VM, with nothing else running during the measurements.
- JDK: Temurin **25.0.4.1** (pinned by bootstrap.sh), for the harness and the JVM proxies.
- Measured commit: **bfe751d** (bfe751dcc0e4ec03b669031c7e9c782607906270). `run-info.json` records
  7a584c1, the head of this branch at the time of the runs: bfe751d plus only the results commit, so the measured source is the same.
- Before every run-all.sh call: `net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535 net.ipv4.tcp_tw_reuse=1
  fs.file-max=2097152 fs.nr_open=2097152 net.ipv4.ip_local_port_range="15000 64999"`, and `ulimit -n 1048576`.
- TCP buffers: see `tcp-sysctl.txt`. The boot values are
  `net.ipv4.tcp_rmem = 4096 131072 33554432`, `net.ipv4.tcp_wmem = 4096 16384 4194304`,
  `net.ipv4.tcp_mem = 1058943 1411927 2117886`, `net.core.rmem_max = net.core.wmem_max = 4194304`,
  `net.core.rmem_default = net.core.wmem_default = 212992`, `net.ipv4.tcp_moderate_rcvbuf = 1`.
  No file under /etc/sysctl.conf, /etc/sysctl.d or /usr/lib/sysctl.d sets them, so the 32 MiB tcp_rmem maximum is the kernel's own default.
  The cgroup v2 root has the `memory` controller.

## Runs

| Directory | What it tests | CPU split (proxy / origin / load generator) | TCP buffers |
|---|---|---|---|
| `slowread-default-microproxy/`, `slowread-default-g3proxy/` | memory scenario, slow-reader attack only (`--attacks slowread`), 1 rep, 512 MB cgroup | 1 / 2 / 3-8 | boot values (tcp_rmem max 33554432) |
| `slowread-linuxdefault-microproxy/`, `slowread-linuxdefault-g3proxy/` | the same, with the upstream Linux default buffers | 1 / 2 / 3-8 | `net.ipv4.tcp_rmem="4096 131072 6291456" net.ipv4.tcp_wmem="4096 16384 4194304"` |
| `sweep-origin2/` | rate sweep, 3 reps, microproxy, g3proxy, littleproxy, with the origin on two cores | 1 / **2,9** / 3-8 | boot values |

Commands (from the repository root):

```
REPS=1 PROXIES=<proxy> SCENARIOS=memory PUBLISH=0 OUT=<out> loadtest/competitors/run-all.sh --attacks slowread
CPUS_PROXY=1 CPUS_ORIGIN=2,9 CPUS_CLIENT=3,4,5,6,7,8 REPS=3 PROXIES=microproxy,g3proxy,littleproxy SCENARIOS=sweep PUBLISH=0 OUT=<out> loadtest/competitors/run-all.sh
```

The slow-reader runs used CPUS_PROXY=1 CPUS_ORIGIN=2 CPUS_CLIENT=3,4,5,6,7,8 from the environment.
After the linuxdefault runs the boot values were restored (`tcp_rmem 4096 131072 33554432`) before the sweep.
The full memory scenario with default buffers (all six proxies, 3 reps) was not run: it was conditional on the OOMs going away, and they did not.

`slowread-memstat-<proxy>.log` (boot buffers) and `slowread-linuxdefault-memstat-<proxy>.log` were written by a watcher that,
every 0.2 s, printed the `anon`, `file`, `sock`, `kernel`, `kernel_stack` and `percpu` lines of the proxy cgroup's memory.stat and the whole of memory.events.
Values are in bytes.

## Findings

### Slow reader: socket buffers are charged to the proxy's cgroup

Last sample before the first `oom_kill` (or the run's peak, if none):

| Run | sock | anon | Result | memory.events at end |
|---|---|---|---|---|
| microproxy, boot buffers | 292.4 MiB (0 -> 33.2 -> 292.4 in 0.4 s; 400.9 MiB in the first sample after the kill) | 50.4 MiB | oom about 1.4 s after the cgroup appeared | max 89, oom 2, oom_kill 1 |
| g3proxy, boot buffers | 492.9 MiB peak, held at 491-493 MiB for the whole attack | 17.3 MiB | **bounded** (no OOM kill), peak RSS 32 MB | max 21967, oom 0, oom_kill 0 |
| microproxy, Linux default buffers | 362.3 MiB | 56.1 MiB | oom about 1.4 s after the cgroup appeared | max 89, oom 1, oom_kill 1, sock_throttled 43 |
| g3proxy, Linux default buffers | 375.5 MiB | 16.0 MiB | oom about 0.6 s after the cgroup appeared | max 82, oom 1, oom_kill 1 |

`sock` makes up most of the cgroup's usage in every run, and the process memory (`anon`) stays at 16-56 MiB, so the hypothesis holds:
kernel socket buffers are charged to the proxy's 512 MB cgroup, and they fill it.
Lowering tcp_rmem's maximum to the Linux default (6 MiB) did not prevent the OOM. Socket memory still reached 362-376 MiB within about 1 s, and the cgroup hit its limit.
In the campaign g3proxy was killed in all 5 repetitions. Here, alone and with boot buffers, it stayed just under the limit for the whole 40 s attack (memory.max hit 21,967 times) and was not killed, so its outcome is marginal.

### Sweep with a two-core origin

Max sustainable rate (req/s), with the proxy's and origin's CPU % (100% is one core) at the last sustained coarse step (45,475/s; LittleProxy 29,104 or 36,380/s) and the step after it:

| Proxy | rep1 | rep2 | rep3 | proxy CPU (last / next) | origin CPU (last / next) | Campaign, one-core origin (5 reps) |
|---|---|---|---|---|---|---|
| microproxy | 48,728 | 49,167 | 49,419 | 98.0-98.3% / 98.4-100.0% | 126.8-129.3% / 124.5-126.2% | 48,592-49,434, origin 92.8-93.9% / 94.5-97.3% |
| g3proxy | 48,607 | 48,600 | 48,083 | 97.8-97.9% / 99.4-99.7% | 126.7-127.7% / 131.0-132.7% | 49,971-50,606, origin 92.5-93.9% / 96.9-97.7% |
| littleproxy | 35,868 | 36,883 | 35,857 | 98.7-99.0% / 98.5-99.0% | 72.5-80.9% / 67.9-70.8% | 35,872-37,398 |

With a second core the origin has headroom (about 127-133% of 200%), but no maximum went up:
MicroProxy's is unchanged, and g3proxy's is about 3% lower. The proxy's own core is at 98-100% at the knee in every run.
So the sweep's knee is the proxy's single core, not the origin.

## Contamination guard and host-monitor coverage

Every run was accepted by aggregate.py's guard (no `--allow-unguarded`), and the largest gap between hostmon.jsonl samples within each run's [timestamp, finished], edges included, is at most 5.8 s (limit 10 s).

| Run | Foreign CPU, mean / p95 / max (% of one CPU) | Load average, mean / max | Guard | Largest hostmon gap |
|---|---|---|---|---|
| slowread-default-microproxy 20261016-034912 | 34.6% / 34.6% / 34.6% | 0.20 / 0.20 | accepted | 5.2 s |
| slowread-default-g3proxy 20261016-034920 | 7.5% / 10.8% / 10.8% | 0.40 / 0.49 | accepted | 5.2 s |
| slowread-linuxdefault-microproxy 20261016-035025 | 37.7% / 37.7% / 37.7% | 0.29 / 0.29 | accepted | 5.8 s |
| slowread-linuxdefault-g3proxy 20261016-035033 | 11.5% / 11.5% / 11.5% | 0.25 / 0.25 | accepted | 5.5 s |
| sweep-origin2 rep1 20261016-035049 | 5.1% / 55.8% / 128.1% | 3.08 / 11.75 | accepted | 5.8 s |
| sweep-origin2 rep2 20261016-040110 | 5.0% / 34.6% / 222.3% | 6.00 / 14.77 | accepted | 5.1 s |
| sweep-origin2 rep3 20261016-041208 | 3.5% / 28.4% / 127.2% | 4.84 / 13.24 | accepted | 5.1 s |

The slow-reader runs last under 10 s when the proxy is killed, so their guard figures come from one or two monitor samples.

## Publishing

Raw files were written by `aggregate.py --publish`, which minifies them and reduces the monitor's command lines to program names.
Paths to the scratch output directory were then made relative by hand (it became `out/`).
`gc/` holds each run's MicroProxy and LittleProxy GC logs, named `<rep>-<timestamp>-<file>`.
