# GCP dedicated-core memory campaign, socket buffers beside the limit, 20261016, JDK 25

The memory scenario (slowloris, slowread and updown, 512 MB cgroup per proxy) for all six proxies, 5 repetitions, rerun on the
same machine as `gcp-20261016-jdk25/` with a harness that keeps the kernel's socket buffers out of the proxy's memory limit.
The follow-up in `gcp-20261016-followup/` showed that in the earlier campaign those buffers were charged to the proxy's cgroup.
That filled the cgroup under the slow-reader attack and made it OOM.
This campaign replaces that memory table: every proxy and workload here is measured with the same method.

## Commit

- Measured commit: **39aa8c5** (39aa8c54878b150b2dce8304e54ed23b73cf3c15, `fix(loadtest): keep the kernel's socket buffers out of the memory scenario's limit`).
  Relative to bfe751d it changes only `loadtest/` and `docs/`, so the MicroProxy source is the same as bfe751d. `run-info.json` records 39aa8c5 with no uncommitted loadtest changes.
- The harness was built with `mvn --batch-mode -q -Pbench -DskipTests package -pl loadtest -am` on JDK 25.

## Machine

- Google Cloud **c3-standard-22** with threads-per-core=1 (11 vCPUs, one per physical core), zone **us-central1-a**,
  Intel Xeon Platinum 8481C @ 2.70GHz, 86 GB. A dedicated VM, with nothing else running during the measurements.
- Ubuntu 24.04.5 LTS, kernel **7.0.0-1014-gcp**.
- JDK: Temurin **25.0.4.1** (pinned by bootstrap.sh), for the harness and the JVM proxies.
- CPU split: proxy **1**, origin **2**, load generator **3,4,5,6,7,8** (from bootstrap.sh's machine report, see `gcp-20261016-jdk25/README.md`).

## Kernel settings

- Before the run-all.sh call: `net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535 net.ipv4.tcp_tw_reuse=1
  fs.file-max=2097152 fs.nr_open=2097152 net.ipv4.ip_local_port_range="15000 64999"`, and `ulimit -n 1048576`.
- TCP buffers were left at the boot values (the VM had been restarted): `net.ipv4.tcp_rmem = 4096 131072 33554432`,
  `net.ipv4.tcp_wmem = 4096 16384 4194304`. Each results file records them under `environment.limits`.
  See `gcp-20261016-followup/tcp-sysctl.txt` for the other buffer settings.

## Command

From the repository root, with `CPUS_PROXY=1 CPUS_ORIGIN=2 CPUS_CLIENT=3,4,5,6,7,8` in the environment and JDK 25 on JAVA_HOME/PATH:

```
REPS=5 SCENARIOS=memory PUBLISH=0 OUT=<out> loadtest/competitors/run-all.sh
```

Each attack records `cap.socketBuffers = "beside the limit"` (settings `attack-cgroup-sockets: exclude`).
Before the campaign, a smoke run (`REPS=1 PROXIES=microproxy,g3proxy SCENARIOS=memory --attacks slowread`, not included here) confirmed that setting.
In that run both proxies came out bounded, with peak socket buffers of 563 MB (MicroProxy) and 521 MB (g3proxy).

## Results

Median of 5 runs. Peak socket buffers are the proxy cgroup's `sock` and are not counted against the 512 MB limit.
Probes are the harness's liveness requests during each attack, summed over the 5 runs.

| Workload | Proxy | Median peak RSS (MB) | Median peak socket buffers (MB) | Verdicts (5 runs) | Probes answered |
|---|---|---|---|---|---|
| slowloris | envoy | 100.0 | 0.1 | bounded ×5 | 400/400 |
| slowloris | g3proxy | 106.5 | 0.8 | bounded ×5 | 400/400 |
| slowloris | goproxy | 33.8 | 0.1 | bounded ×5 | 400/400 |
| slowloris | littleproxy | 112.4 | 3.0 | bounded ×5 | 400/400 |
| slowloris | microproxy | 129.1 | 4.8 | bounded ×5 | 400/400 |
| slowloris | squid | 181.8 | 0.0 | bounded ×5 | 400/400 |
| slowread | envoy | 360.1 | 572.4 | bounded ×5 | 400/400 |
| slowread | g3proxy | 35.5 | 520.5 | bounded ×5 | 400/400 |
| slowread | goproxy | 28.1 | 520.5 | bounded ×5 | 400/400 |
| slowread | littleproxy | 279.9 | 183.7 | bounded ×2, shedding ×3 | 400/400 |
| slowread | microproxy | 83.8 | 565.3 | bounded ×5 | 400/400 |
| slowread | squid | 259.1 | 354.3 | bounded ×5 | 400/400 |
| updown | envoy | 125.1 | 21.2 | bounded ×5 | 400/400 |
| updown | g3proxy | 25.5 | 4.2 | bounded ×5 | 400/400 |
| updown | goproxy | 16.4 | 18.5 | bounded ×5 | 400/400 |
| updown | littleproxy | 457.5 * | 7.9 | oom ×5 | 27/40 |
| updown | microproxy | 84.1 | 13.3 | bounded ×5 | 350/350 |
| updown | squid | 178.7 | 7.8 | bounded ×5 | 400/400 |

\* LittleProxy was OOM-killed in updown in every run, on its own memory ("over the limit on its own memory (513–534 MB of 512 MB, socket buffers aside)").
Its peak RSS was not recorded in 2 of the 5 runs, so the median is over the other 3 (407, 492 and 457 MB).
In 3 of 5 slowread runs, LittleProxy closed some readers itself (22, 26 and 52 of 200), which the harness reports as "shedding".
The verdicts per run are in each `rep*.json` under `results.memory.<proxy>.attacks[].judgement`.

## Contamination guard (aggregate.py)

<!-- perf:contamination -->

| Run (UTC start) | Foreign CPU, mean / p95 / max (% of one CPU) | Load average, mean / max | Busiest outside processes (mean CPU; kernel threads include some interrupt work) | Longest gap in the monitor's samples | Guard |
|---|---|---|---|---|---|
| 20261016-153422 | 8.4% / 68.5% / 147.5% | 0.95 / 2.19 | kernel thread 0.4%, python3 0.3%, agent session 0.2% | 5.5 s | accepted |
| 20261016-154722 | 5.7% / 22.6% / 152.3% | 1.06 / 2.66 | kernel thread 0.2% | 5.1 s | accepted |
| 20261016-160022 | 6.0% / 26.6% / 151.9% | 1.17 / 2.63 | none | 5.1 s | accepted |
| 20261016-161320 | 4.8% / 23.0% / 100.5% | 0.91 / 2.11 | kernel thread 1.0% | 5.1 s | accepted |
| 20261016-162620 | 4.7% / 18.1% / 113.7% | 0.78 / 1.90 | kernel thread 1.8%, agent session 0.2% | 5.1 s | accepted |

<!-- /perf:contamination -->

All five runs were accepted. The guard includes the 10 s limit on gaps in the host monitor's samples.

## Files

Raw files were written by `aggregate.py --publish`, which minifies them and reduces the monitor's command lines to program names.
The one path outside the repository (the scratch output directory in each run's report-file check) was made relative by hand, as `out/`.
`gc/` holds each run's MicroProxy and LittleProxy GC logs, named `<rep>-<timestamp>-<file>`.
