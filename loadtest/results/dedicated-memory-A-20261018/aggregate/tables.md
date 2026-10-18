<!-- perf:scoreboard -->

| Median of the runs | MicroProxy | LittleProxy | Envoy | goproxy (Go) | g3proxy (Rust) | Squid |
|---|---|---|---|---|---|---|
| Peak RSS under slowloris (MB, 512 MB cap) | 102.1 | 113.4 | 105.8 | **34.0** | 109.6 | 182.1 |
| RSS per slow reader, 200 readers (KB) | 151 | 1,044 | 1,458 | 101 | **76** | 466 |
| Peak RSS under slow readers (MB, 512 MB cap) | 84.9 | 270.9 | 349.7 | **28.3** | 38.5 | 259.2 |
| Peak RSS under parallel large uploads and downloads (MB, 512 MB cap) | 81.1 | 511.7 | 129.7 | **16.6** | 28.6 | 178.9 |

<!-- /perf:scoreboard -->

<!-- perf:spread -->

| Lowest–highest run | MicroProxy | LittleProxy | Envoy | goproxy (Go) | g3proxy (Rust) | Squid |
|---|---|---|---|---|---|---|
| Peak RSS under slowloris (MB, 512 MB cap) | 99.9–114.1 | 109.1–122.7 | 104.1–106.5 | 33.8–34.1 | 109.3–109.7 | 182.0–182.3 |
| RSS per slow reader, 200 readers (KB) | 146–155 | 985–1,120 | 1,429–1,593 | 99–103 | 75–77 | 465–467 |
| Peak RSS under slow readers (MB, 512 MB cap) | 83.8–85.8 | 259.5–285.8 | 341.0–376.1 | 28.0–28.7 | 37.2–38.5 | 259.0–259.4 |
| Peak RSS under parallel large uploads and downloads (MB, 512 MB cap) | 80.8–84.0 | 379.9–524.9 | 126.8–131.7 | 16.6–17.0 | 28.4–28.8 | 178.6–179.0 |

<!-- /perf:spread -->

<!-- perf:sweep -->

| Proxy | Max sustainable rate (req/s) | Known to within | CPU per request (µs) | p99 (ms) | Why the knee came |
|---|---|---|---|---|---|
| MicroProxy | n/a | n/a | n/a | n/a | not reached |
| LittleProxy | n/a | n/a | n/a | n/a | not reached |
| Envoy | n/a | n/a | n/a | n/a | not reached |
| goproxy (Go) | n/a | n/a | n/a | n/a | not reached |
| g3proxy (Rust) | n/a | n/a | n/a | n/a | not reached |
| Squid | n/a | n/a | n/a | n/a | not reached |

<!-- /perf:sweep -->

<!-- perf:cpu -->

| Offered req/s | MicroProxy | LittleProxy | Envoy | goproxy (Go) | g3proxy (Rust) | Squid |
|---|---|---|---|---|---|---|

<!-- /perf:cpu -->

<!-- perf:latency -->

| Offered req/s | MicroProxy | LittleProxy | Envoy | goproxy (Go) | g3proxy (Rust) | Squid |
|---|---|---|---|---|---|---|

<!-- /perf:latency -->

<!-- perf:ramp -->

| Proxy | Idle RSS (MB) | RSS per idle connection (KB) | Connections held | Ramp ended |
|---|---|---|---|---|
| MicroProxy | n/a | n/a | n/a | n/a |
| LittleProxy | n/a | n/a | n/a | n/a |
| Envoy | n/a | n/a | n/a | n/a |
| goproxy (Go) | n/a | n/a | n/a | n/a |
| g3proxy (Rust) | n/a | n/a | n/a | n/a |
| Squid | n/a | n/a | n/a | n/a |

<!-- /perf:ramp -->

<!-- perf:memory -->

| Workload | Proxy | Verdict | Peak RSS (MB) | RSS per connection (KB) | Kernel socket buffers, peak (MB) | Honest probes answered | Proxy at the end |
|---|---|---|---|---|---|---|---|
| slowloris | MicroProxy | bounded | 102.1 | 22 | 4.4 | 100% | running |
| slowloris | LittleProxy | bounded | 113.4 | 19 | 2.2 | 100% | running |
| slowloris | Envoy | bounded | 105.8 | 20 | 0.5 | 100% | running |
| slowloris | goproxy (Go) | bounded | 34.0 | 13 | 0.1 | 100% | running |
| slowloris | g3proxy (Rust) | bounded | 109.6 | 43 | 1.0 | 100% | running |
| slowloris | Squid | bounded | 182.1 | 6 | 0.0 | 100% | running |
| slowread | MicroProxy | bounded | 84.9 | 151 | 563.9 | 100% | running |
| slowread | LittleProxy | bounded ×3, shedding ×2 | 270.9 | 1,044 | 178.8 | 100% | running |
| slowread | Envoy | bounded | 349.7 | 1,458 | 571.2 | 100% | running |
| slowread | goproxy (Go) | bounded | 28.3 | 101 | 520.0 | 100% | running |
| slowread | g3proxy (Rust) | bounded | 38.5 | 76 | 520.5 | 100% | running |
| slowread | Squid | bounded | 259.2 | 466 | 354.4 | 100% | running |
| updown | MicroProxy | bounded | 81.1 | 829 | 18.3 | 100% | running |
| updown | LittleProxy | oom | 511.7 | 14,228 | 7.0 | 97% | oom |
| updown | Envoy | bounded | 129.7 | 2,075 | 21.7 | 100% | running |
| updown | goproxy (Go) | bounded | 16.6 | 257 | 21.8 | 100% | running |
| updown | g3proxy (Rust) | bounded | 28.6 | 148 | 4.6 | 100% | running |
| updown | Squid | bounded | 178.9 | 343 | 7.5 | 100% | running |

<!-- /perf:memory -->

<!-- perf:soak -->

| Proxy | Leak verdict | RSS slope (KB/hour) | Median per-window p99 (ms) | Errors |
|---|---|---|---|---|
| MicroProxy | n/a | n/a | n/a | n/a |
| LittleProxy | n/a | n/a | n/a | n/a |
| Envoy | n/a | n/a | n/a | n/a |
| goproxy (Go) | n/a | n/a | n/a | n/a |
| g3proxy (Rust) | n/a | n/a | n/a | n/a |
| Squid | n/a | n/a | n/a | n/a |

<!-- /perf:soak -->

<!-- perf:faults -->

| Fault | MicroProxy | LittleProxy | Envoy | goproxy (Go) | g3proxy (Rust) | Squid |
|---|---|---|---|---|---|---|

<!-- /perf:faults -->

<!-- perf:versions -->

| Proxy | Language | Version | Command line (sweep run) |
|---|---|---|---|
| MicroProxy | Java (virtual threads) | MicroProxy 0.4.1-SNAPSHOT (this repository at 471ba13) | `n/a` |
| LittleProxy | Java (Netty) | io.github.littleproxy:littleproxy 2.9.1 | `n/a` |
| Envoy | C++ | Envoy 1.39.4 | `n/a` |
| goproxy (Go) | Go | github.com/elazarl/goproxy v1.9.2 (go1.27.2) | `n/a` |
| g3proxy (Rust) | Rust | g3proxy 1.12.4 | `n/a` |
| Squid | C++ | Squid Cache: Version 6.14 | `n/a` |

<!-- /perf:versions -->

<!-- perf:contamination -->

| Run (UTC start) | Foreign CPU, mean / p95 / max (% of one CPU) | Load average, mean / max | Busiest outside processes (mean CPU; kernel threads include some interrupt work) | Longest gap in the monitor's samples | Guard |
|---|---|---|---|---|---|
| 20261018-170711 | 5.0% / 22.0% / 102.7% | 1.07 / 3.44 | kernel thread 4.6%, process command line redacted 0.2% | 5.1 s | accepted |
| 20261018-172010 | 5.0% / 22.6% / 125.7% | 0.97 / 2.28 | kernel thread 2.2% | 5.1 s | accepted |
| 20261018-173308 | 4.0% / 11.6% / 84.6% | 1.11 / 2.85 | kernel thread 1.4% | 5.1 s | accepted |
| 20261018-174606 | 3.8% / 20.4% / 49.1% | 0.83 / 2.00 | kernel thread 3.0% | 5.1 s | accepted |
| 20261018-175905 | 4.1% / 17.8% / 121.2% | 0.88 / 2.46 | kernel thread 3.6% | 5.1 s | accepted |

<!-- /perf:contamination -->

<!-- perf:arch-slowread -->

Measured with 200 slow readers and each proxy capped at 512 MB, RSS rose by about 1,044 (985–1,120) KB per reader for LittleProxy and 151 (146–155) KB for MicroProxy (median of 5 runs, lowest–highest in parentheses).

<!-- /perf:arch-slowread -->

<!-- perf:machine -->

|  |  |
|---|---|
| CPU | Intel(R) Xeon(R) Platinum 8481C CPU @ 2.70GHz, 11 vCPUs |
| Memory | 88,486 MB |
| OS | Ubuntu 24.04.5 LTS, Linux 7.0.0-1014-gcp |
| JDK | OpenJDK 64-Bit Server VM 25.0.4.1+1-LTS |
| CPU split (taskset) | proxy 1, origin 2, client 3,4,5,6,7,8 |
| Runs | 5 (20261018-170711, 20261018-172010, 20261018-173308, 20261018-174606, 20261018-175905 UTC) |
| Harness commit | 471ba13a820bdb14d9ef4adbbd791b17760c0048 |

<!-- /perf:machine -->

