<!-- perf:scoreboard -->

| Median of the runs | MicroProxy | LittleProxy | Envoy | goproxy (Go) | g3proxy (Rust) | Squid |
|---|---|---|---|---|---|---|
| Peak RSS under slowloris (MB, 512 MB cap) | 109.6 | 115.0 | 106.5 | **33.9** | 106.6 | 182.0 |

<!-- /perf:scoreboard -->

<!-- perf:spread -->

| Lowest–highest run | MicroProxy | LittleProxy | Envoy | goproxy (Go) | g3proxy (Rust) | Squid |
|---|---|---|---|---|---|---|
| Peak RSS under slowloris (MB, 512 MB cap) | 107.2–116.7 | 112.7–115.4 | 106.2–107.4 | 33.8–33.9 | 106.4–106.8 | 182.0–182.2 |

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
| slowloris | MicroProxy | shedding | 109.6 | 26 | 4.3 | 100% | running |
| slowloris | LittleProxy | shedding | 115.0 | 19 | 0.6 | 100% | running |
| slowloris | Envoy | shedding | 106.5 | 20 | 1.9 | 100% | running |
| slowloris | goproxy (Go) | shedding | 33.9 | 13 | 0.0 | 100% | running |
| slowloris | g3proxy (Rust) | shedding | 106.6 | 42 | 0.9 | 100% | running |
| slowloris | Squid | shedding | 182.0 | 6 | 0.0 | 100% | running |

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
| 20261018-181509 | 4.0% / 12.2% / 32.0% | 0.10 / 0.48 | kernel thread 5.5%, process command line redacted 0.1% | 5.1 s | accepted |
| 20261018-182427 | 4.0% / 11.6% / 20.8% | 0.09 / 0.49 | kernel thread 5.8%, process command line redacted 0.1% | 5.1 s | accepted |
| 20261018-183345 | 3.9% / 11.0% / 30.0% | 0.22 / 1.75 | kernel thread 4.4% | 5.1 s | accepted |

<!-- /perf:contamination -->

<!-- perf:arch-slowread -->



<!-- /perf:arch-slowread -->

<!-- perf:machine -->

|  |  |
|---|---|
| CPU | Intel(R) Xeon(R) Platinum 8481C CPU @ 2.70GHz, 11 vCPUs |
| Memory | 88,486 MB |
| OS | Ubuntu 24.04.5 LTS, Linux 7.0.0-1014-gcp |
| JDK | OpenJDK 64-Bit Server VM 25.0.4.1+1-LTS |
| CPU split (taskset) | proxy 1, origin 2, client 3,4,5,6,7,8 |
| Runs | 3 (20261018-181509, 20261018-182427, 20261018-183345 UTC) |
| Harness commit | 471ba13a820bdb14d9ef4adbbd791b17760c0048 |

<!-- /perf:machine -->

