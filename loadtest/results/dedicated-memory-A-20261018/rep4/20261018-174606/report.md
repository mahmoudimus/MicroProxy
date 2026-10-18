# Load and capacity report: goproxy, g3proxy, squid, microproxy, littleproxy, envoy

- Preset: `standard`  Timestamp (UTC): `20261018-174606`
- Versions: goproxy `github.com/elazarl/goproxy v1.9.2 (go1.27.2)`, g3proxy `g3proxy 1.12.4`, squid `Squid Cache: Version 6.14`, microproxy `0.4.1-SNAPSHOT`, littleproxy `2.9.1`, envoy `/root/MicroProxy/loadtest/competitors/.tools/bin/envoy  version: 72315c132d462e5126e492ab2a71057565dbc87a/1.39.4/Clean/RELEASE/BoringSSL`
- CPU split (taskset): {proxy=1, origin=2, client=3,4,5,6,7,8}
- Host: Linux 7.0.0-1014-gcp amd64, Ubuntu 24.04.5 LTS, OpenJDK 64-Bit Server VM 25.0.4.1+1-LTS
- CPU: Intel(R) Xeon(R) Platinum 8481C CPU @ 2.70GHz; memory 88486.2 MB
- CPUs: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]; taskset present: true; cgroup: v2
- Limits: ulimit -n 1048576, somaxconn 65535, ip_local_port_range 15000 64999, tcp_tw_reuse 1
- External cross-check tools found: none

> Memory is reported as RSS and NMT committed total, with heap shown alongside: heap alone understates a Netty proxy's direct buffers and is not comparable to a virtual-thread proxy's heap-resident stacks. All results come from a single manual run; numbers are not published and depend on the machine and its tuning.

- Note: Ran at nice -20, with the harness's scheduling autogroup at nice -20.
- Harness self-checks: all passed
- Gate: `none`; gated verdicts failed: 0

## Verdicts

Judgements on each proxy under test, kept apart from the harness's own self-checks. **pass** and **FAIL** are verdicts; **inconclusive** means the window was too short to tell (the smoke preset's memory and soak windows are), and never fails a run; real verdicts come from the standard and full presets. Under the gate `none`, no verdict fails the run; only harness self-checks do.

| Proxy | Scenario | Subject | Verdict | Result | Gates the run | Detail |
|---|---|---|---|---|---|---|
| goproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 41.417 KB/s (R² 0.997, growth 1244.496 KB), NMT slope null KB/s (R² null); peak RSS 34 MB, peak NMT other (direct) 0 MB, peak soc… |
| goproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 10.502 KB/s (R² 0.992, growth 315.42 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak socke… |
| goproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 8.34 KB/s (R² 0.429, growth 277.711 KB), NMT slope null KB/s (R² null); peak RSS 16 MB, peak NMT other (direct) 0 MB, peak socket… |
| g3proxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 131.827 KB/s (R² 0.831, growth 3960.09 KB), NMT slope null KB/s (R² null); peak RSS 109 MB, peak NMT other (direct) 0 MB, peak so… |
| g3proxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 0.913 KB/s (R² 0.559, growth 27.429 KB), NMT slope null KB/s (R² null); peak RSS 38 MB, peak NMT other (direct) 0 MB, peak socket… |
| g3proxy | memory | updown | bounded | pass | no (comparison) | RSS slope 13.022 KB/s (R² 0.956, growth 392.545 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak sock… |
| squid | memory | slowloris | bounded | pass | no (comparison) | RSS slope 0.0 KB/s (R² 0.0, growth 0.0 KB), NMT slope null KB/s (R² null); peak RSS 182 MB, peak NMT other (direct) 0 MB, peak socket buffe… |
| squid | memory | slowread | bounded | pass | no (comparison) | RSS slope 335.658 KB/s (R² 0.628, growth 10079.131 KB), NMT slope null KB/s (R² null); peak RSS 259 MB, peak NMT other (direct) 0 MB, peak … |
| squid | memory | updown | bounded | pass | no (comparison) | RSS slope 7.356 KB/s (R² 0.82, growth 221.148 KB), NMT slope null KB/s (R² null); peak RSS 178 MB, peak NMT other (direct) 0 MB, peak socke… |
| microproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope -75.432 KB/s (R² 0.223, growth -2402.899 KB), NMT slope -459.086 KB/s (R² 0.401); peak RSS 114 MB, peak NMT other (direct) 0 MB, … |
| microproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 2.192 KB/s (R² 0.909, growth 69.43 KB), NMT slope 4.209 KB/s (R² 0.814); peak RSS 85 MB, peak NMT other (direct) 0 MB, peak socke… |
| microproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 203.462 KB/s (R² 0.477, growth 6469.885 KB), NMT slope 176.481 KB/s (R² 0.462); peak RSS 83 MB, peak NMT other (direct) 0 MB, pea… |
| littleproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 316.121 KB/s (R² 0.75, growth 10096.263 KB), NMT slope 81.492 KB/s (R² 0.111); peak RSS 111 MB, peak NMT other (direct) 0 MB, pea… |
| littleproxy | memory | slowread | shedding | pass | no (comparison) | closed by the proxy 55 of 200; peak RSS 285 MB, peak NMT other (direct) 110 MB, peak socket buffers 181 MB; probe 80/80 ok |
| littleproxy | memory | updown | oom | **FAIL** | no (comparison) | over the limit on its own memory (515 MB of 512 MB, socket buffers aside), killed; peak RSS 379 MB, peak NMT other (direct) 96 MB, peak soc… |
| envoy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 25.628 KB/s (R² 0.889, growth 769.726 KB), NMT slope null KB/s (R² null); peak RSS 106 MB, peak NMT other (direct) 0 MB, peak soc… |
| envoy | memory | slowread | bounded | pass | no (comparison) | RSS slope 0.714 KB/s (R² 0.953, growth 21.429 KB), NMT slope null KB/s (R² null); peak RSS 349 MB, peak NMT other (direct) 0 MB, peak socke… |
| envoy | memory | updown | bounded | pass | no (comparison) | RSS slope 131.217 KB/s (R² 0.839, growth 4056.693 KB), NMT slope null KB/s (R² null); peak RSS 131 MB, peak NMT other (direct) 0 MB, peak s… |

## Memory under adversarial clients

The proxy runs with its memory capped (small heap and direct-memory ceiling, plus a cgroup limit where available). Each workload runs while the harness samples memory; a normal client probes throughout. Verdicts: **bounded** (memory levels off) or **shedding** (the proxy closes or refuses the adversarial connections and stays up) pass; **unbounded-growth** (RSS or NMT total climbs steadily after the warm-up: a least-squares line with R² ≥ 0.8 along which it grows by more than 32 MB and a quarter of its mean), an out-of-memory or a crash fail. A rising peak alone is not growth: pooled buffers warm up and then stay flat. When too little of the window is left after the warm-up (10 s or a quarter of the workload) to tell, the verdict is **inconclusive**. NMT "other" is where direct (off-heap) buffers are counted; for the slow readers, "direct per reader" is that section's peak over the baseline, divided by the readers: what the proxy holds for each one.

| Workload | Proxy | Verdict | Result | Peak RSS MB | Peak NMT MB | Peak heap(GC) MB | Peak other MB | Direct per reader KB | Proxy end |
|---|---|---|---|---|---|---|---|---|---|
| slowloris | goproxy | bounded | pass | 34.0 | - | - | - | - | running |
| slowloris | g3proxy | bounded | pass | 109.4 | - | - | - | - | running |
| slowloris | squid | bounded | pass | 182.1 | - | - | - | - | running |
| slowloris | microproxy | bounded | pass | 114.1 | 154.0 | 23.1 | 0.1 | - | running |
| slowloris | littleproxy | bounded | pass | 111.7 | 112.3 | 15.7 | 0.8 | - | running |
| slowloris | envoy | bounded | pass | 106.5 | - | - | - | - | running |
| slowread | goproxy | bounded | pass | 28.1 | - | - | - | - | running |
| slowread | g3proxy | bounded | pass | 38.5 | - | - | - | - | running |
| slowread | squid | bounded | pass | 259.0 | - | - | - | - | running |
| slowread | microproxy | bounded | pass | 85.2 | 101.2 | 20.8 | 0.1 | 0 | running |
| slowread | littleproxy | shedding | pass | 285.8 | 227.0 | 10.2 | 111.0 | 566 | running |
| slowread | envoy | bounded | pass | 349.7 | - | - | - | - | running |
| updown | goproxy | bounded | pass | 16.6 | - | - | - | - | running |
| updown | g3proxy | bounded | pass | 28.7 | - | - | - | - | running |
| updown | squid | bounded | pass | 178.6 | - | - | - | - | running |
| updown | microproxy | bounded | pass | 84.0 | 85.9 | 4.9 | 0.1 | - | running |
| updown | littleproxy | oom | **FAIL** | 379.9 | 208.5 | 9.1 | 96.5 | - | oom |
| updown | envoy | bounded | pass | 131.7 | - | - | - | - | running |

## Harness self-checks

These verify the harness worked (each scenario ran, responses validated, metrics were sampled, the report was written), not how well a proxy did. Any failure here fails the run, whichever proxy it concerns.

| Proxy | Scenario | Check | OK | Detail |
|---|---|---|---|---|
| goproxy | memory | responses validate (status and length) | yes | all valid |
| goproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.058 s |
| goproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.106 s |
| goproxy | memory | updown ran and memory was sampled | yes | 8 samples over 38.857 s |
| goproxy | memory | at least one memory workload ran | yes | 3 workloads |
| goproxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| g3proxy | memory | responses validate (status and length) | yes | all valid |
| g3proxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.047 s |
| g3proxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.099 s |
| g3proxy | memory | updown ran and memory was sampled | yes | 8 samples over 35.231 s |
| g3proxy | memory | at least one memory workload ran | yes | 3 workloads |
| g3proxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| squid | memory | responses validate (status and length) | yes | all valid |
| squid | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.047 s |
| squid | memory | slowread ran and memory was sampled | yes | 8 samples over 35.101 s |
| squid | memory | updown ran and memory was sampled | yes | 8 samples over 35.143 s |
| squid | memory | at least one memory workload ran | yes | 3 workloads |
| squid | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| microproxy | memory | responses validate (status and length) | yes | all valid |
| microproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.198 s |
| microproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 37.014 s |
| microproxy | memory | updown ran and memory was sampled | yes | 7 samples over 38.719 s |
| microproxy | memory | at least one memory workload ran | yes | 3 workloads |
| microproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| littleproxy | memory | responses validate (status and length) | yes | all valid |
| littleproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.284 s |
| littleproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 37.208 s |
| littleproxy | memory | updown ran and memory was sampled | yes | 1 samples over 0.0 s |
| littleproxy | memory | at least one memory workload ran | yes | 3 workloads |
| littleproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| envoy | memory | responses validate (status and length) | yes | all valid |
| envoy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.044 s |
| envoy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.104 s |
| envoy | memory | updown ran and memory was sampled | yes | 8 samples over 36.14 s |
| envoy | memory | at least one memory workload ran | yes | 3 workloads |
| envoy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| all | report | JSON results and the Markdown report were written | yes | loadtest/results/dedicated-memory-A-20261018/rep4/20261018-174606/rep… |

