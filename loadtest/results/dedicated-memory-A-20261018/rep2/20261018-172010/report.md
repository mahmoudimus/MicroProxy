# Load and capacity report: littleproxy, envoy, goproxy, g3proxy, squid, microproxy

- Preset: `standard`  Timestamp (UTC): `20261018-172010`
- Versions: littleproxy `2.9.1`, envoy `/root/MicroProxy/loadtest/competitors/.tools/bin/envoy  version: 72315c132d462e5126e492ab2a71057565dbc87a/1.39.4/Clean/RELEASE/BoringSSL`, goproxy `github.com/elazarl/goproxy v1.9.2 (go1.27.2)`, g3proxy `g3proxy 1.12.4`, squid `Squid Cache: Version 6.14`, microproxy `0.4.1-SNAPSHOT`
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
| littleproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 512.637 KB/s (R² 0.483, growth 16353.106 KB), NMT slope -75.378 KB/s (R² 0.028); peak RSS 122 MB, peak NMT other (direct) 0 MB, p… |
| littleproxy | memory | slowread | shedding | pass | no (comparison) | closed by the proxy 49 of 200; peak RSS 275 MB, peak NMT other (direct) 107 MB, peak socket buffers 184 MB; probe 80/80 ok |
| littleproxy | memory | updown | oom | **FAIL** | no (comparison) | over the limit on its own memory (531 MB of 512 MB, socket buffers aside), killed; peak RSS 520 MB, peak NMT other (direct) 84 MB, peak soc… |
| envoy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 24.826 KB/s (R² 0.9, growth 745.738 KB), NMT slope null KB/s (R² null); peak RSS 105 MB, peak NMT other (direct) 0 MB, peak socke… |
| envoy | memory | slowread | bounded | pass | no (comparison) | RSS slope 0.656 KB/s (R² 0.972, growth 19.715 KB), NMT slope null KB/s (R² null); peak RSS 340 MB, peak NMT other (direct) 0 MB, peak socke… |
| envoy | memory | updown | bounded | pass | no (comparison) | RSS slope 86.625 KB/s (R² 0.754, growth 2676.101 KB), NMT slope null KB/s (R² null); peak RSS 129 MB, peak NMT other (direct) 0 MB, peak so… |
| goproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 42.944 KB/s (R² 0.999, growth 1289.982 KB), NMT slope null KB/s (R² null); peak RSS 33 MB, peak NMT other (direct) 0 MB, peak soc… |
| goproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 10.474 KB/s (R² 0.985, growth 314.591 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak sock… |
| goproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 10.938 KB/s (R² 0.224, growth 360.657 KB), NMT slope null KB/s (R² null); peak RSS 16 MB, peak NMT other (direct) 0 MB, peak sock… |
| g3proxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 136.266 KB/s (R² 0.877, growth 4092.764 KB), NMT slope null KB/s (R² null); peak RSS 109 MB, peak NMT other (direct) 0 MB, peak s… |
| g3proxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 0.4 KB/s (R² 0.645, growth 12.0 KB), NMT slope null KB/s (R² null); peak RSS 38 MB, peak NMT other (direct) 0 MB, peak socket buf… |
| g3proxy | memory | updown | bounded | pass | no (comparison) | RSS slope 14.872 KB/s (R² 0.925, growth 448.335 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak sock… |
| squid | memory | slowloris | bounded | pass | no (comparison) | RSS slope 0.171 KB/s (R² 0.75, growth 5.143 KB), NMT slope null KB/s (R² null); peak RSS 182 MB, peak NMT other (direct) 0 MB, peak socket … |
| squid | memory | slowread | bounded | pass | no (comparison) | RSS slope 360.648 KB/s (R² 0.627, growth 10829.888 KB), NMT slope null KB/s (R² null); peak RSS 259 MB, peak NMT other (direct) 0 MB, peak … |
| squid | memory | updown | bounded | pass | no (comparison) | RSS slope 4.704 KB/s (R² 0.875, growth 141.429 KB), NMT slope null KB/s (R² null); peak RSS 178 MB, peak NMT other (direct) 0 MB, peak sock… |
| microproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope -16.259 KB/s (R² 0.012, growth -517.872 KB), NMT slope -292.656 KB/s (R² 0.497); peak RSS 101 MB, peak NMT other (direct) 0 MB, p… |
| microproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 3.03 KB/s (R² 0.883, growth 95.993 KB), NMT slope 3.314 KB/s (R² 0.804); peak RSS 84 MB, peak NMT other (direct) 0 MB, peak socke… |
| microproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 92.516 KB/s (R² 0.569, growth 2932.748 KB), NMT slope -49.67 KB/s (R² 0.078); peak RSS 81 MB, peak NMT other (direct) 0 MB, peak … |

## Memory under adversarial clients

The proxy runs with its memory capped (small heap and direct-memory ceiling, plus a cgroup limit where available). Each workload runs while the harness samples memory; a normal client probes throughout. Verdicts: **bounded** (memory levels off) or **shedding** (the proxy closes or refuses the adversarial connections and stays up) pass; **unbounded-growth** (RSS or NMT total climbs steadily after the warm-up: a least-squares line with R² ≥ 0.8 along which it grows by more than 32 MB and a quarter of its mean), an out-of-memory or a crash fail. A rising peak alone is not growth: pooled buffers warm up and then stay flat. When too little of the window is left after the warm-up (10 s or a quarter of the workload) to tell, the verdict is **inconclusive**. NMT "other" is where direct (off-heap) buffers are counted; for the slow readers, "direct per reader" is that section's peak over the baseline, divided by the readers: what the proxy holds for each one.

| Workload | Proxy | Verdict | Result | Peak RSS MB | Peak NMT MB | Peak heap(GC) MB | Peak other MB | Direct per reader KB | Proxy end |
|---|---|---|---|---|---|---|---|---|---|
| slowloris | littleproxy | bounded | pass | 122.7 | 120.7 | 15.7 | 0.8 | - | running |
| slowloris | envoy | bounded | pass | 105.9 | - | - | - | - | running |
| slowloris | goproxy | bounded | pass | 33.8 | - | - | - | - | running |
| slowloris | g3proxy | bounded | pass | 109.7 | - | - | - | - | running |
| slowloris | squid | bounded | pass | 182.1 | - | - | - | - | running |
| slowloris | microproxy | bounded | pass | 101.3 | 145.0 | 20.8 | 0.1 | - | running |
| slowread | littleproxy | shedding | pass | 275.6 | 223.9 | 10.3 | 107.6 | 549 | running |
| slowread | envoy | bounded | pass | 341.0 | - | - | - | - | running |
| slowread | goproxy | bounded | pass | 28.3 | - | - | - | - | running |
| slowread | g3proxy | bounded | pass | 38.5 | - | - | - | - | running |
| slowread | squid | bounded | pass | 259.2 | - | - | - | - | running |
| slowread | microproxy | bounded | pass | 84.9 | 101.3 | 20.8 | 0.1 | 0 | running |
| updown | littleproxy | oom | **FAIL** | 520.9 | 209.0 | 9.3 | 84.4 | - | oom |
| updown | envoy | bounded | pass | 129.7 | - | - | - | - | running |
| updown | goproxy | bounded | pass | 17.0 | - | - | - | - | running |
| updown | g3proxy | bounded | pass | 28.4 | - | - | - | - | running |
| updown | squid | bounded | pass | 178.9 | - | - | - | - | running |
| updown | microproxy | bounded | pass | 81.1 | 83.3 | 4.8 | 0.1 | - | running |

## Harness self-checks

These verify the harness worked (each scenario ran, responses validated, metrics were sampled, the report was written), not how well a proxy did. Any failure here fails the run, whichever proxy it concerns.

| Proxy | Scenario | Check | OK | Detail |
|---|---|---|---|---|
| littleproxy | memory | responses validate (status and length) | yes | all valid |
| littleproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.243 s |
| littleproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 37.153 s |
| littleproxy | memory | updown ran and memory was sampled | yes | 1 samples over 0.0 s |
| littleproxy | memory | at least one memory workload ran | yes | 3 workloads |
| littleproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| envoy | memory | responses validate (status and length) | yes | all valid |
| envoy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.047 s |
| envoy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.108 s |
| envoy | memory | updown ran and memory was sampled | yes | 8 samples over 36.128 s |
| envoy | memory | at least one memory workload ran | yes | 3 workloads |
| envoy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| goproxy | memory | responses validate (status and length) | yes | all valid |
| goproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.051 s |
| goproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.109 s |
| goproxy | memory | updown ran and memory was sampled | yes | 8 samples over 38.446 s |
| goproxy | memory | at least one memory workload ran | yes | 3 workloads |
| goproxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| g3proxy | memory | responses validate (status and length) | yes | all valid |
| g3proxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.045 s |
| g3proxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.101 s |
| g3proxy | memory | updown ran and memory was sampled | yes | 8 samples over 35.23 s |
| g3proxy | memory | at least one memory workload ran | yes | 3 workloads |
| g3proxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| squid | memory | responses validate (status and length) | yes | all valid |
| squid | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.042 s |
| squid | memory | slowread ran and memory was sampled | yes | 8 samples over 35.102 s |
| squid | memory | updown ran and memory was sampled | yes | 8 samples over 35.142 s |
| squid | memory | at least one memory workload ran | yes | 3 workloads |
| squid | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| microproxy | memory | responses validate (status and length) | yes | all valid |
| microproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.202 s |
| microproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 37.036 s |
| microproxy | memory | updown ran and memory was sampled | yes | 7 samples over 38.154 s |
| microproxy | memory | at least one memory workload ran | yes | 3 workloads |
| microproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| all | report | JSON results and the Markdown report were written | yes | loadtest/results/dedicated-memory-A-20261018/rep2/20261018-172010/rep… |

