# Load and capacity report: g3proxy, squid, microproxy, littleproxy, envoy, goproxy

- Preset: `standard`  Timestamp (UTC): `20261018-175905`
- Versions: g3proxy `g3proxy 1.12.4`, squid `Squid Cache: Version 6.14`, microproxy `0.4.1-SNAPSHOT`, littleproxy `2.9.1`, envoy `/root/MicroProxy/loadtest/competitors/.tools/bin/envoy  version: 72315c132d462e5126e492ab2a71057565dbc87a/1.39.4/Clean/RELEASE/BoringSSL`, goproxy `github.com/elazarl/goproxy v1.9.2 (go1.27.2)`
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
| g3proxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 133.906 KB/s (R² 0.853, growth 4025.084 KB), NMT slope null KB/s (R² null); peak RSS 109 MB, peak NMT other (direct) 0 MB, peak s… |
| g3proxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 1.227 KB/s (R² 0.469, growth 36.855 KB), NMT slope null KB/s (R² null); peak RSS 38 MB, peak NMT other (direct) 0 MB, peak socket… |
| g3proxy | memory | updown | bounded | pass | no (comparison) | RSS slope 9.184 KB/s (R² 0.906, growth 276.865 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak socke… |
| squid | memory | slowloris | bounded | pass | no (comparison) | RSS slope 1.883 KB/s (R² 0.375, growth 56.571 KB), NMT slope null KB/s (R² null); peak RSS 182 MB, peak NMT other (direct) 0 MB, peak socke… |
| squid | memory | slowread | bounded | pass | no (comparison) | RSS slope 432.716 KB/s (R² 0.627, growth 12994.036 KB), NMT slope null KB/s (R² null); peak RSS 259 MB, peak NMT other (direct) 0 MB, peak … |
| squid | memory | updown | bounded | pass | no (comparison) | RSS slope 3.678 KB/s (R² 0.991, growth 110.569 KB), NMT slope null KB/s (R² null); peak RSS 178 MB, peak NMT other (direct) 0 MB, peak sock… |
| microproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope -51.938 KB/s (R² 0.073, growth -1651.828 KB), NMT slope -368.046 KB/s (R² 0.452); peak RSS 99 MB, peak NMT other (direct) 0 MB, p… |
| microproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 3.873 KB/s (R² 0.923, growth 122.579 KB), NMT slope 44.55 KB/s (R² 0.4); peak RSS 83 MB, peak NMT other (direct) 0 MB, peak socke… |
| microproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 134.973 KB/s (R² 0.514, growth 4370.028 KB), NMT slope -29.525 KB/s (R² 0.082); peak RSS 81 MB, peak NMT other (direct) 0 MB, pea… |
| littleproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 532.097 KB/s (R² 0.87, growth 16968.589 KB), NMT slope 173.028 KB/s (R² 0.289); peak RSS 113 MB, peak NMT other (direct) 0 MB, pe… |
| littleproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 16.44 KB/s (R² 0.861, growth 522.9 KB), NMT slope 17.794 KB/s (R² 0.674); peak RSS 259 MB, peak NMT other (direct) 88 MB, peak so… |
| littleproxy | memory | updown | oom | **FAIL** | no (comparison) | over the limit on its own memory (529 MB of 512 MB, socket buffers aside), killed; peak RSS 524 MB, peak NMT other (direct) 97 MB, peak soc… |
| envoy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 24.143 KB/s (R² 0.897, growth 725.122 KB), NMT slope null KB/s (R² null); peak RSS 104 MB, peak NMT other (direct) 0 MB, peak soc… |
| envoy | memory | slowread | bounded | pass | no (comparison) | RSS slope 0.485 KB/s (R² 0.951, growth 14.572 KB), NMT slope null KB/s (R² null); peak RSS 343 MB, peak NMT other (direct) 0 MB, peak socke… |
| envoy | memory | updown | bounded | pass | no (comparison) | RSS slope 67.036 KB/s (R² 0.641, growth 2069.995 KB), NMT slope null KB/s (R² null); peak RSS 127 MB, peak NMT other (direct) 0 MB, peak so… |
| goproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 41.384 KB/s (R² 0.998, growth 1242.842 KB), NMT slope null KB/s (R² null); peak RSS 33 MB, peak NMT other (direct) 0 MB, peak soc… |
| goproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 10.876 KB/s (R² 0.988, growth 326.57 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak socke… |
| goproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 14.168 KB/s (R² 0.858, growth 462.756 KB), NMT slope null KB/s (R² null); peak RSS 16 MB, peak NMT other (direct) 0 MB, peak sock… |

## Memory under adversarial clients

The proxy runs with its memory capped (small heap and direct-memory ceiling, plus a cgroup limit where available). Each workload runs while the harness samples memory; a normal client probes throughout. Verdicts: **bounded** (memory levels off) or **shedding** (the proxy closes or refuses the adversarial connections and stays up) pass; **unbounded-growth** (RSS or NMT total climbs steadily after the warm-up: a least-squares line with R² ≥ 0.8 along which it grows by more than 32 MB and a quarter of its mean), an out-of-memory or a crash fail. A rising peak alone is not growth: pooled buffers warm up and then stay flat. When too little of the window is left after the warm-up (10 s or a quarter of the workload) to tell, the verdict is **inconclusive**. NMT "other" is where direct (off-heap) buffers are counted; for the slow readers, "direct per reader" is that section's peak over the baseline, divided by the readers: what the proxy holds for each one.

| Workload | Proxy | Verdict | Result | Peak RSS MB | Peak NMT MB | Peak heap(GC) MB | Peak other MB | Direct per reader KB | Proxy end |
|---|---|---|---|---|---|---|---|---|---|
| slowloris | g3proxy | bounded | pass | 109.3 | - | - | - | - | running |
| slowloris | squid | bounded | pass | 182.3 | - | - | - | - | running |
| slowloris | microproxy | bounded | pass | 99.9 | 148.6 | 23.0 | 0.1 | - | running |
| slowloris | littleproxy | bounded | pass | 113.4 | 113.9 | 15.7 | 0.8 | - | running |
| slowloris | envoy | bounded | pass | 104.1 | - | - | - | - | running |
| slowloris | goproxy | bounded | pass | 33.9 | - | - | - | - | running |
| slowread | g3proxy | bounded | pass | 38.3 | - | - | - | - | running |
| slowread | squid | bounded | pass | 259.4 | - | - | - | - | running |
| slowread | microproxy | bounded | pass | 83.8 | 103.3 | 20.9 | 0.1 | 0 | running |
| slowread | littleproxy | bounded | pass | 259.5 | 202.0 | 9.8 | 89.0 | 454 | running |
| slowread | envoy | bounded | pass | 343.7 | - | - | - | - | running |
| slowread | goproxy | bounded | pass | 28.7 | - | - | - | - | running |
| updown | g3proxy | bounded | pass | 28.8 | - | - | - | - | running |
| updown | squid | bounded | pass | 178.9 | - | - | - | - | running |
| updown | microproxy | bounded | pass | 81.1 | 80.0 | 4.7 | 0.1 | - | running |
| updown | littleproxy | oom | **FAIL** | 524.9 | 212.8 | 10.4 | 97.9 | - | oom |
| updown | envoy | bounded | pass | 127.2 | - | - | - | - | running |
| updown | goproxy | bounded | pass | 16.7 | - | - | - | - | running |

## Harness self-checks

These verify the harness worked (each scenario ran, responses validated, metrics were sampled, the report was written), not how well a proxy did. Any failure here fails the run, whichever proxy it concerns.

| Proxy | Scenario | Check | OK | Detail |
|---|---|---|---|---|
| g3proxy | memory | responses validate (status and length) | yes | all valid |
| g3proxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.069 s |
| g3proxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.115 s |
| g3proxy | memory | updown ran and memory was sampled | yes | 8 samples over 35.23 s |
| g3proxy | memory | at least one memory workload ran | yes | 3 workloads |
| g3proxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| squid | memory | responses validate (status and length) | yes | all valid |
| squid | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.048 s |
| squid | memory | slowread ran and memory was sampled | yes | 8 samples over 35.103 s |
| squid | memory | updown ran and memory was sampled | yes | 8 samples over 35.143 s |
| squid | memory | at least one memory workload ran | yes | 3 workloads |
| squid | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| microproxy | memory | responses validate (status and length) | yes | all valid |
| microproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.139 s |
| microproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 36.996 s |
| microproxy | memory | updown ran and memory was sampled | yes | 7 samples over 39.29 s |
| microproxy | memory | at least one memory workload ran | yes | 3 workloads |
| microproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| littleproxy | memory | responses validate (status and length) | yes | all valid |
| littleproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.214 s |
| littleproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 37.176 s |
| littleproxy | memory | updown ran and memory was sampled | yes | 3 samples over 12.794 s |
| littleproxy | memory | at least one memory workload ran | yes | 3 workloads |
| littleproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| envoy | memory | responses validate (status and length) | yes | all valid |
| envoy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.043 s |
| envoy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.105 s |
| envoy | memory | updown ran and memory was sampled | yes | 8 samples over 36.09 s |
| envoy | memory | at least one memory workload ran | yes | 3 workloads |
| envoy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| goproxy | memory | responses validate (status and length) | yes | all valid |
| goproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.041 s |
| goproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.099 s |
| goproxy | memory | updown ran and memory was sampled | yes | 8 samples over 38.083 s |
| goproxy | memory | at least one memory workload ran | yes | 3 workloads |
| goproxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| all | report | JSON results and the Markdown report were written | yes | loadtest/results/dedicated-memory-A-20261018/rep5/20261018-175905/rep… |

