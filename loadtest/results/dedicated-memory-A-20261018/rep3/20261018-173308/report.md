# Load and capacity report: envoy, goproxy, g3proxy, squid, microproxy, littleproxy

- Preset: `standard`  Timestamp (UTC): `20261018-173308`
- Versions: envoy `/root/MicroProxy/loadtest/competitors/.tools/bin/envoy  version: 72315c132d462e5126e492ab2a71057565dbc87a/1.39.4/Clean/RELEASE/BoringSSL`, goproxy `github.com/elazarl/goproxy v1.9.2 (go1.27.2)`, g3proxy `g3proxy 1.12.4`, squid `Squid Cache: Version 6.14`, microproxy `0.4.1-SNAPSHOT`, littleproxy `2.9.1`
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
| envoy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 23.446 KB/s (R² 0.906, growth 704.546 KB), NMT slope null KB/s (R² null); peak RSS 105 MB, peak NMT other (direct) 0 MB, peak soc… |
| envoy | memory | slowread | bounded | pass | no (comparison) | RSS slope 0.571 KB/s (R² 0.893, growth 17.142 KB), NMT slope null KB/s (R² null); peak RSS 376 MB, peak NMT other (direct) 0 MB, peak socke… |
| envoy | memory | updown | bounded | pass | no (comparison) | RSS slope 131.943 KB/s (R² 0.697, growth 4082.969 KB), NMT slope null KB/s (R² null); peak RSS 131 MB, peak NMT other (direct) 0 MB, peak s… |
| goproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 39.471 KB/s (R² 0.996, growth 1185.433 KB), NMT slope null KB/s (R² null); peak RSS 34 MB, peak NMT other (direct) 0 MB, peak soc… |
| goproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 12.16 KB/s (R² 0.989, growth 365.146 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak socke… |
| goproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 10.901 KB/s (R² 0.679, growth 355.968 KB), NMT slope null KB/s (R² null); peak RSS 16 MB, peak NMT other (direct) 0 MB, peak sock… |
| g3proxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 137.136 KB/s (R² 0.88, growth 4119.56 KB), NMT slope null KB/s (R² null); peak RSS 109 MB, peak NMT other (direct) 0 MB, peak soc… |
| g3proxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 0.4 KB/s (R² 0.79, growth 12.0 KB), NMT slope null KB/s (R² null); peak RSS 37 MB, peak NMT other (direct) 0 MB, peak socket buff… |
| g3proxy | memory | updown | bounded | pass | no (comparison) | RSS slope 7.791 KB/s (R² 0.782, growth 234.836 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak socke… |
| squid | memory | slowloris | bounded | pass | no (comparison) | RSS slope 0.0 KB/s (R² 0.0, growth 0.0 KB), NMT slope null KB/s (R² null); peak RSS 182 MB, peak NMT other (direct) 0 MB, peak socket buffe… |
| squid | memory | slowread | bounded | pass | no (comparison) | RSS slope 407.025 KB/s (R² 0.628, growth 12222.554 KB), NMT slope null KB/s (R² null); peak RSS 259 MB, peak NMT other (direct) 0 MB, peak … |
| squid | memory | updown | bounded | pass | no (comparison) | RSS slope 2.908 KB/s (R² 0.963, growth 87.429 KB), NMT slope null KB/s (R² null); peak RSS 178 MB, peak NMT other (direct) 0 MB, peak socke… |
| microproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope -62.232 KB/s (R² 0.114, growth -1982.141 KB), NMT slope -450.319 KB/s (R² 0.465); peak RSS 112 MB, peak NMT other (direct) 0 MB, … |
| microproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 35.816 KB/s (R² 0.706, growth 1134.981 KB), NMT slope 7.595 KB/s (R² 0.824); peak RSS 85 MB, peak NMT other (direct) 0 MB, peak s… |
| microproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 137.619 KB/s (R² 0.514, growth 4347.944 KB), NMT slope 139.847 KB/s (R² 0.353); peak RSS 80 MB, peak NMT other (direct) 0 MB, pea… |
| littleproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 456.268 KB/s (R² 0.87, growth 14579.134 KB), NMT slope 180.675 KB/s (R² 0.514); peak RSS 109 MB, peak NMT other (direct) 0 MB, pe… |
| littleproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 7.986 KB/s (R² 0.879, growth 253.714 KB), NMT slope 10.462 KB/s (R² 0.859); peak RSS 269 MB, peak NMT other (direct) 80 MB, peak … |
| littleproxy | memory | updown | oom | **FAIL** | no (comparison) | over the limit on its own memory (530 MB of 512 MB, socket buffers aside), killed; peak RSS 390 MB, peak NMT other (direct) 101 MB, peak so… |

## Memory under adversarial clients

The proxy runs with its memory capped (small heap and direct-memory ceiling, plus a cgroup limit where available). Each workload runs while the harness samples memory; a normal client probes throughout. Verdicts: **bounded** (memory levels off) or **shedding** (the proxy closes or refuses the adversarial connections and stays up) pass; **unbounded-growth** (RSS or NMT total climbs steadily after the warm-up: a least-squares line with R² ≥ 0.8 along which it grows by more than 32 MB and a quarter of its mean), an out-of-memory or a crash fail. A rising peak alone is not growth: pooled buffers warm up and then stay flat. When too little of the window is left after the warm-up (10 s or a quarter of the workload) to tell, the verdict is **inconclusive**. NMT "other" is where direct (off-heap) buffers are counted; for the slow readers, "direct per reader" is that section's peak over the baseline, divided by the readers: what the proxy holds for each one.

| Workload | Proxy | Verdict | Result | Peak RSS MB | Peak NMT MB | Peak heap(GC) MB | Peak other MB | Direct per reader KB | Proxy end |
|---|---|---|---|---|---|---|---|---|---|
| slowloris | envoy | bounded | pass | 105.8 | - | - | - | - | running |
| slowloris | goproxy | bounded | pass | 34.1 | - | - | - | - | running |
| slowloris | g3proxy | bounded | pass | 109.6 | - | - | - | - | running |
| slowloris | squid | bounded | pass | 182.3 | - | - | - | - | running |
| slowloris | microproxy | bounded | pass | 112.6 | 155.4 | 22.9 | 0.1 | - | running |
| slowloris | littleproxy | bounded | pass | 109.1 | 110.9 | 15.8 | 0.8 | - | running |
| slowread | envoy | bounded | pass | 376.1 | - | - | - | - | running |
| slowread | goproxy | bounded | pass | 28.4 | - | - | - | - | running |
| slowread | g3proxy | bounded | pass | 37.2 | - | - | - | - | running |
| slowread | squid | bounded | pass | 259.2 | - | - | - | - | running |
| slowread | microproxy | bounded | pass | 85.8 | 101.3 | 20.7 | 0.1 | 0 | running |
| slowread | littleproxy | bounded | pass | 269.9 | 193.3 | 9.6 | 80.8 | 412 | running |
| updown | envoy | bounded | pass | 131.6 | - | - | - | - | running |
| updown | goproxy | bounded | pass | 16.6 | - | - | - | - | running |
| updown | g3proxy | bounded | pass | 28.6 | - | - | - | - | running |
| updown | squid | bounded | pass | 178.9 | - | - | - | - | running |
| updown | microproxy | bounded | pass | 80.8 | 84.3 | 4.8 | 0.1 | - | running |
| updown | littleproxy | oom | **FAIL** | 390.3 | 213.3 | 10.1 | 101.1 | - | oom |

## Harness self-checks

These verify the harness worked (each scenario ran, responses validated, metrics were sampled, the report was written), not how well a proxy did. Any failure here fails the run, whichever proxy it concerns.

| Proxy | Scenario | Check | OK | Detail |
|---|---|---|---|---|
| envoy | memory | responses validate (status and length) | yes | all valid |
| envoy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.061 s |
| envoy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.112 s |
| envoy | memory | updown ran and memory was sampled | yes | 8 samples over 36.16 s |
| envoy | memory | at least one memory workload ran | yes | 3 workloads |
| envoy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| goproxy | memory | responses validate (status and length) | yes | all valid |
| goproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.039 s |
| goproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.102 s |
| goproxy | memory | updown ran and memory was sampled | yes | 8 samples over 38.082 s |
| goproxy | memory | at least one memory workload ran | yes | 3 workloads |
| goproxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| g3proxy | memory | responses validate (status and length) | yes | all valid |
| g3proxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.048 s |
| g3proxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.1 s |
| g3proxy | memory | updown ran and memory was sampled | yes | 8 samples over 35.227 s |
| g3proxy | memory | at least one memory workload ran | yes | 3 workloads |
| g3proxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| squid | memory | responses validate (status and length) | yes | all valid |
| squid | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.042 s |
| squid | memory | slowread ran and memory was sampled | yes | 8 samples over 35.103 s |
| squid | memory | updown ran and memory was sampled | yes | 8 samples over 35.145 s |
| squid | memory | at least one memory workload ran | yes | 3 workloads |
| squid | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| microproxy | memory | responses validate (status and length) | yes | all valid |
| microproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.182 s |
| microproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 37.034 s |
| microproxy | memory | updown ran and memory was sampled | yes | 7 samples over 38.602 s |
| microproxy | memory | at least one memory workload ran | yes | 3 workloads |
| microproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| littleproxy | memory | responses validate (status and length) | yes | all valid |
| littleproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.295 s |
| littleproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 37.127 s |
| littleproxy | memory | updown ran and memory was sampled | yes | 1 samples over 0.0 s |
| littleproxy | memory | at least one memory workload ran | yes | 3 workloads |
| littleproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| all | report | JSON results and the Markdown report were written | yes | loadtest/results/dedicated-memory-A-20261018/rep3/20261018-173308/rep… |

