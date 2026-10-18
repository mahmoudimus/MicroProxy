# Load and capacity report: microproxy, littleproxy, envoy, goproxy, g3proxy, squid

- Preset: `standard`  Timestamp (UTC): `20261018-170711`
- Versions: microproxy `0.4.1-SNAPSHOT`, littleproxy `2.9.1`, envoy `/root/MicroProxy/loadtest/competitors/.tools/bin/envoy  version: 72315c132d462e5126e492ab2a71057565dbc87a/1.39.4/Clean/RELEASE/BoringSSL`, goproxy `github.com/elazarl/goproxy v1.9.2 (go1.27.2)`, g3proxy `g3proxy 1.12.4`, squid `Squid Cache: Version 6.14`
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
| microproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 56.736 KB/s (R² 0.437, growth 1805.211 KB), NMT slope -120.854 KB/s (R² 0.557); peak RSS 102 MB, peak NMT other (direct) 0 MB, pe… |
| microproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 5.577 KB/s (R² 0.931, growth 176.564 KB), NMT slope 50.182 KB/s (R² 0.476); peak RSS 84 MB, peak NMT other (direct) 0 MB, peak so… |
| microproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 141.864 KB/s (R² 0.757, growth 4585.202 KB), NMT slope 136.761 KB/s (R² 0.245); peak RSS 81 MB, peak NMT other (direct) 0 MB, pea… |
| littleproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 834.841 KB/s (R² 0.804, growth 26652.298 KB), NMT slope 197.785 KB/s (R² 0.184); peak RSS 122 MB, peak NMT other (direct) 0 MB, p… |
| littleproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 10.053 KB/s (R² 0.94, growth 319.701 KB), NMT slope 14.999 KB/s (R² 0.981); peak RSS 270 MB, peak NMT other (direct) 122 MB, peak… |
| littleproxy | memory | updown | oom | **FAIL** | no (comparison) | over the limit on its own memory (512 MB of 512 MB, socket buffers aside), killed; peak RSS 511 MB, peak NMT other (direct) 121 MB, peak so… |
| envoy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 23.687 KB/s (R² 0.89, growth 711.439 KB), NMT slope null KB/s (R² null); peak RSS 104 MB, peak NMT other (direct) 0 MB, peak sock… |
| envoy | memory | slowread | bounded | pass | no (comparison) | RSS slope 0.571 KB/s (R² 0.909, growth 17.143 KB), NMT slope null KB/s (R² null); peak RSS 374 MB, peak NMT other (direct) 0 MB, peak socke… |
| envoy | memory | updown | bounded | pass | no (comparison) | RSS slope 71.439 KB/s (R² 0.631, growth 2209.048 KB), NMT slope null KB/s (R² null); peak RSS 126 MB, peak NMT other (direct) 0 MB, peak so… |
| goproxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 42.149 KB/s (R² 0.998, growth 1266.124 KB), NMT slope null KB/s (R² null); peak RSS 34 MB, peak NMT other (direct) 0 MB, peak soc… |
| goproxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 9.734 KB/s (R² 0.993, growth 292.282 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak socke… |
| goproxy | memory | updown | bounded | pass | no (comparison) | RSS slope 3.266 KB/s (R² 0.121, growth 107.75 KB), NMT slope null KB/s (R² null); peak RSS 16 MB, peak NMT other (direct) 0 MB, peak socket… |
| g3proxy | memory | slowloris | bounded | pass | no (comparison) | RSS slope 136.629 KB/s (R² 0.877, growth 4103.937 KB), NMT slope null KB/s (R² null); peak RSS 109 MB, peak NMT other (direct) 0 MB, peak s… |
| g3proxy | memory | slowread | bounded | pass | no (comparison) | RSS slope 0.428 KB/s (R² 0.375, growth 12.857 KB), NMT slope null KB/s (R² null); peak RSS 38 MB, peak NMT other (direct) 0 MB, peak socket… |
| g3proxy | memory | updown | bounded | pass | no (comparison) | RSS slope 14.584 KB/s (R² 0.926, growth 439.728 KB), NMT slope null KB/s (R² null); peak RSS 28 MB, peak NMT other (direct) 0 MB, peak sock… |
| squid | memory | slowloris | bounded | pass | no (comparison) | RSS slope 0.828 KB/s (R² 0.444, growth 24.858 KB), NMT slope null KB/s (R² null); peak RSS 182 MB, peak NMT other (direct) 0 MB, peak socke… |
| squid | memory | slowread | bounded | pass | no (comparison) | RSS slope 386.644 KB/s (R² 0.628, growth 11610.535 KB), NMT slope null KB/s (R² null); peak RSS 259 MB, peak NMT other (direct) 0 MB, peak … |
| squid | memory | updown | bounded | pass | no (comparison) | RSS slope 8.725 KB/s (R² 0.789, growth 262.3 KB), NMT slope null KB/s (R² null); peak RSS 179 MB, peak NMT other (direct) 0 MB, peak socket… |

## Memory under adversarial clients

The proxy runs with its memory capped (small heap and direct-memory ceiling, plus a cgroup limit where available). Each workload runs while the harness samples memory; a normal client probes throughout. Verdicts: **bounded** (memory levels off) or **shedding** (the proxy closes or refuses the adversarial connections and stays up) pass; **unbounded-growth** (RSS or NMT total climbs steadily after the warm-up: a least-squares line with R² ≥ 0.8 along which it grows by more than 32 MB and a quarter of its mean), an out-of-memory or a crash fail. A rising peak alone is not growth: pooled buffers warm up and then stay flat. When too little of the window is left after the warm-up (10 s or a quarter of the workload) to tell, the verdict is **inconclusive**. NMT "other" is where direct (off-heap) buffers are counted; for the slow readers, "direct per reader" is that section's peak over the baseline, divided by the readers: what the proxy holds for each one.

| Workload | Proxy | Verdict | Result | Peak RSS MB | Peak NMT MB | Peak heap(GC) MB | Peak other MB | Direct per reader KB | Proxy end |
|---|---|---|---|---|---|---|---|---|---|
| slowloris | microproxy | bounded | pass | 102.1 | 119.3 | 22.4 | 0.1 | - | running |
| slowloris | littleproxy | bounded | pass | 122.1 | 120.0 | 15.8 | 0.8 | - | running |
| slowloris | envoy | bounded | pass | 104.2 | - | - | - | - | running |
| slowloris | goproxy | bounded | pass | 34.0 | - | - | - | - | running |
| slowloris | g3proxy | bounded | pass | 109.6 | - | - | - | - | running |
| slowloris | squid | bounded | pass | 182.0 | - | - | - | - | running |
| slowread | microproxy | bounded | pass | 84.1 | 103.3 | 20.9 | 0.1 | 0 | running |
| slowread | littleproxy | bounded | pass | 270.9 | 238.0 | 10.5 | 122.4 | 625 | running |
| slowread | envoy | bounded | pass | 374.1 | - | - | - | - | running |
| slowread | goproxy | bounded | pass | 28.0 | - | - | - | - | running |
| slowread | g3proxy | bounded | pass | 38.5 | - | - | - | - | running |
| slowread | squid | bounded | pass | 259.2 | - | - | - | - | running |
| updown | microproxy | bounded | pass | 81.4 | 85.5 | 4.9 | 0.1 | - | running |
| updown | littleproxy | oom | **FAIL** | 511.7 | 237.7 | 9.5 | 121.5 | - | oom |
| updown | envoy | bounded | pass | 126.8 | - | - | - | - | running |
| updown | goproxy | bounded | pass | 16.6 | - | - | - | - | running |
| updown | g3proxy | bounded | pass | 28.6 | - | - | - | - | running |
| updown | squid | bounded | pass | 179.0 | - | - | - | - | running |

## Harness self-checks

These verify the harness worked (each scenario ran, responses validated, metrics were sampled, the report was written), not how well a proxy did. Any failure here fails the run, whichever proxy it concerns.

| Proxy | Scenario | Check | OK | Detail |
|---|---|---|---|---|
| microproxy | memory | responses validate (status and length) | yes | all valid |
| microproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.151 s |
| microproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 37.002 s |
| microproxy | memory | updown ran and memory was sampled | yes | 7 samples over 39.042 s |
| microproxy | memory | at least one memory workload ran | yes | 3 workloads |
| microproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| littleproxy | memory | responses validate (status and length) | yes | all valid |
| littleproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 37.265 s |
| littleproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 37.172 s |
| littleproxy | memory | updown ran and memory was sampled | yes | 1 samples over 0.0 s |
| littleproxy | memory | at least one memory workload ran | yes | 3 workloads |
| littleproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| envoy | memory | responses validate (status and length) | yes | all valid |
| envoy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.042 s |
| envoy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.105 s |
| envoy | memory | updown ran and memory was sampled | yes | 8 samples over 36.145 s |
| envoy | memory | at least one memory workload ran | yes | 3 workloads |
| envoy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| goproxy | memory | responses validate (status and length) | yes | all valid |
| goproxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.047 s |
| goproxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.098 s |
| goproxy | memory | updown ran and memory was sampled | yes | 8 samples over 38.386 s |
| goproxy | memory | at least one memory workload ran | yes | 3 workloads |
| goproxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| g3proxy | memory | responses validate (status and length) | yes | all valid |
| g3proxy | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.043 s |
| g3proxy | memory | slowread ran and memory was sampled | yes | 8 samples over 35.1 s |
| g3proxy | memory | updown ran and memory was sampled | yes | 8 samples over 35.24 s |
| g3proxy | memory | at least one memory workload ran | yes | 3 workloads |
| g3proxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| squid | memory | responses validate (status and length) | yes | all valid |
| squid | memory | slowloris ran and memory was sampled | yes | 8 samples over 35.045 s |
| squid | memory | slowread ran and memory was sampled | yes | 8 samples over 35.103 s |
| squid | memory | updown ran and memory was sampled | yes | 8 samples over 35.144 s |
| squid | memory | at least one memory workload ran | yes | 3 workloads |
| squid | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| all | report | JSON results and the Markdown report were written | yes | loadtest/results/dedicated-memory-A-20261018/rep1/20261018-170711/rep… |

