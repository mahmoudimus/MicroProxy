# Load and capacity report: envoy, goproxy, g3proxy, squid, microproxy, littleproxy

- Preset: `standard`  Timestamp (UTC): `20261018-183345`
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
| envoy | memory | slowloris | shedding | pass | no (comparison) | closed by the proxy 2000 of 2000; peak RSS 106 MB, peak NMT other (direct) 0 MB, peak socket buffers 1 MB; probe 180/180 ok |
| goproxy | memory | slowloris | shedding | pass | no (comparison) | closed by the proxy 2000 of 2000; peak RSS 33 MB, peak NMT other (direct) 0 MB, peak socket buffers 0 MB; probe 180/180 ok |
| g3proxy | memory | slowloris | shedding | pass | no (comparison) | closed by the proxy 2000 of 2000; peak RSS 106 MB, peak NMT other (direct) 0 MB, peak socket buffers 0 MB; probe 180/180 ok |
| squid | memory | slowloris | shedding | pass | no (comparison) | closed by the proxy 2000 of 2000; peak RSS 182 MB, peak NMT other (direct) 0 MB, peak socket buffers 0 MB; probe 180/180 ok |
| microproxy | memory | slowloris | shedding | pass | no (comparison) | closed by the proxy 2000 of 2000; peak RSS 116 MB, peak NMT other (direct) 0 MB, peak socket buffers 4 MB; probe 180/180 ok |
| littleproxy | memory | slowloris | shedding | pass | no (comparison) | closed by the proxy 2000 of 2000; peak RSS 114 MB, peak NMT other (direct) 0 MB, peak socket buffers 0 MB; probe 170/170 ok |

## Memory under adversarial clients

The proxy runs with its memory capped (small heap and direct-memory ceiling, plus a cgroup limit where available). Each workload runs while the harness samples memory; a normal client probes throughout. Verdicts: **bounded** (memory levels off) or **shedding** (the proxy closes or refuses the adversarial connections and stays up) pass; **unbounded-growth** (RSS or NMT total climbs steadily after the warm-up: a least-squares line with R² ≥ 0.8 along which it grows by more than 32 MB and a quarter of its mean), an out-of-memory or a crash fail. A rising peak alone is not growth: pooled buffers warm up and then stay flat. When too little of the window is left after the warm-up (10 s or a quarter of the workload) to tell, the verdict is **inconclusive**. NMT "other" is where direct (off-heap) buffers are counted; for the slow readers, "direct per reader" is that section's peak over the baseline, divided by the readers: what the proxy holds for each one.

| Workload | Proxy | Verdict | Result | Peak RSS MB | Peak NMT MB | Peak heap(GC) MB | Peak other MB | Direct per reader KB | Proxy end |
|---|---|---|---|---|---|---|---|---|---|
| slowloris | envoy | shedding | pass | 106.2 | - | - | - | - | running |
| slowloris | goproxy | shedding | pass | 33.9 | - | - | - | - | running |
| slowloris | g3proxy | shedding | pass | 106.8 | - | - | - | - | running |
| slowloris | squid | shedding | pass | 182.0 | - | - | - | - | running |
| slowloris | microproxy | shedding | pass | 116.7 | 175.1 | 20.2 | 0.1 | - | running |
| slowloris | littleproxy | shedding | pass | 115.0 | 116.5 | 17.3 | 0.8 | - | running |

## Harness self-checks

These verify the harness worked (each scenario ran, responses validated, metrics were sampled, the report was written), not how well a proxy did. Any failure here fails the run, whichever proxy it concerns.

| Proxy | Scenario | Check | OK | Detail |
|---|---|---|---|---|
| envoy | memory | responses validate (status and length) | yes | all valid |
| envoy | memory | slowloris ran and memory was sampled | yes | 18 samples over 85.12 s |
| envoy | memory | at least one memory workload ran | yes | 1 workloads |
| envoy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| goproxy | memory | responses validate (status and length) | yes | all valid |
| goproxy | memory | slowloris ran and memory was sampled | yes | 18 samples over 85.095 s |
| goproxy | memory | at least one memory workload ran | yes | 1 workloads |
| goproxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| g3proxy | memory | responses validate (status and length) | yes | all valid |
| g3proxy | memory | slowloris ran and memory was sampled | yes | 18 samples over 85.103 s |
| g3proxy | memory | at least one memory workload ran | yes | 1 workloads |
| g3proxy | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| squid | memory | responses validate (status and length) | yes | all valid |
| squid | memory | slowloris ran and memory was sampled | yes | 18 samples over 85.093 s |
| squid | memory | at least one memory workload ran | yes | 1 workloads |
| squid | memory | proxy metrics were sampled (/proc; NMT n/a) | yes | per-second /proc samples present |
| microproxy | memory | responses validate (status and length) | yes | all valid |
| microproxy | memory | slowloris ran and memory was sampled | yes | 18 samples over 89.799 s |
| microproxy | memory | at least one memory workload ran | yes | 1 workloads |
| microproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| littleproxy | memory | responses validate (status and length) | yes | all valid |
| littleproxy | memory | slowloris ran and memory was sampled | yes | 17 samples over 85.001 s |
| littleproxy | memory | at least one memory workload ran | yes | 1 workloads |
| littleproxy | memory | proxy metrics were sampled (/proc and NMT) | yes | per-second /proc samples and NMT present |
| all | report | JSON results and the Markdown report were written | yes | loadtest/results/dedicated-memory-B-20261018/rep3/20261018-183345/rep… |

