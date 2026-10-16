# GCP dedicated-core campaign, 20261016, JDK 21

Raw results of `loadtest/competitors/run-all.sh`, run through `dedicated/bootstrap.sh` with RUN=1, JDK=21, REPS=3, proxies: microproxy, littleproxy. The JDK used was Temurin 21.0.12.1.
Every scenario is included (sweep, ramp, memory, faults, soak). Every repetition finished; none crashed.

Command: `sudo env RUSTUP_HOME=... CARGO_HOME=... JDK=21 REPS=3 PROXIES=microproxy,littleproxy RUN=1 OUT=<out> loadtest/competitors/dedicated/bootstrap.sh`

## Machine

- Google Cloud **c3-standard-22** with threads-per-core=1 (11 vCPUs, one per physical core), zone **us-central1-a**, 86 GB.
- Ubuntu 24.04.5 LTS, kernel **7.0.0-1014-gcp**. A dedicated VM, with nothing else running during the measurements.
- CPU split (run-all.sh): **proxy 1, origin 2, load generator 3,4,5,6,7,8**. CPU 0 is left for housekeeping, and CPUs 9 and 10 are unused.
- JDKs: pinned Temurin 21.0.12.1 and 25.0.4.1 (bootstrap.sh). External proxies are the versions in loadtest/competitors/versions.env.
- Measured commit: **bfe751d** (bfe751dcc0e4ec03b669031c7e9c782607906270), the source the WSL2 campaign (perf/al-khwarizmi-20261013) measured.

### Bootstrap machine report (prepare-only run)

```
[bootstrap] WARNING: running under google: use a dedicated-core instance, and check the guard's foreign-CPU record
[bootstrap] machine: Intel(R) Xeon(R) Platinum 8481C CPU @ 2.70GHz, 11 usable cores, 11 CPUs, virtualization google, 86 GB, kernel 7.0.0-1014-gcp
[bootstrap] java: openjdk version "21.0.12.1" 2026-08-18 LTS; governor: n/a
[bootstrap] split: proxy 1, origin 2, load generator 3,4,5,6,7,8
[bootstrap] load now: 2.37 1.65 0.68 1/265 16716 (should be near 0: stop everything else on the machine)
[bootstrap] local ports: 15000 64999; prepare-only runs restore the kernel settings on exit
[bootstrap] kernel settings restored
```

The governor is n/a because the VM exposes no cpufreq interface. The load figure was taken just after the harness build; measurements started only once the 1-minute load was under 0.3. The run printed no SMT note, which confirms one thread per core.

### Setup workaround

On a machine with no Rust 1.97.0 on the PATH, `setup.sh` fails to build g3proxy: `cargo_bin()` exports
`RUSTUP_HOME`/`CARGO_HOME` inside the `$(cargo_bin)` command substitution, so the cargo it returns runs
without them ("rustup could not choose a version of cargo to run ... no default is configured").
The harness was not changed. Instead, the prepare-only bootstrap and both campaign bootstraps were run with
`sudo env RUSTUP_HOME=<repo>/loadtest/competitors/.tools/rustup CARGO_HOME=<repo>/loadtest/competitors/.tools/cargo ...`,
which points at the toolchain setup.sh itself installed.

### Publishing

Raw files were written by `aggregate.py --publish`, which minifies them and reduces the monitor's command lines to program names. Paths outside
the repository (the scratch output directory and the diagnosis worktree) were then made relative by hand: the scratch directory became `out/`, and the worktree prefix was removed.
`gc/` holds each run's MicroProxy and LittleProxy GC logs, named `<rep>-<timestamp>-<file>`.

## Contamination guard (aggregate.py)

| Run (UTC start) | Foreign CPU, mean / p95 / max (% of one CPU) | Load average, mean / max | Busiest outside processes (mean CPU; kernel threads include some interrupt work) | Guard |
|---|---|---|---|---|
| 20261016-022755 | 4.3% / 23.2% / 77.6% | 3.41 / 14.66 | kernel thread 6.6%, sshd: 0.1% | accepted |
| 20261016-024735 | 7.4% / 49.2% / 164.7% | 3.55 / 14.80 | kernel thread 5.1%, sshd: 0.2% | accepted |
| 20261016-030716 | 5.8% / 30.5% / 106.6% | 3.40 / 14.81 | kernel thread 5.3%, sshd: 0.2% | accepted |

## Host-monitor coverage

The largest gap between hostmon.jsonl samples within [timestamp, finished], with the run's edges included. The limit is 10 s.

| Rep | Start | Finished | Largest gap | Result |
|---|---|---|---|---|
| rep1 | 20261016-022755 | 2026-10-16T02:47:35Z | 5.6s | OK |
| rep2 | 20261016-024735 | 2026-10-16T03:07:16Z | 5.1s | OK |
| rep3 | 20261016-030716 | 2026-10-16T03:26:13Z | 5.1s | OK |

No run was rejected.

Regenerate the aggregate with `python3 -I loadtest/competitors/aggregate.py --raw loadtest/results/gcp-20261016-jdk21`.
