# GCP diagnosis of the MicroProxy latency stall, 20261016

The question: is the roughly 1 s stall that the WSL2 campaign (perf/al-khwarizmi-20261013) saw in MicroProxy's sweep steps, and its 80–360 ms soak p99, a MicroProxy bug?
Each variant ran MicroProxy only, with SCENARIOS=soak,sweep and REPS=1 per invocation and PUBLISH=0. The 3 rounds were interleaved in the order A25 B25 A21 B21 C21. Each directory is <variant>-r<round>.

## Variants

- **A25**: bfe751d on JDK 25 (Temurin 25.0.4.1).
- **B25**: bfe751d with 20307ea reverted (IdleWaits removed; a scratch worktree, `git revert 20307ea`, not pushed) on JDK 25.
- **A21**: bfe751d on JDK 21 (Temurin 21.0.12.1). The launcher sets jdk.useDirectRegister=true (c35d1da).
- **B21**: the IdleWaits revert on JDK 21.
- **C21**: bfe751d on JDK 21 with `--proxy-jvm-args -Djdk.useDirectRegister=false` (direct registration off).

## Results

A stall step is a sweep step with p50 under 1 ms and p99 or max of at least 500 ms.

| Variant | Round | Soak p99 per window, median (ms) | Soak p99 per window, max (ms) | Sweep steps | Stall steps | Max sustainable rate (req/s) |
|---|---|---|---|---|---|---|
| A25 | 1 | 0.21 | 0.90 | 17 | 0 | 49,296 |
| A25 | 2 | 0.21 | 0.23 | 17 | 0 | 49,373 |
| A25 | 3 | 0.21 | 0.29 | 17 | 0 | 48,720 |
| B25 | 1 | 0.22 | 0.72 | 15 | 0 | 29,924 |
| B25 | 2 | 0.22 | 0.32 | 15 | 0 | 29,923 |
| B25 | 3 | 0.22 | 0.48 | 15 | 0 | 29,917 |
| A21 | 1 | 0.20 | 0.21 | 16 | 0 | 37,742 |
| A21 | 2 | 0.19 | 0.23 | 16 | 0 | 36,891 |
| A21 | 3 | 0.21 | 0.23 | 16 | 0 | 37,409 |
| B21 | 1 | 0.20 | 0.28 | 15 | 0 | 35,876 |
| B21 | 2 | 0.20 | 1.39 | 16 | 0 | 38,467 |
| B21 | 3 | 0.20 | 0.22 | 16 | 0 | 36,380 |
| C21 | 1 | 0.20 | 1.22 | 15 | 0 | 33,850 |
| C21 | 2 | 0.20 | 0.41 | 15 | 0 | 33,830 |
| C21 | 3 | 0.20 | 0.53 | 15 | 0 | 34,214 |

**No stall reproduces on this machine in any variant.** Soak p99 stayed at about 0.2 ms in every window (the WSL2 runs measured 80–360 ms), and no sweep step below the knee had a near-1 s max. B and C21 therefore cannot be judged to remove a stall that does not occur here. One side effect: B25's maximum sustainable rate (about 29.9k req/s) is far below A25's (about 49.1k), so reverting IdleWaits costs about 40% of throughput on JDK 25. On JDK 21, B21 and A21 are within noise of each other, and C21 is about 9% below A21.

A 5-minute smoke run (JDK 25, soak only; not included here) agreed: MicroProxy's soak p99 was 0.2–0.7 ms per window, and LittleProxy's was 0.2–3.2 ms.

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

## Contamination guard and coverage

Every diagnosis run passed aggregate.py's guard (no `--allow-unguarded` was needed), and the host monitor's largest gap was 5.8 s or less in every run.

| Run | Start | Finished | Largest gap | Result |
|---|---|---|---|---|
| A21-r1 | 20261015-204014 | 2026-10-15T20:45:29Z | 5.4s | OK |
| A21-r2 | 20261015-210613 | 2026-10-15T21:11:39Z | 5.8s | OK |
| A21-r3 | 20261015-213241 | 2026-10-15T21:38:17Z | 5.7s | OK |
| A25-r1 | 20261015-202934 | 2026-10-15T20:34:57Z | 5.1s | OK |
| A25-r2 | 20261015-205533 | 2026-10-15T21:00:56Z | 5.6s | OK |
| A25-r3 | 20261015-212201 | 2026-10-15T21:27:24Z | 5.5s | OK |
| B21-r1 | 20261015-204529 | 2026-10-15T20:50:26Z | 5.6s | OK |
| B21-r2 | 20261015-211139 | 2026-10-15T21:17:04Z | 5.2s | OK |
| B21-r3 | 20261015-213817 | 2026-10-15T21:43:52Z | 5.3s | OK |
| B25-r1 | 20261015-203457 | 2026-10-15T20:40:14Z | 5.3s | OK |
| B25-r2 | 20261015-210056 | 2026-10-15T21:06:13Z | 5.7s | OK |
| B25-r3 | 20261015-212724 | 2026-10-15T21:32:41Z | 5.6s | OK |
| C21-r1 | 20261015-205026 | 2026-10-15T20:55:33Z | 5.5s | OK |
| C21-r2 | 20261015-211704 | 2026-10-15T21:22:01Z | 5.5s | OK |
| C21-r3 | 20261015-214352 | 2026-10-15T21:49:09Z | 5.8s | OK |
