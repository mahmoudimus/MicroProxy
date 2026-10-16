# Running the comparison on a dedicated machine

The published comparison (docs/project/performance.md) needs quiet, stable CPUs: one CPU for the
proxy under test, one for the origin, the rest for the load generator, and nothing else running. A
shared cloud container is too noisy for numbers worth publishing, so the campaign runs on a dedicated
machine.

## The machine

- Linux (Ubuntu 24.04 or Debian 12), root access, outbound HTTPS (GitHub, Maven Central, go.dev,
  static.rust-lang.org, crates.io).
- At least 8 physical cores, 16 preferred; SMT (hyper-threading) off, so pinned processes never share
  a core: bare metal, or a cloud instance with dedicated cores and one thread per core (for example
  AWS c7i.4xlarge with "threads per core = 1", or a Google Cloud C3 instance with threads-per-core=1).
- Native Linux, or WSL2 on an otherwise idle Windows workstation. Under WSL2 the Windows host shares
  the cores without showing in Linux's /proc, so run-all.sh also logs the Windows side's CPU
  (winmon.py, through powershell.exe) and the guard adds it to the Linux side's foreign CPU; only the
  totals are published, never the desktop's process names. Use a High or Ultimate performance power
  plan, and keep the Windows side idle. The page names the platform (for example "i9-13900K, WSL2
  on Windows 11") so readers can weigh it.
- A limitation to state in the published methodology: from inside WSL2 the harness pins processes to
  the VM's virtual CPUs, not to physical cores, and on a hybrid processor Windows decides whether
  those run on performance or efficiency cores. The Windows monitor catches competing load, and five
  repetitions in rotated order spread scheduling wobble across all proxies, but neither guarantees
  every proxy got the same kind of core.
- On hybrid processors (Intel's performance + efficiency cores) the script uses only the performance
  cores, one thread per core; turning SMT off and leaving the efficiency cores idle is still best.
- 16 GB of memory or more, and nothing else running for the campaign's duration (about 5 hours for
  five repetitions of all six proxies, plus about 30 minutes of setup).

## Steps

```bash
git clone https://github.com/mahmoudimus/MicroProxy && cd MicroProxy
git checkout <branch named in the pull request>
sudo loadtest/competitors/dedicated/bootstrap.sh            # prepare and print a machine report
sudo RUN=1 loadtest/competitors/dedicated/bootstrap.sh      # then run the campaign (about 6 hours)
```

The proxies and harness run on Temurin 25; pass `JDK=21` (with `sudo env JDK=21 ...`: sudo drops
the environment) to run them on Temurin 21 instead. The results land in
`loadtest/results/dedicated-<UTC time>/`; commit that directory's raw results (or attach it as a
tarball) and aggregate with `python3 -I loadtest/competitors/aggregate.py <dir> --publish docs`.

## Running it with Claude Code on the machine

Start `claude remote-control` in the clone, then give it this prompt:

> Prepare this machine with `sudo loadtest/competitors/dedicated/bootstrap.sh` and check its report
> (one thread per core, load near 0). Run the campaign with
> `sudo RUN=1 loadtest/competitors/dedicated/bootstrap.sh`, then again with
> `sudo env JDK=21 REPS=3 PROXIES=microproxy,littleproxy RUN=1 loadtest/competitors/dedicated/bootstrap.sh`. Don't run anything else on the machine meanwhile. Commit the raw
> results directories (no absolute local paths; aggregate.py strips them) to a new branch
> `perf/dedicated-<date>`, push it, and report the machine report, the runs the guard accepted or
> rejected, and the median max sustainable rate and CPU per request of each proxy.

## Slow readers and socket buffers

cgroup v2 charges the TCP socket buffers of the proxy's sockets to its memory cgroup. On some
kernels (Linux 7.0 on Google Cloud, for one) the buffers of the memory scenario's 200 slow readers
alone fill a 512 MB limit, and lowering `tcp_rmem` and `tcp_wmem` to the upstream defaults does not
prevent it. The harness therefore holds the proxy's own memory to the limit and reports the socket
buffers beside it (`--attack-cgroup-sockets exclude`, the default; see
docs/project/load-testing.md). Runs made before that (they have no `peakSockKb`) list the
workload under `"notMeasured"` in their `run-info.json` instead (see aggregate.py's header).
