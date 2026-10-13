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
- Native Linux, not a virtual machine on a workstation: WSL2 is a VM whose Windows-side work the
  guard cannot see, so results from it are diagnostic only (the script says so). A desktop can boot an
  Ubuntu 24.04 live USB for the campaign without installing anything.
- On hybrid processors (Intel's performance + efficiency cores) the script uses only the performance
  cores, one thread per core; turning SMT off and leaving the efficiency cores idle is still best.
- 16 GB of memory or more, and nothing else running for the campaign's duration (about 5 hours for
  five repetitions of all six proxies, plus about 30 minutes of setup).

## Steps

```bash
git clone https://github.com/mahmoudimus/MicroProxy && cd MicroProxy
git checkout <branch named in the pull request>
sudo loadtest/competitors/dedicated/bootstrap.sh            # prepare and print a machine report
sudo RUN=1 loadtest/competitors/dedicated/bootstrap.sh      # then run the campaign (about 5 hours)
```

`JDK=25` runs the proxies and harness on Temurin 25 instead of 21. The results land in
`loadtest/results/dedicated-<UTC time>/`; commit that directory's raw results (or attach it as a
tarball) and aggregate with `python3 -I loadtest/competitors/aggregate.py <dir> --publish docs`.

## Running it with Claude Code on the machine

Start `claude remote-control` in the clone, then give it this prompt:

> Prepare this machine with `sudo loadtest/competitors/dedicated/bootstrap.sh` and check its report
> (SMT off, performance governor, load near 0). Run the campaign with
> `sudo RUN=1 loadtest/competitors/dedicated/bootstrap.sh`, then again with `JDK=25` and
> `PROXIES=microproxy,littleproxy`. Don't run anything else on the machine meanwhile. Commit the raw
> results directories (no absolute local paths; aggregate.py strips them) to a new branch
> `perf/dedicated-<date>`, push it, and report the machine report, the runs the guard accepted or
> rejected, and the median max sustainable rate and CPU per request of each proxy.
