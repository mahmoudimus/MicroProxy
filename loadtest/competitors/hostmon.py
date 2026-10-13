#!/usr/bin/env python3
"""Logs what else runs on the machine while the comparison runs, for the contamination guard.

    python3 -I loadtest/competitors/hostmon.py <benchmark pid> <output .jsonl> [interval seconds]

Every interval (5 s by default) it appends one JSON line: the time, /proc/loadavg, the machine's
busy CPU (in percent of one CPU), the busy CPU of the benchmark's own process tree (the given pid
and every descendant: the harness, the proxies, the origin, the load generator, jcmd), the
difference (foreign CPU), and the five busiest foreign processes with their command lines. It stops
when the benchmark process exits. aggregate.py reads the log to accept or reject each run.

Only the standard library is used; it reads /proc and nothing else.
"""
import json
import os
import sys
import time

CLK = os.sysconf("SC_CLK_TCK")


def cpu_total():
    """(process time, total, interrupt time, steal) in ticks over all CPUs. Process time is user,
    nice and system: what processes are charged with. Interrupt work (irq, softirq, much of it
    the benchmark's own loopback traffic) and steal (the hypervisor's) are kept apart."""
    with open("/proc/stat") as f:
        parts = f.readline().split()[1:9]
    v = [int(x) for x in parts]
    return v[0] + v[1] + v[2], sum(v), v[5] + v[6], v[7]


def procs():
    """pid -> (ppid, cpu ticks, command line)."""
    out = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                stat = f.read()
            rest = stat[stat.rindex(")") + 2:].split()
            ppid = int(rest[1])
            ticks = int(rest[11]) + int(rest[12])
            with open(f"/proc/{d}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
            if not cmd:
                cmd = "[" + stat[stat.index("(") + 1:stat.rindex(")")] + "]"
            out[int(d)] = (ppid, ticks, cmd[:200])
        except (OSError, ValueError, IndexError):
            continue
    return out


def tree(root, ps):
    children = {}
    for pid, (ppid, _, _) in ps.items():
        children.setdefault(ppid, []).append(pid)
    seen, stack = set(), [root]
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        stack.extend(children.get(p, []))
    return seen


def main(argv):
    root, out = int(argv[1]), argv[2]
    interval = float(argv[3]) if len(argv) > 3 else 5.0
    me = os.getpid()
    prev_ps, (prev_busy, prev_total, prev_irq, prev_steal), prev_t = procs(), cpu_total(), time.time()
    with open(out, "a", encoding="utf-8") as log:
        while os.path.exists(f"/proc/{root}"):
            time.sleep(interval)
            ps, (busy, total, irq, steal), now = procs(), cpu_total(), time.time()
            ncpu = os.cpu_count() or 1
            span = max(1, total - prev_total)
            machine = 100.0 * ncpu * (busy - prev_busy) / span
            ours = tree(root, ps) | {me}
            own = 0.0
            foreign = []
            for pid, (_, ticks, cmd) in ps.items():
                before = prev_ps.get(pid)
                # A process that started during the interval (such as a jcmd) counts with all its CPU.
                start = before[1] if before is not None and before[2] == cmd else 0
                pct = 100.0 * (ticks - start) / CLK / max(1e-6, now - prev_t)
                if pid in ours:
                    own += pct
                elif pct >= 1.0:
                    foreign.append({"pid": pid, "cpuPct": round(pct, 1), "cmd": cmd})
            foreign.sort(key=lambda x: -x["cpuPct"])
            with open("/proc/loadavg") as f:
                load = f.read().split()[:3]
            log.write(json.dumps({"t": round(now, 1), "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                                  "loadavg": [float(x) for x in load], "machineCpuPct": round(machine, 1),
                                  "benchmarkCpuPct": round(own, 1), "foreignCpuPct": round(max(0.0, machine - own), 1),
                                  "interruptCpuPct": round(100.0 * ncpu * (irq - prev_irq) / span, 1),
                                  "stealCpuPct": round(100.0 * ncpu * (steal - prev_steal) / span, 1),
                                  "topForeign": foreign[:5]}) + "\n")
            log.flush()
            prev_ps, prev_busy, prev_total, prev_irq, prev_steal, prev_t = ps, busy, total, irq, steal, now


if __name__ == "__main__":
    main(sys.argv)
