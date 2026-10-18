#!/usr/bin/env python3
"""Aggregates repeated runs of the load-testing harness into the data of the performance page.

    python3 -I loadtest/competitors/aggregate.py <runs dir> [--publish <docs dir>] [--allow-unguarded]
    python3 -I loadtest/competitors/aggregate.py --raw docs/assets/perf/raw [--out <dir>] [--publish docs]

<runs dir> holds one harness results directory per repetition (rep1/<timestamp>/results.json, ...,
as run-all.sh writes them). With --raw, the runs are instead read from a published raw/ directory
(<rep>-<timestamp>.json files beside run-info.json and hostmon.jsonl), so that the page can be
regenerated from the data committed beside it. For every proxy, scenario and measure it takes the
median over the repetitions, keeps every run's value (the charts show each run as a dot) and the
minimum and maximum (the spread table), and writes into <runs dir>/aggregate/ (or --out):

  results.json   the page's data: machine, versions, settings, command lines, and every aggregate
  *.svg          static charts, for readers without JavaScript (and GitHub)
  tables.md      the Markdown tables of the page

The rate sweep's maximum sustainable rate is each run's refined maximum when the harness refined
the knee (sweep-refine-steps), with the bracket of offered rates it lies in; for runs made before
refinement existed, the bracket is the coarse one (one sweep step) and the page says the figure is
not refined. A run whose sweep the load generator ended (client-bound) is left out of every sweep
figure, and each latency and CPU curve uses the same runs at every point: it stops at the highest
offered rate every one of those runs sustained.

The memory figures can come from other runs than the rest: "memoryFrom" in run-info.json names a
results directory (relative to this one, in either layout) whose runs, with their own run-info.json
and host monitor log, give every memory-under-attack figure; they pass the same guard, and are
published under raw/memory/. That is for a memory scenario run again on the same machine after a
harness change, without repeating the hours of the other scenarios.

A memory workload listed under "notMeasured" in run-info.json ({"scenario": "memory", "attack": ...,
"reason": ...}) is left out of every figure, and the tables give its reason instead: for a workload
the machine itself made meaningless (not a run that was disturbed, which is "rejected").

Runs listed under "rejected" in run-info.json are left out. Every other run must pass the
contamination guard, read from hostmon.jsonl (written by hostmon.py while the runs ran): the CPU the
machine spent outside the benchmark's processes must average at most 50% of one CPU over the run,
with a 95th percentile of at most 100%, and the monitor must cover the whole run, never more than
10 s (twice its 5 s interval) without a sample, the run's start and end included. --publish refuses runs that fail it or were not monitored
(--allow-unguarded overrides that, for a local preview only).

With --publish it also copies them into <docs dir>/assets/perf/, copies each repetition's raw
results.json (minified) to <docs dir>/assets/perf/raw/ (unless it is reading from there), and
rewrites the generated tables of <docs dir>/project/performance.md, between its <!-- perf:NAME -->
and <!-- /perf:NAME --> markers.

Only the standard library is used. Nothing here invents a number: a value missing from the runs is
missing from the output (null, or "n/a" in the tables). Paths under the repository are made
relative in everything published.
"""
import glob
import json
import math
import os
import re
import shutil
import statistics
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# The fixed order (and color slot) of every proxy the page knows; others follow in run order.
CANONICAL = ["microproxy", "littleproxy", "envoy", "goproxy", "g3proxy", "squid"]
BUILTIN = {
    "microproxy": {"label": "MicroProxy", "language": "Java (virtual threads)"},
    "littleproxy": {"label": "LittleProxy", "language": "Java (Netty)"},
}
# Light and dark series colors, by slot (validated categorical palette; see perf.css).
COLORS_LIGHT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
COLORS_DARK = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"]


# --- statistics -----------------------------------------------------------------------------

def stats(values):
    """Median, minimum, maximum and count of the numbers in values (None when there are none)."""
    vals = [v for v in values if isinstance(v, (int, float))]
    if not vals:
        return None
    return {"med": rnd(statistics.median(vals)), "min": rnd(min(vals)), "max": rnd(max(vals)), "n": len(vals),
            "values": [rnd(v) for v in vals]}


def rnd(v, digits=3):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    r = round(v, digits)
    return int(r) if r == int(r) and abs(r) >= 100 else r


def counts(items):
    out = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


def kb_to_mb(v):
    return None if v is None or v < 0 else v / 1024.0


# --- loading -----------------------------------------------------------------------------------

RAW = [False]


def parse_utc(text):
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def is_raw_dir(runs_dir):
    """Whether runs_dir holds published raw files (<rep>-<timestamp>.json) rather than rep*/<timestamp>/."""
    return any(re.match(r"^rep\d+-", os.path.basename(p)) for p in glob.glob(os.path.join(runs_dir, "*-*.json")))


def load_runs(runs_dir, raw=None):
    """Every rep*/<timestamp>/results.json (or, with --raw, every <rep>-<timestamp>.json), except the
    runs that run-info.json rejects, in start order. raw overrides --raw for this directory."""
    raw = RAW[0] if raw is None else raw
    rejected = {r["rep"] for r in run_info(runs_dir).get("rejected", [])}
    if raw:
        files = sorted(p for p in glob.glob(os.path.join(runs_dir, "*-*.json")) if re.match(r"^rep\d+-", os.path.basename(p)))
    else:
        files = sorted(set(os.path.realpath(p) for p in glob.glob(os.path.join(runs_dir, "rep*", "*", "results.json"))))
    runs = []
    for f in files:
        if raw:
            rep = os.path.basename(f).split("-", 1)[0]
        else:
            rep = os.path.basename(os.path.dirname(os.path.dirname(f)))
        if rep in rejected:
            continue
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        runs.append({"id": rep + "-" + data["timestamp"], "rep": rep, "file": f, "data": data,
                     "start": datetime.strptime(data["timestamp"], "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc).timestamp(),
                     "end": parse_utc(data.get("finished")) or (None if raw else os.path.getmtime(f))})
    if not runs:
        sys.exit("no runs under " + runs_dir)
    runs.sort(key=lambda r: r["start"])
    # Published raw files have no meaningful modification time: a run made before the harness recorded
    # when it finished ends where the next one starts (run-all.sh runs them back to back), the last one
    # at the host monitor's last sample that saw the benchmark's processes busy.
    for i, r in enumerate(runs):
        if r["end"] is None:
            r["end"] = runs[i + 1]["start"] if i + 1 < len(runs) else last_monitor_sample(runs_dir)
    return runs


def last_monitor_sample(runs_dir):
    path = os.path.join(runs_dir, "hostmon.jsonl")
    last = busy = None
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    x = json.loads(line)
                    last = x["t"]
                    if x.get("benchmarkCpuPct", 0) > 0:
                        busy = x["t"]
    return busy or last or 0


def run_info(runs_dir):
    path = os.path.join(runs_dir, "run-info.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# The contamination guard: a run is accepted only if, over its whole duration, the CPU that the
# machine spent outside the benchmark's process tree (hostmon.py's foreign CPU, in percent of one
# CPU, interrupt time excluded) stayed low.
GUARD_MEAN = 50.0
GUARD_P95 = 100.0
# The longest the monitor may go without a sample within a run (its start and end included): a gap
# is time in which the machine could have been busy unseen.
GUARD_MAX_GAP_S = 10.0


def largest_gap(times, start, end):
    """The longest stretch of [start, end] without a sample in times (sorted)."""
    edges = [start] + list(times) + [end]
    return max(b - a for a, b in zip(edges, edges[1:]))


def program(cmd):
    """A foreign process's program, without its arguments or paths: what the page may show."""
    if not cmd:
        return "?"
    if cmd.startswith("["):
        return "kernel thread"
    name = cmd.split()[0].rsplit("/", 1)[-1]
    # The interactive session that drove the runs from the same machine.
    return "interactive session" if name == "claude" else name


def host_load(runs_dir, runs):
    """Per run: the host monitor's foreign CPU and load average while it ran, and the guard's verdict."""
    path = os.path.join(runs_dir, "hostmon.jsonl")
    samples = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            samples = [json.loads(line) for line in f if line.strip()]
    # A campaign run on WSL2 must have the Windows host's log: without it a run cannot be judged.
    wsl = bool(run_info(runs_dir).get("wsl"))
    winsamples = []
    wpath = os.path.join(runs_dir, "winmon.jsonl")
    if os.path.exists(wpath):
        with open(wpath, encoding="utf-8") as f:
            winsamples = [json.loads(line) for line in f if line.strip()]
    out = {}
    for r in runs:
        win = [x for x in samples if r["start"] <= x["t"] <= r["end"]]
        if not win:
            out[r["id"]] = {"samples": 0, "accepted": None, "note": "no host monitor samples for this run"}
            continue
        foreign = sorted(x["foreignCpuPct"] for x in win)
        procs = {}
        for x in win:
            for p in x.get("topForeign", []):
                # "sshd: user@notty" and the like: the program, without the title it gives itself.
                name = (p.get("program") or program(p.get("cmd"))).rstrip(":")
                procs[name] = procs.get(name, 0.0) + p["cpuPct"] / len(win)
        top = sorted(procs.items(), key=lambda kv: -kv[1])[:5]
        mean = statistics.mean(foreign)
        p95 = foreign[min(len(foreign) - 1, int(len(foreign) * 0.95))]
        gap = largest_gap(sorted(x["t"] for x in win), r["start"], r["end"])
        # On WSL2 the Windows host's own work (winmon.py) competes for the same cores without showing
        # in the Linux VM's /proc: it counts against the run as well.
        wwin = [x for x in winsamples if r["start"] <= x["t"] <= r["end"]]
        windows = None
        if wsl or winsamples:
            if not wwin:
                out[r["id"]] = {"samples": len(win), "accepted": None, "note": "no Windows host monitor samples for this run"}
                continue
            gap = max(gap, largest_gap(sorted(x["t"] for x in wwin), r["start"], r["end"]))
            wf = sorted(x["windowsForeignCpuPct"] for x in wwin)
            wmean, wp95 = statistics.mean(wf), wf[min(len(wf) - 1, int(len(wf) * 0.95))]
            # The Windows processes stay in the local log: they are the person's own desktop.
            windows = {"samples": len(wwin), "foreignCpuPct": {"mean": rnd(wmean, 1), "p95": rnd(wp95, 1), "max": rnd(wf[-1], 1)}}
            mean, p95 = mean + wmean, p95 + wp95
        out[r["id"]] = {"samples": len(win), "foreignCpuPct": {"mean": rnd(mean, 1), "p95": rnd(p95, 1), "max": rnd(foreign[-1], 1)},
                        "windowsHost": windows,
                        "loadavg1": {"mean": rnd(statistics.mean(x["loadavg"][0] for x in win), 2),
                                     "max": rnd(max(x["loadavg"][0] for x in win), 2)},
                        "interruptCpuPct": rnd(statistics.mean(x.get("interruptCpuPct", 0) for x in win), 1),
                        "stealCpuPct": rnd(statistics.mean(x.get("stealCpuPct", 0) for x in win), 1),
                        "topForeign": [{"process": n, "meanCpuPct": rnd(v, 1)} for n, v in top],
                        "largestGapS": rnd(gap, 1),
                        "accepted": mean <= GUARD_MEAN and p95 <= GUARD_P95 and gap <= GUARD_MAX_GAP_S}
    return out


def proxy_order(runs):
    seen = []
    for r in runs:
        for p in r["data"]["proxies"]:
            if p not in seen:
                seen.append(p)
    return [p for p in CANONICAL if p in seen] + [p for p in seen if p not in CANONICAL]


def result(run, scenario, proxy):
    r = run["data"].get("results", {}).get(scenario, {}).get(proxy)
    return r if isinstance(r, dict) else None


def usable(r):
    return r is not None and "error" not in r and "unsupported" not in r


def strip_root(text):
    """Makes paths under the repository relative in published JSON text."""
    return text.replace(ROOT + "/", "").replace(ROOT, ".")


def sanitize(text):
    """Replaces machine-specific paths in a command line with placeholders."""
    if not isinstance(text, str):
        return text
    text = text.replace(ROOT + "/", "<repo>/").replace(ROOT, "<repo>")
    # Published raw results already hold paths relative to the repository.
    text = re.sub(r"(?<=[ =:])(loadtest|target)/", r"<repo>/\1/", text)
    text = re.sub(r"(<repo>/)?loadtest/results/[^ ]*/logs/", "<logs>/", text)
    text = re.sub(r"/tmp/[^ ]*/logs/", "<logs>/", text)
    # Any other results directory (a scratch output directory made relative by hand, say).
    text = re.sub(r"(?<=[ =:'])[^ =:'<]*/logs/", "<logs>/", text)
    text = re.sub(r"-Xlog:gc:file=[^ :]*", "-Xlog:gc:file=<logs>/gc.log", text)
    text = re.sub(r"--port \d+", "--port <port>", text)
    text = re.sub(r"127\.0\.0\.1:\d{4,5}", "127.0.0.1:<port>", text)
    text = re.sub(r"/sys/fs/cgroup/(memory/)?[^' ]*", "<cgroup>", text)
    return text


# --- per-scenario aggregation -------------------------------------------------------------------

def foreign_on(series, cpus):
    """Mean busy percentage of the given CPUs not spent by the sampled processes pinned there."""
    system = series.get("system") or []
    proxy = {round(s["t"]): s.get("cpuPct") for s in series.get("proxy") or [] if "cpuPct" in s}
    vals = []
    for s in system:
        busy = s.get("cpuBusyPct")
        if not busy:
            continue
        on = sum(busy[c] for c in cpus if c < len(busy))
        own = proxy.get(round(s["t"]))
        if own is None:
            continue
        vals.append(max(0.0, on - own))
    return statistics.mean(vals) if vals else None


def last_sustained_rate(r):
    """The offered rate of the highest sustained grid step before the knee (None if none was)."""
    steps = r.get("steps") or []
    knee = r.get("kneeStep")
    bound = len(steps) if knee is None else min(knee, len(steps))
    for j in range(bound - 1, -1, -1):
        if steps[j].get("sustainable"):
            return int(round(steps[j]["targetRate"]))
    return None


def proxy_knee(r):
    """Whether the proxy, rather than the load generator or a crash, ended the sweep's sustained range."""
    reason = r.get("kneeReason") or ""
    return r.get("kneeStep") is not None and not reason.startswith("client-bound") and not reason.startswith("proxy ")


def run_bracket(r):
    """The offered rates the run's maximum lies between: the harness's (refined) bracket, or for a
    run made before refinement existed, the coarse one (the last sustained step and the knee)."""
    if "maxSustainableBracket" in r:
        return r["maxSustainableBracket"]
    if not proxy_knee(r):
        return None
    lo = last_sustained_rate(r)
    steps = r.get("steps") or []
    if lo is None or r["kneeStep"] >= len(steps):
        return None
    return [lo, steps[r["kneeStep"]]["targetRate"]]


def cpu_per_request(step):
    """The proxy's CPU time per completed request (µs) over a step, and how it was measured: from
    /proc before and after the step ("measured"), or, for runs made before the harness recorded that,
    from the step's mean sampled CPU% and its achieved rate ("sampled")."""
    res = step.get("proxy") or {}
    v = res.get("cpuUsPerRequest")
    if isinstance(v, (int, float)):
        return v, "measured"
    pct, achieved = res.get("cpuPct"), step.get("achievedRate")
    if isinstance(pct, (int, float)) and pct >= 0 and achieved:
        return pct * 1e4 / achieved, "sampled"
    return None, None


SWEEP_KEYS = ("p50", "p90", "p99", "p999", "max")
PER_RUN_KEYS = ("p50", "p99", "p999", "cpuUsPerReq")


def aggregate_sweep(runs, proxies, proxy_cpus):
    out = {}
    for p in proxies:
        unsupported = None
        rows, used = [], []
        for run in runs:
            r = result(run, "sweep", p)
            if r is not None and "unsupported" in r:
                unsupported = r["unsupported"]
            if not usable(r):
                continue
            client_bound = "client-bound" in (r.get("stopReason") or "") or "client-bound" in (r.get("kneeReason") or "")
            bracket = run_bracket(r)
            rows.append({"run": run["id"], "included": not client_bound,
                         "excluded": "the load generator could not keep its schedule, which ended the sweep" if client_bound else None,
                         "max": rnd(r.get("maxSustainableRate")),
                         "coarseMax": rnd(r.get("maxSustainableRateCoarse", r.get("maxSustainableRate"))),
                         "bracket": [rnd(x) for x in bracket] if bracket else None,
                         "refined": bool(r.get("refined")),
                         "probes": len((r.get("refine") or {}).get("probes") or []),
                         "lastSustainedRate": last_sustained_rate(r),
                         "kneeReason": r.get("kneeReason"), "stopReason": r.get("stopReason"),
                         "transientSteps": len(r.get("transientSteps") or [])})
            if not client_bound:
                used.append((run, r))
        ids = [run["id"] for run, _ in used]
        foreign = [f for f in (foreign_on(r.get("series") or {}, proxy_cpus) for _, r in used) if f is not None]
        # Every point of a curve is the median of the same runs: those that were not client-bound. A
        # curve stops at the highest offered rate every one of them sustained.
        ends = [row["lastSustainedRate"] for row in rows if row["included"]]
        line_end = min(ends) if ends and all(e is not None for e in ends) else None
        by_rate = {}
        for k, (run, r) in enumerate(used):
            for st in r.get("steps", []):
                rate = int(round(st["targetRate"]))
                b = by_rate.setdefault(rate, {"vals": {key: [None] * len(used) for key in SWEEP_KEYS + ("cpuUsPerReq", "cpuPct", "achieved", "foreign", "errors")},
                                              "sustained": 0, "runs": 0, "cpuSource": set(), "spectra": []})
                lat = st.get("latencyMs") or {}
                res = st.get("proxy") or {}
                b["runs"] += 1
                b["sustained"] += 1 if st.get("sustainable") else 0
                for key in SWEEP_KEYS:
                    b["vals"][key][k] = lat.get(key)
                cpu, how = cpu_per_request(st)
                b["vals"]["cpuUsPerReq"][k] = cpu
                if how:
                    b["cpuSource"].add(how)
                b["vals"]["cpuPct"][k] = res.get("cpuPct")
                b["vals"]["achieved"][k] = st.get("achievedRate")
                b["vals"]["foreign"][k] = res.get("foreignCpuPct")
                b["vals"]["errors"][k] = st.get("errorCount")
                if st.get("percentilesMs"):
                    b["spectra"].append(st["percentilesMs"])
        steps = []
        for rate in sorted(by_rate):
            b = by_rate[rate]
            v = b["vals"]
            spectrum = None
            if b["spectra"]:
                spectrum = []
                for i, (pct, _) in enumerate(b["spectra"][0]):
                    st = stats([sp[i][1] for sp in b["spectra"] if i < len(sp)])
                    spectrum.append([pct, st["med"], st["min"], st["max"]])
            steps.append({"rate": rate, "runs": b["runs"], "sustained": b["sustained"],
                          "inCurve": line_end is not None and rate <= line_end and b["runs"] == len(used),
                          "achieved": stats(v["achieved"]), "p50": stats(v["p50"]), "p90": stats(v["p90"]),
                          "p99": stats(v["p99"]), "p999": stats(v["p999"]), "max": stats(v["max"]),
                          "cpuPct": stats(v["cpuPct"]), "cpuUsPerReq": stats(v["cpuUsPerReq"]),
                          "cpuSource": "/".join(sorted(b["cpuSource"])) or None,
                          "foreignCpuPct": stats(v["foreign"]), "errors": stats(v["errors"]),
                          "perRun": {key: [rnd(x) for x in v[key]] for key in PER_RUN_KEYS},
                          "percentiles": spectrum})
        inc = [row for row in rows if row["included"]]
        refined = sum(1 for row in inc if row["refined"])
        widths = [row["bracket"][1] / row["bracket"][0] - 1 for row in inc if row["bracket"] and row["bracket"][0]]
        out[p] = {"unsupported": unsupported, "runs": rows, "curveRuns": ids,
                  "maxSustainable": stats([row["max"] for row in inc]),
                  "refined": "all" if inc and refined == len(inc) else "none" if not refined else "some",
                  "bracketWidth": rnd(max(widths), 4) if widths else None,
                  "curveEndRate": line_end,
                  "kneeReasons": [row["kneeReason"] for row in inc],
                  "foreignOnProxyCpuPct": stats(foreign), "steps": steps}
    return out


def common_rate(sweep, proxies):
    """The highest offered rate on every proxy's curve: every proxy sustained it in every run used."""
    best = None
    measured = [p for p in proxies if sweep[p]["steps"]]
    rates = sorted({s["rate"] for p in measured for s in sweep[p]["steps"]})
    for rate in rates:
        if all(any(s["rate"] == rate and s["inCurve"] for s in sweep[p]["steps"]) for p in measured):
            best = rate
    return best


def aggregate_ramp(runs, proxies):
    out = {}
    for p in proxies:
        idle, per_conn, max_held, failures, by_target = [], [], [], [], {}
        unsupported = None
        for run in runs:
            r = result(run, "ramp", p)
            if r is not None and "unsupported" in r:
                unsupported = r["unsupported"]
            if not usable(r):
                continue
            base = r.get("baseline") or {}
            idle.append(kb_to_mb(base.get("rssKb")))
            per_conn.append((r.get("perConnection") or {}).get("rssKbPerConn"))
            max_held.append(r.get("maxConnectionsHeld"))
            failures.append(r.get("failureKind"))
            pts = by_target.setdefault(0, {"rss": [], "fds": [], "probeP99": [], "held": []})
            pts["rss"].append(kb_to_mb(base.get("rssKb")))
            pts["fds"].append(base.get("fds"))
            pts["held"].append(0)
            for s in r.get("steps", []):
                mem = s.get("memory") or {}
                b = by_target.setdefault(s["target"], {"rss": [], "fds": [], "probeP99": [], "held": []})
                b["rss"].append(kb_to_mb(mem.get("rssKb")))
                b["fds"].append(mem.get("fds"))
                b["held"].append(s.get("held"))
                b["probeP99"].append(((s.get("probe") or {}).get("durationMs") or {}).get("p99"))
        steps = [{"target": t, "held": stats(b["held"]), "rssMb": stats(b["rss"]), "fds": stats(b["fds"]),
                  "probeP99Ms": stats(b["probeP99"]), "runs": len(b["rss"])} for t, b in sorted(by_target.items())]
        out[p] = {"unsupported": unsupported, "idleRssMb": stats(idle), "rssKbPerConn": stats(per_conn),
                  "maxHeld": stats(max_held), "failureKinds": counts(failures), "steps": steps}
    return out


def not_measured(info):
    """The memory workloads run-info.json says this machine could not measure: {attack: reason}."""
    return {x["attack"]: x["reason"] for x in info.get("notMeasured", []) if x.get("scenario") == "memory"}


def aggregate_memory(runs, proxies, excluded=None):
    attacks = []
    for run in runs:
        for a in run["data"].get("settings", {}).get("attacks", "").split(","):
            if a and a not in attacks and a not in (excluded or {}):
                attacks.append(a)
    out = {}
    for attack in attacks:
        per = {}
        for p in proxies:
            verdicts, peaks, bases, per_conn, series, states, probes, caps, shed = [], [], [], [], [], [], [], [], []
            socks, sock_per_conn = [], []
            skipped = None
            for run in runs:
                r = result(run, "memory", p)
                if r is not None and "unsupported" in r:
                    skipped = r["unsupported"]
                if not usable(r):
                    continue
                rec = next((a for a in r.get("attacks", []) if a.get("attack") == attack), None)
                if rec is None:
                    continue
                if "skipped" in rec:
                    skipped = rec["skipped"]
                    continue
                verdicts.append(rec.get("outcome"))
                states.append(rec.get("proxyState"))
                peak = kb_to_mb(rec.get("peakRssKb"))
                base = kb_to_mb((rec.get("baseline") or {}).get("rssKb"))
                peaks.append(peak)
                bases.append(base)
                conns = (rec.get("workload") or {}).get("connections") or 0
                if peak is not None and base is not None and conns:
                    per_conn.append(max(0.0, (peak - base) * 1024.0 / conns))
                # The kernel's TCP buffers for the proxy's sockets (runs that measured them).
                sock_kb = rec.get("peakSockKb")
                sock = kb_to_mb(sock_kb) if isinstance(sock_kb, (int, float)) and sock_kb >= 0 else None
                socks.append(sock)
                if sock is not None and conns:
                    sock_per_conn.append(sock * 1024.0 / conns)
                closed = (rec.get("workload") or {}).get("closedByProxy")
                if conns and closed is not None:
                    shed.append(closed / conns)
                caps.append(rec.get("cap"))
                pts = [[0, base]] if base is not None else []
                for m in rec.get("memSeries") or []:
                    if m.get("rssKb") is not None:
                        pts.append([m["t"], kb_to_mb(m["rssKb"])])
                end = None
                if rec.get("outcome") in ("oom", "crashed"):
                    end = {"verdict": rec["outcome"], "t": pts[-1][0] if pts else 0, "state": rec.get("proxyState")}
                series.append({"run": run["id"], "points": [[rnd(t, 1), rnd(v, 1)] for t, v in pts], "end": end,
                               "peakMb": rnd(peak, 1)})
                ok = total = 0
                for pr in rec.get("probes") or []:
                    for k, v in (pr.get("outcomes") or {}).items():
                        total += v
                        ok += v if k == "OK" else 0
                probes.append(ok / total if total else None)
            # The race chart shows the run with the median peak; the spread is in peakRssMb.
            median_series = None
            if series:
                ordered = sorted(series, key=lambda s: (s["peakMb"] is None, s["peakMb"] or 0))
                median_series = ordered[(len(ordered) - 1) // 2]
            per[p] = {"skipped": skipped, "verdicts": counts(verdicts), "states": counts(states),
                      "peakRssMb": stats(peaks), "baselineRssMb": stats(bases), "rssKbPerConnection": stats(per_conn),
                      "probeOkRatio": stats(probes), "shedRatio": stats(shed), "cap": caps[0] if caps else None,
                      "peakSockMb": stats(socks), "sockKbPerConnection": stats(sock_per_conn),
                      "series": median_series, "allSeries": series}
        # Each figure's run count, against the memory runs' own (which can be other runs than the rest).
        for v in per.values():
            for st in v.values():
                if isinstance(st, dict) and "med" in st:
                    st["of"] = len(runs)
        out[attack] = per
    return out


def aggregate_soak(runs, proxies):
    out = {}
    for p in proxies:
        slopes, growth, verdicts, p99s, errors, reqs, series = [], [], [], [], [], [], []
        unsupported = None
        for run in runs:
            r = result(run, "soak", p)
            if r is not None and "unsupported" in r:
                unsupported = r["unsupported"]
            if not usable(r):
                continue
            fit = (r.get("leakCheck") or {}).get("rssKb") or {}
            slopes.append(fit.get("slopePerHour"))
            growth.append(fit.get("growth"))
            v = next((x for x in run["data"].get("verdicts", []) if x["proxy"] == p and x["scenario"] == "soak"), None)
            verdicts.append(v["verdict"] if v else None)
            p99s.append(statistics.median([w["latencyMs"]["p99"] for w in r.get("windows", []) if w.get("latencyMs", {}).get("p99") is not None] or [None]) if r.get("windows") else None)
            errors.append(r.get("totalErrors"))
            reqs.append(r.get("totalRequests"))
            series.append([[rnd(m["t"], 1), rnd(kb_to_mb(m.get("rssKb")), 1)] for m in r.get("memSeries", []) if m.get("rssKb")])
        out[p] = {"unsupported": unsupported, "rssSlopeKbPerHour": stats(slopes), "rssGrowthKb": stats(growth),
                  "verdicts": counts(verdicts), "medianWindowP99Ms": stats(p99s), "errors": stats(errors),
                  "requests": stats(reqs), "series": series}
    return out


def aggregate_faults(runs, proxies):
    out = {}
    for p in proxies:
        faults = {}
        unsupported = None
        for run in runs:
            r = result(run, "faults", p)
            if r is not None and "unsupported" in r:
                unsupported = r["unsupported"]
            if not usable(r):
                continue
            for f in r.get("faults", []):
                b = faults.setdefault(f["fault"], {"expected": f.get("expected"), "bounded": 0, "runs": 0, "outcomes": [],
                                                   "statuses": [], "maxMs": []})
                b["runs"] += 1
                b["bounded"] += 1 if f.get("ok") else 0
                b["outcomes"].append(" ".join(f"{k}:{v}" for k, v in sorted((f.get("outcomes") or {}).items())))
                b["statuses"].append(" ".join(f"{k}:{v}" for k, v in sorted((f.get("statuses") or {}).items())))
                b["maxMs"].append((f.get("durationMs") or {}).get("max"))
        out[p] = {"unsupported": unsupported, "faults": {k: {"expected": v["expected"], "bounded": v["bounded"],
                                                             "runs": v["runs"], "outcomes": counts(v["outcomes"]),
                                                             "statuses": counts(v["statuses"]), "maxMs": stats(v["maxMs"])}
                                                         for k, v in faults.items()}}
    return out


def commands(runs, proxies):
    """Each proxy's command line, from the first run that started it (paths made relative)."""
    out = {}
    for p in proxies:
        for scenario in ("sweep", "ramp", "memory", "soak", "faults"):
            r = result(runs[0], scenario, p)
            if usable(r) and isinstance(r.get("proxyProcess"), dict):
                cmd = r["proxyProcess"].get("command") or []
                out[p] = {"scenario": scenario, "command": sanitize(" ".join(cmd)),
                          "config": r["proxyProcess"].get("config")}
                break
    return out


def clean_version(p, versions, ext):
    v = versions.get(p)
    if p == "envoy" and v and "/" in v:
        m = re.search(r"/(\d+\.\d+\.\d+)/", v)
        return "Envoy " + (m.group(1) if m else v)
    if v:
        return v
    return (ext or {}).get("version")


run_info_commit = [None]


def proxies_meta(runs, proxies):
    data = runs[0]["data"]
    versions = data.get("versions", {})
    ext = data.get("externalProxies", {})
    meta = []
    for i, p in enumerate(proxies):
        e = ext.get(p) or {}
        b = BUILTIN.get(p, {})
        version = clean_version(p, versions, e)
        if p == "microproxy":
            commit = run_info_commit[0]
            version = "MicroProxy " + versions.get("microproxy", "?") + (f" (this repository at {commit[:7]})" if commit else "")
        elif p == "littleproxy":
            version = "io.github.littleproxy:littleproxy " + versions.get("littleproxy", "?")
        slot = CANONICAL.index(p) if p in CANONICAL else i
        meta.append({"id": p, "label": b.get("label") or e.get("label") or p, "language": b.get("language") or e.get("language"),
                     "version": version, "jvm": p in BUILTIN, "slot": slot, "notes": e.get("notes"),
                     "config": e.get("config"), "colorLight": COLORS_LIGHT[slot % 8], "colorDark": COLORS_DARK[slot % 8]})
    return meta


# The settings of the memory scenario, taken from its own runs when they are not the rest's.
MEMORY_SETTINGS = ("attack", "attacks", "slowloris", "slowread", "updown", "rapidreset", "nmt-every")


def memory_dir(runs_dir):
    """The results directory "memoryFrom" in run-info.json names (relative to runs_dir), or None."""
    rel = run_info(runs_dir).get("memoryFrom")
    if not rel:
        return None
    path = os.path.normpath(os.path.join(runs_dir, rel))
    if not os.path.isdir(path):
        sys.exit(f"run-info.json: memoryFrom {rel!r} is not a directory under {runs_dir}")
    return path


def run_list(runs, hosts, raw_prefix):
    return [{"id": r["id"], "timestamp": r["data"]["timestamp"], "order": r["data"]["proxies"],
             "end": datetime.fromtimestamp(r["end"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if r["end"] else None,
             "raw": raw_prefix + r["id"] + ".json", "harnessOk": r["data"].get("harnessOk"),
             "notes": r["data"].get("notes"), "hostLoad": hosts.get(r["id"])} for r in runs]


def build(runs_dir):
    runs = load_runs(runs_dir)
    proxies = proxy_order(runs)
    first = runs[0]["data"]
    settings = first.get("settings", {})
    split = first.get("cpuSplit") or {}
    proxy_cpus = []
    for part in str(split.get("proxy", "")).split(","):
        if "-" in part:
            a, b = part.split("-")
            proxy_cpus += list(range(int(a), int(b) + 1))
        elif part.strip():
            proxy_cpus.append(int(part))
    slo = float(settings.get("slo-p99-ms", 50))
    sweep = aggregate_sweep(runs, proxies, proxy_cpus)
    rate = common_rate(sweep, proxies)
    info = run_info(runs_dir)
    run_info_commit[0] = info.get("commit")
    hosts = host_load(runs_dir, runs)
    env = first.get("environment", {})
    # The memory figures, from this directory's runs or from the one "memoryFrom" names.
    mem_dir = memory_dir(runs_dir)
    mem_runs, mem_info, mem_hosts = runs, info, hosts
    if mem_dir:
        mem_runs = load_runs(mem_dir, is_raw_dir(mem_dir))
        mem_info = run_info(mem_dir)
        mem_hosts = host_load(mem_dir, mem_runs)
        # The memory scenario's own settings (its workloads, caps and sampling) come from its runs.
        mem_settings = mem_runs[0]["data"].get("settings", {})
        settings = dict(settings)
        for k, v in mem_settings.items():
            if k.startswith(MEMORY_SETTINGS):
                settings[k] = v
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "runInfo": info,
        "runs": run_list(runs, hosts, "raw/"),
        "memoryRuns": run_list(mem_runs, mem_hosts, "raw/memory/") if mem_dir else None,
        "memoryRunInfo": mem_info if mem_dir else None,
        "guard": {"foreignCpuMeanMax": GUARD_MEAN, "foreignCpuP95Max": GUARD_P95, "largestGapMaxS": GUARD_MAX_GAP_S,
                  "rejected": info.get("rejected", [])},
        "machine": {"cpuModel": env.get("cpuModel"), "cpus": len(env.get("cpus") or []), "memTotalMb": round((env.get("memTotalKb") or 0) / 1024),
                    "kernel": env.get("kernel"), "distribution": env.get("distribution"), "os": env.get("os"),
                    "java": env.get("java"), "cgroup": env.get("cgroup"), "limits": env.get("limits"), "cpuSplit": split},
        "settings": settings,
        "proxies": proxies_meta(runs, proxies),
        "commands": commands(runs, proxies),
        "sloP99Ms": slo,
        "commonRate": rate,
        "sweep": sweep,
        "ramp": aggregate_ramp(runs, proxies),
        "memory": aggregate_memory(mem_runs, proxies, not_measured(mem_info)),
        "memoryNotMeasured": not_measured(mem_info),
        "soak": aggregate_soak(runs, proxies),
        "faults": aggregate_faults(runs, proxies),
    }


# --- formatting ---------------------------------------------------------------------------------

def fmt(v, digits=0):
    if v is None:
        return "n/a"
    if digits == 0:
        return f"{v:,.0f}"
    return f"{v:,.{digits}f}"


# The number of runs aggregated, so that a figure from fewer runs says so.
RUNS = [0]


def fewer(st):
    """' (n of N runs)' when fewer runs than all measured it (some were left out), else ''."""
    of = st.get("of", RUNS[0]) if st else 0
    if st and 0 < st["n"] < of:
        return f" ({st['n']} of {of} runs)"
    return ""


def med(st, digits=0, unit=""):
    """The median of a stats object, marked ‡ where runs were left out (a note under the table says which)."""
    if not st:
        return "n/a"
    return f"{fmt(st['med'], digits)}{unit}{' ‡' if fewer(st) else ''}"


def spread(st, digits=0, unit=""):
    """'min–max' of a stats object (one value when every run agreed), with the run count."""
    if not st:
        return "n/a"
    return f"{fmt(st['min'], digits)}–{fmt(st['max'], digits)}{unit}{fewer(st)}"


def med_range(st):
    """'median (min–max)', for prose outside the performance page."""
    return f"{fmt(st['med'])} ({fmt(st['min'])}–{fmt(st['max'])})" if st["min"] != st["max"] else fmt(st["med"])


def step_at(sweep, p, rate):
    return next((s for s in sweep[p]["steps"] if s["rate"] == rate), None)


def curve_step(sweep, p, rate):
    """The step at rate if it is on the proxy's curve (sustained in every run used), else None."""
    st = step_at(sweep, p, rate) if rate else None
    return st if st and st["inCurve"] else None


def scoreboard_rows(d):
    """(metric, better, {proxy: stats or None}, digits, unit, key) for the scoreboard and the spread table."""
    ids = [m["id"] for m in d["proxies"]]
    rate = d["commonRate"]
    rows = []
    rows.append(("Max sustainable rate (req/s)", "higher", {p: d["sweep"][p]["maxSustainable"] for p in ids}, 0, "", "maxrate"))
    if rate:
        rows.append((f"Proxy CPU per request at {rate:,} req/s (µs)", "lower",
                     {p: (curve_step(d["sweep"], p, rate) or {}).get("cpuUsPerReq") for p in ids}, 0, "", "cpu"))
        for key, name in (("p50", "p50"), ("p99", "p99"), ("p999", "p99.9")):
            rows.append((f"{name} latency at {rate:,} req/s (ms)", "lower",
                         {p: (curve_step(d["sweep"], p, rate) or {}).get(key) for p in ids}, 2, "", key))
    rows.append(("Idle RSS (MB)", "lower", {p: d["ramp"][p]["idleRssMb"] for p in ids}, 1, "", "idle"))
    rows.append(("RSS per idle connection (KB)", "lower", {p: d["ramp"][p]["rssKbPerConn"] for p in ids}, 1, "", "perconn"))
    last = max((s["target"] for p in ids for s in d["ramp"][p]["steps"]), default=None)
    if last:
        rows.append((f"RSS holding {last:,} idle connections (MB)", "lower",
                     {p: next((s["rssMb"] for s in d["ramp"][p]["steps"] if s["target"] == last), None) for p in ids}, 1, "", "held"))
    for attack, per in d["memory"].items():
        conns = d["settings"].get(f"{attack}-connections") or d["settings"].get("updown-connections")
        label = ATTACK_NAMES.get(attack, attack)
        if attack == "slowread":
            rows.append((f"RSS per slow reader, {conns} readers (KB)", "lower", {p: per[p]["rssKbPerConnection"] for p in ids}, 0, "", "reader"))
        rows.append((f"Peak RSS under {label} (MB, 512 MB cap)", "lower", {p: per[p]["peakRssMb"] for p in ids}, 1, "", attack))
    return rows


ATTACK_NAMES = {"slowread": "slow readers", "slowloris": "slowloris", "updown": "parallel large uploads and downloads"}


def winner(cells, better):
    """The proxy with the best median, if it is clear of the runner-up in every run (its worst run
    beats the runner-up's best); else None."""
    have = [(p, st) for p, st in cells.items() if st]
    if len(have) < 2:
        return None
    key = (lambda x: -x[1]["med"]) if better == "higher" else (lambda x: x[1]["med"])
    have.sort(key=key)
    (bp, bs), (_, rs) = have[0], have[1]
    if bs["med"] == rs["med"]:
        return None
    clear = bs["min"] > rs["max"] if better == "higher" else bs["max"] < rs["min"]
    return bp if clear else None


def knee_kind(reason):
    """A short, number-free description of why a sweep's knee came."""
    if not reason:
        return None
    kinds = []
    for pattern, kind in (("SLO", "p99 over the SLO"), ("errors", "errors"), ("< 95%", "fell behind the offered rate"),
                          ("backlog", "requests left unsent"), ("client-bound", "load generator saturated"),
                          ("proxy", "proxy stopped")):
        if pattern in reason and kind not in kinds:
            kinds.append(kind)
    return ", ".join(kinds) or reason


def knee_kinds(reasons):
    """Every kind of reason the sweeps' knees came for, once each."""
    kinds = []
    for r in reasons:
        for k in (knee_kind(r) or "").split(", "):
            if k and k not in kinds:
                kinds.append(k)
    return ", ".join(kinds)


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def tally(c, runs=None):
    """Verdict counts: the verdict alone when every run (of runs, by default all) agreed, else each with its count."""
    runs = RUNS[0] if runs is None else runs
    if not c:
        return "n/a"
    if len(c) == 1 and runs > 0 and list(c.values())[0] == runs:
        return list(c)[0]
    return ", ".join(f"{k} ×{v}" for k, v in c.items())


def resolution(s, factor):
    """How finely the maximum sustainable rate is known: the widest bracket of the runs used."""
    if not s["maxSustainable"]:
        return "n/a"
    if s["refined"] == "all" and s["bracketWidth"] is not None:
        return f"within {s['bracketWidth'] * 100:.1f}% (refined)"
    if s["refined"] == "none":
        return f"one ×{factor:g} step (not refined)"
    return f"up to {s['bracketWidth'] * 100:.0f}% (some runs refined)" if s["bracketWidth"] is not None else "n/a"


def excluded_note(d, labels, ids, mark=True):
    """A sentence naming the proxies whose sweep figures leave runs out, or ''."""
    parts = []
    for p in ids:
        rows = d["sweep"][p]["runs"]
        out = [r for r in rows if not r["included"]]
        if out:
            parts.append(f"{labels[p]} {len(rows) - len(out)} of {len(rows)}")
    if not parts:
        return ""
    return (("‡ " if mark else "") + "A run whose sweep the load generator ended (it could not keep its own schedule) is left out of every sweep "
            "figure; runs used: " + "; ".join(parts) + ".")


def memory_fewer_note(d, labels, ids):
    """A sentence naming the memory figures that fewer runs measured (the proxy ended before the
    first memory sample), or ''."""
    parts = []
    for attack, per in d["memory"].items():
        for p in ids:
            st = per[p].get("peakRssMb")
            if st and fewer(st):
                parts.append(f"{labels[p]} under {ATTACK_NAMES.get(attack, attack)} ({st['n']} of {st['of']} runs)")
    if not parts:
        return ""
    return ("‡ Measured in fewer runs than all, because in the others the proxy ran out of memory before the first "
            "memory sample: " + "; ".join(parts) + ".")


def tables(d):
    RUNS[0] = len(d["runs"])
    labels = {m["id"]: m["label"] for m in d["proxies"]}
    ids = [m["id"] for m in d["proxies"]]
    factor = float(d["settings"].get("sweep-factor", 1.25))
    t = {}

    # Scoreboard: medians only; bold where the best is clear of the runner-up in every run.
    rows = []
    unrefined = any(d["sweep"][p]["refined"] != "all" and d["sweep"][p]["maxSustainable"] for p in ids)
    for metric, better, cells, digits, unit, key in scoreboard_rows(d):
        if sum(1 for v in cells.values() if v) < 2:
            continue
        best = winner(cells, better)
        row = [metric + (" †" if key == "maxrate" and unrefined else "")]
        for p in ids:
            cell = med(cells.get(p), digits, unit)
            row.append(f"**{cell}**" if p == best else cell)
        rows.append(row)
    notes = []
    if unrefined:
        ex_row = next((r for p in ids for r in d["sweep"][p]["runs"] if r["included"] and r["bracket"] and not r["refined"]), None)
        example = (f": {fmt(ex_row['bracket'][0])} means at least {fmt(ex_row['bracket'][0])} and less than "
                   f"{fmt(ex_row['bracket'][1])}") if ex_row else ""
        notes.append(f"† Not refined: these runs predate knee refinement, so each run's maximum is known only to within one "
                     f"×{factor:g} sweep step{example}.")
    ex = excluded_note(d, labels, ids)
    if ex:
        notes.append(ex)
    mem_note = memory_fewer_note(d, labels, ids)
    if mem_note:
        notes.append(mem_note)
    gone = d.get("memoryNotMeasured") or {}
    if gone:
        notes.append("Not measured on this machine: " + ", ".join(ATTACK_NAMES.get(a, a) for a in gone)
                     + " (see [Adversarial clients](#adversarial-clients-under-a-memory-cap)).")
    t["scoreboard"] = table(["Median of the runs"] + [labels[p] for p in ids], rows) + ("\n\n" + "\n\n".join(notes) if notes else "")

    # The spread behind every median: the lowest and highest run.
    rows = []
    for metric, better, cells, digits, unit, key in scoreboard_rows(d):
        if sum(1 for v in cells.values() if v) < 2:
            continue
        rows.append([metric] + [spread(cells.get(p), digits, unit) for p in ids])
    t["spread"] = table(["Lowest–highest run"] + [labels[p] for p in ids], rows)

    # Rate sweep.
    rows = []
    rate = d["commonRate"]
    for p in ids:
        s = d["sweep"][p]
        if s["unsupported"]:
            rows.append([labels[p], "not supported: " + s["unsupported"]] + ["n/a"] * 4)
            continue
        at = curve_step(d["sweep"], p, rate)
        rows.append([labels[p], med(s["maxSustainable"]), resolution(s, factor),
                     med((at or {}).get("cpuUsPerReq")), med((at or {}).get("p99"), 2),
                     knee_kinds([k for k in s["kneeReasons"] if k]) or "not reached"])
    header = ["Proxy", "Max sustainable rate (req/s)", "Known to within",
              f"CPU per request at {rate:,} req/s (µs)" if rate else "CPU per request (µs)",
              f"p99 at {rate:,} req/s (ms)" if rate else "p99 (ms)", "Why the knee came"]
    notes = []
    known = {r[2] for r in rows if r[2] != "n/a"}
    if len(known) == 1:
        # The same resolution for every proxy: said once, under the table.
        notes.append("Every maximum is known to within " + known.pop().replace("within ", "") + ".")
        header.pop(2)
        rows = [r[:2] + r[3:] for r in rows]
    if ex:
        notes.append(ex)
    t["sweep"] = table(header, rows) + ("\n\n" + "\n\n".join(notes) if notes else "")

    # Per offered rate, on each proxy's curve only (every run used sustained it).
    rates = sorted({st["rate"] for p in ids for st in d["sweep"][p]["steps"] if st["inCurve"]})
    for name, key, digits in (("cpu", "cpuUsPerReq", 0), ("latency", "p99", 2)):
        rows = []
        for r in rates:
            row = [f"{r:,}"]
            for p in ids:
                st = curve_step(d["sweep"], p, r)
                mark = " *" if st and st["sustained"] < st["runs"] else ""
                row.append(fmt(st[key]["med"], digits) + mark if st and st.get(key) else "–")
            rows.append(row)
        t[name] = table(["Offered req/s"] + [f"{labels[p]}" for p in ids], rows)
        notes = []
        if any(" *" in c for row in rows for c in row):
            notes.append("\\* Not sustained in every run: a lone noisy step that the sweep recovered from at the next step.")
        if ex:
            notes.append(excluded_note(d, labels, ids, mark=False))
        if notes:
            t[name] += "\n\n" + "\n\n".join(notes)

    # Memory.
    rows = []
    for p in ids:
        r = d["ramp"][p]
        rows.append([labels[p], med(r["idleRssMb"], 1), med(r["rssKbPerConn"], 1), med(r["maxHeld"]),
                     tally(r["failureKinds"])])
    t["ramp"] = table(["Proxy", "Idle RSS (MB)", "RSS per idle connection (KB)", "Connections held", "Ramp ended"], rows)

    rows = []
    # The socket-buffer column only for runs that measured them (a memory cgroup on cgroup v2 or v1).
    with_sock = any((per[p].get("peakSockMb") or {}).get("n") for per in d["memory"].values() for p in ids)
    mem_runs = len(d.get("memoryRuns") or d["runs"])
    for attack, per in d["memory"].items():
        for p in ids:
            m = per[p]
            if m["skipped"]:
                rows.append([attack, labels[p], "not supported: " + m["skipped"], "n/a", "n/a", "n/a", "n/a", "n/a"])
                continue
            probes = m["probeOkRatio"] and {**m["probeOkRatio"], "med": m["probeOkRatio"]["med"] * 100}
            rows.append([attack, labels[p], tally(m["verdicts"], mem_runs), med(m["peakRssMb"], 1), med(m["rssKbPerConnection"]),
                         med(m.get("peakSockMb"), 1), med(probes, 0, "%"), tally(m["states"], mem_runs)])
    gone = d.get("memoryNotMeasured") or {}
    for attack in gone:
        rows.append([attack, "every proxy", "not measured (see below)", "n/a", "n/a", "n/a", "n/a", "n/a"])
    header = ["Workload", "Proxy", "Verdict", "Peak RSS (MB)", "RSS per connection (KB)",
              "Kernel socket buffers, peak (MB)", "Honest probes answered", "Proxy at the end"]
    if not with_sock:
        header.pop(5)
        rows = [r[:5] + r[6:] for r in rows]
    t["memory"] = table(header, rows)
    if mem_note:
        t["memory"] += "\n\n" + mem_note
    for attack, reason in gone.items():
        t["memory"] += f"\n\n{ATTACK_NAMES.get(attack, attack).capitalize()} were not measured on this machine: {reason}."

    # Soak and faults.
    rows = []
    for p in ids:
        s = d["soak"][p]
        if s["unsupported"]:
            rows.append([labels[p], "not supported", "n/a", "n/a", "n/a"])
            continue
        rows.append([labels[p], tally(s["verdicts"]), med(s["rssSlopeKbPerHour"]), med(s["medianWindowP99Ms"], 2),
                     med(s["errors"])])
    t["soak"] = table(["Proxy", "Leak verdict", "RSS slope (KB/hour)", "Median per-window p99 (ms)", "Errors"], rows)

    fault_names = []
    for p in ids:
        for f in d["faults"][p]["faults"]:
            if f not in fault_names:
                fault_names.append(f)
    rows = []
    for f in fault_names:
        row = [f]
        for p in ids:
            x = d["faults"][p]["faults"].get(f)
            if not x:
                row.append("n/a")
                continue
            out = max(x["outcomes"], key=x["outcomes"].get) if x["outcomes"] else ""
            row.append(f"{x['bounded']}/{x['runs']} bounded; {out}")
        rows.append(row)
    t["faults"] = table(["Fault"] + [labels[p] for p in ids], rows)

    # Versions and commands.
    rows = []
    for m in d["proxies"]:
        cmd = d["commands"].get(m["id"], {}).get("command", "n/a")
        rows.append([m["label"], m["language"] or "", m["version"] or "n/a", f"`{cmd}`"])
    t["versions"] = table(["Proxy", "Language", "Version", "Command line (sweep run)"], rows)

    # What else used the machine during each run (the host monitor), and the guard's verdict.
    rows = []
    for r in d["runs"] + [{**m, "timestamp": m["timestamp"] + " (memory)"} for m in d.get("memoryRuns") or []]:
        h = r.get("hostLoad") or {}
        if not h.get("samples"):
            rows.append([r["timestamp"], "n/a", "n/a", "n/a", "n/a", "no monitor samples"])
            continue
        f = h["foreignCpuPct"]
        top = ", ".join(f"{p['process']} {fmt(p['meanCpuPct'], 1)}%" for p in h["topForeign"][:3] if p["meanCpuPct"] >= 0.1) or "none"
        rows.append([r["timestamp"], f"{fmt(f['mean'], 1)}% / {fmt(f['p95'], 1)}% / {fmt(f['max'], 1)}%",
                     f"{fmt(h['loadavg1']['mean'], 2)} / {fmt(h['loadavg1']['max'], 2)}", top,
                     f"{fmt(h.get('largestGapS'), 1)} s", "accepted" if h["accepted"] else "**rejected**"])
    t["contamination"] = table(["Run (UTC start)", "Foreign CPU, mean / p95 / max (% of one CPU)", "Load average, mean / max",
                                "Busiest outside processes (mean CPU; kernel threads include some interrupt work)",
                                "Longest gap in the monitor's samples", "Guard"], rows)

    # A sentence for the architecture page's backpressure diagram, from the slow-reader runs.
    slow = d["memory"].get("slowread", {})
    lp, mp = (slow.get("littleproxy") or {}).get("rssKbPerConnection"), (slow.get("microproxy") or {}).get("rssKbPerConnection")
    if lp and mp:
        readers = d["settings"].get("slowread-connections")
        n = len(d.get("memoryRuns") or d["runs"])
        t["arch-slowread"] = (f"Measured with {readers} slow readers and each proxy capped at 512 MB, RSS rose by about "
                              f"{med_range(lp)} KB per reader for LittleProxy and {med_range(mp)} KB for MicroProxy (median of "
                              f"{n} runs, lowest–highest in parentheses).")
    elif "slowread" in (d.get("memoryNotMeasured") or {}):
        t["arch-slowread"] = ("The slow-reader workload was not measured on the machine of the current comparison: "
                              + d["memoryNotMeasured"]["slowread"] + ".")
    else:
        t["arch-slowread"] = ""

    mach = d["machine"]
    rows = [["CPU", f"{mach['cpuModel']}, {mach['cpus']} vCPUs"], ["Memory", f"{mach['memTotalMb']:,} MB"],
            ["OS", f"{mach['distribution']}, Linux {mach['kernel']}"], ["JDK", str(mach["java"])],
            ["CPU split (taskset)", ", ".join(f"{k} {v}" for k, v in mach["cpuSplit"].items())],
            ["Runs", f"{len(d['runs'])} ({', '.join(r['timestamp'] for r in d['runs'])} UTC)"]]
    if d["runInfo"].get("commit"):
        rows.append(["Harness commit", d["runInfo"]["commit"]])
    if d.get("memoryRuns"):
        mem = d["memoryRuns"]
        rows.append(["Memory scenario runs", f"{len(mem)} ({', '.join(r['timestamp'] for r in mem)} UTC), run separately"
                     + (f" with the harness at {d['memoryRunInfo']['commit']}" if (d.get("memoryRunInfo") or {}).get("commit") else "")])
    t["machine"] = table(["", ""], rows)
    return t


# --- static SVG charts ---------------------------------------------------------------------------

SVG_STYLE_LIGHT = "".join(f".s{i}{{stroke:{c};fill:{c}}}" for i, c in enumerate(COLORS_LIGHT))
SVG_STYLE_DARK = "".join(f".s{i}{{stroke:{c};fill:{c}}}" for i, c in enumerate(COLORS_DARK))


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


class Svg:
    def __init__(self, w, h, title):
        self.w, self.h, self.parts = w, h, []
        self.title = title

    def add(self, s):
        self.parts.append(s)

    def text(self, x, y, s, cls="t", anchor="start", size=12):
        self.add(f'<text x="{x:.1f}" y="{y:.1f}" class="{cls}" text-anchor="{anchor}" font-size="{size}">{esc(s)}</text>')

    def render(self):
        style = ("text{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;fill:#52514e}"
                 ".h{fill:#0b0b0b;font-weight:600}.g{stroke:#e1e0d9;stroke-width:1;fill:none}"
                 ".a{stroke:#c3c2b7;stroke-width:1;fill:none}.l{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}"
                 ".l.mp{stroke-width:3}.w{stroke-width:1.5;fill:none}.cap{stroke:#d03b3b;stroke-width:1.5;fill:none}"
                 ".med{stroke:#52514e;fill:none}.ref{stroke:#52514e;stroke-width:1;stroke-dasharray:4 3;fill:none}"
                 + SVG_STYLE_LIGHT +
                 ".dot{stroke:#fcfcfb;stroke-width:1.5}.hollow{fill:#fcfcfb}"
                 "@media (prefers-color-scheme: dark){text{fill:#c3c2b7}.h{fill:#f0efec}.g{stroke:#2c2c2a}.a{stroke:#383835}"
                 ".med{stroke:#c3c2b7}.ref{stroke:#c3c2b7}.cap{stroke:#e66767}"
                 + SVG_STYLE_DARK + ".dot{stroke:#1a1a19}.hollow{fill:#1a1a19}}")
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" '
                f'role="img" aria-label="{esc(self.title)}"><title>{esc(self.title)}</title><style>{style}</style>'
                + "".join(self.parts) + "</svg>\n")


def nice_max(v):
    if v <= 0:
        return 1
    import math
    e = 10 ** math.floor(math.log10(v))
    for m in (1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if v <= m * e:
            return m * e
    return 10 * e


def ticks(maxv, n=5):
    step = maxv / n
    return [step * i for i in range(n + 1)]


def tick_label(v):
    if v >= 1000:
        return f"{v / 1000:g}K"
    return f"{v:g}"


def dot_chart(title, sub, meta, rows, unit, digits, note=None):
    """A strip plot: one row per proxy, a dot per run (offset vertically so equal runs stay visible),
    a tick at the median with its value. rows: {id: {"values": [...], "brackets": [[lo, hi] or None],
    "med": v}}; a run's bracket (the range its true value lies in) is drawn as a faint bar behind it."""
    left, right, top, rowh = 130, 90, 54, 34
    w = 720
    h = top + rowh * len(meta) + (54 if note else 36)
    vals = [v for m in meta for v in (rows.get(m["id"]) or {}).get("values", []) if v is not None]
    vals += [b[1] for m in meta for b in (rows.get(m["id"]) or {}).get("brackets", []) if b]
    vmax = nice_max(max(vals, default=1))
    sv = Svg(w, h, title)
    sv.text(0, 18, title, "h", size=14)
    sv.text(0, 36, sub, size=12)
    pw = w - left - right
    X = lambda v: left + pw * v / vmax
    for tv in ticks(vmax):
        sv.add(f'<line class="g" x1="{X(tv):.1f}" y1="{top - 6}" x2="{X(tv):.1f}" y2="{top + rowh * len(meta)}"/>')
        sv.text(X(tv), top + rowh * len(meta) + 16, tick_label(tv), anchor="middle", size=11)
    for i, m in enumerate(meta):
        y = top + i * rowh + rowh / 2
        sv.text(left - 10, y + 4, m["label"], "h" if m["id"] == "microproxy" else "t", anchor="end")
        sv.add(f'<line class="g" x1="{left}" y1="{y:.1f}" x2="{left + pw}" y2="{y:.1f}" style="stroke-dasharray:2 3"/>')
        r = rows.get(m["id"])
        if not r or not r.get("values"):
            sv.text(left + 6, y + 4, "not measured")
            continue
        n = len(r["values"])
        for k, v in enumerate(r["values"]):
            if v is None:
                continue
            dy = (k - (n - 1) / 2) * min(6, 20 / max(1, n - 1))
            br = (r.get("brackets") or [None] * n)[k]
            if br:
                sv.add(f'<rect class="s{m["slot"]}" x="{X(br[0]):.1f}" y="{y + dy - 2:.1f}" width="{max(1, X(br[1]) - X(br[0])):.1f}" height="4" rx="2" style="opacity:.28;stroke:none"/>')
            sv.add(f'<circle class="s{m["slot"]} dot" cx="{X(v):.1f}" cy="{y + dy:.1f}" r="4.5"/>')
        if r.get("med") is not None:
            xm = X(r["med"])
            sv.add(f'<line class="med" x1="{xm:.1f}" y1="{y - 12:.1f}" x2="{xm:.1f}" y2="{y + 12:.1f}" style="stroke-width:2"/>')
            xr = max(X(v) for v in r["values"] if v is not None)
            xr = max([xr] + [X(b[1]) for b in (r.get("brackets") or []) if b])
            sv.text(xr + 10, y + 4, fmt(r["med"], digits) + unit, size=11)
    sv.add(f'<line class="a" x1="{left}" y1="{top - 6}" x2="{left}" y2="{top + rowh * len(meta)}"/>')
    if note:
        sv.text(0, h - 8, note, size=11)
    return sv.render()


def line_chart(title, sub, xlabel, ylabel, series, ymax=None, xmax=None, hline=None, ylog=None, xlog=False):
    """series: [(meta, [[x, y], ...], end_marker or None)]. ylog: (min, max) for a logarithmic y axis;
    xlog: a logarithmic x axis over the points' range (the sweep's geometric steps, evenly spaced)."""
    import math
    left, right, top, bottom = 56, 120, 54, 46
    w, h = 720, 380
    pw, ph = w - left - right, h - top - bottom
    all_x = [p[0] for _, pts, _ in series for p in pts]
    all_y = [p[1] for _, pts, _ in series for p in pts if p[1] is not None]
    xmax = xmax or nice_max(max(all_x, default=1))
    ymax = ymax or nice_max(max(all_y + ([hline[0]] if hline else []), default=1))
    sv = Svg(w, h, title)
    sv.text(0, 18, title, "h", size=14)
    sv.text(0, 36, sub, size=12)
    X = lambda x: left + pw * x / xmax
    xt = ticks(xmax)
    if xlog and all_x:
        x0, x1 = math.log(min(all_x) / 1.15), math.log(max(all_x) * 1.15)
        X = lambda x: left + pw * (math.log(x) - x0) / (x1 - x0)
        xt = [m * 10 ** e for e in range(math.floor(x0 / math.log(10)), math.ceil(x1 / math.log(10)) + 1)
              for m in (1, 2, 5) if x0 <= math.log(m * 10 ** e) <= x1]
    if ylog:
        lo, hi = math.log10(ylog[0]), math.log10(ylog[1])
        Y = lambda y: top + ph - ph * (math.log10(max(y, ylog[0])) - lo) / (hi - lo)
        yt = []
        for e in range(math.floor(lo), math.ceil(hi) + 1):
            for m in (1, 2, 5):
                v = m * 10 ** e
                if ylog[0] <= v <= ylog[1]:
                    yt.append(v)
    else:
        Y = lambda y: top + ph - ph * min(y, ymax) / ymax
        yt = ticks(ymax)
    for tv in yt:
        sv.add(f'<line class="g" x1="{left}" y1="{Y(tv):.1f}" x2="{left + pw}" y2="{Y(tv):.1f}"/>')
        sv.text(left - 6, Y(tv) + 4, tick_label(tv), anchor="end", size=11)
    for tv in xt:
        sv.text(X(tv), top + ph + 16, tick_label(tv), anchor="middle", size=11)
    sv.add(f'<line class="a" x1="{left}" y1="{top + ph}" x2="{left + pw}" y2="{top + ph}"/>')
    sv.text(left + pw / 2, h - 8, xlabel, anchor="middle", size=12)
    sv.add(f'<text x="14" y="{top + ph / 2:.1f}" font-size="12" text-anchor="middle" transform="rotate(-90 14 {top + ph / 2:.1f})">{esc(ylabel)}</text>')
    if hline:
        # A hard limit (a memory cap) in the critical color; a reference (an SLO) as a dashed rule.
        cls = hline[2] if len(hline) > 2 else "cap"
        sv.add(f'<line class="{cls}" x1="{left}" y1="{Y(hline[0]):.1f}" x2="{left + pw}" y2="{Y(hline[0]):.1f}"/>')
        sv.text(left + 4 if cls == "ref" else left + pw - 4, Y(hline[0]) - 5, hline[1], anchor="start" if cls == "ref" else "end", size=11)
    ends = []
    for m, pts, end in series:
        pts = [p for p in pts if p[1] is not None]
        if not pts:
            continue
        d = " ".join(("M" if i == 0 else "L") + f"{X(x):.1f} {Y(y):.1f}" for i, (x, y) in enumerate(pts))
        cls = "l mp" if m["id"] == "microproxy" else "l"
        sv.add(f'<path class="{cls} s{m["slot"]}" style="fill:none" d="{d}"/>')
        for x, y in pts[:-1]:
            sv.add(f'<circle class="s{m["slot"]}" cx="{X(x):.1f}" cy="{Y(y):.1f}" r="3"/>')
        ex, ey = X(pts[-1][0]), Y(pts[-1][1])
        if end == "knee":
            # The last offered rate every run sustained: the curve stops here, at the knee.
            sv.add(f'<circle class="s{m["slot"]} hollow" cx="{ex:.1f}" cy="{ey:.1f}" r="5" style="stroke-width:2.5"/>')
        elif end:
            sv.add(f'<path class="s{m["slot"]}" style="stroke-width:3" d="M{ex - 6:.1f} {ey - 6:.1f}L{ex + 6:.1f} {ey + 6:.1f}M{ex + 6:.1f} {ey - 6:.1f}L{ex - 6:.1f} {ey + 6:.1f}"/>')
        else:
            sv.add(f'<circle class="s{m["slot"]}" cx="{ex:.1f}" cy="{ey:.1f}" r="3"/>')
        ends.append([ey, m, ex])
    # End labels at the right edge, nudged apart to stay legible (each with a short key line in the series color).
    ends.sort(key=lambda e: e[0])
    for i in range(1, len(ends)):
        if ends[i][0] - ends[i - 1][0] < 14:
            ends[i][0] = ends[i - 1][0] + 14
    for y, m, ex in ends:
        sv.add(f'<line class="s{m["slot"]}" style="stroke-width:3" x1="{left + pw + 6}" y1="{y:.1f}" x2="{left + pw + 18}" y2="{y:.1f}"/>')
        sv.text(left + pw + 22, y + 4, m["label"], "h" if m["id"] == "microproxy" else "t", size=11)
    return sv.render()


def charts(d):
    meta = d["proxies"]
    out = {}
    n = len(d["runs"])
    factor = float(d["settings"].get("sweep-factor", 1.25))
    rows = {}
    unrefined = False
    for m in meta:
        s = d["sweep"][m["id"]]
        inc = [r for r in s["runs"] if r["included"]]
        rows[m["id"]] = {"values": [r["max"] for r in inc], "brackets": [r["bracket"] for r in inc],
                         "med": (s["maxSustainable"] or {}).get("med")}
        unrefined = unrefined or any(not r["refined"] for r in inc)
    out["max-rate.svg"] = dot_chart("Max sustainable rate (requests/s, higher is better)",
                                    f"One dot per run ({n} runs), the tick at the median. One CPU per proxy; p99 within {d['sloP99Ms']:g} ms.",
                                    meta, rows, "/s", 0,
                                    note=(f"Not refined: the faint bar behind each dot is the ×{factor:g} sweep step its true maximum lies in."
                                          if unrefined else "The faint bar behind each dot is the bracket its true maximum lies in."))
    def curve(key):
        series = []
        for m in meta:
            pts = [[s["rate"], s[key]["med"]] for s in d["sweep"][m["id"]]["steps"] if s["inCurve"] and s.get(key)]
            series.append((m, pts, "knee" if d["sweep"][m["id"]]["curveEndRate"] else None))
        return series
    cpu = curve("cpuUsPerReq")
    out["cpu-per-request.svg"] = line_chart("Proxy CPU time per request (µs, lower is better)",
                                            f"Median of the runs at each offered rate; each line stops at the last rate every run sustained (○).",
                                            "offered load (requests/s, log scale)", "CPU per request (µs)", cpu, xlog=True)
    lat = curve("p99")
    ys = [p[1] for _, pts, _ in lat for p in pts]
    lo = 10 ** math.floor(math.log10(max(min(ys, default=1), 0.01)))
    out["latency-p99.svg"] = line_chart("p99 latency vs offered load (lower is better)",
                                        f"Median of the runs, corrected for coordinated omission; each line stops at the last rate every run sustained (○).",
                                        "offered load (requests/s, log scale)", "p99 latency (ms, log scale)", lat, xlog=True,
                                        ylog=(lo, max(100, nice_max(max(ys, default=1)))),
                                        hline=(d["sloP99Ms"], f"SLO: p99 {d['sloP99Ms']:g} ms", "ref"))
    rows = {m["id"]: {"values": (d["ramp"][m["id"]]["idleRssMb"] or {}).get("values", []),
                      "med": (d["ramp"][m["id"]]["idleRssMb"] or {}).get("med")} for m in meta}
    out["idle-rss.svg"] = dot_chart("Idle RSS (MB, lower is better)",
                                    f"Resident memory after start-up and a few validation requests; one dot per run, the tick at the median.",
                                    meta, rows, " MB", 1)
    series = []
    for m in meta:
        pts = [[s["held"]["med"], s["rssMb"]["med"]] for s in d["ramp"][m["id"]]["steps"] if s["rssMb"] and s["held"]]
        series.append((m, pts, None))
    out["ramp-rss.svg"] = line_chart("RSS vs idle keep-alive connections (lower is better)",
                                     f"Median of {n} runs; each connection made one request, then idled.",
                                     "idle connections held", "RSS (MB)", series)
    if "slowread" in d["memory"]:
        per = d["memory"]["slowread"]
        series = []
        for m in meta:
            s = per[m["id"]]["series"]
            if s:
                series.append((m, s["points"], s["end"]))
        readers = d["settings"].get("slowread-connections")
        beside = any((per[m["id"]].get("cap") or {}).get("socketBuffers") == "beside the limit" for m in meta)
        cap = ("Each proxy's own memory capped at 512 MB, its kernel socket buffers beside the cap" if beside
               else "Each proxy in a 512 MB memory cgroup")
        out["slowread-rss.svg"] = line_chart(f"RSS while {readers} slow readers download (lower is better)",
                                             cap + "; the run with the median peak; ✕ = out of memory or crash.",
                                             "seconds since the readers started", "RSS (MB)", series, ymax=560,
                                             hline=(512, "512 MB cgroup limit"))
    return out


# --- output ---------------------------------------------------------------------------------------

def replace_markers(path, blocks):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for name, body in blocks.items():
        pattern = re.compile(r"(<!-- perf:%s -->).*?(<!-- /perf:%s -->)" % (re.escape(name), re.escape(name)), re.S)
        if not pattern.search(text):
            continue
        text = pattern.sub(lambda m: m.group(1) + "\n\n" + body + "\n\n" + m.group(2), text)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def option(argv, name):
    return argv[argv.index(name) + 1] if name in argv else None


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    raw_dir = option(argv, "--raw")
    RAW[0] = raw_dir is not None
    runs_dir = raw_dir or argv[1]
    publish = option(argv, "--publish")
    data = build(runs_dir)
    unclean = [r["id"] for r in data["runs"] + (data["memoryRuns"] or []) if not (r.get("hostLoad") or {}).get("accepted")]
    if publish and unclean and "--allow-unguarded" not in argv:
        sys.exit("not publishing: runs failed the contamination guard or have no host monitor samples: "
                 + ", ".join(unclean) + " (reject them in run-info.json, or pass --allow-unguarded for a local preview)")
    out = option(argv, "--out") or (os.path.join(ROOT, "loadtest", "results", "aggregate-raw") if RAW[0]
                                    else os.path.join(runs_dir, "aggregate"))
    os.makedirs(out, exist_ok=True)
    tbl = tables(data)
    svgs = charts(data)
    # The page draws from the median series; the per-run series stay in the raw files.
    page = json.loads(json.dumps(data))
    for per in page["memory"].values():
        for v in per.values():
            v.pop("allSeries", None)
    with open(os.path.join(out, "results.json"), "w", encoding="utf-8") as f:
        f.write(strip_root(json.dumps(page, indent=1, ensure_ascii=False)))
        f.write("\n")
    for name, svg in svgs.items():
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(svg)
    with open(os.path.join(out, "tables.md"), "w", encoding="utf-8") as f:
        for name, body in tbl.items():
            f.write(f"<!-- perf:{name} -->\n\n{body}\n\n<!-- /perf:{name} -->\n\n")
    print(f"aggregated {len(data['runs'])} runs of {len(data['proxies'])} proxies into {out}")
    if publish:
        assets = os.path.join(publish, "assets", "perf")
        os.makedirs(os.path.join(assets, "raw"), exist_ok=True)
        shutil.copy(os.path.join(out, "results.json"), os.path.join(assets, "results.json"))
        for name in svgs:
            shutil.copy(os.path.join(out, name), os.path.join(assets, name))
        # A chart these runs do not draw (a workload not measured) must not outlive the data it came from.
        for old in glob.glob(os.path.join(assets, "*.svg")):
            if os.path.basename(old) not in svgs:
                os.remove(old)
        raw_dest = os.path.join(assets, "raw")
        if not (RAW[0] and os.path.realpath(runs_dir) == os.path.realpath(raw_dest)):
            publish_raw(runs_dir, raw_dest)
        mem_dir = memory_dir(runs_dir)
        mem_dest = os.path.join(raw_dest, "memory")
        if mem_dir and os.path.realpath(mem_dir) != os.path.realpath(mem_dest):
            # Published beside the rest (replacing earlier memory runs, also when the other runs are
            # read from raw/ itself), and run-info.json pointed at the copy.
            if os.path.isdir(mem_dest):
                shutil.rmtree(mem_dest)
            publish_raw(mem_dir, mem_dest)
            info_path = os.path.join(raw_dest, "run-info.json")
            info = run_info(raw_dest)
            info["memoryFrom"] = "memory"
            with open(info_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(info, indent=1, ensure_ascii=False) + "\n")
        page_md = os.path.join(publish, "project", "performance.md")
        if os.path.exists(page_md):
            replace_markers(page_md, tbl)
        arch_md = os.path.join(publish, "architecture.md")
        if os.path.exists(arch_md):
            replace_markers(arch_md, {"arch-slowread": tbl["arch-slowread"]})
        print(f"published into {assets} and {page_md}")


def publish_raw(runs_dir, dest):
    """Each run's raw results (minified, repository paths made relative), what was run, and the host
    monitor's log, into dest (the page's raw/ directory, or a directory under it)."""
    os.makedirs(dest, exist_ok=True)
    for r in load_runs(runs_dir, is_raw_dir(runs_dir)):
        with open(r["file"], encoding="utf-8") as f:
            raw = json.load(f)
        with open(os.path.join(dest, r["id"] + ".json"), "w", encoding="utf-8") as f:
            f.write(strip_root(json.dumps(raw, separators=(",", ":"), ensure_ascii=False)))
            f.write("\n")
    # The guard's evidence and what was run, beside the raw results.
    info_src = os.path.join(runs_dir, "run-info.json")
    if os.path.exists(info_src):
        shutil.copy(info_src, os.path.join(dest, "run-info.json"))
    # The host monitor's log, with other processes' command lines reduced to their program names
    # (they hold paths of other work on the machine, which is not this page's to publish).
    mon_src = os.path.join(runs_dir, "hostmon.jsonl")
    if os.path.exists(mon_src):
        with open(mon_src, encoding="utf-8") as fin, open(os.path.join(dest, "hostmon.jsonl"), "w", encoding="utf-8") as fout:
            for line in fin:
                if not line.strip():
                    continue
                x = json.loads(line)
                x["topForeign"] = [{"cpuPct": p["cpuPct"], "program": p.get("program") or program(p.get("cmd"))}
                                   for p in x.get("topForeign", [])]
                fout.write(json.dumps(x, separators=(",", ":")) + "\n")
    # The Windows host's log on WSL2: its totals only (the processes of the person's own desktop are
    # not this page's to publish).
    win_src = os.path.join(runs_dir, "winmon.jsonl")
    if os.path.exists(win_src):
        with open(win_src, encoding="utf-8") as fin, open(os.path.join(dest, "winmon.jsonl"), "w", encoding="utf-8") as fout:
            for line in fin:
                if line.strip():
                    x = json.loads(line)
                    fout.write(json.dumps({"t": x["t"], "windowsForeignCpuPct": x["windowsForeignCpuPct"]}, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main(sys.argv)
