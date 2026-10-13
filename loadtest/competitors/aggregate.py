#!/usr/bin/env python3
"""Aggregates repeated runs of the load-testing harness into the data of the performance page.

    python3 -I loadtest/competitors/aggregate.py <runs dir> [--publish <docs dir>] [--allow-unguarded]

<runs dir> holds one harness results directory per repetition (rep1/<timestamp>/results.json, ...,
as run-all.sh writes them). For every proxy, scenario and measure it takes the median over the
repetitions and the minimum and maximum (the spread), and writes into <runs dir>/aggregate/:

  results.json   the page's data: machine, versions, settings, command lines, and every aggregate
  *.svg          static charts, for readers without JavaScript (and GitHub)
  tables.md      the Markdown tables of the page

Runs listed under "rejected" in <runs dir>/run-info.json are left out. Every other run must pass
the contamination guard, read from <runs dir>/hostmon.jsonl (written by hostmon.py while the runs
ran): the CPU the machine spent outside the benchmark's processes must average at most 50% of one
CPU over the run, with a 95th percentile of at most 100%. --publish refuses runs that fail it or
were not monitored (--allow-unguarded overrides that, for a local preview only).

With --publish it also copies them into <docs dir>/assets/perf/, copies each repetition's raw
results.json (minified) to <docs dir>/assets/perf/raw/, and rewrites the generated tables of
<docs dir>/project/performance.md, between its <!-- perf:NAME --> and <!-- /perf:NAME --> markers.

Only the standard library is used. Nothing here invents a number: a value missing from the runs is
missing from the output (null, or "n/a" in the tables).
"""
import glob
import json
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

def load_runs(runs_dir):
    """Every rep*/<timestamp>/results.json, except the runs that run-info.json rejects."""
    rejected = {r["rep"] for r in run_info(runs_dir).get("rejected", [])}
    files = sorted(set(os.path.realpath(p) for p in glob.glob(os.path.join(runs_dir, "rep*", "*", "results.json"))))
    runs = []
    for f in files:
        rep = os.path.basename(os.path.dirname(os.path.dirname(f)))
        if rep in rejected:
            continue
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        runs.append({"id": rep + "-" + data["timestamp"], "rep": rep, "file": f, "data": data,
                     "start": datetime.strptime(data["timestamp"], "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc).timestamp(),
                     "end": os.path.getmtime(f)})
    if not runs:
        sys.exit("no rep*/<timestamp>/results.json under " + runs_dir)
    return runs


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


def program(cmd):
    """A foreign process's program, without its arguments or paths: what the page may show."""
    if not cmd:
        return "?"
    if cmd.startswith("["):
        return "kernel thread"
    name = cmd.split()[0].rsplit("/", 1)[-1]
    # The command-line agent that drove the runs from its own session.
    return "agent session" if name == "claude" else name


def host_load(runs_dir, runs):
    """Per run: the host monitor's foreign CPU and load average while it ran, and the guard's verdict."""
    path = os.path.join(runs_dir, "hostmon.jsonl")
    samples = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            samples = [json.loads(line) for line in f if line.strip()]
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
                name = program(p["cmd"])
                procs[name] = procs.get(name, 0.0) + p["cpuPct"] / len(win)
        top = sorted(procs.items(), key=lambda kv: -kv[1])[:5]
        mean = statistics.mean(foreign)
        p95 = foreign[min(len(foreign) - 1, int(len(foreign) * 0.95))]
        out[r["id"]] = {"samples": len(win), "foreignCpuPct": {"mean": rnd(mean, 1), "p95": rnd(p95, 1), "max": rnd(foreign[-1], 1)},
                        "loadavg1": {"mean": rnd(statistics.mean(x["loadavg"][0] for x in win), 2),
                                     "max": rnd(max(x["loadavg"][0] for x in win), 2)},
                        "interruptCpuPct": rnd(statistics.mean(x.get("interruptCpuPct", 0) for x in win), 1),
                        "stealCpuPct": rnd(statistics.mean(x.get("stealCpuPct", 0) for x in win), 1),
                        "topForeign": [{"process": n, "meanCpuPct": rnd(v, 1)} for n, v in top],
                        "accepted": mean <= GUARD_MEAN and p95 <= GUARD_P95}
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
    text = re.sub(r"(<repo>/)?loadtest/results/[^ ]*/logs/", "<logs>/", text)
    text = re.sub(r"/tmp/[^ ]*/logs/", "<logs>/", text)
    text = re.sub(r"-Xlog:gc:file=[^ :]*", "-Xlog:gc:file=<logs>/gc.log", text)
    text = re.sub(r"--port \d+", "--port <port>", text)
    text = re.sub(r"127\.0\.0\.1:\d{4,5}", "127.0.0.1:<port>", text)
    text = re.sub(r"/sys/fs/cgroup/memory/[^' ]*", "<cgroup>", text)
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


def aggregate_sweep(runs, proxies, proxy_cpus):
    out = {}
    for p in proxies:
        by_rate = {}
        maxes, knees, transients, stops, foreign, client_bound_runs = [], [], [], [], [], []
        unsupported = None
        for run in runs:
            r = result(run, "sweep", p)
            if r is not None and "unsupported" in r:
                unsupported = r["unsupported"]
            if not usable(r):
                continue
            client_bound = "client-bound" in (r.get("stopReason") or "")
            if client_bound:
                # The load generator, not the proxy, ended this sweep: its maximum says nothing about the proxy.
                client_bound_runs.append(run["id"])
            else:
                maxes.append(r.get("maxSustainableRate"))
            knees.append(None if client_bound else r.get("kneeReason"))
            stops.append(r.get("stopReason"))
            transients.append(len(r.get("transientSteps") or []))
            f = foreign_on(r.get("series") or {}, proxy_cpus)
            if f is not None:
                foreign.append(f)
            for s in r.get("steps", []):
                key = int(round(s["targetRate"]))
                b = by_rate.setdefault(key, {"achieved": [], "p50": [], "p90": [], "p99": [], "p999": [], "max": [],
                                             "cpu": [], "foreign": [], "sustained": 0, "saturated": 0, "runs": 0,
                                             "errors": [], "spectra": []})
                if s.get("clientSaturated"):
                    # The harness discards a step where the load generator fell behind; so does the page.
                    b["saturated"] += 1
                    continue
                lat = s.get("latencyMs") or {}
                b["runs"] += 1
                b["achieved"].append(s.get("achievedRate"))
                for k in ("p50", "p90", "p99", "p999", "max"):
                    b[k].append(lat.get(k))
                res = s.get("proxy") or {}
                b["cpu"].append(res.get("cpuPct"))
                b["foreign"].append(res.get("foreignCpuPct"))
                b["errors"].append(s.get("errorCount"))
                b["sustained"] += 1 if s.get("sustainable") else 0
                if s.get("percentilesMs"):
                    b["spectra"].append(s["percentilesMs"])
        steps = []
        for rate in sorted(by_rate):
            b = by_rate[rate]
            spectrum = None
            if b["spectra"]:
                pts = []
                for i, (pct, _) in enumerate(b["spectra"][0]):
                    vals = [sp[i][1] for sp in b["spectra"] if i < len(sp)]
                    st = stats(vals)
                    pts.append([pct, st["med"], st["min"], st["max"]])
                spectrum = pts
            steps.append({"rate": rate, "runs": b["runs"], "sustained": b["sustained"], "clientSaturated": b["saturated"],
                          "achieved": stats(b["achieved"]), "p50": stats(b["p50"]), "p90": stats(b["p90"]),
                          "p99": stats(b["p99"]), "p999": stats(b["p999"]), "max": stats(b["max"]),
                          "cpuPct": stats(b["cpu"]), "foreignCpuPct": stats(b["foreign"]), "errors": stats(b["errors"]),
                          "percentiles": spectrum})
        steps = [st for st in steps if st["runs"] > 0]
        out[p] = {"unsupported": unsupported, "maxSustainable": stats(maxes), "clientBoundRuns": client_bound_runs,
                  "maxSustainableRuns": [m for m in maxes], "kneeReasons": knees, "stopReasons": stops,
                  "transientSteps": transients, "foreignOnProxyCpuPct": stats(foreign), "steps": steps}
    return out


def common_rate(sweep, proxies, slo):
    """The highest offered rate every proxy sustained in a majority of its runs (p99 within the SLO)."""
    best = None
    rates = sorted({s["rate"] for p in proxies for s in sweep[p]["steps"]})
    for rate in rates:
        ok = True
        for p in proxies:
            step = next((s for s in sweep[p]["steps"] if s["rate"] == rate), None)
            if step is None or step["sustained"] * 2 <= step["runs"] or step["p99"] is None or step["p99"]["med"] > slo:
                ok = False
                break
        if ok:
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


def aggregate_memory(runs, proxies):
    attacks = []
    for run in runs:
        for a in run["data"].get("settings", {}).get("attacks", "").split(","):
            if a and a not in attacks:
                attacks.append(a)
    out = {}
    for attack in attacks:
        per = {}
        for p in proxies:
            verdicts, peaks, bases, per_conn, series, states, probes, caps, shed = [], [], [], [], [], [], [], [], []
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
                      "series": median_series, "allSeries": series}
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
    rate = common_rate(sweep, proxies, slo)
    info = run_info(runs_dir)
    run_info_commit[0] = info.get("commit")
    hosts = host_load(runs_dir, runs)
    env = first.get("environment", {})
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "runInfo": info,
        "runs": [{"id": r["id"], "timestamp": r["data"]["timestamp"], "order": r["data"]["proxies"],
                  "raw": "raw/" + r["id"] + ".json", "harnessOk": r["data"].get("harnessOk"),
                  "notes": r["data"].get("notes"), "hostLoad": hosts.get(r["id"])} for r in runs],
        "guard": {"foreignCpuMeanMax": GUARD_MEAN, "foreignCpuP95Max": GUARD_P95,
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
        "memory": aggregate_memory(runs, proxies),
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


def spread(st, digits=0, unit=""):
    """'median (min–max)' of a stats object; '(n runs)' when fewer runs than all measured it."""
    if not st:
        return "n/a"
    fewer = f" ({st['n']} run{'s' if st['n'] > 1 else ''})" if 0 < st["n"] < RUNS[0] else ""
    if st["n"] == 1 or st["min"] == st["max"]:
        return f"{fmt(st['med'], digits)}{unit}{fewer}"
    return f"{fmt(st['med'], digits)}{unit} ({fmt(st['min'], digits)}–{fmt(st['max'], digits)}){fewer}"


def step_at(sweep, p, rate):
    return next((s for s in sweep[p]["steps"] if s["rate"] == rate), None)


def scoreboard_rows(d):
    """(metric, better, {proxy: stats or None}, digits, unit) for the scoreboard."""
    ids = [m["id"] for m in d["proxies"]]
    rate = d["commonRate"]
    rows = []
    rows.append(("Max sustainable rate (req/s)", "higher", {p: d["sweep"][p]["maxSustainable"] for p in ids}, 0, ""))
    if rate:
        for key, name in (("p50", "p50"), ("p99", "p99"), ("p999", "p99.9")):
            rows.append((f"{name} latency at {rate:,} req/s (ms)", "lower",
                         {p: (step_at(d["sweep"], p, rate) or {}).get(key) for p in ids}, 2, ""))
    rows.append(("Idle RSS (MB)", "lower", {p: d["ramp"][p]["idleRssMb"] for p in ids}, 1, ""))
    rows.append(("RSS per idle connection (KB)", "lower", {p: d["ramp"][p]["rssKbPerConn"] for p in ids}, 1, ""))
    last = max((s["target"] for p in ids for s in d["ramp"][p]["steps"]), default=None)
    if last:
        rows.append((f"RSS holding {last:,} idle connections (MB)", "lower",
                     {p: next((s["rssMb"] for s in d["ramp"][p]["steps"] if s["target"] == last), None) for p in ids}, 1, ""))
    names = {"slowread": "slow readers", "slowloris": "slowloris", "updown": "parallel large uploads and downloads"}
    for attack, per in d["memory"].items():
        conns = d["settings"].get(f"{attack}-connections") or d["settings"].get("updown-connections")
        label = names.get(attack, attack)
        if attack == "slowread":
            rows.append((f"RSS per slow reader, {conns} readers (KB)", "lower", {p: per[p]["rssKbPerConnection"] for p in ids}, 0, ""))
        rows.append((f"Peak RSS under {label} (MB, 512 MB cap)", "lower", {p: per[p]["peakRssMb"] for p in ids}, 1, ""))
    return rows


def winner(cells, better):
    """The proxy with the best median (None on a tie), and whether its range overlaps the runner-up's."""
    have = [(p, st) for p, st in cells.items() if st]
    if len(have) < 2:
        return None, False
    key = (lambda x: -x[1]["med"]) if better == "higher" else (lambda x: x[1]["med"])
    have.sort(key=key)
    (bp, bs), (_, rs) = have[0], have[1]
    if bs["med"] == rs["med"]:
        return None, True
    overlap = (bs["min"] <= rs["max"]) if better == "higher" else (bs["max"] >= rs["min"])
    return bp, overlap


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


def tables(d):
    RUNS[0] = len(d["runs"])
    labels = {m["id"]: m["label"] for m in d["proxies"]}
    ids = [m["id"] for m in d["proxies"]]
    t = {}

    # Scoreboard.
    rows = []
    for metric, better, cells, digits, unit in scoreboard_rows(d):
        if sum(1 for v in cells.values() if v) < 2:
            continue
        best, overlap = winner(cells, better)
        row = [metric]
        for p in ids:
            cell = spread(cells.get(p), digits, unit)
            if p == best:
                cell = f"**{cell}**"
            row.append(cell)
        row.append("tie" if best is None else labels[best] + (" (ranges overlap)" if overlap else ""))
        rows.append(row)
    t["scoreboard"] = table(["Metric (median, min–max of the runs)"] + [labels[p] for p in ids] + ["Best median"], rows)

    # Rate sweep.
    rows = []
    rate = d["commonRate"]
    for p in ids:
        s = d["sweep"][p]
        if s["unsupported"]:
            rows.append([labels[p], "not supported: " + s["unsupported"]] + ["n/a"] * 5)
            continue
        at = step_at(d["sweep"], p, rate) if rate else None
        knees = [k for k in s["kneeReasons"] if k]
        sat = sum(st["clientSaturated"] for st in s["steps"])
        cb = len(s["clientBoundRuns"])
        rows.append([labels[p], spread(s["maxSustainable"]) + (f" ({cb} run{'s' if cb > 1 else ''} ended by the load generator, left out)" if cb else ""),
                     spread((at or {}).get("p99"), 2), spread((at or {}).get("p999"), 2),
                     spread((at or {}).get("cpuPct"), 0, "%"),
                     knee_kinds(knees) or "not reached", str(sat)])
    t["sweep"] = table(["Proxy", "Max sustainable rate (req/s)", f"p99 at {rate:,} req/s (ms)" if rate else "p99 (ms)",
                        f"p99.9 at {rate:,} req/s (ms)" if rate else "p99.9 (ms)", "Proxy CPU at that rate",
                        "Why the knee came", "Steps discarded (load generator behind)"], rows)

    # Latency per offered rate (every step, median of the runs).
    rates = sorted({st["rate"] for p in ids for st in d["sweep"][p]["steps"]})
    rows = []
    for r in rates:
        row = [f"{r:,}"]
        for p in ids:
            st = step_at(d["sweep"], p, r)
            if not st or not st["p99"]:
                row.append("–")
            else:
                mark = "" if st["sustained"] * 2 > st["runs"] else " ✗"
                row.append(f"{fmt(st['p99']['med'], 2)}{mark}" + (f" ({st['runs']} run{'s' if st['runs'] > 1 else ''})" if st["runs"] != len(d["runs"]) else ""))
        rows.append(row)
    t["latency"] = table(["Offered req/s"] + [labels[p] + " p99 (ms)" for p in ids], rows)

    # Memory.
    rows = []
    for p in ids:
        r = d["ramp"][p]
        held = r["maxHeld"]
        rows.append([labels[p], spread(r["idleRssMb"], 1), spread(r["rssKbPerConn"], 1), spread(held),
                     ", ".join(f"{k} ×{v}" for k, v in r["failureKinds"].items()) or "n/a"])
    t["ramp"] = table(["Proxy", "Idle RSS (MB)", "RSS per idle connection (KB)", "Connections held", "Ramp ended"], rows)

    rows = []
    for attack, per in d["memory"].items():
        for p in ids:
            m = per[p]
            if m["skipped"]:
                rows.append([attack, labels[p], "not supported: " + m["skipped"], "n/a", "n/a", "n/a", "n/a"])
                continue
            verdicts = ", ".join(f"{k} ×{v}" for k, v in m["verdicts"].items()) or "n/a"
            rows.append([attack, labels[p], verdicts, spread(m["peakRssMb"], 1), spread(m["rssKbPerConnection"]),
                         spread(m["probeOkRatio"] and {**m["probeOkRatio"], **{k: m["probeOkRatio"][k] * 100 for k in ("med", "min", "max")}}, 0, "%"),
                         ", ".join(f"{k} ×{v}" for k, v in m["states"].items())])
    t["memory"] = table(["Workload", "Proxy", "Verdicts", "Peak RSS (MB)", "RSS per connection (KB)", "Honest probes answered",
                         "Proxy at the end"], rows)

    # Soak and faults.
    rows = []
    for p in ids:
        s = d["soak"][p]
        if s["unsupported"]:
            rows.append([labels[p], "not supported", "n/a", "n/a", "n/a"])
            continue
        rows.append([labels[p], ", ".join(f"{k} ×{v}" for k, v in s["verdicts"].items()) or "n/a",
                     spread(s["rssSlopeKbPerHour"]), spread(s["medianWindowP99Ms"], 2), spread(s["errors"])])
    t["soak"] = table(["Proxy", "Leak verdicts", "RSS slope (KB/hour)", "Median per-window p99 (ms)", "Errors"], rows)

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
    for r in d["runs"]:
        h = r.get("hostLoad") or {}
        if not h.get("samples"):
            rows.append([r["timestamp"], "n/a", "n/a", "n/a", "no monitor samples"])
            continue
        f = h["foreignCpuPct"]
        top = ", ".join(f"{p['process']} {fmt(p['meanCpuPct'], 1)}%" for p in h["topForeign"][:3] if p["meanCpuPct"] >= 0.1) or "none"
        rows.append([r["timestamp"], f"{fmt(f['mean'], 1)}% / {fmt(f['p95'], 1)}% / {fmt(f['max'], 1)}%",
                     f"{fmt(h['loadavg1']['mean'], 2)} / {fmt(h['loadavg1']['max'], 2)}", top,
                     "accepted" if h["accepted"] else "**rejected**"])
    t["contamination"] = table(["Run (UTC start)", "Foreign CPU, mean / p95 / max (% of one CPU)", "Load average, mean / max",
                                "Busiest outside processes (mean CPU; kernel threads include some interrupt work)", "Guard"], rows)

    # A sentence for the architecture page's backpressure diagram, from the slow-reader runs.
    slow = d["memory"].get("slowread", {})
    lp, mp = (slow.get("littleproxy") or {}).get("rssKbPerConnection"), (slow.get("microproxy") or {}).get("rssKbPerConnection")
    if lp and mp:
        readers = d["settings"].get("slowread-connections")
        t["arch-slowread"] = (f"Measured with {readers} slow readers and each proxy capped at 512 MB, RSS rose by about "
                              f"{spread(lp)} KB per reader for LittleProxy and {spread(mp)} KB for MicroProxy (median of "
                              f"{len(d['runs'])} runs, lowest–highest in parentheses).")
    else:
        t["arch-slowread"] = ""

    mach = d["machine"]
    rows = [["CPU", f"{mach['cpuModel']}, {mach['cpus']} vCPUs"], ["Memory", f"{mach['memTotalMb']:,} MB"],
            ["OS", f"{mach['distribution']}, Linux {mach['kernel']}"], ["JDK", str(mach["java"])],
            ["CPU split (taskset)", ", ".join(f"{k} {v}" for k, v in mach["cpuSplit"].items())],
            ["Runs", f"{len(d['runs'])} ({', '.join(r['timestamp'] for r in d['runs'])} UTC)"]]
    if d["runInfo"].get("commit"):
        rows.append(["Harness commit", d["runInfo"]["commit"]])
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
                 + SVG_STYLE_LIGHT +
                 "@media (prefers-color-scheme: dark){text{fill:#c3c2b7}.h{fill:#f0efec}.g{stroke:#2c2c2a}.a{stroke:#383835}"
                 + SVG_STYLE_DARK + "}")
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


def bar_chart(title, sub, meta, cells, unit, digits):
    rows = [(m, cells.get(m["id"])) for m in meta]
    left, right, top, rowh = 150, 70, 54, 30
    w, h = 720, top + rowh * len(rows) + 40
    vmax = nice_max(max((c["max"] for _, c in rows if c), default=1))
    sv = Svg(w, h, title)
    sv.text(0, 18, title, "h", size=14)
    sv.text(0, 36, sub, size=12)
    pw = w - left - right
    for tv in ticks(vmax):
        x = left + pw * tv / vmax
        sv.add(f'<line class="g" x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" y2="{top + rowh * len(rows)}"/>')
        sv.text(x, top + rowh * len(rows) + 16, tick_label(tv), anchor="middle", size=11)
    for i, (m, c) in enumerate(rows):
        y = top + i * rowh + rowh / 2
        sv.text(left - 8, y + 4, m["label"], anchor="end")
        if not c:
            sv.text(left + 4, y + 4, "not measured")
            continue
        bw = pw * c["med"] / vmax
        sv.add(f'<rect class="s{m["slot"]}" x="{left}" y="{y - 8}" width="{max(bw, 1):.1f}" height="16" rx="3"/>')
        x1, x2 = left + pw * c["min"] / vmax, left + pw * c["max"] / vmax
        sv.add(f'<path class="a" style="stroke-width:1.5" d="M{x1:.1f} {y}H{x2:.1f}M{x1:.1f} {y - 5}V{y + 5}M{x2:.1f} {y - 5}V{y + 5}"/>')
        sv.text(max(bw, x2 - left) + left + 6, y + 4, fmt(c["med"], digits) + unit, size=11)
    sv.add(f'<line class="a" x1="{left}" y1="{top - 6}" x2="{left}" y2="{top + rowh * len(rows)}"/>')
    return sv.render()


def line_chart(title, sub, xlabel, ylabel, series, ymax=None, xmax=None, hline=None, clamp_note=None):
    """series: [(meta, [[x, y], ...], end_marker or None)]. Points above ymax are pinned and marked."""
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
    Y = lambda y: top + ph - ph * min(y, ymax) / ymax
    for tv in ticks(ymax):
        sv.add(f'<line class="g" x1="{left}" y1="{Y(tv):.1f}" x2="{left + pw}" y2="{Y(tv):.1f}"/>')
        sv.text(left - 6, Y(tv) + 4, tick_label(tv), anchor="end", size=11)
    for tv in ticks(xmax):
        sv.text(X(tv), top + ph + 16, tick_label(tv), anchor="middle", size=11)
    sv.add(f'<line class="a" x1="{left}" y1="{top + ph}" x2="{left + pw}" y2="{top + ph}"/>')
    sv.text(left + pw / 2, h - 8, xlabel, anchor="middle", size=12)
    sv.add(f'<text x="14" y="{top + ph / 2:.1f}" font-size="12" text-anchor="middle" transform="rotate(-90 14 {top + ph / 2:.1f})">{esc(ylabel)}</text>')
    if hline:
        sv.add(f'<line class="cap" x1="{left}" y1="{Y(hline[0]):.1f}" x2="{left + pw}" y2="{Y(hline[0]):.1f}"/>')
        sv.text(left + pw - 4, Y(hline[0]) - 5, hline[1], anchor="end", size=11)
    ends = []
    for m, pts, end in series:
        pts = [p for p in pts if p[1] is not None]
        if not pts:
            continue
        d = " ".join(("M" if i == 0 else "L") + f"{X(x):.1f} {Y(y):.1f}" for i, (x, y) in enumerate(pts))
        cls = "l mp" if m["id"] == "microproxy" else "l"
        sv.add(f'<path class="{cls} s{m["slot"]}" style="fill:none" d="{d}"/>')
        for x, y in pts:
            if y > ymax:
                sv.add(f'<path class="s{m["slot"]}" d="M{X(x) - 5:.1f} {Y(y) + 4:.1f}L{X(x):.1f} {Y(y) - 5:.1f}L{X(x) + 5:.1f} {Y(y) + 4:.1f}Z"/>')
        if end:
            ex, ey = X(pts[-1][0]), Y(pts[-1][1])
            sv.add(f'<path class="s{m["slot"]}" style="stroke-width:3" d="M{ex - 6:.1f} {ey - 6:.1f}L{ex + 6:.1f} {ey + 6:.1f}M{ex + 6:.1f} {ey - 6:.1f}L{ex - 6:.1f} {ey + 6:.1f}"/>')
        ends.append([Y(pts[-1][1]), m])
    # End labels, nudged apart to stay legible (each with a short key line in the series color).
    ends.sort(key=lambda e: e[0])
    for i in range(1, len(ends)):
        if ends[i][0] - ends[i - 1][0] < 14:
            ends[i][0] = ends[i - 1][0] + 14
    for y, m in ends:
        sv.add(f'<line class="s{m["slot"]}" style="stroke-width:3" x1="{left + pw + 6}" y1="{y:.1f}" x2="{left + pw + 18}" y2="{y:.1f}"/>')
        sv.text(left + pw + 22, y + 4, m["label"], size=11)
    if clamp_note:
        sv.text(left, top - 6, clamp_note, size=11)
    return sv.render()


def charts(d):
    meta = d["proxies"]
    out = {}
    n = len(d["runs"])
    out["max-rate.svg"] = bar_chart("Max sustainable rate (requests/s, higher is better)",
                                    f"Median of {n} runs; whiskers span min–max. One CPU per proxy; p99 ≤ {d['sloP99Ms']:g} ms.",
                                    meta, {m["id"]: d["sweep"][m["id"]]["maxSustainable"] for m in meta}, "", 0)
    cap = 100.0
    series = []
    for m in meta:
        pts = [[s["rate"], s["p99"]["med"]] for s in d["sweep"][m["id"]]["steps"] if s["p99"]]
        series.append((m, pts, None))
    out["latency-p99.svg"] = line_chart("p99 latency vs offered load (lower is better)",
                                        f"Median of {n} runs, corrected for coordinated omission; linear axis to {cap:g} ms.",
                                        "offered load (requests/s)", "p99 latency (ms)", series, ymax=cap,
                                        clamp_note=f"▲ = above {cap:g} ms (past the knee), pinned to the top edge")
    out["idle-rss.svg"] = bar_chart("Idle RSS (MB, lower is better)",
                                    f"Resident memory after start-up and a few validation requests; median of {n} runs, whiskers min–max.",
                                    meta, {m["id"]: d["ramp"][m["id"]]["idleRssMb"] for m in meta}, " MB", 1)
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
        out["slowread-rss.svg"] = line_chart(f"RSS while {readers} slow readers download (lower is better)",
                                             "Each proxy in a 512 MB memory cgroup; the run with the median peak; ✕ = out of memory or crash.",
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


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    runs_dir = argv[1]
    publish = argv[argv.index("--publish") + 1] if "--publish" in argv else None
    data = build(runs_dir)
    unclean = [r["id"] for r in data["runs"] if not (r.get("hostLoad") or {}).get("accepted")]
    if publish and unclean and "--allow-unguarded" not in argv:
        sys.exit("not publishing: runs failed the contamination guard or have no host monitor samples: "
                 + ", ".join(unclean) + " (reject them in run-info.json, or pass --allow-unguarded for a local preview)")
    out = os.path.join(runs_dir, "aggregate")
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
        for r in load_runs(runs_dir):
            with open(r["file"], encoding="utf-8") as f:
                raw = json.load(f)
            with open(os.path.join(assets, "raw", r["id"] + ".json"), "w", encoding="utf-8") as f:
                f.write(strip_root(json.dumps(raw, separators=(",", ":"), ensure_ascii=False)))
                f.write("\n")
        # The guard's evidence and what was run, beside the raw results.
        info_src = os.path.join(runs_dir, "run-info.json")
        if os.path.exists(info_src):
            shutil.copy(info_src, os.path.join(assets, "raw", "run-info.json"))
        # The host monitor's log, with other processes' command lines reduced to their program names
        # (they hold paths of other work on the machine, which is not this page's to publish).
        mon_src = os.path.join(runs_dir, "hostmon.jsonl")
        if os.path.exists(mon_src):
            with open(mon_src, encoding="utf-8") as fin, open(os.path.join(assets, "raw", "hostmon.jsonl"), "w", encoding="utf-8") as fout:
                for line in fin:
                    if not line.strip():
                        continue
                    x = json.loads(line)
                    x["topForeign"] = [{"cpuPct": p["cpuPct"], "program": program(p.get("cmd"))} for p in x.get("topForeign", [])]
                    fout.write(json.dumps(x, separators=(",", ":")) + "\n")
        page_md = os.path.join(publish, "project", "performance.md")
        if os.path.exists(page_md):
            replace_markers(page_md, tbl)
        arch_md = os.path.join(publish, "architecture.md")
        if os.path.exists(arch_md):
            replace_markers(arch_md, {"arch-slowread": tbl["arch-slowread"]})
        print(f"published into {assets} and {page_md}")


if __name__ == "__main__":
    main(sys.argv)
