#!/usr/bin/env python3
"""Print a Markdown comparison of MicroProxy and LittleProxy from JMH JSON results.

Every benchmark runs once per proxy (its `proxy` parameter); this pairs the two runs of each
benchmark, mode and parameter set, and prints one row per pair with both scores, their error
margins (JMH's 99.9% confidence half-width), the ratio MicroProxy / LittleProxy and which proxy
did better. For sampled latency (`sample` mode) it adds rows for the 50th, 99th and 99.9th
percentiles; with `-prof gc`, a row for the bytes allocated per operation.

Usage:
    python3 benchmarks/compare.py results.json [more.json ...] [--all-secondary]
        [--littleproxy-version VERSION] [--output FILE]

Standard library only.
"""

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET

PROXIES = ("microproxy", "littleproxy")

# Modes where a higher score is better; in the others (avgt, sample, ss) lower is better.
HIGHER_IS_BETTER = {"thrpt"}

# Secondary metrics shown by default: allocation per operation from -prof gc.
DEFAULT_SECONDARY = {"gc.alloc.rate.norm", "·gc.alloc.rate.norm"}

PERCENTILES = (("50.0", "p50"), ("99.0", "p99"), ("99.9", "p99.9"))


def pinned_littleproxy_version():
    """The LittleProxy version pinned in benchmarks/pom.xml, next to this script."""
    pom = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pom.xml")
    try:
        root = ET.parse(pom).getroot()
    except (OSError, ET.ParseError):
        return None
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    return root.findtext("m:properties/m:littleproxy.version", namespaces=ns)


def load(paths):
    results = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise SystemExit(f"{path}: not a JMH JSON result (expected a list)")
        results.extend(data)
    return results


def num(value):
    """A JMH number as a float, or None: JMH writes "NaN" (a string) for an unknown error."""
    if value is None:
        return None
    try:
        x = float(value)
    except (TypeError, ValueError):
        return None
    return None if x != x else x


def short_name(benchmark):
    # org.microproxy.bench.SmallGetBenchmark.throughput -> SmallGetBenchmark.throughput
    parts = benchmark.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else benchmark


def fmt_number(x):
    if x is None:
        return "?"
    a = abs(x)
    if a >= 100:
        return f"{x:,.0f}"
    if a >= 10:
        return f"{x:.1f}"
    if a >= 1:
        return f"{x:.2f}"
    return f"{x:.3g}"


def fmt_score(score, error, unit):
    if not error:
        return f"{fmt_number(score)} {unit}"
    return f"{fmt_number(score)} ± {fmt_number(error)} {unit}"


def verdict(mp, lp, mp_err, lp_err, higher_better):
    """Which proxy did better, and whether the error intervals overlap."""
    if mp is None or lp is None:
        return "?"
    if mp == lp:
        return "tie"
    better = "MicroProxy" if (mp > lp) == higher_better else "LittleProxy"
    if mp_err is not None and lp_err is not None:
        if abs(mp - lp) <= (mp_err + lp_err):
            return f"{better} (within error)"
    return better


def ratio(mp, lp):
    if mp is None or lp is None or lp == 0:
        return "?"
    return f"{mp / lp:.2f}x"


def build_rows(results, all_secondary):
    # (benchmark, mode, other params) -> proxy -> result
    groups = {}
    order = []
    for r in results:
        params = dict(r.get("params") or {})
        proxy = params.pop("proxy", None)
        if proxy not in PROXIES:
            continue
        key = (r["benchmark"], r["mode"], tuple(sorted(params.items())))
        if key not in groups:
            groups[key] = {}
            order.append(key)
        groups[key][proxy] = r

    rows = []
    for key in order:
        benchmark, mode, params = key
        pair = groups[key]
        mp, lp = pair.get("microproxy"), pair.get("littleproxy")
        label = short_name(benchmark)
        param_text = ", ".join(f"{k}={v}" for k, v in params) or "-"
        higher = mode in HIGHER_IS_BETTER

        def metric(result, getter):
            if result is None:
                return None, None, ""
            return getter(result)

        def primary(result):
            m = result["primaryMetric"]
            return num(m.get("score")), num(m.get("scoreError")), m.get("scoreUnit", "")

        rows.append(make_row(label, mode, param_text, "score", metric(mp, primary), metric(lp, primary), higher))

        if mode == "sample":
            for pct, name in PERCENTILES:
                def percentile(result, pct=pct):
                    m = result["primaryMetric"]
                    return num((m.get("scorePercentiles") or {}).get(pct)), None, m.get("scoreUnit", "")

                rows.append(make_row(label, mode, param_text, name, metric(mp, percentile), metric(lp, percentile), False))

        names = []
        for result in (mp, lp):
            for name in (result or {}).get("secondaryMetrics", {}) or {}:
                if name not in names:
                    names.append(name)
        for name in names:
            if not all_secondary and name not in DEFAULT_SECONDARY:
                continue

            def secondary(result, name=name):
                m = (result.get("secondaryMetrics") or {}).get(name)
                if m is None:
                    return None, None, ""
                return num(m.get("score")), num(m.get("scoreError")), m.get("scoreUnit", "")

            # The profilers' metrics (allocation, GC count and time) are all better lower.
            rows.append(make_row(label, mode, param_text, name.lstrip("·"), metric(mp, secondary),
                                 metric(lp, secondary), False))
    return rows


def make_row(label, mode, params, metric_name, mp, lp, higher):
    mp_score, mp_err, mp_unit = mp
    lp_score, lp_err, lp_unit = lp
    return [
        label,
        mode,
        params,
        metric_name,
        fmt_score(mp_score, mp_err, mp_unit) if mp_score is not None else "missing",
        fmt_score(lp_score, lp_err, lp_unit) if lp_score is not None else "missing",
        ratio(mp_score, lp_score),
        verdict(mp_score, lp_score, mp_err, lp_err, higher),
    ]


def environment(results, littleproxy_version):
    if not results:
        return ""
    r = results[0]
    bits = []
    if littleproxy_version:
        bits.append(f"LittleProxy {littleproxy_version}")
    if r.get("jmhVersion"):
        bits.append(f"JMH {r['jmhVersion']}")
    if r.get("jdkVersion"):
        bits.append(f"JDK {r['jdkVersion']} ({r.get('vmName', '')})")
    bits.append(
        f"{r.get('forks', '?')} fork(s), {r.get('warmupIterations', '?')} x {r.get('warmupTime', '?')} warm-up, "
        f"{r.get('measurementIterations', '?')} x {r.get('measurementTime', '?')} measurement"
    )
    # The heap, GC and other -X options, and the benchmarks' own properties: what tunes the JVM.
    jvm = [a for a in r.get("jvmArgs") or [] if a.startswith(("-X", "--", "-Dbench."))]
    if jvm:
        bits.append("JVM options: `" + " ".join(jvm) + "`")
    return "; ".join(bits)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results", nargs="+", help="JMH JSON result files (-rf json -rff FILE)")
    parser.add_argument("--all-secondary", action="store_true",
                        help="show every secondary metric, not only gc.alloc.rate.norm")
    parser.add_argument("--littleproxy-version", default=None,
                        help="the LittleProxy version measured (default: the one pinned in benchmarks/pom.xml)")
    parser.add_argument("--output", "-o", help="write the Markdown here as well as to standard output")
    args = parser.parse_args(argv)

    results = load(args.results)
    rows = build_rows(results, args.all_secondary)
    version = args.littleproxy_version or pinned_littleproxy_version()

    lines = ["# MicroProxy vs LittleProxy", ""]
    env = environment(results, version)
    if env:
        lines += [env, ""]
    lines += [
        "Ratio is MicroProxy / LittleProxy. For `thrpt` higher is better; for `avgt`, `sample` "
        "and B/op lower is better. Errors are JMH's 99.9% confidence half-widths; \"within error\" "
        "means the two intervals overlap.",
        "",
        "| Benchmark | Mode | Params | Metric | MicroProxy | LittleProxy | Ratio | Better |",
        "|---|---|---|---|---:|---:|---:|---|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in row) + " |")
    if not rows:
        lines.append("| (no results with a `proxy` parameter) | | | | | | | |")
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
