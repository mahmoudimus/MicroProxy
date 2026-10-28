#!/usr/bin/env python3
"""Replay scoped Lean proofs, finite TLC models, and concrete observations of Java code."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess

from install_formal_tools import digest, tool_paths

ROOT = Path(__file__).resolve().parents[2]
STANDARD_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


def audit_axioms(output, expected):
    seen = {}
    for name, axioms in re.findall(r"'([^']+)' depends on axioms: \[([^\]]*)\]", output):
        used = {a.strip() for a in axioms.split(",") if a.strip()}
        if used - STANDARD_AXIOMS:
            raise RuntimeError(f"Untrusted axiom dependencies for {name}: {sorted(used - STANDARD_AXIOMS)}")
        seen[name] = sorted(used)
    for name in re.findall(r"'([^']+)' does not depend on any axioms", output):
        seen[name] = []
    missing = set(expected) - seen.keys()
    if missing:
        raise RuntimeError(f"Missing theorem axiom audit: {sorted(missing)}")
    if not expected:
        raise RuntimeError("Empty security theorem list")
    return {name: seen[name] for name in expected}


def verify_sources(root, sources):
    if not sources:
        raise RuntimeError("Empty Java source mapping")
    for relative, expected in sources.items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root.resolve()) or digest(path) != expected:
            raise RuntimeError(f"Java source drift: {relative}; review models, bridge checks, and mapping before renewal")


def nat(value):
    if type(value) is not int or value < 0:
        raise ValueError(f"Expected nonnegative integer, got {value!r}")
    return str(value)


def byte_list(values):
    if any(type(v) is not int or not 0 <= v < 256 for v in values):
        raise ValueError("Invalid observed unsigned bytes")
    return "[" + ",".join(map(str, values)) + "]"


def entries(values):
    return "[" + ",".join("{ key := " + nat(k) + ", value := " + nat(v)
                           + ", expires := " + nat(e) + " }" for k, v, e in values) + "]"


def observation_claim(row):
    kind = row["kind"]
    if kind in {"record", "budget"} and type(row["accepted"]) is not bool:
        raise ValueError("Acceptance observation must be a JSON boolean")
    if kind == "record":
        actual = f"some ({nat(row['before'])}, {nat(row['after'])})" if row["accepted"] else "none"
        return f"MicroProxy.Records.issue {nat(row['limit'])} {nat(row['before'])} = {actual}"
    if kind == "budget":
        accepted = "true" if row["accepted"] else "false"
        return f"MicroProxy.Resources.charge {nat(row['before'])} {nat(row['cost'])} = ({accepted}, {nat(row['after'])})"
    if kind == "cache":
        args = " ".join(nat(row[key]) for key in ("capacity", "now", "key", "value", "expires"))
        return f"MicroProxy.Resources.put {args} {entries(row['before'])} = {entries(row['after'])}"
    if kind == "label":
        return (f"MicroProxy.CryptoEncoding.encodeLabel {nat(row['length'])} {byte_list(row['label'])} "
                f"{byte_list(row['context'])} = {byte_list(row['encoded'])}")
    if kind == "nonce":
        iv, nonce = int(row["iv"], 16), int(row["nonce"], 16)
        if len(row["iv"]) != 24 or len(row["nonce"]) != 24 or not 0 <= row["sequence"] < 2**64:
            raise ValueError("Nonce observation outside 96-bit IV/64-bit sequence model")
        return (f"MicroProxy.CryptoEncoding.nonce (BitVec.ofNat 96 {iv}) "
                f"(BitVec.ofNat 64 {nat(row['sequence'])}) = BitVec.ofNat 96 {nonce}")
    raise ValueError(f"Unknown Java observation kind: {kind}")


def run(command, log, *, expect_failure=False, expected_failure_exit=1, cwd=ROOT):
    environment = os.environ.copy()
    environment.pop("LEAN_PATH", None)
    with log.open("w") as output:
        completed = subprocess.run([str(a) for a in command], cwd=cwd, env=environment,
                                   stdout=output, stderr=subprocess.STDOUT, timeout=600)
    text = log.read_text()
    expected_exit = expected_failure_exit if expect_failure else 0
    if completed.returncode != expected_exit:
        raise RuntimeError(f"Unexpected command exit {completed.returncode}; see {log}\n{text[-3000:]}")
    return text


def rejected_proof(lean, text, output, name):
    source = output / f"negative-{name}.lean"
    source.write_text(text)
    result = run([lean, "-DwarningAsError=true", source], output / f"negative-{name}.log", expect_failure=True)
    if "error:" not in result or re.search(r"unexpected token|unknown identifier|does not exist|file not found", result):
        raise RuntimeError(f"Negative proof control failed for a parser/import reason: {name}")
    if not re.search(r"unsolved goals|type mismatch|tactic[^\n]*failed|omega could not prove|proved that the proposition|simp made no progress", result, re.IGNORECASE):
        raise RuntimeError(f"Negative control did not fail a proof obligation: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path(os.environ.get(
        "MICROPROXY_FORMAL_CACHE", Path.home() / ".cache/microproxy-formal")))
    parser.add_argument("--output", type=Path, default=ROOT / "target/formal-security")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # A failed replay must never leave a previous success beside partially refreshed logs.
    (output / "report.json").unlink(missing_ok=True)
    (output / "report.partial").unlink(missing_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    config = json.loads((ROOT / "formal/assurance.json").read_text())
    if not any(case["expect"] == "pass" for case in config["tlc_cases"]) or not any(
            case["expect"] == "counterexample" for case in config["tlc_cases"]):
        raise RuntimeError("TLC configuration must include positive and negative controls")
    verify_sources(ROOT, config["java_sources"])
    tools, _, lean, tlc = tool_paths(args.cache.expanduser().resolve())
    if digest(tlc) != tools["tlc"]["sha256"]:
        raise RuntimeError("TLC checksum mismatch; run install_formal_tools.py")
    version = subprocess.check_output([str(lean), "--version"], text=True).strip()
    if f"version {tools['lean']['version']}," not in version:
        raise RuntimeError("Lean version differs from the reviewed toolchain")
    model_paths = set(config["lean_models"])
    for case in config["tlc_cases"]:
        model_paths.update((case["module"], case["config"]))
    model_snapshot = {path: digest(ROOT / path) for path in sorted(model_paths)}
    report = {"scope": config["scope"], "started_utc": started, "lean": version, "axioms": {},
              "source_sha256": config["java_sources"], "model_sha256": model_snapshot,
              "tlc": [], "java_observations": {}, "negative_controls": []}
    all_models = ["import Std\nset_option maxRecDepth 100000\nset_option maxHeartbeats 4000000\n"]
    for model, theorems in config["lean_models"].items():
        path = ROOT / model
        result = run([lean, "-DwarningAsError=true", path], output / (path.stem + ".log"))
        report["axioms"].update(audit_axioms(result, theorems))
        all_models.append(path.read_text().replace("import Std\n", "", 1))
        print(f"Lean checked: {path.name} ({len(theorems)} audited theorems)", flush=True)
    observations = output / "observations"
    observations.mkdir(exist_ok=True)
    for old in observations.glob("*.jsonl"):
        old.unlink()
    run(["mvn", "--batch-mode", "-pl", "microproxy", "-am", "test",
         "-Dtest=FormalRecordModelTest,FormalResourceModelTest,FormalCryptoModelTest,TlsKeyUsageTest,HkdfTest",
         "-Dsurefire.failIfNoSpecifiedTests=false", f"-Dmicroproxy.formal.output={observations}"], output / "java-observations.log")
    counts = Counter()
    claims = []
    for path in sorted(observations.glob("*.jsonl")):
        for line in path.read_text().splitlines():
            row = json.loads(line)
            claims.append("example : " + observation_claim(row) + " := by decide\n")
            counts[row["kind"]] += 1
    for kind, minimum in config["minimum_observations"].items():
        if counts[kind] < minimum:
            raise RuntimeError(f"Missing Java observations for {kind}: {counts[kind]} < {minimum}")
    bridge = output / "JavaObservations.lean"
    bridge.write_text("\n".join(all_models + claims))
    run([lean, "-DwarningAsError=true", bridge], output / "java-model-check.log")
    report["java_observations"] = dict(counts)
    print(f"Java observations checked by Lean: {dict(counts)}", flush=True)
    mutations = [
        ("record-cap", "formal/lean/RecordBounds.lean", "if next < limit then", "if next ≤ limit then"),
        ("budget-credit", "formal/lean/ResourceBounds.lean", "(true, remaining - cost)", "(true, remaining + cost)"),
        ("nonce-forgets-sequence", "formal/lean/CryptoEncoding.lean", "iv ^^^ sequence.zeroExtend 96", "iv ^^^ (0 : BitVec 96)")
    ]
    for name, model, original, mutant in mutations:
        source = (ROOT / model).read_text()
        if source.count(original) != 1:
            raise RuntimeError(f"Negative control needs reviewed renewal: {name}")
        rejected_proof(lean, source.replace(original, mutant, 1), output, name)
        report["negative_controls"].append(name)
    rejected_proof(lean, "\n".join(all_models) + "\nexample : MicroProxy.Resources.charge 8 1 = (true, 8) := by decide\n",
                   output, "wrong-java-observation")
    report["negative_controls"].append("wrong-java-observation")
    java = Path(os.environ["JAVA_HOME"]) / "bin/java" if "JAVA_HOME" in os.environ else Path("java")
    for case in config["tlc_cases"]:
        name = Path(case["config"]).stem
        text = run([java, "-XX:+UseParallelGC", "-Xmx2g", "-cp", tlc, "tlc2.TLC", "-workers", "1",
                    "-seed", "1", "-fp", "0", "-metadir", output / ("states-" + name), "-config", ROOT / case["config"],
                    ROOT / case["module"]], output / (name + ".log"),
                   expect_failure=case["expect"] != "pass", expected_failure_exit=12)
        if case["expect"] == "pass":
            if "Model checking completed. No error has been found." not in text or "distinct states found" not in text:
                raise RuntimeError(f"Incomplete/vacuous TLC result: {name}")
        elif f"Invariant {case['invariant']} is violated" not in text:
            raise RuntimeError(f"TLC negative control did not find its expected counterexample: {name}")
        report["tlc"].append({"case": name, "expect": case["expect"], "state_summary": re.findall(
            r"[^\n]*distinct states found[^\n]*", text)})
        print(f"TLC checked: {name} ({case['expect']})", flush=True)
    verify_sources(ROOT, config["java_sources"])
    for path, expected in model_snapshot.items():
        if digest(ROOT / path) != expected:
            raise RuntimeError(f"Model changed during replay: {path}")
    report["java_runtime"] = subprocess.check_output([str(java), "--version"], text=True).strip()
    report["completed_utc"] = datetime.now(timezone.utc).isoformat()
    temporary_report = output / "report.partial"
    temporary_report.write_text(json.dumps(report, indent=2) + "\n")
    temporary_report.replace(output / "report.json")
    print(f"Formal assurance checks passed; precise scope and limits: formal/README.md. Evidence: {output}")


if __name__ == "__main__":
    main()
