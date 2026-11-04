#!/usr/bin/env python3
"""Focused Native call-order and call-binding coverage repair replay.

Owned component: native-call-order-repair.  This runner uses only copies under
this directory; it does not import parent checkers or edit A/Root/Native.  The
C# checker and official Dafny AST origin adapter are the explicit trusted
boundary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
WORK = HERE / "work"
FLAGS = [
    "--allow-external-contracts",
    "--verification-time-limit", "30",
    "--resource-limit", "50000000",
    "--cores", "2",
    "--solver-option", "O:smt.case_split=0",
]
ALL_ROOTS = ",".join([
    "NativeField.ReduceOnce", "NativeField.Reduce", "NativeField.Add", "NativeField.Sub",
    "NativeField.Mul", "NativeField.MulSub", "NativeField.AddMul",
    "NativeKeccak.SetLane", "NativeKeccak.Iota", "NativeKeccak.Theta",
    "NativeKeccak.RhoPi", "NativeKeccak.Chi", "NativeKeccak.Wipe",
])
SUMMARY = re.compile(r"Dafny program verifier finished with (\d+) verified, (\d+) errors?")
BAD_RUN = re.compile(r"timed?\s*out|out of resource|out of memory|internal error|unhandled exception|pars(?:e|er) error|CLI: Error", re.I)


class GateError(RuntimeError):
    pass


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command, log, cwd=None, env=None, timeout=300):
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as stream:
        try:
            result = subprocess.run([str(c) for c in command], cwd=cwd or HERE,
                                    stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=timeout, env=env)
            rc = result.returncode
        except subprocess.TimeoutExpired:
            stream.write("\nRUNNER TIMEOUT\n")
            rc = 124
    return rc, log.read_text(errors="replace")


def require_ok(rc, text, label):
    if rc != 0 or "SOURCE-COVERAGE OK" not in text or BAD_RUN.search(text):
        raise GateError(label + ": expected SOURCE-COVERAGE OK without diagnostics")
    return {"exit": rc, "status": "SOURCE-COVERAGE OK"}


def require_reject(rc, text, needle, label):
    if BAD_RUN.search(text):
        raise GateError(label + ": tool/parse/resource failure is not a coverage rejection")
    if rc != 2 or needle not in text:
        raise GateError(f"{label}: expected named checker rejection {needle!r}, rc={rc}")
    if "Error: unresolved identifier" in text or "Error: wrong number of arguments" in text:
        raise GateError(label + ": rejection is a source resolution/type error, not the named checker rule")
    return {"exit": rc, "classification": "named-checker-rejection", "needle": needle}


def require_verified(rc, text, expected, label):
    matches = SUMMARY.findall(text)
    if BAD_RUN.search(text) or rc != 0 or len(matches) != 1 or int(matches[0][0]) != expected or int(matches[0][1]) != 0:
        raise GateError(f"{label}: expected exactly {expected} verified, 0 errors")
    return {"exit": rc, "verified": expected, "errors": 0}


def copy_tree(src, dst):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def prepare(name, overlay=None):
    root = WORK / "controls" / name
    copy_tree(HERE / "source-fixtures/formal", root / "formal")
    if overlay is not None:
        base = overlay / "formal" if (overlay / "formal").is_dir() else overlay
        if base.is_dir():
            shutil.copytree(base, root / "formal", dirs_exist_ok=True)
    return root


def checker_command(dafny, plugin, root):
    return [dafny, "resolve", root / "formal/source/AllTraceRoots.dfy",
            "--allow-external-contracts", "--plugin", plugin]


def checker_env():
    env = dict(os.environ)
    env["SOURCE_TRACE_ROOTS"] = ALL_ROOTS
    return env


def pins():
    files = [HERE / "formal/source/checker/SourceCoverage.cs",
             HERE / "formal/source/checker/SourceCoverage.csproj",
             HERE / "formal/source/checker/NativeCanonicalEncoderPolicy.cs",
             HERE / "run.py", HERE / "test_run.py", HERE / "run_encoder_bridge.py"]
    files += sorted((HERE / "formal").rglob("*.dfy"))
    files += sorted((HERE / "source-fixtures").rglob("*.dfy"))
    files += sorted((HERE / "controls").rglob("*.dfy"))
    files += sorted((HERE / "controls").rglob("*.json"))
    return {str(p.relative_to(HERE)): digest(p) for p in files}


def build_checker(dafny):
    build = WORK / "checker-build"
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True)
    shutil.copy2(HERE / "formal/source/checker/SourceCoverage.cs", build / "SourceCoverage.cs")
    shutil.copy2(HERE / "formal/source/checker/SourceCoverage.csproj", build / "SourceCoverage.csproj")
    shutil.copy2(HERE / "formal/source/checker/NativeCanonicalEncoderPolicy.cs", build / "NativeCanonicalEncoderPolicy.cs")
    rc_sdk, sdk = run(["dotnet", "--version"], WORK / "checker-sdk.log", cwd=build)
    if rc_sdk or not re.fullmatch(r"\d+\.\d+\.\d+\s*", sdk): raise GateError("cannot identify build SDK")
    dafny_home = str(Path(dafny).parent)
    rc, text = run(["dotnet", "build", "-v:q", "SourceCoverage.csproj", "-p:DafnyHome=" + dafny_home, "-p:ImportDirectoryBuildProps=false", "-p:ImportDirectoryBuildTargets=false"],
                   WORK / "build.log", cwd=build)
    if rc != 0:
        raise GateError("checker build failed: " + text[-2000:])
    dll = build / "bin/Debug/net6.0/SourceCoverage.dll"
    if not dll.is_file():
        raise GateError("checker DLL missing")
    (WORK / "checker-build.json").write_text(json.dumps({"sdk":sdk.strip(),"dll_sha256":digest(dll),"source_sha256":digest(build/"SourceCoverage.cs"),"project_sha256":digest(build/"SourceCoverage.csproj"),"encoder_policy_sha256":digest(build/"NativeCanonicalEncoderPolicy.cs"),"directory_build_imports_disabled":True},indent=2)+"\n")
    return dll


def pipeline(args):
    WORK.mkdir(parents=True, exist_ok=True)
    before = pins()
    dafny = args.dafny
    rc, version = run([dafny, "--version"], WORK / "dafny-version.log")
    if rc != 0 or "4.9.1" not in version:
        raise GateError("unexpected Dafny version: " + version.strip())
    plugin = build_checker(dafny)
    base_record = {}
    base_path = HERE / "from-base.json"
    if base_path.is_file():
        base_record = json.loads(base_path.read_text())
    report = {"status": "complete", "dafny": version.strip(), "plugin_sha256": digest(plugin),
              "checker_source_sha256": digest(HERE / "formal/source/checker/SourceCoverage.cs"),
              "checker_project_sha256": digest(HERE / "formal/source/checker/SourceCoverage.csproj"),
              "canonical_policy_sha256": digest(HERE / "formal/source/checker/NativeCanonicalEncoderPolicy.cs"),
              "from_base": base_record,
              "baseline13": {}, "root19": {}, "callbinding": {}, "pins_before": before}

    # Baseline thirteen roots.
    base = prepare("baseline13")
    rc, text = run(checker_command(dafny, plugin, base), WORK / "baseline13.log", cwd=HERE, env=checker_env())
    report["baseline13"] = require_ok(rc, text, "baseline13")

    # ROOT 19 controls retained on the copied source baseline.
    root19 = json.loads((HERE / "controls/root19.json").read_text())
    for name, meta in sorted(root19.items()):
        if name == "baseline13":
            continue
        root = prepare("root19-" + name, HERE / "controls/root19" / name)
        rc, text = run(checker_command(dafny, plugin, root), WORK / f"root19-{name}.log", cwd=HERE, env=checker_env())
        if meta["expected_exit"] == 0:
            report["root19"][name] = require_ok(rc, text, "root19-" + name)
        else:
            report["root19"][name] = require_reject(rc, text, meta["needle"], "root19-" + name)

    # New call-binding/root-shape controls.
    cb = json.loads((HERE / "controls/callbinding.json").read_text())
    for name, meta in sorted(cb.items()):
        root = prepare("callbinding-" + name, HERE / "controls/callbinding" / name)
        rc, text = run(checker_command(dafny, plugin, root), WORK / f"callbinding-{name}.log",
                       cwd=HERE, env=checker_env())
        if meta.get("expect") == "accept":
            result = require_ok(rc, text, "callbinding-" + name)
        else:
            result = require_reject(rc, text, meta["needle"], "callbinding-" + name)
        if "verify_method" in meta:
            verify_entry = root / "formal/crypto/NativeField.dfy"
            vrc, vtext = run([dafny, "verify", verify_entry, *FLAGS], WORK / f"callbinding-{name}-verify.log",
                             cwd=HERE)
            result["method"] = require_verified(vrc, vtext, int(meta["verify_method"]), "callbinding-" + name + " method")
        if "verify_nativekeccak" in meta:
            vrc, vtext = run([dafny, "verify", root / "formal/crypto/NativeKeccak.dfy", *FLAGS],
                             WORK / f"callbinding-{name}-nativekeccak-verify.log", cwd=HERE)
            result["nativekeccak"] = require_verified(
                vrc, vtext, int(meta["verify_nativekeccak"]), "callbinding-" + name + " NativeKeccak")
        if "verify_harness" in meta:
            vrc, vtext = run([dafny, "verify", root / "formal/source/RotateThetaTraceHarness.dfy",
                              "--verify-included-files", *FLAGS],
                             WORK / f"callbinding-{name}-harness-verify.log", cwd=HERE)
            result["harness"] = require_verified(
                vrc, vtext, int(meta["verify_harness"]), "callbinding-" + name + " harness")
        report["callbinding"][name] = result

    after = pins()
    if before != after:
        raise GateError("owned source/control pins changed during replay")
    report["pins_after"] = after
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--dafny", default=os.environ.get(
        "DAFNY", "/Users/mahmoud/.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny"))
    args = parser.parse_args(argv)
    report_path = HERE / "report.json"
    report_path.unlink(missing_ok=True)
    try:
        report = pipeline(args)
    except Exception as error:
        report_path.write_text(json.dumps({"status": "failed", "error": str(error)}, indent=2) + "\n")
        print(str(error), file=sys.stderr)
        return 1
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Complete:", report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
