#!/usr/bin/env python3
"""Run the frozen Select tests in their fixture layout using current source bytes.

The real FULL retained report supplies the data-dependent test fixture. This is
test orchestration, not a substitute for the source evidence validator.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_SHA256 = "b1ce4b851ba79f8a2c6d1c1b0e154c59e1ad446968c3e7da0adb54714adc0c1f"
REQUIRED_TESTS = {
    "test_outer_output_mutations_do_not_change_admission_or_signature",
    "test_actual_clean_retained_record_and_raw_log_admit",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative_file(root: Path, value: str) -> Path:
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("FULL evidence path must be relative: " + value)
    path = root / rel
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("FULL evidence file is missing or escapes its root: " + value)
    return path


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)


def run(args) -> dict:
    root = args.root.resolve()
    pkg = root / "formal/source/select"
    if sha(pkg / "package.json") != PACKAGE_SHA256:
        raise ValueError("current Select package differs from the reviewed package")
    replay = load_module("select_test_replay_runner", pkg / "replay.py")
    package = replay.verify_package(pkg, PACKAGE_SHA256)
    baseline = args.baseline.resolve()
    manifest = replay.verify_manifest(pkg, root, baseline, package)

    full_path = args.full_report.resolve()
    full = json.loads(full_path.read_text())
    if (full.get("status") != "complete" or full.get("mode") != "full"
            or full.get("qualification") is not True
            or full.get("package_sha256") != PACKAGE_SHA256):
        raise ValueError("a complete qualifying FULL report for the current package is required")
    retained = full["retained_native"]
    evidence = full_path.parent
    retained_path = relative_file(evidence, retained["report"])
    baseline_log = relative_file(evidence, retained["baseline13"]["log"])
    if (sha(retained_path) != retained["report_sha256"]
            or sha(baseline_log) != retained["baseline13"]["log_sha256"]):
        raise ValueError("FULL retained fixture digest mismatch")
    profile_name = full["profile"]["selector"]
    if profile_name not in {"macos-sdk10.0.400", "linux-sdk10.0.400"}:
        raise ValueError("FULL report names an unreviewed tool profile")
    profile_path = pkg / "profiles" / (profile_name + ".json")
    if sha(profile_path) != full["profile"]["sha256"]:
        raise ValueError("FULL profile differs from the current reviewed profile")
    replay.verify_retained_report(json.loads(retained_path.read_text()), package,
                                  json.loads(profile_path.read_text()), baseline_log.read_text())

    if args.work_root.resolve().is_relative_to(root / "formal"):
        raise ValueError("unit fixture workspace must be outside immutable formal inputs")
    args.work_root.mkdir(parents=True, exist_ok=True)
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    with tempfile.TemporaryDirectory(prefix="select-package-", dir=args.work_root) as tmp:
        layout = Path(tmp)
        candidate = layout / "candidate"
        shutil.copytree(root / "formal", candidate / "formal", ignore=ignore)
        for rel in manifest["baseline_formal_dafny_hashes"]:
            dest = layout / "baseline-git-155b/formal" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(baseline / "formal" / rel, dest)

        # The frozen test uses this relative fixture layout. Its content comes
        # from this invocation's actual final FULL, never a missing/old cache.
        fixture = layout / "preflight-final-2/retained-clean/retained-native/fixture"
        (fixture / "work").mkdir(parents=True)
        shutil.copy2(retained_path, fixture / "report.json")
        shutil.copy2(baseline_log, fixture / "work/baseline13.log")

        original_poly = (candidate / "formal/source/polynomial/replay.py").read_bytes()
        poly_fixture = layout / "unrelated-poly-recipe.py"
        poly_fixture.write_bytes(original_poly + b"\n# Select test: unrelated recipe mutation.\n")
        if poly_fixture.read_bytes() == original_poly:
            raise ValueError("outer-Poly mutation fixture must differ from current bytes")

        module = load_module("select_package_test_replay",
                             candidate / "formal/source/select/test_replay.py")
        module.InputDomainTests.OUTER_POLY = poly_fixture
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
        executed_names = {name.rsplit(".", 1)[-1] for name in result.executed}
        success = (result.wasSuccessful() and result.testsRun == 61
                   and not result.skipped and not result.expectedFailures
                   and not result.unexpectedSuccesses
                   and REQUIRED_TESTS <= executed_names)
        return {"ok": success, "tests": result.testsRun, "skipped": len(result.skipped),
                "expected_failures": len(result.expectedFailures),
                "required_tests_executed": sorted(REQUIRED_TESTS & executed_names),
                "package_sha256": PACKAGE_SHA256, "full_report_sha256": sha(full_path),
                "retained_report_sha256": sha(retained_path),
                "baseline13_log_sha256": sha(baseline_log),
                "outer_poly_fixture_sha256": sha(poly_fixture),
                "outer_poly_fixture_differs": poly_fixture.read_bytes() != original_poly,
                "fixture_source": "actual final FULL retained report and raw log"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--full-report", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        result = run(args)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        result = {"ok": False, "setup_error": str(error)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
