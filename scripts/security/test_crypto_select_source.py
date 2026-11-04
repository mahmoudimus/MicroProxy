#!/usr/bin/env python3
"""Tests for the schema-2 Select semantic gate.

Static/current-input and adversarial shape/context tests run now against the frozen
source package.  Cold positive integration tests require an actual final FULL report
(Mac and/or Linux) and are explicitly skipped until it exists; nothing here fabricates
a COMPLETE report or claims full-proof qualification.
"""
import importlib.util
import json
import os
from pathlib import Path
import unittest.mock
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("select_gate", HERE / "check_select_source.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

FROZEN = Path(os.environ.get("SELECT_WORKSPACE_ROOT") or Path(__file__).resolve().parents[2])


def _copy_frozen(tmp: Path) -> Path:
    target = tmp / "candidate"
    shutil.copytree(FROZEN / "formal", target / "formal",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "bin", "obj", "work"))
    return target


class StaticInputTests(unittest.TestCase):
    """Current-input authority: exact 85/2-diff/package/used closure + profiles."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="select-gate-static-")
        cls.candidate = _copy_frozen(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def admit(self):
        return G.validate_current_inputs(self.candidate)

    def test_frozen_workspace_admits(self):
        facts = self.admit()
        self.assertEqual(facts["package_sha256"], G.PACKAGE_PINS["package_sha256"])
        self.assertEqual(facts["replay_sha256"], G.PACKAGE_PINS["replay_sha256"])
        self.assertEqual(facts["dafny_files"], 85)
        self.assertEqual(facts["controls"], 52)
        self.assertEqual(facts["used_inputs"], 8)
        self.assertEqual(facts["package_files"], 311)  # 309 strict + 2 manifests
        for platform, pin in G.PROFILE_PINS.items():
            self.assertEqual(facts["profiles"][platform]["sha256"], pin["sha256"])
            self.assertEqual(facts["profiles"][platform]["selector"], pin["name"])

    def _drift(self, rel, mutate, label):
        path = self.candidate / rel
        original = path.read_bytes()
        try:
            path.write_bytes(mutate(original))
            with self.assertRaises(G.SelectGateError, msg=label):
                self.admit()
        finally:
            path.write_bytes(original)

    def test_current_observer_model_drift_rejects(self):
        rel = "formal/source/SourceTrace.dfy"
        text = (self.candidate / rel).read_text()
        anchor = "{ O.Encode(O.Read(site, role, address)) }"
        self.assertEqual(text.count(anchor), 1)
        self._drift(rel, lambda b: text.replace(anchor, "{ [] }").encode(), "SourceTrace.Read")

    def test_vocabulary_and_nativefield_drift_reject(self):
        self._drift("formal/source/vocabulary/ObservationVocabulary.dfy",
                    lambda b: b + b"\n// drift\n", "vocabulary")
        self._drift("formal/crypto/NativeField.dfy", lambda b: b + b"\n// drift\n", "NativeField")

    def test_untouched_dafny_drift_and_missing_reject(self):
        self._drift("formal/crypto/MlKem.dfy", lambda b: b + b"\n// drift\n", "untouched83")
        victim = self.candidate / "formal/crypto/Codec.dfy"
        moved = victim.with_suffix(".dfy.aside")
        victim.rename(moved)
        try:
            with self.assertRaises(G.SelectGateError):
                self.admit()
        finally:
            moved.rename(victim)

    def test_extra_or_symlinked_dafny_rejects(self):
        extra = self.candidate / "formal/crypto/extra-observer.dfy"
        try:
            extra.write_text("module Extra {}\n")
            with self.assertRaisesRegex(G.SelectGateError, "current candidate Dafny set changed"):
                self.admit()
        finally:
            extra.unlink(missing_ok=True)
        victim = self.candidate / "formal/crypto/NativeField.dfy"
        original = victim.read_bytes()
        try:
            victim.unlink()
            victim.symlink_to(self.candidate / "formal/crypto/NativeKeccak.dfy")
            with self.assertRaises(G.SelectGateError):
                self.admit()
        finally:
            victim.unlink(missing_ok=True)
            victim.write_bytes(original)

    def test_used_input_drift_rejects(self):
        for rel in sorted(G.USED_INPUTS):
            if rel.endswith(".dfy"):
                continue  # covered by the Dafny closure tests
            self._drift(rel, lambda b: b + b"\n// drift\n", rel)

    def test_package_extra_symlink_and_empty_build_dirs_reject(self):
        package = self.candidate / "formal/source/select"
        extra = package / "unexpected.json"
        try:
            extra.write_text("{}\n")
            with self.assertRaises(G.SelectGateError):
                self.admit()
        finally:
            extra.unlink(missing_ok=True)
        link = package / "linked-control"
        try:
            link.symlink_to(package / "README.md")
            with self.assertRaises(G.SelectGateError):
                self.admit()
        finally:
            link.unlink(missing_ok=True)
        for rel in ("checker/bin", "checker/obj", "fixtures/retained-native/work"):
            path = package / rel
            try:
                path.mkdir(parents=True)
                with self.assertRaises(G.SelectGateError):
                    self.admit()
            finally:
                path.rmdir()

    def test_tampered_package_or_profile_rejects(self):
        package = self.candidate / "formal/source/select"
        original = (package / "package.json").read_bytes()
        try:
            (package / "package.json").write_bytes(original + b"\n")
            with self.assertRaises(G.SelectGateError):
                self.admit()
        finally:
            (package / "package.json").write_bytes(original)
        profile = package / "profiles/macos-sdk10.0.400.json"
        original = profile.read_bytes()
        try:
            data = json.loads(original)
            data["jdk21_version"] = "0.0.0"
            profile.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(G.SelectGateError):
                self.admit()
        finally:
            profile.write_bytes(original)

    def test_closure_map_rules(self):
        baseline = json.loads((self.candidate / "formal/source/select/baseline.json").read_text())
        G._validate_closure(baseline, "baseline")
        narrowed = dict(baseline)
        narrowed["candidate_allowed_formal_diff"] = ["crypto/NativeMlKem.dfy"]
        with self.assertRaises(G.SelectGateError):
            G._validate_closure(narrowed, "baseline")
        inflated = dict(baseline)
        inflated["candidate_allowed_formal_diff"] = [
            "crypto/NativeMlKem.dfy", "crypto/native_kem_domain.dfy", "crypto/Codec.dfy"]
        with self.assertRaises(G.SelectGateError):
            G._validate_closure(inflated, "baseline")
        changed = json.loads(json.dumps(baseline))
        changed["baseline_formal_dafny_hashes"]["crypto/NativeMlKem.dfy"] = "0" * 64
        with self.assertRaises(G.SelectGateError):
            G._validate_closure(changed, "baseline")


class CaseContextTests(unittest.TestCase):
    """Mandatory typed+raw CASE-CONTEXT identity, including the ambiguous loop/block pair."""

    def record(self, case="neg-loop-alloc", operand="a" * 64, argv=None, cwd="/prov/out",
               expected="b" * 64, plugin="c" * 64):
        record = {"case": case, "operand_sha256_before": operand, "operand_sha256_after": operand,
                  "argv": argv or ["dafny", "resolve", "/prov/out/x.dfy"],
                  "cwd": cwd, "expected_fixture_sha256": expected, "plugin_sha256": plugin}
        return record

    def log(self, record):
        return G._context_line(record) + "\ntool output\n"

    def check(self, record, log, **kw):
        args = dict(case=record["case"], argv=record["argv"], cwd=record["cwd"],
                    operand_sha256=record["operand_sha256_before"],
                    expected_fixture=record["expected_fixture_sha256"],
                    plugin_sha256=record["plugin_sha256"], log_text=log, label="ctx")
        args.update(kw)
        G._validate_context(record, **args)

    def test_exact_prefix_passes_and_mismatches_reject(self):
        record = self.record()
        self.check(record, self.log(record))
        canonical = dict(case=record["case"], argv=record["argv"], cwd=record["cwd"],
                         operand_sha256=record["operand_sha256_before"],
                         expected_fixture=record["expected_fixture_sha256"],
                         plugin_sha256=record["plugin_sha256"])
        for broken in (
            {**record, "case": "neg-block-wrap-alloc"},
            {**record, "operand_sha256_before": "d" * 64},
            {**record, "argv": ["dafny", "resolve", "/other.dfy"]},
            {**record, "cwd": "/elsewhere"},
            {**record, "plugin_sha256": "e" * 64},
        ):
            with self.assertRaises(G.SelectGateError):
                self.check(broken, self.log(broken), **canonical)
        with self.assertRaises(G.SelectGateError):
            self.check(record, self.log({**record, "case": "neg-block-wrap-alloc"}))
        with self.assertRaises(G.SelectGateError):
            self.check({**record, "operand_sha256_after": "f" * 64},
                       self.log({**record, "operand_sha256_after": "f" * 64}))

    def test_loop_block_log_swap_rejects_despite_identical_diagnostics(self):
        self.assertEqual(G.CASE_DIAGNOSTICS["neg-loop-alloc"],
                         G.CASE_DIAGNOSTICS["neg-block-wrap-alloc"])
        self.assertIn("neg-loop-alloc", G.CASE_IDENTITY_AMBIGUOUS)
        loop = self.record(case="neg-loop-alloc", expected="1" * 64)
        block = self.record(case="neg-block-wrap-alloc", expected="2" * 64)
        self.check(loop, self.log(loop))
        self.check(block, self.log(block))
        with self.assertRaisesRegex(G.SelectGateError, "prefix differs|identity"):
            self.check(loop, self.log(block))

    def test_parser_type_tool_timeout_never_semantic_negative(self):
        record = self.record()
        for text in ("Error: unresolved identifier foo\n1 resolution/type errors detected in x\n",
                     "timed out\n0 errors\n",
                     "Parser error: bad\n",
                     "Dafny program verifier finished with 0 verified, 1 error (out of resource)\n"):
            with self.assertRaises(G.SelectGateError):
                G._rejected_checker(text, "Select allocation must be a direct top-level statement",
                                    "controls", "synthetic")


class ReportShapeTests(unittest.TestCase):
    """Negative shape tests only; no COMPLETE report/log is fabricated or admitted."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="select-gate-report-")
        cls.candidate = _copy_frozen(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def reject(self, report, **kw):
        path = Path(self._tmp.name) / "report.json"
        path.write_text(json.dumps(report))
        with self.assertRaises(G.SelectGateError):
            G.validate_select_source(path, workspace_root=self.candidate,
                                     platform=kw.get("platform", "macos-arm64"),
                                     expected_mode=kw.get("mode", "full"))

    def test_incomplete_and_misshaped_reports_reject(self):
        self.reject({"schema": G.REPORT_SCHEMA, "status": "incomplete"})
        self.reject({"schema": "wrong", "status": "complete", "mode": "full"})
        self.reject({"schema": G.REPORT_SCHEMA, "status": "complete", "mode": "targeted"})
        self.reject({"schema": G.REPORT_SCHEMA, "status": "complete", "mode": "full",
                     "qualification": False})
        self.reject({"schema": G.REPORT_SCHEMA, "status": "complete", "mode": "full",
                     "qualification": True})
        self.reject({"schema": G.REPORT_SCHEMA, "status": "complete", "mode": "full",
                     "qualification": True, "error": "x"})

    def test_unknown_platform_and_mode_reject(self):
        with self.assertRaises(G.SelectGateError):
            G.validate_current_inputs(self.candidate, "windows-x64")
        path = Path(self._tmp.name) / "report.json"
        path.write_text("{}")
        with self.assertRaises(G.SelectGateError):
            G.validate_select_source(path, workspace_root=self.candidate,
                                     platform="macos-arm64", expected_mode="targeted")


class ColdFullIntegrationTests(unittest.TestCase):
    """Integration path: tracked report+collection, or explicit development env paths."""

    REPORT_ENV = {"macos-arm64": "SELECT_FULL_REPORT_MAC", "linux-x64": "SELECT_FULL_REPORT_LINUX"}
    COLLECTION_ENV = {"macos-arm64": "SELECT_MAC_COLLECTION", "linux-x64": "SELECT_LINUX_COLLECTION"}

    def test_actual_full_report_per_platform(self):
        ran = 0
        for platform in ("macos-arm64", "linux-x64"):
            report = Path(os.environ.get(self.REPORT_ENV[platform]) or
                          INTEGRATION_REPORTS[platform])
            if not report.is_file():
                continue
            collection = os.environ.get(self.COLLECTION_ENV[platform])
            with tempfile.TemporaryDirectory(prefix="select-integration-") as tmp:
                if collection:
                    collection_path = Path(collection)
                elif (report.parent / "COLLECTION-FILES.json").is_file():
                    collection_path = report.parent
                elif (report.parent / "codegen").is_dir():
                    collection_path = _derive_collection(report.parent, Path(tmp) / "collection")
                else:
                    continue
                with self.subTest(platform=platform):
                    result = G.validate_select_source(
                        report, workspace_root=FROZEN, platform=platform,
                        companion_collection=collection_path)
                    self.assertEqual(result["platform"], platform)
                    self.assertEqual(result["package_sha256"], G.PACKAGE_PINS["package_sha256"])
                    self.assertEqual(result["input_counts"],
                                     {"baseline_dafny": 85, "dafny": 85, "package": 311,
                                      "used_inputs": 8})
                    ran += 1
        self.assertEqual(ran, 2, "both tracked FULL reports and collections are required")




MAC_COLLECTION = Path(os.environ.get("SELECT_MAC_COLLECTION") or
                      FROZEN / "formal/crypto/evidence/2026-11-04-select/macos")
MAC_RUN = Path(os.environ.get("SELECT_FULL_REPORT_MAC") or
               MAC_COLLECTION / "package-report.json").parent
LINUX_COLLECTION = Path(os.environ.get("SELECT_LINUX_COLLECTION") or
                        FROZEN / "formal/crypto/evidence/2026-11-04-select/linux")
LINUX_RUN = Path(os.environ.get("SELECT_FULL_REPORT_LINUX") or
                 LINUX_COLLECTION / "package-report.json").parent
# Integration defaults (A checkout): tracked collections under the evidence dir.
REPO_ROOT = Path(__file__).resolve().parents[2]
INTEGRATION_REPORTS = {
    "macos-arm64": REPO_ROOT / "formal/crypto/evidence/2026-11-04-select/macos/package-report.json",
    "linux-x64": REPO_ROOT / "formal/crypto/evidence/2026-11-04-select/linux/package-report.json",
}
UNREACHABLE = "/nonexistent-select-producer"


def _derive_collection(run_dir: Path, destination: Path) -> Path:
    """Build an owned cold collection from actual run output (Root curation equivalent)."""
    import hashlib
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(run_dir / "logs", destination / "logs", dirs_exist_ok=True)
    shutil.copytree(run_dir / "retained-native/fixture", destination / "retained-native/fixture",
                    dirs_exist_ok=True)
    shutil.copyfile(run_dir / "package-report.json", destination / "package-report.json")
    maps = destination / "derived-codegen-maps"
    maps.mkdir(exist_ok=True)
    codegen = run_dir / "codegen"
    for name, root, pattern in (
            ("java-base", codegen / "gen-base-java", "*.java"),
            ("java-overlay", codegen / "gen-overlay-java", "*.java"),
            ("classes-base-jdk21", codegen / "classes-base-jdk21", "*.class"),
            ("classes-base-jdk25", codegen / "classes-base-jdk25", "*.class"),
            ("classes-overlay-jdk21", codegen / "classes-overlay-jdk21", "*.class"),
            ("classes-overlay-jdk25", codegen / "classes-overlay-jdk25", "*.class")):
        rows = []
        for path in sorted(root.rglob(pattern)):
            if path.name in ("gen_base.java", "gen_overlay.java"):
                continue
            rows.append(str(path.relative_to(root)) + " " +
                        hashlib.sha256(path.read_bytes()).hexdigest())
        (maps / (name + ".sha256")).write_text("\n".join(rows) + "\n")
    entries = {}
    for path in sorted(destination.rglob("*")):
        if path.is_file():
            entries[str(path.relative_to(destination))] = {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    (destination / "COLLECTION-FILES.json").write_text(
        json.dumps({"files": entries}, indent=1, sort_keys=True) + "\n")
    (destination / "COLLECTION-PROVENANCE.json").write_text(json.dumps({
        "boundaries": ["DERIVED in the test fixture from actual run output; not producer-recorded commands"],
        "derived_codegen_maps": {name: {"file": "derived-codegen-maps/" + name + ".sha256"}
                                 for name in ("java-base", "java-overlay", "classes-base-jdk21",
                                              "classes-base-jdk25", "classes-overlay-jdk21",
                                              "classes-overlay-jdk25")},
    }, indent=1, sort_keys=True) + "\n")
    return destination


def _rewrite_paths(value, mapping):
    if isinstance(value, str):
        for old, new in mapping:
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [_rewrite_paths(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: _rewrite_paths(item, mapping) for key, item in value.items()}
    return value


class ColdMacActualTests(unittest.TestCase):
    """Cold/adversarial suite over the REAL Mac FULL report and raw logs.

    Each test copies the tracked collection into an owned fixture, rewrites every
    producer path to an unreachable prefix, and mutates real report/log bytes.
    No synthetic COMPLETE report is created and no producer output is opened.
    """

    @classmethod
    def setUpClass(cls):
        if not (MAC_COLLECTION / "package-report.json").is_file():
            raise AssertionError("actual Mac evidence collection not present")
        cls._tmp = tempfile.TemporaryDirectory(prefix="select-gate-cold-")
        cls.ws = _copy_frozen(Path(cls._tmp.name))
        cls.source_report = json.loads((MAC_COLLECTION / "package-report.json").read_text())
        cls.mapping = [
            (cls.source_report["checker"]["dll_path"],
             UNREACHABLE + "/out/checker-build/bin/Debug/net6.0/SourceCoverage.dll"),
            (cls.source_report["output"], UNREACHABLE + "/out"),
            (cls.source_report["package_root"],
             UNREACHABLE + "/candidate/formal/source/select"),
            (cls.source_report["candidate_root"], UNREACHABLE + "/candidate"),
            (cls.source_report["baseline_root"], UNREACHABLE + "/baseline-git-155b"),
            (cls.source_report["tools"]["dafny"], UNREACHABLE + "/tools/dafny"),
            (cls.source_report["tools"]["dotnet"], UNREACHABLE + "/tools/dotnet"),
            (cls.source_report["tools"]["jdk21"], UNREACHABLE + "/tools/jdk21"),
            (cls.source_report["tools"]["jdk25"], UNREACHABLE + "/tools/jdk25"),
            (cls.source_report["tools"]["runtime"], UNREACHABLE + "/tools/runtime.jar"),
        ]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self.fixture = Path(tempfile.mkdtemp(prefix="mac-evidence-", dir=self._tmp.name))
        shutil.copytree(MAC_COLLECTION, self.fixture, dirs_exist_ok=True)
        self.reset()
        # Raw CASE-CONTEXT lines carry the original argv/cwd; rewrite them with the
        # same mapping so the cold fixture is genuinely producer-path-free.  Then
        # re-sync every recorded log digest to the rewritten tracked bytes.
        for path in sorted((self.fixture / "logs").rglob("*")):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            rewritten = _rewrite_paths(text, self.mapping)
            if rewritten != text:
                path.write_text(rewritten)
        def sync(node):
            if isinstance(node, dict):
                if isinstance(node.get("log"), str) and "log_sha256" in node:
                    node["log_sha256"] = G._sha(self.fixture / node["log"])
                for value in node.values():
                    sync(value)
            elif isinstance(node, list):
                for value in node:
                    sync(value)
        self._sync(self.report)
        self.report_path = self.fixture / "package-report.json"
        self.write()

    def _sync(self, node):
        if isinstance(node, dict):
            if isinstance(node.get("log"), str) and "log_sha256" in node:
                node["log_sha256"] = G._sha(self.fixture / node["log"])
            for value in node.values():
                self._sync(value)
        elif isinstance(node, list):
            for value in node:
                self._sync(value)

    def reset(self):
        # Restore both the report and the raw logs to the pristine tracked bytes,
        # rewrite producer paths, and re-sync digests.  Mutations never leak
        # between sub-cases.
        target_logs = self.fixture / "logs"
        if target_logs.exists():
            shutil.rmtree(target_logs)
        shutil.copytree(MAC_COLLECTION / "logs", target_logs)
        for path in sorted(target_logs.rglob("*")):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            rewritten = _rewrite_paths(text, self.mapping)
            if rewritten != text:
                path.write_text(rewritten)
        self.report = _rewrite_paths(json.loads(
            (MAC_COLLECTION / "package-report.json").read_text()), self.mapping)
        self._sync(self.report)

    def rewrite_body(self, rel, body):
        """Keep the mandatory raw CASE-CONTEXT prefix, replace the tool body."""
        path = self.log_path(rel)
        lines = path.read_text().splitlines(keepends=True)
        prefix = lines[0] if lines and lines[0].startswith("CASE-CONTEXT ") else ""
        path.write_text(prefix + body)
        return G._sha(path)

    def tearDown(self):
        shutil.rmtree(self.fixture, ignore_errors=True)

    def write(self):
        self.report_path.write_text(json.dumps(self.report, indent=1, sort_keys=True) + "\n")

    def validate(self, **overrides):
        self.write()
        kwargs = dict(workspace_root=self.ws, platform="macos-arm64",
                      evidence_root=self.fixture)
        kwargs.update(overrides)
        return G.validate_select_source(self.report_path, **kwargs)

    def rejects(self, pattern):
        class _Ctx:
            def __enter__(_self):
                _self.cm = self.assertRaisesRegex(G.SelectGateError, pattern)
                _self.cm.__enter__()
            def __exit__(_self, *exc):
                return _self.cm.__exit__(*exc)
        return _Ctx()

    def log_path(self, rel):
        return self.fixture / rel

    def rewrite_log(self, rel, text):
        path = self.log_path(rel)
        path.write_text(text)
        return G._sha(path)

    def sync(self, record, rel):
        record["log_sha256"] = G._sha(self.log_path(rel))

    def ctx(self, case):
        return self.report["case_contexts"][case]

    # ---- positive -------------------------------------------------
    def test_actual_mac_full_admits_cold_without_producer_paths(self):
        import io
        opened = []
        real_open = io.open

        def spy(file, *args, **kwargs):
            try:
                opened.append(os.fspath(file))
            except TypeError:
                pass
            return real_open(file, *args, **kwargs)

        with unittest.mock.patch("io.open", spy):
            result = self.validate(companion_collection=self.fixture)
        self.assertFalse(Path(UNREACHABLE).exists())
        self.assertGreater(result["checked"], 100)
        self.assertEqual(result["package_sha256"], G.PACKAGE_PINS["package_sha256"])
        self.assertEqual(result["input_counts"],
                         {"baseline_dafny": 85, "dafny": 85, "package": 311, "used_inputs": 8})
        self.assertTrue(result["companion_maps"]["java_identity"])
        # Cold workspace contains only the current source package: no baseline
        # tree, .git, tools or caches that could be used as an authority.
        parent = self.ws.parent
        self.assertFalse((parent / "baseline-git-155b").exists())
        self.assertFalse((self.ws / ".git").exists())
        self.assertFalse((parent / "tools").exists())
        forbidden = {"baseline-git-155b", "tools", ".git"}
        self.assertFalse({p.name for p in parent.iterdir()} & forbidden)
        for path in opened:
            self.assertFalse(path.startswith(UNREACHABLE), path)
            self.assertFalse(path.endswith(".git"), path)

    def test_report_key_status_and_context_inventory(self):
        self.report["unexpected"] = True
        with self.rejects("report key inventory"):
            self.validate()
        self.reset()
        self.report["status"] = "incomplete"
        with self.rejects("status is not complete"):
            self.validate()
        self.reset()
        del self.report["case_contexts"]["encoder-boolean-flip"]
        with self.rejects("case-context inventory"):
            self.validate()
        self.reset()
        self.report["case_contexts"]["extra-case"] = self.report["case_contexts"]["observed"]
        with self.rejects("case-context inventory"):
            self.validate()

    def test_companion_map_tamper_rejects(self):
        path = self.fixture / "derived-codegen-maps/java-base.sha256"
        lines = path.read_text().splitlines()
        lines[0] = lines[0].rsplit(" ", 1)[0] + " " + "0" * 64
        path.write_text("\n".join(lines) + "\n")
        with self.rejects("derived map digest changed"):
            self.validate(companion_collection=self.fixture)

    # ---- portable API / layout ------------------------------------
    def test_wrong_workspace_source_rejects(self):
        path = self.ws / "formal/crypto/NativeMlKem.dfy"
        text = path.read_text()
        path.write_text(text + "\n// drift\n")
        try:
            with self.rejects("current candidate Dafny hash changed"):
                self.validate()
        finally:
            path.write_text(text)

    def test_used_provider_drift_rejects(self):
        path = self.ws / "formal/crypto/native_kem_hash.java"
        text = path.read_text()
        path.write_text(text + "\n// drift\n")
        try:
            with self.rejects("current used input hash changed"):
                self.validate()
        finally:
            path.write_text(text)

    def test_evidence_root_and_log_paths(self):
        with self.rejects("missing file|escaping"):
            self.validate(evidence_root=self.fixture / "logs")
        self.report["controls"]["positive-actual"]["log"] = "../escape.log"
        with self.rejects("escaping path"):
            self.validate()
        self.report["controls"]["positive-actual"]["log"] = "/etc/passwd"
        with self.rejects("relative path"):
            self.validate()

    def test_report_and_profile_identity(self):
        self.report["package_sha256"] = "0" * 64
        with self.rejects("report package digest"):
            self.validate()
        self.reset()
        self.report["profile"]["sha256"] = "0" * 64
        with self.rejects("report profile digest"):
            self.validate()
        self.reset()
        self.report["profile"]["platform"] = "linux-x64"
        with self.rejects("selector/platform"):
            self.validate()

    def test_workspace_profile_drift_rejects(self):
        profile = self.ws / "formal/source/select/profiles/macos-sdk10.0.400.json"
        original = profile.read_bytes()
        try:
            profile.write_bytes(original + b"\n")
            with self.rejects("package file hash changed"):
                self.validate()
        finally:
            profile.write_bytes(original)

    def test_checker_source_drift_rejects(self):
        path = self.ws / "formal/source/select/checker/SourceCoverage.cs"
        text = path.read_text()
        path.write_text(text + "\n// drift\n")
        try:
            with self.rejects("package file hash changed"):
                self.validate()
        finally:
            path.write_text(text)

    def test_control_command_target_and_plugin(self):
        self.report["controls"]["positive-actual"]["command"][2] = "/tmp/elsewhere/x.dfy"
        with self.rejects("checker argv changed"):
            self.validate()
        self.reset()
        self.report["controls"]["positive-actual"]["command"][5] = "/tmp/other.dll"
        with self.rejects("checker argv changed"):
            self.validate()

    def test_report_inputs_and_manifest(self):
        self.report["inputs"]["expected"]["select_harness"] = [7, 0]
        with self.rejects("inputs block"):
            self.validate()
        self.reset()
        self.report["manifest"]["controls"] = 51
        with self.rejects("manifest summary"):
            self.validate()

    # ---- control family -------------------------------------------
    def test_control_status_drop_env_exit(self):
        self.report["controls"]["positive-actual"]["status"] = "named-checker-rejection"
        with self.rejects("control identity/status"):
            self.validate()
        self.reset()
        del self.report["controls"]["neg-shadow-select"]
        with self.rejects("control record inventory"):
            self.validate()
        self.reset()
        self.report["controls"]["positive-actual"]["env"]["SOURCE_TRACE_DEPTH"] = "1"
        with self.rejects("ambient selector"):
            self.validate()
        self.reset()
        self.report["controls"]["neg-wrong-size"]["exit"] = 0
        with self.rejects("checker exit changed"):
            self.validate()

    def test_control_log_semantics(self):
        rec = self.report["controls"]["positive-actual"]
        self.rewrite_body(rec["log"],
                          "SOURCE-COVERAGE OK: exact roots [NativeMlKem.Encaps]; ordered "
                          "markers; fail-closed\n")
        self.sync(rec, rec["log"])
        with self.rejects("printed roots differ"):
            self.validate()
        self.reset()
        rec = self.report["controls"]["neg-select-calls-rotate"]
        text = self.log_path(rec["log"]).read_text()
        self.rewrite_log(rec["log"], text.replace(
            "unregistered executable function call NativeKeccak._default.Rotate",
            "some other policy violation"))
        self.sync(rec, rec["log"])
        with self.rejects("named rejection"):
            self.validate()
        self.reset()
        rec = self.report["controls"]["neg-wrong-size"]
        self.rewrite_body(rec["log"],
                          "NativeMlKem.dfy(274,20): Error: something failed\n\n"
                          "1 resolution/type errors detected in NativeMlKem.dfy\n")
        self.sync(rec, rec["log"])
        with self.rejects("named rejection"):
            self.validate()
        self.reset()
        rec = self.report["controls"]["neg-wrong-size"]
        self.rewrite_log(rec["log"], self.log_path(rec["log"]).read_text() +
                         "\nVerification timed out\n")
        self.sync(rec, rec["log"])
        with self.rejects("crash/resource|inconclusive"):
            self.validate()
        self.reset()
        rec = self.report["controls"]["neg-shadow-select"]
        self.rewrite_body(rec["log"],
                          "SOURCE-COVERAGE OK: exact roots [NativeMlKem.Select]; ordered "
                          "markers; fail-closed\n")
        self.sync(rec, rec["log"])
        with self.rejects("success, not a rejection|diagnostic"):
            self.validate()

    def test_control_log_digest_and_diagnostics_tuple(self):
        self.report["controls"]["positive-actual"]["log_sha256"] = "0" * 64
        with self.rejects("log changed"):
            self.validate()
        self.reset()
        rec = self.report["controls"]["neg-conditional-alloc"]
        text = self.log_path(rec["log"]).read_text().replace("(278,11)", "(279,11)", 1)
        self.rewrite_log(rec["log"], text)
        self.sync(rec, rec["log"])
        with self.rejects("diagnostics differ"):
            self.validate()

    # ---- case identity --------------------------------------------
    def test_shared_needle_log_substitution_rejects(self):
        donor = "logs/controls/neg-conditional-alloc.log"
        target = "logs/controls/neg-loop-alloc.log"
        self.rewrite_log(target, self.log_path(donor).read_text())
        self.sync(self.report["controls"]["neg-loop-alloc"], target)
        with self.rejects("diagnostics differ|prefix differs|identity"):
            self.validate()

    def test_loop_block_raw_swap_rejects_despite_identical_tuples(self):
        self.assertEqual(G.CASE_DIAGNOSTICS["neg-loop-alloc"],
                         G.CASE_DIAGNOSTICS["neg-block-wrap-alloc"])
        loop = self.report["controls"]["neg-loop-alloc"]
        block = self.report["controls"]["neg-block-wrap-alloc"]
        self.rewrite_log(loop["log"], self.log_path(block["log"]).read_text())
        self.sync(loop, loop["log"])
        with self.rejects("prefix differs|diagnostics differ|identity|fixture"):
            self.validate()

    def test_context_typed_and_raw_mismatch(self):
        rec = self.report["controls"]["neg-loop-alloc"]
        rec["case_context"]["case"] = "neg-block-wrap-alloc"
        self.report["case_contexts"]["neg-loop-alloc"]["case"] = "neg-block-wrap-alloc"
        with self.rejects("identity is not this case|prefix differs"):
            self.validate()
        self.reset()
        rec = self.report["controls"]["neg-loop-alloc"]
        rec["case_context"]["operand_sha256_before"] = "0" * 64
        self.report["case_contexts"]["neg-loop-alloc"]["operand_sha256_before"] = "0" * 64
        with self.rejects("operand|prefix differs"):
            self.validate()
        self.reset()
        rec = self.report["controls"]["neg-loop-alloc"]
        rec["case_context"]["operand_sha256_after"] = "0" * 64
        self.report["case_contexts"]["neg-loop-alloc"]["operand_sha256_after"] = "0" * 64
        with self.rejects("operand changed"):
            self.validate()
        self.reset()
        rec = self.report["controls"]["neg-loop-alloc"]
        rec["case_context"]["extra"] = True
        self.report["case_contexts"]["neg-loop-alloc"]["extra"] = True
        with self.rejects("unexpected keys"):
            self.validate()
        self.reset()
        # typed context correct but raw prefix edited -> prefix mismatch
        rec = self.report["controls"]["neg-loop-alloc"]
        text = self.log_path(rec["log"]).read_text()
        self.rewrite_log(rec["log"], text.replace("CASE-CONTEXT case=neg-loop-alloc",
                                                  "CASE-CONTEXT case=other-case", 1))
        self.sync(rec, rec["log"])
        with self.rejects("prefix differs"):
            self.validate()

    # ---- observed / F2 / encoder ----------------------------------
    def test_observed_and_f2(self):
        self.report["observed"]["method"]["verified"] = 2882
        with self.rejects("summary counts"):
            self.validate()
        self.reset()
        rec = self.report["observed"]["harness"]
        self.rewrite_body(rec["log"],
                          "SelectObservedHarness.dfy(9,11): Error: assertion might not hold\n\n"
                          "Dafny program verifier finished with 1 verified, 1 error\n")
        self.sync(rec, rec["log"])
        with self.rejects("diagnostic anchor|prefix differs|inconclusive"):
            self.validate()
        self.reset()
        self.report["f2"]["coverage_accept"]["status"] = "named-checker-rejection"
        with self.rejects("F2 coverage case"):
            self.validate()
        self.reset()
        rec = self.report["f2"]["dafny_full"]
        self.rewrite_body(rec["log"],
                          "\nDafny program verifier finished with 2773 verified, 0 errors\n")
        self.sync(rec, rec["log"])
        with self.rejects("diagnostic anchor|summary|inconclusive|prefix"):
            self.validate()

    def test_encoder_stages(self):
        self.report["encoder"]["fixtures"]["boolean-flip"]["accept"] = True
        self.report["encoder"]["fixtures"]["boolean-flip"]["exit"] = 0
        with self.rejects("encoder fixture verdict"):
            self.validate()
        self.reset()
        rec = self.report["encoder"]["fixtures"]["alpha-case-formals"]
        self.rewrite_body(rec["log"],
                          "SOURCE-COVERAGE OK: exact roots [NativeKaTeX.SetLane]; ordered "
                          "markers; fail-closed\n")
        self.sync(rec, rec["log"])
        with self.rejects("printed roots differ"):
            self.validate()
        self.reset()
        self.report["encoder"]["proofs"][0]["verified"] = 28
        with self.rejects("summary counts"):
            self.validate()
        self.reset()
        rec = self.report["encoder"]["audits"]["SourceTrace.dfy"]
        self.rewrite_body(rec["log"], "Dafny auditor completed with 1 findings\n")
        self.sync(rec, rec["log"])
        with self.rejects("audit findings"):
            self.validate()
        self.reset()
        record = next(p for p in self.report["encoder"]["proofs"]
                      if p["label"] == "proof-source-trace-bridge")
        record["command"] = [part for part in record["command"]
                             if part != "--verify-included-files"]
        with self.rejects("argv changed"):
            self.validate()

    # ---- baseline13 / retained ------------------------------------
    def test_baseline13_record_and_raw_roots(self):
        del self.report["retained_native"]["baseline13"]
        with self.rejects("record shape changed|baseline13"):
            self.validate()
        self.reset()
        self.report["retained_native"]["baseline13"]["status"] = "ok"
        with self.rejects("named result"):
            self.validate()
        self.reset()
        self.report["retained_native"]["baseline13"]["roots"] = \
            self.report["retained_native"]["baseline13"]["roots"][:-1]
        with self.rejects("identities"):
            self.validate()
        self.reset()
        roots = list(self.report["retained_native"]["baseline13"]["roots"])
        roots[0], roots[1] = roots[1], roots[0]
        self.report["retained_native"]["baseline13"]["roots"] = roots
        with self.rejects("identities"):
            self.validate()

    def test_baseline13_raw_log_and_retained_bindings(self):
        rec = self.report["retained_native"]
        path = self.log_path(rec["baseline13"]["log"])
        text = path.read_text().replace("NativeField.ReduceOnce", "NativeField.Unreviewed", 1)
        path.write_text(text)
        self.sync(rec["baseline13"], rec["baseline13"]["log"])
        with self.rejects("raw log identities|baseline13"):
            self.validate()
        self.reset()
        self.report["retained_native"]["root19_count"] = 17
        with self.rejects("case counts"):
            self.validate()
        self.reset()
        self.report["retained_native"]["plugin_sha256"] = "0" * 64
        with self.rejects("plugin"):
            self.validate()
        self.reset()
        self.report["retained_native"]["report_sha256"] = "0" * 64
        with self.rejects("nested report digest"):
            self.validate()

    # ---- codegen / tools / signature ------------------------------
    def test_codegen_counts_and_logs(self):
        self.report["codegen"]["classes"]["25"]["count"] = 64
        with self.rejects("class count/identity"):
            self.validate()
        self.reset()
        rec = self.report["codegen"]["translations"]["base"]
        self.rewrite_log(rec["log"], self.log_path(rec["log"]).read_text() +
                         "\nWarning: something\n")
        self.sync(rec, rec["log"])
        with self.rejects("diagnostic|did not use"):
            self.validate()
        self.reset()
        rec = self.report["codegen"]["translations"]["overlay"]
        self.rewrite_log(rec["log"], "plain translation output\n")
        self.sync(rec, rec["log"])
        with self.rejects("did not use --no-verify"):
            self.validate()
        self.reset()
        self.report["codegen"]["java_algorithm_files"] = 64
        with self.rejects("algorithm Java file count"):
            self.validate()

    def test_tool_identities_and_signature(self):
        self.report["tool_identity_before"]["checks"][0]["actual"] = "0" * 64
        with self.rejects("tool identity changed"):
            self.validate()
        self.reset()
        self.report["tool_identity_after"]["checks"].pop()
        with self.rejects("tool identity count"):
            self.validate()
        self.reset()
        self.report["tool_identity_before"]["profile_sha256"] = "0" * 64
        with self.rejects("profile digest"):
            self.validate()
        self.reset()
        self.report["input_signature"]["files"]["used_inputs"] = 7
        with self.rejects("signature domains"):
            self.validate()
        self.reset()
        self.report["input_signature"]["stable"] = False
        with self.rejects("stability"):
            self.validate()

    def test_full_harness_and_modes(self):
        self.report["full_native_mlkem"]["verified"] = 2772
        with self.rejects("summary counts"):
            self.validate()
        self.reset()
        self.report["harness"]["errors"] = 1
        with self.rejects("summary counts"):
            self.validate()
        self.reset()
        with self.rejects("unknown reviewed platform"):
            self.validate(platform="windows-x64")
        with self.rejects("only full qualification"):
            self.validate(expected_mode="targeted")
        self.reset()
        self.report["mode"] = "targeted"
        with self.rejects("not a full qualification"):
            self.validate()




    def test_producer_python_provenance_is_not_ambient(self):
        # Raw prefix keeps the producer's historical Python; no comparison to the
        # consumer interpreter and no execution/open of that path.
        rec = self.report["retained_native"]
        path = self.log_path(rec["log"])
        text = path.read_text()
        line, rest = text.split("\n", 1)
        prefix = "CASE-CONTEXT case=retained-native argv="
        argv_text, tail = line[len(prefix):].rsplit(" cwd=", 1)
        argv = json.loads(argv_text)
        argv[0] = "/usr/bin/python3.13"
        line = prefix + json.dumps(argv, separators=(",", ":")) + " cwd=" + tail
        path.write_text(line + "\n" + rest)
        self.sync(rec, rec["log"])
        with unittest.mock.patch.object(sys, "executable", "/opt/other/python3.99"):
            self.assertGreater(self.validate()["checked"], 100)

    def test_companion_map_pin_cannot_be_renewed_by_index(self):
        maps = self.fixture / "derived-codegen-maps"
        for name in ("java-base", "java-overlay"):
            path = maps / (name + ".sha256")
            lines = path.read_text().splitlines()
            lines[0] = lines[0].rsplit(" ", 1)[0] + " " + "0" * 64
            path.write_text("\n".join(lines) + "\n")
            index_path = self.fixture / "COLLECTION-FILES.json"
            index = json.loads(index_path.read_text())
            rel = "derived-codegen-maps/" + name + ".sha256"
            index["files"][rel]["sha256"] = G._sha(path)
            index_path.write_text(json.dumps(index, indent=1, sort_keys=True) + "\n")
        with self.rejects("not the reviewed .* pin"):
            self.validate(companion_collection=self.fixture)

    def test_linked_package_ancestor_rejected(self):
        package = self.ws / "formal/source/select"
        outside = Path(self._tmp.name) / "moved-package"
        shutil.move(str(package), str(outside))
        package.symlink_to(outside, target_is_directory=True)
        try:
            with self.rejects("workspace component is a symlink"):
                self.validate()
        finally:
            package.unlink()
            shutil.move(str(outside), str(package))

    def test_retained_case_verdict_forgery_rejected(self):
        nested_path = self.fixture / "retained-native/fixture/report.json"
        nested = json.loads(nested_path.read_text())
        nested["root19"]["alloc-unmarked"] = {"exit": 0, "status": "SOURCE-COVERAGE OK"}
        nested_path.write_text(json.dumps(nested, indent=2, sort_keys=True) + "\n")
        self.report["retained_native"]["report_sha256"] = G._sha(nested_path)
        with self.rejects("not the reviewed named rejection|not the reviewed accepted result"):
            self.validate()

    def test_negative_with_tool_parser_or_type_failure_rejected(self):
        for extra in ("Unhandled exception: deliberate tool failure probe",
                      "Parser error: deliberate probe",
                      "Error: unresolved identifier deliberateProbe"):
            self.reset()
            rec = self.report["f2"]["dafny_full"]
            path = self.log_path(rec["log"])
            path.write_text(path.read_text() + "\n" + extra + "\n")
            self.sync(rec, rec["log"])
            with self.rejects("inconclusive|parser/type/resolution/warning"):
                self.validate()


class ColdLinuxActualTests(unittest.TestCase):
    """Actual Linux FULL cold positive (same schema-2 gate, linux-x64 profile)."""

    @classmethod
    def setUpClass(cls):
        report = LINUX_RUN / "package-report.json"
        if not report.is_file():
            raise AssertionError("actual Linux FULL report not present")
        cls._tmp = tempfile.TemporaryDirectory(prefix="select-gate-linux-")
        cls.ws = _copy_frozen(Path(cls._tmp.name))
        if LINUX_COLLECTION.is_dir():
            cls.collection = Path(cls._tmp.name) / "linux-evidence"
            shutil.copytree(LINUX_COLLECTION, cls.collection)
        else:
            cls.collection = _derive_collection(LINUX_RUN,
                                                Path(cls._tmp.name) / "linux-evidence")
        cls.report = report

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_actual_linux_full_admits_cold(self):
        result = G.validate_select_source(self.report, workspace_root=self.ws,
                                          platform="linux-x64",
                                          companion_collection=self.collection)
        self.assertEqual(result["platform"], "linux-x64")
        self.assertEqual(result["package_sha256"], G.PACKAGE_PINS["package_sha256"])
        self.assertEqual(result["profile_sha256"], G.PROFILE_PINS["linux-x64"]["sha256"])
        self.assertGreater(result["checked"], 100)
        self.assertEqual(result["input_counts"],
                         {"baseline_dafny": 85, "dafny": 85, "package": 311, "used_inputs": 8})
        self.assertTrue(result["companion_maps"]["class_identity"]["25"])

    def test_wrong_platform_report_rejected(self):
        with self.assertRaises(G.SelectGateError):
            G.validate_select_source(self.report, workspace_root=self.ws,
                                     platform="macos-arm64",
                                     companion_collection=self.collection)


class SupportedClaimWrapperTests(unittest.TestCase):
    def test_both_collections_are_mandatory(self):
        report = Path(tempfile.mkdtemp()) / "report.json"
        report.write_text("{}")
        with self.assertRaisesRegex(G.SelectGateError, "companion collection"):
            G.validate_supported_select_claim(macos=(report, None), linux=(report, None),
                                              workspace_root=FROZEN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
