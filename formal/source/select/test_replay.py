#!/usr/bin/env python3
"""Quick unit tests for the production Select package (no Dafny/dotnet runs).

These tests exercise the packaging/portability contract only: split manifests, reviewed
tool profiles, output refusal, timeout preservation, non-qualifying self-test, case
context emission, and the strict source inventory. Expensive semantic replays are run by
ROOT separately.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("select_replay", HERE / "replay.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

PACKAGE = json.loads((HERE / "package.json").read_text())
BASELINE = json.loads((HERE / "baseline.json").read_text())
PACKAGE_SHA = R.sha(HERE / "package.json")
LINUX_PROFILE = "linux-sdk10.0.400"
LINUX_PROFILE_SHA = json.loads((HERE / "profiles/index.json").read_text())["profiles"][LINUX_PROFILE]


class PackageTests(unittest.TestCase):
    def test_schema_and_bindings(self):
        self.assertEqual(PACKAGE["schema"], R.PACKAGE_SCHEMA)
        self.assertEqual(BASELINE["schema"], "microproxy.select-baseline/2")
        self.assertEqual(R.sha(HERE / "baseline.json"), PACKAGE["baseline_manifest_sha256"])
        self.assertEqual(R.sha(HERE / "profiles/index.json"), PACKAGE["profile_index_sha256"])
        self.assertEqual(PACKAGE["controls_expected"], R.EXPECTED_CONTROLS)
        self.assertEqual(PACKAGE["encoder_expected"], R.EXPECTED_ENCODER)
        self.assertFalse((HERE / "inputs.json").exists(), "legacy inputs.json must be replaced")

    def test_closure_is_exactly_two_declared_diffs(self):
        base = BASELINE["baseline_formal_dafny_hashes"]
        cand = BASELINE["candidate_formal_dafny_hashes_excluding_select_package"]
        self.assertEqual(len(base), 85)
        self.assertEqual(len(cand), 85)
        diff = sorted(rel for rel in base if base[rel] != cand[rel])
        self.assertEqual(diff, ["crypto/NativeMlKem.dfy", "crypto/native_kem_domain.dfy"])
        self.assertEqual(BASELINE["candidate_allowed_formal_diff"], diff)
        self.assertEqual(BASELINE["baseline_to_candidate_equal_count"], 83)
        self.assertEqual(cand["crypto/NativeMlKem.dfy"], PACKAGE["candidate_overlay_sha256"])
        self.assertEqual(cand["crypto/native_kem_domain.dfy"],
                         PACKAGE["native_kem_patch"]["domain_patched_sha256"])

    def test_strict_inventory_has_no_output_artifacts(self):
        files = BASELINE["package_files"]
        self.assertEqual(len(files), BASELINE["package_files_count"])
        for rel in files:
            self.assertNotIn("/work/", rel)
            self.assertNotIn("__pycache__", rel)
            self.assertFalse(rel.endswith(".pyc"), rel)
            self.assertFalse(rel.endswith("/bin/" + rel.split("/")[-1]) and rel.split("/")[-2:-1] == ["bin"],
                             rel)
            self.assertNotIn(rel, ("package.json", "baseline.json"))
        self.assertNotIn("fixtures/retained-native/report.json", files)
        self.assertNotIn("fixtures/retained-native/work/build.log", files)
        self.assertTrue(any(rel.startswith("controls/neg-") for rel in files))
        self.assertTrue(any(rel.startswith("fixtures/encoder-fixtures-v2/") for rel in files))

    def test_verify_package_binds_external_hash(self):
        pkg = R.verify_package(HERE, PACKAGE_SHA)
        self.assertEqual(pkg["schema"], R.PACKAGE_SCHEMA)
        with self.assertRaises(R.GateError):
            R.verify_package(HERE, "0" * 64)
        with self.assertRaises(R.GateError):
            R.verify_package(HERE, "not-a-hash")


class ProfileTests(unittest.TestCase):
    def test_named_profiles_are_identity_only(self):
        for name in ("linux-sdk10.0.400", "macos-sdk10.0.400"):
            profile, ident = R.load_profile(HERE, name, None, "linux-x64" if name.startswith("linux") else "macos-arm64")
            self.assertEqual(set(profile), R.PROFILE_IDENTITY_FIELDS)
            self.assertEqual(profile["dotnet_sdk"], "10.0.400")
            self.assertEqual(profile["checker_dll_expected_sha256"],
                             "2785f06aef69011784a64f7cf5cfbeded0c3722760d9ca4317778b12e932cd67")
            self.assertTrue(ident["package_pinned"])

    def test_linux_and_mac_profiles_differ_only_in_platform_identities(self):
        linux, _ = R.load_profile(HERE, "linux-sdk10.0.400", None, "linux-x64")
        mac, _ = R.load_profile(HERE, "macos-sdk10.0.400", None, "macos-arm64")
        self.assertEqual(linux["dafny_core_sha256"], mac["dafny_core_sha256"])
        self.assertEqual(linux["checker_dll_expected_sha256"], mac["checker_dll_expected_sha256"])
        self.assertEqual(linux["runtime_sha256"], mac["runtime_sha256"])
        self.assertNotEqual(linux["dafny_sha256"], mac["dafny_sha256"])
        self.assertNotEqual(linux["z3_sha256"], mac["z3_sha256"])

    def test_external_profile_hash_is_enforced(self):
        R.load_profile(HERE, LINUX_PROFILE, LINUX_PROFILE_SHA, "linux-x64")
        with self.assertRaises(R.GateError):
            R.load_profile(HERE, LINUX_PROFILE, "0" * 64, "linux-x64")
        with self.assertRaises(R.GateError):
            R.load_profile(HERE, "does-not-exist", None)

    def test_path_profile_requires_external_hash(self):
        path = HERE / "profiles" / "linux-sdk10.0.400.json"
        with self.assertRaises(R.GateError):
            R.load_profile(HERE, str(path), None, "linux-x64")
        profile, ident = R.load_profile(HERE, str(path), LINUX_PROFILE_SHA, "linux-x64")
        self.assertFalse(ident["package_pinned"])

    def test_profile_with_machine_paths_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="select-profile-") as tmp:
            bad = json.loads((HERE / "profiles" / "linux-sdk10.0.400.json").read_text())
            bad["dafny"] = "/opt/dafny/dafny"
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps(bad))
            with self.assertRaises(R.GateError):
                R.load_profile(HERE, str(path), R.sha(path))

    def test_profile_with_absolute_value_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="select-profile-") as tmp:
            bad = json.loads((HERE / "profiles" / "linux-sdk10.0.400.json").read_text())
            bad["dafny_sha256"] = "/opt/dafny/dafny"
            path = Path(tmp) / "bad2.json"
            path.write_text(json.dumps(bad))
            with self.assertRaises(R.GateError):
                R.load_profile(HERE, str(path), R.sha(path))


class OutputTests(unittest.TestCase):
    def test_existing_file_is_refused_and_preserved(self):
        with tempfile.TemporaryDirectory(prefix="select-out-") as tmp:
            target = Path(tmp) / "out"
            target.write_text("sentinel")
            with self.assertRaises(R.GateError):
                R.prepare_output(target)
            self.assertEqual(target.read_text(), "sentinel")

    def test_existing_directory_is_refused_and_preserved(self):
        with tempfile.TemporaryDirectory(prefix="select-out-") as tmp:
            target = Path(tmp) / "out"
            target.mkdir()
            (target / "keep.txt").write_text("keep")
            with self.assertRaises(R.GateError):
                R.prepare_output(target)
            self.assertEqual((target / "keep.txt").read_text(), "keep")

    def test_dangling_symlink_is_refused_and_preserved(self):
        with tempfile.TemporaryDirectory(prefix="select-out-") as tmp:
            target = Path(tmp) / "out"
            os.symlink(Path(tmp) / "missing-target", target)
            with self.assertRaises(R.GateError):
                R.prepare_output(target)
            self.assertTrue(target.is_symlink())
            self.assertFalse((Path(tmp) / "missing-target").exists())

    def test_fresh_output_is_created(self):
        with tempfile.TemporaryDirectory(prefix="select-out-") as tmp:
            target = Path(tmp) / "fresh"
            self.assertEqual(R.prepare_output(target), target.resolve())
            self.assertTrue(target.is_dir())


class RunTests(unittest.TestCase):
    def test_timeout_preserves_partial_output_and_appends_marker(self):
        with tempfile.TemporaryDirectory(prefix="select-run-") as tmp:
            log = Path(tmp) / "logs" / "slow.log"
            script = "import sys,time;print('PARTIAL-STDOUT',flush=True);sys.stderr.write('PARTIAL-STDERR\\n');sys.stderr.flush();time.sleep(5)"
            rc, text, _ = R.run([sys.executable, "-c", script], log, timeout=0.4)
            self.assertEqual(rc, 124)
            self.assertIn("PARTIAL-STDOUT", text)
            self.assertIn("PARTIAL-STDERR", text)
            self.assertIn(R.TIMEOUT_MARKER, text)
            self.assertEqual(text.count(R.TIMEOUT_MARKER), 1)

    def test_case_context_prefix_precedes_unmodified_tool_output(self):
        with tempfile.TemporaryDirectory(prefix="select-ctx-") as tmp:
            operand = Path(tmp) / "operand.txt"
            operand.write_text("payload")
            log = Path(tmp) / "case.log"
            cmd = [sys.executable, "-c",
                   "print('TOOL-LINE-1');print('Dafny program verifier ' + "
                   "'finished with 7 verified, 0 errors')"]
            prefix, record = R.case_context("unit-case", operand, cmd, tmp,
                                            plugin="a" * 64, expected=R.sha(operand))
            rc, text, _ = R.run(cmd, log, prefix=prefix)
            self.assertEqual(rc, 0)
            lines = text.splitlines()
            self.assertTrue(lines[0].startswith("CASE-CONTEXT case=unit-case "))
            self.assertIn("operand_sha256=" + R.sha(operand), lines[0])
            self.assertIn("plugin_sha256=" + "a" * 64, lines[0])
            self.assertEqual(lines[1], "TOOL-LINE-1")
            self.assertEqual(text.count("Dafny program verifier finished with 7 verified, 0 errors"), 1)
            record = R.finish_context(record, operand)
            self.assertEqual(record["operand_sha256_after"], record["operand_sha256_before"])

    def test_case_context_detects_operand_change(self):
        with tempfile.TemporaryDirectory(prefix="select-ctx-") as tmp:
            operand = Path(tmp) / "operand.txt"
            operand.write_text("one")
            prefix, record = R.case_context("drift", operand, ["true"], tmp)
            operand.write_text("two")
            with self.assertRaises(R.GateError):
                R.finish_context(record, operand)


class SelfTestTests(unittest.TestCase):
    def _args(self, **kw):
        base = dict(checker_dll=None, self_test_only=False, expected_checker_dll_sha256=None,
                    mode="full", native_kem_checks=False)
        base.update(kw)
        return type("A", (), base)

    def test_self_test_combinations(self):
        R.validate_cli(self._args(checker_dll="x.dll", self_test_only=True,
                                  expected_checker_dll_sha256="0" * 64, mode="targeted"))
        for bad in (
            self._args(checker_dll="x.dll", self_test_only=False),
            self._args(self_test_only=True),
            self._args(self_test_only=True, checker_dll="x.dll", expected_checker_dll_sha256="0" * 64, mode="full"),
            self._args(self_test_only=True, checker_dll="x.dll", expected_checker_dll_sha256="0" * 64,
                       native_kem_checks=True),
            self._args(expected_checker_dll_sha256="0" * 64),
        ):
            with self.assertRaises(R.GateError):
                R.validate_cli(bad)

    def test_explicit_dll_without_self_test_is_rejected_by_build(self):
        with tempfile.TemporaryDirectory(prefix="select-dll-") as tmp:
            dll = Path(tmp) / "x.dll"
            dll.write_bytes(b"not-a-real-dll")
            with self.assertRaises(R.GateError):
                R.build_checker(HERE, Path(tmp) / "out", "dotnet", "/bin/true", {},
                                checker_dll=str(dll), self_test_only=False,
                                expected_dll_sha=R.sha(dll))


class RetainedWorkspaceTests(unittest.TestCase):
    def test_retained_copy_is_out_of_tree_and_package_is_untouched(self):
        def tree_hash(root):
            rows = []
            for p in sorted(Path(root).rglob("*")):
                if p.is_file():
                    rows.append(str(p.relative_to(root)) + " " + R.sha(p))
            return "\n".join(rows)

        before = tree_hash(HERE)
        work = HERE / "fixtures" / "retained-native" / "work"
        self.assertFalse(work.exists(), "package must not carry generated work artifacts")
        with tempfile.TemporaryDirectory(prefix="select-retained-") as tmp:
            src, fixture = R.retained_workspace(HERE, Path(tmp))
            self.assertTrue((fixture / "run.py").is_file())
            self.assertTrue((fixture / "controls" / "root19.json").is_file())
            self.assertTrue((fixture / "formal").is_dir())
            self.assertFalse((fixture / "work").exists())
            self.assertNotEqual(fixture, src)
            self.assertTrue(str(fixture).startswith(str(Path(tmp))))
        self.assertEqual(before, tree_hash(HERE), "package tree changed during retained copy")


class AmbientTests(unittest.TestCase):
    def test_ambient_selector_cleared_and_exact(self):
        old = dict(os.environ)
        try:
            os.environ["SOURCE_TRACE_ROOTS"] = "NativeField.Reduce,NativeMlKem.Select,NativeMlKem.Select"
            os.environ["SOURCE_TRACE_SHADOW"] = "Shadow"
            env = R.clean_env()
            self.assertEqual([k for k in env if k.startswith("SOURCE_TRACE_")], ["SOURCE_TRACE_ROOTS"])
            self.assertEqual(env["SOURCE_TRACE_ROOTS"], "NativeMlKem.Select")
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_scope_requires_exact_once(self):
        good = "SOURCE-COVERAGE OK: exact roots [NativeMlKem.Select]\n"
        self.assertTrue(R.scope_ok(good))
        self.assertFalse(R.scope_ok(good + good))
        self.assertFalse(R.scope_ok("SOURCE-COVERAGE OK: exact roots [NativeField.Reduce]\n"))



class CodegenHandoffTests(unittest.TestCase):
    """The split manifest/profile API must be honoured by the codegen stage.

    ``package.json`` deliberately carries no tool hashes; the reviewed profile is the
    only authority for the Maven runtime identity. These tests use the real
    ``codegen`` function and mock only the external tool boundary via a sentinel.
    """

    class ReachedTranslator(RuntimeError):
        pass

    def _trees(self, tmp):
        cand = Path(tmp) / "candidate"
        base = Path(tmp) / "baseline"
        out = Path(tmp) / "out"
        (cand / "formal/crypto").mkdir(parents=True)
        (base / "formal/crypto").mkdir(parents=True)
        (cand / "formal/crypto/NativeMlKem.dfy").write_text("candidate\n")
        (base / "formal/crypto/NativeMlKem.dfy").write_text("baseline\n")
        runtime = Path(tmp) / "runtime.jar"
        runtime.write_bytes(b"reviewed-runtime-bytes")
        out.mkdir()
        return cand, base, out, runtime

    def _package_without_tool_hashes(self):
        package = {"expected": {"jdk_classes": 65}}
        self.assertNotIn("runtime_sha256", package)
        self.assertNotIn("profile", package)
        return package

    def test_codegen_uses_profile_runtime_and_reaches_translator(self):
        with tempfile.TemporaryDirectory(prefix="select-codegen-") as tmp:
            cand, base, out, runtime = self._trees(tmp)
            package = self._package_without_tool_hashes()
            profile = {"runtime_sha256": R.sha(runtime)}
            calls = []

            def boundary(cmd, log, cwd=None, env=None, timeout=1800, prefix=None):
                calls.append([str(c) for c in cmd])
                Path(log).parent.mkdir(parents=True, exist_ok=True)
                Path(log).write_text("TRANSLATOR-SENTINEL\n")
                raise self.ReachedTranslator("external translator boundary reached")

            old = R.run
            R.run = boundary
            try:
                with self.assertRaises(self.ReachedTranslator):
                    R.codegen(cand, base, HERE, out, "/sentinel/dafny", runtime,
                              "/sentinel/jdk21", "/sentinel/jdk25", package, profile)
            finally:
                R.run = old
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][:5],
                             ["/sentinel/dafny", "translate", "java", "NativeMlKem.dfy", "--no-verify"])
            self.assertIn("--allow-external-contracts", calls[0])
            self.assertTrue((out / "logs/codegen/base-translate.log").read_text().startswith("TRANSLATOR-SENTINEL"))

    def test_wrong_profile_runtime_is_rejected_before_translator(self):
        with tempfile.TemporaryDirectory(prefix="select-codegen-") as tmp:
            cand, base, out, runtime = self._trees(tmp)
            calls = []
            old = R.run
            R.run = lambda *a, **k: calls.append(a)
            try:
                with self.assertRaises(R.GateError):
                    R.codegen(cand, base, HERE, out, "/sentinel/dafny", runtime,
                              "/sentinel/jdk21", "/sentinel/jdk25",
                              self._package_without_tool_hashes(),
                              {"runtime_sha256": "0" * 64})
            finally:
                R.run = old
            self.assertEqual(calls, [])

    def test_missing_or_malformed_profile_runtime_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="select-codegen-") as tmp:
            cand, base, out, runtime = self._trees(tmp)
            for profile in ({}, {"runtime_sha256": ""}, {"runtime_sha256": "xyz"},
                            {"runtime_sha256": 123}, None):
                with self.assertRaises(R.GateError):
                    R.codegen(cand, base, HERE, out, "/sentinel/dafny", runtime,
                              "/sentinel/jdk21", "/sentinel/jdk25",
                              self._package_without_tool_hashes(), profile)


class ReportLifecycleTests(unittest.TestCase):
    """An unexpected helper defect must still emit a FAILED report and nonzero exit."""

    def _argv(self, tmp, out, pkg):
        return ["--package-root", str(pkg), "--output", str(out),
                "--tool-profile", "linux-sdk10.0.400",
                "--expected-package-sha256", "0" * 64,
                "--dafny", "/sentinel/dafny", "--dotnet", "/sentinel/dotnet",
                "--jdk21", "/sentinel/jdk21", "--jdk25", "/sentinel/jdk25",
                "--runtime", "/sentinel/runtime"]

    def _run(self, tmp, outcome):
        out = Path(tmp) / "out"
        pkg = Path(tmp) / "a/b/c"

        def boom(*args, **kwargs):
            sentinel = out / "partial-output.sentinel"
            sentinel.write_text("preserved\n")
            raise outcome

        old = R.verify_package
        R.verify_package = boom
        try:
            rc = R.main(self._argv(tmp, out, pkg))
        finally:
            R.verify_package = old
        return rc, out

    def test_unexpected_exception_writes_failed_runner_exception_report(self):
        with tempfile.TemporaryDirectory(prefix="select-report-") as tmp:
            rc, out = self._run(tmp, KeyError("runtime_sha256"))
            self.assertEqual(rc, 2)
            report = json.loads((out / "package-report.json").read_text())
            self.assertEqual(report["status"], "FAILED")
            self.assertEqual(report["failure_kind"], "runner-exception")
            self.assertEqual(report["error_type"], "KeyError")
            self.assertIn("KeyError", report["traceback"])
            self.assertIn("runtime_sha256", report["error"])
            self.assertTrue((out / "partial-output.sentinel").is_file(),
                            "partial helper output must be preserved")

    def test_gate_error_stays_failed_without_runner_exception_kind(self):
        with tempfile.TemporaryDirectory(prefix="select-report-") as tmp:
            rc, out = self._run(tmp, R.GateError("named gate failure"))
            self.assertEqual(rc, 2)
            report = json.loads((out / "package-report.json").read_text())
            self.assertEqual(report["status"], "FAILED")
            self.assertEqual(report["error"], "named gate failure")
            self.assertNotIn("failure_kind", report)

    def test_cancellation_never_becomes_qualified(self):
        with tempfile.TemporaryDirectory(prefix="select-report-") as tmp:
            old = R.verify_package
            out = Path(tmp) / "out"

            def interrupted(*args, **kwargs):
                raise KeyboardInterrupt()

            R.verify_package = interrupted
            try:
                with self.assertRaises(KeyboardInterrupt):
                    R.main(self._argv(tmp, out, Path(tmp) / "a/b/c"))
            finally:
                R.verify_package = old
            report = json.loads((out / "package-report.json").read_text())
            self.assertEqual(report["status"], "incomplete")



class OutputAdmissionTests(unittest.TestCase):
    """P1: the real CLI must refuse an unresolved dangling symlink without mutation."""

    def _argv(self, tmp, out):
        return ["--package-root", str(HERE), "--output", str(out),
                "--tool-profile", "macos-sdk10.0.400",
                "--expected-package-sha256", PACKAGE_SHA,
                "--dafny", "/nonexistent/dafny", "--dotnet", "/nonexistent/dotnet",
                "--jdk21", "/nonexistent/jdk21", "--jdk25", "/nonexistent/jdk25",
                "--runtime", "/nonexistent/runtime.jar"]

    def test_cli_dangling_symlink_is_refused_and_target_not_created(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory(prefix="select-cli-") as tmp:
            link = Path(tmp) / "out-link"
            target = Path(tmp) / "out-target"
            link.symlink_to(target)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = R.main(self._argv(tmp, link))
            self.assertEqual(rc, 2)
            self.assertFalse(target.exists(), "symlink target must not be created")
            self.assertTrue(link.is_symlink())
            payload = json.loads(stderr.getvalue().strip().splitlines()[-1])
            self.assertEqual(payload["status"], "rejected")
            self.assertEqual(payload["failure_kind"], "output-admission")
            self.assertEqual(list(Path(tmp).glob("out-*")), [link])

    def test_cli_unwritable_parent_is_typed_rejection(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory(prefix="select-cli-ro-") as tmp:
            parent = Path(tmp) / "readonly"
            parent.mkdir()
            out = parent / "fresh"
            stderr = io.StringIO()
            os.chmod(parent, 0o500)
            try:
                with contextlib.redirect_stderr(stderr):
                    rc = R.main(self._argv(tmp, out))
            finally:
                os.chmod(parent, 0o700)
            self.assertEqual(rc, 2)
            self.assertFalse(out.exists())
            payload = json.loads(stderr.getvalue().strip().splitlines()[-1])
            self.assertEqual(payload["status"], "rejected")
            self.assertEqual(payload["failure_kind"], "output-admission")

    def test_cli_existing_file_is_refused_without_mutation(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory(prefix="select-cli-") as tmp:
            out = Path(tmp) / "existing"
            out.write_text("keep me")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = R.main(self._argv(tmp, out))
            self.assertEqual(rc, 2)
            self.assertEqual(out.read_text(), "keep me")
            self.assertEqual(json.loads(stderr.getvalue().strip().splitlines()[-1])["failure_kind"],
                             "output-admission")


class MissingToolReportTests(unittest.TestCase):
    """P6: a missing tool becomes a typed FAILED report, never a traceback/no report."""

    def test_missing_dafny_writes_typed_failed_report(self):
        with tempfile.TemporaryDirectory(prefix="select-missing-") as tmp:
            out = Path(tmp) / "out"
            argv = ["--package-root", str(HERE), "--output", str(out),
                    "--tool-profile", "macos-sdk10.0.400",
                    "--expected-package-sha256", PACKAGE_SHA,
                    "--dafny", str(Path(tmp) / "no-dafny"), "--dotnet", "/usr/local/share/dotnet/dotnet",
                    "--jdk21", "/nonexistent/jdk21", "--jdk25", "/nonexistent/jdk25",
                    "--runtime", "/nonexistent/runtime.jar"]
            rc = R.main(argv)
            self.assertEqual(rc, 2)
            report = json.loads((out / "package-report.json").read_text())
            self.assertEqual(report["status"], "FAILED")
            self.assertIn("cannot read Dafny binary", report["error"])
            self.assertNotIn("failure_kind", report)


class ManifestClosureTests(unittest.TestCase):
    """P2/P5: the used provider and the complete source/package sets are enforced."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="select-closure-")
        root = Path(cls._tmp.name) / "select"
        shutil.copytree(HERE.parents[2], root / "candidate",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copytree(HERE.parents[3] / "baseline-git-155b", root / "baseline-git-155b",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        cls.root = root
        cls.pkg = root / "candidate/formal/source/select"
        cls.candidate = root / "candidate"
        cls.baseline = root / "baseline-git-155b"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def package(self):
        return R.verify_package(self.pkg, R.sha(self.pkg / "package.json"))

    def test_pristine_copy_passes(self):
        self.assertEqual(self.package()["schema"], R.PACKAGE_SCHEMA)
        R.verify_manifest(self.pkg, self.candidate, self.baseline, self.package())

    def test_provider_tamper_is_rejected(self):
        provider = self.candidate / "formal/crypto/native_kem_hash.java"
        original = provider.read_bytes()
        try:
            provider.write_bytes(original + b"\n// tampered provider\n")
            with self.assertRaisesRegex(R.GateError, "candidate source hash mismatch|used candidate input hash mismatch"):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, self.package())
        finally:
            provider.write_bytes(original)

    def test_extra_candidate_source_is_rejected(self):
        extra = self.candidate / "formal/crypto/extra-input.dfy"
        try:
            extra.write_text("module Extra {}\n")
            with self.assertRaisesRegex(R.GateError, "candidate Dafny file inventory changed"):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, self.package())
        finally:
            extra.unlink(missing_ok=True)

    def test_extra_package_file_is_rejected(self):
        extra = self.pkg / "extra-evidence.json"
        try:
            extra.write_text("{}\n")
            with self.assertRaisesRegex(R.GateError, "package file set changed"):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, self.package())
        finally:
            extra.unlink(missing_ok=True)

    def test_package_symlink_is_rejected(self):
        link = self.pkg / "linked-control"
        try:
            link.symlink_to(self.pkg / "README.md")
            with self.assertRaisesRegex(R.GateError, "contains a symlink"):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, self.package())
        finally:
            link.unlink(missing_ok=True)

    def test_candidate_input_set_is_exact(self):
        package = self.package()
        self.assertEqual(sorted(package["candidate_inputs"]), sorted(R.USED_CANDIDATE_INPUTS))


class ProfileHostTests(unittest.TestCase):
    def test_profile_must_match_declared_host(self):
        with self.assertRaisesRegex(R.GateError, "does not match this host"):
            R.load_profile(HERE, "linux-sdk10.0.400", None, "macos-arm64")

    def test_host_platform_is_canonical(self):
        self.assertIn(R.host_platform(), set(R.PROFILE_PLATFORM_MAP.values()))

    def test_profile_nested_identities_are_complete(self):
        mac, _ = R.load_profile(HERE, "macos-sdk10.0.400", None, "macos-arm64")
        self.assertEqual(len(mac["boogie"]), 13)
        self.assertEqual(set(mac["jdk21_tools"]), {"bin/java", "bin/javac", "bin/javap",
                                                   "lib/modules", "release"})
        self.assertEqual(set(mac["jdk25_tools"]), set(mac["jdk21_tools"]))
        self.assertRegex(mac["dotnet_launcher_sha256"], r"^[0-9a-f]{64}$")


class RetainedBindingTests(unittest.TestCase):
    """P3: the retained report must bind the reviewed profile/checker, not just counts."""

    def _package(self):
        return json.loads((HERE / "package.json").read_text())

    def _profile(self):
        return json.loads((HERE / "profiles/macos-sdk10.0.400.json").read_text())

    def _log(self, roots=None):
        roots = roots or R.EXPECTED_BASELINE13_ROOTS
        return ("CASE-CONTEXT case=baseline13\n"
                "SOURCE-COVERAGE OK: exact roots [" + ",".join(roots) + "]\n")

    def _report(self, plugin, baseline13=None):
        package = self._package()
        report = {"status": "complete", "plugin_sha256": plugin,
                  "checker_source_sha256": package["checker_source_sha256"],
                  "checker_project_sha256": package["checker_project_sha256"],
                  "canonical_policy_sha256": package["checker_policy_sha256"],
                  "pins_before": {"x": "1"}, "pins_after": {"x": "1"},
                  "root19": {str(i): {} for i in range(package["expected"]["retained_root19_cases"])},
                  "callbinding": {str(i): {} for i in range(package["expected"]["retained_callbinding_cases"])}}
        report["baseline13"] = baseline13 if baseline13 is not None else {
            "exit": 0, "status": "SOURCE-COVERAGE OK"}
        return report

    def _verify(self, report, log=None):
        return R.verify_retained_report(report, self._package(), self._profile(),
                                        self._log() if log is None else log)

    def test_wrong_plugin_is_rejected(self):
        with self.assertRaisesRegex(R.GateError, "plugin does not match"):
            self._verify(self._report("0" * 64))

    def test_reviewed_plugin_passes(self):
        report = self._verify(self._report(self._profile()["checker_dll_expected_sha256"]))
        self.assertEqual(len(report["root19"]), 18)

    def test_missing_or_wrong_baseline13_record_is_rejected(self):
        good = self._report(self._profile()["checker_dll_expected_sha256"])
        missing = dict(good)
        missing.pop("baseline13")
        with self.assertRaisesRegex(R.GateError, "baseline13 record missing"):
            self._verify(missing)
        for broken in ({"exit": 0, "status": "ok"},
                       {"exit": 2, "status": "SOURCE-COVERAGE OK"},
                       {"status": "SOURCE-COVERAGE OK"}):
            with self.assertRaisesRegex(R.GateError, "named coverage result"):
                self._verify(self._report(self._profile()["checker_dll_expected_sha256"], broken))

    def test_baseline13_raw_log_must_carry_exact_roots(self):
        good = self._report(self._profile()["checker_dll_expected_sha256"])
        with self.assertRaisesRegex(R.GateError, "exactly one named coverage line"):
            self._verify(good, "no coverage marker here\n")
        with self.assertRaisesRegex(R.GateError, "exactly one named coverage line"):
            self._verify(good, self._log() + self._log())
        with self.assertRaisesRegex(R.GateError, "root count changed"):
            self._verify(good, self._log(R.EXPECTED_BASELINE13_ROOTS[:-1]))
        wrong = list(R.EXPECTED_BASELINE13_ROOTS)
        wrong[0] = "NativeField.Unreviewed"
        with self.assertRaisesRegex(R.GateError, "identities changed"):
            self._verify(good, self._log(wrong))
        duplicated = list(R.EXPECTED_BASELINE13_ROOTS)
        duplicated[1] = duplicated[0]
        with self.assertRaisesRegex(R.GateError, "duplicate identities"):
            self._verify(good, self._log(duplicated))
        self.assertTrue(self._verify(good, self._log()))

    def test_missing_log_argument_is_rejected(self):
        with self.assertRaisesRegex(R.GateError, "raw log missing"):
            R.verify_retained_report(self._report(self._profile()["checker_dll_expected_sha256"]),
                                     self._package(), self._profile(), None)

    def test_retained_native_requires_explicit_dotnet_in_command(self):
        text = (HERE / "fixtures/retained-native/run.py").read_text()
        self.assertIn('parser.add_argument("--dotnet", required=True', text)
        self.assertNotIn('["dotnet", "--version"]', text)



class InputDomainTests(unittest.TestCase):
    """Exact used-closure domains: outer evidence/docs are not Select inputs."""

    OUTER_POLY = Path("/Users/mahmoud/.cache/microproxy-formal/issue117-source-assurance-20261103/select-adoption-data/repo/formal/source/polynomial/replay.py")

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="select-domain-")
        root = Path(cls._tmp.name) / "select"
        shutil.copytree(HERE.parents[2], root / "candidate",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "bin", "obj", "work"))
        shutil.copytree(HERE.parents[3] / "baseline-git-155b", root / "baseline-git-155b",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        cls.root = root
        cls.pkg = root / "candidate/formal/source/select"
        cls.candidate = root / "candidate"
        cls.baseline = root / "baseline-git-155b"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def package(self):
        return R.verify_package(self.pkg, R.sha(self.pkg / "package.json"))

    def admit(self, package=None):
        package = package or self.package()
        man = R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        profile = json.loads((self.pkg / "profiles/macos-sdk10.0.400.json").read_text())
        identity = {"path": str(self.pkg / "profiles/macos-sdk10.0.400.json"),
                    "sha256": R.sha(self.pkg / "profiles/macos-sdk10.0.400.json")}
        return man, R.input_signature(self.pkg, self.candidate, self.baseline, man, package, identity)

    def test_outer_output_mutations_do_not_change_admission_or_signature(self):
        _, before = self.admit()
        ledger = self.candidate / "formal/crypto-obligations.json"
        crypto_readme = self.candidate / "formal/crypto/README.md"
        poly = self.candidate / "formal/source/polynomial/replay.py"
        evidence_dir = self.candidate / "formal/crypto/evidence/2026-11-04-poly"
        saved = {p: p.read_bytes() for p in (ledger, crypto_readme, poly)}
        removed = None
        for path in sorted(evidence_dir.rglob("*.log")):
            removed = path
            break
        self.assertIsNotNone(removed)
        removed_bytes = removed.read_bytes()
        made = []
        try:
            ledger.write_bytes(saved[ledger] + b"\n")
            crypto_readme.write_bytes(saved[crypto_readme] + b"\nupdated docs\n")
            root_readme = self.candidate / "formal/README.md"
            root_readme.write_text("# root docs mutation\n")
            made.append(root_readme)
            extra = evidence_dir / "extra-evidence.json"
            extra.write_text("{}\n")
            made.append(extra)
            removed.unlink()
            if self.OUTER_POLY.is_file():
                poly.write_bytes(self.OUTER_POLY.read_bytes())
                self.assertNotEqual(poly.read_bytes(), saved[poly])
            man, after = self.admit()
            self.assertEqual(before, after, "outer outputs must not change the Select input signature")
            self.assertEqual(len(man["package_files"]), 309)
        finally:
            for path, data in saved.items():
                path.write_bytes(data)
            removed.write_bytes(removed_bytes)
            for path in made:
                path.unlink(missing_ok=True)

    def test_each_used_input_drift_is_rejected(self):
        package = self.package()
        for rel in sorted(package["candidate_inputs"]):
            path = self.candidate / rel
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"\n")
                with self.assertRaises(R.GateError):
                    R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
            finally:
                path.write_bytes(original)
        # optional provenance drift is one of the checked used inputs
        self.assertIn("formal/crypto/reference/provenance.json", package["candidate_inputs"])

    def test_provider_drift_fails_before_translator(self):
        provider = self.candidate / "formal/crypto/native_kem_hash.java"
        original = provider.read_bytes()
        try:
            provider.write_bytes(original + b"\n// tampered\n")
            out = Path(self._tmp.name) / "provider-out"
            argv = ["--package-root", str(self.pkg), "--baseline-root", str(self.baseline),
                    "--output", str(out), "--tool-profile", "macos-sdk10.0.400",
                    "--expected-package-sha256", R.sha(self.pkg / "package.json"),
                    "--dafny", "/sentinel/dafny", "--dotnet", "/sentinel/dotnet",
                    "--jdk21", "/sentinel/jdk21", "--jdk25", "/sentinel/jdk25",
                    "--runtime", "/sentinel/runtime.jar"]
            rc = R.main(argv)
            self.assertEqual(rc, 2)
            report = json.loads((out / "package-report.json").read_text())
            self.assertEqual(report["status"], "FAILED")
            self.assertIn("used candidate input hash mismatch", report["error"])
            self.assertFalse((out / "logs/codegen").exists(), "translator must not run")
            self.assertFalse((out / "checker-build").exists(), "checker must not run")
        finally:
            provider.write_bytes(original)

    def test_arbitrary_used_input_key_added_or_omitted_is_rejected(self):
        package = self.package()
        extra = dict(package["candidate_inputs"])
        extra["formal/crypto/unreviewed-extra.py"] = "0" * 64
        with self.assertRaisesRegex(R.GateError, "used candidate input set changed"):
            R.verify_manifest(self.pkg, self.candidate, self.baseline, {**package, "candidate_inputs": extra})
        omitted = dict(package["candidate_inputs"])
        omitted.pop("formal/crypto/native_kem_test.java")
        with self.assertRaisesRegex(R.GateError, "used candidate input set changed"):
            R.verify_manifest(self.pkg, self.candidate, self.baseline, {**package, "candidate_inputs": omitted})
        with self.assertRaisesRegex(R.GateError, "escapes the candidate root"):
            R.verify_used_inputs(self.candidate, {"formal/../escape.py": "0" * 64})
        with self.assertRaisesRegex(R.GateError, "missing or not a regular file"):
            R.verify_used_inputs(self.candidate, {"formal/crypto/does-not-exist.java": "0" * 64})
        file_link = self.candidate / "formal/used-file-link.java"
        try:
            file_link.symlink_to(self.candidate / "formal/crypto/native_kem_hash.java")
            with self.assertRaisesRegex(R.GateError, "symlink component"):
                R.verify_used_inputs(self.candidate, {"formal/used-file-link.java": "0" * 64})
        finally:
            file_link.unlink(missing_ok=True)

    def test_outside_dafny_add_remove_modify_link_rejected(self):
        package = self.package()
        extra = self.candidate / "formal/crypto/extra-observer.dfy"
        try:
            extra.write_text("module Extra {}\n")
            with self.assertRaises(R.GateError):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            extra.unlink(missing_ok=True)
        victim = self.candidate / "formal/crypto/NativeField.dfy"
        moved = victim.with_suffix(".dfy.bak")
        try:
            victim.rename(moved)
            with self.assertRaises(R.GateError):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            moved.rename(victim)
        original = victim.read_bytes()
        try:
            victim.write_bytes(original + b"\n// drift\n")
            with self.assertRaises(R.GateError):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            victim.write_bytes(original)
        try:
            victim.unlink()
            victim.symlink_to(self.candidate / "formal/crypto/NativeKeccak.dfy")
            with self.assertRaises(R.GateError):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            victim.unlink(missing_ok=True)
            victim.write_bytes(original)

    def test_package_build_artifacts_are_rejected_at_admission(self):
        package = self.package()
        for rel in ("checker/bin/fake.dll", "checker/obj/fake.json",
                    "fixtures/retained-native/work/fake.log",
                    "fixtures/retained-native/report.json"):
            path = self.pkg / rel
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("artifact\n")
                with self.assertRaisesRegex(R.GateError, "package file set changed"):
                    R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
            finally:
                path.unlink(missing_ok=True)
                parent = path.parent
                if parent.name in {"bin", "obj", "work"} and not any(parent.iterdir()):
                    parent.rmdir()

    def test_unrelated_outer_extension_files_are_not_select_inputs(self):
        _, before = self.admit()
        made = []
        try:
            for rel in ("formal/crypto/notes.py", "formal/crypto/Unused.java",
                        "formal/unused/source.py"):
                path = self.candidate / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("pass\n")
                made.append(path)
            _, after = self.admit()
            self.assertEqual(before, after)
        finally:
            for path in made:
                path.unlink(missing_ok=True)


    def test_reference_directory_symlink_outside_candidate_is_rejected(self):
        package = self.package()
        ref = self.candidate / "formal/crypto/reference"
        backup = self.candidate / "formal/crypto/reference-real"
        external = Path(self._tmp.name) / "external-reference"
        external.mkdir(exist_ok=True)
        for path in ref.iterdir():
            if path.is_file():
                (external / path.name).write_bytes(path.read_bytes())
        ref.rename(backup)
        ref.symlink_to(external, target_is_directory=True)
        try:
            with self.assertRaisesRegex(R.GateError, "symlink component"):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            ref.unlink()
            backup.rename(ref)
        self.assertTrue((ref / "provenance.json").is_file())

    def test_reference_directory_symlink_inside_candidate_is_rejected(self):
        package = self.package()
        ref = self.candidate / "formal/crypto/reference"
        backup = self.candidate / "formal/crypto/reference-real"
        inside = self.candidate / "formal/crypto/reference-copy"
        shutil.copytree(ref, inside)
        ref.rename(backup)
        ref.symlink_to(inside, target_is_directory=True)
        try:
            with self.assertRaisesRegex(R.GateError, "symlink component"):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            ref.unlink()
            backup.rename(ref)
            shutil.rmtree(inside)


    def test_baseline_dafny_set_is_exact_and_contained(self):
        package = self.package()
        extra = self.baseline / "formal/crypto/extra-v3.dfy"
        try:
            extra.write_text("module Extra {}\n")
            with self.assertRaisesRegex(R.GateError, "baseline Dafny file inventory changed"):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            extra.unlink(missing_ok=True)
        victim = self.baseline / "formal/crypto/NativeField.dfy"
        moved = victim.with_suffix(".dfy.aside")
        try:
            victim.rename(moved)
            with self.assertRaises(R.GateError):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            moved.rename(victim)
        native = self.baseline / "formal/crypto/NativeMlKem.dfy"
        original = native.read_bytes()
        copy = self.baseline / "formal/crypto/NativeMlKem.real.dfy"
        try:
            copy.write_bytes(original)
            native.unlink()
            native.symlink_to(copy)
            with self.assertRaisesRegex(R.GateError, "symlink component"):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            native.unlink(missing_ok=True)
            native.write_bytes(original)
            copy.unlink(missing_ok=True)
        crypto = self.baseline / "formal/crypto"
        aside = self.baseline / "formal/crypto-real"
        try:
            crypto.rename(aside)
            crypto.symlink_to(aside, target_is_directory=True)
            with self.assertRaisesRegex(R.GateError, "symlink component"):
                R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
        finally:
            crypto.unlink(missing_ok=True)
            aside.rename(crypto)

    def test_input_signature_binds_baseline_domain(self):
        _, sig = self.admit()
        self.assertEqual(len(sig["baseline_dafny"]), 85)
        self.assertEqual(len(sig["dafny"]), 85)
        self.assertIn("crypto/NativeMlKem.dfy", sig["baseline_dafny"])

    def test_empty_reserved_directories_are_rejected(self):
        package = self.package()
        for rel in ("checker/bin", "checker/obj", "fixtures/retained-native/work"):
            path = self.pkg / rel
            try:
                path.mkdir(parents=True)
                with self.assertRaisesRegex(R.GateError, "unexpected build/work directory"):
                    R.verify_manifest(self.pkg, self.candidate, self.baseline, package)
            finally:
                path.rmdir()
                parent = path.parent
                if parent.name in {"checker", "retained-native"} and not any(parent.iterdir()):
                    pass

    def test_actual_clean_retained_record_and_raw_log_admit(self):
        root = HERE.parents[3] / "preflight-final-2/retained-clean/retained-native/fixture"
        report_path = root / "report.json"
        log_path = root / "work/baseline13.log"
        if not report_path.is_file() or not log_path.is_file():
            self.skipTest("historical retained-clean fixture not present in this checkout")
        report = json.loads(report_path.read_text())
        package = self.package()
        profile = json.loads((self.pkg / "profiles/macos-sdk10.0.400.json").read_text())
        R.verify_retained_report(report, package, profile, log_path.read_text())

    def test_retained_native_rejects_missing_baseline13_log(self):
        # retained_native reads fixture/work/baseline13.log from the out-of-tree copy.
        src = (HERE / "replay.py").read_text()
        self.assertIn('baseline13_log = fixture / "work" / "baseline13.log"', src)
        self.assertIn("baseline13 raw log missing", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
