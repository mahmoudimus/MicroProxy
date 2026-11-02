"""Fail-closed regressions for actual current-release artifact validation.

These tests use isolated fake tool checkouts for fast subprocess/exit/timeout
binding regressions and the synthetic ledger fixture from
``test_crypto_obligations`` for release-policy regressions.  They do not replace
the reviewed ``formal/crypto`` tool tests: the real positive integration runs
the actual delivery and bundle validators against current artifacts.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_crypto_release as release  # noqa: E402
import crypto_current_release as artifacts  # noqa: E402
from test_crypto_obligations import Fixture  # noqa: E402


def _sha(data: bytes | str) -> str:
    import hashlib
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _write_executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


FAKE_DELIVERY = r'''#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

parser = argparse.ArgumentParser()
parser.add_argument("mode")
parser.add_argument("--stage")
parser.add_argument("--classes")
parser.add_argument("--jar")
parser.add_argument("--runtime")
parser.add_argument("--java-home")
parser.add_argument("--timeout")
args = parser.parse_args()
mode = os.environ.get("FAKE_DELIVERY_MODE", "ok")
if mode == "nonzero":
    print("delivery rejected", file=sys.stderr)
    sys.exit(7)
if mode == "timeout":
    time.sleep(30)
    sys.exit(0)
if mode == "timeout_grandchild":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    Path(os.environ["FAKE_GRANDCHILD_PID"]).write_text(str(child.pid))
    time.sleep(60)
    sys.exit(0)
if mode == "malformed":
    print("not-json")
    sys.exit(0)
stage = json.loads((Path(args.stage) / "receipt.json").read_text())
classes = {}
for path in sorted(Path(args.classes).rglob("*.class")):
    classes[path.relative_to(args.classes).as_posix()] = digest(path)
receipt = {
    "status": "checked",
    "stage_receipt_sha256": digest(Path(args.stage) / "receipt.json"),
    "jar_sha256": digest(args.jar),
    "class_count": len(classes),
    "generated_class_count": len(stage.get("canonical_classes", {})),
    "classes": classes,
    "handwritten_sources": 401,
    "handwritten_lint": ["-Xlint:all,-serial"],
    "existing_generated_sources": {"fixture.java": "a" * 64},
    "comparison": "exact class bytes including all debug attributes",
}
if mode == "incomplete":
    receipt["status"] = "incomplete"
print(json.dumps(receipt))
if mode == "alter_after":
    with Path(args.jar).open("ab") as stream:
        stream.write(b"altered")
'''


FAKE_BUNDLE = r'''#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

parser = argparse.ArgumentParser()
parser.add_argument("--library")
parser.add_argument("--bundle")
parser.add_argument("--delivery-receipt")
parser.add_argument("--stage")
parser.add_argument("--runtime")
parser.add_argument("--java-home", action="append")
parser.add_argument("--output")
args = parser.parse_args()
mode = os.environ.get("FAKE_BUNDLE_MODE", "ok")
if mode == "nonzero":
    print("bundle rejected", file=sys.stderr)
    sys.exit(9)
if mode == "timeout":
    time.sleep(30)
    sys.exit(0)
out = Path(args.output)
out.mkdir(parents=True, exist_ok=False)
receipt_path = out / "receipt.json"
if mode == "malformed":
    receipt_path.write_text("{not-json")
    print(receipt_path)
    sys.exit(0)
delivery = json.loads(Path(args.delivery_receipt).read_text())
classes = delivery["classes"]
names = list(classes)
crypto = {name: classes[name] for name in names[:84]}
retained = dict(classes)
if mode == "short_retained":
    retained.pop(next(iter(retained)))
runtime_classes = {
    "dafny/Fixture%d.class" % index: hashlib.sha256(("rt%d" % index).encode()).hexdigest()
    for index in range(37)
}
resources = {
    "META-INF/LICENSE-dafny.txt": "a" * 64,
    "META-INF/LICENSE-go-mlkem.txt": "b" * 64,
    "META-INF/NOTICE-crypto.txt": "c" * 64,
}
runs = {
    "21": {"completed_full_handshakes": 9, "loaded_classes": {"fixture": "origin"}},
    "25": {"completed_full_handshakes": 9, "loaded_classes": {"fixture": "origin"}},
}
here = Path(__file__).resolve()
harness_source = here.parents[2] / "formal/nonce/BundleNonceSmoke.java"
harness_sha = digest(harness_source)
suites = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
nonce_origins = {
    "PacketKey": "/fixture/bundle.jar",
    "VerifiedNonce": "/fixture/bundle.jar",
    "DafnyRuntime": "/fixture/bundle.jar",
    "harness": "/fixture/nonce-harness",
}
nonce_detail = [
    {"suite": suite, "packet_number": pn, "nonce": "00" * 12,
     "ciphertext_sha256": hashlib.sha256((suite + str(pn)).encode()).hexdigest()}
    for suite in suites for pn in (0, 1, -1)
]
nonce_loaded = {
    "io.github.mahmoudimus.quic.crypto.PacketKey": nonce_origins["PacketKey"],
    "io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default":
        nonce_origins["PacketKey"],
    "nonceadoption.BundleNonceSmoke": nonce_origins["harness"],
    "dafny.Helpers": nonce_origins["DafnyRuntime"],
}
nonce_runs = {
    major: {"cases": 9, "passed": 9, "origins": nonce_origins,
            "cases_detail": nonce_detail,
            "classload_sha256": hashlib.sha256((major + "nonce").encode()).hexdigest(),
            "loaded_classes": nonce_loaded}
    for major in ("21", "25")
}
nonce_smoke = {
    "schema": "microproxy.nonce-bundle-smoke/v1",
    "source": "formal/nonce/BundleNonceSmoke.java",
    "source_sha256": harness_sha,
    "harness_classes": {"nonceadoption/BundleNonceSmoke.class": harness_sha},
    "runs": nonce_runs,
}
receipt = {
    "schema": "microproxy.crypto-current-bundle/v2",
    "status": "complete",
    "artifact_inputs": {
        "library.jar": digest(args.library),
        "bundle.jar": digest(args.bundle),
        "delivery.json": digest(args.delivery_receipt),
        "runtime-reference.jar": digest(args.runtime),
    },
    "library_jar_sha256": digest(args.library),
    "bundle_jar_sha256": digest(args.bundle),
    "stage_receipt_sha256": delivery["stage_receipt_sha256"],
    "canonical": {
        "classes": classes,
        "stage_receipt_sha256": delivery["stage_receipt_sha256"],
    },
    "crypto_classes": crypto,
    "retained_library_classes": retained,
    "runtime_classes": runtime_classes,
    "resources": resources,
    "runs": runs,
    "source_inputs": {
        "formal/crypto/bundle_checks.py": digest(here),
        "formal/crypto/delivery.py": digest(here.parent / "delivery.py"),
        "formal/nonce/BundleNonceSmoke.java": harness_sha,
    },
    "nonce_smoke": nonce_smoke,
    "jdk_inputs": {str(Path(home).resolve()): {} for home in args.java_home},
}
if mode == "wrong_library":
    receipt["library_jar_sha256"] = "0" * 64
if mode == "incomplete":
    receipt["status"] = "incomplete"
if mode == "missing_nonce_smoke":
    receipt.pop("nonce_smoke")
if mode == "short_nonce_smoke":
    nonce_smoke["runs"]["21"]["cases"] = 8
if mode == "wrong_nonce_origin":
    nonce_smoke["runs"]["25"]["origins"]["VerifiedNonce"] = "/elsewhere/nonce.jar"
if mode == "wrong_nonce_runtime":
    nonce_smoke["runs"]["21"]["origins"]["DafnyRuntime"] = "/elsewhere/runtime.jar"
if mode == "wrong_nonce_loaded":
    nonce_smoke["runs"]["21"]["loaded_classes"][
        "io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default"] = \
        nonce_origins["harness"]
if mode == "nonce_harness_leak":
    nonce_smoke["harness_classes"] = {names[0]: harness_sha}
receipt_path.write_text(json.dumps(receipt))
print(receipt_path)
if mode == "mutate_bundle":
    with Path(args.bundle).open("ab") as stream:
        stream.write(b"altered")
'''


class FakeArtifactCheckout:
    """A minimal tool checkout/stage used only to exercise binding mechanics."""

    def __init__(self, base: Path):
        self.root = base
        (self.root / "formal/crypto").mkdir(parents=True)
        self.runtime = self.root / "runtime.jar"
        self.runtime.write_bytes(b"pinned-dafny-runtime")
        self.manifest_path = self.root / "formal/crypto/delivery.json"
        self.manifest = {
            "entry": "formal/crypto/NativeMlKem.dfy",
            "runtime": {"sha256": _sha(self.runtime.read_bytes())},
        }
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.delivery_tool = self.root / "formal/crypto/delivery.py"
        self.delivery_tool.write_text(FAKE_DELIVERY, encoding="utf-8")
        self.bundle_tool = self.root / "formal/crypto/bundle_checks.py"
        self.bundle_tool.write_text(FAKE_BUNDLE, encoding="utf-8")
        self.nonce_smoke_source = self.root / "formal/nonce/BundleNonceSmoke.java"
        self.nonce_smoke_source.parent.mkdir(parents=True)
        self.nonce_smoke_source.write_text(
            "package nonceadoption; public final class BundleNonceSmoke {}\n", encoding="utf-8")
        release_tool = self.root / "scripts/security/check_crypto_release.py"
        release_tool.parent.mkdir(parents=True)
        release_tool.write_text("# fixture release tool\n", encoding="utf-8")

        self.jdk21 = self._jdk("jdk21", "21")
        self.jdk25 = self._jdk("jdk25", "25")
        self.stage = self.root / "stage"
        (self.stage / "classes").mkdir(parents=True)
        canonical = {
            f"io/github/mahmoudimus/quic/internal/verifiedcrypto/C{index:03d}.class": "a" * 64
            for index in range(66)
        }
        self.stage_receipt = {
            "schema": artifacts.STAGE_SCHEMA,
            "status": "complete",
            "component": None,
            "entry": self.manifest["entry"],
            "manifest_sha256": _sha(self.manifest_path.read_bytes()),
            "canonical_classes": canonical,
            "jdk_home": str(self.jdk21),
            "jdk_files": artifacts.audited_delivery.tool_tree(self.jdk21),
        }
        self.stage_receipt_path = self.stage / "receipt.json"
        self.stage_receipt_path.write_text(json.dumps(self.stage_receipt), encoding="utf-8")

        self.classes = self.root / "classes"
        for index in range(artifacts.EXPECTED_LIBRARY_CLASS_COUNT):
            if index < artifacts.EXPECTED_CRYPTO_CLASS_COUNT:
                name = f"io/github/mahmoudimus/quic/internal/verifiedcrypto/C{index:03d}.class"
            elif index < 464:
                name = f"io/github/mahmoudimus/quic/C{index:03d}.class"
            else:
                name = f"io/github/mahmoudimus/verifiedcrypto/C{index:03d}.class"
            path = self.classes / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"class-{index}".encode())
        self.library = self.root / "library.jar"
        self.library.write_bytes(b"actual-library-jar")
        self.bundle = self.root / "bundle.jar"
        self.bundle.write_bytes(b"actual-bundle-jar")
        self.output = self.root / "artifact-output"

    def _jdk(self, name: str, major: str) -> Path:
        home = self.root / name
        _write_executable(home / "bin/java",
                          f'#!/bin/sh\necho \'openjdk version "{major}.0.1" 2026-01-01\' >&2\n')
        (home / "bin/javac").write_text("fixture javac\n", encoding="utf-8")
        return home

    def validate(self, *, output: Path | None = None, timeout: float = 10,
                 tool_root: Path | None = None, java_homes: list[Path] | None = None,
                 repository_root: Path | None = None):
        return artifacts.validate_current_release(
            repository_root or self.root,
            stage=self.stage,
            classes=self.classes,
            library=self.library,
            bundle=self.bundle,
            runtime=self.runtime,
            java_homes=java_homes if java_homes is not None else [self.jdk21, self.jdk25],
            output=output or self.output,
            tool_root=tool_root or self.root,
            timeout=timeout,
        )


class ArtifactWriteSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_atomic_report_write_does_not_follow_predictable_part_alias(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                out = self.base / ("report-" + kind)
                out.mkdir()
                victim = self.base / ("report-victim-" + kind)
                victim.write_text("authoritative report input\n", encoding="utf-8")
                part = out / "report.json.part"
                if kind == "symlink":
                    part.symlink_to(victim)
                else:
                    os.link(victim, part)
                before = _sha(victim.read_bytes())
                artifacts._atomic_write_json(out / "report.json", {"status": "failed"})
                self.assertEqual(_sha(victim.read_bytes()), before)
                self.assertEqual(json.loads((out / "report.json").read_text())["status"],
                                 "failed")

    def test_command_log_writes_do_not_follow_fixed_name_aliases(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                out = self.base / ("logs-" + kind)
                out.mkdir()
                victim = self.base / ("log-victim-" + kind)
                victim.write_text("authoritative log input\n", encoding="utf-8")
                stdout_path = out / "delivery-check.stdout.log"
                if kind == "symlink":
                    stdout_path.symlink_to(victim)
                else:
                    os.link(victim, stdout_path)
                before = _sha(victim.read_bytes())
                artifacts._write_command_logs(out, "delivery-check",
                                              "captured stdout", "captured stderr")
                self.assertEqual(_sha(victim.read_bytes()), before)
                self.assertEqual(stdout_path.read_text(encoding="utf-8"),
                                 "captured stdout")
                self.assertEqual((out / "delivery-check.stderr.log").read_text(
                    encoding="utf-8"), "captured stderr")

    def test_delivery_receipt_exclusive_write_does_not_follow_aliases(self):
        writer = getattr(artifacts, "_atomic_write_text", None)
        self.assertIsNotNone(writer, "module needs an exclusive text writer")
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                out = self.base / ("delivery-" + kind)
                out.mkdir()
                victim = self.base / ("delivery-victim-" + kind)
                victim.write_text("authoritative delivery input\n", encoding="utf-8")
                receipt_path = out / "delivery-check.json"
                if kind == "symlink":
                    receipt_path.symlink_to(victim)
                else:
                    os.link(victim, receipt_path)
                before = _sha(victim.read_bytes())
                writer(receipt_path, '{"status": "checked"}\n')
                self.assertEqual(_sha(victim.read_bytes()), before)
                self.assertEqual(json.loads(receipt_path.read_text())["status"],
                                 "checked")

    def test_fresh_artifact_output_directory_is_private(self):
        checkout = FakeArtifactCheckout(self.base)
        checkout.validate()
        self.assertEqual(stat.S_IMODE(checkout.output.stat().st_mode), 0o700)


class ArtifactBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.checkout = FakeArtifactCheckout(self.base)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _failed_report(self) -> dict:
        path = self.checkout.output / "report.json"
        self.assertTrue(path.is_file(), "failure must leave an atomic report")
        report = json.loads(path.read_text())
        self.assertEqual(report["status"], "failed")
        return report

    def test_complete_bound_fresh_outputs_pass(self):
        report = self.checkout.validate()
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["delivery"]["class_count"],
                         artifacts.EXPECTED_LIBRARY_CLASS_COUNT)
        self.assertEqual(report["bundle"]["crypto_class_count"],
                         artifacts.EXPECTED_CRYPTO_CLASS_COUNT)
        self.assertEqual(report["bundle"]["retained_library_class_count"],
                         artifacts.EXPECTED_RETAINED_LIBRARY_CLASS_COUNT)
        self.assertEqual(report["bundle"]["runtime_class_count"],
                         artifacts.EXPECTED_RUNTIME_CLASS_COUNT)
        on_disk = json.loads((self.checkout.output / "report.json").read_text())
        self.assertEqual(on_disk["status"], "complete")
        self.assertEqual(on_disk["report_sha256"], report["report_sha256"])

    def test_missing_artifacts_and_jdks_fail_closed(self):
        with self.assertRaisesRegex(artifacts.ArtifactValidationError, "exactly two JDK"):
            self.checkout.validate(java_homes=[self.checkout.jdk21])
        with self.assertRaisesRegex(artifacts.ArtifactValidationError, "duplicate JDK"):
            self.checkout.validate(java_homes=[self.checkout.jdk21, self.checkout.jdk21])
        missing = self.base / "missing.jar"
        with self.assertRaisesRegex(artifacts.ArtifactValidationError, "missing or unresolvable"):
            artifacts.validate_current_release(
                self.checkout.root, stage=self.checkout.stage,
                classes=self.checkout.classes, library=missing,
                bundle=self.checkout.bundle, runtime=self.checkout.runtime,
                java_homes=[self.checkout.jdk21, self.checkout.jdk25],
                output=self.checkout.output, tool_root=self.checkout.root)

    def test_root_mismatch_fails_before_running_tools(self):
        other = self.base / "other-checkout"
        other.mkdir()
        with mock.patch.dict(os.environ, {"FAKE_DELIVERY_MODE": "ok"}):
            with self.assertRaisesRegex(artifacts.ArtifactValidationError,
                                        "requires the repository root"):
                self.checkout.validate(repository_root=other)
        self.assertFalse((self.checkout.output / "report.json").exists())

    def test_output_aliases_and_existing_output_are_rejected(self):
        with self.assertRaisesRegex(artifacts.ArtifactValidationError, "aliases library"):
            self.checkout.validate(output=self.checkout.library)
        with self.assertRaisesRegex(artifacts.ArtifactValidationError, "inside stage"):
            self.checkout.validate(output=self.checkout.stage / "nested-output")
        self.checkout.output.mkdir()
        with self.assertRaisesRegex(artifacts.ArtifactValidationError,
                                    "already exists"):
            self.checkout.validate()

    def test_stale_committed_stage_identity_is_rejected(self):
        self.checkout.stage_receipt["manifest_sha256"] = "0" * 64
        self.checkout.stage_receipt_path.write_text(
            json.dumps(self.checkout.stage_receipt), encoding="utf-8")
        with self.assertRaisesRegex(artifacts.ArtifactValidationError,
                                    "different or stale delivery manifest"):
            self.checkout.validate()
        self._failed_report()

    def test_stage_compiler_jdk_must_be_trusted_cli_jdk21(self):
        self.checkout.stage_receipt["jdk_home"] = str(self.checkout.jdk25)
        self.checkout.stage_receipt["jdk_files"] = artifacts.audited_delivery.tool_tree(
            self.checkout.jdk25)
        self.checkout.stage_receipt_path.write_text(
            json.dumps(self.checkout.stage_receipt), encoding="utf-8")
        with self.assertRaisesRegex(artifacts.ArtifactValidationError,
                                    "trusted JDK21"):
            self.checkout.validate()
        report = self._failed_report()
        labels = [command.get("label") for command in report["commands"]]
        self.assertTrue(labels)
        self.assertTrue(all(label.startswith("jdk-") for label in labels), labels)
        self.assertNotIn("delivery-check", labels)
        self.assertNotIn("bundle-check", labels)
        self.assertFalse((self.checkout.output / "delivery-check.stdout.log").exists())
        self.assertFalse((self.checkout.output / "bundle-check").exists())

    def test_stage_compiler_tree_must_match_trusted_jdk_tree(self):
        self.checkout.stage_receipt["jdk_files"]["bin/java"] = "0" * 64
        self.checkout.stage_receipt_path.write_text(
            json.dumps(self.checkout.stage_receipt), encoding="utf-8")
        with self.assertRaisesRegex(artifacts.ArtifactValidationError,
                                    "file tree differs"):
            self.checkout.validate()
        report = self._failed_report()
        labels = [command.get("label") for command in report["commands"]]
        self.assertTrue(all(label.startswith("jdk-") for label in labels), labels)
        self.assertFalse((self.checkout.output / "delivery-check.stdout.log").exists())

    def test_reproduce_stage_uses_bound_stage_jdk(self):
        data = {
            "input_evidence": str(self.base / "evidence.json"),
            "jdk_home": str(self.checkout.jdk21),
            "sources": {},
            "delivered_sources": {},
            "canonical_classes": {},
            "generated_files": {},
            "class_prefixes": [],
        }
        args = argparse.Namespace(stage=self.checkout.stage,
                                  runtime=self.checkout.runtime,
                                  cache=self.base / "cache", timeout=1,
                                  evidence=None, java_home=self.checkout.jdk21,
                                  output=None)
        seen = {}

        def fake_stage(replay, manifest):
            seen["java_home"] = Path(replay.java_home)
            output = Path(replay.output)
            output.mkdir(parents=True)
            receipt = output / "receipt.json"
            receipt.write_text(json.dumps({field: data[field] for field in (
                "sources", "delivered_sources", "canonical_classes",
                "generated_files", "class_prefixes")}), encoding="utf-8")
            return receipt

        with mock.patch.object(artifacts.audited_delivery, "stage",
                               side_effect=fake_stage):
            artifacts.audited_delivery.reproduce_stage(args, {}, data)
        self.assertEqual(seen["java_home"].resolve(),
                         self.checkout.jdk21.resolve())
        self.assertNotEqual(seen["java_home"].resolve(),
                            self.checkout.jdk25.resolve())

    def test_output_inside_jdk_home_is_rejected(self):
        with self.assertRaisesRegex(artifacts.ArtifactValidationError,
                                    "inside JDK home"):
            self.checkout.validate(output=self.checkout.jdk21 / "nested-status.json")

    def test_timeout_reaps_owned_grandchild_process_group(self):
        pid_path = self.base / "grandchild.pid"
        environment = {"FAKE_DELIVERY_MODE": "timeout_grandchild",
                       "FAKE_GRANDCHILD_PID": str(pid_path)}
        with mock.patch.dict(os.environ, environment):
            with self.assertRaisesRegex(artifacts.ArtifactValidationError,
                                        "timed out"):
                self.checkout.validate(timeout=2)
        self.assertTrue(pid_path.is_file())
        pid = int(pid_path.read_text())
        deadline = time.time() + 10
        while time.time() < deadline:
            result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                                    text=True, capture_output=True)
            stat_value = result.stdout.strip()
            if result.returncode != 0 or not stat_value or stat_value.startswith("Z"):
                break
            time.sleep(0.1)
        else:
            self.fail(f"owned grandchild {pid} survived timeout")
        report = self._failed_report()
        self.assertTrue(any(command.get("timeout")
                            for command in report["commands"]))

    def test_historical_committed_adoption_snapshot_is_not_current(self):
        stage = artifacts.DEFAULT_TOOL_ROOT / "formal/crypto/adoption"
        with self.assertRaises(artifacts.ArtifactValidationError):
            artifacts.validate_current_release(
                artifacts.DEFAULT_TOOL_ROOT, stage=stage,
                classes=self.checkout.classes, library=self.checkout.library,
                bundle=self.checkout.bundle, runtime=self.checkout.runtime,
                java_homes=[self.checkout.jdk21, self.checkout.jdk25],
                output=self.checkout.output)

    def test_nonzero_malformed_incomplete_and_timeout_fail(self):
        for mode in ("nonzero", "malformed", "incomplete"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                checkout = FakeArtifactCheckout(Path(directory))
                with mock.patch.dict(os.environ, {"FAKE_DELIVERY_MODE": mode}):
                    with self.assertRaises(artifacts.ArtifactValidationError):
                        checkout.validate()
                report = json.loads((checkout.output / "report.json").read_text())
                self.assertEqual(report["status"], "failed")
        with tempfile.TemporaryDirectory() as directory:
            checkout = FakeArtifactCheckout(Path(directory))
            with mock.patch.dict(os.environ, {"FAKE_DELIVERY_MODE": "timeout"}):
                with self.assertRaisesRegex(artifacts.ArtifactValidationError, "timed out"):
                    checkout.validate(timeout=1)
            report = json.loads((checkout.output / "report.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(command.get("timeout")
                                for command in report["commands"]))

    def test_bundle_nonzero_malformed_incomplete_wrong_binding_fail(self):
        for mode in ("nonzero", "malformed", "incomplete", "wrong_library",
                     "short_retained", "missing_nonce_smoke", "short_nonce_smoke",
                     "wrong_nonce_origin", "wrong_nonce_runtime", "wrong_nonce_loaded",
                     "nonce_harness_leak"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                checkout = FakeArtifactCheckout(Path(directory))
                with mock.patch.dict(os.environ, {"FAKE_BUNDLE_MODE": mode}):
                    with self.assertRaises(artifacts.ArtifactValidationError):
                        checkout.validate()
                report = json.loads((checkout.output / "report.json").read_text())
                self.assertEqual(report["status"], "failed")

    def test_nonce_smoke_requires_executed_cases_and_real_origins(self):
        cases = (
            ("missing_nonce_smoke", "lacks the nonce execution smoke"),
            ("short_nonce_smoke", "did not execute all 9 cases"),
            ("wrong_nonce_origin", "loaded VerifiedNonce outside the bundle"),
            ("wrong_nonce_runtime", "loaded the Dafny runtime outside the bundle"),
            ("wrong_nonce_loaded", "did not execute PacketKey/VerifiedNonce from the bundle"),
            ("nonce_harness_leak", "unexpected harness class set"),
        )
        for mode, pattern in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                checkout = FakeArtifactCheckout(Path(directory))
                with mock.patch.dict(os.environ, {"FAKE_BUNDLE_MODE": mode}):
                    with self.assertRaisesRegex(artifacts.ArtifactValidationError, pattern):
                        checkout.validate()

    def test_altered_artifact_after_delivery_is_rejected(self):
        with mock.patch.dict(os.environ, {"FAKE_DELIVERY_MODE": "alter_after"}):
            with self.assertRaises(artifacts.ArtifactValidationError):
                self.checkout.validate()
        self._failed_report()

    def test_altered_bundle_after_receipt_is_rejected(self):
        with mock.patch.dict(os.environ, {"FAKE_BUNDLE_MODE": "mutate_bundle"}):
            with self.assertRaisesRegex(artifacts.ArtifactValidationError,
                                        "bundle JAR changed during validation"):
                self.checkout.validate()
        self._failed_report()


class ReleaseArtifactPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = Fixture(self.root)
        self.fixture.claim(release.CURRENT_RELEASE_CLAIM)["status"] = "deferred"
        self.fixture.make_supported("shake-mlkem-functional-production")
        self.fixture.make_supported("hkdf-production-functional")
        # Installing multiple components mutates shared receipts; refresh the
        # synthetic evidence hashes once so the ledger describes final bytes.
        for obligation in self.fixture.ledger["obligations"]:
            for ref in obligation["evidence"]:
                candidate = self.root / ref["path"]
                if candidate.is_file():
                    ref["sha256"] = _sha(candidate.read_bytes())
        self.fixture.write_ledger()
        self.protected = self._install_protected_artifacts()
        self.success_report = {
            "schema": artifacts.SCHEMA,
            "status": "complete",
            "report_path": str(self.root / "artifact-report.json"),
        }

    def _write_envelope(self, directory: Path, *, name: str = "inputs.json") -> tuple[Path, Path, dict[str, str]]:
        directory.mkdir(parents=True, exist_ok=True)
        receipt = directory / "native-receipt.json"
        receipt.write_text('{"status": "complete", "scope": "full"}\n', encoding="utf-8")
        envelope = directory / name
        envelope.write_text(json.dumps({
            "schema": "microproxy.crypto-input-evidence/v1",
            "status": "complete",
            "scope": "full",
            "receipts": [{"path": receipt.name,
                          "sha256": _sha(receipt.read_bytes())}],
        }), encoding="utf-8")
        hashes = {str(envelope): _sha(envelope.read_bytes()),
                  str(receipt): _sha(receipt.read_bytes())}
        return envelope, receipt, hashes

    def _install_protected_artifacts(self) -> dict[str, Path]:
        stage = self.root / "stage"
        stage.mkdir()
        envelope, envelope_receipt, external = self._write_envelope(
            self.root / "target" / "native")
        (stage / "receipt.json").write_text(json.dumps({
            "stage": True,
            "input_evidence": str(envelope),
            "external_inputs": external,
        }), encoding="utf-8")
        classes = self.root / "classes"
        classes.mkdir()
        (classes / "Fixture.class").write_text("fixture class\n", encoding="utf-8")
        paths = {
            "stage": stage,
            "stage_receipt": stage / "receipt.json",
            "classes": classes,
            "library": self.root / "library.jar",
            "bundle": self.root / "bundle.jar",
            "runtime": self.root / "runtime.jar",
            "jdk21": self.root / "jdk21",
            "jdk25": self.root / "jdk25",
            "artifact_output": self.root / "target" / "artifact-output",
            "artifact_report": self.root / "target" / "artifact-output" / "report.json",
            "envelope": envelope,
            "envelope_receipt": envelope_receipt,
        }
        for name in ("library", "bundle", "runtime"):
            paths[name].write_text(f"protected {name}\n", encoding="utf-8")
        for name in ("jdk21", "jdk25"):
            paths[name].mkdir()
        paths["artifact_output"].mkdir(parents=True)
        paths["artifact_report"].write_text("protected report\n", encoding="utf-8")
        return paths

    def _protected_digests(self) -> dict[str, str]:
        return {name: _sha(self.protected[name].read_bytes())
                for name in ("stage_receipt", "library", "bundle", "runtime",
                             "artifact_report", "envelope", "envelope_receipt")}

    def _outside_dir(self) -> Path:
        temporary = tempfile.TemporaryDirectory(prefix="microproxy-outside-output-")
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def artifact_args(self) -> list[str]:
        return [
            "--artifact-stage", str(self.root / "stage"),
            "--artifact-classes", str(self.root / "classes"),
            "--library", str(self.root / "library.jar"),
            "--bundle", str(self.root / "bundle.jar"),
            "--runtime", str(self.root / "runtime.jar"),
            "--java-home", str(self.root / "jdk21"),
            "--java-home", str(self.root / "jdk25"),
            "--artifact-output", str(self.root / "target" / "artifact-output"),
        ]

    def run_release(self, *args: str) -> tuple[int, dict]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = release.main(["--root", str(self.root),
                                 "--ledger", str(self.fixture.path), *args])
        return code, json.loads(output.getvalue())

    def test_actual_mode_promotes_only_the_ephemeral_current_claim(self):
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report) as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--require", release.CURRENT_RELEASE_CLAIM)
        self.assertEqual(code, 0, payload)
        validator.assert_called_once()
        self.assertEqual(payload["claim_failures"], [])
        self.assertEqual(payload["claims"][release.CURRENT_RELEASE_CLAIM], "deferred")
        self.assertEqual(payload["static_claims"][release.CURRENT_RELEASE_CLAIM],
                         "deferred")
        self.assertEqual(payload["ephemeral_claims"][release.CURRENT_RELEASE_CLAIM],
                         "supported")
        self.assertEqual(payload["effective_claims"][release.CURRENT_RELEASE_CLAIM],
                         "supported")
        self.assertEqual(payload["artifact_validation"]["status"], "complete")
        self.assertNotIn(release.CURRENT_RELEASE_CLAIM,
                         payload["effective_residual_claims"])

    def test_actual_mode_never_promotes_expert_timing_or_all_complete(self):
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report):
            code, payload = self.run_release(*self.artifact_args(), "--require-all")
        self.assertEqual(code, 1)
        failed = {item["claim"] for item in payload["claim_failures"]}
        self.assertNotIn(release.CURRENT_RELEASE_CLAIM, failed)
        self.assertIn("v8-timing-release-evidence", failed)
        self.assertIn("independent-expert-review", failed)
        self.assertIn("all-v0-v8-complete", failed)
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report):
            code, payload = self.run_release(
                *self.artifact_args(), "--require", "independent-expert-review")
        self.assertEqual(code, 1)
        self.assertEqual(payload["claim_failures"][0]["claim"],
                         "independent-expert-review")

    def test_partial_actual_inputs_fail_without_running_tools(self):
        with mock.patch.object(release, "validate_current_release") as validator:
            code, payload = self.run_release(
                "--artifact-stage", str(self.root / "stage"),
                "--require", release.CURRENT_RELEASE_CLAIM)
        self.assertEqual(code, 1)
        validator.assert_not_called()
        self.assertIn("incomplete actual artifact inputs",
                      payload["claim_failures"][0]["reason"])
        self.assertEqual(payload["ephemeral_claims"], {})

    def test_root_mismatch_fails_without_running_tools(self):
        outside = self._outside_dir()
        with mock.patch.object(release, "validate_current_release") as validator:
            code, payload = self.run_release(
                *self.artifact_args(),
                "--artifact-output", str(outside / "artifact-output"),
                "--require", release.CURRENT_RELEASE_CLAIM)
        self.assertEqual(code, 1)
        validator.assert_not_called()
        self.assertIn("requires --root",
                      payload["claim_failures"][0]["reason"])

    def test_baseline_functional_claims_are_required(self):
        self.fixture.claim("hkdf-production-functional")["status"] = "deferred"
        self.fixture.write_ledger()
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release") as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--require", release.CURRENT_RELEASE_CLAIM)
        self.assertEqual(code, 1)
        validator.assert_not_called()
        self.assertIn("must be statically supported",
                      payload["claim_failures"][0]["reason"])

    def test_artifact_validator_failure_does_not_promote(self):
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  side_effect=artifacts.ArtifactValidationError("bad bytes")):
            code, payload = self.run_release(
                *self.artifact_args(), "--require", release.CURRENT_RELEASE_CLAIM)
        self.assertEqual(code, 1)
        self.assertEqual(payload["claim_failures"][0]["claim"],
                         release.CURRENT_RELEASE_CLAIM)
        self.assertIn("bad bytes", payload["claim_failures"][0]["reason"])
        self.assertEqual(payload["ephemeral_claims"], {})

    def test_safe_status_output_preserves_protected_inputs_on_success_and_failure(self):
        before = self._protected_digests()
        status_path = self.root / "target" / "status.json"
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report):
            code, payload = self.run_release(
                *self.artifact_args(), "--output", str(status_path),
                "--require", release.CURRENT_RELEASE_CLAIM)
        self.assertEqual(code, 0, payload)
        self.assertTrue(status_path.is_file())
        self.assertEqual(before, self._protected_digests())
        status_path.unlink()
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  side_effect=artifacts.ArtifactValidationError("mismatch")):
            code, payload = self.run_release(
                *self.artifact_args(), "--output", str(status_path),
                "--require", release.CURRENT_RELEASE_CLAIM)
        self.assertEqual(code, 1)
        self.assertTrue(status_path.is_file())
        self.assertEqual(before, self._protected_digests())

    def test_unsafe_status_output_aliases_are_rejected_without_writes(self):
        before = self._protected_digests()
        cases = (
            ("library", self.protected["library"]),
            ("artifact report", self.protected["artifact_report"]),
            ("stage receipt", self.protected["stage_receipt"]),
            ("inside artifact output",
             self.protected["artifact_output"] / "status.json"),
            ("inside stage", self.protected["stage"] / "status.json"),
        )
        for label, output in cases:
            with self.subTest(label=label):
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        mock.patch.object(release, "validate_current_release") as validator:
                    code, payload = self.run_release(
                        *self.artifact_args(), "--output", str(output))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
                validator.assert_not_called()
                self.assertEqual(before, self._protected_digests())

    def test_hardlink_symlink_and_part_aliases_are_rejected(self):
        before = self._protected_digests()
        hardlink = self.root / "target" / "hardlink-status.json"
        os.link(self.protected["library"], hardlink)
        symlink = self.root / "target" / "symlink-status.json"
        os.symlink(self.protected["library"], symlink)
        part_output = self.root / "target" / "part-status.json"
        part_temporary = part_output.with_suffix(part_output.suffix + ".part")
        os.link(self.protected["library"], part_temporary)
        cases = (("hardlink", hardlink), ("symlink", symlink),
                 ("legacy part", part_output))
        for label, output in cases:
            with self.subTest(label=label):
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        mock.patch.object(release, "validate_current_release") as validator:
                    code, payload = self.run_release(
                        *self.artifact_args(), "--output", str(output))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
                validator.assert_not_called()
                self.assertEqual(before, self._protected_digests())
        self.assertEqual(_sha(hardlink.read_bytes()), before["library"])
        self.assertEqual(_sha(symlink.read_bytes()), before["library"])
        self.assertEqual(_sha(part_temporary.read_bytes()), before["library"])

    def test_unsafe_output_rejected_with_bad_ledger_and_incomplete_inputs(self):
        self.fixture.path.write_text("{not-json", encoding="utf-8")
        library = self.protected["library"]
        before = _sha(library.read_bytes())
        with mock.patch.object(release, "validate_current_release") as validator:
            code, payload = self.run_release(
                "--library", str(library), "--output", str(library))
        self.assertEqual(code, 1)
        self.assertFalse(payload["output_protection"]["ok"])
        validator.assert_not_called()
        self.assertEqual(_sha(library.read_bytes()), before)

    def test_actual_output_rejects_implicit_checkout_inputs(self):
        implicit = (
            self.root / "quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java",
            self.root / "formal/crypto/delivery.py",
            self.root / "formal/crypto/delivery.json",
            self.root / "formal/crypto/NativeMlKem.dfy",
        )
        for path in implicit:
            with self.subTest(path=path):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"implicit protected input {path.name}\n",
                                encoding="utf-8")
                before = _sha(path.read_bytes())
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        mock.patch.object(release, "validate_current_release") as validator:
                    code, payload = self.run_release(
                        *self.artifact_args(), "--output", str(path))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
                validator.assert_not_called()
                self.assertEqual(_sha(path.read_bytes()), before)

    def test_artifact_output_under_source_root_denied_before_creation(self):
        artifact_output = self.root / "quic/src/main/java/artifacts"
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release") as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--artifact-output", str(artifact_output))
        self.assertEqual(code, 1)
        self.assertFalse(payload["output_protection"]["ok"])
        validator.assert_not_called()
        self.assertFalse(artifact_output.exists())

    def test_safe_target_and_outside_checkout_outputs_allowed(self):
        outside = self._outside_dir()
        status_paths = (self.root / "target" / "closure-status.json",
                        outside / "closure-status.json")
        for status_path in status_paths:
            with self.subTest(output=status_path):
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        mock.patch.object(release, "validate_current_release",
                                          return_value=self.success_report):
                    code, payload = self.run_release(
                        *self.artifact_args(), "--output", str(status_path),
                        "--require", release.CURRENT_RELEASE_CLAIM)
                self.assertEqual(code, 0, payload)
                self.assertTrue(status_path.is_file())
        artifact_outputs = (self.root / "target" / "closure-artifacts",
                            outside / "closure-artifacts")
        for artifact_output in artifact_outputs:
            with self.subTest(artifact_output=artifact_output):
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        mock.patch.object(release, "validate_current_release",
                                          return_value=self.success_report):
                    code, payload = self.run_release(
                        *self.artifact_args(),
                        "--artifact-output", str(artifact_output))
                self.assertEqual(code, 0, payload)

    def test_artifact_output_rejects_explicit_input_and_ledger_aliases(self):
        before = self._protected_digests()
        cases = (
            ("library", self.protected["library"]),
            ("stage directory", self.protected["stage"]),
            ("ledger", self.fixture.path),
        )
        for label, artifact_output in cases:
            with self.subTest(label=label):
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        mock.patch.object(release, "validate_current_release") as validator:
                    code, payload = self.run_release(
                        *self.artifact_args(),
                        "--artifact-output", str(artifact_output))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
                validator.assert_not_called()
                self.assertEqual(before, self._protected_digests())

    def test_current_ci_sibling_output_under_target_allowed(self):
        native = self.root / "target" / "NATIVE_OUTPUT"
        native.mkdir(parents=True)
        evidence, receipt, external = self._write_envelope(native)
        self.protected["stage_receipt"].write_text(json.dumps({
            "stage": True,
            "input_evidence": str(evidence),
            "external_inputs": external,
        }), encoding="utf-8")
        before = {path: _sha(path.read_bytes()) for path in (evidence, receipt)}
        output = native / "current-release.json"
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report):
            code, payload = self.run_release(
                *self.artifact_args(), "--output", str(output),
                "--require", release.CURRENT_RELEASE_CLAIM)
        self.assertEqual(code, 0, payload)
        self.assertTrue(output.is_file())
        self.assertEqual({path: _sha(path.read_bytes())
                          for path in (evidence, receipt)}, before)

    def test_stage_external_inputs_and_evidence_protected_on_success_and_failure(self):
        outside = self._outside_dir()
        evidence, external, hashes = self._write_envelope(outside)
        self.protected["stage_receipt"].write_text(json.dumps({
            "stage": True,
            "input_evidence": str(evidence),
            "external_inputs": hashes,
        }), encoding="utf-8")
        before = {path: _sha(path.read_bytes()) for path in (evidence, external)}
        for path in (evidence, external):
            for failure in (False, True):
                with self.subTest(path=path, failure=failure):
                    validator_patch = (
                        mock.patch.object(release, "validate_current_release",
                                          side_effect=artifacts.ArtifactValidationError("mismatch"))
                        if failure else
                        mock.patch.object(release, "validate_current_release",
                                          return_value=self.success_report))
                    with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                            validator_patch as validator:
                        code, payload = self.run_release(
                            *self.artifact_args(), "--output", str(path))
                    self.assertEqual(code, 1)
                    self.assertFalse(payload["output_protection"]["ok"])
                    validator.assert_not_called()
                    self.assertEqual(_sha(path.read_bytes()), before[path])
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release") as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--output", str(outside))
        self.assertEqual(code, 1)
        self.assertFalse(payload["output_protection"]["ok"])
        validator.assert_not_called()
        self.assertEqual(_sha(evidence.read_bytes()), before[evidence])
        self.assertEqual(_sha(external.read_bytes()), before[external])
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release") as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--artifact-output", str(outside))
        self.assertEqual(code, 1)
        self.assertFalse(payload["output_protection"]["ok"])
        validator.assert_not_called()
        self.assertEqual(_sha(evidence.read_bytes()), before[evidence])
        self.assertEqual(_sha(external.read_bytes()), before[external])

    def test_unparseable_or_missing_stage_blocks_output_writes(self):
        status_path = self.root / "target" / "stage-guard-status.json"
        for mode in ("malformed", "missing"):
            with self.subTest(mode=mode):
                if mode == "malformed":
                    self.protected["stage_receipt"].write_text("{not-json",
                                                               encoding="utf-8")
                else:
                    self.protected["stage_receipt"].unlink()
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        mock.patch.object(release, "validate_current_release") as validator:
                    code, payload = self.run_release(
                        *self.artifact_args(), "--output", str(status_path))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
                validator.assert_not_called()
                self.assertFalse(status_path.exists())

    def test_stage_receipt_symlink_target_cannot_be_a_status_output(self):
        outside = self._outside_dir()
        target = outside / "canonical-receipt.json"
        stage_receipt = self.protected["stage_receipt"]
        original = stage_receipt.read_bytes()
        target.write_bytes(original)
        stage_receipt.unlink()
        stage_receipt.symlink_to(target)
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report) as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--output", str(target))
        self.assertEqual(code, 1)
        self.assertFalse(payload["output_protection"]["ok"])
        validator.assert_not_called()
        self.assertEqual(target.read_bytes(), original)

    def test_actual_mode_rejects_relative_stage_evidence_paths(self):
        outside = self._outside_dir()
        relative = self.root / "target" / "relative-evidence.json"
        relative.write_text('{}', encoding="utf-8")
        envelope = self.protected["envelope"]
        receipt = self.protected["envelope_receipt"]
        base_external = {
            str(envelope): _sha(envelope.read_bytes()),
            str(receipt): _sha(receipt.read_bytes()),
        }
        for field in ("input_evidence", "external_inputs"):
            with self.subTest(field=field):
                stage_receipt = {
                    "stage": True,
                    "input_evidence": str(envelope),
                    "external_inputs": dict(base_external),
                }
                if field == "input_evidence":
                    stage_receipt["input_evidence"] = "target/relative-evidence.json"
                else:
                    stage_receipt["external_inputs"][
                        "target/relative-evidence.json"] = _sha(relative.read_bytes())
                self.protected["stage_receipt"].write_text(
                    json.dumps(stage_receipt), encoding="utf-8")
                status_path = outside / ("relative-" + field + ".json")
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        mock.patch.object(release, "validate_current_release",
                                          return_value=self.success_report) as validator:
                    code, payload = self.run_release(
                        *self.artifact_args(), "--output", str(status_path))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
                validator.assert_not_called()
                self.assertFalse(status_path.exists())

    def test_envelope_receipts_protected_when_external_inputs_omit_them(self):
        for failure in (False, True):
            with self.subTest(failure=failure):
                directory = self.root / "target" / ("envelope-omitted-" + str(failure))
                envelope, receipt, hashes = self._write_envelope(directory)
                self.protected["stage_receipt"].write_text(json.dumps({
                    "stage": True,
                    "input_evidence": str(envelope),
                    "external_inputs": {str(envelope): hashes[str(envelope)]},
                }), encoding="utf-8")
                before = _sha(receipt.read_bytes())
                validator_patch = (
                    mock.patch.object(release, "validate_current_release",
                                      side_effect=artifacts.ArtifactValidationError("mismatch"))
                    if failure else
                    mock.patch.object(release, "validate_current_release",
                                      return_value=self.success_report))
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        validator_patch as validator:
                    code, payload = self.run_release(
                        *self.artifact_args(), "--output", str(receipt))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
                validator.assert_not_called()
                self.assertEqual(_sha(receipt.read_bytes()), before)

    def test_absolute_envelope_receipt_reference_is_validated_and_protected(self):
        outside = self._outside_dir()
        directory = self.root / "target" / "absolute-envelope"
        directory.mkdir(parents=True)
        receipt = outside / "native-receipt.json"
        receipt.write_text('{"status": "complete"}\n', encoding="utf-8")
        envelope = directory / "inputs.json"
        envelope.write_text(json.dumps({
            "schema": "microproxy.crypto-input-evidence/v1",
            "status": "complete",
            "scope": "full",
            "receipts": [{"path": str(receipt),
                          "sha256": _sha(receipt.read_bytes())}],
        }), encoding="utf-8")
        self.protected["stage_receipt"].write_text(json.dumps({
            "stage": True,
            "input_evidence": str(envelope),
            "external_inputs": {str(envelope): _sha(envelope.read_bytes())},
        }), encoding="utf-8")
        before = _sha(receipt.read_bytes())
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report) as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--output", str(receipt))
        self.assertEqual(code, 1)
        self.assertFalse(payload["output_protection"]["ok"])
        validator.assert_not_called()
        self.assertEqual(_sha(receipt.read_bytes()), before)
        safe = outside / "absolute-safe-status.json"
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report) as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--output", str(safe))
        self.assertEqual(code, 0, payload)
        validator.assert_called_once()
        self.assertTrue(safe.is_file())

    def test_envelope_symlink_relative_references_use_delivery_base(self):
        outside = self._outside_dir()
        target_dir = self.root / "target" / "envelope-symlink-target"
        target_dir.mkdir(parents=True)
        link_dir = outside / "envelope-symlink-link"
        link_dir.mkdir()
        receipt = link_dir / "receipt.json"
        receipt.write_text('{"status": "complete"}\n', encoding="utf-8")
        envelope_target = target_dir / "inputs.json"
        envelope_target.write_text(json.dumps({
            "schema": "microproxy.crypto-input-evidence/v1",
            "status": "complete",
            "scope": "full",
            "receipts": [{"path": receipt.name,
                          "sha256": _sha(receipt.read_bytes())}],
        }), encoding="utf-8")
        envelope_link = link_dir / "inputs.json"
        envelope_link.symlink_to(envelope_target)
        self.protected["stage_receipt"].write_text(json.dumps({
            "stage": True,
            "input_evidence": str(envelope_link),
            "external_inputs": {
                str(envelope_link): _sha(envelope_target.read_bytes())},
        }), encoding="utf-8")
        before = _sha(receipt.read_bytes())
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report) as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--output", str(receipt))
        self.assertEqual(code, 1)
        self.assertFalse(payload["output_protection"]["ok"])
        validator.assert_not_called()
        self.assertEqual(_sha(receipt.read_bytes()), before)
        safe = outside / "envelope-symlink-safe-status.json"
        with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                mock.patch.object(release, "validate_current_release",
                                  return_value=self.success_report) as validator:
            code, payload = self.run_release(
                *self.artifact_args(), "--output", str(safe))
        self.assertEqual(code, 0, payload)
        validator.assert_called_once()
        self.assertTrue(safe.is_file())

    def test_malformed_or_missing_envelope_blocks_output_writes(self):
        outside = self._outside_dir()
        directory = self.root / "target" / "malformed-envelopes"
        directory.mkdir(parents=True)
        referenced = directory / "referenced.json"
        referenced.write_text('{"status": "complete"}\n', encoding="utf-8")
        victim = directory / "victim.txt"
        victim.write_text("authoritative victim\n", encoding="utf-8")
        schema = "microproxy.crypto-input-evidence/v1"
        cases = {
            "missing": None,
            "malformed": "{not-json",
            "duplicate_keys": ('{"schema": "%s", "status": "complete", '
                               '"scope": "full", "receipts": [], "receipts": []}'
                               % schema),
            "missing_receipts": json.dumps({
                "schema": schema, "status": "complete", "scope": "full"}),
            "bad_ref_hash": json.dumps({
                "schema": schema, "status": "complete", "scope": "full",
                "receipts": [{"path": referenced.name, "sha256": "0" * 64}]}),
            "ref_extra_key": json.dumps({
                "schema": schema, "status": "complete", "scope": "full",
                "receipts": [{"path": referenced.name,
                              "sha256": _sha(referenced.read_bytes()),
                              "extra": True}]}),
            "traversal_ref": json.dumps({
                "schema": schema, "status": "complete", "scope": "full",
                "receipts": [{"path": "../victim.txt",
                              "sha256": _sha(victim.read_bytes())}]}),
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                envelope = directory / (label + ".json")
                if text is not None:
                    envelope.write_text(text, encoding="utf-8")
                self.protected["stage_receipt"].write_text(json.dumps({
                    "stage": True,
                    "input_evidence": str(envelope),
                    "external_inputs": {},
                }), encoding="utf-8")
                status_path = outside / ("malformed-" + label + ".json")
                with mock.patch.object(release, "ARTIFACT_TOOL_ROOT", self.root), \
                        mock.patch.object(release, "validate_current_release",
                                          return_value=self.success_report) as validator:
                    code, payload = self.run_release(
                        *self.artifact_args(), "--output", str(status_path))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
                validator.assert_not_called()
                self.assertFalse(status_path.exists())

    def test_normal_mode_rejects_ledger_and_checkout_source_clobber(self):
        ledger_before = _sha(self.fixture.path.read_bytes())
        source = self.root / "quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("authoritative checkout source\n", encoding="utf-8")
        source_before = _sha(source.read_bytes())
        target_output = self.root / "target" / "normal-target.json"
        target_output.parent.mkdir(parents=True, exist_ok=True)
        target_output.write_text("fixture target output\n", encoding="utf-8")
        target_before = _sha(target_output.read_bytes())
        for label, output in (("ledger", self.fixture.path), ("source", source),
                             ("fixture target", target_output)):
            with self.subTest(label=label):
                before = _sha(output.read_bytes())
                code, payload = self.run_release("--output", str(output))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
                self.assertEqual(_sha(output.read_bytes()), before)
        self.assertEqual(_sha(self.fixture.path.read_bytes()), ledger_before)
        self.assertEqual(_sha(source.read_bytes()), source_before)
        self.assertEqual(_sha(target_output.read_bytes()), target_before)

    def test_normal_mode_output_aliases_are_rejected(self):
        outside = self._outside_dir()
        ledger_before = _sha(self.fixture.path.read_bytes())
        hardlink = outside / "hardlink-status.json"
        os.link(self.fixture.path, hardlink)
        symlink = outside / "symlink-status.json"
        os.symlink(self.fixture.path, symlink)
        part_output = outside / "part-status.json"
        part_temporary = part_output.with_suffix(part_output.suffix + ".part")
        os.link(self.fixture.path, part_temporary)
        for label, output in (("hardlink", hardlink), ("symlink", symlink),
                             ("legacy part", part_output)):
            with self.subTest(label=label):
                code, payload = self.run_release("--output", str(output))
                self.assertEqual(code, 1)
                self.assertFalse(payload["output_protection"]["ok"])
        self.assertEqual(_sha(self.fixture.path.read_bytes()), ledger_before)

    def test_normal_mode_remains_unchanged_without_artifact_inputs(self):
        status_path = self._outside_dir() / "normal-status.json"
        code, payload = self.run_release(
            "--output", str(status_path),
            "--require", "shake-mlkem-functional-production")
        self.assertEqual(code, 0, payload)
        self.assertNotIn("ephemeral_claims", payload)
        self.assertNotIn("artifact_validation", payload)
        self.assertTrue(status_path.is_file())
        self.assertEqual(json.loads(status_path.read_text()), payload)


if __name__ == "__main__":
    unittest.main()
