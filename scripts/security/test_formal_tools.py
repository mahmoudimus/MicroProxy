"""Fail-closed tests for the proof runner's trust and freshness gates; no network required."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from formal_check import audit_axioms, main, observation_claim, run, verify_sources
from install_formal_tools import checked_download, digest


class FormalTrustGatesTest(unittest.TestCase):
    def test_tlc_counterexample_requires_exact_exit_twelve(self):
        with tempfile.TemporaryDirectory() as directory:
            for code in (12, -9, 1, 137):
                def tool(command, **kwargs):
                    kwargs["stdout"].write("Invariant NoNonceReuse is violated\n")
                    return subprocess.CompletedProcess(command, code)
                with self.subTest(code=code), patch("formal_check.subprocess.run", side_effect=tool):
                    if code == 12:
                        self.assertIn("NoNonceReuse", run(["synthetic-tlc"], Path(directory) / "tlc.log",
                                      expect_failure=True, expected_failure_exit=12))
                    else:
                        with self.assertRaises(RuntimeError):
                            run(["synthetic-tlc"], Path(directory) / "tlc.log", expect_failure=True,
                                expected_failure_exit=12)

    def test_killed_negative_control_is_not_a_successful_counterexample(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("formal_check.subprocess.run", return_value=subprocess.CompletedProcess([], -9)):
                with self.assertRaises(RuntimeError):
                    run(["synthetic-killed-tool"], Path(directory) / "negative.log", expect_failure=True)

    def test_failed_replay_removes_previous_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            previous = output / "report.json"
            previous.write_text('{"old_success":true}')
            with patch("formal_check.ROOT", output / "missing-checkout"), patch(
                    "sys.argv", ["formal_check.py", "--output", str(output)]):
                with self.assertRaises(FileNotFoundError):
                    main()
            self.assertFalse(previous.exists(), "A failed replay must not retain a success report")

    def test_accepts_kernel_audits_with_only_standard_axioms(self):
        output = ("'P.one' depends on axioms: [propext, Quot.sound]\n"
                  "'P.two' does not depend on any axioms\n")
        self.assertEqual({"P.one": ["Quot.sound", "propext"], "P.two": []},
                         audit_axioms(output, ["P.one", "P.two"]))

    def test_rejects_missing_audit_and_empty_claim_list(self):
        with self.assertRaisesRegex(RuntimeError, "Missing theorem"):
            audit_axioms("", ["P.one"])
        with self.assertRaisesRegex(RuntimeError, "Empty security"):
            audit_axioms("", [])

    def test_rejects_holes_custom_axioms_and_native_proof_trust(self):
        for axiom in ("sorryAx", "trusted_AES_is_secure", "Lean.ofReduceBool", "Lean.trustCompiler"):
            with self.subTest(axiom=axiom), self.assertRaisesRegex(RuntimeError, "Untrusted axiom"):
                audit_axioms(f"'P.one' depends on axioms: [propext, {axiom}]", ["P.one"])

    def test_changed_java_is_rejected_until_mapping_is_reviewed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "State.java"
            source.write_text("guarded")
            sources = {"State.java": digest(source)}
            verify_sources(root, sources)
            source.write_text("guard removed")
            with self.assertRaisesRegex(RuntimeError, "Java source drift"):
                verify_sources(root, sources)

    def test_empty_source_map_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "Empty Java source"):
            verify_sources(Path.cwd(), {})

    def test_corrupt_cached_tool_is_not_silently_used(self):
        with tempfile.TemporaryDirectory() as directory:
            cached = Path(directory) / "tool"
            cached.write_bytes(b"corrupt")
            with self.assertRaisesRegex(RuntimeError, "Checksum mismatch"):
                checked_download("https://unused.invalid", "0" * 64, cached)

    def test_bad_download_is_not_installed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "release", root / "installed"
            source.write_bytes(b"synthetic tool")
            with self.assertRaisesRegex(RuntimeError, "Downloaded tool checksum mismatch"):
                checked_download(source.as_uri(), "0" * 64, target)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix(".part").exists())
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            checked_download(source.as_uri(), expected, target)
            self.assertEqual(source.read_bytes(), target.read_bytes())

    def test_observation_fields_cannot_escape_the_bounded_model(self):
        for row in (
            {"kind": "record", "limit": 8, "before": -1, "accepted": True, "after": 0},
            {"kind": "budget", "before": 8, "cost": -1, "accepted": True, "after": 9},
            {"kind": "budget", "before": 8, "cost": 1, "accepted": "false", "after": 0},
            {"kind": "label", "length": 16, "label": [256], "context": [], "encoded": []},
            {"kind": "nonce", "iv": "00" * 12, "sequence": 2**64, "nonce": "00" * 12},
            {"kind": "unknown"},
        ):
            with self.subTest(row=row), self.assertRaises(ValueError):
                observation_claim(row)


if __name__ == "__main__":
    unittest.main()
