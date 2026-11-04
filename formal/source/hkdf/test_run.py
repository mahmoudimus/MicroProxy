import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run


class GateParsing(unittest.TestCase):
    def test_verified_requires_completion_and_zero_errors(self):
        good = "Dafny program verifier finished with 216 verified, 0 errors"
        self.assertEqual({"verified": 216, "errors": 0},
                         run.require_verified(0, good, 216, "x"))
        for rc, text in (
            (4, good),
            (0, good.replace("216 verified", "215 verified")),
            (0, good.replace("0 errors", "1 error")),
            (0, good + "\nVerification timed out"),
            (0, good + "\nout of resource"),
        ):
            with self.subTest(rc=rc, text=text), self.assertRaises(run.GateError):
                run.require_verified(rc, text, 216, "x")
        with self.assertRaises(run.GateError):
            run.require_verified(0, good.replace("216 verified", "217 verified"), 216, "x", exact=216)

    def test_assertion_control_requires_real_assertion_not_tool_failure(self):
        good = ("HkdfTrace.dfy(28,11): Error: assertion might not hold\n"
                "    assert t1 == t2;\n"
                "Dafny program verifier finished with 225 verified, 2 errors")
        self.assertEqual("dafny-assertion-failure",
                         run.require_assertion_failure(4, good, "x")["classification"])
        for rc, text in ((0, good), (4, good.replace("assertion might not hold", "parser error")),
                         (124, good), (4, good + "\nVerification timed out"),
                         (4, "Dafny program verifier finished with 1 verified, 0 errors"),
                         (4, good.replace("assert t1 == t2", "assert t2 == t2"))):
            with self.subTest(rc=rc), self.assertRaises(run.GateError):
                run.require_assertion_failure(rc, text, "x")

    def test_checker_rejection_requires_coverage_error_not_tool_failure(self):
        good = "Hkdf.dfy(1,1): Error: sequence read source is not the method's formal labelUnits"
        self.assertEqual("resolved-ast-coverage-rejection",
                         run.require_checker_rejection(2, good, "sequence read source", "x")["classification"])
        for rc, text in ((0, good), (2, "CLI: Error: file not found"),
                         (2, "unresolved identifier: Foo"), (124, good)):
            with self.subTest(rc=rc), self.assertRaises(run.GateError):
                run.require_checker_rejection(rc, text, "sequence read source", "x")

    def test_metadata_commands_select_only_the_actual_encoder(self):
        expected = {
            "metadata-branch-erases-boolean": "EvBranch",
            "metadata-branch-erases-one-id": "EvBranch",
            "metadata-read-erases-address": "EvRead",
            "metadata-mac-erases-target": "EvMac",
            "metadata-mac-erases-lengths": "EvMac",
            "metadata-call-erases-arity": "EvCall",
            "metadata-ops-erases-shift": "EvOps",
        }
        self.assertEqual(set(expected), set(run.METADATA_ENCODERS))
        for name, encoder in expected.items():
            command = run.metadata_command("dafny", Path("Hkdf.dfy"), name)
            self.assertEqual("VerifiedHkdf." + encoder + ".",
                             command[command.index("--filter-symbol") + 1])
            self.assertIn("--progress", command)
            self.assertNotIn("--no-verify", command)
            for option, value in (("--verification-time-limit", "30"),
                                  ("--resource-limit", "50000000")):
                self.assertEqual(value, command[command.index(option) + 1])
        with self.assertRaises(run.GateError):
            run.metadata_command("dafny", Path("Hkdf.dfy"), "unknown-control")

    def test_named_metadata_failure_requires_named_proof_obligation(self):
        good = ("Hkdf.dfy(38,45): Error: a postcondition could not be proved on this return path\n"
                "MetadataEvBranchBoolean\n"
                "Dafny program verifier finished with 247 verified, 1 error")
        self.assertEqual("dafny-metadata-proof-failure",
                         run.require_named_proof_failure(4, good, "MetadataEvBranchBoolean", "x")["classification"])
        for rc, text in ((0, good), (124, good), (4, good.replace("MetadataEvBranchBoolean", "other")),
                         (4, "MetadataEvBranchBoolean\nDafny program verifier finished with 247 verified, 1 error")):
            with self.subTest(rc=rc), self.assertRaises(run.GateError):
                run.require_named_proof_failure(rc, text, "MetadataEvBranchBoolean", "x")

    def test_replace_once_rejects_changed_anchor(self):
        self.assertEqual("a b", run.replace_once("a b", "b", "B", "x").replace("a B", "a b"))
        with self.assertRaises(run.GateError):
            run.replace_once("a b b", "b", "B", "x")
        with self.assertRaises(run.GateError):
            run.replace_once("a b", "c", "B", "x")


class MutationInventory(unittest.TestCase):
    def test_binding_controls_include_the_former_full_gate_bypass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            controls = run.binding_mutants(run.INSTRUMENTED.read_text(), root)
            self.assertEqual({
                "callee-suchthat-model-erasure", "callee-suchthat-same-model",
                "trace-suchthat-reset", "nested-callee-suchthat",
                "ghost-call-callee-binding", "ghost-call-trace-binding",
                "actual-call-trace-binding", "statement-expression",
            }, set(controls))
            erased = (root / "callee-suchthat-model-erasure/Hkdf.dfy").read_text()
            self.assertIn("encTrace :| encTrace == [];", erased)
            self.assertNotIn("EvCall(5, 3, 3) + LabelInfoTrace(labelUnits, contextLen, length) +", erased)
            self.assertNotIn("assert encTrace == LabelInfoTrace(labelUnits, |context|, length);", erased)
            for name in controls:
                self.assertTrue((root / name / "HkdfTrace.dfy").is_file())

    def test_checker_mutants_generate_each_named_control(self):
        text = run.INSTRUMENTED.read_text()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            found = run.checker_mutants(text, root)
            expected = {
                "unmarked-secret-branch", "unmarked-secret-read", "stale-marker",
                "shadow-callee", "array-shadow", "interposed-assignment", "ghost-if-marker",
                "unmarked-call", "unmarked-alloc", "omitted-mac-observer",
                "synthetic-golden-trace", "reset-empty-trace", "local-shadow-trace",
                "shadow-marker-call", "pattern-call", "expect-secret-branch",
                "print-secret-index", "match-source-secret", "loop-start-mismatch",
                "loop-increment-mismatch", "loop-exit-missing", "loop-exit-wrong-index",
                "seqeq-private", "by-method-helper", "loop-init-conditional",
                "callee-order-encTrace", "callee-order-expTrace",
                "site-label-collision", "site-label-nonliteral", "block-boundary-pending",
            }
            self.assertEqual(expected, set(found))
            for name in expected:
                self.assertTrue((root / name / "Hkdf.dfy").is_file())

    def test_control_harness_uses_frozen_input_instead_of_mutable_checkout(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            frozen = root / "Frozen.dfy"
            frozen.write_text('include "../../dafny/hkdf/Hkdf.dfy"\n// frozen source\n')
            output = root / "control"
            output.mkdir()
            with patch.object(run, "HARNESS", root / "missing-mutable-input.dfy"):
                run.write_mutant_harness(output, frozen)
            self.assertEqual('include "Hkdf.dfy"\n// frozen source\n',
                             (output / "HkdfTrace.dfy").read_text())

    def test_accept_mutant_relabels_site_bijectively(self):
        text = run.INSTRUMENTED.read_text()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            accept = run.accept_mutants(text, root)
            mutated = (accept / "Hkdf.dfy").read_text()
            self.assertNotIn("EvBranch(2,", mutated)
            self.assertIn("EvBranch(99,", mutated)
            self.assertTrue((accept / "HkdfTrace.dfy").is_file())

    def test_metadata_mutants_generate_each_named_control(self):
        text = run.INSTRUMENTED.read_text()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            found = run.metadata_mutants(text, root)
            expected = {"metadata-branch-erases-boolean", "metadata-branch-erases-one-id",
                        "metadata-read-erases-address", "metadata-mac-erases-target",
                        "metadata-mac-erases-lengths", "metadata-call-erases-arity",
                        "metadata-ops-erases-shift"}
            self.assertEqual(expected, set(found))
            for name in expected:
                self.assertTrue((root / name / "Hkdf.dfy").is_file())

    def test_observed_mutants_extend_trace_and_generate_harness(self):
        text = run.INSTRUMENTED.read_text()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            names = run.observed_mutants(text, root)
            self.assertEqual({"observed-secret-branch", "observed-secret-index",
                              "observed-secret-metadata"}, set(names))
            for name in names:
                mutant = (root / name / "Hkdf.dfy").read_text()
                harness = (root / name / "HkdfTrace.dfy").read_text()
                self.assertIn("Secret", mutant)
                self.assertIn('include "Hkdf.dfy"', harness)
                self.assertNotIn('include "../../dafny/hkdf/Hkdf.dfy"', harness)


class Pins(unittest.TestCase):
    def test_manifest_inventory_matches_repository(self):
        manifest = json.loads((run.HERE / "inputs.json").read_text())
        self.assertEqual(set(run.inventory()), set(manifest["inputs"]))
        for name, expected in manifest["inputs"].items():
            self.assertEqual(expected, run.digest(run.P / name), name)


class OutputIsolation(unittest.TestCase):
    def test_existing_output_is_rejected_before_pipeline_or_other_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "existing"
            output.mkdir()
            sentinel = output / "report.json"
            sentinel.write_text("old report must survive")
            other = root / "evidence"
            other.mkdir()
            (other / "report.json").write_text("unrelated evidence")
            with patch.object(run, "P", root), patch.object(run, "pipeline") as pipeline:
                with self.assertRaisesRegex(FileExistsError, "File exists"):
                    run.main(["--output", str(output)])
                pipeline.assert_not_called()
            self.assertEqual("old report must survive", sentinel.read_text())
            self.assertEqual("unrelated evidence", (other / "report.json").read_text())

    def test_all_receipts_are_inside_new_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "fresh"
            result = {"status": "complete", "test": "owned receipt"}
            with patch.object(run, "P", root), patch.object(run, "pipeline", return_value=result) as pipeline:
                self.assertEqual(0, run.main(["--output", str(output)]))
            pipeline.assert_called_once()
            self.assertEqual(output.resolve() / "evidence", pipeline.call_args.args[2])
            self.assertEqual(result, json.loads((output / "evidence/report.json").read_text()))
            self.assertFalse((root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
