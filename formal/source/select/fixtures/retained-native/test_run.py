import json
import unittest
from pathlib import Path

import run


class ComponentInventory(unittest.TestCase):
    def test_root19_inventory_is_complete(self):
        controls = json.loads((run.HERE / "controls/root19.json").read_text())
        self.assertEqual(19, len(controls))
        self.assertEqual(0, controls["baseline13"]["expected_exit"])
        self.assertEqual(2, controls["duplicate-root"]["expected_exit"])
        self.assertEqual(0, controls["rename-public-formal"]["expected_exit"])
        self.assertEqual(0, controls["rename-helper-formal"]["expected_exit"])

    def test_callbinding_inventory_is_complete(self):
        controls = json.loads((run.HERE / "controls/callbinding.json").read_text())
        expected = {"delayed-callee", "interposed-op", "block-boundary", "nested-callee",
                    "binding-unknown", "pure-call-delayed", "pure-call-no-call-marker",
                    "pure-call-inline-projection", "pure-call-missing-child",
                    "pure-call-second-inline", "pure-call-second-missing-child",
                    "pure-call-two-direct-accepted", "pure-call-forged-ghost-local",
                    "callee-before-call", "pure-rr-before-call", "call-child-interposed-marker",
                    "root-signature-add", "root-extra-output", "root-wrong-ghost",
                    "root-array-role", "root-unexpected-field", "root-array-rank"}
        self.assertEqual(expected, set(controls))
        self.assertEqual(86, controls["delayed-callee"]["verify_method"])
        self.assertEqual(86, controls["root-signature-add"]["verify_method"])
        self.assertEqual(86, controls["callee-before-call"]["verify_method"])
        self.assertEqual(86, controls["call-child-interposed-marker"]["verify_method"])

    def test_source_fixtures_are_complete(self):
        expected = {
            "formal/crypto/NativeField.dfy", "formal/crypto/NativeKeccak.dfy",
            "formal/crypto/NativeTypes.dfy", "formal/primitives/Field.dfy",
            "formal/primitives/Keccak.dfy", "formal/source/SourceTrace.dfy",
            "formal/source/ObservationVocabulary.dfy", "formal/source/AllTraceRoots.dfy",
            "formal/source/NativeKeccakTraceHarness.dfy", "formal/source/NativeFieldTraceHarness.dfy",
            "formal/source/RotateThetaTraceHarness.dfy",
        }
        actual = {str(p.relative_to(run.HERE / "source-fixtures")) for p in (run.HERE / "source-fixtures").rglob("*.dfy")}
        self.assertEqual(expected, actual)

    def test_identity_paths_have_no_name_or_text_fallbacks(self):
        text = (run.HERE / "formal/source/checker/SourceCoverage.cs").read_text()
        self.assertIn("SameOrigin(def.Pure.Tok, fc.Tok)", text)
        self.assertIn("VarKey(v)", text)
        self.assertNotIn('MemberName.EndsWith("1")', text)
        self.assertNotIn("def.Pure.ToString() == fc.ToString()", text)
        self.assertNotIn("p.Name == v.Name", text)

    def test_call_order_gate_is_positional(self):
        text = (run.HERE / "formal/source/checker/SourceCoverage.cs").read_text()
        self.assertIn("bool IsOrderedCallChild(List<Expression> leaves", text)
        self.assertIn("if (childIndex != 2 || leaves.Count < 3) return false;", text)
        self.assertIn("must place its exact defining Call marker immediately before its callee trace leaf", text)
        self.assertIn("must place its exact defining Call marker immediately before its pure trace leaf", text)
        self.assertNotIn("MustPlace", text)

    def test_build_is_deterministic_and_isolated(self):
        text = (run.HERE / "run.py").read_text()
        self.assertIn("NativeCanonicalEncoderPolicy.cs", text)
        self.assertIn("-p:ImportDirectoryBuildProps=false", text)
        self.assertIn("-p:ImportDirectoryBuildTargets=false", text)
        self.assertIn("directory_build_imports_disabled", text)

    def test_checker_contains_focused_rules(self):
        text = (run.HERE / "formal/source/checker/SourceCoverage.cs").read_text()
        for needle in ("callee trace append is not the first trace update immediately after its defining call",
                       "pure-function trace append does not bind its exact defining Call marker",
                       "input formals, found", "output formals, found",
                       "root is not in an exact default class"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
