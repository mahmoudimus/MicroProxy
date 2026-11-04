import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("polynomial_replay", Path(__file__).with_name("replay.py"))
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)


def ok(verified, errors=0):
    return f"Dafny program verifier finished with {verified} verified, {errors} errors\n"


def checker_ok(roots):
    return "POLYNOMIAL-SOURCE-COVERAGE OK: exact resolved roots [" + ",".join(roots) + "]\n"


class ProofGateTests(unittest.TestCase):
    def test_positive_proof_requires_exact_count_and_zero_errors(self):
        self.assertEqual({"verified": 1001, "errors": 0},
                         REPLAY.require_verified(0, ok(1001), 1001, "poly"))
        for rc, text in (
            (4, ok(1001)),
            (0, ok(1000)),
            (0, ok(1001, 1)),
            (0, ok(0)),
            (0, ok(1001) + "Verification timed out\n"),
            (0, ok(1001) + "out of resource\n"),
            (0, ok(1001) + "Warning: possible mitigation\n"),
            (0, ok(1001) + "parse error\n"),
        ):
            with self.subTest(rc=rc, text=text), self.assertRaises(REPLAY.GateError):
                REPLAY.require_verified(rc, text, 1001, "poly")

    def test_named_proof_failure_rejects_resource_and_parse_results(self):
        good = ("NativePolynomial.dfy(22,27): Error: a postcondition could not be proved on this return path\n"
                + ok(1000, 1))
        self.assertEqual("dafny-proof-failure",
                         REPLAY.require_dafny_error(4, good, "postcondition", "x")["classification"])
        for rc, text in (
            (0, good),
            (2, good),
            (4, good.replace("postcondition could not be proved", "unrelated error")),
            (4, good + "Verification out of resource\n"),
            (4, good + "parse error\n"),
            (124, good),
        ):
            with self.subTest(rc=rc), self.assertRaises(REPLAY.GateError):
                REPLAY.require_dafny_error(rc, text, "postcondition", "x")

    def test_assertion_control_requires_the_named_assertion(self):
        good = ("BranchObservedHarness.dfy(10,4): Error: assertion might not hold\n"
                "    assert t1 == t2;\n" + ok(0, 1))
        self.assertEqual("dafny-assertion-failure",
                         REPLAY.require_assertion_failure(4, good, "paired")["classification"])
        for rc, text in ((0, good), (4, good.replace("assert t1 == t2", "assert t2 == t2")),
                         (4, good + "out of memory\n"), (124, good)):
            with self.subTest(rc=rc), self.assertRaises(REPLAY.GateError):
                REPLAY.require_assertion_failure(rc, text, "paired")


class FocusedCounterexampleTests(unittest.TestCase):
    def test_filter_symbol_is_the_actual_qualified_member(self):
        focus = REPLAY.MISSING_FALSE_PREFIX_FOCUS
        self.assertEqual("NativePolynomial.ZetasValue", focus["filter_symbol"])
        self.assertIn(focus["filter_symbol"], REPLAY.DEFAULT_PURE_FUNCS)
        self.assertNotIn("_default", focus["filter_symbol"])
        self.assertEqual("ensures ZetasValue(i).1", focus["named_postcondition"])

    def test_missing_false_prefix_mutant_is_only_the_old_prefix_deletion(self):
        item = next(row for row in REPLAY.MUTATIONS if row[0] == "missing-false-prefix")
        _, old, new, _, mode, named = item
        self.assertEqual("focused", mode)
        self.assertEqual("ensures ZetasValue(i).1", named)
        self.assertEqual(old.replace("BranchFalsePrefix(800,3) + ", ""), new)
        self.assertIn("BranchFalsePrefix(800,3) + ST.Branch(803,true)", old)
        self.assertNotIn("BranchFalsePrefix(800,3)", new)

    def test_focused_positive_requires_nonzero_verified_and_zero_errors(self):
        self.assertEqual("focused-positive",
                         REPLAY.require_focused_positive(0, ok(1), "NativePolynomial.ZetasValue", "x")["classification"])
        for rc, text in ((4, ok(1)), (0, ok(0)), (0, ok(1, 1)),
                         (0, ok(1) + "Verification timed out\n"),
                         (0, ok(1) + "out of resource\n"),
                         (0, ok(1) + "Warning: bad\n"),
                         (0, ok(1) + ok(1))):
            with self.subTest(rc=rc), self.assertRaises(REPLAY.GateError):
                REPLAY.require_focused_positive(rc, text, "NativePolynomial.ZetasValue", "x")

    def test_focused_counterexample_requires_one_named_postcondition_only(self):
        good = ("NativePolynomial.dfy(569,24): Error: a postcondition could not be proved on this return path\n"
                "    ensures ZetasValue(i).1 == (if i < 16 then [] else [])\n"
                + ok(0, 1))
        result = REPLAY.require_focused_counterexample(
            4, good, "NativePolynomial.ZetasValue", "ensures ZetasValue(i).1", "x")
        self.assertEqual("focused-dafny-postcondition-counterexample", result["classification"])
        for rc, text in (
            (0, good),
            (4, good.replace("0 verified, 1 error", "0 verified, 0 errors")),
            (4, good.replace("0 verified, 1 error", "0 verified, 2 errors")),
            (4, good.replace("a postcondition could not be proved", "an unrelated error")),
            (4, good.replace("ensures ZetasValue(i).1", "ensures Other(i).1")),
            (4, good + "Verification timed out\n"),
            (4, good + "out of resource\n"),
            (4, good + "Warning: bad\n"),
        ):
            with self.subTest(rc=rc), self.assertRaises(REPLAY.GateError):
                REPLAY.require_focused_counterexample(
                    rc, text, "NativePolynomial.ZetasValue", "ensures ZetasValue(i).1", "x")

    def test_unknown_filter_zero_match_is_rejected_as_vacuous(self):
        with self.assertRaises(REPLAY.GateError):
            REPLAY.require_focused_positive(0, ok(0), "NativePolynomial._default.ZetasValue", "unknown-filter")


class CheckerGateTests(unittest.TestCase):
    def test_positive_checker_requires_exact_reviewed_root_identities(self):
        good = checker_ok(REPLAY.DEFAULT_METHOD_ROOTS)
        self.assertEqual(20, REPLAY.require_checker_ok(0, good, REPLAY.DEFAULT_METHOD_ROOTS, "checker")["root_count"])
        for rc, text, expected in (
            (2, good, REPLAY.DEFAULT_METHOD_ROOTS),
            (0, "POLYNOMIAL-SOURCE-COVERAGE OK\n", REPLAY.DEFAULT_METHOD_ROOTS),
            (0, good + "Warning: bad\n", REPLAY.DEFAULT_METHOD_ROOTS),
            (0, checker_ok(REPLAY.DEFAULT_METHOD_ROOTS[:-1]), REPLAY.DEFAULT_METHOD_ROOTS),
            (0, checker_ok([REPLAY.DEFAULT_METHOD_ROOTS[0]] * 20), REPLAY.DEFAULT_METHOD_ROOTS),
            (0, checker_ok([f"Wrong.Root{i}" for i in range(20)]), REPLAY.DEFAULT_METHOD_ROOTS),
        ):
            with self.subTest(rc=rc), self.assertRaises(REPLAY.GateError):
                REPLAY.require_checker_ok(rc, text, expected, "checker")

    def test_explicit_control_root_set_is_accepted_only_when_exact(self):
        control = [REPLAY.DEFAULT_METHOD_ROOTS[-1]]
        self.assertEqual(control, REPLAY.require_checker_ok(0, checker_ok(control), control, "control")["roots"])
        with self.assertRaises(REPLAY.GateError):
            REPLAY.require_checker_ok(0, checker_ok(REPLAY.DEFAULT_METHOD_ROOTS), control, "control")

    def test_checker_environment_cannot_leak_ambient_selectors(self):
        with patch.dict(os.environ, {
            "POLY_TRACE_ROOTS": "NativeField.ReduceOnce,NativeField.ReduceOnce",
            "POLY_TRACE_FUNCS": "FunctionControl.PrivateBranchObserved",
        }, clear=False):
            clean = REPLAY.tool_env()
            self.assertNotIn("POLY_TRACE_ROOTS", clean)
            self.assertNotIn("POLY_TRACE_FUNCS", clean)
            default = REPLAY.checker_env()
            self.assertNotIn("POLY_TRACE_ROOTS", default)
            self.assertNotIn("POLY_TRACE_FUNCS", default)
            roots = REPLAY.checker_env(roots="Control.SecretBranchObserved")
            self.assertEqual("Control.SecretBranchObserved", roots["POLY_TRACE_ROOTS"])
            self.assertNotIn("POLY_TRACE_FUNCS", roots)
            funcs = REPLAY.checker_env(funcs="FunctionControl.PrivateIndexObserved")
            self.assertEqual("FunctionControl.PrivateIndexObserved", funcs["POLY_TRACE_FUNCS"])
            self.assertNotIn("POLY_TRACE_ROOTS", funcs)

    def test_default_root_and_function_inventories_are_static_unique_reviewed_sets(self):
        self.assertEqual(20, len(REPLAY.DEFAULT_METHOD_ROOTS))
        self.assertEqual(20, len(set(REPLAY.DEFAULT_METHOD_ROOTS)))
        self.assertEqual(19, len(REPLAY.DEFAULT_PURE_FUNCS))
        self.assertEqual(19, len(set(REPLAY.DEFAULT_PURE_FUNCS)))
        self.assertEqual("NativePolynomial.NewZetas", REPLAY.DEFAULT_METHOD_ROOTS[0])
        self.assertEqual("NativeField.AddMul", REPLAY.DEFAULT_METHOD_ROOTS[-1])
        self.assertIn("NativePolynomial.GammasValue", REPLAY.DEFAULT_PURE_FUNCS)

    def test_checker_rejection_requires_named_cause_not_bare_exit2(self):
        good = "Error: positional formal 1: SourceTrace._default.Branch\n"
        self.assertEqual("resolved-ast-coverage-rejection",
                         REPLAY.require_checker_rejection(2, good, "positional formal 1", "x")["classification"])
        for rc, text in ((0, good), (2, "Error: unrelated\n"),
                         (2, good + "Verification timed out\n"),
                         (2, good + "POLYNOMIAL-SOURCE-COVERAGE OK\n"), (124, good)):
            with self.subTest(rc=rc), self.assertRaises(REPLAY.GateError):
                REPLAY.require_checker_rejection(rc, text, "positional formal 1", "x")


class InventoryTests(unittest.TestCase):
    def test_mutations_retain_mandatory_current_controls(self):
        labels = {item[0] for item in REPLAY.MUTATIONS}
        self.assertTrue({
            "leaf-branch-mutation", "real-path-mutation", "child-ghost-mutation",
            "caller-arg-mutation", "chunktrace-helper-mutation",
            "branchfalseprefix-helper-mutation", "missing-false-prefix",
            "ghost-reorder", "fake-ops", "synthetic-callee", "drop-callee-trace",
            "duplicate-projection", "wrong-local", "rebind-local",
            "rebind-same-model", "rebind-suchthat",
        }.issubset(labels))
        self.assertEqual(
            {"canonical-branch-flip", "canonical-erase-address",
             "canonical-erase-ops", "canonical-dead-branch"},
            {item[0] for item in REPLAY.CANONICAL_CONTROLS})
        self.assertTrue(REPLAY.ROOT_CONTROLS["SecretBranchObserved"][0])
        self.assertFalse(REPLAY.ROOT_CONTROLS["SecretBranchUnmarked"][0])
        self.assertTrue(REPLAY.FUNC_CONTROLS["FunctionControl.PrivateBranchObserved"])

    def test_package_inventory_is_scoped_and_excludes_scaffolding_and_evidence(self):
        files = set(REPLAY.package_files())
        self.assertIn("formal/crypto/NativePolynomial.dfy", files)
        self.assertIn("formal/crypto/native_polynomial_domain.dfy", files)
        self.assertIn("formal/source/SourceTrace.dfy", files)
        self.assertIn("formal/source/vocabulary/ObservationVocabulary.dfy", files)
        self.assertIn("formal/source/polynomial/checker/PolynomialSourceCoverage.cs", files)
        self.assertIn("formal/source/polynomial/controls/PolynomialControls.dfy", files)
        self.assertNotIn("formal/source/polynomial/inputs.json", files)
        self.assertNotIn("README.md", files)
        self.assertNotIn("PORT-MANIFEST.json", files)
        self.assertNotIn("formal/crypto/MlKem.dfy", files)
        self.assertNotIn("formal/crypto/ByteLanes.dfy", files)
        self.assertFalse(any(name.startswith("formal/source/polynomial/evidence/") for name in files))
        self.assertFalse(any("__pycache__" in name for name in files))

    def test_safe_relpath_rejects_absolute_parent_and_backslash(self):
        self.assertEqual("formal/source/x.dfy", REPLAY.safe_relpath("formal/source/x.dfy").as_posix())
        for name in ("/absolute", "../up", "a/../b", "a\\b", "", "a;b", "a\rb"):
            with self.subTest(name=name), self.assertRaises(REPLAY.GateError):
                REPLAY.safe_relpath(name)

    def test_safe_path_rejects_symlinked_component(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "real").mkdir()
            (root / "real/file").write_text("x\n")
            (root / "link").symlink_to(root / "real")
            self.assertEqual("x\n", (REPLAY.safe_path(root, "real/file")).read_text())
            with self.assertRaises(REPLAY.GateError):
                REPLAY.safe_path(root, "link/file")

    def test_replace_once_rejects_missing_or_duplicate_anchor(self):
        self.assertEqual("a B", REPLAY.replace_once("a b", "b", "B", "x"))
        with self.assertRaises(REPLAY.GateError):
            REPLAY.replace_once("a b b", "b", "B", "x")
        with self.assertRaises(REPLAY.GateError):
            REPLAY.replace_once("a b", "c", "B", "x")


def make_baseline(folder):
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    files = {}
    for i in range(20):
        name = f"f{i}.dfy"
        (root / name).write_text("x\n")
        files[name] = hashlib.sha256(b"x\n").hexdigest()
    manifest = {"commit": REPLAY.BASELINE_COMMIT, "tree": REPLAY.BASELINE_TREE,
                "files": files, "source_discovery": "test"}
    raw = json.dumps(manifest).encode()
    (root / "manifest.json").write_bytes(raw)
    return root, hashlib.sha256(raw).hexdigest()


class RuntimeGateTests(unittest.TestCase):
    def test_runtime_must_be_pinned_toolchain_or_approved_maven(self):
        self.assertIn("toolchain", REPLAY.approve_runtime("a" * 64, "a" * 64))
        self.assertIn("Maven", REPLAY.approve_runtime(REPLAY.APPROVED_MAVEN_RUNTIME_SHA256, "b" * 64))
        with self.assertRaises(REPLAY.GateError):
            REPLAY.approve_runtime("c" * 64, "b" * 64)


class BaselineGateTests(unittest.TestCase):
    def test_baseline_manifest_requires_complete_20_file_pin(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "manifest.json").write_text(
                '{"commit":"%s","tree":"%s","files":{}}' % (REPLAY.BASELINE_COMMIT, REPLAY.BASELINE_TREE))
            with self.assertRaises(REPLAY.GateError):
                REPLAY.verify_baseline(root)

    def test_baseline_manifest_rejects_hash_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            root, digest = make_baseline(folder)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"]["f0.dfy"] = "0" * 64
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaises(REPLAY.GateError):
                REPLAY.verify_baseline(root, trusted_manifest_sha256=REPLAY.BASELINE_MANIFEST_SHA256)

    def test_self_asserted_commit_tree_is_not_authentication(self):
        with tempfile.TemporaryDirectory() as folder:
            root, _ = make_baseline(folder)
            with self.assertRaises(REPLAY.GateError):
                REPLAY.verify_baseline(root)

    def test_untrusted_manifest_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root, digest = make_baseline(folder)
            with patch.object(REPLAY, "BASELINE_MANIFEST_SHA256", digest):
                with self.assertRaises(REPLAY.GateError):
                    REPLAY.verify_baseline(root, trusted_manifest_sha256="0" * 64)

    def test_reviewed_manifest_digest_authenticates_without_git(self):
        with tempfile.TemporaryDirectory() as folder:
            root, digest = make_baseline(folder)
            with patch.object(REPLAY, "BASELINE_MANIFEST_SHA256", digest):
                record = REPLAY.verify_baseline(root, trusted_manifest_sha256=digest)
            self.assertTrue(record["baseline_authenticated"])
            self.assertEqual("trusted-manifest-sha256", record["authentication"])
            self.assertFalse(record["git_show_verified"])

    def test_baseline_root_symlink_is_rejected_before_resolution(self):
        with tempfile.TemporaryDirectory() as folder:
            root, _ = make_baseline(Path(folder) / "real")
            link = Path(folder) / "link"
            link.symlink_to(root)
            with self.assertRaises(REPLAY.GateError):
                REPLAY.verify_baseline(link, trusted_manifest_sha256=REPLAY.BASELINE_MANIFEST_SHA256)


if __name__ == "__main__":
    unittest.main()
