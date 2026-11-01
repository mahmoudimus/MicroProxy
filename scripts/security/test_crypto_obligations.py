"""Independent fail-closed fixtures for the crypto obligation and release gates.

These tests do not consume the repository's current HKDF pins or receipts; they
construct a synthetic ledger so in-progress HKDF work cannot make the gate tests
stale. The repository ledger itself is exercised separately by the documented
commands.
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_crypto_obligations as obligations  # noqa: E402
import check_crypto_release as release  # noqa: E402


def sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    import hashlib
    return hashlib.sha256(data).hexdigest()


DEPENDENCIES = {
    "V0": [],
    "V1": ["V0"],
    "V2": ["V1"],
    "V3": ["V0"],
    "V4": ["V0"],
    "V5": ["V4"],
    "V6": ["V5"],
    "V7": ["V1", "V2", "V4", "V6"],
    "V8": ["V0", "V1", "V2", "V3", "V4", "V5", "V6", "V7"],
}
CLAIM_OBLIGATION = {
    "shake-mlkem-functional-production": "V6",
    "hkdf-isolated-functional": "V1",
    "hkdf-production-functional": "V1",
    "mlkem-reduceonce-historical-bytecode": "V3",
    "packet-nonce-bytecode": "V3",
    "saw-portable-alternate-route": "V3",
    "packet-receive-trace-scoped": "V7",
    "v8-nontiming-release-gate": "V8",
    "v8-timing-release-evidence": "V8",
    "current-release-jar-identity": "V6",
    "historical-adoption-jar-identity": "V6",
    "independent-expert-review": "V8",
    "cryptographic-security-proof": "V6",
    "jvm-constant-time": "V7",
    "whole-proxy-security": "V8",
    "aws-full-upstream-hkdf-replay": "V1",
    "all-v0-v8-complete": "V8",
}


class Fixture:
    REAL_ROOT = Path(__file__).resolve().parents[2]

    def __init__(self, directory: Path):
        self.root = directory
        self.assumptions = sorted(obligations.ALLOWED_ASSUMPTIONS)
        self.ledger = self._build()
        self.path = self.root / "formal/crypto-obligations.json"

    def write(self, relative: str, text: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def add_evidence(self, oid: str, relative: str, kind: str, role: str = "fixture evidence") -> dict:
        path = self.root / relative
        if not path.exists():
            path = self.write(relative, "fixture evidence\n")
        ref = {"path": relative, "sha256": sha(path.read_bytes()), "kind": kind, "role": role}
        self.obligation(oid)["evidence"].append(ref)
        return ref

    def obligation(self, oid: str) -> dict:
        return next(item for item in self.ledger["obligations"] if item["id"] == oid)

    def claim(self, claim_id: str) -> dict:
        return next(item for item in self.ledger["claims"] if item["id"] == claim_id)

    def _build(self) -> dict:
        # The unified V7 report validator is always active; fixture roots carry
        # the actual component report/manifest data rather than a shape stub.
        for relative in ("formal/timing/PRODUCTION-EVIDENCE.json", "formal/timing/inputs.json"):
            target = self.root / relative
            if not target.exists():
                real = self.REAL_ROOT / relative
                if real.is_file():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(real.read_bytes())
        packed = self.assumptions
        items = []
        for index, oid in enumerate(obligations.REQUIRED_OBLIGATIONS):
            relative = f"evidence/{oid}.txt"
            self.write(relative, "nonvacuity: satisfiable witness\ncontrol: mutant failure\n")
            used = [packed[index]]
            if index < len(packed) - len(obligations.REQUIRED_OBLIGATIONS):
                used.append(packed[index + len(obligations.REQUIRED_OBLIGATIONS)])
            items.append({
                "id": oid,
                "title": f"fixture {oid}",
                "status": "finite-tests",
                "statement": f"fixture statement for {oid}",
                "dependencies": list(DEPENDENCIES[oid]),
                "assumptions": used,
                "evidence": [{"path": relative, "sha256": sha((self.root / relative).read_bytes()),
                              "kind": "component-receipt", "role": "fixture receipt"}],
                "nonvacuity": {"name": f"{oid}-satisfiable-domain", "path": relative,
                               "markers": ["satisfiable witness"]},
                "limitations": [f"fixture limitation for {oid}"],
            })
        claims = []
        for claim_id in sorted(obligations.ALLOWED_CLAIMS):
            oid = CLAIM_OBLIGATION[claim_id]
            claims.append({
                "id": claim_id,
                "statement": f"fixture claim {claim_id}",
                "status": "unsupported",
                "strength": "none",
                "production": False,
                "obligations": [oid],
                "assumptions": [packed[0]],
                "evidence": [f"evidence/{oid}.txt"],
                "limitations": ["fixture residual"],
            })
        assumption_entries = {
            name: {"statement": f"fixture assumption {name}",
                   "evidence": [f"assumptions/{name}.md"]}
            for name in packed
        }
        for name in packed:
            self.write(f"assumptions/{name}.md", f"assumption: {name}\n")
        return {
            "schema": obligations.LEDGER_SCHEMA,
            "scope": "synthetic fixture; independent of volatile repository HKDF pins",
            "assumptions": assumption_entries,
            "obligations": items,
            "claims": claims,
        }

    def write_ledger(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.ledger, indent=2), encoding="utf-8")
        return self.path

    def _write_json(self, relative: str, value: dict) -> None:
        self.write(relative, json.dumps(value, indent=2))

    def _load_json(self, relative: str) -> dict:
        path = self.root / relative
        if path.exists():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    return value
            except json.JSONDecodeError:
                pass
        return {}

    def _nested_set(self, container: dict, dotted: str, value) -> None:
        current = container
        parts = dotted.split(".")
        for part in parts[:-1]:
            child = current.get(part)
            if not isinstance(child, dict):
                child = {}
                current[part] = child
            current = child
        current[parts[-1]] = value

    def _set_evidence(self, oid: str, relative: str, kind: str) -> None:
        path = self.root / relative
        if not path.exists():
            if relative.endswith(".json"):
                self._write_json(relative, {})
            else:
                self.write(relative, f"fixture required evidence: {relative}\n")
        refs = self.obligation(oid)["evidence"]
        refs[:] = [ref for ref in refs if ref["path"] != relative]
        refs.append({"path": relative, "sha256": sha(path.read_bytes()),
                     "kind": kind, "role": "fixture required evidence"})

    def _runtime_hash(self, oid: str) -> str:
        for check in obligations.REQUIRED_COMPONENT_CHECKS[oid]["inventory_checks"]:
            return check["expected_runtime_sha256"]
        return "a" * 64

    def _nested_get(self, value, dotted: str):
        current = value
        for part in dotted.split("."):
            current = current[part]
        return current

    def _expected_receipt_value(self, oid: str, receipt_path: str, value_path: str):
        matches = []
        for (exact_oid, exact_receipt, exact_path), expected in obligations.REQUIRED_RECEIPT_EXACT.items():
            if exact_oid != oid or exact_receipt != receipt_path:
                continue
            if value_path == exact_path:
                matches.append((len(exact_path), expected))
            elif value_path.startswith(exact_path + "."):
                matches.append((len(exact_path), self._nested_get(expected, value_path[len(exact_path) + 1:])))
        if matches:
            return max(matches, key=lambda item: item[0])[1]
        return None

    def _refresh_receipt_checks(self, oid: str) -> None:
        for check in self.obligation(oid).get("receipt_checks", []):
            receipt = self._load_json(check["receipt"])
            for path in list(check["values"]):
                check["values"][path] = self._nested_get(receipt, path)

    def _write_expected_hash_map(self, oid: str, receipt_path: str, map_path: str,
                                 includes: tuple, excludes: tuple, path_prefix: str) -> None:
        expected = obligations.REQUIRED_HASH_MAP_KEYS.get((oid, receipt_path, map_path))
        if expected is None:
            raise AssertionError(f"missing expected hash-map keys for {oid}:{receipt_path}:{map_path}")
        mapping = {}
        for key in expected:
            actual_relative = f"{path_prefix}/{key}" if path_prefix else key
            path = self.root / actual_relative
            if not path.exists():
                real = self.REAL_ROOT / actual_relative
                if real.is_file():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(real.read_bytes())
                else:
                    self.write(actual_relative, f"fixture pinned source {key}\n")
            mapping[key] = sha(path.read_bytes())
        receipt = self._load_json(receipt_path)
        self._nested_set(receipt, map_path, mapping)
        self._write_json(receipt_path, receipt)

    def _refresh_required_hash_maps(self, oid: str) -> None:
        for signature in obligations.REQUIRED_COMPONENT_CHECKS[oid]["hash_maps"]:
            receipt_path, map_path, includes, excludes = signature[:4]
            path_prefix = signature[4] if len(signature) > 4 else ""
            self._write_expected_hash_map(oid, receipt_path, map_path, includes, excludes, path_prefix)

    def _refresh_required_inventories(self, oid: str) -> None:
        for required in obligations.REQUIRED_COMPONENT_CHECKS[oid].get("inventory_checks", ()):
            expected = obligations.REQUIRED_INVENTORY_KEYS.get((oid, required.get("id")))
            if expected is None:
                raise AssertionError(f"missing expected inventory keys for {oid}:{required.get('id')}")
            expected_set = set(expected)
            for prefix in required.get("managed_prefixes", []):
                directory = self.root / required["root"] / prefix
                if directory.is_dir():
                    for path in directory.rglob("*"):
                        relative = path.relative_to(self.root / required["root"]).as_posix()
                        if path.is_file() and relative not in expected_set:
                            path.unlink()
            mapping = {}
            for key in expected:
                actual_relative = f"{required['root']}/{key}"
                path = self.root / actual_relative
                if not path.exists():
                    self.write(actual_relative, f"fixture delivered source {key}\n")
                mapping[key] = sha(path.read_bytes())
            receipt = self._load_json(required["receipt"])
            self._nested_set(receipt, required.get("delivered_field", "delivered_sources"), mapping)
            self._write_json(required["receipt"], receipt)

    def _refresh_required_file_sets(self, oid: str) -> None:
        for required in obligations.REQUIRED_COMPONENT_CHECKS[oid].get("file_set_checks", ()):
            expected = obligations.REQUIRED_FILE_SET_KEYS.get((oid, required.get("id")))
            if expected is None:
                raise AssertionError(f"missing expected file set for {oid}:{required.get('id')}")
            directory = self.root / required["root"]
            directory.mkdir(parents=True, exist_ok=True)
            for path in directory.rglob("*"):
                if path.is_file() and path.relative_to(directory).as_posix() not in expected:
                    path.unlink()
            mapping = {}
            for key in expected:
                path = directory / key
                if not path.exists():
                    real = self.REAL_ROOT / required["root"] / key
                    if real.is_file():
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(real.read_bytes())
                    else:
                        self.write(f"{required['root']}/{key}", f"generated fixture {key}\n")
                mapping[key] = sha(path.read_bytes())
            receipt = self._load_json(required["receipt"])
            self._nested_set(receipt, required["field"], mapping)
            self._write_json(required["receipt"], receipt)

    def install_required_component(self, oid: str) -> None:
        """Install the mandatory evidence/check contract for a supported component."""
        # Seed every required file before receipts are mutated.
        for relative, kind in obligations.REQUIRED_COMPONENT_EVIDENCE[oid]:
            path = self.root / relative
            if not path.exists():
                real = self.REAL_ROOT / relative
                if real.is_file():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(real.read_bytes())
                elif relative.endswith(".json"):
                    self._write_json(relative, {})
                else:
                    self.write(relative, f"fixture required evidence: {relative}\n")
        checks = obligations.REQUIRED_COMPONENT_CHECKS[oid]
        obligation = self.obligation(oid)
        runtime_hash = self._runtime_hash(oid)

        # Generated-file inventory and delivery runtime/facades.
        obligation["inventory_checks"] = []
        for required in checks["inventory_checks"]:
            prefix = required["managed_prefixes"][0]
            delivered = {}
            for name in ("FixtureA.java", "FixtureB.java"):
                relative = f"{required['root']}/{prefix}{name}"
                self.write(relative, f"generated fixture {name}\n")
                delivered[f"{prefix}{name}"] = sha((self.root / relative).read_bytes())
            stage = self._load_json(required["receipt"])
            stage["delivered_sources"] = delivered
            stage["runtime_sha256"] = runtime_hash
            self._write_json(required["receipt"], stage)
            if required.get("runtime_manifest"):
                delivery = self._load_json(required["runtime_manifest"])
                delivery["runtime"] = {
                    "coordinate": "fixture:runtime",
                    "url": "https://example.invalid/runtime",
                    "sha256": runtime_hash,
                }
                self._write_json(required["runtime_manifest"], delivery)
            if required.get("facade_manifest"):
                source = "fixture/facade/Source.java"
                destination = "fixture/facade/Destination.java"
                self.write(source, "fixture facade source\n")
                self.write(destination, "fixture facade destination\n")
                delivery = self._load_json(required["facade_manifest"])
                delivery["facades"] = [{
                    "source": source, "destination": destination,
                    "sha256": sha((self.root / destination).read_bytes()),
                }]
                self._write_json(required["facade_manifest"], delivery)
            obligation["inventory_checks"].append(dict(required))

        # Receipt checks: create and pin the required scalar fields.
        obligation["receipt_checks"] = []
        for receipt_path, value_paths in checks["receipt_checks"]:
            receipt = self._load_json(receipt_path)
            values = {}
            for path in value_paths:
                exact = self._expected_receipt_value(oid, receipt_path, path)
                if exact is not None:
                    value = exact
                elif path in {"runtime.sha256", "runtime_sha256"}:
                    value = runtime_hash
                elif path == "runtime.coordinate":
                    value = "fixture:runtime"
                elif path == "runtime.url":
                    value = "https://example.invalid/runtime"
                elif path == "runs.nonce.result":
                    value = "blocked_by_array_clone_translation"
                elif path.startswith("runs."):
                    value = 2 if path.endswith("exit_code") else "semantic proof failure"
                else:
                    value = 1
                self._nested_set(receipt, path, value)
                values[path] = value
            self._write_json(receipt_path, receipt)
            obligation["receipt_checks"].append({"receipt": receipt_path, "values": values})

        # Hash maps: each mandatory map has a real pinned file and exact filters.
        obligation["hash_maps"] = []
        for signature in checks["hash_maps"]:
            receipt_path, map_path, includes, excludes = signature[:4]
            path_prefix = signature[4] if len(signature) > 4 else ""
            self._write_expected_hash_map(oid, receipt_path, map_path, includes, excludes, path_prefix)
            entry = {"receipt": receipt_path, "path": map_path}
            if includes:
                entry["include_prefixes"] = list(includes)
            if excludes:
                entry["exclude_paths"] = list(excludes)
            if path_prefix:
                entry["path_prefix"] = path_prefix
            obligation["hash_maps"].append(entry)
        self._refresh_required_hash_maps(oid)

        # Provider/facade entry hashes.
        obligation["entry_hash_checks"] = []
        for receipt_path, entry_path, path_key, hash_key in checks["entry_hash_checks"]:
            source = f"fixture/{entry_path}/Source.java"
            destination = f"fixture/{entry_path}/Destination.java"
            content = f"fixture entry for {entry_path}\n"
            self.write(source, content)
            self.write(destination, content)
            receipt = self._load_json(receipt_path)
            if entry_path == "facades":
                entry = {"source": source, "destination": destination,
                         hash_key: sha(content)}
            else:
                entry = {path_key: source, hash_key: sha((self.root / source).read_bytes())}
            receipt[entry_path] = [entry]
            self._write_json(receipt_path, receipt)
            obligation["entry_hash_checks"].append({
                "receipt": receipt_path, "path": entry_path,
                "path_key": path_key, "hash_key": hash_key,
            })

        # Named semantic controls with a mandatory failure-bearing field.
        obligation["control_groups"] = []
        for group_id, receipt_path, controls_path in checks["control_groups"]:
            field = obligations.REQUIRED_CONTROL_FAILURE_FIELDS[group_id]
            value = {"errors": 1, "result": "semantic proof failure",
                     "rejected": "fixture rejected mutation"}[field]
            controls = {name: {field: value} for name in obligations.REQUIRED_CONTROL_INVENTORY[group_id]}
            exact_controls = obligations.REQUIRED_RECEIPT_EXACT.get((oid, receipt_path, controls_path))
            if isinstance(exact_controls, dict):
                controls = exact_controls
            elif group_id == "saw-scoped-replay":
                controls = {
                    "proof": {"result": "verified"},
                    "wrong_modulus": {"result": "proof_counterexample", "exit_code": 2},
                    "vacuous": {"result": "rejected_vacuous_specification"},
                    "nonce": {"result": "blocked_by_array_clone_translation"},
                }
            receipt = self._load_json(receipt_path)
            self._nested_set(receipt, controls_path, controls)
            self._write_json(receipt_path, receipt)
            expected = {name: dict(fields) for name, fields in controls.items()}
            obligation["control_groups"].append({
                "id": group_id, "receipt": receipt_path,
                "controls_path": controls_path, "expected": expected,
            })

        # Exact generated file-set inventory.
        obligation["file_set_checks"] = []
        for required in checks.get("file_set_checks", ()):
            obligation["file_set_checks"].append(dict(required))
        self._refresh_required_file_sets(oid)

        # Required nonvacuity and reviewed text markers.
        if checks["nonvacuity"]:
            path, markers = checks["nonvacuity"]
            if path.endswith(".json"):
                data = self._load_json(path)
                data["_fixture_nonvacuity"] = " ".join(markers)
                self._write_json(path, data)
            else:
                self.write(path, "\n".join(markers) + "\n")
            obligation["nonvacuity"] = {
                "name": f"{oid}-fixture-nonvacuity", "path": path, "markers": list(markers),
            }
        obligation["text_checks"] = []
        for path, markers in checks["text_checks"]:
            target = self.root / path
            if not target.exists():
                real = self.REAL_ROOT / path
                if real.is_file():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(real.read_bytes())
                else:
                    self.write(path, "\n".join(markers) + "\n")
            obligation["text_checks"].append({"path": path, "markers": list(markers)})

        # Pin the final bytes only after every receipt mutation.
        for relative, kind in obligations.REQUIRED_COMPONENT_EVIDENCE[oid]:
            self._set_evidence(oid, relative, kind)

    def make_supported(self, claim_id: str) -> None:
        policy = obligations.CLAIM_POLICIES[claim_id]
        for oid in policy.get("component_checks", ()):
            self.install_required_component(oid)
        # Shared manifests and generated directories may be mutated by a later
        # component; refresh exact file sets and re-pin every installed component.
        for oid in policy.get("component_checks", ()):
            self._refresh_required_file_sets(oid)
            self._refresh_required_hash_maps(oid)
            self._refresh_required_inventories(oid)
            self._refresh_receipt_checks(oid)
        for oid in policy.get("component_checks", ()):
            for path, kind in obligations.REQUIRED_COMPONENT_EVIDENCE[oid]:
                self._set_evidence(oid, path, kind)
        for oid, allowed in policy.get("required_statuses", {}).items():
            self.obligation(oid)["status"] = allowed[0]
        claim = self.claim(claim_id)
        evidence_paths = []
        for path, kind in policy["required_evidence"]:
            if path is None:
                found = next(ref["path"] for oid in policy["obligations"]
                             for ref in self.obligation(oid)["evidence"] if ref["kind"] == kind)
                evidence_paths.append(found)
            else:
                evidence_paths.append(path)
        claim.update({
            "status": "supported",
            "strength": policy["strength"],
            "production": policy["production"],
            "obligations": list(policy["obligations"]),
            "assumptions": sorted(policy["assumptions"]),
            "evidence": list(dict.fromkeys(evidence_paths)),
            "limitations": ["fixture supported scope; no wider timing/security claim"],
        })

    def make_production_supported(self) -> None:
        self.make_supported("shake-mlkem-functional-production")

    def add_control_fixture(self) -> None:
        self.write("controls.json", json.dumps({"controls": {"mutant": {"verified": 1, "errors": 1}}}))
        self.add_evidence("V4", "controls.json", "component-receipt", "controls")
        self.obligation("V4")["control_groups"] = [{
            "receipt": "controls.json",
            "controls_path": "controls",
            "expected": {"mutant": {"verified": 1, "errors": 1}},
        }]

    def add_inventory_fixture(self) -> None:
        self.write("src/main/java/io/x/A.java", "a\n")
        self.write("src/main/java/io/x/B.java", "b\n")
        stage = {"delivered_sources": {
            "io/x/A.java": sha((self.root / "src/main/java/io/x/A.java").read_bytes()),
            "io/x/B.java": sha((self.root / "src/main/java/io/x/B.java").read_bytes()),
        }}
        runtime_hash = "a" * 64
        self.write("stage.json", json.dumps(stage))
        self.write("delivery.json", json.dumps({"runtime": {
            "coordinate": "fixture:runtime", "url": "https://example.invalid/runtime", "sha256": runtime_hash}}))
        self.add_evidence("V6", "stage.json", "delivery-receipt")
        self.add_evidence("V6", "delivery.json", "delivery-receipt")
        self.obligation("V6")["inventory_checks"] = [{
            "root": "src/main/java",
            "receipt": "stage.json",
            "delivered_field": "delivered_sources",
            "managed_prefixes": ["io/x/"],
            "runtime_manifest": "delivery.json",
            "expected_runtime_sha256": runtime_hash,
        }]


class ObligationLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = Fixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self):
        return obligations.validate_ledger(self.root, self.fixture.write_ledger())

    def assert_invalid(self, pattern: str):
        with self.assertRaisesRegex(obligations.LedgerError, pattern):
            self.validate()

    def test_valid_fixture_reports_deferred_residuals_without_claiming_completion(self):
        status = self.validate()
        self.assertTrue(status["ok"])
        self.assertIn("hkdf-production-functional", status["residual_claims"])
        self.assertEqual(status["obligations"]["V0"], "finite-tests")

    def test_dropped_obligation_fails_the_fixed_inventory(self):
        self.fixture.ledger["obligations"].remove(self.fixture.obligation("V7"))
        self.assert_invalid("inventory incomplete")

    def test_duplicate_obligation_fails(self):
        self.fixture.ledger["obligations"].append(dict(self.fixture.obligation("V4")))
        self.fixture.ledger["obligations"] = [
            self.fixture.obligation("V0"), self.fixture.obligation("V1"), self.fixture.obligation("V2"),
            self.fixture.obligation("V3"), self.fixture.obligation("V4"), dict(self.fixture.obligation("V4")),
            self.fixture.obligation("V5"), self.fixture.obligation("V6"), self.fixture.obligation("V7"),
            self.fixture.obligation("V8")]
        self.assert_invalid("duplicate obligation")

    def test_dependency_cycle_fails(self):
        self.fixture.obligation("V0")["dependencies"] = ["V8"]
        self.assert_invalid("cycle")

    def test_dropped_root_dependency_leaves_an_unreachable_obligation(self):
        self.fixture.obligation("V8")["dependencies"].remove("V7")
        self.assert_invalid("not reachable")

    def test_unknown_dependency_fails(self):
        self.fixture.obligation("V4")["dependencies"].append("V99")
        self.assert_invalid("unknown dependency")

    def test_unexpected_or_unused_assumption_fails(self):
        rogue = {"statement": "fixture rogue", "evidence": ["assumptions/rogue.md"]}
        self.fixture.write("assumptions/rogue.md", "rogue\n")
        self.fixture.ledger["assumptions"]["rogue"] = rogue
        self.assert_invalid("assumption inventory changed")

    def test_unknown_assumption_reference_fails(self):
        self.fixture.obligation("V4")["assumptions"].append("not-reviewed")
        self.assert_invalid("unknown/unlisted assumption")

    def test_duplicate_assumption_reference_fails(self):
        self.fixture.obligation("V4")["assumptions"].append(self.fixture.obligation("V4")["assumptions"][0])
        self.assert_invalid("unique list")

    def test_duplicate_json_keys_are_rejected(self):
        self.fixture.path.parent.mkdir(parents=True, exist_ok=True)
        self.fixture.path.write_text('{"schema": "x", "schema": "y"}', encoding="utf-8")
        with self.assertRaisesRegex(obligations.LedgerError, "duplicate JSON key"):
            obligations.load_json(self.fixture.path)

    def test_stale_and_tampered_evidence_fails(self):
        self.fixture.write_ledger()
        (self.root / "evidence/V4.txt").write_text("tampered\n", encoding="utf-8")
        self.assert_invalid("stale/tampered evidence")

    def test_null_or_unpinned_hash_fails(self):
        for value in (None, "", "0" * 64, "f" * 63, "F" * 64):
            with self.subTest(value=value):
                self.fixture.obligation("V4")["evidence"][0]["sha256"] = value
                self.assert_invalid("pinned nonzero lowercase SHA-256")

    def test_path_traversal_and_absolute_evidence_fails(self):
        for value in ("../escape.txt", "/tmp/escape.txt", "evidence/../escape.txt", "C:\\escape.txt"):
            with self.subTest(value=value):
                self.fixture.obligation("V4")["evidence"][0]["path"] = value
                self.assert_invalid("path|relative|escapes")

    def test_symlinked_evidence_is_rejected(self):
        outside = self.root.parent / "outside-evidence.txt"
        outside.write_text("outside\n", encoding="utf-8")
        link = self.root / "evidence/link.txt"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside)
        self.fixture.obligation("V4")["evidence"].append({
            "path": "evidence/link.txt", "sha256": sha(outside.read_bytes()),
            "kind": "component-receipt", "role": "fixture symlink"})
        self.assert_invalid("symlink")

    def test_proof_status_without_named_nonvacuity_fails(self):
        self.fixture.obligation("V4")["status"] = "implementation-proof"
        del self.fixture.obligation("V4")["nonvacuity"]
        self.assert_invalid("named nonvacuity")

    def test_nonvacuity_marker_must_be_present(self):
        self.fixture.obligation("V4")["status"] = "implementation-proof"
        self.fixture.obligation("V4")["nonvacuity"]["markers"] = ["missing satisfiable witness"]
        self.assert_invalid("nonvacuity/domain marker missing")

    def test_control_inventory_missing_extra_or_nonfailing_all_fail(self):
        self.fixture.add_control_fixture()
        cases = []
        missing = {"controls": {}}
        cases.append(("missing", missing, "control inventory changed"))
        cases.append(("extra", {"controls": {"mutant": {"verified": 1, "errors": 1},
                                            "extra": {"verified": 1, "errors": 1}}}, "control inventory changed"))
        cases.append(("success-label", {"controls": {"mutant": {"verified": 1, "errors": 0}}}, "errors changed"))
        cases.append(("timeout", {"controls": {"mutant": {"verified": 1, "errors": 1, "result": "timeout"}}},
                      "timeout/resource/crash/parser"))
        cases.append(("killed", {"controls": {"mutant": {"verified": 1, "errors": 1, "result": "counterexample",
                                                         "exit_code": 137}}}, "interrupted/resource exit"))
        for name, receipt, pattern in cases:
            with self.subTest(name=name):
                self.fixture.write("controls.json", json.dumps(receipt))
                for ref in self.fixture.obligation("V4")["evidence"]:
                    if ref["path"] == "controls.json":
                        ref["sha256"] = sha((self.root / "controls.json").read_bytes())
                self.assert_invalid(pattern)

    def test_v0_finite_fixture_cannot_be_relabelled_as_production_claim(self):
        claim = self.fixture.claim("shake-mlkem-functional-production")
        claim.update({
            "status": "supported",
            "strength": "none",
            "production": False,
            "obligations": ["V0"],
            "evidence": ["evidence/V0.txt"],
            "assumptions": sorted(
                obligations.CLAIM_POLICIES[claim["id"]]["assumptions"]),
        })
        self.assert_invalid("reviewed policy|dependency set")

    def test_model_only_obligation_cannot_support_production_claim(self):
        self.fixture.make_production_supported()
        self.fixture.obligation("V5")["status"] = "model-proof"
        self.assert_invalid("cannot support this claim")

    def test_finite_observation_cannot_support_proof_claim(self):
        self.fixture.make_production_supported()
        ref = next(ref for ref in self.fixture.obligation("V4")["evidence"]
                   if ref["path"] == "formal/crypto/SHAKE-EVIDENCE.json")
        ref["kind"] = "finite-test"
        self.assert_invalid("required evidence|must be kind|finite")

    def test_text_only_claim_evidence_cannot_support_production(self):
        self.fixture.make_production_supported()
        claim = self.fixture.claim("shake-mlkem-functional-production")
        claim["evidence"] = ["formal/obligations.md"]
        self.assert_invalid("not declared by its obligations|required evidence")

    def test_broad_or_blocked_claims_cannot_be_supported(self):
        for claim_id in ("cryptographic-security-proof", "packet-nonce-bytecode", "jvm-constant-time"):
            with self.subTest(claim=claim_id):
                claim = self.fixture.claim(claim_id)
                claim["status"] = "supported"
                claim["obligations"] = ["V4"]
                self.fixture.obligation("V4")["status"] = "implementation-proof"
                claim["evidence"] = ["evidence/V4.txt"]
                claim["strength"] = "none"
                self.assert_invalid("reviewed policy|cannot support|must be|required")

    def test_each_mandatory_validation_section_is_required(self):
        cases = (
            ("control_groups", "V4", "control_groups", "required control group removed"),
            ("receipt_checks", "V4", "receipt_checks", "required receipt check removed"),
            ("hash_maps", "V4", "hash_maps", "required pinned source/tool map"),
            ("entry_hash_checks", "V6", "entry_hash_checks", "required provider/facade"),
            ("inventory_checks", "V6", "inventory_checks", "generated-file inventory"),
            ("nonvacuity", "V4", "nonvacuity", "named nonvacuity"),
        )
        for name, oid, field, pattern in cases:
            with self.subTest(section=name), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                fixture.make_production_supported()
                del fixture.obligation(oid)[field]
                fixture.write_ledger()
                with self.assertRaisesRegex(obligations.LedgerError, pattern):
                    obligations.validate_ledger(fixture.root, fixture.path)

    def test_non_timing_gate_required_text_checks_cannot_be_removed(self):
        self.fixture.make_supported("v8-nontiming-release-gate")
        del self.fixture.obligation("V8")["text_checks"]
        self.assert_invalid("required reviewed text checks removed")

    def test_control_group_cannot_lose_a_named_control_or_downgrade_to_labels(self):
        cases = []
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.make_production_supported()
            group = fixture.obligation("V4")["control_groups"][0]
            removed = next(iter(group["expected"]))
            del group["expected"][removed]
            with self.assertRaisesRegex(obligations.LedgerError, "control inventory changed"):
                obligations.validate_ledger(fixture.root, fixture.write_ledger())
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.make_production_supported()
            group = fixture.obligation("V4")["control_groups"][0]
            group["require_semantic_failure"] = False
            for fields in group["expected"].values():
                fields.clear()
                fields["verified"] = 1
            receipt = fixture._load_json(group["receipt"])
            controls = {name: {"verified": 1} for name in group["expected"]}
            fixture._nested_set(receipt, group["controls_path"], controls)
            fixture._write_json(group["receipt"], receipt)
            fixture._set_evidence("V4", group["receipt"], "component-receipt")
            with self.assertRaisesRegex(obligations.LedgerError, "missing required failure field"):
                obligations.validate_ledger(fixture.root, fixture.write_ledger())

    def _set_receipt_expected(self, oid: str, receipt_path: str, values: dict) -> None:
        for check in self.fixture.obligation(oid).get("receipt_checks", []):
            if check["receipt"] == receipt_path:
                check["values"].update(values)

    def test_v4_positive_proof_metadata_cannot_be_zeroed_after_repin(self):
        self.fixture.make_production_supported()
        receipt_path = "formal/crypto/SHAKE-EVIDENCE.json"
        receipt = self.fixture._load_json(receipt_path)
        receipt["proofs"] = {}
        receipt["audits"] = {}
        receipt["generation"] = {"status": "fabricated"}
        receipt["vectors"]["count"] = 0
        self.fixture._write_json(receipt_path, receipt)
        self._set_receipt_expected("V4", receipt_path, {
            "proofs": {}, "audits": {}, "generation": {"status": "fabricated"},
            "vectors.count": 0,
        })
        self.fixture._set_evidence("V4", receipt_path, "component-receipt")
        self.assert_invalid("required receipt value changed: formal/crypto/SHAKE-EVIDENCE.json")

    def test_v5_positive_proof_metadata_cannot_be_zeroed_after_repin(self):
        self.fixture.make_production_supported()
        codec_path = "formal/crypto/CODEC-EVIDENCE.json"
        poly_path = "formal/crypto/POLYNOMIAL-EVIDENCE.json"
        codec = self.fixture._load_json(codec_path)
        codec["proofs"] = {}
        self.fixture._write_json(codec_path, codec)
        poly = self.fixture._load_json(poly_path)
        poly["verified"] = 0
        self.fixture._write_json(poly_path, poly)
        self._set_receipt_expected("V5", codec_path, {
            "proofs.proof-Codec": 0, "proofs.proof-Sampling": 0,
            "proofs.codec_domain": 0, "proofs.sampling_domain": 0,
        })
        self._set_receipt_expected("V5", poly_path, {"verified": 0})
        self.fixture._set_evidence("V5", codec_path, "component-receipt")
        self.fixture._set_evidence("V5", poly_path, "component-receipt")
        self.assert_invalid("required receipt value changed")

    def test_v6_positive_proof_metadata_cannot_be_zeroed_after_repin(self):
        self.fixture.make_production_supported()
        kem_path = "formal/crypto/KEM-EVIDENCE.json"
        native_path = "formal/crypto/NATIVE-KEM-EVIDENCE.json"
        linux_path = "formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json"
        kem = self.fixture._load_json(kem_path)
        kem["proofs"] = {"proof-full": 0, "generate-java": 0}
        self.fixture._write_json(kem_path, kem)
        native = self.fixture._load_json(native_path)
        native["proofs"] = {
            "proof-native-composition": 0, "proof-reference-graph": 0,
            "proof-native-kernels": 0, "generate-java": 0,
        }
        self.fixture._write_json(native_path, native)
        linux = self.fixture._load_json(linux_path)
        linux["verified"] = 0
        self.fixture._write_json(linux_path, linux)
        self._set_receipt_expected("V6", kem_path, {
            "proofs.proof-full": 0, "proofs.generate-java": 0,
        })
        self._set_receipt_expected("V6", native_path, {
            "proofs.proof-native-composition": 0, "proofs.proof-reference-graph": 0,
            "proofs.proof-native-kernels": 0, "proofs.generate-java": 0,
        })
        self._set_receipt_expected("V6", linux_path, {"verified": 0})
        for path in (kem_path, native_path, linux_path):
            self.fixture._set_evidence("V6", path, "component-receipt")
        self.assert_invalid("required receipt value changed")

    def test_v7_packet_positive_text_metadata_cannot_be_zeroed_after_repin(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        evidence_path = "formal/packet/EVIDENCE.md"
        original = (self.root / evidence_path).read_text(encoding="utf-8")
        mutated = original.replace("46 verified,0 errors", "0 verified,0 errors")
        self.fixture.write(evidence_path, mutated)
        text_check = self.fixture.obligation("V7")["text_checks"][0]
        text_check["markers"] = [marker.replace("46 verified,0 errors", "0 verified,0 errors")
                                 for marker in text_check["markers"]]
        self.fixture._set_evidence("V7", evidence_path, "component-receipt")
        self.assert_invalid("required reviewed text checks removed")

    def _repin_trace_report(self) -> str:
        path = "formal/timing/PRODUCTION-EVIDENCE.json"
        self.fixture._set_evidence("V7", path, "component-receipt")
        return path

    def test_trace_positive_fixture_and_mutant_diagnostic_snapshot_bound(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        path = "formal/timing/PRODUCTION-EVIDENCE.json"
        report = self.fixture._load_json(path)
        positive = report["fixtures"]["ConstantTime"]
        positive["obligations"] = 0
        positive["instructions"] = 0
        positive["instructions_reachable"] = 0
        report["certificate_mutants"]["secret-guard"]["diagnostic"] = "timeout"
        self.fixture._write_json(path, report)
        self._repin_trace_report()
        self.assert_invalid("trace report does not match reviewed snapshot")

    def test_trace_owned_contract_and_open_reason_snapshot_bound(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        path = "formal/timing/PRODUCTION-EVIDENCE.json"
        report = self.fixture._load_json(path)
        report["assumed_owned_callees"][0]["contract"]["result"] = "sec"
        report["open_roots"][0]["reason"] = "fabricated reason"
        self.fixture._write_json(path, report)
        self._repin_trace_report()
        self.assert_invalid("trace report does not match reviewed snapshot")

    def test_trace_budget_command_and_class_binding_values_snapshot_bound(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        path = "formal/timing/PRODUCTION-EVIDENCE.json"
        report = self.fixture._load_json(path)
        command = report["roots"][0]["verify_command"]
        command[command.index("30")] = "999"
        first_class = next(iter(report["class_binding"]))
        report["class_binding"][first_class]["class_sha256"] = "0" * 64
        self.fixture._write_json(path, report)
        self._repin_trace_report()
        self.assert_invalid("trace report does not match reviewed snapshot")

    def test_trace_input_drift_cannot_be_hidden_by_repin(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        inputs_path = "formal/timing/inputs.json"
        report_path = "formal/timing/PRODUCTION-EVIDENCE.json"
        inputs = self.fixture._load_json(inputs_path)
        removed = next(iter(inputs["inputs"]))
        del inputs["inputs"][removed]
        self.fixture._write_json(inputs_path, inputs)
        report = self.fixture._load_json(report_path)
        report["inputs"].pop(removed, None)
        self.fixture._write_json(report_path, report)
        self.fixture._set_evidence("V7", inputs_path, "input-manifest")
        self.fixture._set_evidence("V7", report_path, "component-receipt")
        self.assert_invalid("pinned map key inventory changed|trace report inputs differ|trace report does not match reviewed snapshot")

    def test_trace_scope_deletion_and_fake_closure_fail(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        report_path = "formal/timing/PRODUCTION-EVIDENCE.json"
        report = self.fixture._load_json(report_path)
        report["open_roots"] = report["open_roots"][1:]
        report["assumed_owned_callees"] = []
        report["unchecked_owned_callees"] = []
        self.fixture._write_json(report_path, report)
        self.fixture._set_evidence("V7", report_path, "component-receipt")
        self.assert_invalid("assumed owned callee set changed|open owned root|unchecked owned callee|trace report does not match reviewed snapshot")

    def test_v7_cannot_be_promoted_with_open_roots_or_assumed_callees(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        self.fixture.obligation("V7")["status"] = "bytecode-proof"
        self.assert_invalid("V7 cannot be promoted")

    def test_unvalidated_future_categories_fail_closed_even_with_receipts(self):
        cases = (
            ("cryptographic-security-proof", "security-reduction-receipt", "V6"),
            ("jvm-constant-time", "timing-proof-receipt", "V7"),
            ("v8-timing-release-evidence", "timing-proof-receipt", "V8"),
            ("whole-proxy-security", "whole-system-proof-receipt", "V8"),
            ("independent-expert-review", "expert-review-receipt", "V8"),
            ("current-release-jar-identity", "current-jar-receipt", "V6"),
            ("aws-full-upstream-hkdf-replay", "upstream-closure-receipt", "V1"),
        )
        for claim_id, kind, oid in cases:
            with self.subTest(claim=claim_id), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                fixture.write(f"fake-{claim_id}.json", json.dumps({
                    "schema": "microproxy.self-certified/v1",
                    "status": "complete",
                    "independent_external": True,
                    "scope": "full-jar",
                    "full_jar_verified": True,
                    "full_dependency_graph_verified": True,
                }))
                fixture.add_evidence(oid, f"fake-{claim_id}.json", kind)
                claim = fixture.claim(claim_id)
                policy = obligations.CLAIM_POLICIES[claim_id]
                claim.update({
                    "status": "supported",
                    "strength": policy["strength"],
                    "production": policy["production"],
                    "obligations": list(policy["obligations"]),
                    "assumptions": sorted(policy["assumptions"]),
                    "evidence": [f"fake-{claim_id}.json"],
                    "limitations": ["fabricated metadata must not self-certify"],
                })
                with self.assertRaisesRegex(obligations.LedgerError, "no reviewed semantic evidence validator"):
                    obligations.validate_ledger(fixture.root, fixture.write_ledger())

    def test_trimmed_hkdf_input_map_cannot_be_blessed_by_repin(self):
        self.fixture.make_supported("hkdf-production-functional")
        receipt_path = "formal/dafny/PRODUCTION-EVIDENCE.json"
        receipt = self.fixture._load_json(receipt_path)
        first = next(iter(receipt["inputs"]))
        receipt["inputs"] = {first: receipt["inputs"][first]}
        self.fixture._write_json(receipt_path, receipt)
        for oid in ("V1", "V2"):
            self.fixture._set_evidence(oid, receipt_path, "component-receipt")
        self.assert_invalid("pinned map key inventory changed")

    def test_trimmed_generated_file_set_cannot_be_blessed_by_repin(self):
        self.fixture.make_supported("hkdf-production-functional")
        generated_path = "formal/dafny/hkdf/GENERATED.json"
        generated = self.fixture._load_json(generated_path)
        removed = next(iter(generated["source"]))
        del generated["source"][removed]
        self.fixture._write_json(generated_path, generated)
        generated_root = "quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf"
        (self.root / generated_root / removed).unlink()
        delivery_key = "io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/" + removed
        new_generated_hash = sha((self.root / generated_path).read_bytes())
        for inputs_path in ("formal/dafny/inputs.json", "formal/dafny/PRODUCTION-EVIDENCE.json"):
            inputs = self.fixture._load_json(inputs_path)
            inputs["inputs"][generated_path] = new_generated_hash
            inputs["inputs"].pop(generated_root + "/" + removed, None)
            if inputs_path.endswith("PRODUCTION-EVIDENCE.json"):
                inputs.get("delivered_generated_java", {}).pop(removed, None)
                inputs.get("generated_java", {}).pop(delivery_key, None)
            self.fixture._write_json(inputs_path, inputs)
            for oid in ("V1", "V2"):
                kind = "component-receipt" if inputs_path.endswith("PRODUCTION-EVIDENCE.json") else "input-manifest"
                self.fixture._set_evidence(oid, inputs_path, kind)
        delivery = self.fixture._load_json("formal/crypto/delivery.json")
        delivery.get("existing_generated_sources", {}).pop(delivery_key, None)
        self.fixture._write_json("formal/crypto/delivery.json", delivery)
        for oid in ("V1", "V2"):
            self.fixture._set_evidence(oid, generated_path, "delivery-receipt")
            self.fixture._set_evidence(oid, "formal/crypto/delivery.json", "delivery-receipt")
        self.assert_invalid("pinned map key inventory changed|generated file inventory no longer matches")

    def test_trimmed_stage_source_map_cannot_be_blessed_by_repin(self):
        self.fixture.make_production_supported()
        stage_path = "formal/crypto/adoption/stage-receipt.json"
        stage = self.fixture._load_json(stage_path)
        first = next(iter(stage["sources"]))
        stage["sources"] = {first: stage["sources"][first]}
        self.fixture._write_json(stage_path, stage)
        for oid in ("V4", "V5", "V6"):
            self.fixture._set_evidence(oid, stage_path, "delivery-receipt")
        self.assert_invalid("pinned map key inventory changed")

    def test_trimmed_delivered_inventory_cannot_be_blessed_by_repin(self):
        self.fixture.make_production_supported()
        stage_path = "formal/crypto/adoption/stage-receipt.json"
        stage = self.fixture._load_json(stage_path)
        first = next(iter(stage["delivered_sources"]))
        stage["delivered_sources"] = {first: stage["delivered_sources"][first]}
        self.fixture._write_json(stage_path, stage)
        for oid in ("V4", "V5", "V6"):
            self.fixture._set_evidence(oid, stage_path, "delivery-receipt")
        self.assert_invalid("delivered generated inventory no longer matches|generated file inventory changed")

    def test_trimmed_hkdf_control_inventory_fails(self):
        self.fixture.make_supported("hkdf-production-functional")
        receipt_path = "formal/dafny/PRODUCTION-EVIDENCE.json"
        receipt = self.fixture._load_json(receipt_path)
        removed = next(iter(receipt["controls"]))
        del receipt["controls"][removed]
        self.fixture._write_json(receipt_path, receipt)
        for oid in ("V1", "V2"):
            self.fixture._set_evidence(oid, receipt_path, "component-receipt")
        self.assert_invalid("required receipt value changed|controls")

    def test_removed_hkdf_java_runs_fails(self):
        self.fixture.make_supported("hkdf-production-functional")
        receipt_path = "formal/dafny/PRODUCTION-EVIDENCE.json"
        receipt = self.fixture._load_json(receipt_path)
        receipt.pop("java_runs", None)
        self.fixture._write_json(receipt_path, receipt)
        for oid in ("V1", "V2"):
            self.fixture._set_evidence(oid, receipt_path, "component-receipt")
        self.assert_invalid("required receipt value changed|java_runs")

    def test_v3_proof_label_requires_its_contract(self):
        self.fixture.install_required_component("V3")
        self.fixture.obligation("V3")["status"] = "implementation-proof"
        del self.fixture.obligation("V3")["control_groups"]
        self.assert_invalid("required control group removed|required evidence")

    def test_v0_proof_label_cannot_reuse_unrelated_saw_nonvacuity(self):
        self.fixture.install_required_component("V0")
        self.fixture.obligation("V0")["status"] = "implementation-proof"
        self.fixture.obligation("V0")["nonvacuity"] = {
            "name": "unrelated-saw",
            "path": "formal/saw/evidence/proof.log",
            "markers": ["a = 1", "Proof succeeded"],
        }
        self.assert_invalid("nonvacuity path/markers changed|required-evidence")

    def test_hkdf_local_functional_and_production_policies_pass(self):
        for claim_id in ("hkdf-isolated-functional", "hkdf-production-functional"):
            with self.subTest(claim=claim_id), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                fixture.make_supported(claim_id)
                status = obligations.validate_ledger(fixture.root, fixture.write_ledger())
                self.assertEqual(status["claims"][claim_id], "supported")

    def test_target_receipt_cannot_support_full_aws_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            target = {
                "status": "complete", "scope": "target",
                "full_dependency_graph_verified": False, "schema": "replay/v1",
            }
            fixture.write("formal/reference/aws-hkdf/CLOSURE-RECEIPT.json", json.dumps(target))
            fixture.write("formal/reference/aws-hkdf/inputs.json", "{}\n")
            fixture.write("formal/reference/aws-hkdf/README.md", "target only\n")
            fixture.add_evidence("V1", "formal/reference/aws-hkdf/CLOSURE-RECEIPT.json", "upstream-closure-receipt")
            fixture.add_evidence("V1", "formal/reference/aws-hkdf/inputs.json", "input-manifest")
            fixture.add_evidence("V1", "formal/reference/aws-hkdf/README.md", "documentation")
            fixture.make_supported("aws-full-upstream-hkdf-replay")
            fixture.write_ledger()
            with self.assertRaisesRegex(obligations.LedgerError, "no reviewed semantic evidence validator"):
                obligations.validate_ledger(fixture.root, fixture.path)

    def test_component_class_probe_cannot_support_full_jar_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            probe = {
                "schema": "microproxy.component-class-probe/v1",
                "scope": "12-class-component", "status": "complete",
                "full_jar_verified": False,
            }
            fixture.write("probe.json", json.dumps(probe))
            fixture.add_evidence("V6", "probe.json", "current-jar-receipt")
            fixture.make_supported("current-release-jar-identity")
            fixture.write_ledger()
            with self.assertRaisesRegex(obligations.LedgerError, "no reviewed semantic evidence validator"):
                obligations.validate_ledger(fixture.root, fixture.path)

    def test_stale_hkdf_input_is_not_hidden_by_repinned_evidence(self):
        self.fixture.make_supported("hkdf-production-functional")
        source_path = "formal/dafny/hkdf/Hkdf.dfy"
        inputs_path = "formal/dafny/inputs.json"
        inputs = self.fixture._load_json(inputs_path)
        inputs["inputs"][source_path] = sha((self.root / source_path).read_bytes())
        self.fixture._write_json(inputs_path, inputs)
        for oid in ("V1", "V2"):
            self.fixture._set_evidence(oid, inputs_path, "input-manifest")
        (self.root / source_path).write_text("changed local HKDF kernel after receipt\n", encoding="utf-8")
        for oid in ("V1", "V2"):
            self.fixture._set_evidence(oid, source_path, "spec-source")
        self.assert_invalid("stale source/evidence hash")

    def test_new_hkdf_generated_file_fails_exact_inventory(self):
        self.fixture.make_supported("hkdf-production-functional")
        self.fixture.write(
            "quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/Extra.java",
            "unexpected generated file\n")
        self.assert_invalid("generated file set changed")

    def test_dropped_hkdf_provider_binding_fails(self):
        self.fixture.make_supported("hkdf-production-functional")
        delivery_path = "formal/crypto/delivery.json"
        delivery = self.fixture._load_json(delivery_path)
        delivery["existing_generated_dependencies"] = {}
        self.fixture._write_json(delivery_path, delivery)
        self.fixture._set_evidence("V2", delivery_path, "delivery-receipt")
        self.assert_invalid("hash map must be a nonempty object|required receipt value|existing_generated_dependencies")

    def test_inventory_prefix_narrowing_fails(self):
        self.fixture.make_production_supported()
        inventory = self.fixture.obligation("V6")["inventory_checks"][0]
        inventory["managed_prefixes"] = ["io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeField/"]
        self.assert_invalid("generated-file inventory removed or narrowed|missing evidence path")

    def test_hash_map_exclude_filter_expansion_fails(self):
        self.fixture.make_supported("v8-nontiming-release-gate")
        assurance = next(entry for entry in self.fixture.obligation("V0")["hash_maps"]
                         if entry["receipt"] == "formal/assurance.json")
        assurance["exclude_paths"] = ["quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java"]
        self.assert_invalid("required pinned source/tool map|filters loosened")

    def test_packet_trace_and_non_timing_gate_supported_policies_pass(self):
        for claim_id in ("packet-receive-trace-scoped", "v8-nontiming-release-gate"):
            with self.subTest(claim=claim_id), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                fixture.make_supported(claim_id)
                status = obligations.validate_ledger(fixture.root, fixture.write_ledger())
                self.assertEqual(status["claims"][claim_id], "supported")

    def test_non_timing_gate_rejects_implementation_label_for_python_v0(self):
        self.fixture.make_supported("v8-nontiming-release-gate")
        self.fixture.obligation("V0")["status"] = "implementation-proof"
        self.assert_invalid("obligation V0 status implementation-proof cannot support this claim")

    def test_all_complete_derives_missing_required_claims(self):
        self.fixture.make_supported("shake-mlkem-functional-production")
        self.fixture.make_supported("v8-nontiming-release-gate")
        for oid in ("V0", "V1", "V2", "V3", "V7"):
            self.fixture.install_required_component(oid)
        for oid in ("V0", "V1", "V2", "V3", "V7"):
            self.fixture._refresh_required_file_sets(oid)
            self.fixture._refresh_required_hash_maps(oid)
            self.fixture._refresh_required_inventories(oid)
            self.fixture._refresh_receipt_checks(oid)
        for oid in obligations.REQUIRED_COMPONENT_CHECKS:
            self.fixture._refresh_receipt_checks(oid)
            for path, kind in obligations.REQUIRED_COMPONENT_EVIDENCE[oid]:
                self.fixture._set_evidence(oid, path, kind)
        for oid in ("V1", "V2", "V3", "V7"):
            self.fixture.obligation(oid)["status"] = "implementation-proof"
        claim = self.fixture.claim("all-v0-v8-complete")
        policy = obligations.CLAIM_POLICIES[claim["id"]]
        claim.update({
            "status": "supported",
            "strength": policy["strength"],
            "production": policy["production"],
            "obligations": list(policy["obligations"]),
            "assumptions": sorted(policy["assumptions"]),
            "evidence": [path for path, _ in policy["required_evidence"]],
            "limitations": ["derived completion"],
        })
        self.assert_invalid("no reviewed semantic evidence validator|required claims are not supported|obligations are not complete|V7 cannot be promoted")

    def test_repinned_source_with_old_receipt_still_fails(self):
        self.fixture.make_production_supported()
        stage_path = "formal/crypto/adoption/stage-receipt.json"
        source_path = "formal/crypto/Shake.dfy"
        old_hash = sha((self.root / source_path).read_bytes())
        stage = self.fixture._load_json(stage_path)
        stage.setdefault("sources", {})[source_path] = old_hash
        self.fixture._write_json(stage_path, stage)
        for oid in ("V4", "V5", "V6"):
            self.fixture._set_evidence(oid, stage_path, "delivery-receipt")
        (self.root / source_path).write_text("changed source after receipt\n", encoding="utf-8")
        ref = next(ref for ref in self.fixture.obligation("V4")["evidence"]
                   if ref["path"] == source_path)
        ref["sha256"] = sha((self.root / source_path).read_bytes())
        self.assert_invalid("stale source/evidence hash")

    def test_claim_evidence_must_be_declared_by_its_obligations(self):
        self.fixture.claim("shake-mlkem-functional-production")["evidence"] = ["evidence/V0.txt"]
        self.assert_invalid("not declared by its obligations")

    def test_generated_inventory_rejects_changed_missing_and_added_files(self):
        self.fixture.add_inventory_fixture()
        self.validate()
        (self.root / "src/main/java/io/x/A.java").write_text("changed\n", encoding="utf-8")
        self.assert_invalid("delivered generated source changed")
        (self.root / "src/main/java/io/x/A.java").write_text("a\n", encoding="utf-8")
        (self.root / "src/main/java/io/x/C.java").write_text("c\n", encoding="utf-8")
        self.assert_invalid("generated file inventory changed")
        (self.root / "src/main/java/io/x/C.java").unlink()
        (self.root / "src/main/java/io/x/B.java").unlink()
        self.assert_invalid("missing evidence path")

    def test_changed_runtime_pin_fails(self):
        self.fixture.add_inventory_fixture()
        delivery = json.loads((self.root / "delivery.json").read_text())
        delivery["runtime"]["sha256"] = "b" * 64
        self.fixture.write("delivery.json", json.dumps(delivery))
        self.fixture.obligation("V6")["evidence"] = [
            ref for ref in self.fixture.obligation("V6")["evidence"] if ref["path"] != "delivery.json"]
        self.fixture.add_evidence("V6", "delivery.json", "delivery-receipt")
        self.assert_invalid("runtime hash is not the reviewed pin")

    def test_changed_tool_source_hash_map_fails(self):
        tools = self.fixture.write("tools/tool.json", "tool bytes\n")
        manifest = self.fixture.write("tools/manifest.json", json.dumps({"pins": {"tools/tool.json": sha(tools.read_bytes())}}))
        self.fixture.add_evidence("V0", "tools/manifest.json", "input-manifest")
        self.fixture.add_evidence("V0", "tools/tool.json", "tool-manifest")
        self.fixture.obligation("V0")["hash_maps"] = [{"receipt": "tools/manifest.json", "path": "pins"}]
        self.validate()
        tools.write_text("changed tool bytes\n", encoding="utf-8")
        self.assert_invalid("stale/tampered evidence hash|stale source/evidence hash")

    def test_cli_failure_is_machine_readable(self):
        self.fixture.path.parent.mkdir(parents=True, exist_ok=True)
        self.fixture.path.write_text("{not-json", encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = obligations.main(["--root", str(self.root), "--ledger", str(self.fixture.path)])
        self.assertEqual(code, 1)
        payload = json.loads(output.getvalue())
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["failures"])


class ReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = Fixture(self.root)
        self.fixture.write_ledger()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_release(self, *args: str) -> tuple[int, dict]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = release.main(["--root", str(self.root), "--ledger", str(self.fixture.path), *args])
        return code, json.loads(output.getvalue())

    def test_normal_release_check_succeeds_with_explicit_deferred_residuals(self):
        code, payload = self.run_release()
        self.assertEqual(code, 0)
        self.assertTrue(payload["ok"])
        self.assertIn("v8-timing-release-evidence", payload["residual_claims"])

    def test_require_supported_claim_succeeds(self):
        self.fixture.make_production_supported()
        self.fixture.write_ledger()
        code, payload = self.run_release("--require", "shake-mlkem-functional-production")
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["claim_failures"], [])

    def test_require_deferred_claim_fails(self):
        code, payload = self.run_release("--require", "hkdf-production-functional")
        self.assertEqual(code, 1)
        self.assertEqual(payload["claim_failures"][0]["status"], "unsupported")

    def test_require_all_does_not_accept_deferred_as_done(self):
        self.fixture.make_production_supported()
        self.fixture.write_ledger()
        code, payload = self.run_release("--require-all")
        self.assertEqual(code, 1)
        failed = {item["claim"] for item in payload["claim_failures"]}
        self.assertIn("hkdf-production-functional", failed)
        self.assertIn("v8-timing-release-evidence", failed)
        self.assertIn("all-v0-v8-complete", failed)

    def test_require_unknown_claim_fails(self):
        code, payload = self.run_release("--require", "not-a-claim")
        self.assertEqual(code, 1)
        self.assertEqual(payload["claim_failures"][0]["reason"], "unknown claim")

    def test_require_broad_security_or_timing_claims_fails(self):
        for claim in ("cryptographic-security-proof", "jvm-constant-time",
                      "whole-proxy-security", "independent-expert-review"):
            with self.subTest(claim=claim):
                code, payload = self.run_release("--require", claim)
                self.assertEqual(code, 1)
                self.assertEqual(payload["claim_failures"][0]["claim"], claim)
                self.assertEqual(payload["claim_failures"][0]["status"], "unsupported")

    def test_ledger_failure_fails_release_gate(self):
        self.fixture.ledger["obligations"].pop()
        self.fixture.write_ledger()
        code, payload = self.run_release()
        self.assertEqual(code, 1)
        self.assertFalse(payload["ok"])


if __name__ == "__main__":
    unittest.main()
