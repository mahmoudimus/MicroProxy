"""Independent fail-closed fixtures for the crypto obligation and release gates.

These tests do not consume the repository's current HKDF pins or receipts; they
construct a synthetic ledger so in-progress HKDF work cannot make the gate tests
stale. The repository ledger itself is exercised separately by the documented
commands.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

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
    "packet-nonce-functional-production": "V3",
    "poly-source-trace-ni": "V5",
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
        expected = obligations.REQUIRED_HASH_MAP_KEYS.get(
            (oid, receipt_path, map_path, tuple(includes), path_prefix))
        if expected is None:
            raise AssertionError(
                f"missing expected hash-map keys for {oid}:{receipt_path}:{map_path}:{includes}:{path_prefix}")
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
        existing = receipt.get(map_path)
        if not isinstance(existing, dict):
            existing = {}
        # A single manifest map can be validated by more than one reviewed
        # signature (V3: live formal entries and historical quic/src entries).
        # Replace only this signature's include scope so the split preserves
        # keys owned by the other signature.
        kept = {key: value for key, value in existing.items()
                if not (includes and any(key.startswith(prefix) for prefix in includes))}
        kept.update(mapping)
        self._nested_set(receipt, map_path, kept)
        # The timing receipt binds the actual manifest bytes as well as its
        # semantic map. Preserve the reviewed fixture's encoding when its data
        # is unchanged; do not repin the report to mask a changed manifest.
        real = self.REAL_ROOT / receipt_path
        if (receipt_path == "formal/timing/inputs.json" and real.is_file()
                and receipt == json.loads(real.read_text())):
            (self.root / receipt_path).write_bytes(real.read_bytes())
        else:
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
        if oid == "V7":
            assumption = "trusted-source-observation-coverage"
            if assumption not in self.obligation(oid)["assumptions"]:
                self.obligation(oid)["assumptions"].append(assumption)

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

    def test_v7_manifest_bytes_must_match_the_executed_binding(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        path = "formal/timing/inputs.json"
        target = self.root / path
        # Same JSON data, different executed-input bytes. Renewing the ledger
        # evidence hash must not erase the replay's manifest binding.
        target.write_bytes(target.read_bytes() + b"\n")
        self.fixture._set_evidence("V7", path, "input-manifest")
        self.assert_invalid("Keccak input-manifest binding changed")

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

    def test_trace_execution_and_callee_controls_survive_snapshot_renewal(self):
        """A future digest renewal cannot bless dead execution or private modulus."""
        import copy
        self.fixture.make_supported("packet-receive-trace-scoped")
        path = "formal/timing/PRODUCTION-EVIDENCE.json"
        original = self.fixture._load_json(path)
        for case in ("wipe-stores", "wipe-role", "dead-extract", "apply-probe",
                     "private-modulus", "timeout-mutant"):
            with self.subTest(case=case):
                report = copy.deepcopy(original)
                callees = {item["method"].split(":")[0]: item
                           for item in report["callee_roots"]}
                if case == "wipe-stores":
                    callees["Wipe"]["witness_execution"]["counts"]["store"] = 0
                elif case == "wipe-role":
                    callees["Wipe"]["witness_execution"]["role_store_counts"] = [0, 4]
                elif case == "dead-extract":
                    callees["Extract"]["witness_execution"]["differing_registers"] = [1]
                elif case == "apply-probe":
                    report["apply_probe"]["rows"] = 0
                elif case == "private-modulus":
                    callees["PublicMod"]["contract"]["params"] = ["sec", "pub"]
                else:
                    callees["Wipe"]["mutants"]["secret-store-index"]["status"] = "timeout"
                self.fixture._write_json(path, report)
                self._repin_trace_report()
                # Simulate a reviewed-code digest renewal while keeping the
                # independent semantic requirements intact.
                renewed = sha((self.fixture.root / path).read_bytes())
                with mock.patch.object(obligations, "REQUIRED_TRACE_REPORT_SHA256", renewed):
                    self.assert_invalid(
                        "trace (Wipe execution|Apply execution|owned-callee|callee mutant)")

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

    def test_trimmed_native_polynomial_input_map_cannot_be_blessed_by_repin(self):
        self.fixture.make_production_supported()
        path = "formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json"
        receipt = self.fixture._load_json(path)
        first = next(iter(receipt["mac_full"]["receipt"]["inputs"]))
        receipt["mac_full"]["receipt"]["inputs"] = {
            first: receipt["mac_full"]["receipt"]["inputs"][first]}
        self.fixture._write_json(path, receipt)
        self.fixture._set_evidence("V5", path, "component-receipt")
        self.assert_invalid("pinned map key inventory changed")

    def test_trimmed_native_codec_input_map_cannot_be_blessed_by_repin(self):
        self.fixture.make_production_supported()
        path = "formal/crypto/NATIVE-CODEC-EVIDENCE.json"
        receipt = self.fixture._load_json(path)
        first = next(iter(receipt["inputs"]))
        receipt["inputs"] = {first: receipt["inputs"][first]}
        self.fixture._write_json(path, receipt)
        self.fixture._set_evidence("V5", path, "component-receipt")
        self.assert_invalid("pinned map key inventory changed")

    def test_native_codec_proofs_cannot_be_relabelled_as_older_reuse(self):
        # The wrapper's fresh top-level proofs are the reviewed contract; a
        # receipt that keeps only the historical reused_evidence map and pins a
        # smaller proof count there must not be accepted as current evidence.
        self.fixture.make_production_supported()
        path = "formal/crypto/NATIVE-CODEC-EVIDENCE.json"
        receipt = self.fixture._load_json(path)
        receipt["reused_evidence"] = {"proofs": {
            "proof-NativeField": 86, "proof-NativeCodec": 1503,
            "proof-NativeSampling": 281, "native_codec_domain": 8,
            "native_sampling_domain": 4}}
        receipt["proofs"] = {"proof-NativeField": 84, "proof-NativeCodec": 1493,
                             "proof-NativeSampling": 281,
                             "native_codec_domain": 8, "native_sampling_domain": 4}
        self.fixture._write_json(path, receipt)
        self._set_receipt_expected("V5", path, {
            "proofs.proof-NativeField": 84, "proofs.proof-NativeCodec": 1493})
        self.fixture._set_evidence("V5", path, "component-receipt")
        self.assert_invalid("required receipt value changed")

    def test_native_codec_control_cannot_be_removed_after_repinning(self):
        self.fixture.make_production_supported()
        path = "formal/crypto/NATIVE-CODEC-EVIDENCE.json"
        receipt = self.fixture._load_json(path)
        del receipt["controls"]["cbd-sign"]
        self.fixture._write_json(path, receipt)
        self.fixture._set_evidence("V5", path, "component-receipt")
        self.assert_invalid("control inventory changed")

    def test_native_polynomial_linux_control_cannot_be_emptied_after_repinning(self):
        self.fixture.make_production_supported()
        path = "formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json"
        receipt = self.fixture._load_json(path)
        receipt["linux_controls"]["receipt"]["controls"] = {}
        self.fixture._write_json(path, receipt)
        self.fixture._set_evidence("V5", path, "component-receipt")
        self.assert_invalid("control inventory changed")

    def test_pending_linux_kem_cannot_be_promoted_by_metadata(self):
        # A missing fresh source graph must fail even when the wrapper's other
        # scalar fields and hashes are renewed: platform metadata is not evidence.
        self.fixture.make_production_supported()
        path = "formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json"
        receipt = self.fixture._load_json(path)
        del receipt["source_graph"]
        self.fixture._write_json(path, receipt)
        self.fixture._set_evidence("V6", path, "component-receipt")
        self.assert_invalid("missing field 'source_graph'")

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

    def test_hkdf_source_control_cannot_be_removed_after_repinning_expectations(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        path = obligations.HKDF_SOURCE_RECEIPT
        receipt = self.fixture._load_json(path)
        del receipt["controls"]["third-callee-dup"]
        self.fixture._write_json(path, receipt)
        self.fixture._set_evidence("V7", path, "component-receipt")
        self._set_receipt_expected("V7", path, {"controls": receipt["controls"]})
        self.assert_invalid("required receipt value changed|controls")

    def test_hkdf_source_input_map_cannot_be_trimmed_after_repinning(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        path = obligations.HKDF_SOURCE_RECEIPT
        receipt = self.fixture._load_json(path)
        receipt["inputs"].pop("formal/source/hkdf/checker/HkdfCoverage.cs")
        self.fixture._write_json(path, receipt)
        self.fixture._set_evidence("V7", path, "component-receipt")
        self.assert_invalid("pinned map key inventory changed")

    def test_hkdf_source_positives_assembly_and_sdk_cannot_be_self_blessed(self):
        for field, value in (("positive.hkdf_body.verified", 1),
                             ("checker.build.assembly_sha256", "0" * 64),
                             ("checker.build.sdk", "unreviewed"),
                             ("checker.declarations", 1),
                             ("metadata_targets", {})):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as folder:
                fixture = Fixture(Path(folder))
                fixture.make_supported("packet-receive-trace-scoped")
                path = obligations.HKDF_SOURCE_RECEIPT
                receipt = fixture._load_json(path)
                fixture._nested_set(receipt, field, value)
                fixture._write_json(path, receipt)
                fixture._set_evidence("V7", path, "component-receipt")
                for check in fixture.obligation("V7")["receipt_checks"]:
                    if check["receipt"] == path:
                        for checked in list(check["values"]):
                            check["values"][checked] = fixture._nested_get(receipt, checked)
                with self.assertRaisesRegex(obligations.LedgerError, "required receipt value changed"):
                    obligations.validate_ledger(fixture.root, fixture.write_ledger())

    def test_hkdf_source_trust_assumption_cannot_move_out_of_its_obligation(self):
        self.fixture.make_supported("packet-receive-trace-scoped")
        assumption = "trusted-source-observation-coverage"
        self.fixture.obligation("V7")["assumptions"].remove(assumption)
        if assumption not in self.fixture.obligation("V8")["assumptions"]:
            self.fixture.obligation("V8")["assumptions"].append(assumption)
        self.assert_invalid("required HKDF source-coverage trust assumption removed")

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

    def test_packet_nonce_functional_production_policy_passes(self):
        self.fixture.make_supported("packet-nonce-functional-production")
        status = self.validate()
        self.assertEqual(status["claims"]["packet-nonce-functional-production"], "supported")
        self.assertNotIn("packet-nonce-functional-production", status["residual_claims"])

    def test_packet_nonce_receipt_controls_and_proof_counts_are_semantically_checked(self):
        self.fixture.make_supported("packet-nonce-functional-production")
        path = "formal/nonce/PRODUCTION-EVIDENCE.json"
        original = self.fixture._load_json(path)
        cases = (
            ("control", lambda r: r["controls"]["wrong-endian"].update({"status": "verified"}),
             "not a semantic proof rejection"),
            ("proof", lambda r: r["proof"]["kernel"].update({"verified": 0}),
             "proof counts changed"),
            ("audit", lambda r: r["proof"]["audits"].update({"kernel": "0 warnings"}),
             "trusted declaration"),
            ("historical", lambda r: r["bridge"].update({"sha256": "f" * 64}),
             "PacketKey source identity changed"),
        )
        for name, mutate, pattern in cases:
            receipt = json.loads(json.dumps(original))
            mutate(receipt)
            self.fixture._write_json(path, receipt)
            self.fixture._set_evidence("V3", path, "component-receipt")
            with self.subTest(case=name):
                self.assert_invalid(pattern)
        self.fixture._write_json(path, original)
        self.fixture._set_evidence("V3", path, "component-receipt")

    def test_packet_nonce_immutable_core_rejects_medium_domain_narrowing_repro(self):
        self.fixture.make_supported("packet-nonce-functional-production")
        kernel = "formal/nonce/Nonce.dfy"
        text = (self.root / kernel).read_text(encoding="utf-8")
        narrowed = text.replace("    requires iv.Length == 12",
                                "    requires (pn >> 62) == 0\n    requires iv.Length == 12", 1)
        self.assertNotEqual(text, narrowed)
        (self.root / kernel).write_text(narrowed, encoding="utf-8")
        generated_before = sha((self.root / (
            "quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/"
            "VerifiedNonce/__default.java")).read_bytes())
        self._renew_nonce_component_for(self.fixture, [kernel])
        self.assertEqual(generated_before, sha((self.root / (
            "quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/"
            "VerifiedNonce/__default.java")).read_bytes()))
        self.assert_invalid("reviewed core source changed")

    def test_each_nonce_core_pin_rollback_is_rejected_after_json_renewal(self):
        pins = obligations.PACKET_NONCE_CORE_PINS
        for path in pins:
            if path == "formal/nonce/inputs.json":
                continue  # covered by the exact input-map test below
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                fixture.make_supported("packet-nonce-functional-production")
                original = (fixture.root / path).read_bytes()
                (fixture.root / path).write_text(
                    original.decode("utf-8", "replace") + "\n// renewed core pin\n",
                    encoding="utf-8")
                # Reuse the helper through a scoped Fixture instance.
                ObligationLedgerTests._renew_nonce_component_for(fixture, [path])
                with self.assertRaisesRegex(obligations.LedgerError,
                                            "reviewed core source changed|exact 13-file core input map changed"):
                    obligations.validate_ledger(fixture.root, fixture.write_ledger())

    @staticmethod
    def _renew_nonce_component_for(fixture, changed):
        receipt_path = "formal/nonce/PRODUCTION-EVIDENCE.json"
        receipt = fixture._load_json(receipt_path)
        roles = {
            "formal/nonce/Nonce.dfy": "kernel_source",
            "formal/nonce/NonceDomain.dfy": "domain_source",
            "formal/nonce/run.py": "runner",
            "formal/nonce/test_run.py": "test_runner",
            "formal/nonce/tools.json": "tools",
            "formal/nonce/inputs.json": "input_manifest",
            "formal/nonce/GENERATED.json": "generated_receipt",
        }
        kinds = {
            "formal/nonce/Nonce.dfy": "spec-source",
            "formal/nonce/NonceDomain.dfy": "spec-source",
            "formal/nonce/run.py": "tool-manifest",
            "formal/nonce/test_run.py": "test-source",
            "formal/nonce/tools.json": "tool-manifest",
            "formal/nonce/inputs.json": "input-manifest",
            "formal/nonce/GENERATED.json": "generated-source",
        }
        for path in changed:
            receipt["component"][roles[path]]["sha256"] = sha(
                (fixture.root / path).read_bytes())
            fixture._set_evidence("V3", path, kinds[path])
        inputs = fixture._load_json("formal/nonce/inputs.json")
        for path in changed:
            if path in inputs["inputs"]:
                inputs["inputs"][path] = sha((fixture.root / path).read_bytes())
        fixture._write_json("formal/nonce/inputs.json", inputs)
        receipt["component"]["input_manifest"]["sha256"] = sha(
            (fixture.root / "formal/nonce/inputs.json").read_bytes())
        receipt["proof"]["source_sha256"] = {
            "before": sha((fixture.root / "formal/nonce/Nonce.dfy").read_bytes()),
            "after": sha((fixture.root / "formal/nonce/Nonce.dfy").read_bytes()),
        }
        fixture._write_json(receipt_path, receipt)
        fixture._set_evidence("V3", receipt_path, "component-receipt")
        fixture._set_evidence("V3", "formal/nonce/inputs.json", "input-manifest")
        fixture._set_evidence("V3", "formal/nonce/GENERATED.json", "generated-source")

    def test_packet_nonce_core_input_map_rejects_value_renewal(self):
        self.fixture.make_supported("packet-nonce-functional-production")
        inputs_path = "formal/nonce/inputs.json"
        inputs = self.fixture._load_json(inputs_path)
        bench = "formal/nonce/bench/NonceBenchmark.java"
        inputs["inputs"][bench] = "a" * 64
        self.fixture._write_json(inputs_path, inputs)
        receipt_path = "formal/nonce/PRODUCTION-EVIDENCE.json"
        receipt = self.fixture._load_json(receipt_path)
        receipt["component"]["input_manifest"]["sha256"] = sha(
            (self.root / inputs_path).read_bytes())
        self.fixture._write_json(receipt_path, receipt)
        self.fixture._set_evidence("V3", inputs_path, "input-manifest")
        self.fixture._set_evidence("V3", receipt_path, "component-receipt")
        self.assert_invalid("reviewed core source changed|exact 13-file core input map changed")

    def test_packet_nonce_generation_identity_fields_are_immutable(self):
        self.fixture.make_supported("packet-nonce-functional-production")
        receipt_path = "formal/nonce/PRODUCTION-EVIDENCE.json"
        original = self.fixture._load_json(receipt_path)
        cases = (
            ("generated_class_key", "io/x/Other.class", "generated class key changed"),
            ("generated_class_sha256", "b" * 64, "generated class hash is not the reviewed output"),
            ("translation_metadata_sha256", "c" * 64, "translation metadata is not the accepted output"),
            ("external_replay_report_sha256", "d" * 64, "external report is not the accepted component replay"),
        )
        for field, value, pattern in cases:
            with self.subTest(field=field):
                receipt = json.loads(json.dumps(original))
                receipt["generation"][field] = value
                self.fixture._write_json(receipt_path, receipt)
                self.fixture._set_evidence("V3", receipt_path, "component-receipt")
                self.assert_invalid(pattern)
        self.fixture._write_json(receipt_path, original)
        self.fixture._set_evidence("V3", receipt_path, "component-receipt")

    def test_packet_nonce_hand_edited_generated_source_is_rejected(self):
        self.fixture.make_supported("packet-nonce-functional-production")
        generated = ("quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/"
                     "VerifiedNonce/__default.java")
        (self.root / generated).write_text("// hand-edited generated nonce\n", encoding="utf-8")
        self.fixture._set_evidence("V3", generated, "generated-source")
        self.assert_invalid("checked-in generated Java changed|reviewed input changed")

    def test_legacy_saw_map_cannot_be_rebound_to_current_packetkey(self):
        self.fixture.make_supported("packet-nonce-functional-production")
        inputs_path = "formal/saw/inputs.json"
        inputs = self.fixture._load_json(inputs_path)
        packetkey = "quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java"
        inputs["inputs"][packetkey] = sha((self.root / packetkey).read_bytes())
        self.fixture._write_json(inputs_path, inputs)
        self.fixture._set_evidence("V3", inputs_path, "input-manifest")
        self.assert_invalid("stale source/evidence hash")

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


class PromotedTraceControlTests(unittest.TestCase):
    """Falsify control facts even after an accepted snapshot digest is renewed.

    Call the semantic validators directly: a hash mismatch cannot mask a missing
    control. The baseline is the reviewed trace receipt, not a fresh HKDF run.
    """

    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        self.report = json.loads((root / "formal/timing/PRODUCTION-EVIDENCE.json").read_text())

    def validate(self):
        obligations._validate_trace_composition(self.report, "V7:trace-report")
        obligations._validate_trace_promoted_controls(self.report, "V7:trace-report")
        obligations._validate_trace_boundaries(self.report, "V7:trace-report")

    def field(self, name="Add"):
        return next(item for item in self.report["callee_roots"]
                    if item["class"].endswith("NativeField.__default")
                    and item["method"].startswith(name + ":"))

    def helper(self, name):
        return next(item for item in self.report["roots"]
                    if item["class"].endswith("HkdfBridge")
                    and item["method"].startswith(name + ":"))

    def test_reviewed_promoted_controls_are_accepted(self):
        self.validate()

    def test_private_requirement_cannot_become_not_applicable(self):
        self.field()["execution_control"]["status"] = "not-applicable: no private parameters or private parameter roles"
        with self.assertRaisesRegex(obligations.LedgerError, "private execution control"):
            self.validate()

    def test_return_liveness_cannot_be_replaced_with_parameter_liveness(self):
        control = self.field()["execution_control"]
        control["differing_registers"] = list(control["parameter_registers"])
        control["non_parameter_differing"] = []
        control["return_differs"] = False
        with self.assertRaisesRegex(obligations.LedgerError, "return liveness"):
            self.validate()

    def test_private_requirement_and_return_register_are_independent(self):
        control = self.field()["execution_control"]
        control["require_liveness"] = False
        control["return_register"] = control["parameter_registers"][0]
        with self.assertRaisesRegex(obligations.LedgerError, "private execution control"):
            self.validate()

    def test_non_parameter_initial_values_cannot_fake_flow(self):
        self.field()["execution_control"]["state_invariants"]["non_parameter_private_start_at_zero"] = False
        with self.assertRaisesRegex(obligations.LedgerError, "private execution control"):
            self.validate()

    def test_equal_input_pair_is_not_private_evidence(self):
        self.field()["execution_control"]["seeds"]["T"] = [11, 3]
        with self.assertRaisesRegex(obligations.LedgerError, "private execution control"):
            self.validate()

    def test_success_flags_cannot_hide_different_observation_tapes(self):
        self.field()["execution_control"]["events"]["t"].append(["guard", 0, True])
        with self.assertRaisesRegex(obligations.LedgerError, "observation tapes"):
            self.validate()

    def test_private_shift_admission_remains_an_enforced_audit_gate(self):
        self.field()["execution_control"]["shift_count_rule"]["shift_calls"][0]["count_taint"] = "sec"
        with self.assertRaisesRegex(obligations.LedgerError, "private execution control"):
            self.validate()

    def test_fully_expanded_body_cannot_reintroduce_owned_call(self):
        self.field()["call_targets"]["io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeField/__default.Q:()I"] = 99
        with self.assertRaisesRegex(obligations.LedgerError, "identity/contract"):
            self.validate()

    def test_field_source_and_compiled_identity_cannot_be_relabelled(self):
        self.field()["source_rebuild_sha256"]["class_sha256"] = "0" * 64
        with self.assertRaisesRegex(obligations.LedgerError, "identity/contract"):
            self.validate()

    def test_timeout_is_not_a_genuine_field_proof_mutant(self):
        self.field()["mutants"]["public-result-from-secret-arg"]["status"] = "timeout"
        with self.assertRaisesRegex(obligations.LedgerError, "proof-mutant"):
            self.validate()

    def test_sequence_pair_cannot_claim_copy_or_private_output_refinement(self):
        self.helper("sequence")["execution_control"]["return_differs"] = True
        with self.assertRaisesRegex(obligations.LedgerError, "must not claim"):
            self.validate()

    def test_sequence_requires_the_actual_private_input_role(self):
        self.helper("sequence")["execution_control"]["secret_parameter_roles"] = ["unrelated"]
        with self.assertRaisesRegex(obligations.LedgerError, "private execution control"):
            self.validate()

    def test_public_label_controls_cannot_skip_an_executed_length(self):
        self.helper("labelUnits")["execution_control"]["lengths"]["runs"][-1]["stores"] = 0
        with self.assertRaisesRegex(obligations.LedgerError, "executed length"):
            self.validate()

    def test_duplicated_control_summary_must_match_the_checked_body(self):
        row = self.report["promoted_controls"]["records"][0]
        row["control"]["status"] = "FAILED"
        with self.assertRaisesRegex(obligations.LedgerError, "not bound"):
            self.validate()

    def test_new_helpers_do_not_authorize_larger_solver_budgets(self):
        self.field()["solver_limits"]["time"] = 120
        with self.assertRaisesRegex(obligations.LedgerError, "identity/contract"):
            self.validate()

    def test_private_root_cannot_disable_its_declared_control_requirement(self):
        self.field()["execution_control_required"] = False
        with self.assertRaisesRegex(obligations.LedgerError, "identity/contract"):
            self.validate()

    def test_summary_cannot_disable_the_private_input_requirement(self):
        self.report["promoted_controls"]["records"][0]["require_applicable"] = False
        with self.assertRaisesRegex(obligations.LedgerError, "not bound"):
            self.validate()

    def test_receipt_cannot_hide_its_trusted_code(self):
        self.report["trusted"] = []
        with self.assertRaisesRegex(obligations.LedgerError, "trust/scope boundary"):
            self.validate()

    def test_receipt_cannot_hide_the_interpreter_scope(self):
        self.report["execution_controls"]["scope"] = ""
        with self.assertRaisesRegex(obligations.LedgerError, "trust/scope boundary"):
            self.validate()

    def test_receipt_cannot_relabel_partial_composition_as_complete(self):
        self.report["composition_not_a_closure"] = "All owned calls are proved."
        with self.assertRaisesRegex(obligations.LedgerError, "trust/scope boundary"):
            self.validate()

    def test_finite_controls_must_keep_their_value_refinement_limit(self):
        self.report["promoted_controls"]["note"] = ""
        with self.assertRaisesRegex(obligations.LedgerError, "trust/scope boundary"):
            self.validate()


class KeccakTraceGateTests(unittest.TestCase):
    """Reject changed Keccak claims independently of the snapshot digest."""

    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        self.report = json.loads((root / "formal/timing/PRODUCTION-EVIDENCE.json").read_text())
        self.component = self.report["keccak_traces"]

    def validate(self):
        return obligations._validate_trace_keccak(self.report, "V7:trace-report")

    def reject(self, pattern="Keccak"):
        with self.assertRaisesRegex(obligations.LedgerError, pattern):
            self.validate()

    def test_reviewed_keccak_evidence_is_accepted(self):
        self.assertGreater(self.validate(), 0)

    def test_keccak_component_cannot_be_omitted(self):
        self.report.pop("keccak_traces")
        self.reject("Keccak component")

    def test_root_inventory_cannot_shrink(self):
        self.component["roots"].pop("Theta")
        self.reject("Keccak root inventory")

    def test_positive_proof_cannot_be_partial(self):
        self.component["roots"]["PermuteScratch"]["proof"]["verified"] = 1
        self.reject("Keccak .*proof")

    def test_solver_budget_cannot_be_silently_increased(self):
        cmd = self.component["roots"]["Rotate"]["proof"]["command"]
        cmd[cmd.index("--resource-limit") + 1] = "200000000"
        self.reject("Keccak .*budget")

    def test_public_call_model_cannot_be_dropped(self):
        self.component["model_proofs"].pop("PublicProviderPublic", None)
        self.reject("Keccak model inventory")

    def test_word_arithmetic_requires_its_reviewed_proof_count(self):
        self.component["model_proofs"]["WordArithmetic"]["verified"] = 1
        self.reject("Keccak .*proof")

    def test_unknown_remaining_provider_is_rejected(self):
        self.component["roots"]["Rotate"]["remaining_calls"]["owned/Secret.run:()J"] = 1
        self.reject("Keccak .*provider")

    def test_native_class_binding_cannot_drift(self):
        self.component["binding"]["native"]["class_sha256"] = "0" * 64
        self.reject("Keccak .*class")

    def test_loaded_module_must_match_the_pinned_file(self):
        for side in ("before", "after"):
            self.component["binding"][side]["modules"]["composition"]["sha256"] = "0" * 64
        self.reject("Keccak .*module")

    def test_after_binding_must_equal_before(self):
        self.component["binding"]["after"]["modules"]["trace_exec"]["path"] += ".shadow"
        self.reject("Keccak .*binding")

    def test_fault_is_not_a_completed_execution(self):
        self.component["roots"]["PermuteScratch"]["control"]["terminal"]["s"] = "fault"
        self.reject("Keccak .*execution")

    def test_all_rounds_must_execute(self):
        self.component["roots"]["PermuteScratch"]["control"]["rounds_executed"] = 23
        self.reject("Keccak .*round")

    def test_public_heap_equality_cannot_be_omitted(self):
        ctl = self.component["roots"]["PermuteScratch"]["control"]
        ctl["public_heap_equal"] = False
        ctl["checks"]["public_heap_equal"] = False
        self.reject("Keccak .*execution")

    def test_heap_shape_cannot_be_enlarged_to_hide_a_fault(self):
        ctl = self.component["roots"]["PermuteScratch"]["control"]
        role = next(iter(ctl["heap_shape"]))
        ctl["heap_shape"][role] = [125, 125]
        self.reject("Keccak .*shape")

    def test_private_count_requires_the_named_branch_obligation(self):
        self.component["private_count"]["left"]["proof"].pop("anchor", None)
        self.reject("Keccak .*private-count anchor")

    def test_unrelated_error_cannot_replace_private_count_failure(self):
        proof = self.component["private_count"]["right"]["proof"]
        proof["anchor_status"] = "unrelated-false-lemma"
        self.reject("Keccak .*private-count anchor")

    def test_partial_control_cannot_be_promoted(self):
        self.component["noncompletion_controls"]["fuel"]["accepted_as_complete"] = True
        self.reject("Keccak .*noncompletion")

    def test_trust_and_scope_disclosures_cannot_be_removed(self):
        self.component["scope"]["not_claimed"] = []
        self.reject("Keccak scope")

    def test_compiled_oracle_comparison_cannot_be_skipped(self):
        self.component["oracle_kats"]["cases"] = 0
        self.reject("Keccak .*oracle")

    def test_declared_and_actual_admission_must_match(self):
        self.component["admission"]["actual"] = []
        self.reject("Keccak .*admission")

    def test_public_only_contract_is_required_for_each_root(self):
        self.component["roots"]["Theta"]["public_contract"]["public_only_postcondition"] = ""
        self.reject("Keccak .*public-call contract")

    def test_shape_hash_cannot_substitute_for_actual_body_identity(self):
        entry = self.component["roots"]["Rotate"]["inlined"][0]
        entry["callee_bytecode_sha256"] = entry["callee_shape_sha256"]
        self.reject("Keccak .*callee body identity")

    def test_body_binding_must_still_match_after_composition(self):
        self.component["inlined_body_binding_after"] = {}
        self.reject("Keccak .*callee body binding")

    def test_public_call_mutants_cannot_be_omitted(self):
        self.component["public_call_mutants"] = {}
        self.reject("Keccak public-call mutant inventory")

    def test_public_only_failure_cannot_be_an_unrelated_structure_error(self):
        self.component["public_call_mutants"]["private_argument"]["proof"]["contains_structure_error"] = True
        self.reject("Keccak .*public-call mutant anchor")

    def test_helper_class_pin_cannot_be_dead_metadata(self):
        self.component["helper_entry_pin"]["declared_helpers_entry_sha256"] = "0" * 64
        self.reject("Keccak .*runtime class pin")

    def test_known_provider_arity_is_part_of_the_contract(self):
        contract = self.component["roots"]["PermuteScratch"]["public_contract"]
        contract["known_public_arity"] = {}
        self.reject("Keccak .*public-call contract")

    def test_wrong_arity_requires_its_own_public_only_failure(self):
        self.component["public_call_mutants"].pop("wrong_arity")
        self.reject("Keccak public-call mutant inventory")

    def test_mutant_summary_must_match_derived_proof_facts(self):
        self.component["public_call_mutants"]["private_argument"]["proof_status"] = "verified"
        self.reject("Keccak .*derived metadata")

    def _rewrite_inline(self, root_name, transform):
        entry = self.component["roots"][root_name]["inlined"][0]
        old_target = entry["target"]
        transform(entry["callee_body"])
        body = entry["callee_body"]
        entry["target"] = f"{body['owner']}.{body['name']}:{body['descriptor']}"
        entry["callee_bytecode_sha256"] = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        after = self.component["inlined_body_binding_after"]
        after.pop(old_target, None)
        after[entry["target"]] = {
            key: entry[key] for key in ("callee_bytecode_sha256", "callee_class_sha256")}

    def test_fake_callee_with_renewed_self_hash_is_rejected(self):
        self._rewrite_inline("Iota", lambda b: b.update(bytecode=["not-real-bytecode"]))
        self.reject("Keccak .*callee body identity")

    def test_fabricated_callee_with_renewed_binding_is_rejected(self):
        self._rewrite_inline("Iota", lambda b: b.update(
            name="Fabricated", descriptor="()V", bytecode=[[0, "return", ""]]))
        self.reject("Keccak .*inline")

    def test_replacing_inline_with_another_real_body_is_rejected(self):
        self.component["roots"]["Iota"]["inlined"][0] = copy.deepcopy(
            self.component["roots"]["Rotate"]["inlined"][0])
        self.reject("Keccak .*inline")

    def test_provider_inventory_cannot_be_emptied_consistently(self):
        row = self.component["roots"]["Chi"]
        row["call_targets"] = row["remaining_calls"] = {}
        for location in (row["public_contract"], row["certificate"]):
            location.update(known_public_ids=[], known_public_targets=[], known_public_arity={})
        self.reject("Keccak .*provider")

    def test_provider_ids_cannot_be_renumbered_consistently(self):
        row = self.component["roots"]["Rotate"]
        row["call_targets"] = {k: v + 100 for k, v in row["call_targets"].items()}
        for location in (row["public_contract"], row["certificate"]):
            location["known_public_ids"] = [101]
            location["known_public_arity"] = {"101": 1}
        self.reject("Keccak .*provider")

    def test_remaining_call_counts_are_exact(self):
        self.component["roots"]["Chi"]["remaining_calls"]["dafny/Helpers.toInt:(I)I"] += 1
        self.reject("Keccak .*provider")

    def test_remaining_call_counts_require_integers(self):
        self.component["roots"]["Rotate"]["remaining_calls"]["java/lang/Integer.signum:(I)I"] = True
        self.reject("Keccak .*provider")

    def test_certificate_provider_ids_must_match_public_contract(self):
        self.component["roots"]["Rotate"]["certificate"]["known_public_ids"] = []
        self.reject("Keccak .*certificate")

    def test_certificate_provider_arity_must_match_public_contract(self):
        self.component["roots"]["Rotate"]["certificate"]["known_public_arity"] = {}
        self.reject("Keccak .*certificate")

    def test_zero_certificate_digest_is_rejected_even_when_self_consistent(self):
        row = self.component["roots"]["Rotate"]
        row["certificate"]["certificate_sha256"] = row["proof"]["source_sha256"] = "0" * 64
        self.reject("Keccak .*certificate")

    def test_zero_proof_log_digest_is_rejected(self):
        self.component["model_proofs"]["WordArithmetic"]["log_sha256"] = "0" * 64
        self.reject("Keccak .*log binding")

    def test_resource_error_cannot_replace_a_named_mutant_failure(self):
        self.component["mutants"]["branch"]["proof"]["obligation"] = "Error: out of resource"
        self.reject("Keccak .*negative obligation")

    def test_parse_error_cannot_replace_private_count_anchor(self):
        anchor = self.component["private_count"]["left"]["proof"]["anchor"]
        anchor["error_message"] = "Error: parse error"
        anchor["diagnostics"][0]["message"] = "Error: parse error"
        self.reject("Keccak .*private-count anchor")

    def test_direct_call_inventory_cannot_be_fabricated(self):
        self.component["roots"]["Rotate"]["direct"]["call_targets"] = {}
        self.reject("Keccak .*direct")

    def test_execution_step_count_cannot_be_fabricated(self):
        self.component["roots"]["Rotate"]["control"]["steps"] = {"s": 0, "t": 0}
        self.reject("Keccak .*execution profile")

    def test_proof_tool_paths_must_match_the_top_level_tool_binding(self):
        self.report["tools"]["binary"] += ".shadow"
        self.reject("Keccak .*tool origin")

    def test_trivial_proof_file_cannot_replace_the_certificate(self):
        self.component["roots"]["Rotate"]["proof"]["command"][2] = "/tmp/unreviewed/Trivial.dfy"
        self.reject("Keccak .*proved certificate")

    def test_certificate_and_oracle_digests_have_independent_pins(self):
        row = self.component["roots"]["Rotate"]
        row["certificate"]["certificate_sha256"] = row["proof"]["source_sha256"] = "a" * 64
        row["certificate"]["oracle_sha256"] = "b" * 64
        self.reject("Keccak .*proof artifact")

    def test_model_proof_must_name_the_bound_model(self):
        self.component["model_proofs"]["PublicProvider"]["command"][2] = "/tmp/Trivial.dfy"
        self.reject("Keccak .*model origin")

    def test_nonzero_proof_log_digest_also_has_an_independent_pin(self):
        self.component["model_proofs"]["WordArithmetic"]["log_sha256"] = "a" * 64
        self.reject("Keccak .*proof artifact")

    def test_fabricated_oracle_function_is_rejected(self):
        self.component["roots"]["Rotate"]["certificate"]["oracle_function"] = "TrivialOracle"
        self.reject("Keccak .*oracle origin")

    def test_equal_fabricated_event_hashes_are_rejected(self):
        self.component["roots"]["Rotate"]["control"]["events_sha256"] = {"s": "a" * 64, "t": "a" * 64}
        self.reject("Keccak .*auxiliary identity")

    def test_inline_site_is_bound_to_the_reviewed_composition(self):
        self.component["roots"]["Rotate"]["inlined"][0]["site"] = "fabricated"
        self.reject("Keccak .*auxiliary identity")

    def test_auxiliary_components_cannot_be_emptied(self):
        for name in ("overlay", "actual_tables", "binding_controls", "oracle_kats"):
            with self.subTest(name=name):
                saved = self.component[name]
                self.component[name] = {}
                self.reject("Keccak .*oracle comparison" if name == "oracle_kats"
                            else "Keccak .*component identity")
                self.component[name] = saved


class PolySourceGateTests(unittest.TestCase):
    """Ingestion gate regressions over the real adopted report and logs.

    ROOT's independent probe (P/poly-source-log-binding-root-probe.json) showed
    three false greens in the first version of this gate: dropping every
    non-proof/audit indexed log, relabelling a proof log digest to another proof
    log with the same shape, and erasing the non-positive `checks` records.  Each
    test below mutates a real copy of the adopted report/index/log tree and
    requires the gate to reject it; the positive test requires the unmodified
    adopted bytes to pass.
    """

    REAL_ROOT = Path(__file__).resolve().parents[2]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self._install_real_tree()

    def tearDown(self):
        self.temporary.cleanup()

    # ---- fixture helpers -------------------------------------------------
    def _install_real_tree(self):
        source = obligations.POLY_SOURCE_RECEIPT
        if not (self.REAL_ROOT / source).is_file():
            self.fail("adopted poly source report is required for these regressions")
        for relative in obligations.POLY_SOURCE_INPUT_KEYS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.REAL_ROOT / relative, destination)
        for relative in (obligations.POLY_SOURCE_BASELINE_TEMPLATE,
                         obligations.POLY_SOURCE_BASELINE_HELPER,
                         obligations.POLY_SOURCE_BASELINE_TEST):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.REAL_ROOT / relative, destination)
        tracked = self.REAL_ROOT / obligations.POLY_SOURCE_TRACKED_PREFIX
        shutil.copytree(tracked, self.root / obligations.POLY_SOURCE_TRACKED_PREFIX)
        self.receipt_path = self.root / source
        self.receipt_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.REAL_ROOT / source, self.receipt_path)
        self.index_path = self.root / obligations.POLY_SOURCE_TRACKED_INDEX
        self.receipt = json.loads(self.receipt_path.read_text())
        self.index = json.loads(self.index_path.read_text())

    def tracked(self, relative: str) -> Path:
        return self.root / obligations.POLY_SOURCE_TRACKED_PREFIX / relative

    def write_log(self, relative: str, text: str) -> str:
        path = self.tracked(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        value = hashlib.sha256(path.read_bytes()).hexdigest()
        self.index["logs"][relative] = value
        return value

    def commit(self):
        """Write the mutated report and keep the index's report digest honest."""
        self.receipt_path.write_text(json.dumps(self.receipt, indent=2))
        report = self.root / obligations.POLY_SOURCE_TRACKED_REPORT
        report.write_text(json.dumps(self.receipt, indent=2))
        self.index["report"]["sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
        self.index_path.write_text(json.dumps(self.index, indent=2))

    def validate(self) -> int:
        self.commit()
        return obligations._validate_poly_source_evidence(self.root, "poly-source")

    def reject(self, pattern: str) -> None:
        self.commit()
        with self.assertRaisesRegex(obligations.LedgerError, pattern):
            obligations._validate_poly_source_evidence(self.root, "poly-source")

    def proof(self, label: str) -> dict:
        return next(item for item in self.receipt["proofs"] if item["label"] == label)

    def mutation(self, name: str) -> dict:
        return next(item for item in self.receipt["controls"]["mutations"]
                    if item["control"] == name)

    def check_record(self, predicate):
        return next(item for item in self.receipt["checks"] if predicate(item))

    # ---- positive --------------------------------------------------------
    def test_adopted_real_report_and_logs_pass_the_semantic_gate(self):
        self.assertGreater(self.validate(), 600)

    # ---- ROOT probe (1): every mandatory log must stay indexed -----------
    def test_control_build_and_closure_logs_cannot_be_dropped(self):
        keep = set()
        for item in self.receipt["proofs"] + self.receipt["audits"]:
            relative = item["log"].split(self.index["producer_root"] + "/", 1)[1]
            keep.add(relative)
        self.index["logs"] = {k: v for k, v in self.index["logs"].items() if k in keep}
        self.reject("tracked log inventory changed")

    def test_single_mandatory_log_cannot_be_unindexed(self):
        del self.index["logs"]["logs/checker-positive.log"]
        self.reject("tracked log inventory changed")

    # ---- ROOT probe (2): per-path binding + parsed content ---------------
    def _swap_proof_log_content(self, label: str, donor_label: str) -> None:
        """ROOT probe (2): same pinned path/digest pair, donor log content."""
        donor_rel = obligations.POLY_SOURCE_PROOF_LOGS[donor_label]
        target_rel = obligations.POLY_SOURCE_PROOF_LOGS[label]
        self.write_log(target_rel, self.tracked(donor_rel).read_text())
        sha = self.index["logs"][target_rel]
        for item in (self.proof(label),
                     self.check_record(lambda x: x.get("label") == label)):
            item["log_sha256"] = sha

    def test_proof_log_content_must_match_the_claimed_count(self):
        self._swap_proof_log_content("polynomial", "field")
        self.reject("verified 86, expected 1001")

    def test_consistent_forgery_of_both_proof_copies_is_still_rejected(self):
        # Update the tracked report, the index report digest and both proof
        # records consistently: the parsed log content must still fail.
        self._swap_proof_log_content("polynomial", "field")
        self.commit()
        self.reject("verified 86, expected 1001")

    def test_proof_log_path_must_be_the_pinned_producer_path(self):
        self.proof("polynomial")["log"] = "/tmp/verify-polynomial.log"
        self.reject("not the pinned producer path")

    def test_positive_proof_log_with_a_warning_is_rejected(self):
        relative = "logs/verify-polynomial.log"
        text = self.tracked(relative).read_text()
        self.write_log(relative, text + "\nNativePolynomial.dfy(1,1): Warning: something\n")
        for item in (self.proof("polynomial"),
                     self.check_record(lambda x: x.get("label") == "polynomial")):
            item["log_sha256"] = self.index["logs"][relative]
        self.reject("contains a verifier diagnostic")

    def test_positive_proof_log_with_resource_exhaustion_is_rejected(self):
        relative = "logs/verify-field.log"
        self.write_log(relative, "\nDafny program verifier finished with 86 verified, "
                                 "0 errors, 1 out of resource\n")
        for item in (self.proof("field"), self.check_record(lambda x: x.get("label") == "field")):
            item["log_sha256"] = self.index["logs"][relative]
        self.reject("inconclusive diagnostic")

    def test_audit_log_must_report_zero_findings(self):
        relative = "logs/audit-formal-crypto-NativeField.dfy.log"
        self.write_log(relative, "Dafny auditor completed with 3 findings\n")
        audit = next(a for a in self.receipt["audits"]
                     if a["file"] == "formal/crypto/NativeField.dfy")
        audit["log_sha256"] = self.index["logs"][relative]
        self.reject("auditor findings do not match")

    # ---- ROOT probe (3): the exact 64-record inventory -------------------
    def test_non_positive_check_records_cannot_be_erased(self):
        keep = []
        for item in self.receipt["checks"]:
            is_positive_proof = "label" in item and "target" in item
            keep.append(item if is_positive_proof else {})
        self.receipt["checks"] = keep
        self.reject("checks inventory dropped the reviewed record")

    def test_check_record_inventory_cannot_shrink(self):
        tagged = [item for item in self.receipt["checks"]
                  if isinstance(item.get("selector"), dict)
                  and "ByMethodProbe.Identity" in (item["selector"].get("POLY_TRACE_FUNCS") or "")]
        self.assertEqual(len(tagged), 1)
        self.receipt["checks"].remove(tagged[0])
        self.assertEqual(len(self.receipt["checks"]), 63)
        self.reject("check-record count changed")

    def test_checker_rejection_inventory_cannot_drop_by_method(self):
        before = len(self.receipt["checks"])
        keep = [item for item in self.receipt["checks"]
                if not (isinstance(item.get("selector"), dict)
                        and "ByMethodProbe.Identity" in (
                            item["selector"].get("POLY_TRACE_FUNCS") or ""))]
        self.assertEqual(len(keep), before - 1)
        # keep the length at 64 with a duplicate so the count check cannot mask it
        self.receipt["checks"] = keep + [dict(keep[0])]
        self.reject("checks inventory dropped the reviewed record|unexpected check record shape")

    def test_tampered_rejection_text_is_rejected(self):
        record = self.check_record(
            lambda x: x.get("needle") == "function-by-method is unsupported")
        record["text"] = record["text"].replace("unsupported", "also unsupported")
        self.reject("checker rejection diagnostic changed|not its tracked log")

    def test_positive_rewrite_of_a_rejection_log_is_rejected(self):
        relative = "logs/controls/checker-ByMethodProbe-Identity.log"
        first = self.tracked(relative).read_text().split("\n", 1)[0]
        self.write_log(relative, first + "\n\n" + obligations.POLY_SOURCE_DEFAULT_FIRST_LINE
                       + "\n\nDafny program verifier did not attempt verification\n")
        record = self.check_record(
            lambda x: x.get("needle") == "function-by-method is unsupported")
        record["log_sha256"] = self.index["logs"][relative]
        record["text"] = self.tracked(relative).read_text()
        self.reject("is a success, not a rejection")

    def test_dafny_negative_log_must_show_a_real_failure(self):
        relative = obligations.POLY_SOURCE_DAFNY_NEGATIVES[0][0]
        text = self.tracked(relative).read_text()
        first = text.split("\n", 1)[0]
        # keep the pinned diagnostic line and the named anchor, forge the summary
        forged = first + "\n\nDafny program verifier finished with 3 verified, 0 errors\n"
        self.write_log(relative, forged)
        record = self.check_record(lambda x: x.get("classification") == "dafny-assertion-failure")
        record["log_sha256"] = self.index["logs"][relative]
        record["text"] = forged
        self.reject("does not match")

    def test_unusable_mutation_log_must_stay_inconclusive(self):
        relative = "logs/controls/leaf-branch-mutation-dafny.log"
        self.write_log(relative, "\nDafny program verifier finished with 1001 verified, 0 errors\n")
        record = self.mutation("leaf-branch-mutation")
        record["dafny_log_sha256"] = self.index["logs"][relative]
        self.reject("not an inconclusive resource diagnostic")

    def test_default_checker_roots_cannot_change(self):
        record = self.check_record(
            lambda x: x.get("selector") == obligations.POLY_SOURCE_DEFAULT_SELECTOR)
        record["roots"] = list(reversed(record["roots"]))
        self.reject("default checker roots changed")

    def test_default_pure_function_inventory_cannot_shrink(self):
        record = self.check_record(
            lambda x: x.get("selector") == obligations.POLY_SOURCE_DEFAULT_SELECTOR)
        record["expected_pure_functions"] = record["expected_pure_functions"][:-1]
        self.reject("pure-function identities changed")

    def test_root_set_digest_must_match_the_roots(self):
        record = self.check_record(
            lambda x: x.get("selector") == obligations.POLY_SOURCE_DEFAULT_SELECTOR)
        record["root_set_sha256"] = "a" * 64
        self.reject("root-set digest changed")

    def test_checker_positive_log_roots_must_match_the_record(self):
        relative = "logs/checker-positive.log"
        first = self.tracked(relative).read_text().split("\n", 1)[0]
        tampered = first.replace("NativePolynomial.NewZetas", "NativePolynomial.Forged", 1)
        self.write_log(relative, tampered + "\n")
        record = self.check_record(
            lambda x: x.get("selector") == obligations.POLY_SOURCE_DEFAULT_SELECTOR)
        record["log_sha256"] = self.index["logs"][relative]
        record["text"] = self.tracked(relative).read_text()
        self.reject("printed roots changed|printed roots differ")

    def test_repeated_root_probe_log_must_print_the_repeated_selector(self):
        relative = "logs/checker-scope-probe-repeated.log"
        text = self.tracked(relative).read_text().split("\n", 1)[0]
        forged = text.replace("NativePolynomial.NewZetas", "NativePolynomial.Add", 1)
        self.write_log(relative, forged + "\n")
        probe = self.receipt["controls"]["scope_probe"]
        probe["log_sha256"] = self.index["logs"][relative]
        duplicate = self.check_record(lambda x: x.get("probe") == "repeated-single-root")
        duplicate["log_sha256"] = self.index["logs"][relative]
        self.reject("does not print the repeated selector roots")

    def test_n1b_body_log_must_clear_the_minimum(self):
        relative = "logs/controls/rebind-and-model-swap-body.log"
        self.write_log(relative, "\nDafny program verifier finished with 10 verified, 0 errors\n")
        self.reject("did not clear the minimum")

    def test_n1b_generated_java_identity_must_hold(self):
        self.receipt["controls"]["n1b"][0]["java_files"] = 65
        self.reject("generated-Java identity changed")

    def test_tracked_log_bytes_must_match_the_index(self):
        path = self.tracked("logs/verify-field.log")
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(obligations.LedgerError, "tracked log differs from the index"):
            obligations._validate_poly_source_evidence(self.root, "poly-source")

    def test_tracked_report_must_equal_the_adopted_receipt(self):
        (self.root / obligations.POLY_SOURCE_TRACKED_REPORT).write_text("{}\n")
        with self.assertRaisesRegex(obligations.LedgerError, "tracked report"):
            obligations._validate_poly_source_evidence(self.root, "poly-source")

    def test_baseline_must_be_the_pre_adoption_tree(self):
        self.index["baseline"]["components"]["formal/crypto/NativeField.dfy"] = (
            self.receipt["inputs_before"]["formal/crypto/NativeField.dfy"])
        self.reject("candidate-as-own-baseline")

    # ---- F-A: exact identity multisets for the supplementary records ----
    def _extra(self, predicate):
        return next(item for item in self.receipt["checks"] if predicate(item))

    def _duplicate_and_drop(self, drop, duplicate) -> None:
        before = len(self.receipt["checks"])
        self.receipt["checks"].remove(drop)
        self.receipt["checks"].append(dict(duplicate))
        self.assertEqual(len(self.receipt["checks"]), before)

    def test_positive_scope_identity_cannot_be_duplicated(self):
        branch = self._extra(lambda x: x.get("selector") == {
            "POLY_TRACE_FUNCS": None, "POLY_TRACE_ROOTS": "Control.SecretBranchObserved"})
        index_scope = self._extra(lambda x: x.get("selector") == {
            "POLY_TRACE_FUNCS": None, "POLY_TRACE_ROOTS": "Control.SecretIndexObserved"})
        self._duplicate_and_drop(index_scope, branch)
        self.reject("positive-scope identities are duplicated or incomplete")

    def test_checker_rejection_identity_cannot_be_duplicated(self):
        branch = self._extra(lambda x: x.get("selector") == {
            "POLY_TRACE_FUNCS": None, "POLY_TRACE_ROOTS": "Control.SecretBranchUnmarked"})
        index_rej = self._extra(lambda x: x.get("selector") == {
            "POLY_TRACE_FUNCS": None, "POLY_TRACE_ROOTS": "Control.SecretIndexUnmarked"})
        self._duplicate_and_drop(index_rej, branch)
        self.reject("checker-rejection identities are duplicated or incomplete")

    def test_shadow_callee_rejection_cannot_be_replaced_by_a_duplicate(self):
        role = self._extra(lambda x: x.get("selector") == {
            "POLY_TRACE_FUNCS": None, "POLY_TRACE_ROOTS": "Control.RoleShadow"})
        shadow = self._extra(lambda x: x.get("selector") == {
            "POLY_TRACE_FUNCS": None, "POLY_TRACE_ROOTS": "Control.ShadowCallee"})
        self._duplicate_and_drop(shadow, role)
        self.reject("checker-rejection identities are duplicated or incomplete")

    def test_dafny_negative_identity_cannot_be_duplicated(self):
        branch = self._extra(lambda x: x.get("classification") == "dafny-assertion-failure"
                             and "BranchObservedHarness" in x.get("text", ""))
        index_neg = self._extra(lambda x: x.get("classification") == "dafny-assertion-failure"
                                and "IndexObservedHarness" in x.get("text", ""))
        self._duplicate_and_drop(index_neg, branch)
        self.reject("Dafny-negative identities are duplicated or incomplete")

    def test_green_control_identity_cannot_be_duplicated(self):
        unmarked = self._extra(lambda x: x.get("log", "").endswith(
            "logs/controls-UnmarkedHarnesses.dfy.log"))
        function_unmarked = self._extra(lambda x: x.get("log", "").endswith(
            "logs/controls-FunctionUnmarkedHarnesses.dfy.log"))
        self._duplicate_and_drop(function_unmarked, unmarked)
        self.reject("green-control identities are duplicated or incomplete")

    # ---- F-B: green records must bind a real producer path and digest ----
    def test_green_record_cannot_use_a_temporary_path(self):
        record = self._extra(lambda x: x.get("log", "").endswith(
            "logs/controls-UnmarkedHarnesses.dfy.log"))
        record["log"] = "/tmp/not-a-producer.log"
        record["log_sha256"] = "z" * 64
        self.reject("green check log is not a producer path|log_sha256 for")

    def test_green_record_digest_must_match_the_index(self):
        record = self._extra(lambda x: x.get("log", "").endswith(
            "logs/controls-UnmarkedHarnesses.dfy.log"))
        record["log_sha256"] = "0" * 64
        self.reject("log digest does not match the index")

    # ---- F-C: recorded digests are mandatory; N1b schema is explicit ----
    def test_proof_record_must_carry_its_log_digest(self):
        for item in (self.proof("field"),
                     self.check_record(lambda x: x.get("label") == "field")):
            del item["log_sha256"]
        self.reject("lacks its log_sha256")

    def test_canonical_record_must_carry_its_checker_digest(self):
        del self.receipt["controls"]["canonical"][0]["checker_log_sha256"]
        duplicate = self.check_record(lambda x: x.get("control") == "canonical-branch-flip")
        del duplicate["checker_log_sha256"]
        self.reject("lacks its checker_log_sha256")

    def test_n1b_schema_without_digests_still_passes(self):
        # body/harness/generate logs intentionally carry no digest field; the
        # explicit schema option must accept them while checker stays mandatory.
        n1b = self.receipt["controls"]["n1b"][0]
        self.assertNotIn("body_log_sha256", n1b)
        self.assertIn("checker_log_sha256", n1b)
        self.assertGreater(self.validate(), 700)

    # ---- F-D: exactly one reviewed validator definition ----
    def test_single_validate_checks_definition(self):
        import inspect
        source = inspect.getsource(obligations)
        self.assertEqual(source.count("def _poly_validate_checks("), 1)
        self.assertEqual(obligations._poly_validate_checks.__code__.co_firstlineno,
                         source[:source.index("def _poly_validate_checks(")].count("\n") + 1)

    # ---- F-E: reviewed needles/reasons, not free receipt text ----
    def test_mutation_needle_cannot_be_replaced_by_arbitrary_text(self):
        for item in (self.mutation("synthetic-callee"),
                     self.check_record(lambda x: x.get("control") == "synthetic-callee")):
            item["checker"]["needle"] = "x"
        self.reject("mutation checker needle changed")

    def test_canonical_needle_cannot_be_replaced(self):
        self.receipt["controls"]["canonical"][0]["checker"]["needle"] = "x"
        duplicate = self.check_record(lambda x: x.get("control") == "canonical-branch-flip")
        duplicate["checker"]["needle"] = "x"
        self.reject("canonical checker needle changed")

    def test_decoy_rejection_is_the_reviewed_string(self):
        self.receipt["controls"]["decoy"]["rejection"] = "some rejection"
        duplicate = self.check_record(lambda x: x.get("schema", "").startswith(
            "microproxy.native-polynomial-decoy"))
        duplicate["rejection"] = "some rejection"
        self.reject("decoy rejection is not the reviewed")

    def test_probe_reason_is_the_reviewed_string(self):
        self.receipt["controls"]["scope_probe"]["reason"] = "duplicate roots"
        duplicate = self.check_record(lambda x: x.get("probe") == "repeated-single-root")
        duplicate["reason"] = "duplicate roots"
        self.reject("repeated-root rejection reason changed")

    # ---- F-F: mutation negatives must carry the reviewed diagnostics ----
    def test_mutation_dafny_diagnostics_must_match_the_reviewed_ones(self):
        relative = obligations.POLY_SOURCE_MUTATION_LOGS["real-path-mutation"][1]
        text = self.tracked(relative).read_text()
        forged = text.replace("a postcondition could not be proved on this return path",
                              "an unrelated postcondition failure", 1)
        self.write_log(relative, forged)
        record = self.mutation("real-path-mutation")
        record["dafny_log_sha256"] = self.index["logs"][relative]
        self.reject("mutation Dafny diagnostics changed")

    def test_mutation_negative_without_its_anchor_is_rejected(self):
        relative = obligations.POLY_SOURCE_MUTATION_LOGS["real-path-mutation"][1]
        text = self.tracked(relative).read_text()
        summary = [line for line in text.split("\n") if line.startswith("Dafny program verifier")][0]
        self.write_log(relative, "\n" + summary + "\n")
        record = self.mutation("real-path-mutation")
        record["dafny_log_sha256"] = self.index["logs"][relative]
        self.reject("does not match|diagnostics changed|has no named error diagnostic")

    def test_canonical_anchor_is_pinned(self):
        self.receipt["controls"]["canonical"][0]["dafny"]["named"] = "x"
        duplicate = self.check_record(lambda x: x.get("control") == "canonical-branch-flip")
        duplicate["dafny"]["named"] = "x"
        self.reject("canonical Dafny anchor changed")

    def test_observe_only_mutation_stays_nonsemantic(self):
        record = self.mutation("leaf-branch-mutation")
        self.assertIs(record["dafny_evidence_usable"], False)
        relative = obligations.POLY_SOURCE_MUTATION_LOGS["leaf-branch-mutation"][1]
        green = "\nDafny program verifier finished with 1001 verified, 0 errors\n"
        self.write_log(relative, green)
        record["dafny_log_sha256"] = self.index["logs"][relative]
        self.reject("not an inconclusive resource diagnostic")

    def test_supported_claim_must_cite_every_reviewed_input(self):
        claim = {"id": obligations.POLY_SOURCE_CLAIM,
                 "evidence": ["formal/crypto/NativeField.dfy"]}
        with self.assertRaisesRegex(obligations.LedgerError, "does not cite"):
            obligations._validate_poly_source_claim(self.root, claim, "claim")



if __name__ == "__main__":
    unittest.main()
