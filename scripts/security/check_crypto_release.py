#!/usr/bin/env python3
"""Release-claim gate over the MicroProxy crypto obligation ledger.

Normal mode validates the ledger and prints machine-readable claim status.  A
non-supported residual claim is reported but does not fail the normal check.
``--require CLAIM`` and ``--require-all`` fail closed: a deferred, blocked,
snapshot, not-selected or unsupported claim is never accepted as done.

Actual-artifact mode is opt-in through the explicit ``--artifact-stage``,
``--artifact-classes``, ``--library``, ``--bundle``, ``--runtime``,
``--java-home`` and ``--artifact-output`` inputs.  It first validates the normal
ledger and the reviewed static functional claims, then runs fresh
``delivery.py check`` and ``bundle_checks.py`` subprocesses.  Only a successful,
fully bound pair of fresh receipts promotes an *ephemeral* status for
``current-release-jar-identity`` in this invocation's output.  The static ledger
claim stays deferred, and expert/timing/whole-proxy/all-complete claims are
never promoted here.

Actual mode also requires the stage's compiler JDK metadata to equal the
explicit operator-supplied trusted JDK21 tree.  Both ``--output`` and
``--artifact-output`` are restricted to locations outside the audited checkout
or under its top-level ``target/`` directory, and are rejected when they overlap
explicit artifacts, stage/classes/JDK directories, the ledger, the private
artifact report, or stage-referenced external input/evidence files (including
symlink/hardlink, ancestor, and legacy ``.part`` aliases).  The same guard now
applies to normal-mode ``--output`` even when no artifact batch is requested.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_crypto_obligations import (  # noqa: E402
    COMPLETION_REQUIRED_CLAIMS,
    ROOT,
    STATUS_SCHEMA,
    LedgerError,
    validate_ledger,
)
from crypto_current_release import (  # noqa: E402
    ArtifactValidationError,
    DEFAULT_TOOL_ROOT,
    validate_current_release,
)

CURRENT_RELEASE_CLAIM = "current-release-jar-identity"
CURRENT_RELEASE_BASELINE_STATUS = "deferred"
CURRENT_RELEASE_REQUIRED_SUPPORTED_CLAIMS = (
    "hkdf-production-functional",
    "shake-mlkem-functional-production",
)
CURRENT_RELEASE_REQUIRED_OBLIGATION_STATUSES = {
    "V2": "implementation-proof",
    "V4": "implementation-proof",
    "V5": "implementation-proof",
    "V6": "implementation-proof",
}
# The audit tools and the repository whose ledger is validated must be the same
# checkout; tests may patch this constant for an isolated fixture.
ARTIFACT_TOOL_ROOT = ROOT
MAX_STAGE_EVIDENCE_BYTES = 4 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")


def _claim_failure(claim: str, reason: str, status: str | None = None) -> dict[str, object]:
    return {"claim": claim, "status": status, "reason": reason}


def _check_current_release_baseline(status: dict[str, object]) -> None:
    """Require the static ledger baseline reviewed for ephemeral promotion.

    A JSON status/receipt cannot enable the claim by itself.  The static claim
    must remain deferred, both reviewed functional production claims must be
    supported, and V2/V4/V5/V6 must be the actual implementation proof statuses.
    """
    claims = status.get("claims")
    obligations = status.get("obligations")
    if not isinstance(claims, dict) or not isinstance(obligations, dict):
        raise ArtifactValidationError("ledger status lacks claims/obligation status")
    baseline = claims.get(CURRENT_RELEASE_CLAIM)
    if baseline != CURRENT_RELEASE_BASELINE_STATUS:
        raise ArtifactValidationError(
            f"{CURRENT_RELEASE_CLAIM} static baseline must remain "
            f"{CURRENT_RELEASE_BASELINE_STATUS!r}, found {baseline!r}")
    for claim in CURRENT_RELEASE_REQUIRED_SUPPORTED_CLAIMS:
        found = claims.get(claim)
        if found != "supported":
            raise ArtifactValidationError(
                f"{claim} must be statically supported before current-release "
                f"artifact validation, found {found!r}")
    for obligation, expected in CURRENT_RELEASE_REQUIRED_OBLIGATION_STATUSES.items():
        found = obligations.get(obligation)
        if found != expected:
            raise ArtifactValidationError(
                f"{obligation} must be {expected!r} before current-release "
                f"artifact validation, found {found!r}")


def _artifact_arguments(args: argparse.Namespace) -> dict[str, object]:
    return {
        "artifact_stage": args.artifact_stage,
        "artifact_classes": args.artifact_classes,
        "library": args.library,
        "bundle": args.bundle,
        "runtime": args.runtime,
        "java_home": list(args.java_home or []),
        "artifact_output": args.artifact_output,
    }


def _missing_artifact_arguments(values: dict[str, object]) -> list[str]:
    return [name for name, value in values.items() if not value]


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _load_bounded_json(path: Path, label: str) -> dict[str, object]:
    """Read data-only JSON with duplicate rejection and an explicit size cap."""
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_STAGE_EVIDENCE_BYTES + 1)
        if len(data) > MAX_STAGE_EVIDENCE_BYTES:
            raise ValueError(f"exceeds {MAX_STAGE_EVIDENCE_BYTES} bytes")
        value = json.loads(data.decode("utf-8"),
                           object_pairs_hook=_no_duplicate_keys)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{label}: cannot read JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label}: expected a JSON object")
    return value


def _digest(path: Path) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _resolved_file(path: Path, label: str) -> Path:
    try:
        resolved = Path(path).resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label}: missing or unresolvable: {path}") from exc
    if not resolved.is_file():
        raise ValueError(f"{label}: not a regular file: {resolved}")
    return resolved


def _absolute_stage_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is not a nonempty path")
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError(f"{label} must be absolute: {value!r}")
    return candidate


def _envelope_reference(base: Path, value: object, label: str) -> Path:
    """Resolve an envelope receipt reference using delivery.safe_path semantics."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}: receipt path is not a nonempty string")
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    name = PurePosixPath(value)
    if name.is_absolute() or ".." in name.parts or "\\" in value or not name.parts:
        raise ValueError(f"{label}: unsafe relative receipt path: {value!r}")
    base_resolved = Path(base).resolve()
    path = base_resolved.joinpath(*name.parts)
    if any(part.is_symlink() for part in [path, *path.parents]
           if part != base_resolved and base_resolved in part.parents):
        raise ValueError(f"{label}: receipt path uses a symlink: {path}")
    return path


def _validated_file(path: Path, label: str, expected: object) -> Path:
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise ValueError(f"{label}: receipt hash is not a SHA-256 hex string")
    resolved = _resolved_file(path, label)
    if _digest(resolved) != expected:
        raise ValueError(f"{label}: receipt hash does not match {resolved}")
    return resolved


def _same_file(left: Path, right: Path) -> bool:
    """Resolve symlinks and compare inode identity, including hard links."""
    try:
        return os.path.samefile(left, right)
    except (OSError, ValueError):
        try:
            return left.resolve() == right.resolve()
        except OSError:
            return False


def _overlaps(left: Path, right: Path) -> bool:
    """True for same file, one inside the other, or ancestor/descendant paths."""
    if _same_file(left, right):
        return True
    try:
        left_resolved = left.resolve()
        right_resolved = right.resolve()
    except OSError:
        return False
    return (left_resolved == right_resolved
            or left_resolved.is_relative_to(right_resolved)
            or right_resolved.is_relative_to(left_resolved))


def _unique_resolved_roots(*values: Path | None) -> list[Path]:
    roots: list[Path] = []
    for value in values:
        if value is None:
            continue
        resolved = value.resolve()
        if resolved not in roots:
            roots.append(resolved)
    return roots


def _explicit_protected_paths(args: argparse.Namespace, ledger_path: Path,
                              *, for_artifact_output: bool) -> tuple[
                                  list[tuple[str, Path]], list[tuple[str, Path]]]:
    files: list[tuple[str, Path]] = []
    directories: list[tuple[str, Path]] = []
    for label, value in (("--library", args.library),
                         ("--bundle", args.bundle),
                         ("--runtime", args.runtime)):
        if value is not None:
            files.append((label, value))
    files.append(("ledger", ledger_path))
    for label, value in (("--artifact-stage", args.artifact_stage),
                         ("--artifact-classes", args.artifact_classes)):
        if value is not None:
            directories.append((label, value))
    for index, value in enumerate(args.java_home or []):
        directories.append((f"--java-home[{index}]", value))
    if for_artifact_output:
        if args.output is not None:
            files.append(("--output", args.output))
    else:
        if args.artifact_output is not None:
            directories.append(("--artifact-output", args.artifact_output))
            files.append(("--artifact-output report",
                          args.artifact_output / "report.json"))
    return files, directories


def _stage_input_paths(stage: Path) -> list[tuple[str, Path]]:
    """Read-only inventory of every external file the delivery check consumes.

    Fresh stages store absolute paths.  Their input envelope is data-only, not a
    tool or authority source; malformed evidence fails closed before any output
    write.  The envelope's referenced receipts are inventoried independently of
    the stage's editable external_inputs map, so omitting an entry cannot hide a
    path that delivery.validate_input_evidence will actually read.
    """
    receipt = _load_bounded_json(stage / "receipt.json", "stage receipt")
    paths: list[tuple[str, Path]] = [
        ("stage receipt", _resolved_file(stage / "receipt.json", "stage receipt"))
    ]

    evidence_candidate = _absolute_stage_path(receipt.get("input_evidence"),
                                              "stage input_evidence")
    evidence_path = _resolved_file(evidence_candidate, "stage input_evidence")
    paths.append(("stage input_evidence", evidence_path))

    external = receipt.get("external_inputs")
    if not isinstance(external, dict):
        raise ValueError("stage external_inputs is not a path map")
    for key, expected in external.items():
        candidate = _absolute_stage_path(key, f"stage external input {key}")
        paths.append((f"stage external input {key}",
                      _validated_file(candidate, f"stage external input {key}",
                                      expected)))

    envelope = _load_bounded_json(evidence_path, "stage input_evidence")
    if (envelope.get("schema") != "microproxy.crypto-input-evidence/v1"
            or envelope.get("status") != "complete"
            or envelope.get("scope") != "full"
            or not isinstance(envelope.get("receipts"), list)
            or not envelope["receipts"]):
        raise ValueError("stage input_evidence is not a complete full envelope")
    # delivery.validate_input_evidence uses the supplied envelope path's parent
    # as its safe_path root, even when the envelope file itself is a symlink.
    base = evidence_candidate.parent
    for index, reference in enumerate(envelope["receipts"]):
        label = f"stage input_evidence receipt[{index}]"
        if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
            raise ValueError(f"{label}: malformed receipt reference")
        candidate = _envelope_reference(base, reference["path"], label)
        paths.append((label, _validated_file(candidate, label, reference["sha256"])))
    return paths


def _check_overlaps(label: str, candidate: Path,
                    files: list[tuple[str, Path]],
                    directories: list[tuple[str, Path]]) -> None:
    for protected_label, protected in files:
        if _overlaps(candidate, protected):
            raise ValueError(f"{label} overlaps {protected_label}")
    for protected_label, protected in directories:
        if _overlaps(candidate, protected):
            raise ValueError(f"{label} overlaps {protected_label}")


def _check_allowed_location(label: str, candidate: Path,
                            authoritative_roots: list[Path],
                            target_roots: list[Path],
                            other_roots: list[Path]) -> None:
    resolved = candidate.resolve()
    for root in authoritative_roots:
        if resolved.is_relative_to(root):
            if any(resolved.is_relative_to(target) for target in target_roots):
                return
            raise ValueError(
                f"{label} is inside the audited checkout; outputs "
                f"must be outside it or under {root}/target")
    for root in other_roots:
        if resolved.is_relative_to(root):
            raise ValueError(f"{label} is inside protected --root {root}")


def _validate_one_output(label: str, candidate: Path | None,
                         files: list[tuple[str, Path]],
                         directories: list[tuple[str, Path]],
                         authoritative_roots: list[Path],
                         target_roots: list[Path],
                         other_roots: list[Path],
                         *, check_legacy_part: bool) -> None:
    if candidate is None:
        return
    _check_overlaps(label, candidate, files, directories)
    if check_legacy_part:
        legacy_part = candidate.with_suffix(candidate.suffix + ".part")
        _check_overlaps("legacy " + label, legacy_part, files, directories)
    _check_allowed_location(label, candidate, authoritative_roots,
                            target_roots, other_roots)


def _output_protection_failure(reason: str) -> int:
    status = {
        "schema": STATUS_SCHEMA,
        "ok": False,
        "output_protection": {"ok": False, "reason": reason},
        "claim_failures": [_claim_failure(
            CURRENT_RELEASE_CLAIM, f"unsafe output: {reason}", None)],
    }
    sys.stdout.write(json.dumps(status, indent=2, sort_keys=True) + "\n")
    return 1


def _validate_output_paths(args: argparse.Namespace, ledger_path: Path, *,
                           artifact_mode: bool) -> None:
    """Complete output closure for `--output` and `--artifact-output`.

    Policy: outputs may be outside the audited checkout or under its top-level
    `target/` directory.  Explicit artifact/stage/classes/JDK/ledger/report
    aliases stay rejected, as do stage-referenced external inputs, the input
    envelope, and every receipt the envelope references (alias or ancestor).
    Normal-mode `--output` uses the same guard without requiring a stage.
    """
    output_path = args.output
    artifact_output = args.artifact_output
    if output_path is None and artifact_output is None:
        return
    authoritative_roots = _unique_resolved_roots(ARTIFACT_TOOL_ROOT,
                                                 DEFAULT_TOOL_ROOT)
    target_roots = [root / "target" for root in authoritative_roots]
    other_roots = [root for root in _unique_resolved_roots(args.root)
                   if root not in authoritative_roots]

    output_files, output_dirs = _explicit_protected_paths(
        args, ledger_path, for_artifact_output=False)
    private_files, private_dirs = _explicit_protected_paths(
        args, ledger_path, for_artifact_output=True)

    # Check explicit aliases first so a bad artifact/ledger target is reported
    # even when the stage itself is missing or malformed.
    if output_path is not None:
        _check_overlaps("--output", output_path, output_files, output_dirs)
        _check_overlaps("legacy --output.part",
                        output_path.with_suffix(output_path.suffix + ".part"),
                        output_files, output_dirs)
    if artifact_output is not None:
        _check_overlaps("--artifact-output", artifact_output,
                        private_files, private_dirs)

    stage_files: list[tuple[str, Path]] = []
    if artifact_mode:
        if args.artifact_stage is None:
            raise ValueError(
                "artifact stage is required to inventory external input/evidence paths")
        stage_files = _stage_input_paths(args.artifact_stage)

    # Re-check with the stage inventory, then apply the checkout/target policy.
    _validate_one_output("--output", output_path,
                         output_files + stage_files, output_dirs,
                         authoritative_roots, target_roots, other_roots,
                         check_legacy_part=True)
    _validate_one_output("--artifact-output", artifact_output,
                         private_files + stage_files, private_dirs,
                         authoritative_roots, target_roots, other_roots,
                         check_legacy_part=False)


def _atomic_write_text(path: Path, text: str) -> None:
    """Exclusive unique temporary write; never reuse a predictable .part path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = 0o644
    descriptor, temporary = tempfile.mkstemp(
        prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require", action="append", default=[], metavar="CLAIM",
                        help="require one supported claim; repeatable")
    parser.add_argument("--require-all", action="store_true",
                        help="require every completion-required claim to be supported")
    parser.add_argument("--artifact-stage", type=Path,
                        help="actual complete canonical delivery stage directory")
    parser.add_argument("--artifact-classes", type=Path,
                        help="actual compiled QUIC library classes directory")
    parser.add_argument("--library", type=Path,
                        help="actual QUIC library JAR")
    parser.add_argument("--bundle", type=Path,
                        help="actual minimized application/bundle JAR")
    parser.add_argument("--runtime", type=Path,
                        help="pinned Maven Dafny runtime JAR")
    parser.add_argument("--java-home", type=Path, action="append", default=[],
                        help="actual JDK home; supply exactly JDK21 and JDK25")
    parser.add_argument("--artifact-output", type=Path,
                        help="fresh output directory for artifact reports/logs")
    args = parser.parse_args(list(argv) if argv is not None else None)

    artifact_values = _artifact_arguments(args)
    artifact_requested = any(value for value in artifact_values.values())
    ledger_path = args.ledger or (args.root / "formal/crypto-obligations.json")

    # Protect the status path before ledger validation on every failure path,
    # including normal mode.  A rejected --output is never written, even if the
    # ledger is bad or the artifact inputs are incomplete.
    if args.output is not None or args.artifact_output is not None:
        try:
            _validate_output_paths(args, ledger_path,
                                   artifact_mode=artifact_requested)
        except (ValueError, LedgerError, OSError) as exc:
            return _output_protection_failure(str(exc))

    try:
        status = validate_ledger(args.root, args.ledger)
    except LedgerError as exc:
        status = {"schema": STATUS_SCHEMA, "ok": False,
                  "claim_failures": [_claim_failure(None, str(exc))]}
        code = 1
    except Exception as exc:
        status = {"schema": STATUS_SCHEMA, "ok": False,
                  "claim_failures": [_claim_failure(None, f"internal validator failure: {type(exc).__name__}: {exc}")]}
        code = 2
    else:
        claims_status = status["claims"]
        ephemeral_claims: dict[str, str] = {}
        artifact_report: dict[str, object] | None = None
        artifact_failures: list[dict[str, object]] = []
        internal_artifact_error: Exception | None = None
        if artifact_requested:
            missing = _missing_artifact_arguments(artifact_values)
            if missing:
                artifact_failures.append(_claim_failure(
                    CURRENT_RELEASE_CLAIM,
                    "incomplete actual artifact inputs: missing " + ", ".join(sorted(missing)),
                    claims_status.get(CURRENT_RELEASE_CLAIM)))
            else:
                try:
                    if args.root.resolve() != ARTIFACT_TOOL_ROOT.resolve():
                        raise ArtifactValidationError(
                            "actual artifact mode requires --root to be the audited "
                            f"tool checkout root ({ARTIFACT_TOOL_ROOT}), got {args.root}")
                    _check_current_release_baseline(status)
                    artifact_report = validate_current_release(
                        args.root,
                        stage=args.artifact_stage,
                        classes=args.artifact_classes,
                        library=args.library,
                        bundle=args.bundle,
                        runtime=args.runtime,
                        java_homes=args.java_home,
                        output=args.artifact_output,
                        tool_root=ARTIFACT_TOOL_ROOT,
                    )
                    if artifact_report.get("status") != "complete":
                        raise ArtifactValidationError(
                            "fresh artifact validation did not return complete status")
                except ArtifactValidationError as exc:
                    artifact_failures.append(_claim_failure(
                        CURRENT_RELEASE_CLAIM, str(exc),
                        claims_status.get(CURRENT_RELEASE_CLAIM)))
                except Exception as exc:  # preserve exit 2 for unexpected internal failure
                    internal_artifact_error = exc
                else:
                    ephemeral_claims[CURRENT_RELEASE_CLAIM] = "supported"

        effective_claims = dict(claims_status)
        effective_claims.update(ephemeral_claims)
        required = list(dict.fromkeys(args.require))
        if args.require_all:
            required.extend(sorted(COMPLETION_REQUIRED_CLAIMS))
        required = list(dict.fromkeys(required))
        failures: list[dict[str, object]] = list(artifact_failures)
        for claim in required:
            found = effective_claims.get(claim)
            if found is None:
                failures.append(_claim_failure(claim, "unknown claim", None))
            elif found != "supported":
                failures.append(_claim_failure(claim, f"claim is {found}, not supported", found))
        if internal_artifact_error is not None:
            failures.append(_claim_failure(
                CURRENT_RELEASE_CLAIM,
                "internal artifact validator failure: "
                f"{type(internal_artifact_error).__name__}: {internal_artifact_error}"))
        status["required_claims"] = required
        status["claim_failures"] = failures
        status["ok"] = not failures and internal_artifact_error is None
        code = 2 if internal_artifact_error is not None else (0 if not failures else 1)
        if artifact_requested:
            status["static_claims"] = dict(claims_status)
            status["ephemeral_claims"] = dict(ephemeral_claims)
            status["effective_claims"] = effective_claims
            status["effective_residual_claims"] = sorted(
                claim for claim, value in effective_claims.items()
                if value != "supported")
            status["artifact_validation"] = artifact_report or {
                "status": "failed",
                "error": (artifact_failures[-1]["reason"]
                          if artifact_failures else
                          f"internal artifact validator failure: {internal_artifact_error}"),
            }

    text = json.dumps(status, indent=2, sort_keys=True) + "\n"
    if args.output:
        _atomic_write_text(args.output, text)
    sys.stdout.write(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
