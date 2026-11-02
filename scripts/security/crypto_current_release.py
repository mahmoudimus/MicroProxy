#!/usr/bin/env python3
"""Fresh current-release artifact validation for the crypto release gate.

This module deliberately does not re-implement class/JAR semantics.  It invokes
the independently reviewed ``formal/crypto/delivery.py check`` and
``formal/crypto/bundle_checks.py`` tools in fresh subprocesses and only binds
their successful receipts to the exact inputs supplied to this run:

* the canonical delivery stage (and its current manifest pin), bound to the
  operator-supplied trusted JDK21 compiler tree before any artifact subprocess;
* the actual compiled library classes and library JAR,
* the actual minimized bundle JAR,
* the pinned Maven Dafny runtime,
* explicit JDK 21 and JDK 25 homes,
* a fresh, non-clobbering 0700 output directory.

Every report, command log and receipt copy is written through an exclusive
random temporary and ``os.replace``; no predictable ``.part`` name is followed.

The stage's editable `jdk_home`/`jdk_files` metadata is never its own oracle: the
operator must supply the same JDK21 patch level that generated the stage, and the
recorded tree must equal the audited `delivery.tool_tree()` of that supplied home.
Trusted CLI `java -version` probes are used only to discover the 21/25 homes; a
stage pointing at any other (including the supplied JDK25) is rejected before any
`delivery.py` or `bundle_checks.py` subprocess runs.

The tools themselves derive the canonical class map from strict source
compilation, replay the native proof roots, compare every class/JAR entry,
check all retained library classes, runtime classes and notices, and run the
origin-checked handshake smoke.  This module never accepts an externally
supplied artifact receipt and never trusts the committed historical adoption
snapshot as current.  Any missing input, stale stage, nonzero exit, timeout,
malformed/incomplete output, artifact change during the run, or root mismatch
fails closed while atomically leaving an ``incomplete``/``failed`` report.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Sequence

_CHECKOUT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CHECKOUT_ROOT / "formal/crypto"))
import delivery as audited_delivery  # noqa: E402

SCHEMA = "microproxy.crypto-current-release-artifact-validation/v1"
STAGE_SCHEMA = "microproxy.crypto-delivery-stage/v1"
BUNDLE_SCHEMA = "microproxy.crypto-current-bundle/v2"

# Current release scope: every actual QUIC library class, the scoped crypto
# classes, the retained library classes in the minimized bundle, the bundled
# Dafny runtime classes and the three packaged notices.  These are release
# identity pins, not proof-strength claims.
EXPECTED_LIBRARY_CLASS_COUNT = 468
EXPECTED_CRYPTO_CLASS_COUNT = 84
EXPECTED_RETAINED_LIBRARY_CLASS_COUNT = 468
EXPECTED_RUNTIME_CLASS_COUNT = 37
EXPECTED_RESOURCES = (
    "META-INF/LICENSE-dafny.txt",
    "META-INF/LICENSE-go-mlkem.txt",
    "META-INF/NOTICE-crypto.txt",
)
EXPECTED_BUNDLE_RUNS = {"21": 9, "25": 9}
EXPECTED_NONCE_SMOKE_CASES = 9
EXPECTED_NONCE_SMOKE_SUITES = (
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
)
EXPECTED_NONCE_SMOKE_PACKET_NUMBERS = (0, 1, -1)
NONCE_SMOKE_SOURCE = "formal/nonce/BundleNonceSmoke.java"
NONCE_SMOKE_OWNERS = (
    "io.github.mahmoudimus.quic.crypto.PacketKey",
    "io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default",
    "nonceadoption.BundleNonceSmoke",
    "dafny.Helpers",
)
EXPECTED_JDK_MAJORS = frozenset({"21", "25"})
DEFAULT_TIMEOUT_SECONDS = 7200
SHA256 = re.compile(r"[0-9a-f]{64}")

# The validator always binds the repository that owns the ledger to the
# checkout that owns the audited tools.  A caller may pass a different
# ``tool_root`` only for isolated tests; production callers use the checkout.
DEFAULT_TOOL_ROOT = _CHECKOUT_ROOT


class ArtifactValidationError(RuntimeError):
    """A fail-closed current-release artifact validation failure."""


def digest(path: Path | str) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactValidationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"),
                           object_pairs_hook=_no_duplicate_keys)
    except ArtifactValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactValidationError(f"{label}: cannot read JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactValidationError(f"{label}: expected a JSON object")
    return value


def _atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    """Exclusive random temporary write; never follow a predictable output alias."""
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _tail(text: str, limit: int = 4000) -> str:
    text = text or ""
    return text[-limit:]


def _sha_map(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise ArtifactValidationError(f"{label}: expected a nonempty hash map")
    result: dict[str, str] = {}
    for name, sha in value.items():
        if not isinstance(name, str) or not isinstance(sha, str) or not SHA256.fullmatch(sha):
            raise ArtifactValidationError(f"{label}: malformed class hash entry")
        result[name] = sha
    return result


def _resolved_file(path: str | Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ArtifactValidationError(f"{label}: missing or unresolvable: {candidate}") from exc
    if not resolved.is_file():
        raise ArtifactValidationError(f"{label}: not a regular file: {resolved}")
    return resolved


def _resolved_dir(path: str | Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ArtifactValidationError(f"{label}: missing or unresolvable: {candidate}") from exc
    if not resolved.is_dir():
        raise ArtifactValidationError(f"{label}: not a directory: {resolved}")
    return resolved


def _snapshot_tree(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ArtifactValidationError(f"unexpected symlink in artifact tree: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = digest(path)
        elif not path.is_dir():
            raise ArtifactValidationError(f"unexpected artifact type: {path}")
    return result


def _tree_digest(snapshot: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _prepare_output(output: str | Path, inputs: Iterable[tuple[str, Path]],
                    input_dirs: Iterable[tuple[str, Path]]) -> Path:
    """Create a fresh output directory and refuse every clobber/alias case."""
    candidate = Path(output).expanduser()
    resolved = candidate.resolve()
    for label, path in inputs:
        if resolved == path:
            raise ArtifactValidationError(f"artifact output aliases {label}: {resolved}")
    for label, path in input_dirs:
        if resolved.is_relative_to(path):
            raise ArtifactValidationError(f"artifact output is inside {label}: {resolved}")
    if candidate.exists() or candidate.is_symlink():
        raise ArtifactValidationError(f"artifact output already exists: {resolved}")
    try:
        candidate.mkdir(parents=True, exist_ok=False)
        candidate.chmod(0o700)
    except OSError as exc:
        raise ArtifactValidationError(f"cannot create artifact output: {exc}") from exc
    return resolved


def _write_command_logs(out: Path, label: str, stdout: str | None,
                        stderr: str | None) -> tuple[Path, Path]:
    stdout_path = out / (label + ".stdout.log")
    stderr_path = out / (label + ".stderr.log")
    _atomic_write_text(stdout_path, stdout or "")
    _atomic_write_text(stderr_path, stderr or "")
    return stdout_path, stderr_path


def _kill_owned_group(process: subprocess.Popen[str] | None) -> None:
    """Kill only the process group created for this validator's direct child."""
    if process is None or process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass


def _reap_owned_group(process: subprocess.Popen[str]) -> tuple[str, str]:
    """Terminate the owned group and collect its remaining output."""
    _kill_owned_group(process)
    try:
        return process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        return process.communicate()


def _run(report: dict[str, Any], out: Path, argv: Sequence[str | Path], *,
         label: str, timeout: float, cwd: Path) -> subprocess.CompletedProcess[str]:
    command = [str(value) for value in argv]
    process: subprocess.Popen[str] | None = None
    pending: list[int] = []
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    installed: dict[int, Any] = {}

    def cancel(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt(f"artifact validation cancelled by signal {signum}")

    def remember(signum: int, frame: Any) -> None:
        pending.append(signum)

    # Reuse the audited delivery runner's owned-group pattern: briefly record
    # cancellation during startup, then convert SIGINT/SIGTERM to an exception
    # while the child runs so the finally/except path can reap the whole group.
    try:
        for sig in handlers:
            installed[sig] = signal.getsignal(sig)
            signal.signal(sig, remember)
    except (ValueError, OSError):
        for sig, handler in installed.items():
            signal.signal(sig, handler)
        installed = {}
    try:
        try:
            process = subprocess.Popen(command, cwd=str(cwd), text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
        finally:
            for sig, handler in installed.items():
                signal.signal(sig, cancel if handler == signal.SIG_DFL else handler)
        if pending:
            raise KeyboardInterrupt(f"artifact validation cancelled while starting {label}")
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stdout, stderr = _reap_owned_group(process)
        _write_command_logs(out, label, stdout, stderr)
        report["commands"].append({"label": label, "argv": command, "timeout": timeout})
        raise ArtifactValidationError(
            f"{label} timed out after {timeout} seconds")
    except OSError as exc:
        if process is not None:
            _reap_owned_group(process)
        raise ArtifactValidationError(f"{label}: cannot execute: {exc}") from exc
    except BaseException:
        if process is not None:
            stdout, stderr = _reap_owned_group(process)
            _write_command_logs(out, label, stdout, stderr)
        raise
    finally:
        for sig, handler in installed.items():
            signal.signal(sig, handler)
    stdout_path, stderr_path = _write_command_logs(out, label, stdout, stderr)
    report["commands"].append({
        "label": label,
        "argv": command,
        "exit": process.returncode,
        "stdout_sha256": digest(stdout_path),
        "stderr_sha256": digest(stderr_path),
    })
    if process.returncode != 0:
        detail = stderr.strip() or stdout.strip()
        raise ArtifactValidationError(
            f"{label} exited {process.returncode}: {_tail(detail)}")
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactValidationError(message)


def _jdk_major(home: Path, report: dict[str, Any], out: Path, *,
               label: str, timeout: float) -> str:
    java = home / "bin" / "java"
    javac = home / "bin" / "javac"
    _require(java.is_file() and javac.is_file(),
             f"JDK {home} lacks bin/java or bin/javac")
    completed = _run(report, out, [java, "-version"], label=label,
                     timeout=min(timeout, 120), cwd=home)
    text = completed.stdout + completed.stderr
    match = re.search(r'version "(\d+)', text)
    if match is None:
        raise ArtifactValidationError(f"JDK {home} did not report a Java version")
    return match.group(1)


def _check_stage(stage: Path, manifest_path: Path,
                 manifest: dict[str, Any], *, trusted_jdk21: Path) -> tuple[dict[str, Any], Path]:
    receipt_path = stage / "receipt.json"
    receipt = _load_json(receipt_path, "stage receipt")
    _require(receipt.get("schema") == STAGE_SCHEMA,
             "stage receipt schema is not the current delivery stage")
    _require(receipt.get("status") == "complete",
             "stage receipt is not complete")
    _require(receipt.get("component") is None,
             "a component-provisional stage cannot support the current release")
    _require(receipt.get("entry") == manifest.get("entry"),
             "stage entry differs from the current delivery manifest")
    expected_manifest = receipt.get("manifest_sha256")
    _require(isinstance(expected_manifest, str)
             and SHA256.fullmatch(expected_manifest)
             and expected_manifest == digest(manifest_path),
             "stage was generated from a different or stale delivery manifest")
    canonical = receipt.get("canonical_classes")
    _require(isinstance(canonical, dict) and canonical,
             "stage receipt lacks its canonical class map")
    stage_jdk = receipt.get("jdk_home")
    _require(isinstance(stage_jdk, str) and stage_jdk,
             "stage receipt lacks its compiler JDK home")
    try:
        stage_jdk_resolved = Path(stage_jdk).resolve(strict=True)
        trusted_jdk_resolved = trusted_jdk21.resolve(strict=True)
    except OSError as exc:
        raise ArtifactValidationError(
            "stage or trusted compiler JDK home is missing") from exc
    _require(stage_jdk_resolved == trusted_jdk_resolved,
             "stage compiler JDK is not the operator-supplied trusted JDK21: "
             f"stage={stage_jdk_resolved} trusted={trusted_jdk_resolved}")
    recorded_tree = receipt.get("jdk_files")
    _require(isinstance(recorded_tree, dict) and recorded_tree,
             "stage receipt lacks its compiler JDK file tree")
    try:
        actual_tree = audited_delivery.tool_tree(trusted_jdk_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ArtifactValidationError(
            f"cannot hash the trusted compiler JDK tree: {exc}") from exc
    _require(recorded_tree == actual_tree,
             "stage compiler JDK file tree differs from the operator-supplied "
             "trusted JDK21")
    return receipt, receipt_path


def _check_delivery_receipt(receipt: dict[str, Any], *, stage_receipt: dict[str, Any],
                            library_sha: str, stage_sha: str) -> dict[str, Any]:
    _require(receipt.get("status") == "checked",
             "fresh delivery check did not report checked status")
    classes = _sha_map(receipt.get("classes"), "delivery classes")
    _require(len(classes) == EXPECTED_LIBRARY_CLASS_COUNT,
             f"delivery check covered {len(classes)} classes, expected "
             f"{EXPECTED_LIBRARY_CLASS_COUNT}")
    _require(all(name.startswith("io/github/mahmoudimus/") for name in classes),
             "delivery classes escape the QUIC library namespace")
    _require(receipt.get("class_count") == len(classes),
             "delivery class count does not match its class map")
    _require(receipt.get("jar_sha256") == library_sha,
             "delivery receipt does not bind the supplied library JAR")
    _require(receipt.get("stage_receipt_sha256") == stage_sha,
             "delivery receipt does not bind the supplied stage receipt")
    _require(receipt.get("generated_class_count")
             == len(stage_receipt.get("canonical_classes", {})),
             "delivery generated-class count differs from the stage")
    _require(receipt.get("comparison")
             == "exact class bytes including all debug attributes",
             "delivery receipt lacks the reviewed exact-byte comparison")
    _require(isinstance(receipt.get("handwritten_sources"), int)
             and receipt["handwritten_sources"] > 0,
             "delivery receipt lacks handwritten source coverage")
    _require(isinstance(receipt.get("handwritten_lint"), list),
             "delivery receipt lacks handwritten lint policy")
    return {
        "class_count": len(classes),
        "generated_class_count": receipt["generated_class_count"],
        "handwritten_sources": receipt["handwritten_sources"],
        "stage_receipt_sha256": stage_sha,
        "jar_sha256": library_sha,
        "classes": classes,
    }


def _check_nonce_smoke(nonce: Any, *, tool_hashes: dict[str, str],
                       delivery_classes: dict[str, str]) -> dict[str, Any]:
    _require(isinstance(nonce, dict), "bundle receipt lacks the nonce execution smoke")
    _require(nonce.get("schema") == "microproxy.nonce-bundle-smoke/v1",
             "nonce smoke schema changed")
    _require(nonce.get("source") == NONCE_SMOKE_SOURCE,
             "nonce smoke source path changed")
    _require(nonce.get("source_sha256") == tool_hashes.get(NONCE_SMOKE_SOURCE),
             "nonce smoke harness does not bind the current checkout source")
    harness = _sha_map(nonce.get("harness_classes"), "nonce smoke harness classes")
    _require(set(harness) == {"nonceadoption/BundleNonceSmoke.class"},
             "nonce smoke compiled an unexpected harness class set")
    _require(not (set(harness) & set(delivery_classes)),
             "nonce smoke harness leaked into the production class map")
    runs = nonce.get("runs")
    _require(isinstance(runs, dict) and set(runs) == {"21", "25"},
             "nonce smoke does not cover both required JDKs")
    summary: dict[str, Any] = {}
    for major in ("21", "25"):
        run = runs.get(major)
        _require(isinstance(run, dict), f"nonce smoke JDK {major} record is missing")
        _require(run.get("cases") == EXPECTED_NONCE_SMOKE_CASES
                 and run.get("passed") == EXPECTED_NONCE_SMOKE_CASES,
                 f"nonce smoke JDK {major} did not execute all {EXPECTED_NONCE_SMOKE_CASES} cases")
        origins = run.get("origins")
        _require(isinstance(origins, dict)
                 and set(origins) == {"PacketKey", "VerifiedNonce", "DafnyRuntime", "harness"},
                 f"nonce smoke JDK {major} origin inventory changed")
        _require(all(isinstance(value, str) and value for value in origins.values()),
                 f"nonce smoke JDK {major} origin paths are malformed")
        _require(origins["PacketKey"] == origins["VerifiedNonce"],
                 f"nonce smoke JDK {major} loaded VerifiedNonce outside the bundle")
        _require(origins["DafnyRuntime"] == origins["PacketKey"],
                 f"nonce smoke JDK {major} loaded the Dafny runtime outside the bundle")
        _require(origins["harness"] not in {origins["PacketKey"], origins["DafnyRuntime"]},
                 f"nonce smoke JDK {major} harness shares a production origin")
        detail = run.get("cases_detail")
        _require(isinstance(detail, list) and len(detail) == EXPECTED_NONCE_SMOKE_CASES,
                 f"nonce smoke JDK {major} case inventory changed")
        seen = set()
        for row in detail:
            _require(isinstance(row, dict)
                     and set(row) == {"suite", "packet_number", "nonce", "ciphertext_sha256"},
                     f"nonce smoke JDK {major} case fields changed")
            suite, packet_number = row["suite"], row["packet_number"]
            _require(suite in EXPECTED_NONCE_SMOKE_SUITES
                     and type(packet_number) is int
                     and packet_number in EXPECTED_NONCE_SMOKE_PACKET_NUMBERS,
                     f"nonce smoke JDK {major} has an unexpected case")
            _require((suite, packet_number) not in seen,
                     f"nonce smoke JDK {major} repeats a case")
            seen.add((suite, packet_number))
            _require(isinstance(row["nonce"], str)
                     and re.fullmatch(r"[0-9a-f]{24}", row["nonce"]),
                     f"nonce smoke JDK {major} has a malformed nonce")
            _require(isinstance(row["ciphertext_sha256"], str)
                     and SHA256.fullmatch(row["ciphertext_sha256"]),
                     f"nonce smoke JDK {major} has a malformed ciphertext digest")
        _require(seen == {(suite, packet_number)
                          for suite in EXPECTED_NONCE_SMOKE_SUITES
                          for packet_number in EXPECTED_NONCE_SMOKE_PACKET_NUMBERS},
                 f"nonce smoke JDK {major} case matrix changed")
        loaded = run.get("loaded_classes")
        _require(isinstance(loaded, dict), f"nonce smoke JDK {major} lacks loaded origins")
        for owner in NONCE_SMOKE_OWNERS:
            _require(owner in loaded, f"nonce smoke JDK {major} did not load {owner}")
        _require(loaded["io.github.mahmoudimus.quic.crypto.PacketKey"] == origins["PacketKey"]
                 and loaded["io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default"]
                 == origins["PacketKey"],
                 f"nonce smoke JDK {major} did not execute PacketKey/VerifiedNonce from the bundle")
        _require(loaded["nonceadoption.BundleNonceSmoke"] == origins["harness"],
                 f"nonce smoke JDK {major} harness origin differs")
        _require(loaded["dafny.Helpers"] == origins["DafnyRuntime"],
                 f"nonce smoke JDK {major} runtime origin differs")
        _require(isinstance(run.get("classload_sha256"), str)
                 and SHA256.fullmatch(run["classload_sha256"]),
                 f"nonce smoke JDK {major} class-load digest is malformed")
        summary[major] = {"cases": EXPECTED_NONCE_SMOKE_CASES,
                          "classload_sha256": run["classload_sha256"]}
    return summary


def _check_bundle_receipt(receipt: dict[str, Any], *, delivery_receipt: dict[str, Any],
                          library_sha: str, bundle_sha: str, runtime_sha: str,
                          delivery_receipt_sha: str, stage_sha: str,
                          tool_hashes: dict[str, str],
                          java_homes: dict[str, Path]) -> dict[str, Any]:
    _require(receipt.get("schema") == BUNDLE_SCHEMA,
             "bundle receipt schema is not the current bundle identity schema")
    _require(receipt.get("status") == "complete",
             "bundle check did not report complete status")
    _require(receipt.get("library_jar_sha256") == library_sha,
             "bundle receipt does not bind the supplied library JAR")
    _require(receipt.get("bundle_jar_sha256") == bundle_sha,
             "bundle receipt does not bind the supplied bundle JAR")
    _require(receipt.get("stage_receipt_sha256") == stage_sha,
             "bundle receipt does not bind the same stage as delivery check")

    artifacts = receipt.get("artifact_inputs")
    _require(isinstance(artifacts, dict), "bundle receipt lacks artifact inputs")
    _require(artifacts.get("library.jar") == library_sha,
             "bundle artifact input does not bind the library JAR")
    _require(artifacts.get("bundle.jar") == bundle_sha,
             "bundle artifact input does not bind the bundle JAR")
    _require(artifacts.get("delivery.json") == delivery_receipt_sha,
             "bundle receipt does not consume this fresh delivery receipt")
    _require(artifacts.get("runtime-reference.jar") == runtime_sha,
             "bundle artifact input does not bind the pinned runtime")

    canonical = receipt.get("canonical")
    _require(isinstance(canonical, dict), "bundle receipt lacks canonical binding")
    _require(canonical.get("classes") == delivery_receipt.get("classes"),
             "bundle canonical class map differs from the fresh delivery receipt")
    _require(canonical.get("stage_receipt_sha256") == stage_sha,
             "bundle canonical binding differs from the fresh stage")

    classes = _sha_map(delivery_receipt.get("classes"), "delivery classes")
    crypto = _sha_map(receipt.get("crypto_classes"), "bundle crypto classes")
    retained = _sha_map(receipt.get("retained_library_classes"),
                        "bundle retained library classes")
    runtime_classes = _sha_map(receipt.get("runtime_classes"),
                               "bundle runtime classes")
    _require(len(crypto) == EXPECTED_CRYPTO_CLASS_COUNT,
             f"bundle covered {len(crypto)} crypto classes, expected "
             f"{EXPECTED_CRYPTO_CLASS_COUNT}")
    _require(set(crypto).issubset(classes)
             and all(crypto[name] == classes[name] for name in crypto),
             "bundle crypto classes differ from the fresh delivery class map")
    _require(len(retained) == EXPECTED_RETAINED_LIBRARY_CLASS_COUNT,
             f"bundle retained {len(retained)} library classes, expected "
             f"{EXPECTED_RETAINED_LIBRARY_CLASS_COUNT}")
    _require(set(retained) == set(classes)
             and all(retained[name] == classes[name] for name in retained),
             "minimized bundle does not retain every canonical library class")
    _require(len(runtime_classes) == EXPECTED_RUNTIME_CLASS_COUNT,
             f"bundle covered {len(runtime_classes)} runtime classes, expected "
             f"{EXPECTED_RUNTIME_CLASS_COUNT}")

    resources = receipt.get("resources")
    _require(isinstance(resources, dict)
             and set(resources) == set(EXPECTED_RESOURCES),
             "bundle receipt does not cover the three reviewed crypto notices")
    _require(all(isinstance(value, str) and SHA256.fullmatch(value)
                 for value in resources.values()),
             "bundle notice hashes are malformed")

    runs = receipt.get("runs")
    _require(isinstance(runs, dict) and set(runs) == {"21", "25"},
             "bundle receipt does not cover both required JDKs")
    for major, expected_count in EXPECTED_BUNDLE_RUNS.items():
        run = runs.get(major)
        _require(isinstance(run, dict)
                 and run.get("completed_full_handshakes") == expected_count,
                 f"bundle JDK {major} did not complete {expected_count} handshakes")
        loaded = run.get("loaded_classes")
        _require(isinstance(loaded, dict) and loaded,
                 f"bundle JDK {major} lacks checked loaded-class origins")

    jdk_inputs = receipt.get("jdk_inputs")
    _require(isinstance(jdk_inputs, dict)
             and set(jdk_inputs) == {str(path) for path in java_homes.values()},
             "bundle receipt does not bind the supplied JDK homes")

    source_inputs = receipt.get("source_inputs")
    _require(isinstance(source_inputs, dict), "bundle receipt lacks source inputs")
    for name in ("formal/crypto/delivery.py", "formal/crypto/bundle_checks.py", NONCE_SMOKE_SOURCE):
        _require(source_inputs.get(name) == tool_hashes.get(name),
                 f"bundle receipt tool/source binding differs: {name}")
    nonce_smoke = _check_nonce_smoke(receipt.get("nonce_smoke"), tool_hashes=tool_hashes,
                                     delivery_classes=classes)

    return {
        "crypto_class_count": len(crypto),
        "retained_library_class_count": len(retained),
        "runtime_class_count": len(runtime_classes),
        "resources": sorted(resources),
        "runs": {major: run["completed_full_handshakes"]
                 for major, run in runs.items()},
        "nonce_smoke": nonce_smoke,
    }


def _check_unchanged(snapshot: dict[str, Any], *, classes: Path, library: Path,
                     bundle: Path, runtime: Path, stage_receipt_path: Path,
                     manifest_path: Path) -> None:
    for label, path, expected in (
        ("library JAR", library, snapshot["library"]),
        ("bundle JAR", bundle, snapshot["bundle"]),
        ("runtime JAR", runtime, snapshot["runtime"]),
        ("stage receipt", stage_receipt_path, snapshot["stage_receipt"]),
        ("delivery manifest", manifest_path, snapshot["manifest"]),
    ):
        if digest(path) != expected:
            raise ArtifactValidationError(f"{label} changed during validation")
    if _snapshot_tree(classes) != snapshot["classes"]:
        raise ArtifactValidationError("actual class tree changed during validation")
    for path, expected in snapshot["tools"].items():
        if digest(Path(path)) != expected:
            raise ArtifactValidationError(f"validated tool/source changed: {path}")


def validate_current_release(repository_root: str | Path, *, stage: str | Path,
                             classes: str | Path, library: str | Path,
                             bundle: str | Path, runtime: str | Path,
                             java_homes: Sequence[str | Path],
                             output: str | Path,
                             tool_root: str | Path | None = None,
                             timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Validate fresh actual current-release artifacts and return a bound report.

    All failures raise ``ArtifactValidationError`` after atomically leaving a
    ``failed`` report in the fresh output directory.  Success requires both
    audited tools to exit zero, their receipts to bind the exact inputs and
    JDKs supplied here, and every input/tool/source hash to remain unchanged
    across the run.
    """
    repository_root = Path(repository_root).expanduser().resolve()
    tool_root_path = (Path(tool_root).expanduser().resolve()
                      if tool_root is not None else DEFAULT_TOOL_ROOT)
    if repository_root != tool_root_path:
        raise ArtifactValidationError(
            "actual artifact validation requires the repository root to be the "
            f"audited tool checkout root: ledger={repository_root} "
            f"tools={tool_root_path}")

    stage_path = _resolved_dir(stage, "artifact stage")
    classes_path = _resolved_dir(classes, "actual library classes")
    library_path = _resolved_file(library, "actual library JAR")
    bundle_path = _resolved_file(bundle, "actual minimized bundle JAR")
    runtime_path = _resolved_file(runtime, "pinned Dafny runtime JAR")
    homes = [_resolved_dir(home, f"JDK home {index}")
             for index, home in enumerate(java_homes)]
    _require(len(homes) == 2, "exactly two JDK homes (21 and 25) are required")
    _require(len(set(homes)) == 2, "duplicate JDK home supplied")

    all_files = {
        "library": library_path,
        "bundle": bundle_path,
        "runtime": runtime_path,
    }
    _require(len(set(all_files.values())) == 3,
             "library, bundle and runtime artifacts must be distinct files")
    all_inputs = [("stage", stage_path), ("classes", classes_path),
                  *[(f"JDK home {index}", home) for index, home in enumerate(homes)],
                  *all_files.items()]
    output_path = _prepare_output(output, all_inputs,
                                  [("stage", stage_path), ("classes", classes_path),
                                   *[(f"JDK home {index}", home)
                                     for index, home in enumerate(homes)]])

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "incomplete",
        "scope": ("Actual current QUIC library class/JAR identity, minimized-bundle "
                  "crypto/retained-library/runtime/notice identity and JDK21/JDK25 "
                  "origin-checked handshake smoke; no timing, whole-proxy security, "
                  "deployment identity or expert-review claim"),
        "repository_root": str(repository_root),
        "tool_root": str(tool_root_path),
        "inputs": {
            "stage": str(stage_path),
            "classes": str(classes_path),
            "library": str(library_path),
            "bundle": str(bundle_path),
            "runtime": str(runtime_path),
            "java_homes": [str(home) for home in homes],
        },
        "commands": [],
    }
    report_path = output_path / "report.json"
    _atomic_write_json(report_path, report)

    manifest_path = tool_root_path / "formal/crypto/delivery.json"
    delivery_tool = tool_root_path / "formal/crypto/delivery.py"
    bundle_tool = tool_root_path / "formal/crypto/bundle_checks.py"
    try:
        _require(manifest_path.is_file(), f"missing delivery manifest: {manifest_path}")
        _require(delivery_tool.is_file(), f"missing delivery tool: {delivery_tool}")
        _require(bundle_tool.is_file(), f"missing bundle tool: {bundle_tool}")
        manifest = _load_json(manifest_path, "delivery manifest")
        runtime_sha = digest(runtime_path)
        _require(runtime_sha == manifest.get("runtime", {}).get("sha256"),
                 "supplied runtime does not match the delivery manifest pin")
        library_sha = digest(library_path)
        bundle_sha = digest(bundle_path)

        majors = [_jdk_major(home, report, output_path,
                             label=f"jdk-{index}-version", timeout=timeout)
                  for index, home in enumerate(homes)]
        _require(set(majors) == EXPECTED_JDK_MAJORS,
                 f"JDK homes reported {sorted(set(majors))}, expected 21 and 25")
        jdks = {major: home for major, home in zip(majors, homes)}
        # delivery.reproduce_stage and bundle_checks both compile with the
        # stage receipt's jdk_home.  Bind that metadata to the operator's
        # explicit trusted JDK21 (and its audited tool_tree) before any
        # artifact subprocess can execute.
        stage_receipt, stage_receipt_path = _check_stage(
            stage_path, manifest_path, manifest, trusted_jdk21=jdks["21"])
        stage_receipt_sha = digest(stage_receipt_path)

        tool_paths = [Path(__file__).resolve(), delivery_tool, bundle_tool]
        nonce_smoke_tool = tool_root_path / NONCE_SMOKE_SOURCE
        _require(nonce_smoke_tool.is_file(),
                 f"missing nonce execution smoke harness: {nonce_smoke_tool}")
        tool_paths.append(nonce_smoke_tool)
        release_tool = tool_root_path / "scripts/security/check_crypto_release.py"
        if release_tool.is_file():
            tool_paths.append(release_tool)
        tool_hashes = {path.relative_to(tool_root_path).as_posix(): digest(path)
                       for path in tool_paths if path.is_relative_to(tool_root_path)}
        for name in ("formal/crypto/delivery.py", "formal/crypto/bundle_checks.py"):
            _require(name in tool_hashes,
                     f"tool checkout does not provide {name}")
        snapshot = {
            "library": library_sha,
            "bundle": bundle_sha,
            "runtime": runtime_sha,
            "stage_receipt": stage_receipt_sha,
            "manifest": digest(manifest_path),
            "classes": _snapshot_tree(classes_path),
            "tools": {str(path): digest(path) for path in tool_paths},
        }
        report["inputs"].update({
            "library_sha256": library_sha,
            "bundle_sha256": bundle_sha,
            "runtime_sha256": runtime_sha,
            "stage_receipt_sha256": stage_receipt_sha,
            "delivery_manifest_sha256": snapshot["manifest"],
            "classes_tree_sha256": _tree_digest(snapshot["classes"]),
        })
        report["tools"] = tool_hashes
        report["java_homes"] = {major: str(home) for major, home in jdks.items()}
        _atomic_write_json(report_path, report)

        delivery_result = _run(
            report, output_path,
            [sys.executable, delivery_tool, "check", "--stage", stage_path,
             "--classes", classes_path, "--jar", library_path,
             "--runtime", runtime_path, "--java-home", jdks["21"]],
            label="delivery-check", timeout=timeout, cwd=tool_root_path)
        delivery_receipt_path = output_path / "delivery-check.json"
        _atomic_write_text(delivery_receipt_path, delivery_result.stdout)
        delivery_receipt = _load_json(delivery_receipt_path, "fresh delivery receipt")
        delivery_summary = _check_delivery_receipt(
            delivery_receipt, stage_receipt=stage_receipt,
            library_sha=library_sha, stage_sha=stage_receipt_sha)
        _require(set(delivery_summary["classes"])
                 == {name for name in snapshot["classes"] if name.endswith(".class")},
                 "fresh delivery class map differs from the actual classes tree")
        report["delivery"] = {
            "receipt": "delivery-check.json",
            "receipt_sha256": digest(delivery_receipt_path),
            "class_count": delivery_summary["class_count"],
            "generated_class_count": delivery_summary["generated_class_count"],
            "handwritten_sources": delivery_summary["handwritten_sources"],
            "stage_receipt_sha256": stage_receipt_sha,
            "jar_sha256": library_sha,
        }
        _atomic_write_json(report_path, report)

        bundle_output = output_path / "bundle-check"
        bundle_result = _run(
            report, output_path,
            [sys.executable, bundle_tool, "--library", library_path,
             "--bundle", bundle_path, "--delivery-receipt", delivery_receipt_path,
             "--stage", stage_path, "--runtime", runtime_path,
             "--java-home", jdks["21"], "--java-home", jdks["25"],
             "--output", bundle_output],
            label="bundle-check", timeout=timeout, cwd=tool_root_path)
        expected_receipt = (bundle_output / "receipt.json").resolve()
        printed = Path(bundle_result.stdout.strip()).resolve() if bundle_result.stdout.strip() else None
        _require(printed == expected_receipt,
                 "bundle check did not report its fresh receipt path")
        _require(expected_receipt.is_file(), "bundle check did not write a receipt")
        bundle_receipt = _load_json(expected_receipt, "fresh bundle receipt")
        bundle_summary = _check_bundle_receipt(
            bundle_receipt, delivery_receipt=delivery_receipt,
            library_sha=library_sha, bundle_sha=bundle_sha, runtime_sha=runtime_sha,
            delivery_receipt_sha=digest(delivery_receipt_path),
            stage_sha=stage_receipt_sha, tool_hashes=tool_hashes, java_homes=jdks)

        _check_unchanged(snapshot, classes=classes_path, library=library_path,
                         bundle=bundle_path, runtime=runtime_path,
                         stage_receipt_path=stage_receipt_path,
                         manifest_path=manifest_path)
        _require(digest(delivery_receipt_path)
                 == report["delivery"]["receipt_sha256"],
                 "fresh delivery receipt changed during bundle validation")

        report.update({
            "status": "complete",
            "delivery": {**report["delivery"],
                         "receipt_sha256": digest(delivery_receipt_path)},
            "bundle": {
                "receipt": "bundle-check/receipt.json",
                "receipt_sha256": digest(expected_receipt),
                **bundle_summary,
            },
            "report_path": str(report_path),
            "report_sha256": None,
        })
        report["report_sha256"] = _report_digest(report)
        _atomic_write_json(report_path, report)
        return report
    except ArtifactValidationError as exc:
        report.update({"status": "failed", "error": str(exc),
                       "report_path": str(report_path)})
        _atomic_write_json(report_path, report)
        raise
    except BaseException as exc:
        report.update({"status": "failed",
                       "error": f"internal artifact validator failure: "
                                f"{type(exc).__name__}: {exc}",
                       "report_path": str(report_path)})
        _atomic_write_json(report_path, report)
        raise


def _report_digest(report: dict[str, Any]) -> str:
    value = {key: item for key, item in report.items()
             if key not in {"report_sha256"}}
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()
