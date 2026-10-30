#!/usr/bin/env python3
"""Replay one scoped proof and controls against existing Java 21 class files.

Does not compile Java, download tools, or change production files.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
VACUITY = ("Contradiction detected!", "Could not determine if preconditions are vacuous")
NONCE_BLOCKER = 'TODO: invoke virtual "clone" unsupported for arrays'
CLASS_PREFIX = "quic/target/classes/"
TERMINATION_GRACE = 1.0


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def check_inputs(manifest, classes):
    actual = {}
    for name, expected in manifest["inputs"].items():
        path = classes / name[len(CLASS_PREFIX):] if name.startswith(CLASS_PREFIX) else ROOT / name
        if not path.is_file():
            raise RuntimeError(f"Missing existing build input: {path}")
        digest = sha256(path)
        if digest != expected:
            raise RuntimeError(f"Input changed; review before renewing its pin: {path}")
        actual[name] = digest
        if path.suffix == ".class":
            header = path.read_bytes()[:8]
            if header[:4] != bytes.fromhex("cafebabe") or int.from_bytes(header[6:8], "big") != 65:
                raise RuntimeError(f"Expected unmodified Java 21 class file: {path}")
    return actual


def stop_process_group(process):
    """Give the whole owned session a bounded grace period, then kill it."""
    try:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + TERMINATION_GRACE
        while time.monotonic() < deadline:
            process.poll()  # Reap the leader even if a descendant is still alive.
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(min(0.02, max(0, deadline - time.monotonic())))
    finally:
        # Run even if cleanup itself is interrupted. A descendant may survive
        # TERM after its leader exits, so checking only returncode is insufficient.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=TERMINATION_GRACE)


def execute(command, env, log, timeout):
    start = time.monotonic()
    # A file avoids communicate() waiting forever on inherited descendant pipes.
    # Keep cleanup inside our lifetime instead of Popen.__exit__'s unbounded wait.
    with log.open("w") as stream:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        message = ""
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            status = 124
            message = "\nRunner timeout: process group terminated.\n"
        except BaseException:
            message = "\nRunner interrupted before completion.\n"
            raise
        finally:
            stop_process_group(process)
            stream.write(message)
    output = log.read_text()
    return {"command": command, "exit_code": status,
            "seconds": round(time.monotonic() - start, 3), "log": str(log)}, output


def extracted_jdk(java_home, cache, digest, env, log, timeout):
    destination = cache / "saw-jdk21" / digest
    marker = destination / ".complete"
    if not marker.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(dir=destination.parent))
        try:
            run, _ = execute([str(java_home / "bin/jimage"), "extract", "--dir", str(temp),
                              str(java_home / "lib/modules")], env, log, timeout)
            if run["exit_code"] != 0:
                raise RuntimeError(f"JDK extraction failed; inspect {log}")
            (temp / ".complete").write_text(digest + "\n")
            if destination.exists():
                raise RuntimeError(f"Inspect incomplete JDK extraction: {destination}")
            temp.rename(destination)
        finally:
            shutil.rmtree(temp, ignore_errors=True)
    if marker.read_text().strip() != digest:
        raise RuntimeError(f"JDK extraction marker mismatch: {destination}")
    return destination


def write_report(path, report):
    """Publish a whole report atomically, including the initial invalidation."""
    fd, name = tempfile.mkstemp(prefix=".report-", suffix=".json", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(json.dumps(report, indent=2) + "\n")
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def replay(args, report, report_path):
    saw, java_home, output = args.saw.resolve(), args.java_home.resolve(), args.output.resolve()
    manifest = json.loads((HERE / "inputs.json").read_text())
    origin = args.classes.resolve()
    inputs = check_inputs(manifest, origin)
    # Use an isolated copy so a concurrent Maven build cannot change proof inputs.
    classes = Path(tempfile.mkdtemp(prefix="classes-", dir=output))
    shutil.copytree(origin, classes, dirs_exist_ok=True)
    if check_inputs(manifest, origin) != inputs or check_inputs(manifest, classes) != inputs:
        raise RuntimeError("Class files changed during snapshot creation")
    env = dict(os.environ, PATH=str(saw.parent) + os.pathsep + os.environ.get("PATH", ""))
    version_run, version = execute([str(saw), "--version"], env, output / "saw-version.log", args.timeout)
    report["setup"] = {"saw_version": version_run}
    if version_run["exit_code"] != 0:
        raise RuntimeError(f"SAW version check failed; inspect {version_run['log']}")
    version = version.strip()
    if version != manifest["saw"]["version"]:
        raise RuntimeError(f"Expected {manifest['saw']['version']}; found {version}")
    modules_digest = sha256(java_home / "lib/modules")
    saw_digest = sha256(saw)
    jdk = extracted_jdk(java_home, args.cache.resolve(), modules_digest, env,
                        output / "jdk-extraction.log", args.timeout)
    classpath = os.pathsep.join([str(classes)] + [str(p) for p in sorted(jdk.iterdir()) if p.is_dir()])
    report.update({"saw_version": version, "saw_binary_sha256": saw_digest,
                   "jdk_modules_sha256": modules_digest, "jdk_classes": str(jdk),
                   "class_origin": str(origin), "class_snapshot": str(classes),
                   "inputs": inputs})
    cases = [("proof", "mlkem-reduce-once.saw"),
             ("wrong_modulus", "controls/wrong-modulus.saw"),
             ("vacuous", "controls/vacuous.saw"),
             ("nonce", "blocked/packet-key-nonce.saw")]
    for name, script in cases:
        summary_path = output / f"{name}.summary.json"
        summary_path.unlink(missing_ok=True)  # Never reuse a stale successful summary.
        command = [str(saw), "--no-color", "--detect-vacuity", "-f", "json",
                   "-s", str(summary_path), "-b", str(java_home / "bin"),
                   "-c", classpath, str(HERE / script)]
        report["runs"][name] = {"command": command, "result": "incomplete",
                                 "log": str(output / f"{name}.log")}
        write_report(report_path, report)
        run, log = execute(command, env, output / f"{name}.log", args.timeout)
        report["runs"][name] = run
        summary = json.loads(summary_path.read_text()) if summary_path.exists() else []
        run["saw_summary"] = summary
        if name == "proof":
            methods = [item for item in summary if item.get("type") == "method"]
            valid = (run["exit_code"] == 0 and "Sat:" in log
                     and not any(marker in log for marker in VACUITY) and len(methods) == 1
                     and methods[0].get("method") == "io/github/mahmoudimus/quic/tls/MlKem768.reduceOnce"
                     and methods[0].get("status") == "verified" and methods[0].get("dependencies") == []
                     and bool(methods[0].get("vcs"))
                     and all(vc.get("status") == "verified" and not vc.get("dependencies")
                             for vc in methods[0]["vcs"]))
            result = "verified"
        elif name == "wrong_modulus":
            valid = (run["exit_code"] == 2 and "Counterexample" in log and "a:" in log
                     and "Literal equality postcondition" in log and "Proof failed." in log
                     and "simulating function" in log and not any(marker in log for marker in VACUITY))
            result = "proof_counterexample"
        elif name == "vacuous":
            valid = (run["exit_code"] == 0 and "Contradiction detected!" in log
                     and "proofs may be vacuous" in log)
            result = "rejected_vacuous_specification"
        else:
            valid = run["exit_code"] == 2 and NONCE_BLOCKER in log
            result = "blocked_by_array_clone_translation"
        run["result"] = result if valid else "unexpected_failure"
        report["runs"][name] = run
        write_report(report_path, report)
        print(f"{name}: {run['result']} ({run['seconds']}s)", flush=True)
        if not valid:
            raise RuntimeError(f"Unexpected {name} result; inspect {run['log']}")
    check_inputs(manifest, classes)
    if sha256(saw) != saw_digest:
        raise RuntimeError("SAW binary changed during replay")
    if sha256(java_home / "lib/modules") != modules_digest:
        raise RuntimeError("JDK modules changed during replay")
    report["status"] = "complete"
    write_report(report_path, report)
    print(f"One bytecode method verified; nonce remains blocked. Evidence: {report_path}")


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--saw", type=Path, required=True, help="SAW 1.6, with bundled solvers beside it")
    parser.add_argument("--java-home", type=Path, required=True, help="JDK 21 home")
    parser.add_argument("--classes", type=Path, default=ROOT / "target/saw-reference-classes")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/microproxy-formal")
    parser.add_argument("--output", type=Path, default=HERE / "evidence")
    parser.add_argument("--timeout", type=int, default=90, help="Seconds per subprocess")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    report = {"status": "incomplete", "scope":
              "pre-adoption Java 21 MlKem768.reduceOnce for 0 <= a < 6658; PacketKey.nonce remains blocked",
              "runs": {}}
    # Invalidate a previous success before parsing or checking any replay input.
    write_report(report_path, report)
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        if args.timeout <= 0:
            raise ValueError("--timeout must be positive")
        replay(args, report, report_path)
    except BaseException as error:
        report["status"] = "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        write_report(report_path, report)
        raise
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    main()
