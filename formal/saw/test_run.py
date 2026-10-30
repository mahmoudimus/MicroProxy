"""Regression tests for runner evidence and subprocess lifetime boundaries.

Run with: python3 -m unittest discover -s formal/saw -p 'test_*.py' -v
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


RUNNER = Path(__file__).with_name("run.py")


def assert_processes_stopped(test, pids):
    for pid in pids:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                   capture_output=True, text=True).stdout.strip()
            if not state or state.startswith("Z"):
                break
            time.sleep(0.01)
        else:
            test.fail(f"Process {pid} survived runner cleanup")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.here = self.root / "formal/saw"
        self.here.mkdir(parents=True)
        shutil.copyfile(RUNNER, self.here / "run.py")
        self.source = self.root / "input.java"
        self.source.write_text("pinned source\n")
        self.classes = self.root / "classes"
        self.classes.mkdir()
        (self.classes / "Input.class").write_bytes(bytes.fromhex("cafebabe00000041"))
        manifest = {"saw": {"version": "test SAW"}, "inputs": {
            "input.java": hashlib.sha256(self.source.read_bytes()).hexdigest(),
            "quic/target/classes/Input.class": hashlib.sha256(
                (self.classes / "Input.class").read_bytes()).hexdigest()}}
        (self.here / "inputs.json").write_text(json.dumps(manifest))
        self.java = self.root / "jdk"
        (self.java / "lib").mkdir(parents=True)
        (self.java / "lib/modules").write_bytes(b"test modules")
        digest = hashlib.sha256(b"test modules").hexdigest()
        self.cache = self.root / "cache"
        extracted = self.cache / "saw-jdk21" / digest
        (extracted / "java.base").mkdir(parents=True)
        (extracted / ".complete").write_text(digest + "\n")
        self.output = self.root / "evidence"
        self.output.mkdir()
        self.report = self.output / "report.json"
        self.saw = self.root / "saw"
        self.saw.write_text("#!" + sys.executable + "\n" + '''
import json, os, pathlib, signal, subprocess, sys, time
if sys.argv[1:] == ["--version"]:
    print("test SAW")
    raise SystemExit(0)
summary = pathlib.Path(sys.argv[sys.argv.index("-s") + 1])
case = pathlib.Path(sys.argv[-1]).name
observed = summary.parent / "observed-reports.jsonl"
with observed.open("a") as stream:
    stream.write((summary.parent / "report.json").read_text().replace("\\n", " ") + "\\n")
if case == "mlkem-reduce-once.saw":
    if os.environ.get("BLOCK_PROOF"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen([sys.executable, "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"])
        pathlib.Path(os.environ["BLOCK_PROOF"]).write_text(json.dumps([os.getpid(), child.pid]))
        time.sleep(60)
    summary.write_text(json.dumps([{"type": "method", "method":
        "io/github/mahmoudimus/quic/tls/MlKem768.reduceOnce", "status": "verified",
        "dependencies": [], "vcs": [{"status": "verified", "dependencies": []}]}]))
    print("Sat: a = 1")
elif case == "wrong-modulus.saw":
    print("Counterexample a: Literal equality postcondition simulating function Proof failed.")
    raise SystemExit(2)
elif case == "vacuous.saw":
    print("Contradiction detected! proofs may be vacuous")
elif case == "packet-key-nonce.saw":
    if os.environ.get("MUTATE_INPUT"):
        pathlib.Path(os.environ["MUTATE_INPUT"]).write_text("changed during proof\\n")
    print('TODO: invoke virtual "clone" unsupported for arrays')
    raise SystemExit(2)
''')
        self.saw.chmod(0o755)

    def command(self):
        return [sys.executable, str(self.here / "run.py"),
                "--saw", str(self.saw), "--java-home", str(self.java),
                "--classes", str(self.classes), "--cache", str(self.cache),
                "--output", str(self.output)]

    def invoke(self, **extra_env):
        return subprocess.run(self.command(), env=dict(os.environ, **extra_env), capture_output=True,
                              text=True, timeout=10)

    def stale_success(self):
        self.report.write_text(json.dumps({"status": "complete", "runs": {
            "proof": {"result": "verified"}}}))

    def test_invalid_initial_input_replaces_previous_success(self):
        for invalid in ("missing", "changed"):
            with self.subTest(invalid=invalid):
                self.stale_success()
                if invalid == "missing":
                    self.source.unlink()
                else:
                    self.source.write_text("changed source\n")
                result = self.invoke()
                self.assertNotEqual(0, result.returncode)
                report = json.loads(self.report.read_text())
                self.assertEqual("failed", report["status"])
                self.assertEqual({}, report["runs"])
                self.assertIn("input", report["error"]["message"].lower())

    def test_unreadable_manifest_replaces_previous_success(self):
        self.stale_success()
        (self.here / "inputs.json").unlink()
        result = self.invoke()
        self.assertNotEqual(0, result.returncode)
        report = json.loads(self.report.read_text())
        self.assertEqual("failed", report["status"])
        self.assertEqual("FileNotFoundError", report["error"]["type"])

    def test_final_validation_failure_never_publishes_completion(self):
        self.stale_success()
        result = self.invoke(MUTATE_INPUT=str(self.source))
        self.assertNotEqual(0, result.returncode)
        report = json.loads(self.report.read_text())
        self.assertEqual("failed", report["status"])
        self.assertEqual("verified", report["runs"]["proof"]["result"])
        self.assertIn("Input changed", report["error"]["message"])
        observed = [json.loads(line) for line in
                    (self.output / "observed-reports.jsonl").read_text().splitlines()]
        self.assertEqual(4, len(observed))
        self.assertTrue(all(report["status"] == "incomplete" for report in observed))

    def test_success_is_complete_only_after_all_controls(self):
        result = self.invoke()
        self.assertEqual(0, result.returncode, result.stderr)
        report = json.loads(self.report.read_text())
        self.assertEqual("complete", report["status"])
        self.assertEqual({"proof", "wrong_modulus", "vacuous", "nonce"}, set(report["runs"]))
        self.assertEqual("blocked_by_array_clone_translation", report["runs"]["nonce"]["result"])

    def test_changed_runtime_never_publishes_completion(self):
        for target, error in ((self.saw, "SAW binary changed"),
                              (self.java / "lib/modules", "JDK modules changed")):
            with self.subTest(target=target):
                original = target.read_bytes()
                try:
                    result = self.invoke(MUTATE_INPUT=str(target))
                    self.assertNotEqual(0, result.returncode)
                    report = json.loads(self.report.read_text())
                    self.assertEqual("failed", report["status"])
                    self.assertIn(error, report["error"]["message"])
                finally:
                    target.write_bytes(original)

    @unittest.skipUnless(os.name == "posix", "Runner process groups require POSIX")
    def test_sigterm_records_interruption_and_cleans_process_group(self):
        pids_path = self.root / "blocked-pids.json"
        process = subprocess.Popen(self.command(), env=dict(os.environ, BLOCK_PROOF=str(pids_path)),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, start_new_session=True)
        pids = []
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not pids_path.exists():
                time.sleep(0.01)
            self.assertTrue(pids_path.exists(), "Proof process did not start")
            pids = json.loads(pids_path.read_text())
            process.send_signal(signal.SIGTERM)
            output, _ = process.communicate(timeout=4)
            self.assertEqual(143, process.returncode, output)
            report = json.loads(self.report.read_text())
            self.assertEqual("interrupted", report["status"])
            self.assertEqual("SystemExit", report["error"]["type"])
            self.assertEqual("incomplete", report["runs"]["proof"]["result"])
            assert_processes_stopped(self, pids)
        finally:
            if pids:
                try:
                    os.killpg(pids[0], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)


@unittest.skipUnless(os.name == "posix", "Runner process groups require POSIX")
class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pids = self.root / "pids.json"
        # Both processes ignore TERM and inherit the runner's output destination.
        self.child = self.root / "child.py"
        self.child.write_text('''
import json, os, pathlib, signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
descendant = subprocess.Popen([sys.executable, "-c",
    "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"])
pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(), descendant.pid]))
print("child ready", flush=True)
time.sleep(60)
''')
        self.driver = self.root / "driver.py"
        self.driver.write_text('''
import importlib.util, json, os, pathlib, sys
spec = importlib.util.spec_from_file_location("saw_runner", sys.argv[1])
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
try:
    result, output = runner.execute([sys.executable, sys.argv[2], sys.argv[3]],
        dict(os.environ), pathlib.Path(sys.argv[4]), float(sys.argv[5]))
    print(json.dumps(result))
except KeyboardInterrupt:
    print("interrupted")
''')

    def start_driver(self, timeout):
        process = subprocess.Popen([sys.executable, str(self.driver), str(RUNNER),
                                    str(self.child), str(self.pids), str(self.root / "run.log"),
                                    str(timeout)], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, start_new_session=True)
        self.addCleanup(self.cleanup_processes, process)
        return process

    def cleanup_processes(self, driver):
        if self.pids.exists():
            try:
                os.killpg(json.loads(self.pids.read_text())[0], signal.SIGKILL)
            except ProcessLookupError:
                pass
        if driver.poll() is None:
            os.killpg(driver.pid, signal.SIGKILL)
        driver.communicate(timeout=3)

    def wait_ready(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.pids.exists():
                return json.loads(self.pids.read_text())
            time.sleep(0.01)
        self.fail("Child did not publish process IDs")

    def assert_children_stopped(self):
        assert_processes_stopped(self, json.loads(self.pids.read_text()))

    def test_timeout_kills_term_ignoring_process_and_descendant(self):
        process = self.start_driver(0.3)
        self.wait_ready()
        try:
            output, _ = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("Runner did not bound cleanup after SIGTERM was ignored")
        self.assertEqual(0, process.returncode, output)
        self.assertEqual(124, json.loads(output)["exit_code"])
        self.assertIn("child ready", (self.root / "run.log").read_text())
        self.assert_children_stopped()

    def test_interrupt_cleans_detached_process_group(self):
        process = self.start_driver(60)
        self.wait_ready()
        process.send_signal(signal.SIGINT)
        try:
            output, _ = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            self.fail("Runner did not finish interruption cleanup")
        self.assertEqual(0, process.returncode, output)
        self.assertIn("interrupted", output)
        self.assert_children_stopped()


if __name__ == "__main__":
    unittest.main()
