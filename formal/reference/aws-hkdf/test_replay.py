import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('aws_hkdf_replay', Path(__file__).with_name('replay.py'))
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)


class ReferenceGateTests(unittest.TestCase):
    def test_success_is_exactly_one_nonempty_successful_summary(self):
        self.assertEqual(replay.verified(0, 'Dafny program verifier finished with 9 verified, 0 errors'), 9)

    def test_failures_cannot_authenticate_a_successful_reference_replay(self):
        good = 'Dafny program verifier finished with 9 verified, 0 errors'
        for status, output in [(4, good), (-9, good), (0, ''), (0, good + '\n' + good),
                               (0, good.replace('9 verified', '0 verified')),
                               (0, good.replace('0 errors', '1 errors')),
                               *[(0, failure + '\n' + good) for failure in
                                 ['Verification out of resource', 'timed out', 'timeout',
                                  'inconclusive', 'internal error', 'crash', 'Error: assertion failed']]]:
            with self.subTest(status=status, output=output), self.assertRaises(ValueError):
                replay.verified(status, output)

    def test_changed_missing_dropped_and_added_dependency_inputs_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            a, b = root / 'A.dfy', root / 'B.dfy'
            a.write_text('include "B.dfy"\nmodule A {}\n')
            b.write_text('module B {}\n')
            pins = {'entry': 'A.dfy', 'inputs': {'A.dfy': replay.sha(a), 'B.dfy': replay.sha(b)},
                    'recipe_inputs': {}, 'commit': 'a' * 40, 'submodules': {}}
            with patch.object(replay.subprocess, 'check_output', return_value='a' * 40):
                replay.check_inputs(root, pins)
                b.write_text('module Changed {}\n')
                with self.assertRaises(ValueError):
                    replay.check_inputs(root, pins)
                b.write_text('module B {}\n')
                with self.assertRaises(ValueError):
                    replay.check_inputs(root, {**pins, 'inputs': {'A.dfy': replay.sha(a)}})
                b.unlink()
                with self.assertRaises(ValueError):
                    replay.check_inputs(root, pins)
                b.write_text('module B {}\n')
                a.write_text('include "B.dfy"\ninclude "C.dfy"\nmodule A {}\n')
                with self.assertRaises(ValueError):
                    replay.check_inputs(root, pins)

    def test_redirected_checkout_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / 'Real.dfy'
            real.write_text('module A {}')
            (root / 'Alias.dfy').symlink_to(real)
            for name in ['../Real.dfy', str(real), 'Alias.dfy', 'missing.dfy', 'a\\b.dfy']:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    replay.checked_path(root, name)

    def test_changed_submodule_revision_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'A.dfy').write_text('module A {}')
            pins = {'entry': 'A.dfy', 'inputs': {'A.dfy': replay.sha(root / 'A.dfy')},
                    'recipe_inputs': {}, 'commit': 'a' * 40, 'submodules': {'libraries': 'b' * 40}}
            with patch.object(replay.subprocess, 'check_output', side_effect=['a' * 40, 'c' * 40]):
                with self.assertRaises(ValueError):
                    replay.check_inputs(root, pins)

    def test_startup_failure_invalidates_an_existing_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / 'output'
            output.mkdir()
            (output / 'report.json').write_text('{"status":"complete","full_dependency_graph_verified":true}')
            (root / 'inputs.json').write_text('{ malformed')
            argv = ['replay.py', '--checkout', str(root), '--dafny', str(root / 'missing-tool'),
                    '--scope', 'closure', '--output', str(output)]
            with patch.object(replay, 'HERE', root), patch('sys.argv', argv):
                self.assertEqual(replay.main(), 1)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertFalse(report['full_dependency_graph_verified'])

    def test_target_count_cannot_close_full_dependency_graph(self):
        for minimum, count in [(None, 9), (9, 9), (10, 10), (1000, 9)]:
            with self.subTest(minimum=minimum), self.assertRaises(ValueError):
                replay.closure_verified(count, {'closure_verified_minimum': minimum, 'inputs': dict.fromkeys(range(71))})

    def test_fake_tool_with_correct_version_is_rejected_before_execution(self):
        sys.path.insert(0, str(replay.REPOSITORY / 'formal/dafny'))
        import toolchain
        pins = json.loads((replay.HERE / 'inputs.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fake = root / 'fake-dafny'
            fake.write_text('#!/bin/sh\necho "4.9.1+fake"\n')
            fake.chmod(0o755)
            official = root / 'official/dafny'
            with patch.object(toolchain, 'install', return_value=(official, None, None, {'sha256': 'a' * 64})), \
                 patch.object(replay.subprocess, 'check_output', side_effect=AssertionError('Fake tool executed')):
                with self.assertRaisesRegex(ValueError, 'checksum-pinned official'):
                    replay.check_tool(root, fake, pins)

    def test_timeout_kills_solver_child_even_when_leader_exits_on_term(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / 'child.pid'
            child = 'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)'
            leader = ('import subprocess,sys,time; from pathlib import Path; '
                      'p=subprocess.Popen([sys.executable,"-c",'+repr(child)+']); '
                      'Path('+repr(str(pid_file))+').write_text(str(p.pid)); time.sleep(60)')
            with self.assertRaises(subprocess.TimeoutExpired):
                replay.execute([sys.executable, '-c', leader], 0.5)
            pid = int(pid_file.read_text())
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                result = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], text=True, capture_output=True)
                state = result.stdout.strip()
                if not state or state.startswith('Z'):
                    break
                time.sleep(0.02)
            else:
                os.kill(pid, 9)
                self.fail('Owned solver child survived timeout cleanup')


if __name__ == '__main__':
    unittest.main()
