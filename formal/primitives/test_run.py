import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('primitives_replay', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ReplayGates(unittest.TestCase):
    def test_marker_write_failure_removes_old_success(self):
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / 'report.json'
            report.write_text('{"status":"complete"}')
            with patch.object(runner.shared, 'atomic_report', side_effect=OSError('disk full')):
                with self.assertRaises(OSError):
                    runner.main(['--output', folder])
            self.assertFalse(report.exists(), 'old success survived failed marker creation')

    def test_round_omission_control_changes_executable_loop_only(self):
        source = (runner.HERE / 'Keccak.dfy').read_text()
        mutant = runner.mutations('Keccak', source)['round-count']
        self.assertIn('for i := 0 to 23', mutant)
        self.assertIn('ensures r == S.Iter(a, 24)', mutant)
        self.assertIn('assert completed == 24;', mutant)

    def test_audit_rejects_skipped_proof_or_extra_assumption(self):
        runner.zero_audit(0, 'Dafny auditor completed with 0 findings')
        for code, text in ((1, ''), (0, 'Dafny auditor completed with 1 findings'),
                           (0, 'Warning: skipped proof\nDafny auditor completed with 0 findings')):
            with self.subTest(code=code, text=text), self.assertRaises(RuntimeError):
                runner.zero_audit(code, text)

    def test_changed_mutation_anchors_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'anchor'):
            runner.mutations('Keccak', '')
        for kernel in ('Keccak', 'Field'):
            source = (runner.HERE / (kernel + '.dfy')).read_text()
            controls = runner.mutations(kernel, source)
            self.assertGreaterEqual(len(controls), 3)
            for name, changed in controls.items():
                self.assertNotEqual(source, changed, name)

    def test_domains_cover_all_declared_entry_points(self):
        text = runner.domain_harness(runner.HERE)
        for name in ('Permute', 'Rotate', 'ReduceOnce', 'Reduce', 'Add', 'Sub', 'Mul', 'MulSub', 'AddMul'):
            self.assertIn('.' + name + '(', text)
        self.assertNotIn('requires false', text)
        self.assertIn('22154496', text)
        self.assertIn('|s| == 25', text)

    def test_partial_or_unrelated_java_output_cannot_pass(self):
        valid = {key: minimum for key, minimum in runner.JAVA_MINIMUMS.items()}
        self.assertEqual(valid, runner.parse_tests('PASS GeneratedPrimitivesTest ' + json.dumps(valid)))
        for bad in ('PASS', 'PASS GeneratedPrimitivesTest {}',
                    'PASS GeneratedPrimitivesTest ' + json.dumps(dict(valid, one_bit_states=0)),
                    '\n'.join(['PASS GeneratedPrimitivesTest ' + json.dumps(valid)] * 2)):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                runner.parse_tests(bad)

    def test_setup_failure_invalidates_stale_success(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'report.json'
            p.write_text('{"status":"complete"}')
            with patch.object(runner, 'pipeline', side_effect=RuntimeError('changed source')):
                self.assertEqual(1, runner.main(['--output', folder]))
            self.assertEqual('failed', json.loads(p.read_text())['status'])

    def test_interruption_cannot_leave_old_success(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'report.json'
            p.write_text('{"status":"complete"}')
            with patch.object(runner, 'pipeline', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    runner.main(['--output', folder])
            self.assertEqual('incomplete', json.loads(p.read_text())['status'])

    def test_report_serialization_failure_is_a_failed_run(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(runner, 'pipeline', return_value={'status': 'complete', 'bad': Path(folder)}):
                self.assertEqual(1, runner.main(['--output', folder]))
            self.assertEqual('failed', json.loads((Path(folder)/'report.json').read_text())['status'])


if __name__ == '__main__':
    unittest.main()
