"""Admission and diagnostic regressions for the actual SHAKE API proof replay."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class ReplayTests(unittest.TestCase):
    def module(self):
        path = Path(__file__).with_name('replay.py')
        self.assertTrue(path.is_file(), 'SHAKE API replay implementation is missing')
        spec = importlib.util.spec_from_file_location('shake_api_replay_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_missing_included_source_is_rejected(self):
        r = self.module()
        sources = {r.ENTRY: 'a' * 64, 'formal/crypto/NativeShake.dfy': 'b' * 64}
        inputs = {**sources, **{p: 'c' * 64 for p in r.REPLAY_INPUTS}}
        r.check_inventory(sources, inputs)
        for omitted in inputs:
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                r.check_inventory(sources, {k: v for k, v in inputs.items() if k != omitted})
        with self.assertRaises(ValueError):
            r.check_inventory(sources, {**inputs, 'extra': 'd' * 64})

    def test_parser_closure_uses_both_roots_and_retains_includes(self):
        r = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            calls = []
            def discover(actual_root, entry, dafny, **kwargs):
                calls.append(entry.relative_to(actual_root).as_posix())
                return {calls[-1]: 'a' * 64, 'Hidden.dfy': 'b' * 64}
            graph = r.discover_graph(root, 'dafny', discover)
            self.assertEqual(calls, [r.ENTRY, r.CONTROL_ENTRY])
            self.assertEqual(set(graph), {r.ENTRY, r.CONTROL_ENTRY, 'Hidden.dfy'})
            def fail(*args, **kwargs):
                raise ValueError('parser rejected include')
            with self.assertRaisesRegex(ValueError, 'parser rejected'):
                r.discover_graph(root, 'dafny', fail)

    def test_conflicting_parser_snapshots_are_rejected(self):
        r = self.module()
        n = iter(('a', 'b'))
        def discover(*args, **kwargs):
            return {'same.dfy': next(n) * 64}
        with self.assertRaisesRegex(ValueError, 'changed'):
            r.discover_graph(Path('/repo'), 'dafny', discover)

    def test_omitting_a_discovered_include_from_manifest_is_rejected(self):
        r = self.module()
        actual = {r.ENTRY: 'a' * 64, 'Hidden.dfy': 'b' * 64}
        r.check_graph(actual, actual)
        with self.assertRaises(ValueError):
            r.check_graph(actual, {r.ENTRY: 'a' * 64})

    def test_source_drift_and_unsafe_paths_are_rejected(self):
        r = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'source.dfy'
            source.write_text('module Good {}')
            pins = {'source.dfy': r.sha(source)}
            r.check_pins(root, pins)
            source.write_text('module Changed {}')
            with self.assertRaises(ValueError):
                r.check_pins(root, pins)
            (root / 'alias.dfy').symlink_to(source)
            (root / 'linked').symlink_to(root, target_is_directory=True)
            for path in ('../source.dfy', str(source), 'alias.dfy', 'linked/source.dfy'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    r.check_pins(root, {path: r.sha(source)})

    def test_output_refusal_preserves_existing_contents_and_dangling_links(self):
        r = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'repo'
            root.mkdir()
            out = root.parent / 'out'
            out.mkdir()
            sentinel = out / 'sentinel'
            sentinel.write_text('preserve')
            with self.assertRaises(ValueError):
                r.admit_output(root, out)
            self.assertEqual(sentinel.read_text(), 'preserve')
            dangling = root.parent / 'dangling'
            dangling.symlink_to(root.parent / 'missing')
            with self.assertRaises(ValueError):
                r.admit_output(root, dangling)
            self.assertTrue(dangling.is_symlink())
            with self.assertRaises(ValueError):
                r.admit_output(root, root / 'assurance' / 'out')
            self.assertFalse((root / 'assurance').exists())
            fresh = r.admit_output(root, root.parent / 'fresh')
            self.assertTrue(fresh.is_dir())

    def test_positive_requires_exact_included_body_count(self):
        r = self.module()
        good = 'Dafny program verifier finished with 123 verified, 0 errors\n'
        self.assertEqual(r.proof_result(0, good, 123), {'verified': 123, 'errors': 0})
        for status, text in ((0, good.replace('123', '20')), (4, good),
                             (0, good + good), (0, good + 'Internal error: crashed'),
                             (0, good + 'Unhandled exception'),
                             (0, good + 'System.NullReferenceException: failed'),
                             (0, good + 'Verification out of resources'),
                             (0, good + 'Error: invalid proof'),
                             (0, good + 'warning: ignored'),
                             (0, good + 'CASE-TIMEOUT')):
            with self.subTest(status=status, text=text), self.assertRaises(ValueError):
                r.proof_result(status, text, 123)

    def test_negative_requires_exact_assertion_location_and_exit(self):
        r = self.module()
        anchor = 'assert !s.squeezing;'
        expected = (r.CONTROL_ENTRY, 17, anchor)
        good = (r.CONTROL_ENTRY + '(17,5): Error: assertion might not hold\n'
                '17 | ' + anchor + '\n'
                'Dafny program verifier finished with 1 verified, 1 error\n')
        self.assertEqual(r.proof_result(4, good, 1, negative=expected)['errors'], 1)
        bad = [(0, good), (4, good.replace('(17,5)', '(18,5)')),
               (4, good.replace(r.CONTROL_ENTRY, 'Other.dfy')),
               (4, good.replace(anchor, 'assert unrelated;')),
               (4, good.replace('assertion might not hold', 'a precondition could not be proved')),
               (4, good.replace('1 verified, 1 error', '2 verified, 2 errors')),
               (4, good + 'Internal error: crashed'), (4, good + 'CASE-TIMEOUT'),
               (4, good + 'Unhandled exception')]
        for status, text in bad:
            with self.subTest(status=status, text=text), self.assertRaises(ValueError):
                r.proof_result(status, text, 1, negative=expected)

    def test_selected_false_method_can_have_zero_verified_and_one_error(self):
        r = self.module()
        text = (r.CONTROL_ENTRY + '(17,5): Error: assertion might not hold\n'
                '17 | assert !s.squeezing;\n'
                'Dafny program verifier finished with 0 verified, 1 error\n')
        result = r.proof_result(4, text, 0,
            negative=(r.CONTROL_ENTRY, 17, 'assert !s.squeezing;'))
        self.assertEqual(result, {'verified': 0, 'errors': 1})
        with self.assertRaises(ValueError):
            r.proof_result(0, 'Dafny program verifier finished with 0 verified, 0 errors\n', 0)

    def test_injected_included_assumption_requires_exact_audit_finding(self):
        r = self.module()
        anchor = 'Xof: Definition has `assume {:axiom}` statement in body'
        text = 'NativeShake.dfy(20,5): Warning: ' + anchor + '\nDafny auditor completed with 1 finding\n'
        self.assertEqual(r.audit_result(0, text, expected=1, anchor=anchor), 1)
        for bad in (text.replace('Xof:', 'Other:'), text + 'Warning: unrelated diagnostic',
                    text + 'System.NullReferenceException'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                r.audit_result(0, bad, expected=1, anchor=anchor)

    def test_audit_requires_every_discovered_file_and_zero_findings(self):
        r = self.module()
        clean = 'Dafny auditor completed with 0 findings\n'
        graph = {'Entry.dfy': 'a' * 64, 'Included.dfy': 'b' * 64}
        records = {p: {'findings': r.audit_result(0, clean)} for p in graph}
        r.check_audits(graph, records)
        with self.assertRaises(ValueError):
            r.check_audits(graph, {'Entry.dfy': records['Entry.dfy']})
        for status, text in ((0, clean + clean), (1, clean),
                             (0, clean.replace('0 findings', '1 finding')),
                             (0, clean + 'Unhandled exception'), (0, clean + 'Error: crash')):
            with self.subTest(status=status, text=text), self.assertRaises(ValueError):
                r.audit_result(status, text)

    def test_manifest_cannot_change_during_replay(self):
        r = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / 'inputs.json'
            path.write_bytes(b'original')
            r.check_manifest(path, b'original')
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                r.check_manifest(path, b'original')

    def test_main_failure_retains_failed_report(self):
        r = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'repo'
            root.mkdir()
            out = root.parent / 'run'
            with patch.object(r, 'ROOT', root), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(r.main(['--output', str(out)]), 1)
            report = json.loads((out / 'report.json').read_text())
            self.assertEqual(report['status'], 'FAILED')
            self.assertEqual(report['error_type'], 'ValueError')
            self.assertEqual(report['commands'], [])

    def test_main_existing_output_rejects_without_mutation(self):
        r = self.module()
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory).resolve() / 'existing'
            out.mkdir()
            sentinel = out / 'report.json'
            sentinel.write_text('preserve')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(r.main(['--output', str(out)]), 1)
            self.assertEqual(sentinel.read_text(), 'preserve')

    def test_timeout_preserves_partial_output_and_is_not_a_counterexample(self):
        r = self.module()
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'timeout.log'
            import sys
            status, output = r.execute([sys.executable, '-u', '-c',
                'import time; print("partial tool output",flush=True); time.sleep(10)'],
                log, Path(directory), timeout=0.2)
            self.assertEqual(status, 124)
            self.assertIn('partial tool output', output)
            self.assertIn('CASE-TIMEOUT', output)
            self.assertEqual(log.read_text(), output)


if __name__ == '__main__':
    unittest.main()
