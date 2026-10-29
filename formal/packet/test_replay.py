import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
from argparse import Namespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('packet_runner', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ReplayTrust(unittest.TestCase):
    def test_evidence_or_cache_inside_cleaned_output_is_rejected_before_tools(self):
        cleaned = runner.ROOT / 'quic/target/proof-output'
        with tempfile.TemporaryDirectory() as name:
            outside = Path(name)
            for evidence, cache in ((cleaned, outside), (outside, cleaned)):
                with self.subTest(evidence=evidence), patch.object(runner.shared, 'install') as install:
                    with self.assertRaisesRegex(RuntimeError, 'outside the cleaned'):
                        runner.pipeline(Namespace(cache=cache), evidence)
                    install.assert_not_called()

    def test_module_clean_preserves_parent_evidence_and_removes_stale_classes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            parent = '''<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>
              <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>
              <modules><module>quic</module></modules><build><plugins><plugin>
              <groupId>org.apache.maven.plugins</groupId><artifactId>maven-clean-plugin</artifactId>
              <version>3.2.0</version></plugin></plugins></build></project>'''
            (root / 'pom.xml').write_text(parent)
            (root / 'quic').mkdir()
            (root / 'quic/pom.xml').write_text('''<project><modelVersion>4.0.0</modelVersion>
              <parent><groupId>test</groupId><artifactId>parent</artifactId><version>1</version></parent>
              <artifactId>quic</artifactId></project>''')
            evidence = root / 'target/packet-verification/report.json'
            evidence.parent.mkdir(parents=True)
            evidence.write_text('{"status":"incomplete"}')
            stale = root / 'quic/target/classes/Stale.class'
            stale.parent.mkdir(parents=True)
            stale.write_text('stale')
            subprocess.run(runner.module_clean_command(), cwd=root, capture_output=True,
                           text=True, check=True, timeout=60)
            self.assertTrue(evidence.is_file(), 'clean removed active parent evidence')
            self.assertFalse(stale.exists(), 'production classes were not rebuilt from a clean output')

    def test_setup_failure_invalidates_old_success(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'report.json').write_text('{"status":"complete"}')
            with patch.object(runner, 'pipeline', side_effect=RuntimeError('changed input')):
                self.assertEqual(1, runner.main(['--output', name]))
            self.assertEqual('failed', json.loads((root / 'report.json').read_text())['status'])

    def test_interruption_leaves_incomplete_report(self):
        with tempfile.TemporaryDirectory() as name:
            with patch.object(runner, 'pipeline', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    runner.main(['--output', name])
            self.assertEqual('incomplete', json.loads((Path(name) / 'report.json').read_text())['status'])

    def test_bad_report_metadata_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            with patch.object(runner, 'pipeline', return_value={'status':'complete', 'bad':object()}):
                self.assertEqual(1, runner.main(['--output', name]))
            self.assertEqual('failed', json.loads((Path(name) / 'report.json').read_text())['status'])

    def test_only_zero_audit_findings_are_accepted(self):
        runner.zero_audit(0, 'Dafny auditor completed with 0 findings')
        for status, text in ((0, ''), (0, 'Dafny auditor completed with 1 findings'),
                             (1, 'Dafny auditor completed with 0 findings'),
                             (0, 'Warning: admitted\nDafny auditor completed with 0 findings')):
            with self.assertRaises(RuntimeError):
                runner.zero_audit(status, text)

    def test_domain_harness_covers_all_declared_lengths_and_shifts(self):
        source = runner.domain_harness(Path('/tmp/Kernel.dfy'))
        self.assertIn('requires 1 <= length <= 4', source)
        self.assertIn('requires count < 64', source)
        self.assertNotIn('requires length ==', source)
        for name in ('Decode', 'ReadPrefix', 'Unprotect', 'ShiftLeft', 'ShiftRight', 'Less', 'SignedLess'):
            self.assertIn('K.' + name + '(', source)

    def test_ir_harness_carries_actual_program_and_input_domain(self):
        program = {'inputs': 1, 'nodes': [(1, 0, 0, 0), (2, 0, 0, 0)], 'output': 1, 'opcodes': []}
        source = runner.trace_harness(Path('/tmp/Trace.dfy'), {'Decode': program})
        self.assertIn('T.Node(2,0,0,0)', source)
        self.assertIn('T.Valid(CodeDecode(),1,0)', source)
        self.assertIn('T.TwoRun(', source)

    def test_changed_class_invalidates_its_certificate(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'Kernel.class'
            path.write_bytes(b'original')
            pinned = {path: runner.shared.digest(path)}
            runner.check_classes(pinned)
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'Class changed'):
                runner.check_classes(pinned)


if __name__ == '__main__':
    unittest.main()
