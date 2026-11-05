#!/usr/bin/env python3
"""Bounded Select admission, build-evaluation and evidence regressions."""
import argparse
import copy
import hashlib
import importlib.util
import importlib._bootstrap_external
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(Path(path).read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.work = self.work_root / self.id().split('.')[-1]
        self.work.mkdir()
        self.views = self.work / 'views'
        shutil.copytree(self.original_views, self.views)
        for path in self.views.rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        self.receipt_sha = self.original_receipt_sha

    def admit(self):
        return self.api.admit_views(self.manifest, self.manifest_sha, self.views, self.receipt_sha)

    def alter_receipt(self, mutate):
        path = self.views / 'receipt.json'
        data = json.loads(path.read_text())
        mutate(data)
        path.write_text(json.dumps(data, sort_keys=True) + '\n')
        self.receipt_sha = sha(path)

    def change(self, relative, raw=b'// changed\n'):
        path = self.views / relative
        path.write_bytes(path.read_bytes() + raw)

    def test_real_authenticated_views(self):
        result = self.admit()
        self.assertEqual(result['current_sources'], self.api.current_sources(result['manifest']))
        self.assertEqual(result['legacy_facts']['dafny_files'], 85)
        self.assertEqual(result['legacy_facts']['package_files'], 311)
        self.assertEqual(result['legacy_facts']['used_inputs'], 8)

    def test_view_receipt_external_digest_required(self):
        self.receipt_sha = '0' * 64
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_manifest_external_digest_required(self):
        with self.assertRaises(self.api.SelectError):
            self.api.admit_views(self.manifest, '0' * 64, self.views, self.receipt_sha)

    def test_receipt_success_flag_is_not_authority(self):
        self.alter_receipt(lambda d: d.update(qualification=True))
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_missing_current_source(self):
        (self.views / 'current/formal/crypto/NativeTypes.dfy').unlink()
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_extra_current_source(self):
        (self.views / 'current/formal/extra.dfy').write_text('module Extra {}')
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_fourth_current_source_change(self):
        self.change('current/formal/crypto/NativeTypes.dfy')
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_historical_source_substitution_and_self_renewed_map(self):
        relative = 'formal/crypto/NativeKeccak.dfy'
        path = self.views / 'current' / relative
        path.write_bytes((self.views / 'historical' / relative).read_bytes())
        def forge(data):
            data['views']['current']['files'][relative] = sha(path)
            data['views']['current']['sources'][relative] = sha(path)
            data['views']['current']['file_map_sha256'] = self.api.map_sha(data['views']['current']['files'])
            data['views']['current']['source_map_sha256'] = self.api.map_sha(data['views']['current']['sources'])
        self.alter_receipt(forge)
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_current_source_substituted_into_history(self):
        relative = 'formal/crypto/NativeKeccak.dfy'
        (self.views / 'historical' / relative).write_bytes((self.views / 'current' / relative).read_bytes())
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_changed_legacy_package(self):
        self.change('current/formal/source/select/package.json', b' ')
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_changed_legacy_helper(self):
        self.change('current/formal/source/select/replay.py', b'\n# changed\n')
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_changed_profile(self):
        self.change('current/formal/source/select/profiles/linux-sdk10.0.400.json', b' ')
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_changed_build_authority(self):
        self.change('current/formal/source/keccak/encoder/build_authority.py', b'\n# changed\n')
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_hardlink_source_alias(self):
        os.link(self.views / 'current/formal/crypto/NativeTypes.dfy', self.work / 'alias.dfy')
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_symlink_source_substitution(self):
        source = self.views / 'current/formal/crypto/NativeTypes.dfy'
        other = self.work / 'same-bytes.dfy'
        other.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(other)
        with self.assertRaises(self.api.SelectError):
            self.admit()

    def test_receipt_sources_map_must_match_manifest(self):
        self.alter_receipt(lambda d: d['views']['current']['sources'].pop('formal/crypto/NativeTypes.dfy'))
        with self.assertRaises(self.api.SelectError):
            self.admit()


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.work = self.work_root / self.id().split('.')[-1]
        self.work.mkdir()
        self.build = self.work / 'build'
        self.project = self.build / 'formal/source/select/checker'
        self.project.mkdir(parents=True)
        self.reference = self.work / 'tool-reference.dll'
        self.reference.write_bytes(b'known tool reference')
        self.tools = {str(self.reference): sha(self.reference)}
        self.props = {'ImportDirectoryBuildProps': 'false'}
        for name in ('SourceCoverage.cs', 'NativeCanonicalEncoderPolicy.cs'):
            (self.project / name).write_text('// authenticated fixture')
        obj = self.project / 'obj/Debug/net6.0'
        obj.mkdir(parents=True)
        generated = obj / 'SourceCoverage.AssemblyInfo.cs'
        generated.write_text('// generated')
        self.data = {'Properties': dict(self.props, MSBuildAllProjects=''), 'Items': {
            'ReferencePath': [{'Identity': str(self.reference)}],
            'Compile': [{'Identity': str(p)} for p in [self.project / 'SourceCoverage.cs',
                self.project / 'NativeCanonicalEncoderPolicy.cs', generated]]}}
        authority = type('EvaluationFixture', (), {})()
        authority.root = self.work / 'authority'
        authority.immutable_before = {'packs': {}}
        authority.properties = lambda: self.props
        self.authority = authority

    def validate(self):
        return self.evaluation.validate_evaluation(self.authority, json.dumps(self.data),
            self.build, self.project, 'SourceCoverage', self.tools)

    def test_exact_old_select_source_layout(self):
        self.assertEqual(len(self.validate()['compile_inputs']), 3)

    def test_wrong_authored_source(self):
        wrong = self.project / 'Different.cs'
        wrong.write_text('// wrong')
        self.data['Items']['Compile'].append({'Identity': str(wrong)})
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_authored_encoder(self):
        self.data['Items']['Compile'] = self.data['Items']['Compile'][:1]
        with self.assertRaises(ValueError):
            self.validate()

    def test_unmapped_reference(self):
        unknown = self.work / 'unmapped.dll'
        unknown.write_bytes(b'unknown')
        self.data['Items']['ReferencePath'].append({'Identity': str(unknown)})
        with self.assertRaises(ValueError):
            self.validate()

    def test_changed_mapped_reference(self):
        self.reference.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.validate()

    def test_unmapped_external_import(self):
        imported = self.work / 'outside.targets'
        imported.write_text('<Project/>')
        self.data['Properties']['MSBuildAllProjects'] = str(imported)
        with self.assertRaises(ValueError):
            self.validate()

    def test_isolation_property_mismatch(self):
        self.data['Properties']['ImportDirectoryBuildProps'] = 'true'
        with self.assertRaises(ValueError):
            self.validate()


class LogTests(unittest.TestCase):
    def test_captured_source_ignores_valid_poisoned_pyc(self):
        work = self.work_root / self.id().split('.')[-1]
        work.mkdir()
        source = work / 'candidate.py'
        source.write_text("VALUE = 'safe'\n")
        code = compile("VALUE = 'poisoned'\n", str(source), 'exec')
        pyc = Path(importlib.util.cache_from_source(str(source)))
        pyc.parent.mkdir()
        pyc.write_bytes(importlib._bootstrap_external._code_to_timestamp_pyc(
            code, int(source.stat().st_mtime), source.stat().st_size))
        probe = 'import importlib.util; s=importlib.util.spec_from_file_location("probe",' + repr(str(source)) + '); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(m.VALUE)'
        legacy = subprocess.run([sys.executable, '-I', '-B', '-c', probe], capture_output=True, text=True)
        self.assertEqual((legacy.returncode, legacy.stdout.strip()), (0, 'poisoned'))
        self.assertEqual(self.api.captured_module('safe_probe', source, sha(source)).VALUE, 'safe')

    def test_reviewed_environment_drops_injection_selectors(self):
        admitted = self.api.admit_views(self.manifest, self.manifest_sha,
            self.original_views, self.original_receipt_sha)
        relative = 'formal/source/keccak/encoder/build_authority.py'
        helper = self.api.captured_module('environment_authority_test', admitted['current'] / relative,
            admitted['manifest']['current_tooling'][relative])
        authority = helper.BuildAuthority.__new__(helper.BuildAuthority)
        authority.root, authority.dotnet_root = self.work_root / 'environment-fixture', self.work_root / 'dotnet-fixture'
        poison = {k: 'deliberate-untrusted-value' for k in (
            'JDK_JAVAC_OPTIONS', 'JDK_JAVA_OPTIONS', 'JDK_ALTERNATE_VM', 'JAVA_TOOL_OPTIONS',
            'DYLD_INSERT_LIBRARIES', 'LD_PRELOAD', 'PYTHONPATH', 'DOTNET_STARTUP_HOOKS')}
        with mock.patch.dict(os.environ, poison):
            env = self.api.minimal_env(authority)
        self.assertFalse(set(poison) & set(env))

    def test_minimal_environment_fails_closed_on_injection(self):
        authority = type('BadEnvironmentFixture', (), {'environment': lambda self: {'DYLD_INSERT_LIBRARIES': 'bad'}})()
        with self.assertRaises(self.api.SelectError):
            self.api.minimal_env(authority)

    def test_named_semantic_failure(self):
        text = 'case.dfy(13,11): Error: assertion might not hold\nassert t1 == t2;\nDafny program verifier finished with 1 verified, 1 error\n'
        self.api.classify_proof(text, 4, [1, 1], ('case.dfy(13,11): Error: assertion might not hold', 'assert t1 == t2;'))

    def test_mixed_failure_is_not_semantic_evidence(self):
        base = 'Error: assertion might not hold\nDafny program verifier finished with 1 verified, 1 error\n'
        for extra in ('Unhandled exception: tool failure', 'timed out', 'parse errors detected', 'Error: unresolved identifier X'):
            with self.subTest(extra=extra), self.assertRaises(self.api.SelectError):
                self.api.classify_proof(base + extra, 4, [1, 1], ('assertion might not hold',))

    def test_zero_filtered_proof_rejected(self):
        with self.assertRaises(self.api.SelectError):
            self.api.classify_proof('Dafny program verifier finished with 0 verified, 0 errors', 0, [0, 0], ())

    def test_wrong_exit_rejected(self):
        with self.assertRaises(self.api.SelectError):
            self.api.classify_proof('Dafny program verifier finished with 1 verified, 1 error', 0, [1, 1], ())

    def test_missing_named_anchor_rejected(self):
        with self.assertRaises(self.api.SelectError):
            self.api.classify_proof('Dafny program verifier finished with 1 verified, 1 error', 4, [1, 1], ('required named assertion',))


class EvidenceTests(unittest.TestCase):
    """Forgeries of copies of an ACTUAL current replay; producer bytes stay intact."""
    def setUp(self):
        self.work = self.work_root / self.id().split('.')[-1]
        self.work.mkdir()
        self.fragment = json.loads((self.evidence_root / 'semantics.json').read_text())
        shutil.copytree(self.evidence_root / 'logs', self.work / 'logs')
        shutil.copytree(self.evidence_root / 'csv', self.work / 'csv')

    def validate(self):
        return self.api.check_semantic_evidence(self.fragment, self.work, self.policy,
            self.helper, self.package, self.manifest_data)

    def test_actual_current_evidence(self):
        self.assertEqual(self.validate()['typed_controls'], 25)

    def test_case_source_substitution_with_self_renewed_map(self):
        row = self.fragment['controls']['positive-actual']
        relative = 'formal/crypto/NativeKeccak.dfy'
        row['source_map'][relative] = self.manifest_data['predecessor']['sources'][relative]
        row['plain']['source_map'][relative] = row['source_map'][relative]
        row['plain']['source_map_sha256'] = self.api.map_sha(row['plain']['source_map'])
        with self.assertRaises(self.api.SelectError):
            self.validate()

    def forge_paired_native_pin(self, key):
        row = self.fragment[key]
        native = 'formal/crypto/NativeMlKem.dfy'
        row['source_map'][native] = '0' * 64
        row['source_map_sha256'] = self.api.map_sha(row['source_map'])
        row['parser_closure'][native] = '0' * 64
        with self.assertRaises(self.api.SelectError):
            self.validate()

    def test_positive_paired_harness_cannot_supply_native_pin(self):
        self.forge_paired_native_pin('harness_plain')

    def test_observed_paired_harness_cannot_supply_native_pin(self):
        self.forge_paired_native_pin('observed_harness_plain')

    def test_current_keccak_parser_dependency_cannot_be_dropped(self):
        self.fragment['controls']['positive-actual']['plain']['parser_closure'].pop('formal/crypto/NativeKeccak.dfy')
        with self.assertRaises(self.api.SelectError):
            self.validate()

    def test_command_and_context_cannot_disagree_with_raw_header(self):
        row = self.fragment['controls']['positive-actual']['checker']
        row['command'] = row['command'][:-2]
        row['case_context']['argv'] = row['command']
        with self.assertRaises(self.api.SelectError):
            self.validate()

    def test_parser_raw_record_cannot_be_omitted(self):
        self.fragment['parser_records'].pop(0)
        with self.assertRaises(self.api.SelectError):
            self.validate()

    def test_source_closure_digest_cannot_be_substituted(self):
        row = self.fragment['controls']['positive-actual']['plain']
        row['parser_closure']['formal/crypto/NativeKeccak.dfy'] = '0' * 64
        with self.assertRaises(self.api.SelectError):
            self.validate()

    def test_focused_solver_flags_cannot_be_changed_with_renewed_header(self):
        row = self.fragment['proofs']['positive']
        row['command'][row['command'].index('--resource-limit') + 1] = '999999999'
        row['case_context']['argv'] = row['command']
        path = self.work / row['log']
        lines = path.read_text().splitlines(keepends=True)
        lines[0] = lines[0].replace('"50000000"', '"999999999"')
        path.write_text(''.join(lines))
        row['log_sha256'] = sha(path)
        with self.assertRaises(self.api.SelectError):
            self.validate()

    def forge_proof_summary(self, mutation):
        for kind, row in self.fragment['proofs'].items():
            with self.subTest(proof=kind):
                path = self.work / row['log']
                original = path.read_text()
                summaries = [line for line in original.splitlines()
                             if line.startswith('Dafny program verifier finished with ')]
                self.assertEqual(len(summaries), 1)
                path.write_text(mutation(original, summaries[0]))
                row['log_sha256'] = sha(path)
                try:
                    with self.assertRaises(self.api.SelectError):
                        self.validate()
                finally:
                    path.write_text(original)
                    row['log_sha256'] = sha(path)

    def test_all_proofs_reject_mixed_summary_units(self):
        self.forge_proof_summary(lambda text, line: text +
            '\nDafny program verifier finished with 1 assertions verified, 0 errors\n')

    def test_all_proofs_reject_wrong_summary_unit(self):
        self.forge_proof_summary(lambda text, line:
            text.replace(line, line.replace(' verified,', ' assertions verified,')))

    def test_all_proofs_reject_duplicate_summary(self):
        self.forge_proof_summary(lambda text, line: text + '\n' + line + '\n')

    def test_all_proofs_require_full_anchored_summary(self):
        self.forge_proof_summary(lambda text, line:
            text.replace(line, 'prefix ' + line + ' trailing'))

    def test_mixed_named_failure_and_crash_rejected(self):
        row = self.fragment['proofs']['f2']
        path = self.work / row['log']
        path.write_text(path.read_text() + '\nUnhandled exception: deliberate evidence forgery\n')
        row['log_sha256'] = sha(path)
        with self.assertRaises(self.api.SelectError):
            self.validate()

    def test_observed_failure_requires_original_named_assertion(self):
        row = self.fragment['proofs']['observed_harness']
        path = self.work / row['log']
        path.write_text(path.read_text().replace('SelectObservedHarness.dfy(13,11): Error:',
                                                'SelectObservedHarness.dfy(99,99): Error:'))
        row['log_sha256'] = sha(path)
        with self.assertRaises(self.api.SelectError):
            self.validate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=HERE / 'manifest.json')
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--views-root', type=Path, required=True)
    parser.add_argument('--expected-views-receipt-sha256', required=True)
    parser.add_argument('--work-root', type=Path, required=True)
    parser.add_argument('--evidence-root', type=Path)
    args = parser.parse_args()
    api = load('current_select_tested', HERE / 'select_replay.py')
    evaluation = load('current_select_evaluation_tested', HERE / 'select-current/evaluation.py')
    work = api.output_admission(args.work_root, [args.views_root, args.manifest.parent, HERE])
    work.mkdir()
    classes = [AdmissionTests, EvaluationTests, LogTests]
    if args.evidence_root:
        classes.append(EvidenceTests)
    for cls in classes:
        cls.work_root, cls.api, cls.evaluation = work, api, evaluation
    AdmissionTests.original_views = args.views_root
    AdmissionTests.original_receipt_sha = args.expected_views_receipt_sha256
    AdmissionTests.manifest, AdmissionTests.manifest_sha = args.manifest, args.expected_manifest_sha256
    LogTests.original_views, LogTests.original_receipt_sha = args.views_root, args.expected_views_receipt_sha256
    LogTests.manifest, LogTests.manifest_sha = args.manifest, args.expected_manifest_sha256
    if args.evidence_root:
        admitted = api.admit_views(args.manifest, args.expected_manifest_sha256,
            args.views_root, args.expected_views_receipt_sha256)
        relative = 'formal/source/select/replay.py'
        EvidenceTests.evidence_root = args.evidence_root
        EvidenceTests.manifest_data = admitted['manifest']
        EvidenceTests.helper = api.captured_module('evidence_frozen_helpers', admitted['current'] / relative,
            admitted['manifest']['support_inputs'][relative])
        EvidenceTests.package = json.loads((admitted['current'] / 'formal/source/select/package.json').read_text())
        EvidenceTests.policy = api.load_expectations(HERE / 'select-current/expectations.json', api.EXPECTATIONS_SHA)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in classes)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
               'skipped': len(result.skipped), 'expected_failures': len(result.expectedFailures),
               'actual_evidence_controls': bool(args.evidence_root)}
    (work / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')
    return 0 if result.wasSuccessful() and not result.skipped and not result.expectedFailures else 1


if __name__ == '__main__':
    raise SystemExit(main())
