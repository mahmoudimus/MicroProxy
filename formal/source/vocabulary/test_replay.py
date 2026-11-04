import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('vocabulary_replay', Path(__file__).with_name('replay.py'))
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)


def ok_output(files, modules=1, types=0, members=1):
    lines = ['OBSERVATION-DECLARATIONS FILE ' + name for name in files]
    lines.append('OBSERVATION-DECLARATIONS OK: files=%d modules=%d types=%d members=%d' %
                 (len(files), modules, types, members))
    return '\n'.join(lines) + '\n'


def reject_output(message, files):
    lines = ['/work/Hidden.dfy(2,17): Error: ' + message]
    lines += ['OBSERVATION-DECLARATIONS FILE ' + name for name in files]
    return '\n'.join(lines) + '\n'


class ProofGateTests(unittest.TestCase):
    def test_reviewed_positive_count_is_required(self):
        with self.assertRaises(ValueError):
            REPLAY.proof_result(0, 'Dafny program verifier finished with 1 verified, 0 errors\n', expected=29)

    def test_named_control_must_be_the_actual_error(self):
        output = ('Error: unrelated failed assertion\n'
                  'source snippet mentions control-read-role\n'
                  'Dafny program verifier finished with 0 verified, 1 error\n')
        with self.assertRaises(ValueError):
            REPLAY.proof_result(4, output, negative='control-read-role')

    def test_control_cannot_have_unreviewed_extra_obligations(self):
        output = ('Error: control-read-role\n'
                  'Dafny program verifier finished with 3 verified, 1 error\n')
        with self.assertRaises(ValueError):
            REPLAY.proof_result(4, output, negative='control-read-role')

    def test_resource_failure_cannot_count_as_control(self):
        output = ('Error: control-read-role\nVerification out of resource\n'
                  'Dafny program verifier finished with 0 verified, 1 error\n')
        with self.assertRaises(ValueError):
            REPLAY.proof_result(4, output, negative='control-read-role')

    def test_exact_assertion_control_is_accepted(self):
        output = ('Control.dfy(8,4): Error: control-read-role\n'
                  'Dafny program verifier finished with 0 verified, 1 error\n')
        self.assertEqual(REPLAY.proof_result(4, output, negative='control-read-role'),
                         {'verified': 0, 'errors': 1})


class DeclarationPolicyTests(unittest.TestCase):
    def test_policy_findings_only_match_owned_policy_diagnostics(self):
        output = ('/work/M.dfy(2,17): Error: owned declaration missing implementation: '
                  'function M._default.F\n'
                  '/work/M.dfy(3,2): Error: unrelated source error\n')
        self.assertEqual(REPLAY.policy_findings(output),
                         ['owned declaration missing implementation: function M._default.F'])

    def test_plugin_ok_requires_exact_closure_coverage(self):
        result = REPLAY.plugin_ok_result(0, ok_output(['a.dfy', 'b.dfy']),
                                         ['a.dfy', 'b.dfy'])
        self.assertEqual(result['files'], ['a.dfy', 'b.dfy'])
        with self.assertRaises(ValueError):
            REPLAY.plugin_ok_result(0, ok_output(['a.dfy']), ['a.dfy', 'b.dfy'])

    def test_plugin_ok_rejects_a_policy_finding(self):
        output = ok_output(['a.dfy']) + (
            '/work/M.dfy(2,17): Error: owned declaration missing implementation: '
            'function M._default.F\n')
        with self.assertRaises(ValueError):
            REPLAY.plugin_ok_result(0, output, ['a.dfy'])

    def test_plugin_ok_rejects_wrong_reviewed_counts(self):
        with self.assertRaises(ValueError):
            REPLAY.plugin_ok_result(0, ok_output(['a.dfy'], modules=1, types=0, members=0),
                                    ['a.dfy'], (1, 0, 3))

    def test_plugin_ok_accepts_explicit_zero_counts(self):
        result = REPLAY.plugin_ok_result(0, ok_output(['a.dfy'], modules=0, types=0, members=0),
                                         ['a.dfy'], (0, 0, 0))
        self.assertEqual((result['modules'], result['types'], result['members']), (0, 0, 0))

    def test_plugin_ok_rejects_missing_inventory_key(self):
        output = ('OBSERVATION-DECLARATIONS FILE a.dfy\n'
                  'OBSERVATION-DECLARATIONS OK: files=1 modules=1 types=0\n')
        with self.assertRaises(ValueError):
            REPLAY.plugin_ok_result(0, output, ['a.dfy'], (1, 0, 1))

    def test_unseen_path_is_a_named_policy_finding(self):
        output = '/work/Seen.dfy: Error: unseen owned source file: /work/Unseen.dfy\n'
        self.assertEqual(REPLAY.policy_findings(output),
                         ['unseen owned source file: /work/Unseen.dfy'])

    def test_plugin_hash_change_is_rejected(self):
        with self.assertRaises(ValueError):
            REPLAY.require_plugin_unchanged('a' * 64, 'b' * 64, 'after policy calls')
        REPLAY.require_plugin_unchanged('a' * 64, 'a' * 64)

    def test_reviewed_positive_counts_cover_current_entries(self):
        expected = REPLAY.EXPECTED_POLICY_COUNTS
        self.assertEqual(expected[REPLAY.COMPONENT + 'ObservationVocabulary.dfy'], (1, 3, 29))
        self.assertEqual(expected[REPLAY.COMPONENT + 'erasure/base/Client.dfy'], (1, 0, 3))
        self.assertEqual(expected[REPLAY.COMPONENT + 'erasure/trace/Client.dfy'], (2, 3, 35))
        self.assertEqual(len(expected), 9)
        self.assertEqual(REPLAY.DECLARATION_CONTROLS['positive-shapes']['counts'], (1, 5, 7))
        self.assertEqual(REPLAY.DECLARATION_CONTROLS['empty-entry']['counts'], (0, 0, 0))
        self.assertEqual(REPLAY.DECLARATION_CONTROLS['comment-only-include']['counts'], (0, 0, 0))

    def test_plugin_ok_rejects_missing_success_marker(self):
        with self.assertRaises(ValueError):
            REPLAY.plugin_ok_result(0, 'OBSERVATION-DECLARATIONS FILE a.dfy\n', ['a.dfy'])

    def test_policy_rejection_records_files_and_findings(self):
        message = 'owned declaration missing implementation: function M._default.HiddenOracle'
        result = REPLAY.plugin_rejection_result(
            2, reject_output(message, ['a.dfy', 'b.dfy']), [message],
            ['a.dfy', 'b.dfy'], [])
        self.assertEqual(result['files'], ['a.dfy', 'b.dfy'])
        self.assertEqual(result['findings'], [message])

    def test_policy_rejection_requires_the_named_message(self):
        output = reject_output('unsupported owned trait: M.Tr', ['a.dfy'])
        with self.assertRaises(ValueError):
            REPLAY.plugin_rejection_result(
                2, output, ['owned declaration missing implementation'], ['a.dfy'], [])

    def test_policy_rejection_cannot_be_a_solver_failure(self):
        message = 'owned declaration missing implementation: function M._default.F'
        output = reject_output(message, ['a.dfy']) + (
            'Dafny program verifier finished with 0 verified, 1 error\n')
        with self.assertRaises(ValueError):
            REPLAY.plugin_rejection_result(2, output, [message], ['a.dfy'], [])

    def test_policy_rejection_cannot_be_a_parse_error(self):
        message = 'owned declaration missing implementation: function M._default.F'
        output = reject_output(message, ['a.dfy']) + '2 parse errors detected\n'
        with self.assertRaises(ValueError):
            REPLAY.plugin_rejection_result(2, output, [message], ['a.dfy'], [])

    def test_source_inventory_includes_the_ast_checker(self):
        files = REPLAY.source_files()
        self.assertIn(REPLAY.CHECKER_CS, files)
        self.assertIn(REPLAY.CHECKER_CSPROJ, files)

    def test_required_declaration_controls_are_declared(self):
        required = {
            'hidden-oracle', 'attribute-bodyless', 'forged-generated-origin',
            'bare-const', 'abstract-type',
            'opaque-type', 'abstract-module', 'trait', 'bodyless-constructor',
            'bodyless-method-lemma', 'next-declaration-body',
            'quoted-comment-marker', 'contract-set-literal',
            'requires-set-literal', 'include-only-closure',
            'empty-entry', 'comment-only-include', 'positive-shapes',
        }
        self.assertTrue(required.issubset(REPLAY.DECLARATION_CONTROLS))


class OutputIsolationTests(unittest.TestCase):
    def test_failed_setup_never_inspects_or_creates_a_sibling_build_tree(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            out = parent / 'replay'
            with (mock.patch.object(REPLAY.sys, 'argv', ['replay', '--output', str(out)]),
                  mock.patch.object(REPLAY, 'check_pins', side_effect=ValueError('stop setup')),
                  mock.patch.object(REPLAY, 'tree_digest', side_effect=AssertionError('outside output')),
                  redirect_stdout(io.StringIO())):
                self.assertEqual(REPLAY.main(), 1)
            self.assertEqual(list(parent.iterdir()), [out])
            self.assertTrue((out / 'evidence.json').is_file())


if __name__ == '__main__':
    unittest.main()
