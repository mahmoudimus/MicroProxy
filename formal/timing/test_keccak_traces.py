"""Fast fail-closed tests for the official Keccak trace replay component.

These tests need no Dafny, JDK or jar.  They exercise the admission gate, loaded
module/file pin binding, provider whitelist/secret-argument gates, final-control
completion obligations and the target-free public KAT table.  The optional
expensive test is skipped unless KECCAK_TRACE_REPLAY=1.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

if __package__:
    from . import keccak_traces as kt
else:  # running from formal/timing
    import keccak_traces as kt


class AdmissionGateTests(unittest.TestCase):
    def test_exact_reviewed_left_plus_right(self):
        record = kt.require_reviewed_admission(
            actual={kt.LEFT_SHIFT, kt.RIGHT_SHIFT},
            declared={kt.LEFT_SHIFT, kt.RIGHT_SHIFT})
        self.assertEqual(sorted(kt.REVIEWED_SHIFT_SET), record['actual'])
        self.assertEqual(record['actual'], record['declared'])

    def test_right_only_and_extra_sets_reject(self):
        for actual in ({kt.RIGHT_SHIFT}, {kt.LEFT_SHIFT}, set(),
                       {kt.LEFT_SHIFT, kt.RIGHT_SHIFT, 'dafny/Other.x:()V'}):
            with self.assertRaises(kt.AdmissionError, msg=repr(actual)):
                kt.require_reviewed_admission(actual=actual)

    def test_declared_policy_mismatch_rejects(self):
        with self.assertRaises(kt.AdmissionError):
            kt.require_reviewed_admission(
                actual={kt.LEFT_SHIFT, kt.RIGHT_SHIFT},
                declared={kt.RIGHT_SHIFT})

    def _assert_refusal(self, admitted):
        with mock.patch.object(kt.bt, 'SHIFT_COUNT_PUBLIC_RUNTIME_CALLS', admitted):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'out'
                with self.assertRaises(kt.AdmissionError):
                    kt.replay(output, jar=Path('/missing'),
                              dafny=Path('/missing'), solver=Path('/missing'),
                              java_home=Path('/missing'), classpath=Path('/missing'))
                evidence = json.loads((output / 'keccak-traces.json').read_text())
                self.assertEqual('failed', evidence['status'])
                self.assertIn('requires exactly {left,right}', evidence['error'])
                self.assertNotIn('binding', evidence)
                self.assertNotIn('runtime_replay', evidence)

    def test_official_replay_refuses_injected_right_only_admission(self):
        self._assert_refusal({kt.RIGHT_SHIFT})

    def test_official_replay_refuses_injected_extra_admission(self):
        self._assert_refusal({kt.LEFT_SHIFT, kt.RIGHT_SHIFT, 'dafny/Other.x:()V'})


class BindingTests(unittest.TestCase):
    def _pins(self, paths: dict[str, Path]) -> Path:
        folder = Path(tempfile.mkdtemp(prefix='keccak-pins-'))
        pin_file = folder / 'inputs.json'
        pin_file.write_text(json.dumps({'inputs': {
            path.resolve().relative_to(kt.REPO).as_posix(): kt.sha(path)
            for path in paths.values()}}))
        self.addCleanup(lambda: __import__('shutil').rmtree(folder, ignore_errors=True))
        return pin_file

    def test_loaded_module_binding_and_tamper(self):
        paths = {
            'bt': kt.HERE / 'bytecode_trace.py',
            'comp': kt.HERE / 'composition.py',
            'exec': kt.HERE / 'trace_exec.py',
            'rp': kt.HERE / 'runtime_primitives.py',
            'compact': kt.HERE / 'compact_certificates.py',
            'kt': kt.HERE / 'keccak_traces.py',
        }
        pin_file = self._pins(paths)
        record = kt._bind_modules(pin_file)
        self.assertEqual({'bytecode_trace', 'composition', 'trace_exec',
                          'runtime_primitives', 'compact_certificates', 'keccak_traces'},
                         set(record))
        tampered = json.loads(pin_file.read_text())
        key = (kt.HERE / 'composition.py').resolve().relative_to(kt.REPO).as_posix()
        tampered['inputs'][key] = '0' * 64
        pin_file.write_text(json.dumps(tampered))
        with self.assertRaises(kt.KeccakTraceError):
            kt._bind_modules(pin_file)

    def test_trusted_file_binding_and_tamper(self):
        policy = kt.HERE / 'policy.json'
        paths = {
            'policy': policy,
            'secret': kt.HERE / 'SecretTrace.dfy',
            'provider': kt.HERE / 'PublicProvider.dfy',
            'public_layer': kt.HERE / 'PublicProviderPublic.dfy',
            'words': kt.HERE / 'WordArithmetic.dfy',
            'source': kt.REPO / kt.NATIVE_SOURCE_REL,
        }
        pin_file = self._pins(paths)
        records = kt._bind_files(pin_file, policy)
        self.assertEqual({'policy', 'secret_trace', 'public_provider',
                          'public_provider_public', 'word_arithmetic',
                          'native_source'}, set(records))
        tampered = json.loads(pin_file.read_text())
        key = paths['words'].resolve().relative_to(kt.REPO).as_posix()
        tampered['inputs'][key] = '0' * 64
        pin_file.write_text(json.dumps(tampered))
        with self.assertRaises(kt.KeccakTraceError):
            kt._bind_files(pin_file, policy)

    def test_shadow_loaded_module_path_rejects(self):
        pin_file = self._pins({'bt': kt.HERE / 'bytecode_trace.py'})

        class ShadowModule:
            __file__ = str(Path(tempfile.mkdtemp()) / 'shadow_bytecode_trace.py')

        with self.assertRaises(Exception):
            kt.rp.bind_loaded_modules(
                {'bytecode_trace': ShadowModule()}, inputs_path=pin_file,
                canonical={'bytecode_trace': kt.HERE / 'bytecode_trace.py'})

    def test_canonical_path_gate(self):
        with self.assertRaises(kt.KeccakTraceError):
            kt._canonical(Path('/tmp/not-policy.json'), kt.HERE / 'policy.json', 'policy')


def call_result(target: str, taints: dict[int, str], args=(0,)) -> dict:
    return {
        'code': [{'type': 'step', 'kind': ('call', 1, list(args), [], False)}],
        'call_targets': {target: 1},
        'reg_taints': taints,
    }


class ProviderWhitelistTests(unittest.TestCase):
    def test_public_provider_with_public_argument_passes(self):
        result = call_result('java/lang/Integer.signum:(I)I', {0: 'pub'})
        self.assertEqual({'java/lang/Integer.signum:(I)I': 1},
                         kt._validate_remaining_calls(result))

    def test_secret_provider_argument_rejects(self):
        result = call_result('java/lang/Integer.signum:(I)I', {0: 'sec'})
        with self.assertRaises(kt.KeccakTraceError):
            kt._validate_remaining_calls(result)

    def test_known_provider_wrong_arity_rejects(self):
        target = 'dafny/DafnyEuclidean.EuclideanDivision:(II)I'
        result = call_result(target, {0: 'pub'}, args=(0,))
        with self.assertRaises(kt.KeccakTraceError):
            kt._validate_remaining_calls(result)
        ok = call_result(target, {0: 'pub', 1: 'pub'}, args=(0, 1))
        self.assertEqual({target: 1}, kt._validate_remaining_calls(ok))

    def test_private_owned_shift_and_unknown_public_targets_reject(self):
        for target in (kt.NATIVE_OWNER + '.Chi:([J[J)V', kt.LEFT_SHIFT,
                       'java/lang/Unknown:(I)I'):
            with self.assertRaises(kt.KeccakTraceError, msg=target):
                kt._validate_remaining_calls(call_result(target, {0: 'pub'}))

    def test_public_provider_with_heap_argument_rejects(self):
        result = call_result('java/lang/Integer.signum:(I)I', {0: 'pub'})
        result['code'][0]['kind'] = ('call', 1, [0], ['role'], False)
        with self.assertRaises(kt.KeccakTraceError):
            kt._validate_remaining_calls(result)


class FinalControlGateTests(unittest.TestCase):
    def valid(self):
        return {
            'status': 'ok', 'rounds_executed': 24,
            'terminal': {'s': 'stop', 't': 'stop'},
            'fault_events': {'s': [], 't': []},
            'checks': {
                'both_terminal_stop': True, 'no_fault_event': True,
                'trace_equal': True, 'public_registers_equal': True,
                'public_heap_equal': True,
                'role_lengths_honest': True, 'heap_shape_preserved': True,
                'private_heap_output_live': True,
                'both_private_input_roles_vary': True,
                'both_private_outputs_live': True, '24_rounds_executed': True,
                'to_int_big_integer_only_zero_argument': True,
            },
        }

    def test_full_completion_accepted(self):
        kt.validate_control(self.valid(), final=True)

    def test_missing_round_or_liveness_or_fault_rejects(self):
        for key, value in (('rounds_executed', 23),
                           ('status', 'FAILED'),
                           ('terminal', {'s': 'stop', 't': 'fault'})):
            record = self.valid()
            record[key] = value
            with self.assertRaises(kt.KeccakTraceError, msg=key):
                kt.validate_control(record, final=True)
        for key in ('both_private_input_roles_vary', 'both_private_outputs_live',
                    '24_rounds_executed', 'to_int_big_integer_only_zero_argument'):
            record = copy.deepcopy(self.valid())
            record['checks'][key] = False
            with self.assertRaises(kt.KeccakTraceError, msg=key):
                kt.validate_control(record, final=True)


class PublicHeapControlTests(unittest.TestCase):
    def test_control_rejects_secret_write_into_public_role(self):
        owner = kt.NATIVE_OWNER + '.RhoPi'
        roles = {f'{owner}#p0': 'sec', f'{owner}#p1': 'sec',
                 f'{owner}#p2': 'pub', f'{owner}#p3': 'pub'}
        result = {
            'registers': 2, 'roles': roles, 'call_targets': {},
            'reg_taints': {0: 'pub', 1: 'sec'}, 'param_regs': [],
            'code': [
                {'type': 'step', 'site': 0, 'dst': 0, 'kind': ('lit', 0)},
                {'type': 'step', 'site': 1, 'dst': 1,
                 'kind': ('load', f'{owner}#p0', 0)},
                {'type': 'step', 'site': 2, 'dst': 0,
                 'kind': ('store', f'{owner}#p2', 0, 1)},
                {'type': 'stop', 'ret': None},
            ],
            'sites': [{'site': i, 'method': 'RhoPi'} for i in range(3)],
        }
        tables = {'offsets': list(range(25)), 'sources': list(range(25))}
        record = kt.control('RhoPi', result, tables)
        self.assertEqual('FAILED', record['status'])
        self.assertFalse(record['public_heap_equal'])
        self.assertIn('public_heap_equal', record['reason'])


class PublicKATTests(unittest.TestCase):
    def test_python_domain_table(self):
        rows = {(kind, args): value for kind, args, value in kt._public_kats()}
        self.assertEqual(243, len(rows))
        for i in range(25):
            self.assertEqual(i // 5, rows[('div', (i,))])
            self.assertEqual(i % 5, rows[('mod', (i,))])
        word = 0x0123456789ABCDEF
        for n in range(64):
            self.assertEqual(kt._rotate_word(word, n), rows[('rot', (0, n))])
        self.assertEqual(0, rows[('signum', (0,))])
        self.assertEqual(1, rows[('signum', (63,))])
        self.assertEqual(0, rows[('tointbigzero', ())])

    def test_word_arithmetic_is_target_free(self):
        text = (kt.HERE / 'WordArithmetic.dfy').read_text()
        self.assertIn('include "PublicProvider.dfy"', text)
        self.assertNotRegex(text, r'TARGET_(EUCLIDEAN|TO_INT|INTEGER)')
        self.assertNotIn('secret', text.lower().split('//')[0])


class BodyDigestTests(unittest.TestCase):
    def test_body_digest_distinguishes_opcode_even_when_shape_collides(self):
        def method(op):
            return kt.bt.Method('x/Owner', 'm', '(I)I', True, {'ACC_STATIC'},
                                [kt.bt.Insn(0, op, '', '0: ' + op),
                                 kt.bt.Insn(1, 'ireturn', '', '1: ireturn')])
        left, right = method('lshl'), method('lushr')
        fake_l = {'code': [{'type': 'step', 'kind': ('op', 'shl', 0, 0)}],
                  'call_targets': {}}
        fake_r = {'code': [{'type': 'step', 'kind': ('op', 'ushr', 0, 0)}],
                  'call_targets': {}}
        self.assertEqual(kt.comp.shape_signature(fake_l),
                         kt.comp.shape_signature(fake_r))
        a = kt._callee_body_record(left, 'classhash')
        b = kt._callee_body_record(right, 'classhash')
        self.assertNotEqual(a['callee_bytecode_sha256'], b['callee_bytecode_sha256'])
        self.assertFalse(a['callee_shape_sha256_is_body_identity'])
        literal_one = kt.bt.Method('x/Owner', 'm', '(I)I', True, {'ACC_STATIC'},
                                    [kt.bt.Insn(0, 'bipush', '1', '0: bipush 1'),
                                     kt.bt.Insn(1, 'ireturn', '', '1: ireturn')])
        literal_two = kt.bt.Method('x/Owner', 'm', '(I)I', True, {'ACC_STATIC'},
                                    [kt.bt.Insn(0, 'bipush', '2', '0: bipush 2'),
                                     kt.bt.Insn(1, 'ireturn', '', '1: ireturn')])
        self.assertNotEqual(
            kt._callee_body_record(literal_one, 'classhash')['callee_bytecode_sha256'],
            kt._callee_body_record(literal_two, 'classhash')['callee_bytecode_sha256'])

    def test_expected_proof_counts_are_frozen(self):
        self.assertEqual(16, kt.EXPECTED_PUBLIC_PROVIDER_CHECKS)
        self.assertEqual(9, kt.EXPECTED_PUBLIC_LAYER_CHECKS)
        self.assertEqual(56, kt.EXPECTED_WORD_ARITHMETIC_CHECKS)
        self.assertEqual({'Rotate': 48, 'Theta': 163, 'RhoPi': 80, 'Iota': 29,
                          'Chi': 67, 'Round': 294, 'PermuteScratch': 472},
                         kt.EXPECTED_ROOT_CHECKS)


class HelperPinTests(unittest.TestCase):
    def test_declared_and_actual_helpers_entry_must_match(self):
        policy = {'runtime_classification': {'pinned_runtime': {
            'helpers_entry_sha256': 'entry', 'jar_sha256': 'jar'}}}
        runtime = {'artifact_binding': {'entry_sha256': 'entry', 'jar_sha256': 'jar'}}
        self.assertTrue(kt._check_helper_pin(policy, runtime)['matches'])
        bad = copy.deepcopy(runtime)
        bad['artifact_binding']['entry_sha256'] = 'other'
        with self.assertRaises(kt.KeccakTraceError):
            kt._check_helper_pin(policy, bad)


class PublicMutantFlagTests(unittest.TestCase):
    def test_flags_are_derived_from_actual_proof_record(self):
        good = {'status': 'proof_failed', 'contains_structure_error': False}
        flags = kt._public_mutant_flags(good, 'good')
        self.assertTrue(flags['structure_valid'])
        self.assertTrue(flags['public_only_false'])
        self.assertTrue(flags['derived_from_proof'])
        for bad in ({'status': 'verified', 'contains_structure_error': False},
                    {'status': 'proof_failed', 'contains_structure_error': True}):
            with self.assertRaises(kt.KeccakTraceError):
                kt._public_mutant_flags(bad, 'bad')


class SurfaceTests(unittest.TestCase):
    def test_replay_has_no_skip_flags(self):
        params = inspect.signature(kt.replay).parameters
        self.assertNotIn('check_pins', params)
        self.assertNotIn('run_java', params)
        self.assertEqual(['output', 'jar', 'dafny', 'solver', 'java_home',
                          'classpath', 'policy_path', 'inputs_path'], list(params))

    def test_no_admission_mutation_or_scratch_imports(self):
        text = Path(kt.__file__).read_text()
        self.assertNotIn('SHIFT_COUNT_PUBLIC_RUNTIME_CALLS.add', text)
        self.assertNotIn('public-provider-semantics', text)
        self.assertNotIn('keccak-composition-candidate', text)
        self.assertNotIn('/Users/mahmoud/.cache', text)

    def test_oracle_adapter_is_view_subclass(self):
        self.assertTrue(issubclass(kt.OracleView, kt.trace_exec.ProgramView))


@unittest.skipUnless(os.environ.get('KECCAK_TRACE_REPLAY') == '1',
                     'set KECCAK_TRACE_REPLAY=1 for the expensive official replay')
class OptionalOfficialReplayTest(unittest.TestCase):
    def test_actual_replay(self):
        required = ('KECCAK_JAR', 'DAFNY', 'DAFNY_SOLVER', 'JAVA_HOME',
                    'MICROPROXY_CLASSES', 'KECCAK_TRACE_OUTPUT')
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            self.skipTest('missing replay environment: ' + ', '.join(missing))
        evidence = kt.replay(
            Path(os.environ['KECCAK_TRACE_OUTPUT']),
            jar=Path(os.environ['KECCAK_JAR']), dafny=Path(os.environ['DAFNY']),
            solver=Path(os.environ['DAFNY_SOLVER']),
            java_home=Path(os.environ['JAVA_HOME']),
            classpath=Path(os.environ['MICROPROXY_CLASSES']))
        self.assertEqual('verified', evidence['status'])
        self.assertEqual(16, evidence['model_proofs']['PublicProvider']['verified'])
        self.assertEqual(9, evidence['model_proofs']['PublicProviderPublic']['verified'])
        self.assertEqual(56, evidence['model_proofs']['WordArithmetic']['verified'])
        for name, count in kt.EXPECTED_ROOT_CHECKS.items():
            self.assertEqual(count, evidence['roots'][name]['proof']['verified'], name)
        self.assertEqual(24, evidence['roots']['PermuteScratch']['control']['rounds_executed'])
        self.assertTrue(evidence['roots']['PermuteScratch']['control']['public_heap_equal'])
        contract = evidence['roots']['PermuteScratch']['public_contract']
        self.assertEqual({'3': 1, '8': 1, '9': 2, '13': 2, '14': 1},
                         contract['known_public_arity'])
        self.assertEqual('EveryCallArityMatches',
                         contract['every_call_arity_matches_lemma'])
        branch_lines = '\n'.join(evidence['mutants']['branch']['proof']['error_lines'])
        index_lines = '\n'.join(evidence['mutants']['index']['proof']['error_lines'])
        self.assertIn('SecretTrace.dfy(227,', branch_lines)
        self.assertIn('SecretTrace.dfy(224,', index_lines)
        # error_lines contains diagnostic headers, not the verifier's printed
        # source excerpts. Check the bound full logs for the named obligation.
        for key in ('branch', 'index'):
            proof = evidence['mutants'][key]['proof']
            log_bytes = Path(proof['log']).read_bytes()
            self.assertEqual(proof['log_sha256'], hashlib.sha256(log_bytes).hexdigest())
            self.assertIn('ensures InstrOK', log_bytes.decode())
            self.assertTrue(proof['contains_structure_error'])
        expected_public_lines = {
            'private_argument': 'PublicProviderPublic.dfy(28,',
            'unknown_target': 'PublicProviderPublic.dfy(26,',
            'private_heap_argument': 'PublicProviderPublic.dfy(27,',
        }
        expected_public_lines['wrong_arity'] = 'PublicProviderPublic.dfy(29,'
        for key, anchor in expected_public_lines.items():
            mutant = evidence['public_call_mutants'][key]
            self.assertFalse(mutant['proof']['contains_structure_error'])
            self.assertTrue(mutant['derived_from_proof'])
            self.assertTrue(mutant['structure_valid'])
            self.assertTrue(mutant['public_only_false'])
            self.assertIn(anchor, '\n'.join(mutant['proof']['error_lines']))


if __name__ == '__main__':
    unittest.main()
