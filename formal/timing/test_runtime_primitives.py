"""Tests for the runtime-primitive replay.

Fast tests use the reviewed bytecode shape and the frozen translator/interpreter
only: no Dafny, JDK or jar is required.  The complete jar -> disassembly ->
Dafny -> Java replay is an explicit, expensive API/CLI check and is skipped
unless ``RUNTIME_PRIMITIVES_REPLAY=1``.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import bytecode_trace as bt  # noqa: E402
import runtime_primitives as rp  # noqa: E402

POLICY = json.loads((HERE / 'policy.json').read_text())
REQUIRED_COUNTS = (0, 1, 15, 24, 63, 64, 65, 127, 255)


def canonical_method(spec: rp.PrimitiveSpec) -> bt.Method:
    """Build the reviewed 9-instruction method *for fast translator tests only*.

    The expensive replay never uses this helper: it disassembles the actual
    pinned ``dafny/Helpers.class`` entry.  Here it lets the unit tests exercise
    the frozen translator and interpreter without a JDK.
    """
    insns = [bt.Insn(offset, op, operand,
                     (f'{offset}: {op} {operand}').strip())
             for offset, op, operand in spec.bytecode]
    return bt.Method(spec.owner, spec.name, spec.descriptor, True, {'ACC_STATIC'}, insns)


def overlaid_policy():
    return rp.primitive_policy(POLICY)


def translated(spec):
    policy, _ = overlaid_policy()
    return rp.translate_primitive(canonical_method(spec), policy, spec)['result']


class BodyIdentityTests(unittest.TestCase):
    def test_reviewed_body_is_exact_and_uses_if_icmpne_64(self):
        for spec in rp.PRIMITIVES:
            method = canonical_method(spec)
            rp.verify_body(method, spec)
            ops = [insn.op for insn in method.insns]
            jvm_op = 'lshl' if spec.op == 'shl' else 'lushr'
            self.assertEqual(['iload_2', 'bipush', 'if_icmpne', 'lconst_0', 'lreturn',
                              'lload_0', 'iload_2', jvm_op, 'lreturn'], ops)
            guard = method.insns[2]
            self.assertEqual(('if_icmpne', '8'), (guard.op, guard.operand))
            self.assertEqual('64', method.insns[1].operand)
            self.assertNotIn('if_icmpge', ops)
            self.assertNotIn('if_icmplt', ops)
            self.assertFalse(method.exception_table)
            self.assertFalse(method.handlers)

    def test_body_mutants_reject(self):
        for spec in rp.PRIMITIVES:
            method = canonical_method(spec)
            mutants = {
                'guard_literal_65': bt.Insn(1, 'bipush', '65', '1: bipush 65'),
                'guard_ge_not_eq': bt.Insn(3, 'if_icmpge', '8', '3: if_icmpge 8'),
                'wrong_shift_op': bt.Insn(
                    10, 'lushr' if spec.op == 'shl' else 'lshl', '', '10: wrong shift'),
            }
            for label, replacement in mutants.items():
                mutant = copy.copy(method)
                mutant.insns = list(method.insns)
                index = next(i for i, insn in enumerate(mutant.insns)
                             if insn.offset == replacement.offset)
                mutant.insns[index] = replacement
                with self.assertRaises(rp.RuntimePrimitiveError, msg=label):
                    rp.verify_body(mutant, spec)

    def test_wrong_owner_name_descriptor_reject(self):
        methods = {}
        for spec in rp.PRIMITIVES:
            method = canonical_method(spec)
            methods[f'{method.name}:{method.descriptor}'] = method
        for spec in rp.PRIMITIVES:
            rp.bind_method(methods, spec)
            for field, value in (('owner', 'dafny/Helper'),
                                 ('name', 'bv64ShiftLeft2'),
                                 ('descriptor', '(JB)I')):
                with self.assertRaises(rp.RuntimePrimitiveError, msg=f'{spec.key}:{field}'):
                    rp.bind_method(methods, spec, **{field: value})

    def test_body_with_exception_table_rejects(self):
        spec = rp.PRIMITIVES[0]
        method = canonical_method(spec)
        method.handlers = [(0, 1, 2, 'Class dafny/DafnyHaltException')]
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.verify_body(method, spec)


class PolicyOverlayTests(unittest.TestCase):
    def test_overlay_adds_only_two_body_contracts_and_preserves_admission(self):
        before = copy.deepcopy(POLICY)
        policy, changes = overlaid_policy()
        self.assertEqual(set(changes), {
            'dafny/Helpers.bv64ShiftLeft:(JB)J',
            'dafny/Helpers.bv64ShiftRight:(JB)J',
        })
        self.assertEqual(POLICY, before, 'base policy was mutated')
        self.assertEqual(policy['classes']['dafny/Helpers']['methods'], {
            'bv64ShiftLeft:(JB)J': {'params': ['sec', 'pub']},
            'bv64ShiftRight:(JB)J': {'params': ['sec', 'pub']},
        })
        self.assertEqual(policy['classes']['dafny/Helpers']['fields'], {})
        self.assertEqual(policy['calls'], before['calls'])
        self.assertEqual(policy['runtime_classification'], before['runtime_classification'])
        self.assertEqual(policy['limits'], before['limits'])
        self.assertEqual(policy['roots'], before['roots'])
        # The in-memory primitive overlay never adds a left-shift admission.
        self.assertEqual(policy['runtime_classification']['shift_count_public'],
                         before['runtime_classification']['shift_count_public'])
        self.assertEqual(set(bt.SHIFT_COUNT_PUBLIC_RUNTIME_CALLS),
                         set(before['runtime_classification']['shift_count_public']))
        self.assertTrue(rp.reviewed_admission_state(set(bt.SHIFT_COUNT_PUBLIC_RUNTIME_CALLS)))

    def test_existing_mismatched_params_reject_and_matching_entry_is_preserved(self):
        policy = copy.deepcopy(POLICY)
        policy['classes']['dafny/Helpers'] = {
            'fields': {'kept': {'taint': 'pub'}},
            'methods': {'bv64ShiftLeft:(JB)J': {'params': ['pub', 'pub'], 'note': 'kept'}},
        }
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.primitive_policy(policy)
        policy['classes']['dafny/Helpers']['methods']['bv64ShiftLeft:(JB)J'] = {
            'params': ['sec', 'pub'], 'note': 'kept'}
        overlaid, _ = rp.primitive_policy(policy)
        self.assertEqual(overlaid['classes']['dafny/Helpers']['fields'],
                         {'kept': {'taint': 'pub'}})
        self.assertEqual(overlaid['classes']['dafny/Helpers']['methods']['bv64ShiftLeft:(JB)J'],
                         {'params': ['sec', 'pub'], 'note': 'kept'})

    def test_unknown_override_rejects(self):
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.primitive_policy(POLICY, params_overrides={'middle': ('sec', 'pub')})


class PrivateCountAnchorTests(unittest.TestCase):
    #: The emitted 7-instruction certificate has this Chunk0 ensures line and
    #: the pinned model has the branch RegTaint requirement at this line.
    CERT_LINE = 25
    MODEL_LINE = 227

    def fixture(self, folder: Path):
        cert = folder / 'RuntimeShiftLeft_PrivateCount_audit.dfy'
        cert.write_text('\n' * (self.CERT_LINE - 1)
                        + '      ensures InstrOK(p, p.chunks[0][j])\n')
        model = folder / 'SecretTrace.dfy'
        model.write_text('\n' * (self.MODEL_LINE - 1)
                         + '      cond < p.registers && RegTaint(p, cond) == Pub &&\n')
        log = (
            f'{cert}({self.CERT_LINE},14): Error: possible violation of postcondition '
            'of forall statement\n'
            f'   |\n{self.CERT_LINE} |       ensures InstrOK(p, p.chunks[0][j])\n'
            f'{model}({self.MODEL_LINE},28): Related location: this proposition could not be proved\n'
            f'    |\n{self.MODEL_LINE} |       cond < p.registers && RegTaint(p, cond) == Pub &&\n'
            '\nDafny program verifier finished with 9 verified, 2 errors\n')
        return cert, model, log

    def test_anchored_private_count_accepts_only_named_chunk0_branch(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            cert, model, log = self.fixture(folder)
            anchor = rp.private_count_anchor(cert, model, log)
            self.assertEqual(self.CERT_LINE, anchor['certificate_line'])
            self.assertEqual(self.MODEL_LINE, anchor['model_line'])
            self.assertIn('Chunk0.InstrOK', anchor['obligation'])
            log_path = folder / 'proof.log'
            log_path.write_text(log)
            record = {'status': 'proof_failed', 'verified': 9, 'errors': 2,
                      'returncode': 4, 'obligation': 'Error: possible violation of postcondition',
                      'log': str(log_path)}
            result = rp._require_private_count_failure(
                record, certificate_path=cert, model_path=model, label='anchored')
            self.assertEqual('proof_failed_named_chunk0_branch_postcondition',
                             result['anchor_status'])

    def test_unrelated_false_lemma_is_not_a_private_count_control(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            _, model, _ = self.fixture(folder)
            public_cert = folder / 'RuntimeShiftLeft_public_unrelated_false_lemma.dfy'
            public_cert.write_text('\n' * 7 + '    ensures false\n' + '  {\n')
            unrelated_log = (
                f'{public_cert}(10,2): Error: a postcondition could not be proved on this return path\n'
                f'   |\n10 |   {{\n'
                f'{public_cert}(9,12): Related location: this is the postcondition that could not be proved\n'
                f'  |\n9 |     ensures false\n'
                '\nDafny program verifier finished with 11 verified, 1 error\n')
            self.assertEqual('proof_failed', rp.classify_dafny(4, unrelated_log)['status'])
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.private_count_anchor(public_cert, model, unrelated_log)
            log_path = folder / 'unrelated.log'
            log_path.write_text(unrelated_log)
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp._require_private_count_failure(
                    {'status': 'proof_failed', 'verified': 9, 'errors': 2,
                     'returncode': 4, 'obligation': 'Error: a postcondition could not be proved',
                     'log': str(log_path)},
                    certificate_path=public_cert, model_path=model, label='unrelated')

    def test_missing_related_anchor_wrong_file_and_malformed_parse_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            cert, model, log = self.fixture(folder)
            no_related = log.replace(
                f'{model}({self.MODEL_LINE},28): Related location: this proposition could not be proved\n',
                '')
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.private_count_anchor(cert, model, no_related)
            other = folder / 'other.dfy'
            other.write_text(cert.read_text())
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.private_count_anchor(other, model, log)
            malformed = 'Dafny program verifier finished with 9 verified, 2 errors\n'
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.private_count_anchor(cert, model, malformed)

    def test_precondition_outside_named_chunk_and_resource_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            cert, model, _ = self.fixture(folder)
            precondition_log = (
                f'{cert}(61,12): Error: function precondition could not be proved\n'
                f'   |\n61 |     ensures Exec(P(), 0, s, fuel).1 == Exec(P(), 0, t, fuel).1\n'
                f'{model}(352,13): Related location: this proposition could not be proved\n'
                f'    |\n352 |     requires Structure(p)\n'
                '\nDafny program verifier finished with 9 verified, 2 errors\n')
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.private_count_anchor(cert, model, precondition_log)
            log_path = folder / 'resource.log'
            log_path.write_text('Dafny program verifier finished with 9 verified, 2 errors\n'
                                'out of resource\n')
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp._require_private_count_failure(
                    {'status': 'timeout_resource_or_crash', 'verified': 9, 'errors': 2,
                     'returncode': 4, 'obligation': None, 'log': str(log_path)},
                    certificate_path=cert, model_path=model, label='resource')

    def test_positive_program_diff_is_only_the_two_expected_annotations(self):
        policy, _ = overlaid_policy()
        secret_policy, _ = rp.primitive_policy(
            POLICY, params_overrides={spec.key: ('sec', 'sec') for spec in rp.PRIMITIVES})
        for spec in rp.PRIMITIVES:
            positive = bt.translate(canonical_method(spec), policy, policy['classes'][spec.owner])
            mutant = bt.translate(canonical_method(spec), secret_policy,
                                  secret_policy['classes'][spec.owner])
            diff = rp._private_count_program_diff(positive, mutant)
            self.assertEqual({2: {'positive': 'pub', 'mutant': 'sec'},
                              4: {'positive': 'pub', 'mutant': 'sec'}}, diff['taint_diff'])
            self.assertFalse(diff['unrelated_false_assertions'])
            extra_taint = copy.deepcopy(mutant)
            extra_taint['reg_taints'][5] = 'sec'
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp._private_count_program_diff(positive, extra_taint)
            changed_code = copy.deepcopy(mutant)
            changed_code['code'][0]['kind'] = ('lit', 65)
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp._private_count_program_diff(positive, changed_code)


class TranslationTests(unittest.TestCase):
    def test_actual_translation_shape_and_audit(self):
        for spec in rp.PRIMITIVES:
            result = translated(spec)
            shape = rp.assert_primitive_shape(result, spec)
            self.assertEqual([], bt.audit_certificate(result))
            self.assertEqual(7, len(result['code']))
            self.assertEqual([1, 2], result['param_regs'])
            self.assertEqual({}, result['roles'])
            self.assertEqual({}, result['call_targets'])
            self.assertEqual(7, result['instructions_reachable'])
            self.assertTrue(result['cfg_edges_checked'])
            self.assertEqual({0: 'pub', 1: 'sec', 2: 'pub', 3: 'pub',
                              4: 'pub', 5: 'pub', 6: 'sec'}, shape['reg_taints'])
            branch = next(insn for insn in result['code'] if insn['type'] == 'branch')
            self.assertEqual((2, 4, 5, 3),
                             (branch['site'], branch['cond'], branch['thn'], branch['els']))
            # thn is the shift, els is the zero fall-through: the emitted guard
            # is (count != 64), exactly the JVM if_icmpne.
            self.assertEqual(('lit', 64), result['code'][0]['kind'])
            self.assertEqual(('op', 'ne', 2, 3), result['code'][1]['kind'])
            self.assertEqual(('op', spec.op, 1, 2), result['code'][5]['kind'])

    def test_private_count_mutation_has_named_audit_failure(self):
        policy, _ = rp.primitive_policy(
            POLICY, params_overrides={spec.key: ('sec', 'sec') for spec in rp.PRIMITIVES})
        for spec in rp.PRIMITIVES:
            class_policy = policy['classes'][spec.owner]
            result = bt.translate(canonical_method(spec), policy, class_policy)
            problems = [item['problem'] for item in bt.audit_certificate(result)]
            self.assertTrue(any('secret branch condition' in problem for problem in problems),
                            problems)
            self.assertNotEqual([], problems)
            # Mutating only the annotation cannot turn the model theorem into a
            # universal proof; the expensive replay also requires actual Dafny
            # rejection of this emitted certificate.


class FiniteControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = {spec.key: rp.finite_control(translated(spec), spec)
                    for spec in rp.PRIMITIVES}

    def test_required_counts_are_present_and_trace_equal(self):
        for spec in rp.PRIMITIVES:
            observed = {row['requested_count'] for row in self.rows[spec.key]}
            self.assertTrue(set(REQUIRED_COUNTS).issubset(observed))
            for row in self.rows[spec.key]:
                self.assertEqual('stop/stop', row['terminal'])
                self.assertTrue(row['trace_equal'])
                self.assertTrue(row['public_registers_equal'])
                self.assertTrue(row['difference_is_input_only'])

    def test_guard_is_equality_at_64_not_at_least_64(self):
        for spec in rp.PRIMITIVES:
            for row in self.rows[spec.key]:
                value = row['signed_byte_value']
                self.assertEqual(value == 64, row['zero_branch_taken'], row)
                self.assertEqual(value != 64, row['branch_taken'], row)
                if value == 64:
                    self.assertEqual([0, 0], row['model_results'], row)
                else:
                    # 65..127 and negative byte counts must fall through to the
                    # shift, not to the zero constant.
                    self.assertNotEqual([0, 0], row['model_results'])
            by_count = {row['requested_count']: row for row in self.rows[spec.key]}
            self.assertEqual([0, 0], by_count[64]['model_results'])
            self.assertFalse(by_count[64]['branch_taken'])
            for count in (65, 127, 255, -1, -64, -128):
                self.assertTrue(by_count[count]['branch_taken'], count)
                self.assertFalse(by_count[count]['zero_branch_taken'], count)

    def test_signed_byte_aliases(self):
        expected = {-128: -128, -64: -64, -1: -1, 128: -128, 192: -64, 255: -1}
        for raw, value in expected.items():
            self.assertEqual(value, rp.signed_byte_value(raw))
            self.assertEqual(value & rp.MASK64, rp.count_word(raw))
        for spec in rp.PRIMITIVES:
            by_count = {row['requested_count']: row for row in self.rows[spec.key]}
            self.assertEqual(-1, by_count[255]['signed_byte_value'])
            self.assertEqual(-128, by_count[128]['signed_byte_value'])
            self.assertEqual(-64, by_count[192]['signed_byte_value'])
            # -1 / 255 shift by 63; 128 / -128 and 192 / -64 shift by 0.
            self.assertEqual(by_count[127]['model_results'], by_count[255]['model_results'])
            self.assertEqual(by_count[0]['model_results'], by_count[128]['model_results'])
            self.assertEqual(by_count[0]['model_results'], by_count[192]['model_results'])

    def test_nonvacuity_and_count_64_exception(self):
        for spec in rp.PRIMITIVES:
            for row in self.rows[spec.key]:
                a, b = row['model_results']
                if row['requested_count'] == 64:
                    self.assertEqual(a, b)
                    self.assertEqual(0, a)
                else:
                    self.assertNotEqual(a, b, row)
                    self.assertTrue(row['differing_registers'])

    def test_expected_value_semantics(self):
        left, right = rp.PRIMITIVES
        word = 0x0123456789ABCDEF
        self.assertEqual(word, rp.expected_shift_result(left, word, 0))
        self.assertEqual((word << 1) & rp.MASK64, rp.expected_shift_result(left, word, 1))
        self.assertEqual((word << 1) & rp.MASK64, rp.expected_shift_result(left, word, 65))
        self.assertEqual(0, rp.expected_shift_result(left, word, 64))
        self.assertEqual(0, rp.expected_shift_result(right, word, 64))
        self.assertEqual(1, rp.expected_shift_result(right, 0x8000000000000001, -1))


class ProofStatusTests(unittest.TestCase):
    def test_success_requires_expected_count(self):
        record = rp.classify_dafny(0, 'Dafny program verifier finished with 12 verified, 0 errors',
                                   expected_verified=12)
        self.assertEqual('verified', record['status'])
        record = rp.classify_dafny(0, 'Dafny program verifier finished with 11 verified, 0 errors',
                                   expected_verified=12)
        self.assertEqual('unexpected_verified_count', record['status'])

    def test_genuine_negative_requires_obligation(self):
        log = ('Dafny program verifier finished with 2 verified, 2 errors\n'
               'Error: possible violation of postcondition')
        record = rp.classify_dafny(4, log)
        self.assertEqual('proof_failed', record['status'])
        record = rp.classify_dafny(4, 'Dafny program verifier finished with 2 verified, 2 errors')
        self.assertEqual('not_a_proof_result', record['status'])

    def test_timeout_crash_missing_and_multiple_summaries_are_not_proofs(self):
        summary = 'Dafny program verifier finished with 2 verified, 1 errors'
        cases = [
            (4, summary + '\nError: possible violation of postcondition\ntimed out',
             'timeout_resource_or_crash'),
            (134, '', 'no_single_summary'),
            (1, 'Error: file not found', 'no_single_summary'),
            (0, summary + '\n' + summary, 'no_single_summary'),
        ]
        for status, log, expected in cases:
            record = rp.classify_dafny(status, log)
            self.assertEqual(expected, record['status'], (status, log))
        resource = rp.classify_dafny(4, summary + '\nout of resource')
        self.assertTrue(resource['bad_run'])
        self.assertEqual('timeout_resource_or_crash', resource['status'])
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp._require_proof(rp.classify_dafny(4, summary + '\ntimed out'),
                              expected_verified=2, label='timeout-control')
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp._require_proof_failure(rp.classify_dafny(134, ''), 'crash-control')


class ArtifactBindingTests(unittest.TestCase):
    def test_entry_hash_round_trip_and_tamper(self):
        entry = b'not really a class, but the hash is what binds it'
        expected = hashlib.sha256(entry).hexdigest()
        self.assertEqual(expected, rp.check_entry_identity(entry, expected))
        tampered = bytes([entry[0] ^ 0xFF]) + entry[1:]
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.check_entry_identity(tampered, expected)

    def test_jar_identity_and_entry_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            jar = folder / 'runtime.jar'
            entry = b'pinned-entry-bytes'
            with zipfile.ZipFile(jar, 'w') as archive:
                archive.writestr(rp.HELPERS_ENTRY, entry)
            jar_sha = rp.check_jar_identity(jar, hashlib.sha256(jar.read_bytes()).hexdigest())
            self.assertEqual(jar_sha, hashlib.sha256(jar.read_bytes()).hexdigest())
            bound = rp.bind_helpers(jar, folder / 'work',
                                    expected_jar_sha=jar_sha,
                                    expected_entry_sha=hashlib.sha256(entry).hexdigest())
            self.assertEqual(entry, (Path(bound['classpath']) / rp.HELPERS_ENTRY).read_bytes())
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.check_jar_identity(jar, '0' * 64)
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.bind_helpers(jar, folder / 'work2', expected_jar_sha=jar_sha,
                                expected_entry_sha='0' * 64)

    def test_jar_without_helpers_entry_rejects(self):
        with tempfile.TemporaryDirectory() as folder:
            jar = Path(folder) / 'empty.jar'
            with zipfile.ZipFile(jar, 'w') as archive:
                archive.writestr('other/Class.class', b'x')
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.read_helpers_entry(jar)


class JavaAdapterContractTests(unittest.TestCase):
    def test_java_source_uses_signed_byte_cast_and_hex_words(self):
        source = rp._java_source((0, 64, 255, -1), (0x0123456789ABCDEF, 0xFEDCBA9876543210))
        self.assertIn('(byte) count', source)
        self.assertIn('dafny.Helpers.bv64ShiftLeft', source)
        self.assertIn('dafny.Helpers.bv64ShiftRight', source)
        self.assertIn('0x0123456789ABCDEFL', source)
        self.assertIn('0xFEDCBA9876543210L', source)
        self.assertNotIn('18364758544493064720L', source)

    def test_adapter_comparison_rejects_a_mismatch(self):
        model_rows = {spec.key: rp.finite_control(translated(spec), spec,
                                                  counts=(0, 64), words=(1, 3))
                      for spec in rp.PRIMITIVES}
        java_rows = []
        for raw in (0, 64):
            for word in (1, 3):
                java_rows.append({
                    'word': word, 'requested_count': raw,
                    'left': rp.expected_shift_result(rp.PRIMITIVES[0], word, raw),
                    'right': rp.expected_shift_result(rp.PRIMITIVES[1], word, raw),
                })
        comparison = rp.check_java_adapter(java_rows, model_rows, words=(1, 3))
        self.assertEqual(8, comparison['comparisons'])
        java_rows[0]['left'] ^= 1
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.check_java_adapter(java_rows, model_rows, words=(1, 3))


class OfficialBindingTests(unittest.TestCase):
    def test_after_binding_drift_is_rejected_before_verified(self):
        before = {'composition': {'sha256': 'a' * 64}}
        after = copy.deepcopy(before)
        after['composition']['sha256'] = '0' * 64
        pins = {'composition': {'actual_sha256': 'a' * 64}}
        pins_after = copy.deepcopy(pins)
        pins_after['composition']['actual_sha256'] = '0' * 64
        # Historical old gate: it recorded the after values but never compared them.
        old_gate = lambda b, a, p, q: 'verified'
        self.assertEqual('verified', old_gate(before, after, pins, pins_after))
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.require_stable_binding(before, after, pins, pins_after)
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.require_stable_binding(before, before, pins, pins_after)
        self.assertEqual({'module_binding_equal': True, 'pins_equal': True},
                         rp.require_stable_binding(before, before, pins, pins))

    def test_import_time_binding_records_canonical_modules(self):
        self.assertEqual({'bytecode_trace', 'composition', 'trace_exec'},
                         set(rp.LOADED_MODULE_BINDING))
        expected = json.loads((HERE / 'inputs.json').read_text())['inputs']
        for name, record in rp.LOADED_MODULE_BINDING.items():
            self.assertEqual(record['sha256'], expected[record['pin_key']])
            self.assertEqual(Path(record['path']).resolve(), (HERE / (name + '.py')).resolve())

    def test_loaded_module_binding_rejects_shadow_path_and_wrong_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            shadow = folder / 'composition.py'
            shadow.write_text('# shadow\n')
            fake = types.SimpleNamespace(__file__=str(shadow))
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.bind_loaded_modules({'composition': fake},
                                       canonical={'composition': HERE / 'composition.py'})
            pins = folder / 'inputs.json'
            pins.write_text(json.dumps({
                'inputs': {'formal/timing/composition.py': '0' * 64}}))
            canonical = types.SimpleNamespace(__file__=str(HERE / 'composition.py'))
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.bind_loaded_modules({'composition': canonical}, inputs_path=pins,
                                       canonical={'composition': HERE / 'composition.py'})

    def test_preloaded_shadow_trusted_modules_fail_before_use(self):
        with tempfile.TemporaryDirectory() as folder:
            shadow = Path(folder) / 'shadow'
            shadow.mkdir()
            (shadow / 'composition.py').write_text(
                'WITNESS_STEP_CAP = 1\ndef witness(result):\n    return None\n')
            (shadow / 'trace_exec.py').write_text(
                'def run_to_completion(*args, **kwargs):\n    return None\n')
            (shadow / 'bytecode_trace.py').write_bytes((HERE / 'bytecode_trace.py').read_bytes())
            for name, attribute in (('bytecode_trace', 'bt'), ('composition', 'comp'),
                                    ('trace_exec', 'trace_exec')):
                code = (
                    'import sys\n'
                    f'sys.path.insert(0, {str(shadow)!r})\n'
                    f'import {name}\n'
                    f'sys.path.insert(0, {str(HERE)!r})\n'
                    'import runtime_primitives as rp\n'
                    f'print(rp.{attribute}.__file__)\n')
                completed = subprocess.run([sys.executable, '-c', code],
                                           cwd=str(HERE.parent.parent),
                                           capture_output=True, text=True)
                self.assertNotEqual(0, completed.returncode, name)
                self.assertIn('not the canonical source', completed.stderr, name)

    def test_skip_boolean_api_modes_reject_before_any_work(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'out'
            for kwargs in ({'check_pins': False}, {'run_java': False}):
                with self.assertRaises(TypeError, msg=repr(kwargs)):
                    rp.replay(output, **kwargs)
            self.assertFalse((output / 'runtime-primitives.json').exists())

    def test_cli_rejects_removed_skip_flags(self):
        with tempfile.TemporaryDirectory() as folder:
            for flag in ('--no-pin-check', '--no-java'):
                output = Path(folder) / flag.lstrip('-')
                completed = subprocess.run(
                    [sys.executable, '-m', 'formal.timing.runtime_primitives', flag,
                     '--output', str(output)],
                    cwd=str(HERE.parent.parent), capture_output=True, text=True)
                self.assertNotEqual(0, completed.returncode, flag)
                self.assertIn('unrecognized arguments', completed.stderr, flag)
                self.assertNotIn('Complete', completed.stdout, flag)
                self.assertFalse((output / 'runtime-primitives.json').exists(), flag)


class AdmissionAndPinsTests(unittest.TestCase):
    def test_default_extractor_path_is_the_loaded_module(self):
        self.assertEqual(Path(bt.__file__).resolve(), rp.DEFAULT_EXTRACTOR.resolve())

    def test_expected_pins_are_the_reviewed_ones(self):
        self.assertEqual('dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6',
                         rp.EXPECTED_JAR_SHA256)
        self.assertEqual('4e5ec798394565756a1bc8438eb1638c2ad79eca264ae105ac576f537451e76c',
                         rp.EXPECTED_HELPERS_ENTRY_SHA256)
        self.assertEqual(('--verification-time-limit', '30', '--resource-limit', '50000000',
                          '--solver-option', 'O:smt.case_split=0'), rp.VERIFICATION_FLAGS)
        self.assertEqual({'with_witness': 12, 'without_witness': 11}, rp.EXPECTED_VERIFIED)

    def test_current_policy_matches_a_reviewed_admission_state(self):
        state = rp.reviewed_admission_state(set(POLICY['runtime_classification']['shift_count_public']))
        self.assertTrue(state)
        self.assertIn('current official A', state)
        self.assertEqual({rp.LEFT_SHIFT_CALL, rp.RIGHT_SHIFT_CALL},
                         set(POLICY['runtime_classification']['shift_count_public']))
        self.assertEqual(set(POLICY['runtime_classification']['shift_count_public']),
                         set(bt.SHIFT_COUNT_PUBLIC_RUNTIME_CALLS))
        self.assertIn('dafny/Helpers.bv64ShiftLeft:(JB)J', POLICY['calls'])
        bt.check_runtime_classification(POLICY)

    def test_policy_helpers_entry_hash_is_live_and_tamper_rejected(self):
        runtime = POLICY['runtime_classification']['pinned_runtime']
        self.assertEqual(rp.EXPECTED_HELPERS_ENTRY_SHA256, runtime.get('helpers_entry_sha256'))
        self.assertEqual(rp.EXPECTED_JAR_SHA256, runtime.get('jar_sha256'))
        bound = {'jar_sha256': rp.EXPECTED_JAR_SHA256,
                 'entry_sha256': rp.EXPECTED_HELPERS_ENTRY_SHA256}
        self.assertEqual({'jar_sha256': rp.EXPECTED_JAR_SHA256,
                          'helpers_entry_sha256': rp.EXPECTED_HELPERS_ENTRY_SHA256},
                         rp.require_policy_artifact_pins(POLICY, bound))
        missing = copy.deepcopy(POLICY)
        del missing['runtime_classification']['pinned_runtime']['helpers_entry_sha256']
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.require_policy_artifact_pins(missing, bound)
        tampered = copy.deepcopy(POLICY)
        tampered['runtime_classification']['pinned_runtime']['helpers_entry_sha256'] = '0' * 64
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.require_policy_artifact_pins(tampered, bound)
        with self.assertRaises(rp.RuntimePrimitiveError):
            rp.require_policy_artifact_pins(POLICY, {'jar_sha256': rp.EXPECTED_JAR_SHA256,
                                                     'entry_sha256': '0' * 64})

    def test_reviewed_admission_states_are_exact(self):
        right = rp.RIGHT_SHIFT_CALL
        left = rp.LEFT_SHIFT_CALL
        self.assertIn('right-only', rp.reviewed_admission_state({right}))
        self.assertIn('right-plus-left', rp.reviewed_admission_state({right, left}))
        for admitted in (set(), {left}, {right, 'java/lang/Other.x:()V'}):
            with self.assertRaises(rp.RuntimePrimitiveError):
                rp.reviewed_admission_state(admitted)


@unittest.skipUnless(os.environ.get('RUNTIME_PRIMITIVES_REPLAY') == '1',
                     'set RUNTIME_PRIMITIVES_REPLAY=1 for the expensive jar/Dafny/Java replay')
class ExpensiveReplayTests(unittest.TestCase):
    def test_complete_replay_writes_verified_evidence(self):
        # Prefer the JDK 21 used by the reviewed bytecode evidence; fall back to
        # an ambient JAVA_HOME when that installation is not present.
        pinned_jdk = Path('/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home')
        java_home = pinned_jdk if (pinned_jdk / 'bin/javap').is_file() else rp.DEFAULT_JAVA_HOME
        with tempfile.TemporaryDirectory() as folder:
            evidence = rp.replay(Path(folder) / 'out', java_home=java_home)
        self.assertEqual('verified', evidence['status'])
        self.assertEqual('dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6',
                         evidence['artifact_binding']['jar_sha256'])
        self.assertEqual('4e5ec798394565756a1bc8438eb1638c2ad79eca264ae105ac576f537451e76c',
                         evidence['artifact_binding']['entry_sha256'])
        for spec in rp.PRIMITIVES:
            proofs = evidence['proofs'][spec.key]
            self.assertEqual('verified', proofs['with_witness']['status'])
            self.assertEqual('verified', proofs['without_witness']['status'])
            self.assertEqual(12, proofs['with_witness']['verified'])
            self.assertEqual(11, proofs['without_witness']['verified'])
            self.assertEqual([], proofs['audit'])
            self.assertTrue(proofs['witness']['nonvacuity'])
            negative = evidence['negative_controls'][spec.key]
            self.assertEqual('proof_failed', negative['dafny']['status'])
            self.assertEqual(9, negative['dafny']['verified'])
            self.assertEqual(2, negative['dafny']['errors'])
            self.assertEqual('proof_failed_named_chunk0_branch_postcondition',
                             negative['anchor_status'])
            self.assertEqual('ensures InstrOK(p, p.chunks[0][j])',
                             negative['anchor']['certificate_statement'])
            self.assertEqual('cond < p.registers && RegTaint(p, cond) == Pub &&',
                             negative['anchor']['model_statement'])
            self.assertTrue(negative['program_diff']['executable_instructions_equal'])
            self.assertEqual({2, 4}, {int(key) for key in negative['program_diff']['taint_diff']})
            self.assertFalse(negative['program_diff']['unrelated_false_assertions'])
            self.assertTrue(any('secret branch condition' in item
                                for item in negative['audit']))
            counts = {row['requested_count'] for row in proofs['finite_controls']}
            self.assertTrue(set(REQUIRED_COUNTS).issubset(counts))
            self.assertTrue(evidence['binding_controls']['tampered_entry']['rejected'])
            self.assertTrue(evidence['binding_controls']['wrong_owner']['rejected'])
        self.assertEqual('finite-java-equals-model',
                         evidence['java_adapter']['comparison']['status'])
        self.assertTrue(evidence['policy_overlay']['admission_tables_unchanged']['calls'])
        self.assertEqual({'module_binding_equal': True, 'pins_equal': True},
                         evidence['binding_stability'])
        self.assertEqual(rp.EXPECTED_HELPERS_ENTRY_SHA256,
                         evidence['artifact_binding']['policy_pinned_runtime_helpers_entry_sha256'])
        self.assertIn('current official A', evidence['scope']['admission_state'])


if __name__ == '__main__':
    unittest.main()
