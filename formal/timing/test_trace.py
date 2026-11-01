import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import bytecode_trace as bt
import run

HERE = Path(__file__).resolve().parent
JDK = Path(os.environ.get('JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))
JAVAP = JDK / 'bin/javap'
JAVAC = JDK / 'bin/javac'
POLICY = json.loads((HERE / 'policy.json').read_text())


class BytecodeTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.classes = Path(cls.folder.name)
        subprocess.run([str(JAVAC), '-g', '--release', '21', '-d', str(cls.classes)]
                       + [str(p) for p in sorted((HERE / 'fixtures').glob('*.java'))],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def fixture(self, spec):
        methods = bt.disassemble(JAVAP, self.classes, spec['class'])
        policy = {'calls': {**POLICY['calls'], **spec.get('calls', {})},
                  'statics': POLICY['statics'],
                  'classes': {spec['class']: {
                      'methods': {spec['method']: {'params': spec['params']}},
                      'fields': spec.get('fields', {})}}}
        return methods[spec['method']], policy, policy['classes'][spec['class']]

    def spec(self, name):
        return next(f for f in POLICY['fixtures'] if f['class'] == name)

    def test_parser_and_cfg_shapes(self):
        spec = self.spec('ConstantTime')
        method, _, _ = self.fixture(spec)
        self.assertTrue(method.insns)
        succ = bt.cfg(method)
        self.assertEqual(0, bt.stack_depths(method, succ)[method.insns[0].offset])
        self.assertIn('select', method.name)

    def test_positive_fixture_translates_and_audits_clean(self):
        method, policy, cp = self.fixture(self.spec('ConstantTime'))
        result = bt.translate(method, policy, cp)
        self.assertEqual([], bt.audit_certificate(result))
        text = bt.certificate_module('ConstantTimeTest', result)
        self.assertIn('lemma TwoRun', text)
        self.assertIn('lemma WellFormed', text)
        # F1: every emitted instruction must be reachable from entry.
        self.assertEqual(len(result['code']), result['instructions_reachable'])

    def test_secret_branch_rejected(self):
        method, policy, cp = self.fixture(self.spec('SecretBranch'))
        result = bt.translate(method, policy, cp)
        self.assertTrue(any('secret branch' in f['problem'] for f in bt.audit_certificate(result)))

    def test_secret_index_rejected(self):
        method, policy, cp = self.fixture(self.spec('SecretIndex'))
        result = bt.translate(method, policy, cp)
        self.assertTrue(any('secret load index' in f['problem'] for f in bt.audit_certificate(result)))

    def test_early_compare_rejected(self):
        method, policy, cp = self.fixture(self.spec('EarlyCompare'))
        result = bt.translate(method, policy, cp)
        self.assertTrue(any('secret branch' in f['problem'] for f in bt.audit_certificate(result)))

    def test_exception_oracle_fails_closed(self):
        method, policy, cp = self.fixture(self.spec('ExceptionOracle'))
        with self.assertRaises(bt.PolicyError):
            bt.translate(method, policy, cp)

    def test_secret_allocation_rejected(self):
        method, policy, cp = self.fixture(self.spec('SecretAlloc'))
        result = bt.translate(method, policy, cp)
        self.assertTrue(any('secret allocation' in f['problem'] for f in bt.audit_certificate(result)))

    def test_secret_loop_bound_rejected(self):
        method, policy, cp = self.fixture(self.spec('SecretLoopBound'))
        result = bt.translate(method, policy, cp)
        self.assertTrue(any('secret branch' in f['problem'] for f in bt.audit_certificate(result)))

    def test_secret_digest_comparison_branch_rejected(self):
        method, policy, cp = self.fixture(self.spec('SecretDigestBranch'))
        result = bt.translate(method, policy, cp)
        self.assertTrue(any('secret branch' in f['problem'] for f in bt.audit_certificate(result)))

    def test_unlisted_call_fails_closed(self):
        method, _, cp = self.fixture(self.spec('SecretDigestBranch'))
        policy = {'calls': {}, 'statics': {}, 'classes': cp}
        with self.assertRaises(bt.PolicyError):
            bt.translate(method, policy, cp)

    def test_certificate_mutation_is_detected_by_audit(self):
        method, policy, cp = self.fixture(self.spec('ConstantTime'))
        result = bt.translate(method, policy, cp)
        sec = next(r for r, t in result['reg_taints'].items() if t == 'sec' and r < result['registers'])
        import copy
        mutant = copy.deepcopy(result)
        branch = next(i for i in mutant['code'] if i['type'] == 'branch')
        branch['cond'] = sec
        self.assertTrue(bt.audit_certificate(mutant))
        mutant = copy.deepcopy(result)
        load = next(i for i in mutant['code'] if i['type'] == 'step' and i['kind'][0] == 'load')
        load['kind'] = ('load', load['kind'][1], sec)
        self.assertTrue(bt.audit_certificate(mutant))

    def test_policy_roots_are_resolvable(self):
        for root in POLICY['roots']:
            cp = POLICY['classes'][root['class'].replace('.', '/')]
            key = f"{root['name']}:{root['descriptor']}"
            self.assertIn(key, cp['methods'], root['class'])
            for param in cp['methods'][key]['params']:
                self.assertIn(param, ('pub', 'sec', 'array_pub', 'array_sec', 'seq_pub', 'seq_sec'))

    def test_unsupported_opcode_fails_closed(self):
        insn = bt.Insn(0, 'multianewarray', '', '0: multianewarray')
        with self.assertRaises(bt.PolicyError):
            bt.stack_effect(insn)

    def test_field_alias_write_rejected(self):
        method, policy, cp = self.fixture(self.spec('FieldAlias'))
        with self.assertRaisesRegex(bt.PolicyError, 'reference field'):
            bt.translate(method, policy, cp)

    def test_virtual_dispatch_rejected(self):
        method, policy, cp = self.fixture(self.spec('VirtualDispatch'))
        with self.assertRaisesRegex(bt.PolicyError, 'virtual dispatch'):
            bt.translate(method, policy, cp)

    def test_runtime_type_test_rejected(self):
        method, policy, cp = self.fixture(self.spec('ClassOracle'))
        with self.assertRaisesRegex(bt.PolicyError, 'type test/cast'):
            bt.translate(method, policy, cp)

    def test_object_identity_rejected(self):
        method, policy, cp = self.fixture(self.spec('NewIdentity'))
        with self.assertRaisesRegex(bt.PolicyError, 'object identity/new'):
            bt.translate(method, policy, cp)

    def test_call_result_array_without_length_contract_rejected(self):
        method, policy, cp = self.fixture(self.spec('ResultArrayCall'))
        with self.assertRaisesRegex(bt.PolicyError, 'length contract'):
            bt.translate(method, policy, cp)

    def test_category_two_stack_op_rejected(self):
        method, policy, cp = self.fixture(self.spec('CategoryTwo'))
        with self.assertRaisesRegex(bt.PolicyError, 'category-2'):
            bt.translate(method, policy, cp)

    def test_fake_dafny_build_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Unexpected Dafny build'):
            run.require_exact_build('4.9.1+deadbeef')

    def test_arbitrary_runtime_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            fake = Path(folder) / 'DafnyRuntime.jar'
            fake.write_bytes(b'not the pinned runtime')
            with self.assertRaisesRegex(RuntimeError, 'DafnyRuntime checksum'):
                run.check_runtime(fake)

    def test_changed_shared_helper_pin_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Pinned input changed'):
            run.check_inputs({'formal/dafny/toolchain.py': '0' * 64})

    def test_fake_runtime_fails_before_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fake = root / 'DafnyRuntime.jar'
            fake.write_bytes(b'not the pinned runtime')
            code = run.main(['--output', str(root / 'out'), '--runtime', str(fake),
                             '--classes', str(root / 'missing-classes'), '--java-home', str(JDK)])
            self.assertEqual(1, code)
            report = (root / 'out' / 'report.json').read_text()
            self.assertIn('DafnyRuntime checksum', report)

    def test_fixture_inventory_is_explicit(self):
        expected = {'ConstantTime', 'SecretBranch', 'SecretIndex', 'EarlyCompare',
                    'ExceptionOracle', 'SecretAlloc', 'SecretLoopBound', 'SecretDigestBranch',
                    'FieldAlias', 'VirtualDispatch', 'ClassOracle', 'NewIdentity',
                    'ResultArrayCall', 'CategoryTwo'}
        self.assertEqual(expected, {f['class'] for f in POLICY['fixtures']})



class CalleeScopeTests(unittest.TestCase):
    def test_owned_callee_classes_are_bound_even_without_root_certificate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rebuilt, production = root / 'rebuilt', root / 'production'
            extra = 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.class'
            for name in [*run.ROOT_CLASSES, extra]:
                for folder in (rebuilt, production):
                    path = folder / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'identity fixture, not executable crypto')
            bound = run.bind_classes(root, rebuilt, production)
            self.assertIn(extra, bound)
            (production / extra).write_bytes(b'changed callee')
            with self.assertRaisesRegex(RuntimeError, 'differs'):
                run.bind_classes(root, rebuilt, production)

    def test_every_opaque_owned_call_is_explicitly_assumed(self):
        target = 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.compute:()I'
        provider = 'java/lang/Integer.intValue:()I'
        policy = {'calls': {target: {'kind': 'call', 'result': 'sec'}, provider: {}},
                  'unchecked_owned_callees': [target]}
        roots = [{'call_targets': {target: 1, provider: 2}}]
        scope = run.owned_contracts(roots, policy)
        self.assertEqual([target], [entry['target'] for entry in scope])
        self.assertEqual('assumed-not-traced', scope[0]['trace_status'])
        policy['unchecked_owned_callees'] = []
        with self.assertRaisesRegex(RuntimeError, 'owned callee'):
            run.owned_contracts(roots, policy)

    def test_unused_open_label_units_has_no_false_zero_length_contract(self):
        target = 'io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.labelUnits:(Ljava/lang/String;)Ldafny/DafnySequence;'
        self.assertFalse(target in POLICY['calls'], 'open labelUnits must remain unmodeled')


if __name__ == '__main__':
    unittest.main()
