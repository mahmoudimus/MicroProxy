import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# This module imports its siblings by bare name. Make those imports work no
# matter how the module is entered: `python3 -m unittest formal.timing.test_trace`
# from the repository root (namespace package), `python3 -m unittest discover`,
# or `python3 formal/timing/test_trace.py` directly.
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import bytecode_trace as bt  # noqa: E402
import composition as comp  # noqa: E402
import run  # noqa: E402
import trace_exec  # noqa: E402
JDK = Path(os.environ.get('JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))
JAVAP = JDK / 'bin/javap'
JAVAC = JDK / 'bin/javac'
RUNTIME = Path(os.environ.get(
    'DAFNY_RUNTIME',
    str(Path.home() / '.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar')))
DAFNY = Path(os.environ.get(
    'DAFNY', str(Path.home() / '.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny')))
POLICY = json.loads((HERE / 'policy.json').read_text())

#: Fixtures are compiled once per test module (all test classes share them).
_FIXTURE_DIR = None


def setUpModule():
    global _FIXTURE_DIR
    _FIXTURE_DIR = tempfile.TemporaryDirectory()
    subprocess.run([str(JAVAC), '-g', '--release', '21', '-cp', str(RUNTIME),
                    '-d', _FIXTURE_DIR.name]
                   + [str(p) for p in sorted((HERE / 'fixtures').glob('*.java'))],
                   check=True, capture_output=True)


def tearDownModule():
    if _FIXTURE_DIR is not None:
        _FIXTURE_DIR.cleanup()


def fixture_classes() -> Path:
    return Path(_FIXTURE_DIR.name)


def callee_contract(name, descriptor, params, result='args', heap='none'):
    """A recorded callee contract matching `params` (review-record shape)."""
    argument_types, _ = bt.descriptor_types(descriptor)
    role_names = [f'p{i}' for i in range(len(argument_types))]
    roles = {role: taint for role, taint in zip(role_names, params)}
    roles['result'] = result
    return {'params': list(params), 'result': result, 'heap': heap,
            'reading': 'unit-test contract', 'roles': roles}


class BytecodeTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.classes = fixture_classes()

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
        # F3 tightened this control: the secret *heap* argument is now rejected
        # at the external call site (the runtime may branch on the contents)
        # before the branch on the secret result is reached.
        method, policy, cp = self.fixture(self.spec('SecretDigestBranch'))
        with self.assertRaisesRegex(bt.PolicyError, 'secret heap argument'):
            bt.translate(method, policy, cp)

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
        for root in (POLICY['roots'] + POLICY.get('callee_roots', [])
                     + POLICY.get('composed_roots', [])):
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

    def test_call_composition_fixtures_reject_normally(self):
        expected = {
            'CalleeOwner': 'unlisted call',
            'CalleeDescriptor': 'unlisted call',
            'SecretResultBranch': 'secret branch',
            'HeapResultLaunder': 'sec > annot pub',
            'PostWipeLaunder': 'secret branch',
            'PrivateEuclidean': 'public-argument-only runtime call',
            'PrivateEuclideanDivision': 'public-argument-only runtime call',
            'LongSlotPrivate': 'secret branch',
            'LongSlotArray': 'secret branch',
        }
        for name, reason in expected.items():
            spec = self.spec(name)
            method, policy, cp = self.fixture(spec)
            try:
                result = bt.translate(method, policy, cp)
                failures = bt.audit_certificate(result)
                actual = failures[0]['problem'] if failures else ''
            except bt.PolicyError as error:
                actual = str(error)
            self.assertIn(reason, actual, name)

    def test_callee_roots_and_composed_scope_are_explicit(self):
        callee_targets = {f"{r['class'].replace('.', '/')}.{r['name']}:{r['descriptor']}"
                          for r in POLICY['callee_roots']}
        composed = POLICY['composed_roots'][0]
        discharged = {
            'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Extract:(JII)I',
            'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.PublicMod:(II)I',
            'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Wipe:([I)V',
        }
        self.assertEqual(discharged, set(composed['discharged']))
        self.assertTrue(discharged <= callee_targets)
        self.assertEqual(set(composed['discharged']) | set(composed['supporting']),
                         set(composed['inline']))
        self.assertFalse(discharged & set(composed['supporting']))
        # The policy's own accounting must agree with the composed root.
        self.assertEqual(discharged, set(POLICY['composition']['discharged_targets']))
        self.assertEqual(set(composed['supporting']),
                         set(POLICY['composition']['supporting_targets']))
        # The original caller roots keep the discharged targets in opaque scope.
        self.assertTrue(discharged <= set(POLICY['unchecked_owned_callees']))
        feed = next(r for r in POLICY['roots'] if r['name'] == 'Feed')
        self.assertEqual(
            'io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.__default',
            feed['class'])
        self.assertEqual(
            '([I[B)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;',
            feed['descriptor'])
        self.assertEqual(5, len(POLICY['roots']))

    def test_public_euclidean_and_long_slot_fixtures_accept(self):
        for name in ('PublicEuclidean', 'LongSlotPublic', 'HeapExternalPublic'):
            spec = self.spec(name)
            method, policy, cp = self.fixture(spec)
            result = bt.translate(method, policy, cp)
            self.assertEqual([], bt.audit_certificate(result), name)

    def test_long_slot_parameter_metadata_and_return_registers(self):
        for name, expected_taints in (('LongSlotPrivate', ['pub', 'sec']),
                                      ('LongSlotPublic', ['pub', 'pub'])):
            spec = self.spec(name)
            method, policy, cp = self.fixture(spec)
            result = bt.translate(method, policy, cp)
            # Category-2 (long) parameters occupy two JVM slots; the parameter
            # register list is the actual mapping the certificate uses.
            self.assertEqual(2, len(result['param_regs']), name)
            self.assertEqual([1, 2], result['param_regs'], name)
            self.assertEqual(expected_taints,
                             [result['reg_taints'][r] for r in result['param_regs']], name)
            stops = [i for i in result['code'] if i['type'] == 'stop']
            self.assertTrue(stops)
            self.assertTrue(all(s.get('ret') is not None for s in stops), name)

    def test_runtime_classification_covers_euclidean_overloads_and_guard(self):
        families = set(POLICY['runtime_classification']['euclidean_families'])
        self.assertEqual(10, len(families))
        # F4: the recorded classification must equal the enforced code tables.
        self.assertEqual(bt.PRIVATE_SAFE_RUNTIME_CALLS,
                         set(POLICY['runtime_classification']['private_safe']))
        self.assertEqual(bt.SHIFT_COUNT_PUBLIC_RUNTIME_CALLS,
                         set(POLICY['runtime_classification']['shift_count_public']))
        self.assertEqual(set(bt.PUBLIC_HEAP_EXCEPTIONS),
                         set(POLICY['runtime_classification']['public_heap_exceptions']))
        bt.check_runtime_classification(POLICY)
        for target in POLICY['calls']:
            if target.startswith('dafny/DafnyEuclidean.'):
                self.assertIn(target, families)
        self.assertFalse(bt.runtime_call_public_ok(
            'dafny/DafnyEuclidean.EuclideanModulus:(II)I', ['sec', 'pub']))
        self.assertTrue(bt.runtime_call_public_ok(
            'dafny/DafnyEuclidean.EuclideanModulus:(II)I', ['pub', 'pub']))
        self.assertTrue(bt.runtime_call_public_ok('dafny/Helpers.bv64ShiftRight:(JB)J', ['sec', 'pub']))
        self.assertFalse(bt.runtime_call_public_ok('dafny/Helpers.bv64ShiftRight:(JB)J', ['sec', 'sec']))
        self.assertFalse(bt.runtime_call_public_ok('dafny/Helpers.toInt:(I)I', ['sec']))
        self.assertFalse(bt.runtime_call_public_ok('dafny/Helpers.toIntChecked:(JLjava/lang/String;)I',
                                                   ['sec', 'pub']))
        # F3: heap contents are part of the public-argument requirement.
        self.assertFalse(bt.runtime_call_public_ok(
            'java/security/MessageDigest.isEqual:([B[B)Z', ['pub', 'pub'], ['pub', 'sec']))
        self.assertTrue(bt.runtime_call_public_ok(
            'java/security/MessageDigest.isEqual:([B[B)Z', ['pub', 'pub'], ['pub', 'pub']))
        self.assertTrue(bt.runtime_call_public_ok(
            'java/security/MessageDigest.isEqual:([B[B)Z', ['pub', 'pub']))

    def test_audit_rejects_private_runtime_argument_after_mutation(self):
        spec = self.spec('PublicEuclidean')
        method, policy, cp = self.fixture(spec)
        result = bt.translate(method, policy, cp)
        call = next(i for i in result['code'] if i['type'] == 'step' and i['kind'][0] == 'call')
        result['reg_taints'][call['kind'][2][0]] = 'sec'
        problems = [f['problem'] for f in bt.audit_certificate(result)]
        self.assertTrue(any('public-argument-only' in p for p in problems), problems)

    def test_fixture_inventory_is_explicit(self):
        expected = {'ConstantTime', 'SecretBranch', 'SecretIndex', 'EarlyCompare',
                    'ExceptionOracle', 'SecretAlloc', 'SecretLoopBound', 'SecretDigestBranch',
                    'FieldAlias', 'VirtualDispatch', 'ClassOracle', 'NewIdentity',
                    'ResultArrayCall', 'CategoryTwo', 'CalleeOwner', 'CalleeDescriptor',
                    'SecretResultBranch', 'HeapResultLaunder', 'PostWipeLaunder',
                    'PrivateEuclidean', 'PublicEuclidean', 'PrivateEuclideanDivision',
                    'LongSlotPrivate', 'LongSlotPublic', 'LongSlotArray',
                    'HeapExternalCompare', 'HeapExternalPublic'}
        self.assertEqual(expected, {f['class'] for f in POLICY['fixtures']})
        self.assertEqual(len(expected), len(POLICY['fixtures']),
                         'each reviewed fixture class must have exactly one recorded spec')



class InlineCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.classes = fixture_classes()

    def policy(self, caller_method, caller_params):
        policy = copy.deepcopy(POLICY)
        policy['calls'].update({
            'InlineCallee.add:(II)I': {'kind': 'call', 'result': 'args'},
            'InlineCallee.sub:(II)I': {'kind': 'call', 'result': 'args'},
            'InlineCallee.clear:([I)V': {'kind': 'call', 'result': 'sec'},
            'InlineCallee.write:([II)V': {'kind': 'call', 'result': 'sec'},
        })
        policy['classes']['InlineCallee'] = {'fields': {}, 'methods': {
            'add:(II)I': {'params': ['sec', 'pub']},
            'sub:(II)I': {'params': ['sec', 'pub']},
            'clear:([I)V': {'params': ['array_sec']},
            'write:([II)V': {'params': ['array_sec', 'sec']},
        }}
        policy['classes']['InlineCaller'] = {'fields': {}, 'methods': {
            caller_method: {'params': caller_params}}}
        return policy

    CALLEE_PARAMS = {
        'add:(II)I': ['sec', 'pub'],
        'sub:(II)I': ['sec', 'pub'],
        'clear:([I)V': ['array_sec'],
        'write:([II)V': ['array_sec', 'sec'],
    }

    def entries(self, targets):
        records = []
        for name, desc in targets:
            declared = self.CALLEE_PARAMS[f'{name}:{desc}']
            if desc.endswith(')V'):
                result = 'V'
                heap = 'parameter-array-clear' if name == 'clear' else 'parameter-array-write'
            else:
                result = 'args'
                heap = 'none'
            records.append({'class': 'InlineCallee', 'name': name, 'descriptor': desc,
                            'contract': callee_contract(name, desc, declared, result, heap)})
        return records

    def inline(self, caller_method, caller_params, targets):
        policy = self.policy(caller_method, caller_params)
        methods = bt.disassemble(JAVAP, self.classes, 'InlineCaller')
        result = bt.translate(methods[caller_method], policy, policy['classes']['InlineCaller'])
        specs = comp.load_callee_specs(policy, JAVAP, self.classes, self.entries(targets))
        composed = comp.inline_owned_callees(result, specs, policy)
        composed['call_targets'] = comp.active_targets(composed)
        return composed

    def test_public_argument_result_is_composed_and_branchable(self):
        result = self.inline('addPublic:(I)I', ['pub'], [('add', '(II)I')])
        self.assertEqual([], bt.audit_certificate(result))
        self.assertNotIn('InlineCallee.add:(II)I', result['call_targets'])
        self.assertEqual(1, len(result['inlined']))
        self.assertIsNone(comp.witness(result))

    def test_secret_argument_result_cannot_control_caller_branch(self):
        result = self.inline('addSecret:(I)I', ['sec'], [('add', '(II)I')])
        problems = [f['problem'] for f in bt.audit_certificate(result)]
        self.assertTrue(any('secret branch' in p for p in problems), problems)
        self.assertIsNotNone(comp.witness(result))

    def test_inline_exposes_heap_write_instead_of_hiding_it(self):
        with self.assertRaisesRegex(bt.PolicyError, 'secret write into public array'):
            self.inline('writeThenRead:([II)I', ['array_pub', 'sec'], [('write', '([II)V')])

    def test_inline_models_callee_heap_stores_on_secret_role(self):
        result = self.inline('clearThenRead:([I)I', ['array_sec'], [('clear', '([I)V')])
        self.assertEqual([], bt.audit_certificate(result))
        stores = [i for i in result['code']
                  if i['type'] == 'step' and i['kind'][0] == 'store']
        self.assertTrue(stores)
        self.assertTrue(all(s['kind'][1] == 'InlineCaller.clearThenRead#p0' for s in stores))
        witness = comp.witness(result)
        self.assertIsNotNone(witness)
        # F1/F5: the stores must actually be *executed*, not merely emitted.
        execution = witness['execution']
        self.assertIsNotNone(execution)
        self.assertEqual('stop', execution['terminal'])
        self.assertEqual(4, execution['counts']['store'])
        self.assertEqual(4, len(execution['store_events']))
        self.assertTrue(execution['public_registers_agree'])

    def test_copy_operand_order_matches_frozen_apply(self):
        # F1/L1: copies must carry the value in operand `b` (the frozen model's
        # Apply(12, a, b) == b) and a public placeholder in operand `a`. This
        # asserts the *positions* against a secret source, so restoring the old
        # `Op(12, src, 0)` order fails all three assertions (placeholder becomes
        # the secret source, the source becomes the public zero register, and the
        # emitted certificate no longer contains `Op(12, 0, src)`).
        shape = standalone_translate('ExtractShape', 'extract:(JII)I', ['sec', 'pub', 'pub'])
        copies = [i for i in shape['code'] if i['type'] == 'step'
                  and i['kind'][0] == 'op' and i['kind'][1] == 'copy']
        self.assertTrue(copies)
        first = copies[0]
        self.assertEqual(0, first['kind'][2], first)
        self.assertEqual('sec', shape['reg_taints'].get(first['kind'][3], 'sec'), first)
        text = bt.certificate_module('CopyShape', shape)
        self.assertIn('Op(12, 0, %d)' % first['kind'][3], text)
        # Composed bodies remap the zero register: the placeholder is a public
        # register and the frozen Apply returns the source (never the placeholder).
        result = self.inline('clearThenRead:([I)I', ['array_sec'], [('clear', '([I)V')])
        composed = [i for i in result['code'] if i['type'] == 'step'
                    and i['kind'][0] == 'op' and i['kind'][1] == 'copy']
        self.assertTrue(composed)
        for copy in composed:
            placeholder, source = copy['kind'][2], copy['kind'][3]
            self.assertNotEqual(placeholder, source, copy)
            self.assertEqual('pub', result['reg_taints'].get(placeholder, 'sec'), copy)
            self.assertEqual(source,
                             trace_exec.apply(bt.KIND['copy'], placeholder, source))

    def test_exact_target_mismatch_is_not_inlined(self):
        result = self.inline('subResult:(I)I', ['pub'], [('add', '(II)I')])
        self.assertNotIn('inlined', result)
        self.assertIn('InlineCallee.sub:(II)I', result['call_targets'])

    def test_reference_result_callee_is_rejected(self):
        policy = self.policy('addPublic:(I)I', ['pub'])
        with self.assertRaisesRegex(bt.PolicyError, 'scalar/void results'):
            comp.load_callee_specs(policy, JAVAP, self.classes,
                                   [{'class': 'InlineCallee', 'name': 'make', 'descriptor': '(I)[I'}])

    def test_inlined_body_shape_binds_to_certified_direct_translation(self):
        result = self.inline('addPublic:(I)I', ['pub'], [('add', '(II)I')])
        policy = self.policy('addPublic:(I)I', ['pub'])
        methods = bt.disassemble(JAVAP, self.classes, 'InlineCallee')
        direct = bt.translate(methods['add:(II)I'], policy, policy['classes']['InlineCallee'])
        expected = hashlib.sha256(json.dumps(comp.shape_signature(direct), sort_keys=True).encode()).hexdigest()
        self.assertEqual(expected, result['inlined'][0]['callee_shape_sha256'])

    def test_composition_does_not_add_owned_assumptions(self):
        result = self.inline('addPublic:(I)I', ['pub'], [('add', '(II)I')])
        self.assertEqual(set(), {t for t in result['call_targets'] if t.startswith('InlineCallee.')})
        self.assertEqual([], bt.audit_certificate(result))


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



def fixture_spec(name):
    return next(f for f in POLICY['fixtures'] if f['class'] == name)


def fixture_policy_for(spec):
    return {'calls': {**POLICY['calls'], **spec.get('calls', {})},
            'statics': POLICY['statics'],
            'classes': {spec['class']: {
                'methods': {spec['method']: {'params': spec['params']}},
                'fields': spec.get('fields', {})}}}


def fixture_method(spec):
    return bt.disassemble(JAVAP, fixture_classes(), spec['class'])[spec['method']]


def standalone_translate(name, method, params, calls=None):
    """Translate one fixture method as its own root with a synthetic policy."""
    policy = {'calls': {**POLICY['calls'], **(calls or {})},
              'statics': POLICY['statics'],
              'classes': {name: {'methods': {method: {'params': params}}, 'fields': {}}}}
    methods = bt.disassemble(JAVAP, fixture_classes(), name)
    return bt.translate(methods[method], policy, policy['classes'][name])


class TraceExecutionTests(unittest.TestCase):
    """F1/F5: concrete executed control flow and the frozen operand table."""

    def standalone(self, name, method, params, calls=None):
        return standalone_translate(name, method, params, calls)

    def wipe_shaped(self):
        return self.standalone('InlineCallee', 'clear:([I)V', ['array_sec'],
                               {'InlineCallee.clear:([I)V': {'kind': 'call', 'result': 'sec'}})

    def test_frozen_apply_operand_order(self):
        # The frozen model is Apply(12, a, b) == b and Apply(8, a, b) == a; the
        # translator must therefore emit copies as Op(12, 0, src).
        self.assertEqual(9, trace_exec.apply(bt.KIND['copy'], 7, 9))
        self.assertEqual(7, trace_exec.apply(bt.KIND['cast'], 7, 9))

    def test_wipe_shaped_fixture_reaches_all_stores_and_terminates(self):
        result = self.wipe_shaped()
        witness = comp.witness(result)
        self.assertIsNotNone(witness)
        execution = witness['execution']
        self.assertIsNotNone(execution, 'witness execution must complete, not truncate')
        self.assertEqual('stop', execution['terminal'])
        self.assertEqual(4, execution['counts']['store'])
        self.assertEqual(4, len(execution['store_events']))
        self.assertEqual([0, 0, 0, 0], execution['final_heap'][0])
        self.assertTrue(execution['zeroed_roles'])
        self.assertGreaterEqual(witness['fuel'], execution['steps'])
        self.assertTrue(execution['public_registers_agree'])

    def test_extract_shaped_private_flow_through_ops_is_live(self):
        # ExtractShape uses a real `>>>` op (not the atomic external call used by
        # the generated Extract), so the fixture can show the secret reaching the
        # returned register. The *real* `Callee_Extract` must not be asserted that
        # way: its `Helpers.bv64ShiftRight` call is atomic and the model's
        # ProviderResult depends only on public arguments (helper-model
        # abstraction; only non-parameter liveness is demonstrated there).
        result = self.standalone('ExtractShape', 'extract:(JII)I', ['sec', 'pub', 'pub'])
        self.assertEqual([1, 2, 3], result['param_regs'],
                         'category-2 long parameter occupies JVM slots 0-1')
        witness = comp.witness(result)
        execution = witness['execution']
        self.assertIsNotNone(execution)
        self.assertEqual('stop', execution['terminal'])
        stop = next(i for i in result['code'] if i['type'] == 'stop')
        self.assertIsNotNone(stop['ret'])
        self.assertIn(stop['ret'], execution['differing_registers'])
        non_param = [r for r in execution['differing_registers']
                     if r not in result['param_regs']]
        self.assertTrue(non_param, execution['differing_registers'])
        self.assertTrue(execution['public_registers_agree'])
        # M2: only private parameters differ initially; every other secret
        # register starts equal (zero), so the differences above come from
        # execution rather than from initialisation.
        param_set = set(result['param_regs'])
        for r in range(result['registers']):
            if result['reg_taints'].get(r, 'sec') == 'sec' and r not in param_set:
                self.assertEqual(0, witness['regs_s'][r], r)
                self.assertEqual(0, witness['regs_t'][r], r)

    def test_witness_is_hypothesis_only_when_no_finite_execution(self):
        result = self.wipe_shaped()
        witness = comp.witness(result)
        view = trace_exec.ProgramView(result)
        self.assertIsNone(trace_exec.run_to_completion(
            view, witness['regs_s'], witness['heap_s'], 1, 1))
        hypothesis_only = dict(witness)
        hypothesis_only['execution'] = None
        hypothesis_only['fuel'] = None
        text = bt.certificate_module('Hypothesis', result, witness=hypothesis_only)
        self.assertIn('lemma WitnessHypothesis', text)
        self.assertNotIn('lemma Witness()', text)
        text = bt.certificate_module('Validated', result, witness=witness)
        self.assertIn('lemma Witness()', text)
        self.assertIn('TwoRun(WS(), WT(), %d)' % witness['fuel'], text)
        # Concrete executed control flow is validated by the bounded interpreter,
        # not by symbolically unrolling a long Exec in the verifier.
        self.assertNotIn('EStore?', text)

    @unittest.skipUnless(DAFNY.is_file(), 'pinned Dafny toolchain not available')
    def test_apply_mirror_matches_compiled_dafny_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            for name in ('SecretTrace.dfy', 'ApplyProbe.dfy'):
                (work / name).write_bytes((HERE / name).read_bytes())
            completed = subprocess.run([str(DAFNY), 'run', '--no-verify',
                                        str(work / 'ApplyProbe.dfy')],
                                       capture_output=True, text=True, cwd=work)
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        info = run.check_apply_probe(completed.stdout)
        self.assertGreater(info['rows'], 100)
        self.assertEqual('mirror-equals-compiled-model', info['status'])


class CompositionRoleIdentityTests(unittest.TestCase):
    """F2: merged/derived roles must be rejected, never silently aliased."""

    CALLEES = {
        'pickAlloc:([II)I': ['array_sec', 'pub'],
        'pickTwo:([I[II)I': ['array_sec', 'array_sec', 'pub'],
    }

    def policy(self, caller_method, caller_params):
        policy = copy.deepcopy(POLICY)
        policy['calls'].update({f'MergeRoleCallee.{key}': {'kind': 'call', 'result': 'args'}
                                for key in self.CALLEES})
        policy['classes'] = {
            'MergeRoleCallee': {'fields': {}, 'methods': {
                key: {'params': params} for key, params in self.CALLEES.items()}},
            'MergeRoleCaller': {'fields': {}, 'methods': {
                caller_method: {'params': caller_params}}},
        }
        return policy

    def inline(self, caller_method, caller_params, name, desc):
        key = f'{name}:{desc}'
        policy = self.policy(caller_method, caller_params)
        entries = [{'class': 'MergeRoleCallee', 'name': name, 'descriptor': desc,
                    'contract': callee_contract(name, desc, self.CALLEES[key])}]
        methods = bt.disassemble(JAVAP, fixture_classes(), 'MergeRoleCaller')
        result = bt.translate(methods[caller_method], policy,
                              policy['classes']['MergeRoleCaller'])
        specs = comp.load_callee_specs(policy, JAVAP, fixture_classes(), entries)
        return comp.inline_owned_callees(result, specs, policy)

    def test_allocation_and_parameter_role_merge_rejected(self):
        with self.assertRaisesRegex(comp.CompositionError, 'merged array role'):
            self.inline('allocMerge:([II)I', ['array_sec', 'pub'], 'pickAlloc', '([II)I')

    def test_two_parameter_role_merge_rejected(self):
        with self.assertRaisesRegex(comp.CompositionError, 'merged array role'):
            self.inline('twoMerge:([I[II)I', ['array_sec', 'array_sec', 'pub'],
                        'pickTwo', '([I[II)I')

    def test_role_identity_error_is_policy_error_not_value_error(self):
        try:
            self.inline('allocMerge:([II)I', ['array_sec', 'pub'], 'pickAlloc', '([II)I')
        except comp.CompositionError as error:
            self.assertIsInstance(error, bt.PolicyError)
        else:
            self.fail('merged role was accepted')
        try:
            self.inline('twoMerge:([I[II)I', ['array_sec', 'array_sec', 'pub'],
                        'pickTwo', '([I[II)I')
        except ValueError as error:
            self.fail('raw ValueError escaped the inliner: ' + repr(error))
        except comp.CompositionError:
            pass


class RuntimeHeapClassificationTests(unittest.TestCase):
    """F3: default public-scalar-and-heap classification for ordinary calls."""

    def test_secret_heap_argument_rejected_by_default(self):
        spec = fixture_spec('HeapExternalCompare')
        policy = fixture_policy_for(spec)
        with self.assertRaisesRegex(bt.PolicyError, 'secret heap argument'):
            bt.translate(fixture_method(spec), policy, policy['classes'][spec['class']])

    def test_public_heap_argument_accepted(self):
        spec = fixture_spec('HeapExternalPublic')
        policy = fixture_policy_for(spec)
        result = bt.translate(fixture_method(spec), policy, policy['classes'][spec['class']])
        self.assertEqual([], bt.audit_certificate(result))

    def test_audit_rejects_secret_heap_argument_after_mutation(self):
        spec = fixture_spec('HeapExternalPublic')
        policy = fixture_policy_for(spec)
        result = bt.translate(fixture_method(spec), policy, policy['classes'][spec['class']])
        call = next(i for i in result['code']
                    if i['type'] == 'step' and i['kind'][0] == 'call')
        self.assertTrue(call['kind'][3])
        result['roles'][call['kind'][3][0]] = 'sec'
        problems = [f['problem'] for f in bt.audit_certificate(result)]
        self.assertTrue(any('secret heap argument' in p for p in problems), problems)


class ClassificationDriftTests(unittest.TestCase):
    """F4: declared classification must equal the enforced code tables."""

    def test_shipped_policy_is_consistent(self):
        bt.check_runtime_classification(POLICY)

    def test_private_safe_drift_fails_closed(self):
        policy = copy.deepcopy(POLICY)
        policy['runtime_classification']['private_safe'].append(
            'dafny/DafnyEuclidean.EuclideanModulus:(II)I')
        with self.assertRaisesRegex(RuntimeError, 'classification drift'):
            bt.check_runtime_classification(policy)

    def test_shift_count_drift_fails_closed(self):
        policy = copy.deepcopy(POLICY)
        policy['runtime_classification']['shift_count_public'] = []
        with self.assertRaisesRegex(RuntimeError, 'classification drift'):
            bt.check_runtime_classification(policy)

    def test_heap_exception_drift_fails_closed(self):
        policy = copy.deepcopy(POLICY)
        policy['runtime_classification']['public_heap_exceptions'] = [
            'java/security/MessageDigest.isEqual:([B[B)Z']
        with self.assertRaisesRegex(RuntimeError, 'classification drift'):
            bt.check_runtime_classification(policy)

    def test_missing_classification_fails_closed(self):
        policy = copy.deepcopy(POLICY)
        policy.pop('runtime_classification')
        with self.assertRaisesRegex(RuntimeError, 'classification'):
            bt.check_runtime_classification(policy)


class ContractBindingTests(unittest.TestCase):
    """F6: the recorded callee contract must match the enforced policy."""

    OWNER = 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default'

    def entry(self, name):
        return next(e for e in POLICY['callee_roots'] if e['name'] == name)

    def test_every_callee_contract_matches_the_class_policy(self):
        for entry in POLICY['callee_roots']:
            comp.check_contract(entry, POLICY)

    def test_publicmod_is_public_public_everywhere(self):
        entry = self.entry('PublicMod')
        self.assertEqual(['pub', 'pub'], entry['contract']['params'])
        self.assertEqual(['pub', 'pub'], [value for key, value
                                          in entry['contract']['roles'].items()
                                          if key != 'result'])
        self.assertEqual(['pub', 'pub'],
                         POLICY['classes'][self.OWNER]['methods']['PublicMod:(II)I']['params'])

    def test_private_publicmod_contract_is_rejected(self):
        entry = copy.deepcopy(self.entry('PublicMod'))
        entry['contract']['params'] = ['sec', 'pub']
        entry['contract']['roles']['value'] = 'sec'
        with self.assertRaisesRegex(comp.CompositionError, 'contract'):
            comp.check_contract(entry, POLICY)

    def test_contract_role_mismatch_is_rejected(self):
        entry = copy.deepcopy(self.entry('Extract'))
        entry['contract']['roles']['value'] = 'pub'
        with self.assertRaisesRegex(comp.CompositionError, 'contract roles'):
            comp.check_contract(entry, POLICY)

    def test_contract_result_mismatch_is_rejected(self):
        entry = copy.deepcopy(self.entry('Extract'))
        entry['contract']['result'] = 'pub'
        with self.assertRaisesRegex(comp.CompositionError, 'contract result'):
            comp.check_contract(entry, POLICY)

    def test_unreviewed_heap_effect_is_rejected(self):
        entry = copy.deepcopy(self.entry('Wipe'))
        entry['contract']['heap'] = 'none'
        with self.assertRaisesRegex(comp.CompositionError, 'heap effect'):
            comp.check_contract(entry, POLICY)

    def test_missing_contract_is_rejected(self):
        entry = copy.deepcopy(self.entry('Pow2'))
        entry.pop('contract')
        with self.assertRaisesRegex(comp.CompositionError, 'no recorded contract'):
            comp.check_contract(entry, POLICY)


class AuditCallIdTests(unittest.TestCase):
    """F7: the audit must never treat an unknown/ambiguous call id as owned."""

    def accepted(self):
        spec = fixture_spec('HeapExternalPublic')
        policy = fixture_policy_for(spec)
        return bt.translate(fixture_method(spec), policy, policy['classes'][spec['class']])

    def test_unknown_call_id_rejected(self):
        result = self.accepted()
        call = next(i for i in result['code']
                    if i['type'] == 'step' and i['kind'][0] == 'call')
        target = next(name for name, ident in result['call_targets'].items()
                      if ident == call['kind'][1])
        del result['call_targets'][target]
        problems = [f['problem'] for f in bt.audit_certificate(result)]
        self.assertTrue(any('unclassified call target id' in p for p in problems), problems)

    def test_ambiguous_call_id_rejected(self):
        result = self.accepted()
        call = next(i for i in result['code']
                    if i['type'] == 'step' and i['kind'][0] == 'call')
        result['call_targets']['fake/Target:()V'] = call['kind'][1]
        problems = [f['problem'] for f in bt.audit_certificate(result)]
        self.assertTrue(any('ambiguous' in p for p in problems), problems)


class InlineBindingTests(unittest.TestCase):
    """F8: nested inline shape bindings are checked, and described honestly."""

    def test_matching_binding_is_accepted(self):
        run.check_inline_bindings([{'target': 't', 'callee_shape_sha256': 'h'}],
                                  {'t': {'direct_shape_sha256': 'h'}})

    def test_mismatched_binding_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'shape differs'):
            run.check_inline_bindings([{'target': 't', 'callee_shape_sha256': 'h'}],
                                      {'t': {'direct_shape_sha256': 'other'}})

    def test_missing_callee_record_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'no separate callee certificate'):
            run.check_inline_bindings([{'target': 't', 'callee_shape_sha256': 'h'}], {})


class InlineRecursionTests(unittest.TestCase):
    """F9: recursive callee cycles fail closed before expansion."""

    def test_recursive_callee_cycle_rejected(self):
        policy = copy.deepcopy(POLICY)
        policy['calls'].update({'RecursiveCallee.count:([II)I': {'kind': 'call',
                                                                 'result': 'args'}})
        policy['classes'] = {'RecursiveCallee': {'fields': {}, 'methods': {
            'count:([II)I': {'params': ['array_sec', 'pub']}}}}
        entries = [{'class': 'RecursiveCallee', 'name': 'count', 'descriptor': '([II)I',
                    'contract': callee_contract('count', '([II)I', ['array_sec', 'pub'])}]
        with self.assertRaisesRegex(comp.CompositionError, 'recursive'):
            comp.load_callee_specs(policy, JAVAP, fixture_classes(), entries)


class WitnessContractTests(unittest.TestCase):
    """M2: contract-driven, fail-closed witness obligations.

    These use a synthetic certificate/record shape so the gate can be tested
    without the frozen baseline classes; the replay applies the same function to
    the real `Callee_Extract` / `Callee_Wipe` records.
    """

    OWNER = 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default'

    def root(self, name, params, heap='none'):
        return {'class': self.OWNER.replace('/', '.'), 'name': name,
                'descriptor': '([I)V', 'contract': {'params': params, 'heap': heap,
                                                    'result': 'V'}}

    def result(self, roles, param_regs):
        return {'param_regs': list(param_regs), 'roles': roles}

    def test_parameter_registers_are_recorded(self):
        result = self.result({}, [1, 2, 3])
        report = run.check_witness_contract('Callee_Public', self.root('Pow2', ['pub']),
                                            result, None)
        self.assertEqual([1, 2, 3], report['parameter_registers'])
        self.assertEqual('not-required', report['status'])

    def test_dead_parameter_only_liveness_is_rejected(self):
        # The secret differs only in its own parameter register, i.e. the
        # executed program never used it (the pre-M2 "reported but not gated"
        # behaviour).
        execution = {'differing_registers': [1], 'zeroed_roles': [],
                     'role_store_counts': [], 'terminal': 'stop'}
        witness = {'heap_s': [], 'execution': execution}
        with self.assertRaisesRegex(RuntimeError, 'parameter-only'):
            run.check_witness_contract('Callee_Extract',
                                       self.root('Extract', ['sec', 'pub', 'pub']),
                                       self.result({}, [1, 2, 3]), witness)

    def test_non_parameter_liveness_is_accepted(self):
        execution = {'differing_registers': [1, 7], 'zeroed_roles': [],
                     'role_store_counts': [], 'terminal': 'stop'}
        report = run.check_witness_contract('Callee_Extract',
                                            self.root('Extract', ['sec', 'pub', 'pub']),
                                            self.result({}, [1, 2, 3]),
                                            {'heap_s': [], 'execution': execution})
        self.assertEqual('non-parameter-secret-live', report['liveness'])
        self.assertEqual([7], report['non_parameter_differing'])
        self.assertEqual([1, 2, 3], report['parameter_registers'])

    def test_private_callee_without_validated_execution_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'no validated witness execution'):
            run.check_witness_contract('Callee_Extract',
                                       self.root('Extract', ['sec']),
                                       self.result({}, [1]),
                                       {'heap_s': [], 'execution': None})

    def wipe(self):
        role = f'{self.OWNER}.Wipe#p0'
        return self.root('Wipe', ['array_sec'], 'parameter-array-clear'), role

    def test_clearing_wrong_role_is_rejected(self):
        root, role = self.wipe()
        roles = {'aaa/decoy#p0': 'sec', role: 'sec'}
        execution = {'differing_registers': [], 'zeroed_roles': [0],
                     'role_store_counts': [4, 0], 'terminal': 'stop'}
        with self.assertRaisesRegex(RuntimeError, 'did not zero the secret parameter role'):
            run.check_witness_contract('Callee_Wipe', root,
                                       self.result(roles, [1]),
                                       {'heap_s': [[1, 2, 3, 4], [1, 2, 3, 4]],
                                        'execution': execution})

    def test_clearing_insufficient_stores_is_rejected(self):
        root, role = self.wipe()
        roles = {role: 'sec'}
        execution = {'differing_registers': [], 'zeroed_roles': [0],
                     'role_store_counts': [3], 'terminal': 'stop'}
        with self.assertRaisesRegex(RuntimeError, 'wrote 3 of 4 elements'):
            run.check_witness_contract('Callee_Wipe', root,
                                       self.result(roles, [1]),
                                       {'heap_s': [[1, 2, 3, 4]], 'execution': execution})

    def test_clearing_correct_role_and_stores_is_accepted(self):
        root, role = self.wipe()
        roles = {'aaa/decoy#p0': 'sec', role: 'sec'}
        execution = {'differing_registers': [], 'zeroed_roles': [1],
                     'role_store_counts': [0, 4], 'terminal': 'stop'}
        report = run.check_witness_contract('Callee_Wipe', root,
                                            self.result(roles, [1]),
                                            {'heap_s': [[1, 2, 3, 4], [1, 2, 3, 4]],
                                             'execution': execution})
        self.assertEqual([role], report['cleared_parameter_roles'])

    def test_clearing_without_a_secret_parameter_array_is_rejected(self):
        root, role = self.wipe()
        roles = {role: 'pub'}  # policy/role disagreement cannot pass silently
        execution = {'differing_registers': [], 'zeroed_roles': [0],
                     'role_store_counts': [4], 'terminal': 'stop'}
        with self.assertRaisesRegex(RuntimeError, 'no secret parameter array role'):
            run.check_witness_contract('Callee_Wipe', root,
                                       self.result(roles, [1]),
                                       {'heap_s': [[1, 2, 3, 4]], 'execution': execution})


class StandardPrefixClassificationTests(unittest.TestCase):
    """L2: every enumerated standard-runtime namespace is inside the gate."""

    def test_standard_jdk_prefixes_are_gated(self):
        cases = [
            ('javax/crypto/Mac.doFinal:([B)[B', ['pub'], ['sec']),
            ('sun/security/provider/Foo.digest:([B)V', ['pub'], ['sec']),
            ('jdk/internal/util/Foo.run:(I)I', ['sec'], []),
            ('com/sun/crypto/provider/Foo.run:(I)I', ['sec'], []),
            ('java/security/MessageDigest.isEqual:([B[B)Z', ['pub', 'pub'], ['pub', 'sec']),
            ('dafny/DafnyEuclidean.EuclideanModulus:(II)I', ['sec', 'pub'], []),
        ]
        for target, scalars, heap in cases:
            self.assertFalse(bt.runtime_call_public_ok(target, scalars, heap), target)
            self.assertIn(bt.runtime_call_problem(target, scalars, heap),
                          ('public-argument-only runtime call %s with secret argument' % target,
                           'public-argument-only runtime call %s with secret heap argument' % target))

    def test_public_use_of_the_same_namespaces_is_admitted(self):
        self.assertTrue(bt.runtime_call_public_ok('javax/crypto/Mac.doFinal:([B)[B',
                                                 ['pub'], ['pub']))
        self.assertTrue(bt.runtime_call_public_ok('sun/security/provider/Foo.digest:([B)V',
                                                 ['pub'], ['pub']))
        self.assertTrue(bt.runtime_call_public_ok('jdk/internal/util/Foo.run:(I)I', ['pub']))
        self.assertTrue(bt.runtime_call_public_ok('com/sun/crypto/provider/Foo.run:(I)I', ['pub']))

    def test_prefix_enumeration_is_recorded_and_exhaustive(self):
        self.assertEqual({'dafny/', 'java/', 'javax/', 'jdk/', 'sun/', 'com/sun/'},
                         set(bt.EXTERNAL_RUNTIME_PREFIXES))
        self.assertEqual(set(bt.EXTERNAL_RUNTIME_PREFIXES),
                         set(POLICY['runtime_classification']['external_runtime_prefixes']))
        # A non-enumerated prefix is outside the claim (not silently admitted as
        # an owned contract by the gate itself); policy admission still requires
        # an explicit `calls` entry, and no third-party target is admitted today.
        self.assertFalse(any(target.startswith(('org/', 'com/google/', 'net/'))
                             for target in POLICY['calls']))

    def test_prefix_drift_fails_closed(self):
        policy = copy.deepcopy(POLICY)
        policy['runtime_classification']['external_runtime_prefixes'] = ['dafny/', 'java/']
        with self.assertRaisesRegex(RuntimeError, 'classification drift'):
            bt.check_runtime_classification(policy)


class ProofGateTests(unittest.TestCase):
    """F9: one strict normal proof-failure gate for every mutant."""

    GOOD = ('Dafny program verifier finished with 4 verified, 2 errors\n'
            'Error: possible violation of postcondition of forall statement')

    def test_normal_obligation_failure_is_accepted(self):
        diagnostic = run.check_proof_rejected(4, self.GOOD)
        self.assertIn('postcondition', diagnostic)

    def test_assertion_failure_is_accepted(self):
        output = ('Dafny program verifier finished with 3 verified, 1 error\n'
                  'Error: assertion might not hold')
        self.assertIn('assertion', run.check_proof_rejected(4, output))

    def test_zero_errors_is_rejected(self):
        output = ('Dafny program verifier finished with 6 verified, 0 errors\n'
                  'Error: possible violation of postcondition')
        with self.assertRaisesRegex(RuntimeError, 'zero errors'):
            run.check_proof_rejected(4, output)

    def test_timeout_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'proof obligation'):
            run.check_proof_rejected(4, self.GOOD + '\nRunner timeout; terminating process group.')

    def test_missing_summary_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'proof obligation'):
            run.check_proof_rejected(4, 'Error: possible violation of postcondition')

    def test_non_obligation_error_is_rejected(self):
        output = ('Dafny program verifier finished with 4 verified, 2 errors\n'
                  'Error: syntax error')
        with self.assertRaisesRegex(RuntimeError, 'proof obligation'):
            run.check_proof_rejected(4, output)

    def test_exit_zero_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'proof obligation'):
            run.check_proof_rejected(0, self.GOOD)


# --------------------------------------------------------------------------- #
class PutfieldValueBindingTests(unittest.TestCase):
    """Check scalar field values and reference-field rejection."""

    CLASS = 'FieldStoreProbe'
    FIELDS = {
        'FieldStoreProbe.publicValue:I': {
            'role': 'FieldStoreProbe.publicValue', 'taint': 'pub'},
        'FieldStoreProbe.publicLong:J': {
            'role': 'FieldStoreProbe.publicLong', 'taint': 'pub'},
        'FieldStoreProbe.secretValue:I': {
            'role': 'FieldStoreProbe.secretValue', 'taint': 'sec'},
        'FieldStoreProbe.secretLong:J': {
            'role': 'FieldStoreProbe.secretLong', 'taint': 'sec'},
        'FieldStoreProbe.refValue:[I': {
            'role': 'FieldStoreProbe.refValue.ref', 'taint': 'pub',
            'array_role': 'FieldStoreProbe.refValue', 'array_taint': 'pub'},
        'FieldStoreProbe.refObject:Ljava/lang/Object;': {
            'role': 'FieldStoreProbe.refObject.ref', 'taint': 'pub'},
    }

    def translate(self, method, params, fields=None):
        policy = {'calls': dict(POLICY['calls']), 'statics': POLICY['statics'],
                  'classes': {self.CLASS: {
                      'methods': {method: {'params': params}},
                      'fields': self.FIELDS if fields is None else fields}}}
        methods = bt.disassemble(JAVAP, fixture_classes(), self.CLASS)
        return bt.translate(methods[method], policy, policy['classes'][self.CLASS])

    @staticmethod
    def store(result):
        return next(step for step in result['code']
                    if step['type'] == 'step' and step['kind'][0] == 'store')

    def test_secret_int_putfield_into_public_field_is_rejected(self):
        result = self.translate('set:(I)V', ['sec'])
        problems = [failure['problem'] for failure in bt.audit_certificate(result)]
        self.assertTrue(any('secret write into public array' in problem
                            for problem in problems), problems)

    def test_secret_long_putfield_into_public_field_is_rejected(self):
        result = self.translate('setLong:(J)V', ['sec'])
        problems = [failure['problem'] for failure in bt.audit_certificate(result)]
        self.assertTrue(any('secret write into public array' in problem
                            for problem in problems), problems)

    def test_putfield_records_the_argument_register_not_the_receiver(self):
        # The receiver occupies IR register 1 for an instance method; the
        # argument is result['param_regs'][0]. The old translator recorded the
        # receiver in the Store and discarded the argument.
        for method in ('set:(I)V', 'setLong:(J)V'):
            result = self.translate(method, ['pub'])
            self.assertEqual([], bt.audit_certificate(result))
            self.assertFalse(result['static'])
            self.assertEqual(result['param_regs'][0], self.store(result)['kind'][3],
                             method)

    def test_positive_public_scalar_setters_still_accept(self):
        for method in ('set:(I)V', 'setLong:(J)V'):
            result = self.translate(method, ['pub'])
            self.assertEqual([], bt.audit_certificate(result), method)
            self.assertEqual('pub', result['roles'][self.store(result)['kind'][1]])

    def test_private_scalar_store_keeps_the_secret_value_binding(self):
        for method in ('setSecret:(I)V', 'setSecretLong:(J)V'):
            result = self.translate(method, ['sec'])
            self.assertEqual([], bt.audit_certificate(result), method)
            store = self.store(result)
            self.assertEqual(result['param_regs'][0], store['kind'][3], method)
            self.assertEqual('sec', result['roles'][store['kind'][1]], method)

    def test_public_field_reads_are_unchanged(self):
        for method in ('get:()I', 'getLong:()J'):
            result = self.translate(method, [])
            self.assertEqual([], bt.audit_certificate(result), method)
            self.assertFalse([step for step in result['code']
                              if step['type'] == 'step' and step['kind'][0] == 'store'])

    def test_reference_field_write_still_fails_closed(self):
        with self.assertRaisesRegex(bt.PolicyError, 'reference field'):
            self.translate('setRef:([I)V', ['pub'])

    def test_finite_execution_stores_the_argument_value(self):
        # Public setter with receiver 5 and argument 7: the model heap cell must
        # be 7. The old translation stored the receiver word 5.
        result = self.translate('set:(I)V', ['pub'])
        value_reg = result['param_regs'][0]
        regs = [0] * result['registers']
        regs[1] = 5
        regs[value_reg] = 7
        run = trace_exec.run_to_completion(
            trace_exec.ProgramView(result), regs, [[0, 0, 0, 0]], 32)
        self.assertEqual('stop', run['terminal'])
        self.assertEqual([[7, 0, 0, 0]], run['heap'])

    def test_finite_execution_secret_store_tracks_the_secret_argument(self):
        result = self.translate('setSecret:(I)V', ['sec'])
        value_reg = result['param_regs'][0]
        def at(value):
            regs = [0] * result['registers']
            regs[1] = 5
            regs[value_reg] = value
            return trace_exec.run_to_completion(
                trace_exec.ProgramView(result), regs, [[0, 0, 0, 0]], 32)
        secret_s, secret_t = at(11), at(13)
        self.assertEqual('stop', secret_s['terminal'])
        self.assertEqual('stop', secret_t['terminal'])
        self.assertEqual([[11, 0, 0, 0]], secret_s['heap'])
        self.assertEqual([[13, 0, 0, 0]], secret_t['heap'])

    def test_array_reference_field_rule_without_role_annotation_is_rejected(self):
        # Descriptor `[I` with only role/taint: no implicit scalar-word
        # treatment and no dependence on an array_role annotation.
        fields = {'FieldStoreProbe.refValue:[I': {
            'role': 'FieldStoreProbe.refValue.ref', 'taint': 'pub'}}
        with self.assertRaisesRegex(bt.PolicyError,
                                    r'write to reference field .* outside alias contract'):
            self.translate('setRef:([I)V', ['pub'], fields)

    def test_object_reference_field_rule_without_role_annotation_is_rejected(self):
        # Descriptor `Ljava/lang/Object;` with only role/taint. The old writer
        # accepted this as a scalar word write.
        fields = {'FieldStoreProbe.refObject:Ljava/lang/Object;': {
            'role': 'FieldStoreProbe.refObject.ref', 'taint': 'pub'}}
        with self.assertRaisesRegex(bt.PolicyError,
                                    r'write to reference field .* outside alias contract'):
            self.translate('setRefObject:(Ljava/lang/Object;)V', ['pub'], fields)

    def test_private_flow_witness_rejects_secret_to_public_store_with_live_return(self):
        # setAndEcho has a live private return *and* a public field store. The
        # old translator accepted it because the Store named the public receiver
        # register; the TwoRun trace theorem did not observe the differing return.
        # The patched translator must bind the secret argument and reject that
        # secret-to-public Store, not merely a dead-secret input.
        result = self.translate('setAndEcho:(I)I', ['sec'])
        value_reg = result['param_regs'][0]
        store = self.store(result)
        stop = next(inst for inst in result['code'] if inst['type'] == 'stop')
        self.assertEqual(value_reg, store['kind'][3])
        self.assertEqual(value_reg, stop['ret'])
        self.assertEqual('sec', result['reg_taints'][value_reg])
        problems = [failure['problem'] for failure in bt.audit_certificate(result)]
        self.assertTrue(any('secret write into public array' in problem
                            for problem in problems), problems)

        def at(value):
            regs = [0] * result['registers']
            regs[1] = 5
            regs[value_reg] = value
            return trace_exec.run_to_completion(
                trace_exec.ProgramView(result), regs, [[0, 0, 0, 0]], 32)
        secret_s, secret_t = at(11), at(13)
        self.assertEqual('stop', secret_s['terminal'])
        self.assertEqual('stop', secret_t['terminal'])
        self.assertEqual([[11, 0, 0, 0]], secret_s['heap'])
        self.assertEqual([[13, 0, 0, 0]], secret_t['heap'])
        self.assertNotEqual(secret_s['regs'][value_reg], secret_t['regs'][value_reg])


if __name__ == '__main__':
    unittest.main()
