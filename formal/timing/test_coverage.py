"""Regression controls for the promoted primitive-trace roots (#117).

Two groups:

  * `PolicyCoverageTests` — the reviewed inventory: the remaining promoted
    `HkdfBridge.labelUnits` helper, explicit sequence retirement, its narrowed allocation-site
    declassification, the nine `NativeField` callee roots with their exact
    intermediate contracts and inlining closures, and the *frozen* budget and
    aggregate-label entries that must not drift.
  * `ExecutionControlTests` — the finite paired-state control module. Every test
    either asserts a positive property of the control on a real promoted program
    or asserts that a deliberately broken program/seed/return/fuel is *rejected*
    by the control or by the existing audit. Nothing here re-implements the
    interpreter; all execution goes through the frozen `trace_exec` mirror.

The module needs only `javap` + the bound class directory (like
`test_trace.py`); it does not run Dafny or a replay.
"""
import copy
import hashlib
import json
import os
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import bytecode_trace as bt            # noqa: E402
import composition as comp             # noqa: E402
import execution_controls as ec        # noqa: E402
import run as R                        # noqa: E402

JDK = Path(os.environ.get(
    'JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))
JAVAP = JDK / 'bin/javap'
REPO = HERE.parent.parent
CLASSES = REPO / 'quic/target/classes'
POLICY = json.loads((HERE / 'policy.json').read_text())

BRIDGE = 'io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge'
BRIDGE_OWNER = BRIDGE.replace('.', '/')
FIELD = 'io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default'
FIELD_OWNER = FIELD.replace('.', '/')
SEQUENCE = 'sequence:([BLjava/lang/String;)Ldafny/DafnySequence;'
LABEL_UNITS = 'labelUnits:(Ljava/lang/String;)Ldafny/DafnySequence;'
FIELD_PRIVATE = {
    'ReduceOnce:(I)I': ['Q:()I'],
    'Reduce:(I)I': ['Q:()I', 'ReduceOnce:(I)I'],
    'Add:(II)I': ['Q:()I', 'ReduceOnce:(I)I'],
    'Sub:(II)I': ['Q:()I', 'ReduceOnce:(I)I'],
    'Mul:(II)I': ['Q:()I', 'ReduceOnce:(I)I', 'Reduce:(I)I'],
    'MulSub:(III)I': ['Q:()I', 'ReduceOnce:(I)I', 'Reduce:(I)I'],
    'AddMul:(IIII)I': ['Q:()I', 'ReduceOnce:(I)I', 'Reduce:(I)I'],
}
FIELD_PUBLIC = ['Q:()I', 'MaxReduce:()I']


def target(owner, key):
    return '%s.%s' % (owner, key)


def disassemble(classname, key):
    return bt.disassemble(JAVAP, CLASSES, classname)[key]


HISTORICAL = json.loads((HERE / 'fixtures/pre-array-hkdf/HISTORICAL.json').read_text())
HISTORICAL_POLICY = copy.deepcopy(POLICY)
HISTORICAL_POLICY['classes'][BRIDGE_OWNER]['methods'][SEQUENCE] = HISTORICAL['method_policy']
HISTORICAL_POLICY['calls'][BRIDGE_OWNER + '.' + SEQUENCE] = HISTORICAL['call_contract']
_historical_classes = None
_historical_temporary = None


def historical_sequence_result():
    """Exact predecessor source in an isolated compile, with zero current credit."""
    global _historical_classes, _historical_temporary
    if _historical_classes is None:
        source = HERE / 'fixtures/pre-array-hkdf/HkdfBridge.java'
        if hashlib.sha256(source.read_bytes()).hexdigest() != HISTORICAL['source_sha256']:
            raise AssertionError('historical HKDF fixture changed')
        _historical_temporary = tempfile.TemporaryDirectory(prefix='historical-hkdf-sequence-')
        _historical_classes = Path(_historical_temporary.name)
        runtime = Path(os.environ.get('DAFNY_RUNTIME_JAR',
            str(Path.home() / '.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar')))
        actual = subprocess.run([str(JDK / 'bin/javac'), '--release', '21', '-g:lines,vars,source',
            '-encoding', 'UTF-8', '-Xpkginfo:always', '-Xlint:all,-serial,-cast,-rawtypes',
            '-cp', str(CLASSES) + os.pathsep + str(runtime), '-d', str(_historical_classes), str(source)],
            capture_output=True, text=True)
        if actual.returncode != 0 or actual.stdout.strip() or actual.stderr.strip():
            raise AssertionError('historical-only compile failed: ' + actual.stdout + actual.stderr)
        compiled = _historical_classes / (BRIDGE_OWNER + '.class')
        if hashlib.sha256(compiled.read_bytes()).hexdigest() != HISTORICAL['class_sha256']:
            raise AssertionError('historical-only compiled class differs from predecessor')
    method = bt.disassemble(JAVAP, _historical_classes, BRIDGE)[SEQUENCE]
    return bt.translate(method, HISTORICAL_POLICY, HISTORICAL_POLICY['classes'][BRIDGE_OWNER])


def field_specs():
    return comp.load_callee_specs(POLICY, JAVAP, CLASSES, POLICY['callee_roots'])


def expanded_field(key):
    specs = field_specs()
    direct = bt.translate(disassemble(FIELD, key), POLICY, POLICY['classes'][FIELD_OWNER])
    result = comp.inline_owned_callees(
        copy.deepcopy(direct), {t: specs[t] for t in POLICY_FIELD_INLINE[key]}, POLICY)
    result['call_targets'] = comp.active_targets(result)
    return result


POLICY_FIELD_INLINE = {
    target(FIELD_OWNER, key): {target(FIELD_OWNER, inner) for inner in inline}
    for key, inline in FIELD_PRIVATE.items()
}
POLICY_FIELD_INLINE[target(FIELD_OWNER, 'Q:()I')] = set()
POLICY_FIELD_INLINE[target(FIELD_OWNER, 'MaxReduce:()I')] = set()


def synthetic(steps, *, registers, param_regs, reg_taints, roles=None,
              ret=None, call_targets=None):
    """Build a minimal *result* dict with a single terminal stop."""
    code, sites = [], []
    for index, (dst, kind) in enumerate(steps):
        code.append({'type': 'step', 'site': index, 'dst': dst, 'kind': kind, 'ann': 'pub'})
        sites.append({'site': index, 'class': 'synthetic', 'method': 'run',
                      'descriptor': '()V', 'offset': index, 'what': 'synthetic'})
    code.append({'type': 'stop', 'ret': ret})
    sites.append({'site': len(code) - 1, 'class': 'synthetic', 'method': 'run',
                  'descriptor': '()V', 'offset': -1, 'what': 'stop'})
    return {'code': code, 'sites': sites, 'registers': registers,
            'roles': roles or {}, 'reg_taints': reg_taints, 'param_regs': param_regs,
            'inputs': len(param_regs), 'call_targets': call_targets or {},
            'instructions_reachable': len(code), 'cfg_edges_checked': True}


# --------------------------------------------------------------------------- #
class PolicyCoverageTests(unittest.TestCase):
    def helper_roots(self):
        self.assertIn('helper_roots', POLICY, 'the remaining adapter helper stays promoted')
        return POLICY['helper_roots']

    def test_remaining_adapter_helper_and_explicit_sequence_retirement(self):
        helpers = {(entry['class'], entry['name'], entry['descriptor'])
                   for entry in self.helper_roots()}
        self.assertEqual({(BRIDGE, 'labelUnits', '(Ljava/lang/String;)Ldafny/DafnySequence;')},
                         helpers)
        self.assertNotIn(SEQUENCE, bt.disassemble(JAVAP, CLASSES, BRIDGE))
        self.assertNotIn(SEQUENCE, POLICY['classes'][BRIDGE_OWNER]['methods'])
        self.assertNotIn(BRIDGE_OWNER + '.' + SEQUENCE, POLICY['calls'])
        retired = POLICY['retired_helper_roots']
        self.assertEqual(1, len(retired))
        self.assertEqual('sequence', retired[0]['name'])
        self.assertFalse(retired[0]['replacement_bytecode_certified'])
        self.assertFalse(HISTORICAL['current_credit'])
        self.assertFalse(any(x['name'] == 'CopyInput' for x in POLICY['helper_roots']))
        open_targets = {(entry['class'], entry['method']) for entry in POLICY['open_roots']}
        for _, name, descriptor in helpers:
            self.assertNotIn((BRIDGE, f'{name}:{descriptor}'), open_targets)
        self.assertEqual(13, len(POLICY['open_roots']))
        # The five original caller roots are a separate, frozen inventory.
        self.assertEqual(5, len(POLICY['roots']))

    def test_label_units_allocation_declassification_is_narrowed(self):
        entry = POLICY['classes'][BRIDGE_OWNER]['methods'][LABEL_UNITS]
        self.assertEqual([11], entry.get('alloc_public'),
                         'the public label path must be a pc-list, not a blanket flag')
        method = disassemble(BRIDGE, LABEL_UNITS)
        result = bt.translate(method, POLICY, POLICY['classes'][BRIDGE_OWNER])
        self.assertEqual([], bt.audit_certificate(result))
        public_role = f'{BRIDGE_OWNER}.labelUnits@11:new'
        self.assertEqual('pub', result['roles'][public_role])
        # Removing the flag must flip only that role back to secret.
        broad = copy.deepcopy(POLICY)
        broad['classes'][BRIDGE_OWNER]['methods'][LABEL_UNITS].pop('alloc_public')
        plain = bt.translate(method, broad, broad['classes'][BRIDGE_OWNER])
        self.assertEqual('sec', plain['roles'][public_role])

    def test_other_allocation_sites_stay_secret_under_the_pc_list(self):
        text = '''public final class TwoAlloc {
  public static int run(int);
    descriptor: (I)I
    Code:
       0: iload_0
       1: newarray       short
       3: iconst_0
       4: iload_0
       5: sastore
       6: iload_0
       7: newarray       short
       9: iconst_0
      10: iload_0
      11: sastore
      12: iconst_0
      13: ireturn
}
'''
        method = bt.parse(text, 'probes/TwoAlloc')['run:(I)I']
        class_policy = {'methods': {'run:(I)I': {'params': ['pub'], 'alloc_public': [1]}},
                        'fields': {}}
        policy = {'calls': POLICY['calls'], 'statics': POLICY['statics'],
                  'classes': {'probes/TwoAlloc': class_policy}}
        result = bt.translate(method, policy, class_policy)
        self.assertEqual('pub', result['roles']['probes/TwoAlloc.run@1:new'])
        self.assertEqual('sec', result['roles']['probes/TwoAlloc.run@7:new'],
                         'only pc 1 is declassified; other allocations stay secret')

    def test_nativefield_class_contracts_and_callee_inventory(self):
        owner = FIELD_OWNER
        methods = POLICY['classes'][owner]['methods']
        self.assertEqual(['sec'], methods['ReduceOnce:(I)I']['params'])
        self.assertEqual(['sec'], methods['Reduce:(I)I']['params'])
        self.assertEqual(['sec', 'sec'], methods['Add:(II)I']['params'])
        self.assertEqual(['sec', 'sec'], methods['Sub:(II)I']['params'])
        self.assertEqual(['sec', 'sec'], methods['Mul:(II)I']['params'])
        self.assertEqual(['sec', 'sec', 'sec'], methods['MulSub:(III)I']['params'])
        self.assertEqual(['sec', 'sec', 'sec', 'sec'], methods['AddMul:(IIII)I']['params'])
        self.assertEqual([], methods['Q:()I']['params'])
        self.assertEqual([], methods['MaxReduce:()I']['params'])

        by_name = {entry['name']: entry for entry in POLICY['callee_roots']}
        for key in list(FIELD_PRIVATE) + FIELD_PUBLIC:
            name = key.split(':')[0]
            self.assertIn(name, by_name)
            entry = by_name[name]
            self.assertEqual(FIELD, entry['class'])
            self.assertEqual(key.split(':', 1)[1], entry['descriptor'])
            self.assertEqual('owned-callee', entry['role'])
            self.assertEqual({'time': 30, 'resources': 50000000,
                              'solver_options': ['O:smt.case_split=0']}, entry['limits'])
            if key in FIELD_PUBLIC:
                self.assertEqual([], entry.get('inline', []))
            else:
                self.assertEqual({target(owner, inner) for inner in FIELD_PRIVATE[key]},
                                 set(entry['inline']))
                for inline_target in entry['inline']:
                    self.assertIn(inline_target.rsplit('.', 1)[1].split(':')[0], by_name,
                                  'every inline target must itself be a certified callee root')
            comp.check_contract(entry, POLICY)
        # Intermediate translation contracts exist for exactly the nine targets.
        for key in list(FIELD_PRIVATE) + FIELD_PUBLIC:
            self.assertIn(target(owner, key), POLICY['calls'])
        for name in ('Q', 'MaxReduce'):
            self.assertEqual('pub', POLICY['calls'][target(owner, f'{name}:()I')]['result'])
        for key in FIELD_PRIVATE:
            self.assertEqual('args', POLICY['calls'][target(owner, key)]['result'])
        # Mutant controls only for the roots that still contain a provider call.
        for key in FIELD_PRIVATE:
            self.assertEqual(['public-result-from-secret-arg'],
                             POLICY['callee_mutants'].get(key.split(':')[0], []))
        for name in ('Q', 'MaxReduce'):
            self.assertNotIn(name, POLICY['callee_mutants'])

    def test_frozen_budget_and_label_inventories_are_unchanged(self):
        self.assertEqual({'Decaps': {'time': 60, 'resources': 100000000},
                          'Feed': {'time': 120, 'resources': 200000000,
                                   'justification': POLICY['limits']['Feed']['justification'],
                                   'solver_options': []},
                          'Expand': {'time': 120, 'resources': 200000000,
                                     'solver_options': [],
                                     'justification': POLICY['limits']['Expand']['justification']},
                          'LabelInfo': {'time': 120, 'resources': 200000000,
                                        'solver_options': [],
                                        'justification': POLICY['limits']['LabelInfo']['justification']}},
                         POLICY['limits'])
        self.assertEqual(31, len(POLICY['unchecked_owned_callees']))
        self.assertIn('NativeMlKem.Field/NTT/codec/sampling helpers',
                      POLICY['unchecked_owned_callees'])
        # The composed Feed certificate and its discharged set are untouched.
        composed = POLICY['composed_roots'][0]
        self.assertEqual(set(POLICY['composition']['discharged_targets']),
                         set(composed['discharged']))


# --------------------------------------------------------------------------- #
class StatePairTests(unittest.TestCase):
    def result(self):
        return synthetic(
            [(3, ('op', 'copy', 0, 1))],
            registers=4, param_regs=[1, 2],
            reg_taints={0: 'pub', 1: 'sec', 2: 'sec', 3: 'sec'},
            roles={'probes/X.run#p0': 'sec', 'probes/X.run@9:new': 'sec',
                   'probes/X.pubrole': 'pub'},
            ret=3)

    def test_pair_restricts_initial_differences_to_inputs(self):
        states = ec.build_states(self.result())
        invariants = states['invariants']
        self.assertTrue(invariants['differences_are_inputs_only'])
        self.assertTrue(invariants['parameter_secret_role_contents_differ'])
        self.assertEqual([11, 14], [states['regs_s'][r] for r in (1, 2)])
        self.assertEqual([13, 18], [states['regs_t'][r] for r in (1, 2)])
        self.assertEqual(0, states['regs_s'][3])
        self.assertEqual(0, states['regs_t'][3])
        # by name: the parameter role differs, the internal and public roles do not
        index = {name: i for i, name in enumerate(states['role_names'])}
        parameter = index['probes/X.run#p0']
        internal = index['probes/X.run@9:new']
        public = index['probes/X.pubrole']
        self.assertNotEqual(states['heap_s'][parameter], states['heap_t'][parameter])
        self.assertEqual(states['heap_s'][internal], states['heap_t'][internal])
        self.assertEqual([0, 0, 0, 0], states['heap_s'][internal])
        self.assertEqual(states['heap_s'][public], states['heap_t'][public])

    def test_parameter_only_private_writes_are_not_liveness(self):
        result = synthetic([], registers=2, param_regs=[1],
                           reg_taints={0: 'pub', 1: 'sec'}, ret=1)
        control = ec.paired_control(result, require_liveness=True)
        self.assertEqual('FAILED', control['status'])
        self.assertTrue(control['parameter_only_liveness'])
        self.assertIn('non_parameter_private_flow', control['checks'])
        self.assertFalse(control['checks']['non_parameter_private_flow'])

    def test_constant_return_is_rejected(self):
        result = synthetic([(3, ('lit', 7))], registers=4, param_regs=[1],
                           reg_taints={0: 'pub', 1: 'sec', 3: 'pub'}, ret=3)
        control = ec.paired_control(result, require_liveness=True)
        self.assertEqual('FAILED', control['status'])
        self.assertFalse(control['return_differs'])

    def test_non_parameter_initialisation_is_not_flow(self):
        # The returned value comes from a private *non-parameter* register that
        # starts at 0 in both runs: the input parameter differs, but the return
        # does not, so this is not input liveness and the control must fail.
        result = synthetic([], registers=3, param_regs=[1],
                           reg_taints={0: 'pub', 1: 'sec', 2: 'sec'}, ret=2)
        control = ec.paired_control(result, require_liveness=True)
        self.assertEqual('FAILED', control['status'])
        self.assertNotIn(2, control['differing_registers'])
        self.assertFalse(control['return_differs'])

    def test_wrong_return_register_is_rejected(self):
        result = synthetic([(3, ('op', 'copy', 0, 1))], registers=4, param_regs=[1],
                           reg_taints={0: 'pub', 1: 'sec', 3: 'sec'}, ret=3)
        control = ec.paired_control(result, require_liveness=True,
                                    expect_return_register=1)
        self.assertEqual('FAILED', control['status'])
        self.assertIn('return-register-mismatch', control['reason'])

    def test_truncated_execution_is_not_a_proof(self):
        result = synthetic([(3, ('op', 'copy', 0, 1))], registers=4, param_regs=[1],
                           reg_taints={0: 'pub', 1: 'sec', 3: 'sec'}, ret=3)
        control = ec.paired_control(result, require_liveness=True, step_cap=1)
        self.assertEqual('FAILED', control['status'])
        self.assertIn('no-finite-execution', control['reason'])

    def test_owned_call_remaining_is_rejected(self):
        target_name = target(FIELD_OWNER, 'ReduceOnce:(I)I')
        result = synthetic([(3, ('call', 1, [1], [], False))], registers=4,
                           param_regs=[1], reg_taints={0: 'pub', 1: 'sec', 3: 'sec'},
                           ret=3, call_targets={target_name: 1})
        control = ec.paired_control(result, require_liveness=False,
                                    require_no_owned_calls=True)
        self.assertEqual('FAILED', control['status'])
        self.assertIn('no_owned_calls_remaining', control['checks'])
        self.assertFalse(control['checks']['no_owned_calls_remaining'])


# --------------------------------------------------------------------------- #
class AuditGateTests(unittest.TestCase):
    """The existing audit still rejects the classic private-flow escapes."""

    def sequence_result(self):
        return historical_sequence_result()

    def private_result(self):
        """Standalone `NativeField.Add`: branch-free arithmetic with private operands."""
        return bt.translate(disassemble(FIELD, 'Add:(II)I'), POLICY,
                            POLICY['classes'][FIELD_OWNER])

    def label_units_result(self):
        return bt.translate(disassemble(BRIDGE, LABEL_UNITS), POLICY,
                            POLICY['classes'][BRIDGE_OWNER])

    def test_secret_branch_is_rejected(self):
        result = self.private_result()
        mutant = copy.deepcopy(result)
        ret = mutant['code'][-1]['ret']
        mutant['sites'].append({'site': len(mutant['sites']), 'class': FIELD_OWNER,
                                'method': 'injected', 'descriptor': '', 'offset': -1,
                                'what': 'injected-branch'})
        mutant['code'].insert(len(mutant['code']) - 1,
                              {'type': 'branch', 'site': len(mutant['sites']) - 1,
                               'cond': ret, 'thn': len(mutant['code']) - 1,
                               'els': len(mutant['code']) - 1})
        problems = [failure['problem'] for failure in bt.audit_certificate(mutant)]
        self.assertTrue(any('secret branch' in problem for problem in problems), problems)

    def test_secret_store_index_and_value_are_rejected(self):
        result = self.label_units_result()
        store = next(step for step in result['code']
                     if step['type'] == 'step' and step['kind'][0] == 'store')
        index_mutant = copy.deepcopy(result)
        index_mutant['reg_taints'][store['kind'][2]] = 'sec'
        problems = [failure['problem'] for failure in bt.audit_certificate(index_mutant)]
        self.assertTrue(any('secret store index' in problem for problem in problems), problems)
        value_mutant = copy.deepcopy(result)
        value_mutant['reg_taints'][store['kind'][3]] = 'sec'
        problems = [failure['problem'] for failure in bt.audit_certificate(value_mutant)]
        self.assertTrue(any('secret write into public array' in problem for problem in problems),
                        problems)

    def test_private_shift_count_is_rejected_by_the_runtime_rule(self):
        partial = bt.translate(disassemble(FIELD, 'ReduceOnce:(I)I'), POLICY,
                               POLICY['classes'][FIELD_OWNER])
        specs = field_specs()
        expanded = comp.inline_owned_callees(
            copy.deepcopy(partial),
            {target(FIELD_OWNER, 'Q:()I'): specs[target(FIELD_OWNER, 'Q:()I')]}, POLICY)
        expanded['call_targets'] = comp.active_targets(expanded)
        self.assertEqual([], bt.audit_certificate(expanded))
        id_to_target = {ident: name for name, ident in expanded['call_targets'].items()}
        call = next(step for step in expanded['code']
                    if step['type'] == 'step' and step['kind'][0] == 'call'
                    and id_to_target.get(step['kind'][1]) == ec.SHIFT_CALL)
        mutant = copy.deepcopy(expanded)
        mutant['reg_taints'][call['kind'][2][1]] = 'sec'
        problems = [failure['problem'] for failure in bt.audit_certificate(mutant)]
        self.assertTrue(any('bv64ShiftRight' in problem and 'secret argument' in problem
                            for problem in problems), problems)


# --------------------------------------------------------------------------- #
class PromotedRootControlTests(unittest.TestCase):
    def test_historical_sequence_input_pair_only(self):
        result = historical_sequence_result()
        control = ec.paired_control(result, require_liveness=False)
        self.assertEqual('ok', control['status'], control.get('reason'))
        self.assertTrue(control['state_invariants']['parameter_secret_role_contents_differ'])
        self.assertIn(control['return_register'], control['public_registers'],
                      'the produced sequence role is held in a public length register')
        # documented limit: no copy/alias or private-output claim is made
        self.assertFalse(control['require_liveness'])

    def test_label_units_is_public_only_and_bounded_lengths_hold(self):
        result = bt.translate(disassemble(BRIDGE, LABEL_UNITS), POLICY,
                              POLICY['classes'][BRIDGE_OWNER])
        self.assertTrue(ec.paired_control(result, require_liveness=False)['status']
                        .startswith('not-applicable'))
        lengths = ec.length_control(result, (0, 1, 3, 5))
        self.assertEqual('ok', lengths['status'])
        self.assertEqual([0, 1, 3, 5], [run['stores'] for run in lengths['runs']])
        self.assertTrue(all(run['alloc_sizes_match'] for run in lengths['runs']))

    def test_seven_expanded_nativefield_bodies_pass(self):
        specs = field_specs()
        for key in FIELD_PRIVATE:
            with self.subTest(method=key):
                direct = bt.translate(disassemble(FIELD, key), POLICY,
                                      POLICY['classes'][FIELD_OWNER])
                result = comp.inline_owned_callees(
                    copy.deepcopy(direct),
                    {t: specs[t] for t in POLICY_FIELD_INLINE[target(FIELD_OWNER, key)]},
                    POLICY)
                result['call_targets'] = comp.active_targets(result)
                self.assertEqual([], bt.audit_certificate(result))
                self.assertEqual([], ec.owned_call_targets(result))
                self.assertEqual(result['instructions_reachable'], len(result['code']))
                control = ec.paired_control(result, require_liveness=True)
                self.assertEqual('ok', control['status'], control.get('reason'))
                self.assertTrue(control['return_differs'])
                self.assertTrue(control['non_parameter_differing'])
                self.assertTrue(all(call['count_taint'] == 'pub'
                                    for call in control['shift_count_rule']['shift_calls']))

    def test_public_leaves_have_no_private_control(self):
        for key in FIELD_PUBLIC:
            with self.subTest(method=key):
                result = bt.translate(disassemble(FIELD, key), POLICY,
                                      POLICY['classes'][FIELD_OWNER])
                control = ec.paired_control(result, require_liveness=False)
                self.assertTrue(control['status'].startswith('not-applicable'))
                self.assertEqual(2, len(result['code']))


class ApplicabilityGateTests(unittest.TestCase):
    """F1 (review): a *required* control must not degrade to `not-applicable`.

    The replay gate derives the requirement from the root's declared
    metadata/contract, never from the control's self-reported status; a structural
    `not-applicable` therefore means a lost obligation for a required root, while
    a genuine public-only root keeps it.
    """

    def expanded_add(self):
        specs = field_specs()
        direct = bt.translate(disassemble(FIELD, 'Add:(II)I'), POLICY,
                              POLICY['classes'][FIELD_OWNER])
        result = comp.inline_owned_callees(
            copy.deepcopy(direct),
            {t: specs[t] for t in POLICY_FIELD_INLINE[target(FIELD_OWNER, 'Add:(II)I')]},
            POLICY)
        result['call_targets'] = comp.active_targets(result)
        return result

    def test_requirement_derives_from_declared_metadata_not_control_status(self):
        private_root = next(entry for entry in POLICY['callee_roots']
                            if entry['name'] == 'Add')
        public_leaf = next(entry for entry in POLICY['callee_roots']
                           if entry['name'] == 'Q')
        sequence_root = HISTORICAL['root']
        label_root = next(entry for entry in POLICY['helper_roots']
                          if entry['name'] == 'labelUnits')
        self.assertTrue(R.control_requirement(private_root))
        self.assertFalse(R.control_requirement(public_leaf))
        self.assertTrue(R.control_requirement(sequence_root))
        self.assertFalse(R.control_requirement(label_root))
        # a contract with a private scalar parameter also demands applicability
        self.assertTrue(R.control_requirement({'contract': {'params': ['sec']}}))
        self.assertFalse(R.control_requirement({'contract': {'params': ['pub']}}))
        # the control's own status is irrelevant to the requirement
        self.assertTrue(R.control_requirement({'control': 'private-paired',
                                               'status': 'not-applicable'}))

    def test_required_private_control_rejects_not_applicable_degradation(self):
        result = self.expanded_add()
        real = ec.paired_control(result, require_liveness=True, require_no_owned_calls=True)
        self.assertEqual('ok', real['status'])
        required_root = next(entry for entry in POLICY['callee_roots']
                              if entry['name'] == 'Add')
        # the real control satisfies the required gate
        self.assertTrue(R.verify_promoted_control('Callee_Add', required_root, real,
                                                  real.get('status')))
        # a frozen-extractor/parameter-classification regression that removes the
        # private parameters must not be accepted by a *required* gate
        degraded = copy.deepcopy(result)
        degraded['reg_taints'] = {register: 'pub' for register in degraded['reg_taints']}
        relaxed = ec.paired_control(degraded, require_liveness=True,
                                    require_no_owned_calls=True)
        self.assertTrue(relaxed['status'].startswith('not-applicable'))
        # legacy permissive acceptance is the bug this gate removes
        self.assertTrue(R.acceptable_control(relaxed))
        self.assertFalse(R.acceptable_control(relaxed, require_applicable=True))
        with self.assertRaises(RuntimeError) as caught:
            R.verify_promoted_control('Callee_Add', required_root, relaxed,
                                      relaxed.get('status'))
        self.assertIn('execution control', str(caught.exception))
        # a genuine public leaf keeps its legitimate not-applicable
        leaf_root = next(entry for entry in POLICY['callee_roots']
                         if entry['name'] == 'Q')
        leaf = ec.paired_control(
            bt.translate(disassemble(FIELD, 'Q:()I'), POLICY,
                         POLICY['classes'][FIELD_OWNER]),
            require_liveness=False)
        self.assertTrue(leaf['status'].startswith('not-applicable'))
        self.assertFalse(R.control_requirement(leaf_root))
        self.assertFalse(R.verify_promoted_control('Callee_Q', leaf_root, leaf,
                                                   leaf.get('status')),
                         'a public leaf is not required to be applicable')

    def test_historical_sequence_control_rejects_public_only_degradation(self):
        sequence_root = HISTORICAL['root']
        label_root = next(entry for entry in POLICY['helper_roots']
                          if entry['name'] == 'labelUnits')
        sequence = historical_sequence_result()
        real = ec.paired_control(sequence, require_liveness=False)
        self.assertEqual('ok', real['status'])
        self.assertTrue(real['secret_parameter_roles'])
        self.assertTrue(R.verify_promoted_control('HkdfBridge_sequence', sequence_root,
                                                  real, 'validated-finite-execution'))
        # the requested helper must not accept a witness-less/public-only state
        with self.assertRaises(RuntimeError) as caught:
            R.verify_promoted_control('HkdfBridge_sequence', sequence_root, real,
                                      'public-only')
        self.assertIn('witness', str(caught.exception))
        # dropping the private input role degrades the control to not-applicable
        degraded = copy.deepcopy(sequence)
        degraded['roles'] = {name: 'pub' for name in degraded['roles']}
        relaxed = ec.paired_control(degraded, require_liveness=False)
        self.assertTrue(relaxed['status'].startswith('not-applicable'))
        self.assertFalse(R.acceptable_control(relaxed, require_applicable=True))
        with self.assertRaises(RuntimeError):
            R.verify_promoted_control('HkdfBridge_sequence', sequence_root, relaxed,
                                      'validated-finite-execution')
        # labelUnits is genuinely public-only: its control stays accepted
        label_units = bt.translate(disassemble(BRIDGE, LABEL_UNITS), POLICY,
                                   POLICY['classes'][BRIDGE_OWNER])
        public = ec.paired_control(label_units, require_liveness=False)
        self.assertTrue(public['status'].startswith('not-applicable'))
        self.assertFalse(R.verify_promoted_control('HkdfBridge_labelUnits', label_root,
                                                   public, 'public-only'),
                         'labelUnits is genuinely public-only and is not required')
        self.assertFalse(R.acceptable_control(public, require_applicable=True))

    def test_summary_cannot_report_ok_when_a_required_control_is_not_applicable(self):
        degraded = {'status': 'not-applicable: no private parameters or private parameter roles'}
        good = {'status': 'ok'}
        self.assertEqual('ok', R.promoted_controls_summary(
            [{'certificate': 'Callee_Q', 'require_applicable': False, 'control': degraded},
             {'certificate': 'Callee_Add', 'require_applicable': True, 'control': good}])['status'])
        self.assertEqual('FAILED', R.promoted_controls_summary(
            [{'certificate': 'Callee_Q', 'require_applicable': False, 'control': degraded},
             {'certificate': 'Callee_Add', 'require_applicable': True,
              'control': degraded}])['status'])


if __name__ == '__main__':
    unittest.main()
