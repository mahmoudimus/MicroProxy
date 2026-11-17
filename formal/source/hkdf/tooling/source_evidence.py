"""Portable projection of a completed current replay, never a proof oracle.

The input report and raw sidecars remain unchanged. Only this derived receipt is
staged in the repository after review; it contains no private absolute paths.
"""
import hashlib
import json
from pathlib import Path
import re

DLL = '96a275e60ab2a9a90187310fee01cdb8797a1276e3fe3e869f518c2dad0e8d89'
SDK = '10.0.400'
CORE = {'proof-source-0': 257, 'proof-source-1': 11, 'proof-source-2': 13,
        'proof-nested-mixed-AND-OR': 257, 'proof-nested-mixed-OR-AND': 257}
BODY = ('copy-empty', 'copy-model-forged-address', 'extract-arguments-reversed',
        'pair-private-values-equal', 'snapshot-live-alias-forgery')
FUNCTIONAL = ('counter', 'feedback', 'truncation', 'prefix', 'public-domain')
LEGACY = {'old-block-boundary-pending': 257, 'old-callee-suchthat-model-erasure': 255,
          'old-third-callee-dup': 258, 'old-third-expdup': 257,
          'supplement-old-bijective-site-relabel': 257}
POSITIVE_PROOF_LABELS = (frozenset(CORE) | {'public-domain'} |
    {'legacy-' + kind + '-' + name for name in LEGACY for kind in ('body', 'NI')} |
    {'metadata-positive-' + name for name in ('EvBranch', 'EvCall', 'EvMac', 'EvOps', 'EvRead')} |
    {'proof-observed-secret-' + name for name in ('branch', 'index', 'metadata')})
PRODUCERS = ('formal/source/hkdf/run.py', 'formal/source/hkdf/replay.py',
    'formal/source/hkdf/checker/HkdfCoverage.cs', 'formal/source/hkdf/checker/HkdfCoverage.csproj',
    'formal/source/hkdf/tooling/admission.py', 'formal/source/hkdf/tooling/owned_call.py',
    'formal/source/hkdf/tooling/passive_drain.py', 'formal/source/hkdf/tooling/proof_rules.py',
    'formal/source/hkdf/tooling/outcome_rules.py', 'formal/source/hkdf/tooling/evaluation_validator.py',
    'formal/source/hkdf/tooling/build_support.py', 'formal/source/hkdf/tooling/source_evidence.py',
    'formal/dafny/run.py', 'formal/dafny/check_adapter_discipline.py')
SOURCES = ('formal/dafny/hkdf/Hkdf.dfy', 'formal/source/hkdf/HkdfTrace.dfy',
           'formal/source/hkdf/ArrayInputTrace.dfy')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def require_positive_proof_exits(commands):
    indexed = {command['label']: command for command in commands}
    require(len(commands) == len(indexed), 'duplicate command label')
    for label in POSITIVE_PROOF_LABELS:
        require(label in indexed and indexed[label]['exit'] == 0,
                'required positive proof command did not exit zero: ' + label)


def project(root):
    root = Path(root)
    report_path = root / 'report.json'
    r = json.loads(report_path.read_text())
    require(r['status'] == 'complete bounded full' and r['phase'] == 'full', 'not a completed full replay')
    require(r['qualification'] is False and r['tools_after_equal'], 'scope/tool drift')
    inputs = r['inputs_before']
    require(inputs == r['inputs_after'] == r['frozen_inputs_after'], 'source/package drift')
    for name, pin in inputs.items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'noncanonical input')
        require(sha(root / 'frozen' / name) == pin, 'actual frozen input changed')
    require(r['official_parser_closure'] == {n: inputs[n] for n in SOURCES}, 'incomplete parser graph')
    require(r['manifest_sha256'] == r['manifest_after_sha256'], 'manifest drift')
    before, after = root / 'TOOLS-BEFORE.json', root / 'TOOLS-AFTER.json'
    require(sha(before) == r['tools_before']['sha256'] and sha(after) == r['tools_after']['sha256'], 'tool map pin mismatch')
    tools = json.loads(before.read_text())
    require(tools == json.loads(after.read_text()), 'tool maps differ')
    trees = {}
    for major in (21, 25):
        keys = [k for k in tools if k.startswith('jdk' + str(major) + '-typed-tree:')]
        require(len(keys) == 1, 'full typed JDK tree absent; old five-operand evidence cannot be relabeled')
        tree = tools[keys[0]]
        require(tree.get('.', [None])[0] == 'directory' and len(tree) > 5, 'not a complete typed tree')
        for name in ('bin/java', 'bin/javac', 'bin/javap', 'lib/modules', 'release'):
            require(tree[name][0] == 'file' and len(tree[name]) == 3, 'critical JDK file absent')
        require(all(len(v) == 3 and v[0] in ('directory', 'file', 'symlink') for v in tree.values()), 'unknown JDK entry')
        trees[str(major)] = {kind: sum(v[0] == kind for v in tree.values())
                             for kind in ('file', 'directory', 'symlink')}
    require(r['build']['dll_sha256'] == DLL, 'unreviewed checker DLL')
    props = r['build']['evaluation']['properties']
    require(props.get('UseSharedCompilation') == 'false', 'shared compiler admission')
    coverage = r['coverage']
    plan = json.loads((root / 'frozen/formal/source/hkdf/controls/v2.json').read_text())
    expected_controls = {x['name']: x['kind'] for x in plan['coverage']}
    require({x['name']: x['kind'] for x in coverage} == expected_controls, 'wrong actual coverage cases')
    require(len(coverage) == len({x['name'] for x in coverage}) == 115, 'coverage omitted/duplicated')
    require(sum(x['kind'] == 'negative' for x in coverage) == 112, 'negative coverage inventory changed')
    require(all(x['outcome'] == ('ordinary-valid named coverage rejection' if x['kind'] == 'negative'
                                else 'accepted valid control') for x in coverage), 'coverage not admitted')
    proofs = {p['name']: p for p in r['proofs']}
    require(len(proofs) == len(r['proofs']), 'duplicate proof record')
    for name, count in CORE.items():
        require(proofs[name]['rows'] == count and proofs[name]['outcome'] == 'all actual VCs passed', 'missing full core/mixed proof')
    for name in BODY:
        p = proofs[name]
        require(p['failed_correctness'] == p['passed_WF'] == 1 and p['rows'] == 2, 'wrong body failure')
    domain = proofs['public-domain']
    require(domain['rows'] > 0 and 'PublicDomain.AllInputs (correctness)' in domain['families'], 'unrestricted all-eight domain absent')
    for name in FUNCTIONAL:
        require(proofs['functional-' + name]['classification'] == 'normal original functional/domain proof failure', 'original functional control absent')
    require(r['functional_audit_controls'] == {name: 'unexpected trust/skip rejected'
            for name in ('extra-assumption', 'skipped-proof')}, 'nonvacuity audit control absent')
    require(r['audits'][:3] == [{'name': 'audit-source-0', 'findings': 1},
            {'name': 'audit-source-1', 'findings': 0}, {'name': 'audit-source-2', 'findings': 0}], 'canonical trust audit changed')
    require(r['java']['raw_changed_files'] == [] and r['java']['binding_erasure_exact'], 'Java/binding erasure delta')
    require(all(len(r['java']['classes'][str(j)]) == 12 for j in (21, 25)), 'wrong actual production class count')
    require(len(r['adapter_checks']) == 4 and {(x['jdk'], x['action']) for x in r['adapter_checks']} ==
            {(j, a) for j in (21, 25) for a in ('discipline', 'self-test')}, 'adapter controls omitted')
    legacy = LEGACY
    for name, count in legacy.items():
        require(proofs['legacy-body-' + name]['rows'] == count and
                proofs['legacy-NI-' + name]['rows'] == 11, 'legacy body/NI control omitted')
    for name in ('EvBranch', 'EvCall', 'EvMac', 'EvOps', 'EvRead'):
        require(proofs['metadata-positive-' + name]['rows'] == 1, 'metadata positive omitted')
    for name in ('branch-erases-boolean', 'branch-erases-one-id', 'read-erases-address',
                 'mac-erases-target', 'mac-erases-lengths', 'call-erases-arity', 'ops-erases-shift'):
        require(proofs['metadata-' + name]['classification'] == 'dafny-metadata-proof-failure', 'metadata counterexample omitted')
    for name in ('branch', 'index', 'metadata'):
        require(proofs['proof-observed-secret-' + name]['rows'] == 2 and
                proofs['observed-secret-' + name + '-NI']['classification'] == 'dafny-assertion-failure', 'observed-secret control omitted')
    require('included_assumption_control' in r, 'included assumption control omitted')
    raw_records = {}
    commands = r['commands']
    require_positive_proof_exits(commands)
    for c in commands:
        label = c['label']
        log = root / 'logs' / (label + '.log')
        raw = root / 'logs' / (label + '.raw-execution.json')
        require(c['process_group_empty_after_exit'], 'owned group not drained')
        require(sha(log) == c['log_sha256'] and sha(raw) == c['raw_execution_sha256'], 'raw log/record hash mismatch')
        execution = json.loads(raw.read_text())
        require(execution['actual_exit_observed'] and execution['returncode'] == c['exit']
                and execution['argv'] == c['argv'] and execution['log_sha256'] == c['log_sha256']
                and execution['supervisor_failure'] is None, 'raw execution mismatch')
        raw_records[label] = {'exit': c['exit'], 'stdout_sha256': sha(log), 'raw_execution_sha256': sha(raw)}
    runtime = {}
    for major in ('21', '25'):
        array = (root / 'logs' / ('runtime-' + major + '.log')).read_text().strip()
        original = r['original_runtime'][major]
        require(original == (root / 'logs' / ('original-runtime-' + major + '.log')).read_text().strip(), 'original runtime raw output mismatch')
        require(array == 'HKDF-ARRAY-INTEGRATION-PASS cases=150 assertions=346', 'array runtime not complete')
        require(re.fullmatch(r'PASS GeneratedHkdfTest: 45 cases, 2766 assertions; providers: [^\r\n]+', original), 'original runtime not complete')
        runtime[major] = {'array': {'cases': 150, 'assertions': 346},
                          'original': {'cases': 45, 'assertions': 2766}}
    generated = {Path(k).name: v for k, v in r['java']['generated_sources'].items()
                 if '/VerifiedHkdf/' in k and k.endswith('.java')}
    require(len(generated) == 9, 'wrong compiler package inventory')
    # Paths in the original reports/sidecars are preserved as raw provenance.
    # This portable projection keeps only repo paths, logical labels and hashes.
    controls = {x['name']: {'kind': x['kind'], 'classification': x['outcome']} for x in coverage}
    return {'schema': 'microproxy.hkdf-source-traces/v2', 'status': 'complete',
        'qualification': False, 'inputs': inputs, 'manifest_sha256': r['manifest_sha256'],
        'producer_pins': {n: inputs[n] for n in PRODUCERS},
        'positive': {'hkdf_body': {'verified': 257, 'errors': 0},
                     'sequence_harness': {'verified': 11, 'errors': 0},
                     'array_harness': {'verified': 13, 'errors': 0},
                     'mixed_AND_OR': {'verified': 257, 'errors': 0},
                     'mixed_OR_AND': {'verified': 257, 'errors': 0},
                     'public_domain': {'verified': domain['rows'], 'errors': 0}},
        'audit': [{'file': n, 'findings': 1 if i == 0 else 0} for i, n in enumerate(SOURCES)],
        'controls': controls,
        'body_controls': {name: {'failed_correctness': 1, 'passed_WF': 1} for name in BODY},
        'functional_controls': {name: 'normal original functional/domain proof failure' for name in FUNCTIONAL},
        'functional_audit_controls': r['functional_audit_controls'],
        'retained_controls': {'legacy_body_NI': {name: {'body': count, 'NI': 11} for name, count in legacy.items()},
            'metadata_positive': ['EvBranch', 'EvCall', 'EvMac', 'EvOps', 'EvRead'],
            'metadata_negative': ['branch-erases-boolean', 'branch-erases-one-id', 'read-erases-address',
                'mac-erases-target', 'mac-erases-lengths', 'call-erases-arity', 'ops-erases-shift'],
            'observed_secret': {'branch': 'actual Extract passes; NI fails',
                                'index': 'actual Extract passes; NI fails',
                                'metadata': 'actual Extract passes; NI fails'},
            'included_assumption': 'official parser and explicit per-file audit reject hidden axiom'},
        'checker': {'positive': 'all8exactroots', 'assembly_sha256': DLL, 'sdk': SDK},
        'flags': {'seconds': 30, 'resources': 50000000, 'cores': 2, 'case_split': 0, 'seed': 0},
        'java': {'hashes': generated, 'generated_package_files': 9, 'classes': 12,
                 'raw_changed_files': [], 'same_JDK_production_generated_identity': True,
                 'class_maps': r['java']['classes'], 'runtime': runtime,
                 'adapter_discipline_and_selftests_each_JDK': True},
        'tool_scope': {'profile': r['profile'], 'full_typed_JDK_trees': trees,
                       'before_sha256': sha(before), 'after_sha256': sha(after)},
        'derivation': {'raw_report_sha256': sha(report_path), 'actual_command_count': len(commands),
                        'raw_records': raw_records},
        'scope': {'assumptions': ['deterministic external Mac with fixed output length'],
                  'trusted': ['Dafny/Boogie/Z3', 'C# AST checker', 'compiler ghost erasure',
                              'javac/DafnyRuntime/JVM/JIT/CPU/GC', 'JCE HMAC', 'Java adapter boundary'],
                  'open': ['physical timing', 'whole-crypto composition', 'global trace IDs',
                           'compiler/adapter refinement', 'release/adoption', 'external expert review']}}
