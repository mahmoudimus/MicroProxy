#!/usr/bin/env python3
"""Cold retained Darwin qualification plus independently selected local identity."""
import sys

if sys.flags.optimize:
    raise RuntimeError('HKDF cold CI requires unoptimized Python')
if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
    raise RuntimeError('HKDF cold CI requires Python -I -B')

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).absolute().parent
ADMISSION_SHA256 = '35565fdc4c371b313908d0900d617edde9cd0053a1c993f90f07c891733f960d'
_raw = (HERE / 'admission.py').read_bytes()
if hashlib.sha256(_raw).hexdigest() != ADMISSION_SHA256:
    raise ValueError('cold CI bootstrap source pin mismatch')
_spec = importlib.util.spec_from_file_location('cold_ci_admission', HERE / 'admission.py')
A = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = A
exec(compile(_raw, str(HERE / 'admission.py'), 'exec', dont_inherit=True), A.__dict__)

BASE = 'formal/crypto/epochs/hkdf-array-001/'
OLD = 'formal/source/epochs/keccak-004/'
API = 'scripts/security/crypto_current_release.py'
DELIVERY = 'formal/crypto/delivery.py'
TOOLING = 'formal/source/hkdf/tooling/admission.py'
SELECTION_SCHEMA = 'microproxy.hkdf-array-cold-ci-selection/1'
INDEX_SCHEMA = 'microproxy.hkdf-array-retained-qualification/1'
CHECKOUT_SCHEMA = 'microproxy.hkdf-array-ci-checkout/1'
DELIVERY_SCHEMA = 'microproxy.hkdf-array-delivery/1'
SCOPE = 'retained-Darwin-arm64-plus-fresh-local-identity'
ARRAY_TEST = 'io/github/mahmoudimus/quic/HkdfArrayInputTest.class'
PREPARED_PATHS = {'capsule': 'capsule', 'views': 'views',
                  'historical_root': 'views/baf-project', 'epoch_project': 'views/epoch-project'}
ORIGINAL_MAPS = {
    'baf': 'a7bc58a1c5d6d0fdacee79b1a0c2de759f6d6b3f107ce94989f2f5f6f8e81c7c',
    'epoch': '800e13e277eb7098f0df780bb737d8c112ae1d1fbedd22a704fdd5cdb7660da2',
    'current85': '4cd8e0957af4d15b3620fa4541dbfbeda4b664f9eb2b848f31353548fbacc9fb',
    'current434': 'b8c2991319e63b6986a3fa672ee8f7a7de4d9450623b6cfcaec4bc701bcbe843',
    'historical85': 'dcae80f69109f9d02e3a47c328082b9270479be0dc19d68286cb553f10630f9a',
    'historical434': 'f5c9b2c1603866e6927dab1f48231733da9f432384874fb35393eaab29ca7118',
}
FIXED_CODE = {
    OLD + 'ci/run.py': '341e5c51c0cbec2b9a27c9ba5b04ecb50af4f08af946a9d1f9e1a7b68760081d',
    OLD + 'ci/selection.json': 'a4278744422a6e59e84976e0fdbf234521fc9a81d94eaefabe26c470dd44dabe',
    OLD + 'parent/parent.py': '28a891c07dd5f4124343f5d50ac406dd1222d90fa17078e5f45f3ee598d46845',
    OLD + 'parent/policy.json': '8bb7b5d157f46db802ce5bd118c79ef365377f708667580bc0d89c1bf1c317d2',
    OLD + 'capsule/safeextract.py': '3ef0b190bb255cf50dbf6800395b69d39951e6af9c094f8f79ea26f2be4cf182',
}
CODE = {*FIXED_CODE, BASE + 'ci.py', BASE + 'admission.py', BASE + 'run.py',
        API, DELIVERY, TOOLING, 'formal/source/hkdf/tooling/source_evidence.py',
        'scripts/security/check_crypto_obligations.py'}
INDEX_ROLES = ('report', 'policy', 'prepared_receipt', 'api_report', 'stage_receipt',
               'delivery_receipt', 'bundle_receipt', 'checkout', 'inputs_before',
               'inputs_after', 'tools_before', 'tools_after', 'project_after', 'build_outputs_after',
               'execution_request', 'api_request', 'qualified_python')


def check_selected_files(root, pins):
    A.check_pins(root, pins)


def check_original_maps(value):
    A.require(value == ORIGINAL_MAPS, 'fixed original Baf/epoch/source/view identities changed')


def check_darwin_preparation(policy, selected_darwin_sha, retained_receipt_sha):
    A.require(policy['retained']['prepared_receipt_sha256'] == A.pin(selected_darwin_sha)
              == retained_receipt_sha, 'local preparation SHA cannot replace retained Darwin authority')


def check_local_paths(root, receipt):
    root = A.absolute(root)
    A.require(all(receipt.get(n) == str(root / rel) for n, rel in PREPARED_PATHS.items()),
              'local preparation path substitution')


def check_clone(original, overlays, removals, expected):
    original, overlays, removals, expected = (A.pin_map(v, empty=True) for v in
                                              (original, overlays, removals, expected))
    A.require(not overlays.keys() & removals.keys(), 'overlapping clone overlay/removal')
    result = dict(original)
    for name, pin in removals.items():
        A.require(result.get(name) == pin, 'clone removal is not an exact original input')
        del result[name]
    result.update(overlays)
    A.require(result == expected, 'constructed project differs from original plus exact current overlays')
    return result


def check_project_inputs(project, before, outputs):
    A.pin_map(before)
    A.build_outputs(outputs, before)
    actual = A.files(project)
    roots = tuple(Path(n) for n in outputs['directories'])
    generated = {n: h for n, h in actual.items() if n not in before and
                 (n in outputs['files'] or any(Path(n).is_relative_to(root) for root in roots))}
    inputs = {n: h for n, h in actual.items() if n not in generated}
    A.require(inputs == before, 'complete current project inputs missing, extra or changed')
    return {'inputs': inputs, 'outputs': generated, 'project': actual}


def check_partition(inputs, outputs, project):
    inputs, outputs, project = (A.pin_map(v, empty=True) for v in (inputs, outputs, project))
    A.require(not inputs.keys() & outputs.keys() and project == {**inputs, **outputs},
              'complete retained project/input/build-output partition differs')


def check_index_subtree(pins, prefix, expected):
    prefix = A.relative(prefix) + '/'
    actual = {n[len(prefix):]: h for n, h in pins.items() if n.startswith(prefix)}
    A.require(actual == A.pin_map(expected, empty=True), 'retained stage subtree missing, extra or changed: ' + prefix)


def check_test_roles(old_inputs, actual_outputs):
    A.pin_map(old_inputs)
    A.pin_map(actual_outputs)
    A.require(len(old_inputs) == 189 and len(actual_outputs) > len(old_inputs)
              and all(n.endswith('.class') for n in {*old_inputs, *actual_outputs})
              and ARRAY_TEST in set(actual_outputs) - set(old_inputs)
              and set(old_inputs) < set(actual_outputs),
              'historical189 binary inputs and measured current test outputs have distinct complete roles')
    A.require(all(actual_outputs[n] == h for n, h in old_inputs.items()),
              'historical189 overlapping test input bytes are immutable')


def check_compiled_trees(classes, tests, class_map, resources, test_outputs):
    A.pin_map(class_map)
    A.pin_map(resources)
    A.pin_map(test_outputs)
    A.require(not class_map.keys() & resources.keys()
              and all(n.endswith('.class') for n in class_map)
              and all(not n.endswith('.class') for n in resources), 'production class/resource role collision')
    A.check_tree(classes, {**class_map, **resources})
    A.check_tree(tests, test_outputs)


def check_local_tools(roots, expected, snapshot=None):
    A.require(type(expected) is dict and expected and set(roots) == set(expected), 'local tool role inventory')
    snapshot = A.files if snapshot is None else snapshot
    for role in expected:
        A.require(snapshot(A.absolute(roots[role])) == expected[role], 'local tool inventory differs: ' + role)


def check_code_bindings(code, current_inputs, api_tools=None):
    A.require(set(A.pin_map(code)) == CODE
              and all(code[n] == h for n, h in FIXED_CODE.items())
              and code[BASE + 'admission.py'] == ADMISSION_SHA256,
              'complete externally selected code closure required')
    A.require(all(current_inputs.get(n) == h for n, h in code.items()), 'unbound current CI/tool source')
    if api_tools is not None:
        A.require(all(current_inputs.get(n) == h for n, h in A.pin_map(api_tools).items()), 'unbound actual API tools/code')


def check_source_trees(repository, project, full_inputs, trees, outputs):
    expected_roots = {str(Path(ref['path']).parent / part)
        for ref in outputs['directories'].values()
        for part in ('src/main/java', 'src/main/resources', 'src/test/java', 'src/test/resources')}
    A.require(set(trees) == expected_roots, 'complete reactor source/resource tree roles required')
    for name, tree in trees.items():
        prefix = A.relative(name) + '/'
        A.require(tree == {n[len(prefix):]: h for n, h in full_inputs.items() if n.startswith(prefix)}, 'sealed source tree differs from full inputs')
        for root in (repository, project):
            actual = A.files(root / name) if (root / name).exists() else {}
            A.require(actual == tree, 'missing/extra current source/resource tree: ' + name)


def check_all_test_outputs(project, outputs, trees):
    roots = {str(Path(ref['path']).parent / 'target/test-classes') for ref in outputs['directories'].values()}
    A.require(set(trees) == roots, 'complete reactor test output roles required')
    for name, tree in trees.items():
        actual = A.files(project / A.relative(name)) if (project / name).exists() else {}
        A.require(actual == A.pin_map(tree, empty=True), 'missing/extra actual test output: ' + name)


def check_hkdf_identity(local, retained, local_project, darwin_project):
    """Compare content identities and authenticate each separately recorded root.

    This reads both unchanged records. It does not rewrite receipts or normalize
    arbitrary path strings. The one root field belongs to the current-only
    validator's derived result, not the portable HKDF proof receipt.
    """
    expected = {'scope', 'qualification', 'manifest_sha256', 'receipt_sha256', 'raw_map_sha256',
                'producer_pins', 'shared_component_validation', 'class_maps', 'runtime_suites',
                'proof_counts', 'complete_before_after_maps_match'}
    A.inventory(local, expected, 'local HKDF result')
    A.inventory(retained, expected, 'retained HKDF result')
    A.require(local['shared_component_validation']['project_root'] == str(local_project)
              and retained['shared_component_validation']['project_root'] == str(darwin_project), 'HKDF result root substitution')
    A.require(all(local[n] == retained[n] for n in expected - {'shared_component_validation'}), 'current HKDF content identity differs')
    a, b = local['shared_component_validation'], retained['shared_component_validation']
    A.require(set(a) == set(b) and all(a[n] == b[n] for n in a if n != 'project_root'), 'current HKDF component identity differs')


def selected_json(path, pin):
    raw = A.captured(A.absolute(path))
    A.require(A.digest(raw) == A.pin(pin), 'externally selected JSON bytes changed: ' + str(path))
    return A.parse_json(raw)


def read_index(root, expected):
    root = A.absolute(root)
    index = selected_json(root / 'index.json', expected)
    A.inventory(index, ('schema', 'scope', 'files', 'roles'), 'retained qualification index')
    A.require(index['schema'] == INDEX_SCHEMA and index['scope'] == 'retained-Darwin-arm64',
              'actual retained Darwin qualification required')
    pins = A.pin_map(index['files'])
    A.inventory(index['roles'], INDEX_ROLES, 'retained role')
    A.require('index.json' not in pins and len(set(index['roles'].values())) == len(INDEX_ROLES),
              'self-authorized or aliased retained role')
    for name in index['roles'].values():
        A.require(A.relative(name) in pins, 'unindexed retained role')
    A.check_tree(root, {**pins, 'index.json': expected})
    return index


def require_completion(report, policy_sha):
    A.require(report.get('schema') == DELIVERY_SCHEMA
              and report.get('status') == 'complete bounded delivery'
              and report.get('qualification') is False and report.get('artifact_API_called') is True
              and report.get('policy_sha256') == policy_sha
              and report.get('project') == report.get('tool_root')
              and type(report.get('project')) is str and Path(report['project']).is_absolute()
              and report.get('complete_input_maps_match') is True
              and report.get('complete_tool_maps_match') is True,
              'actual complete Darwin whole-artifact qualification is absent')


def load_selection(repository, path, expected):
    s = selected_json(path, expected)
    A.inventory(s, ('schema', 'scope', 'code', 'retained', 'original_maps', 'local_tools', 'local_python_sha256'), 'cold CI selection')
    A.require(s['schema'] == SELECTION_SCHEMA and s['scope'] == SCOPE, 'unsupported cold CI subject')
    check_code_bindings(s['code'], s['code'])
    A.inventory(s['retained'], ('index_sha256', 'policy_sha256', 'prepared_receipt_sha256',
                               'checkout_sha256', 'tool_map_sha256', 'execution_request_sha256',
                               'qualified_python_sha256'), 'retained Darwin selection')
    for pin in s['retained'].values():
        A.pin(pin)
    check_original_maps(s['original_maps'])
    A.require(type(s['local_tools']) is dict and s['local_tools'], 'separate local tool authority required')
    A.require(A.sha(Path(sys.executable).resolve()) == A.pin(s['local_python_sha256']), 'local Python source/executable drift')
    check_selected_files(repository, s['code'])
    A.require(A.sha(Path(__file__).absolute()) == s['code'][BASE + 'ci.py'], 'executing CI bytes differ from selected source')
    return s


def cold_original(repository, selected, prepared_root, prepared_sha, original_data):
    """Reuse the unchanged original admission with the local receipt's OWN SHA."""
    ci = A.load_module('hkdf_ci_original_ci', repository / (OLD + 'ci/run.py'), selected['code'][OLD + 'ci/run.py'])
    args = argparse.Namespace(repository=repository, selection=repository / (OLD + 'ci/selection.json'),
        expected_selection_sha256=selected['code'][OLD + 'ci/selection.json'], prepared=A.absolute(prepared_root),
        expected_prepared_sha256=A.pin(prepared_sha))
    p, policy, old_selected, _ = ci.authorities(args)
    prepared = ci.admitted_preparation(p, policy, old_selected, args)
    check_local_paths(args.prepared, prepared)
    views = Path(prepared['views'])
    constructed = p.admit_constructed(policy, views, prepared['views_sha256'])
    source = p.read_json(views / 'source-views/receipt.json', constructed['source_views_receipt_sha256'])
    maps = {'baf': p.map_sha(constructed['baf_files']), 'epoch': p.map_sha(constructed['epoch_files'])}
    for name in ('current', 'historical'):
        maps[name + '85'] = p.map_sha(source['views'][name]['sources'])
        maps[name + '434'] = p.map_sha(source['views'][name]['files'])
    check_original_maps(maps)
    roots = p.admit_capsule(Path(prepared['capsule']), old_selected['capsule_sha256'], policy)
    before = {n: p.files(root) for n, root in roots.items()}
    baf = Path(prepared['historical_root'])
    p.captured_module('check_select_source', baf / 'scripts/security/check_select_source.py',
                      constructed['baf_files']['scripts/security/check_select_source.py'])
    ledger = p.captured_module('hkdf_ci_historical_ledger', baf / 'scripts/security/check_crypto_obligations.py',
                              constructed['baf_files']['scripts/security/check_crypto_obligations.py'])
    historical = ledger.validate_ledger(baf, baf / 'formal/crypto-obligations.json')
    current = p.current_components(policy, Path(prepared['epoch_project']), views / 'source-views', roots)
    cold = {'status': 'current-prerequisites-validated', 'artifact_API_called': False,
            'complete_before_after_maps_match': True, 'policy_sha256': old_selected['policy_sha256'], 'current': current}
    ci.retained_data(p, policy, old_selected, A.absolute(original_data), Path(prepared['epoch_project']),
                     Path(prepared['capsule']), cold)
    A.require(before == {n: p.files(root) for n, root in roots.items()}, 'original raw data changed during cold admission')
    ci.admitted_preparation(p, policy, old_selected, args)
    stage_contract = policy['evidence']['stage']
    old_stage = p.read_json(roots['stage'] / stage_contract['receipt'], stage_contract['receipt_sha256'])
    return constructed, {'maps': maps, 'historical': historical, 'current': current,
                         'local_prepared_receipt_sha256': prepared_sha,
                         'original_stage_receipt_sha256': stage_contract['receipt_sha256'],
                         'qualification': False}, old_stage


def admit_retained(repository, root, selected):
    """Pure receipt/raw admission. Never invokes stage or the artifact API."""
    authority = selected['retained']
    index = read_index(root, authority['index_sha256'])
    pins, roles = index['files'], index['roles']
    rows = {role: selected_json(root / name, pins[name]) for role, name in roles.items()}
    policy, report, api, stage, delivery, bundle, sealed = (rows[n] for n in
        ('policy', 'report', 'api_report', 'stage_receipt', 'delivery_receipt', 'bundle_receipt', 'checkout'))
    A.require(pins[roles['policy']] == authority['policy_sha256']
              and pins[roles['checkout']] == authority['checkout_sha256']
              and pins[roles['execution_request']] == authority['execution_request_sha256'],
              'retained full policy/checkout/execution request not externally selected')
    A.require(pins[roles['qualified_python']] == authority['qualified_python_sha256'],
              'qualified Python observation not externally selected')
    check_darwin_preparation(policy, authority['prepared_receipt_sha256'], pins[roles['prepared_receipt']])
    require_completion(report, authority['policy_sha256'])
    A.require(policy.get('schema') == A.SCHEMA and policy.get('epoch') == 'hkdf-array-001'
              and policy.get('qualification') is False, 'old HKDF full policy subject')
    for kind in ('inputs', 'classes'):
        A.check_delta(policy['predecessor'][kind], policy['candidate'][kind], policy['allowed'][kind])
    A.require(report['artifact_report_sha256'] == pins[roles['api_report']]
              and report['whole_artifact'] == api and api.get('status') == 'complete'
              and api.get('schema') == 'microproxy.crypto-current-release-artifact-validation/v1'
              and api.get('repository_root') == api.get('tool_root') == report['project'], 'actual whole API chain changed')
    A.require(rows['inputs_before'] == rows['inputs_after'] == sealed['project_inputs']
              and rows['tools_before'] == rows['tools_after']
              and A.map_sha(rows['tools_before']) == authority['tool_map_sha256'], 'retained complete before/after maps changed')
    check_partition(rows['inputs_after'], rows['build_outputs_after'], rows['project_after'])
    for role, name in [('inputs_before', 'INPUTS-BEFORE.json'), ('inputs_after', 'INPUTS-AFTER.json'),
                       ('tools_before', 'TOOLS-BEFORE.json'), ('tools_after', 'TOOLS-AFTER.json'),
                       ('project_after', 'PROJECT-TREE-AFTER.json'), ('build_outputs_after', 'BUILD-OUTPUTS-AFTER.json')]:
        A.require(report['maps'][name] == {'path': name, 'sha256': pins[roles[role]]}, 'retained map provenance changed')
    A.require(stage.get('schema') == 'microproxy.crypto-delivery-stage/v1'
              and stage.get('status') == 'complete' and stage.get('component') is None
              and stage.get('manifest_sha256') == policy['delivery']['config']['sha256'], 'retained stage/config subject changed')
    config = A.parse_json(A.read_reference(repository, policy['delivery']['config']))
    for directory, field in [('inputs', 'inputs'), ('sources', 'delivered_sources'),
                              ('classes', 'canonical_classes'),
                              (config['output_name'] + '-java', 'generated_files')]:
        check_index_subtree(pins, (Path(roles['stage_receipt']).parent / directory).as_posix(), stage[field])
    A.require(all(sealed['project_inputs'].get(n) == h for n, h in stage['inputs'].items()), 'retained stage input does not bind the selected current project')
    A.require(sealed.get('schema') == CHECKOUT_SCHEMA
              and sealed['audited_inputs'] == policy['candidate']['inputs']
              and sealed['class_files'] == policy['candidate']['classes']
              and len(sealed['class_files']) == 468, 'retained checkout differs from actual full qualification')
    A.inventory(sealed, ('schema', 'policy_sha256', 'report_sha256', 'api_report_sha256',
        'stage_receipt_sha256', 'project_inputs', 'audited_inputs', 'class_files', 'resources',
        'test_input_binaries', 'test_outputs', 'test_output_trees', 'source_trees', 'build_outputs'), 'current checkout')
    A.require(sealed['build_outputs'] == policy['delivery']['build_outputs']
              == report['build_output_policy'], 'retained finite output policy changed')
    A.build_outputs(sealed['build_outputs'], sealed['project_inputs'])
    for name, role in [('policy_sha256', 'policy'), ('report_sha256', 'report'),
                       ('api_report_sha256', 'api_report'), ('stage_receipt_sha256', 'stage_receipt')]:
        A.require(sealed[name] == pins[roles[role]], 'sealed qualification receipt chain changed')
    check_code_bindings(selected['code'], sealed['project_inputs'], api['tools'])
    A.require(api['inputs']['stage_receipt_sha256'] == pins[roles['stage_receipt']]
              and api['inputs']['delivery_manifest_sha256'] == policy['delivery']['config']['sha256']
              and api['inputs']['runtime_sha256'] == policy['tools']['runtime_sha256']
              and api['delivery']['receipt_sha256'] == pins[roles['delivery_receipt']]
              and api['bundle']['receipt_sha256'] == pins[roles['bundle_receipt']], 'API stage/config/runtime/receipt subject changed')
    A.load_module('delivery', repository / DELIVERY, selected['code'][DELIVERY])
    rules = A.load_module('hkdf_ci_artifact_receipt_rules', repository / API, selected['code'][API])
    checked = rules._check_delivery_receipt(delivery, stage_receipt=stage,
        library_sha=api['inputs']['library_sha256'], stage_sha=pins[roles['stage_receipt']])
    checked_bundle = rules._check_bundle_receipt(bundle, delivery_receipt=delivery,
        library_sha=api['inputs']['library_sha256'], bundle_sha=api['inputs']['bundle_sha256'],
        runtime_sha=api['inputs']['runtime_sha256'], delivery_receipt_sha=pins[roles['delivery_receipt']],
        stage_sha=pins[roles['stage_receipt']], tool_hashes=api['tools'],
        java_homes={n: Path(h) for n, h in api['java_homes'].items()})
    A.require(checked['classes'] == sealed['class_files'] and bundle['resources'] == sealed['resources'], 'actual delivery class/resource identity differs')
    for n in ('class_count', 'generated_class_count', 'handwritten_sources', 'stage_receipt_sha256', 'jar_sha256'):
        A.require(api['delivery'][n] == checked[n], 'API delivery summary differs from checked raw receipt')
    A.require(all(api['bundle'][n] == v for n, v in checked_bundle.items()), 'API bundle summary differs from checked raw receipt')
    check_raw_commands(root, index, rows)
    return policy, sealed, report, stage


def recorded_path(value):
    """Validate a recorded Darwin spelling without resolving it on this host."""
    A.require(type(value) is str and value.startswith('/') and str(Path(value)) == value
              and '..' not in Path(value).parts and '\\' not in value,
              'noncanonical recorded absolute path')
    return Path(value)


def qualified_python_spelling(request, policy, index, rows):
    """Bind observed child spelling to the selected resolved binary observation.

    All paths here belong to the retained Darwin execution. Never resolve them
    on the current host or infer aliases from an executable's basename.
    """
    py, qualified = request['python'], rows['qualified_python']
    A.inventory(py, ('path','sha256','observed_sys_executable','resolved_executable',
                     'framework','qualified_python_sha256'), 'selected Python roles')
    for role in ('resolved_executable','framework'):
        A.inventory(py[role], ('path','sha256'), 'selected Python '+role)
        recorded_path(py[role]['path'])
        A.pin(py[role]['sha256'])
    recorded_path(py['path'])
    recorded_path(py['observed_sys_executable'])
    A.require(py['qualified_python_sha256'] == index['files'][index['roles']['qualified_python']],
              'selected qualified Python observation changed')
    A.require(qualified['qualification'] is False and qualified['implementation'] == 'cpython'
              and qualified['mandatory_flags'] == ['-I','-B']
              and qualified['actual_sys_flags'] == {'isolated':1,'dont_write_bytecode':1,
                  'optimize':0,'ignore_environment':1,'no_user_site':1}, 'qualified Python execution flags changed')
    A.require(qualified['actual_qualification_argv'] == [py['path'],'-I','-B']
              and request['runtime_locations']['python'] == py['path'], 'qualified Python launch spelling changed')
    A.require(qualified['actual_sys_executable'] == py['observed_sys_executable'],
              'observed child Python spelling is not independently qualified')
    A.require(qualified['path'] == py['resolved_executable']['path']
              and qualified['sha256'] == py['resolved_executable']['sha256']
              == py['sha256'] == policy['tools']['python_sha256'], 'resolved Python binary identity differs from policy')
    A.require(py['framework'] == {'path':qualified['framework'],'sha256':qualified['framework_sha256']},
              'qualified Python framework identity changed')
    return py['observed_sys_executable']


def qualified_invocations(index, rows):
    """Derive exact commands from the separately selected actual launch request."""
    request, policy, report, api = (rows[n] for n in ('execution_request', 'policy', 'report', 'api_report'))
    pins, roles = index['files'], index['roles']
    A.require(request['schema'] == 'microproxy.hkdf-array-qualification-request/1'
              and request['qualification'] is False and request['platform_scope'] == 'Darwin-arm64',
              'selected actual Darwin qualification request required')
    source, project, out = (recorded_path(request[n]) for n in ('root', 'project', 'output'))
    rt = request['runtime_locations']
    A.inventory(rt, ('python', 'runtime', 'jdk21', 'jdk25', 'maven', 'prepared', 'data',
                     'hkdf', 'cache', 'junit', 'maven_repository'), 'recorded runtime operand')
    for value in rt.values():
        recorded_path(value)
    child_python = qualified_python_spelling(request, policy, index, rows)
    A.require(request['policy']['sha256'] == pins[roles['policy']]
              and recorded_path(request['policy']['path']).is_relative_to(source)
              and report['project'] == report['tool_root'] == str(project), 'selected Python/policy/project operands changed')
    A.require(policy['delivery']['api'] == {'path': API, 'sha256': policy['candidate']['inputs'][API]}
              and policy['candidate']['inputs']['formal/crypto/delivery.json'] == policy['delivery']['config']['sha256'],
              'qualified API entry or canonical delivery configuration changed')
    for name in ('run', 'admission'):
        relative = BASE + name + '.py'
        A.require(request['bootstrap'][name] == {'path': str(source / relative),
                  'sha256': policy['candidate']['inputs'][relative]}, 'selected runner/bootstrap changed')
        A.require(pins.get((Path(roles['report']).parent / 'runner' / (name+'.py')).as_posix())
                  == policy['candidate']['inputs'][relative], 'captured artifact worker source unbound')
    A.require(request['new_initial_stage'] == str(out / 'stage')
              and request['new_actual_API_output'] == str(out / 'actual-artifacts'), 'selected stage/API output substitution')
    argv = request['argv']
    names = ('root', 'policy', 'expected-policy-sha256', 'project', 'output', 'library', 'bundle',
             'runtime', 'jdk21', 'jdk25', 'prepared', 'data', 'hkdf', 'cache', 'junit', 'maven', 'maven-repository')
    A.require(type(argv) is list and len(argv) == 1+2*len(names) and argv[0] == 'qualify'
              and set(argv[1::2]) == {'--'+n for n in names}, 'selected qualification argv inventory')
    opts = dict(zip(argv[1::2], argv[2::2]))
    expected = {'--root': str(source), '--project': str(project), '--output': str(out),
                '--policy': request['policy']['path'], '--expected-policy-sha256': request['policy']['sha256'],
                **{'--'+n.replace('_','-'): rt[n] for n in rt if n != 'python'}}
    expected['--library'], expected['--bundle'] = opts['--library'], opts['--bundle']
    A.require(opts == expected, 'qualification argv differs from selected actual operands')
    library, bundle = (recorded_path(opts['--'+n]) for n in ('library','bundle'))
    A.require(library != bundle and library.is_relative_to(project / 'quic/target')
              and bundle.is_relative_to(project / 'microproxy-starlark/target'), 'selected private artifact origins changed')
    A.require(report['runtime_locations'] == {n: rt[n] for n in
              ('prepared','data','hkdf','cache','junit','maven','maven_repository')}, 'recorded runtime locations changed')
    tools = rows['tools_before']
    A.require(tools['python_sha256'] == policy['tools']['python_sha256']
              and tools['runtime_sha256'] == policy['tools']['runtime_sha256'], 'recorded Python/runtime bytes changed')
    for name in ('jdk21','jdk25','maven'):
        A.require(A.map_sha(tools['trees'][name]) == policy['tools'][name+'_tree_sha256'], 'recorded compiler/Maven tree changed')
    A.require(A.map_sha(tools['maven_repository']) == policy['tools']['maven_repository_tree_sha256'], 'recorded private Maven repository changed')
    for role in ('cache','junit','maven_repository'):
        A.require(A.map_sha(tools[role]) == request['operand_maps'][role]['map_sha256'], 'selected dependency/cache operand changed')
    A.require(rows['stage_receipt']['jdk_home'] == rt['jdk21']
              and rows['stage_receipt']['manifest_sha256'] == policy['delivery']['config']['sha256'], 'stage compiler/config differs from request')
    home, child = out/'child/home', out/'child'
    settings = home/'.m2/settings.xml'
    settings_raw = ('<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">\n'
        '  <mirrors><mirror><id>selected-central</id><mirrorOf>*</mirrorOf>\n'
        '    <url>https://repo.maven.apache.org/maven2</url>\n'
        '  </mirror></mirrors>\n</settings>\n').encode()
    A.require(pins.get((Path(roles['report']).parent/'child/home/.m2/settings.xml').as_posix())
              == A.digest(settings_raw), 'offline Maven settings bytes unbound')
    api_request = {'project':str(project),'api':policy['delivery']['api'],
        'delivery_sha256':policy['candidate']['inputs'][DELIVERY],'stage':str(out/'stage'),
        'classes':str(project/'quic/target/classes'),'library':str(library),'bundle':str(bundle),
        'runtime':rt['runtime'],'jdk21':rt['jdk21'],'jdk25':rt['jdk25'],
        'output':str(out/'actual-artifacts'),'timeout':policy['delivery']['timeout']}
    A.require(rows['api_request'] == api_request, 'actual API request differs from selected source/tool/stage/runtime/JDK/artifacts')
    expected_api_inputs = {n:api_request[n] for n in ('stage','classes','library','bundle','runtime')}
    expected_api_inputs['java_homes'] = [rt['jdk21'],rt['jdk25']]
    A.require(all(api['inputs'].get(n)==v for n,v in expected_api_inputs.items())
              and api['java_homes'] == {'21':rt['jdk21'],'25':rt['jdk25']}
              and api['inputs']['delivery_manifest_sha256'] == policy['delivery']['config']['sha256'],
              'API actual path/JDK/config operands changed')
    api_tools = {API, DELIVERY, 'formal/crypto/bundle_checks.py', 'formal/nonce/BundleNonceSmoke.java'}
    if 'scripts/security/check_crypto_release.py' in policy['candidate']['inputs']:
        api_tools.add('scripts/security/check_crypto_release.py')
    A.require(set(api['tools']) == api_tools and all(api['tools'][n] == policy['candidate']['inputs'].get(n) for n in api_tools),
              'API source/tool inventory differs from selected actual checkout')
    python = child_python
    commands = {
      'initial-new-config-stage':[python,'-I','-B',str(project/DELIVERY),'stage','--output',str(out/'stage'),
          '--cache',str(home/'.cache/microproxy-formal'),'--runtime',rt['runtime'],'--java-home',rt['jdk21'],
          '--evidence',str(project/policy['delivery']['native_evidence']['path'])],
      'private-maven-package':[str(Path(rt['maven'])/'bin/mvn'),'-o','-q','--settings',str(settings),
          '--global-settings',str(settings),'-Dmaven.repo.local='+str(home/'.m2/repository'),
          '-pl','microproxy-starlark','-am','-DskipTests','package'],
      'whole-artifact-api':[python,'-I','-B',str(out/'runner/run.py'),'_api','--request',str(out/'api-request.json'),
          '--expected-request-sha256',pins[roles['api_request']]]}
    environment = {'PATH':rt['jdk21']+'/bin:'+rt['maven']+'/bin:/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC',
        'HOME':str(home),'TMPDIR':str(child/'tmp'),'TMP':str(child/'tmp'),'TEMP':str(child/'tmp'),
        'XDG_CONFIG_HOME':str(child/'config'),'XDG_CACHE_HOME':str(child/'cache'),'JAVA_HOME':rt['jdk21'],
        'MAVEN_SKIP_RC':'1','PYTHONDONTWRITEBYTECODE':'1','MAVEN_USER_HOME':str(home/'.m2')}
    api_commands = {'jdk-0-version':[rt['jdk21']+'/bin/java','-version'],
      'jdk-1-version':[rt['jdk25']+'/bin/java','-version'],
      'delivery-check':[python,str(project/DELIVERY),'check','--stage',str(out/'stage'),'--classes',api_request['classes'],
          '--jar',str(library),'--runtime',rt['runtime'],'--java-home',rt['jdk21']],
      'bundle-check':[python,str(project/'formal/crypto/bundle_checks.py'),'--library',str(library),'--bundle',str(bundle),
          '--delivery-receipt',str(out/'actual-artifacts/delivery-check.json'),'--stage',str(out/'stage'),
          '--runtime',rt['runtime'],'--java-home',rt['jdk21'],'--java-home',rt['jdk25'],
          '--output',str(out/'actual-artifacts/bundle-check')]}
    return commands, environment, api_commands, out


def check_raw_commands(root, index, rows):
    pins, roles = index['files'], index['roles']
    report, api, bundle = rows['report'], rows['api_report'], rows['bundle_receipt']
    expected_commands, expected_env, expected_api, recorded_output = qualified_invocations(index, rows)
    labels = ['initial-new-config-stage', 'private-maven-package', 'whole-artifact-api']
    A.require([r['label'] for r in report['commands']] == labels, 'epoch execution inventory changed')
    for row in report['commands']:
        label = row['label']
        base = Path(roles['report']).parent / 'logs'
        raw_name = (base / (label+'.raw-execution.json')).as_posix()
        A.require(type(row['exit']) is int and row['exit'] == 0
                  and row['argv'] == expected_commands[label]
                  and row['raw_execution_record'] == str(recorded_output/'logs'/(label+'.raw-execution.json'))
                  and row['process_group_empty_after_exit'] is True
                  and pins.get(raw_name) == row['raw_execution_sha256'], 'retained actual execution/owned drain incomplete')
        raw = selected_json(root / raw_name, pins[raw_name])
        A.require(raw['actual_exit_observed'] is True and raw['returncode'] == row['exit']
                  and raw['argv'] == row['argv'] and raw['cwd'] == report['project']
                  and raw['environment'] == expected_env
                  and raw['log'] == str(recorded_output/'logs'/(label+'.log'))
                  and raw['supervisor_failure'] is None
                  and pins.get((base / (label + '.log')).as_posix()) == raw['log_sha256'], 'retained raw actual exit/log differs')
        if label == 'private-maven-package':
            A.require('-o' in raw['argv'] and raw['argv'][-1] == 'package'
                      and not {'install', 'deploy'} & set(raw['argv']), 'retained package was not bounded offline package')
    A.require([r['label'] for r in api['commands']] == ['jdk-0-version', 'jdk-1-version', 'delivery-check', 'bundle-check'], 'actual API command inventory changed')
    A.require([r['label'] for r in bundle['commands']] == ['version-0', 'version-1', 'compile-harness',
        'jdk21-bundle-smoke', 'jdk25-bundle-smoke', 'compile-nonce-smoke', 'jdk21-nonce-smoke', 'jdk25-nonce-smoke'], 'actual bundle command inventory changed')
    for row in api['commands']:
        A.require(type(row['exit']) is int and row['exit'] == 0
                  and row['argv'] == expected_api[row['label']], 'actual API command failed or invocation changed')
        for stream in ('stdout', 'stderr'):
            name = (Path(roles['api_report']).parent / (row['label'] + '.' + stream + '.log')).as_posix()
            A.require(pins.get(name) == row[stream + '_sha256'], 'API raw stream unbound')
    for row in bundle['commands']:
        name = (Path(roles['bundle_receipt']).parent / (row['label'] + '.log')).as_posix()
        A.require(type(row['exit']) is int and row['exit'] == 0 and pins.get(name) == row['log_sha256'], 'bundle raw execution unbound')
    for major in ('21', '25'):
        for suffix, record in [('classload', bundle['runs'][major]), ('nonce-classload', bundle['nonce_smoke']['runs'][major])]:
            name = (Path(roles['bundle_receipt']).parent / ('jdk' + major + '-' + suffix + '.log')).as_posix()
            A.require(pins.get(name) == record['classload_sha256'], 'bundle origin trace unbound')


def check(args):
    repository, project = map(A.absolute, (args.repository, args.project))
    selected = load_selection(repository, args.selection, args.expected_selection_sha256)
    retained_root = A.absolute(args.retained_data)
    # Fail here before cold/local work when actual Darwin qualification is absent.
    policy, sealed, report, retained_stage = admit_retained(repository, retained_root, selected)
    original, cold, original_stage = cold_original(repository, selected, args.prepared, args.expected_prepared_sha256, args.original_data)
    A.require(retained_stage['canonical_classes'] == original_stage['canonical_classes']
              and retained_stage['sources'] == original_stage['sources'], 'new retained native stage differs from authenticated unchanged original native identity')
    check_clone(original['epoch_files'], sealed['audited_inputs'], policy['allowed']['inputs']['removed'], sealed['project_inputs'])
    check_selected_files(repository, sealed['audited_inputs'])
    A.require(sealed['build_outputs'] == policy['delivery']['build_outputs'], 'finite output policy changed')
    check_project_inputs(project, sealed['project_inputs'], sealed['build_outputs'])
    A.require(sealed['test_input_binaries'] == {n.removeprefix('quic/target/test-classes/'): h
        for n, h in sealed['project_inputs'].items() if n.startswith('quic/target/test-classes/')}, 'historical test binary input role changed')
    check_test_roles(sealed['test_input_binaries'], sealed['test_outputs'])
    A.require(sealed['test_outputs'] == sealed['test_output_trees'].get('quic/target/test-classes'), 'quic actual test output role differs')
    check_all_test_outputs(project, sealed['build_outputs'], sealed['test_output_trees'])
    check_compiled_trees(A.absolute(args.classes), A.absolute(args.test_outputs), sealed['class_files'], sealed['resources'], sealed['test_outputs'])
    A.require(A.absolute(args.classes) == project / 'quic/target/classes'
              and A.absolute(args.test_outputs) == project / 'quic/target/test-classes', 'alternate compiled origin')
    check_source_trees(repository, project, sealed['project_inputs'], sealed['source_trees'], sealed['build_outputs'])
    local_roots = A.parse_json(A.captured(A.absolute(args.local_tools)))
    helper = A.load_module('hkdf_ci_local_typed_tools', repository / TOOLING, selected['code'][TOOLING])
    check_local_tools(local_roots, selected['local_tools'], snapshot=helper.tree_snapshot)
    runner = A.load_module('hkdf_ci_epoch_runner', repository / (BASE + 'run.py'), selected['code'][BASE + 'run.py'])
    loaded = A.load_policy(repository, A.absolute(args.policy), selected['retained']['policy_sha256'])
    A.bind_runtime(loaded, hkdf=A.absolute(args.hkdf_raw))
    hkdf = runner.check_hkdf(repository, loaded)
    runner.check_native_binding(repository, original_stage, sealed['class_files'], runner.managed_hkdf_sources(repository, loaded))
    check_hkdf_identity(hkdf, report['hkdf'], repository, report['project'])
    check_project_inputs(project, sealed['project_inputs'], sealed['build_outputs'])
    check_compiled_trees(args.classes, args.test_outputs, sealed['class_files'], sealed['resources'], sealed['test_outputs'])
    check_all_test_outputs(project, sealed['build_outputs'], sealed['test_output_trees'])
    check_local_tools(local_roots, selected['local_tools'], snapshot=helper.tree_snapshot)
    check_source_trees(repository, project, sealed['project_inputs'], sealed['source_trees'], sealed['build_outputs'])
    load_selection(repository, args.selection, args.expected_selection_sha256)
    read_index(retained_root, selected['retained']['index_sha256'])
    return {'schema': 'microproxy.hkdf-array-cold-ci-result/1', 'status': 'complete', 'scope': SCOPE,
            'qualification': False, 'fresh_Linux_proof_or_API': False, 'globalV7': False,
            'selection_sha256': args.expected_selection_sha256,
            'retained_Darwin_index_sha256': selected['retained']['index_sha256'],
            'retained_Darwin_prepared_sha256': selected['retained']['prepared_receipt_sha256'],
            'local_prepared_sha256': args.expected_prepared_sha256,
            'complete_current_inputs': len(sealed['project_inputs']), 'production_classes': len(sealed['class_files']),
            'actual_test_outputs': len(sealed['test_outputs']), 'cold_original': cold, 'hkdf': hkdf,
            'outstanding': ['global-V7', 'physical-JVM-timing', 'independent-expert-review']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'project', 'policy', 'selection', 'retained-data', 'original-data',
                 'prepared', 'classes', 'test-outputs', 'local-tools', 'hkdf-raw'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('expected-selection-sha256', 'expected-prepared-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    A.require(sys.flags.isolated and sys.flags.dont_write_bytecode, 'cold CI requires Python -I -B')
    print(json.dumps(check(args), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError) as exc:
        print('HKDF COLD CI REJECTED: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
