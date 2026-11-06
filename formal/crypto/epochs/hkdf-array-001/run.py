#!/usr/bin/env python3
"""HKDF array epoch: retained native, fresh HKDF and current artifact scopes."""
import sys

if sys.flags.optimize:
    raise RuntimeError('HKDF array epoch requires unoptimized Python')
if not (sys.flags.isolated and sys.flags.dont_write_bytecode):
    raise RuntimeError('HKDF array epoch requires Python -I -B')

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
from zipfile import ZipFile

# Pin the tiny bootstrap before executing it. -B alone does not prevent .pyc
# reads. The selected policy subsequently binds this runner and bootstrap again.
HERE = Path(__file__).absolute().parent
ADMISSION_SHA256 = '35565fdc4c371b313908d0900d617edde9cd0053a1c993f90f07c891733f960d'
_path = HERE / 'admission.py'
_raw = _path.read_bytes()
if hashlib.sha256(_raw).hexdigest() != ADMISSION_SHA256:
    raise ValueError('epoch bootstrap raw source pin mismatch')
_spec = importlib.util.spec_from_file_location('hkdf_epoch_admission', _path)
A = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = A
exec(compile(_raw, str(_path), 'exec', dont_inherit=True), A.__dict__)

EpochError = A.EpochError
load_policy = A.load_policy
check_delta = A.check_delta
BASE = 'formal/crypto/epochs/hkdf-array-001/'
SOURCE_BASE = 'formal/source/epochs/keccak-004/'
JAVA = 'quic/src/main/java/'
HKDF_PACKAGE = JAVA + 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/'


def check_delivery_config(before, after, selected):
    """The successor can update existing HKDF source pins only."""
    A.require(type(before) is dict and type(after) is dict, 'delivery configuration objects required')
    old = dict(before)
    new = dict(after)
    old_sources = old.pop('existing_generated_sources', None)
    new_sources = new.pop('existing_generated_sources', None)
    A.require(old == new, 'delivery native/compiler/control/runtime policy changed')
    allowed = {'changed': selected, 'added': {}, 'removed': {}}
    A.check_delta(old_sources, new_sources, allowed)
    return selected


def check_stage(stage, config_sha256, jdk21):
    receipt = A.parse_json(A.captured(A.absolute(stage) / 'receipt.json'))
    A.require(receipt.get('status') == 'complete' and receipt.get('component') is None
              and receipt.get('manifest_sha256') == config_sha256, 'stage does not match new configuration')
    A.require(receipt.get('jdk_home') == str(A.absolute(jdk21)), 'stage has wrong JDK21 home')
    return receipt


def check_jar_subset(jar, classes):
    """Supplement the full API; reject duplicate or MR overrides anywhere."""
    A.pin_map(classes)
    with ZipFile(A.absolute(jar)) as archive:
        names = archive.namelist()
        A.require(len(names) == len(set(names)), 'duplicate JAR entry')
        for name in names:
            override = re.fullmatch(r'META-INF/versions/[0-9]+/(.+\.class)', name)
            A.require(not override or override[1] == 'module-info.class', 'multi-release JAR class override')
        for name, expected in classes.items():
            A.require(name in names and A.digest(archive.read(name)) == expected, 'actual HKDF JAR class missing/changed: ' + name)
    return classes


def check_native_binding(project, stage, classes, managed):
    """Bind every retained native operand and all canonical classes.

    `managed` contains individual HKDF successor paths and hashes derived from
    the completed v2 receipt. It is never a prefix exception.
    """
    wanted = dict(stage['inputs'])
    wanted.update({JAVA + n: pin for n, pin in stage['delivered_sources'].items()})
    wanted.pop('formal/crypto/delivery.json', None)  # checked as a full config successor
    for name in set(wanted) & set(managed):
        wanted[name] = managed[name]
    for name, expected in wanted.items():
        A.require(A.sha(A.absolute(project) / name) == expected, 'retained native input/provider changed: ' + name)
    if classes is not None:
        A.require(all(classes.get(n) == pin for n, pin in stage['canonical_classes'].items()),
                  'retained native canonical class changed')
    return wanted


def check_artifact_result(project, result):
    A.require(result.get('schema') == 'microproxy.crypto-current-release-artifact-validation/v1'
              and result.get('status') == 'complete'
              and result.get('repository_root') == result.get('tool_root') == str(A.absolute(project)),
              'whole artifact API incomplete or different project/tool root')
    return result


def project_hkdf(raw_root, projector, expected):
    module = A.load_module('epoch_hkdf_raw_projection', projector, expected)
    return module.project(A.absolute(raw_root))


def tool_module(project, policy, relative, name):
    A.reauthenticate(policy)
    A.require(relative in policy['candidate']['inputs'], 'unselected executable tool: ' + relative)
    return A.load_module(name, A.absolute(project) / relative, policy['candidate']['inputs'][relative])


def retained_context(project, policy):
    """Reopen only externally selected original authority; no current constructor."""
    A.reauthenticate(policy)
    contract = policy['retained']
    ci = A.load_module('epoch_retained_ci', A.absolute(project) / contract['ci']['path'], contract['ci']['sha256'])
    args = argparse.Namespace(repository=A.absolute(project), selection=A.absolute(project) / contract['selection']['path'],
                              expected_selection_sha256=contract['selection']['sha256'])
    parent, original_policy, selected, _ = ci.authorities(args)
    args.prepared = A.location(policy, 'prepared')
    args.expected_prepared_sha256 = contract['prepared_receipt_sha256']
    prepared = ci.admitted_preparation(parent, original_policy, selected, args)
    views = Path(prepared['views'])
    capsule = Path(prepared['capsule'])
    roots = parent.admit_capsule(capsule, selected['capsule_sha256'], original_policy)
    view_receipt = parent.admit_constructed(original_policy, views, prepared['views_sha256'])
    return ci, parent, original_policy, selected, prepared, views, capsule, roots, view_receipt


def check_retained(project: Path, policy: dict) -> dict:
    context = retained_context(project, policy)
    ci, p, old_policy, selected, prepared, views, capsule, roots, original_views = context
    A.require(policy['delivery']['predecessor']['sha256'] == p.CONFIG,
              'delivery successor must start from the selected retained native configuration')
    original_project = views / 'epoch-project'
    before = {n: p.files(root) for n, root in roots.items()}
    baf = views / 'baf-project'
    p.captured_module('check_select_source', baf / 'scripts/security/check_select_source.py',
                      original_views['baf_files']['scripts/security/check_select_source.py'])
    historical_validator = p.captured_module('epoch_original_historical_ledger', baf / 'scripts/security/check_crypto_obligations.py',
                                            original_views['baf_files']['scripts/security/check_crypto_obligations.py'])
    historical = historical_validator.validate_ledger(baf, baf / 'formal/crypto-obligations.json')
    current = p.current_components(old_policy, original_project, views / 'source-views', roots)
    cold = {'status': 'current-prerequisites-validated', 'artifact_API_called': False,
            'complete_before_after_maps_match': True, 'policy_sha256': selected['policy_sha256'], 'current': current}
    sealed, _ = ci.retained_data(p, old_policy, selected, A.location(policy, 'data'), original_project, capsule, cold)
    A.require(policy['predecessor'] == {'inputs': sealed['source_files'], 'classes': sealed['class_files']},
              'predecessor maps differ from the original selected artifact subject')
    stage = p.read_json(roots['stage'] / old_policy['evidence']['stage']['receipt'], old_policy['evidence']['stage']['receipt_sha256'])
    managed = managed_hkdf_sources(project, policy)
    native_inputs = check_native_binding(project, stage, policy['candidate'].get('classes'), managed)
    p.admit_constructed(old_policy, views, prepared['views_sha256'])
    p.admit_capsule(capsule, selected['capsule_sha256'], old_policy)
    A.require(before == {n: p.files(root) for n, root in roots.items()}, 'retained raw evidence changed during cold validation')
    A.reauthenticate(policy)
    return {'scope': 'retained native evidence on authenticated original Keccak subject',
            'qualification': False, 'selection_sha256': policy['retained']['selection']['sha256'],
            'historical': {'status': 'HISTORICAL', 'commit': p.BAF, 'tree': p.TREE, 'result': historical},
            'original_source_files': sealed['source_files'], 'original_class_files': sealed['class_files'],
            'current_components': current, 'native_inputs': native_inputs, 'native_classes': stage['canonical_classes'],
            'candidate_native_class_map_selected': 'classes' in policy['candidate'],
            'original_stage_receipt_sha256': old_policy['evidence']['stage']['receipt_sha256'],
            'original_delivery_config_sha256': p.CONFIG,
            'original_project_files': original_views['epoch_files'],
            'artifact_prerequisites': old_policy['artifact_prerequisites'],
            'complete_before_after_maps_match': True}


def managed_hkdf_sources(project, policy):
    """Individual generated HKDF filenames, with no provider/native exclusions."""
    manifest = A.parse_json(A.read_reference(project, policy['hkdf']['manifest']))
    A.require(manifest.get('schema') == 'microproxy.hkdf-source-traces-inputs/v2', 'old HKDF input subject')
    generated_path = 'formal/dafny/hkdf/GENERATED.json'
    A.require(manifest['inputs'].get(generated_path) == policy['candidate']['inputs'].get(generated_path),
              'generated HKDF authority is outside selected candidate inputs')
    generated = A.parse_json(A.captured(A.absolute(project) / generated_path))
    A.require(len(A.pin_map(generated['source'])) == 9, 'wrong generated HKDF source inventory')
    return {HKDF_PACKAGE + n: pin for n, pin in generated['source'].items()}


def check_hkdf(project: Path, policy: dict) -> dict:
    A.reauthenticate(policy)
    project = A.absolute(project)
    contract = policy['hkdf']
    raw_root = A.location(policy, 'hkdf')
    A.check_tree(raw_root, contract['raw_files'])
    manifest = A.parse_json(A.read_reference(project, contract['manifest']))
    receipt = A.parse_json(A.read_reference(project, contract['receipt']))
    A.require(manifest.get('schema') == 'microproxy.hkdf-source-traces-inputs/v2', 'old HKDF manifest subject')
    A.check_pins(project, manifest['inputs'])
    A.require(all(policy['candidate']['inputs'].get(n) == pin for n, pin in manifest['inputs'].items()),
              'HKDF source/producer input outside selected candidate map')
    projector = A.load_module('epoch_hkdf_raw_projection', project / contract['projector']['path'], contract['projector']['sha256'])
    A.require(contract['producers'] == {n: manifest['inputs'][n] for n in projector.PRODUCERS},
              'current HKDF producer inventory differs from selected authority')
    projected = projector.project(raw_root)
    A.require(projected == receipt == A.parse_json(A.captured(raw_root / 'SOURCE-EVIDENCE-v2.json')),
              'selected HKDF receipt differs from actual complete raw derivation')
    A.require(receipt['tool_scope']['before_sha256'] == receipt['tool_scope']['after_sha256'] == contract['tool_map_sha256'],
              'HKDF full tool-map authority mismatch')
    validator = tool_module(project, policy, 'scripts/security/check_crypto_obligations.py', 'epoch_current_hkdf_obligations')
    result = validator.validate_current_hkdf(project)
    A.require(result.get('ok') is True and result.get('full_ledger') is False and result.get('globalV7') is False
              and result.get('artifactqualification') is False
              and result.get('manifest_sha256') == contract['manifest']['sha256']
              and result.get('source_receipt_sha256') == contract['receipt']['sha256'],
              'shared current HKDF component validator did not admit this subject/scope')
    A.check_tree(raw_root, contract['raw_files'])
    A.check_pins(project, manifest['inputs'])
    A.reauthenticate(policy)
    return {'scope': 'fresh current HKDF v2 component evidence, not whole-library qualification',
            'qualification': False, 'manifest_sha256': contract['manifest']['sha256'],
            'receipt_sha256': contract['receipt']['sha256'], 'raw_map_sha256': A.map_sha(contract['raw_files']),
            'producer_pins': contract['producers'], 'shared_component_validation': result,
            'class_maps': receipt['java']['class_maps'], 'runtime_suites': receipt['java']['runtime'],
            'proof_counts': receipt['positive'], 'complete_before_after_maps_match': True}


def project_map(retained, policy):
    expected = dict(retained['original_project_files'])
    for name in policy['allowed']['inputs']['removed']:
        expected.pop(name, None)
    expected.update(policy['candidate']['inputs'])
    return expected


def protected_roots(policy, **extra):
    return {'source-root': policy.root, 'policy': policy.path,
            'python-prefix': Path(sys.base_prefix).resolve(), 'python-executable': Path(sys.executable).resolve(),
            **policy.locations, **extra}


def prepare_project(root, policy, output):
    """Full original authenticated project plus only the selected candidate delta."""
    output = A.output_admission(output, protected_roots(policy))
    retained = check_retained(A.absolute(root), policy)
    hkdf = check_hkdf(A.absolute(root), policy)
    _, _, _, _, _, views, _, _, _ = retained_context(root, policy)
    before = project_map(retained, policy)
    output.mkdir(mode=0o700)
    project = output / 'project'
    project.mkdir(mode=0o700)
    for name, expected in before.items():
        origin = A.candidate_origin(root, policy, name) if name in policy['candidate']['inputs'] else views / 'epoch-project' / name
        raw = A.captured(origin)
        A.require(A.digest(raw) == expected, 'candidate construction input changed: ' + name)
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(origin.stat().st_mode & 0o777)
    A.check_tree(project, before)
    A.check_candidate_sources(A.absolute(root), policy)
    (output / 'project-map.json').write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
    (output / 'preparation.json').write_text(json.dumps({'schema': 'microproxy.hkdf-array-preparation/1',
        'qualification': False, 'candidate_class_map_selected': 'classes' in policy['candidate'],
        'policy_sha256': policy.expected, 'project': str(project),
        'project_map_sha256': A.map_sha(before), 'retained': retained, 'hkdf': hkdf}, indent=2) + '\n')
    return project


def selected_delivery_config(project, policy):
    old = A.parse_json(A.read_reference(project, policy['delivery']['predecessor']))
    new = A.parse_json(A.read_reference(project, policy['delivery']['config']))
    A.require(A.sha(A.absolute(project) / 'formal/crypto/delivery.json') == policy['delivery']['config']['sha256'],
              'canonical delivery configuration differs from selected successor')
    managed = managed_hkdf_sources(project, policy)
    selected = {}
    for name, expected in managed.items():
        key = name.removeprefix(JAVA)
        if old['existing_generated_sources'].get(key) != expected:
            row = policy['allowed']['inputs']['changed'].get(name)
            A.require(row == {'before': old['existing_generated_sources'].get(key), 'after': expected},
                      'delivery HKDF source update lacks its exact selected input delta')
            selected[key] = row
    check_delivery_config(old, new, selected)
    return new


def project_inventory(actual, before, selected_outputs):
    """Partition the complete map; an existing target input never becomes output."""
    A.build_outputs(selected_outputs, before)
    roots = tuple(Path(n) for n in selected_outputs['directories'])
    outputs = {n: pin for n, pin in actual.items() if n not in before and
               (n in selected_outputs['files'] or any(Path(n).is_relative_to(root) for root in roots))}
    inputs = {n: pin for n, pin in actual.items() if n not in outputs}
    return {'project': actual, 'inputs': inputs, 'outputs': outputs}


def source_inventory_unchanged(project, before, selected_outputs=None):
    selected_outputs = selected_outputs if selected_outputs is not None else {'directories': {}, 'files': {}}
    maps = project_inventory(A.files(project), before, selected_outputs)
    A.require(maps['inputs'] == before, 'complete project input inventory changed, missing or extra')
    return maps


def operand_snapshot(project, policy, runtime, jdk21, jdk25):
    helper = tool_module(project, policy, 'formal/source/hkdf/tooling/admission.py', 'epoch_full_tool_snapshot')
    trees = {name: helper.tree_snapshot(path) for name, path in
             (('jdk21', jdk21), ('jdk25', jdk25), ('maven', A.location(policy, 'maven')))}
    for name, tree in trees.items():
        A.require(A.map_sha(tree) == policy['tools'][name + '_tree_sha256'], 'wrong selected ' + name + ' runtime/tool tree')
    hkdf_tools = A.parse_json(A.captured(A.location(policy, 'hkdf') / 'TOOLS-BEFORE.json'))
    for name in ('jdk21', 'jdk25'):
        keys = [k for k in hkdf_tools if k.startswith(name + '-typed-tree:')]
        A.require(len(keys) == 1 and hkdf_tools[keys[0]] == trees[name], 'artifact JDK differs from completed HKDF JDK subject')
    A.require(A.sha(runtime) == policy['tools']['runtime_sha256'], 'wrong selected Dafny runtime')
    A.require(A.sha(Path(sys.executable).resolve()) == policy['tools']['python_sha256'], 'wrong selected Python tool')
    return {'trees': trees, 'runtime_sha256': A.sha(runtime), 'python_sha256': A.sha(Path(sys.executable).resolve())}


def tool_snapshot(project, policy, runtime, jdk21, jdk25):
    operands = operand_snapshot(project, policy, runtime, jdk21, jdk25)
    repository = A.files(A.location(policy, 'maven_repository'))
    A.require(A.map_sha(repository) == policy['tools']['maven_repository_tree_sha256'], 'wrong selected Maven dependency tree')
    return {**operands, 'maven_repository': repository,
            'cache': A.files(A.location(policy, 'cache')), 'junit': A.files(A.location(policy, 'junit'))}


def private_maven_command(maven, home, *, offline):
    """Explicit cache/settings operands; Java's user.home is not inferred from HOME."""
    settings = A.absolute(home) / '.m2/settings.xml'
    settings.parent.mkdir(parents=True, exist_ok=True)
    with settings.open('x') as stream:
        stream.write('<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">\n'
                     '  <mirrors><mirror><id>selected-central</id><mirrorOf>*</mirrorOf>\n'
                     '    <url>https://repo.maven.apache.org/maven2</url>\n'
                     '  </mirror></mirrors>\n</settings>\n')
    return [A.absolute(maven) / 'bin/mvn', *(['-o'] if offline else []), '-q',
            '--settings', settings, '--global-settings', settings,
            '-Dmaven.repo.local=' + str(settings.parent / 'repository'),
            '-pl', 'microproxy-starlark', '-am', '-DskipTests', 'package']


def maven_environment(env, maven, jdk21):
    env.update(JAVA_HOME=str(jdk21), MAVEN_SKIP_RC='1', PYTHONDONTWRITEBYTECODE='1',
               MAVEN_USER_HOME=str(Path(env['HOME']) / '.m2'),
               PATH=str(jdk21 / 'bin') + ':' + str(maven / 'bin') + ':/usr/bin:/bin')


def measure(project, policy, output, library, bundle, runtime, jdk21, jdk25):
    """Online private package measurement only. Never a proof or artifact qualification."""
    A.reauthenticate(policy)
    A.require(policy['schema'] == A.SOURCE_SCHEMA, 'measurement requires selected source-only construction authority')
    project, runtime, jdk21, jdk25 = map(A.absolute, (project, runtime, jdk21, jdk25))
    for name in ('prepared', 'data', 'hkdf', 'maven'):
        A.location(policy, name)
    output = A.output_admission(output, protected_roots(policy, project=project, runtime=runtime, jdk21=jdk21, jdk25=jdk25))
    A.require(project != policy.root, 'measurement requires the new constructed isolated project')
    library, bundle = A.absolute(library), A.absolute(bundle)
    A.require(library != bundle and library.is_relative_to(project) and bundle.is_relative_to(project)
              and not library.exists() and not bundle.exists(), 'measurement artifact outputs must be new inside the project')
    retained, hkdf = check_retained(project, policy), check_hkdf(project, policy)
    before = project_map(retained, policy)
    A.check_tree(project, before)
    selected_delivery_config(project, policy)
    tools = operand_snapshot(project, policy, runtime, jdk21, jdk25)
    owner = tool_module(project, policy, 'formal/source/hkdf/tooling/owned_call.py', 'measurement_owned_execution')
    helper = tool_module(project, policy, 'formal/source/hkdf/tooling/admission.py', 'measurement_private_environment')
    output.mkdir(mode=0o700)
    env = helper.child_environment(output / 'child')
    repository = Path(env['HOME']) / '.m2/repository'
    repository.mkdir(parents=True)
    command = private_maven_command(A.location(policy, 'maven'), Path(env['HOME']), offline=False)
    maven_environment(env, A.location(policy, 'maven'), jdk21)
    report = {'schema': 'microproxy.hkdf-array-package-measurement/1', 'status': 'incomplete', 'qualification': False,
              'proof_executed': False, 'artifact_API_called': False, 'candidate_class_map_selected': False,
              'dependency_cache_qualified': False, 'dependency_population': 'online HTTPS; no closed-tool claim',
              'policy_sha256': policy.expected, 'project': str(project), 'argv': list(map(str, command)),
              'runtime_locations': {k: str(v) for k, v in policy.locations.items()}, 'commands': [],
              'scope': 'Unqualified actual complete class/JAR/cache measurement for later external policy selection'}
    owner.durable_json(output / 'report.json', report)
    owner.durable_json(output / 'INPUTS-BEFORE.json', before)
    owner.durable_json(output / 'TOOLS-BEFORE.json', tools)
    owner.durable_json(output / 'DEPENDENCY-CACHE-BEFORE.json', A.files(repository))
    try:
        code, text, record = owner.run(command, output / 'maven-package.log', project, env, policy['delivery']['timeout'])
        row = {'label': 'unqualified-online-package', 'argv': list(map(str, command)), 'exit': code, **record}
        owner.durable_json(output / 'maven-package.record.json', row)
        report['commands'].append(row)
        owner.durable_json(output / 'report.json', report)
        A.require(code == 0, 'unqualified Maven measurement failed')
        actual = {n: pin for n, pin in A.files(project / 'quic/target/classes').items() if n.endswith('.class')}
        A.require(actual, 'measurement produced no actual class files')
        owner.durable_json(output / 'ACTUAL-CLASSES.json', actual)
        report['actual_class_count'] = len(actual)
        report['artifacts'] = {name: {'path': str(path), 'sha256': A.sha(path)} for name, path in (('library', library), ('bundle', bundle))}
        report['status'] = 'complete unqualified measurement'
    except BaseException as exc:
        report.update(status='failed/incomplete', error=type(exc).__name__ + ': ' + str(exc))
        raise
    finally:
        try:
            maps = project_inventory(A.files(project), before, policy['delivery']['build_outputs'])
            after = operand_snapshot(project, policy, runtime, jdk21, jdk25)
            cache = A.files(repository)
            for name, value in (('PROJECT-TREE-AFTER.json', maps['project']), ('INPUTS-AFTER.json', maps['inputs']),
                                ('BUILD-OUTPUTS-AFTER.json', maps['outputs']), ('TOOLS-AFTER.json', after),
                                ('DEPENDENCY-CACHE-AFTER.json', cache)):
                owner.durable_json(output / name, value)
            report['maps'] = {name: {'path': name, 'sha256': A.sha(output / name)} for name in
                              ('INPUTS-BEFORE.json', 'INPUTS-AFTER.json', 'PROJECT-TREE-AFTER.json', 'BUILD-OUTPUTS-AFTER.json',
                               'TOOLS-BEFORE.json', 'TOOLS-AFTER.json', 'DEPENDENCY-CACHE-BEFORE.json', 'DEPENDENCY-CACHE-AFTER.json')}
            report['dependency_cache_root'] = str(repository)
            report['dependency_cache_map_sha256'] = A.map_sha(cache)
            report['actual_class_map_sha256'] = A.map_sha(actual) if 'actual' in locals() else None
            report['inputs_before_after_equal'] = maps['inputs'] == before
            report['selected_tool_operands_before_after_equal'] = after == tools
            A.require(maps['inputs'] == before and after == tools, 'measurement input/tool operand inventory changed')
            A.require(cache == A.files(repository), 'dependency cache changed while freezing the measurement')
        except BaseException as exc:
            report.update(status='failed/incomplete', final_inventory_error=type(exc).__name__ + ': ' + str(exc))
            raise
        finally:
            owner.durable_json(output / 'report.json', report)
    return report


def seed_child_home(env, policy, retained, tools):
    home = Path(env['HOME'])
    spec = retained['artifact_prerequisites']
    repository = home / '.m2/repository'
    for name, expected in tools['maven_repository'].items():
        origin = A.location(policy, 'maven_repository') / name
        target = repository / name
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = A.captured(origin)
        A.require(A.digest(raw) == expected, 'Maven dependency changed before private copy')
        target.write_bytes(raw)
    for name, expected in spec['junit'].items():
        raw = A.captured(A.location(policy, 'junit') / name)
        A.require(A.digest(raw) == expected, 'unselected JUnit fixture dependency')
        A.require(A.sha(repository / name) == expected, 'Maven/JUnit dependency disagreement')
    asset = spec['official_asset']
    selected = {**{asset['directory'] + '/' + n: pin for n, pin in spec['distribution'].items()}, asset['archive']: asset['sha256']}
    for name, expected in selected.items():
        origin = A.location(policy, 'cache') / name
        raw = A.captured(origin)
        A.require(A.digest(raw) == expected, 'official Dafny cache input changed')
        target = home / '.cache/microproxy-formal' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(origin.stat().st_mode & 0o777)
    A.check_tree(home / '.cache/microproxy-formal', selected)


def qualify(project: Path, policy: dict, output: Path, library: Path, bundle: Path,
            runtime: Path, jdk21: Path, jdk25: Path) -> dict:
    """Create one new stage, package privately, then call the unchanged full API.

    This entry point performs SMT/compiler/JVM work and needs the controller's
    execution lease. Admission and prepare_project do not obtain such a lease.
    """
    A.reauthenticate(policy)
    A.require(policy['schema'] == A.SCHEMA, 'source-only construction authority cannot qualify classes or artifacts')
    project, runtime, jdk21, jdk25 = map(A.absolute, (project, runtime, jdk21, jdk25))
    for name in ('prepared', 'data', 'hkdf', 'cache', 'junit', 'maven', 'maven_repository'):
        A.location(policy, name)
    output = A.output_admission(output, protected_roots(policy, project=project, runtime=runtime, jdk21=jdk21, jdk25=jdk25))
    A.require(project != policy.root, 'qualification requires the new constructed isolated project')
    library, bundle = A.absolute(library), A.absolute(bundle)
    A.require(library != bundle and library.is_relative_to(project) and bundle.is_relative_to(project),
              'private Maven artifacts must be distinct files in the new project')
    retained = check_retained(project, policy)
    hkdf = check_hkdf(project, policy)
    before = project_map(retained, policy)
    A.check_tree(project, before)
    selected_delivery_config(project, policy)
    tools = tool_snapshot(project, policy, runtime, jdk21, jdk25)
    owner = tool_module(project, policy, 'formal/source/hkdf/tooling/owned_call.py', 'epoch_owned_execution')
    helper = tool_module(project, policy, 'formal/source/hkdf/tooling/admission.py', 'epoch_private_environment')
    output.mkdir(mode=0o700)
    (output / 'logs').mkdir()
    owner.durable_json(output / 'INPUTS-BEFORE.json', before)
    owner.durable_json(output / 'TOOLS-BEFORE.json', tools)
    report = {'schema': 'microproxy.hkdf-array-delivery/1', 'status': 'incomplete', 'qualification': False,
              'policy_sha256': policy.expected, 'project': str(project), 'tool_root': str(project),
              'runtime_locations': {k: str(v) for k, v in policy.locations.items()},
              'retained': retained, 'hkdf': hkdf, 'commands': [],
              'scope': 'Retained original native components, current HKDF and finite current whole-artifact checks',
              'outstanding': ['global-V7', 'physical-JVM-timing', 'independent-expert-review']}
    owner.durable_json(output / 'report.json', report)
    env = helper.child_environment(output / 'child')

    def call(label, argv):
        code, text, record = owner.run(argv, output / 'logs' / (label + '.log'), project, env,
                                       policy['delivery']['timeout'])
        row = {'label': label, 'argv': list(map(str, argv)), 'exit': code, **record}
        owner.durable_json(output / 'logs' / (label + '.record.json'), row)
        report['commands'].append(row)
        owner.durable_json(output / 'report.json', report)
        A.require(code == 0, 'owned command failed: ' + label)
        return text

    try:
        seed_child_home(env, policy, retained, tools)
        maven_environment(env, A.location(policy, 'maven'), jdk21)
        stage = output / 'stage'
        call('initial-new-config-stage', [sys.executable, '-I', '-B', project / 'formal/crypto/delivery.py', 'stage',
             '--output', stage, '--cache', Path(env['HOME']) / '.cache/microproxy-formal', '--runtime', runtime,
             '--java-home', jdk21, '--evidence', project / policy['delivery']['native_evidence']['path']])
        check_stage(stage, policy['delivery']['config']['sha256'], jdk21)
        call('private-maven-package', private_maven_command(A.location(policy, 'maven'), Path(env['HOME']), offline=True))
        classes = project / 'quic/target/classes'
        actual = {n: pin for n, pin in A.files(classes).items() if n.endswith('.class')}
        A.require(actual == policy['candidate']['classes'], 'actual whole-library class map differs from selected new subject')
        A.check_delta(policy['predecessor']['classes'], actual, policy['allowed']['classes'])
        subset = hkdf['class_maps']['21']
        A.require(len(subset) == 12 and all(actual.get(n) == pin for n, pin in subset.items()), 'current HKDF12-class JAR subject mismatch')
        check_jar_subset(library, subset)
        check_jar_subset(bundle, subset)
        artifact_before = {name: A.sha(path) for name, path in (('library', library), ('bundle', bundle), ('runtime', runtime))}
        request = {'project': str(project), 'api': policy['delivery']['api'],
                   'delivery_sha256': policy['candidate']['inputs']['formal/crypto/delivery.py'],
                   'stage': str(stage), 'classes': str(classes), 'library': str(library), 'bundle': str(bundle),
                   'runtime': str(runtime), 'jdk21': str(jdk21), 'jdk25': str(jdk25),
                   'output': str(output / 'actual-artifacts'), 'timeout': policy['delivery']['timeout']}
        owner.durable_json(output / 'api-request.json', request)
        runner = output / 'runner'
        runner.mkdir()
        for name in ('run.py', 'admission.py'):
            origin = project / BASE / name
            raw = A.captured(origin)
            A.require(A.digest(raw) == policy['candidate']['inputs'][BASE + name], 'captured worker changed')
            (runner / name).write_bytes(raw)
        call('whole-artifact-api', [sys.executable, '-I', '-B', runner / 'run.py', '_api', '--request', output / 'api-request.json',
                                   '--expected-request-sha256', A.sha(output / 'api-request.json')])
        api = check_artifact_result(project, A.parse_json(A.captured(output / 'actual-artifacts/report.json')))
        A.require(artifact_before == {name: A.sha(path) for name, path in (('library', library), ('bundle', bundle), ('runtime', runtime))},
                  'actual artifact mutated during whole qualification')
        A.require({n: pin for n, pin in A.files(classes).items() if n.endswith('.class')} == actual,
                  'actual whole class tree changed during qualification')
        source_inventory_unchanged(project, before, policy['delivery']['build_outputs'])
        A.require(tool_snapshot(project, policy, runtime, jdk21, jdk25) == tools, 'selected complete tools changed')
        # Recheck both evidence layers; no proof-producing replay is added here.
        check_retained(project, policy)
        check_hkdf(project, policy)
        report.update(status='complete bounded delivery', qualification=False,
                      artifact_API_called=True, artifact_report_sha256=A.sha(output / 'actual-artifacts/report.json'),
                      whole_artifact=api, exact_class_delta=policy['allowed']['classes'],
                      complete_input_maps_match=True, complete_tool_maps_match=True)
    except BaseException as exc:
        report.update(status='failed/incomplete', qualification=False, error=type(exc).__name__ + ': ' + str(exc))
        raise
    finally:
        try:
            maps = project_inventory(A.files(project), before, policy['delivery']['build_outputs'])
            tools_after = tool_snapshot(project, policy, runtime, jdk21, jdk25)
            for name, value in (('PROJECT-TREE-AFTER.json', maps['project']), ('INPUTS-AFTER.json', maps['inputs']),
                                ('BUILD-OUTPUTS-AFTER.json', maps['outputs']), ('TOOLS-AFTER.json', tools_after)):
                owner.durable_json(output / name, value)
            report['maps'] = {name: {'path': name, 'sha256': A.sha(output / name)} for name in
                              ('INPUTS-BEFORE.json', 'INPUTS-AFTER.json', 'PROJECT-TREE-AFTER.json',
                               'BUILD-OUTPUTS-AFTER.json', 'TOOLS-BEFORE.json', 'TOOLS-AFTER.json')}
            report['build_output_policy'] = policy['delivery']['build_outputs']
            A.require(maps['inputs'] == before and tools_after == tools, 'final complete input/tool inventory changed')
        except BaseException as exc:
            report.update(status='failed/incomplete', qualification=False,
                          complete_input_maps_match=False, complete_tool_maps_match=False,
                          final_inventory_error=type(exc).__name__ + ': ' + str(exc))
            raise
        finally:
            owner.durable_json(output / 'report.json', report)
    return report


def api_worker(request_path, expected):
    raw = A.captured(A.absolute(request_path))
    A.require(A.digest(raw) == A.pin(expected), 'artifact worker request changed')
    request = A.parse_json(raw)
    project = A.absolute(request['project'])
    A.load_module('delivery', project / 'formal/crypto/delivery.py', request['delivery_sha256'])
    ref = A.reference(request['api'])
    api = A.load_module('epoch_current_artifact_api', project / ref['path'], ref['sha256'])
    result = api.validate_current_release(project, tool_root=project, stage=Path(request['stage']),
        classes=Path(request['classes']), library=Path(request['library']), bundle=Path(request['bundle']),
        runtime=Path(request['runtime']), java_homes=[Path(request['jdk21']), Path(request['jdk25'])],
        output=Path(request['output']), timeout=request['timeout'])
    check_artifact_result(project, result)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    worker = commands.add_parser('_api')
    worker.add_argument('--request', type=Path, required=True)
    worker.add_argument('--expected-request-sha256', required=True)
    for name in ('admit', 'prepare', 'prepare-source', 'measure', 'qualify'):
        command = commands.add_parser(name)
        command.add_argument('--root', type=Path, required=True)
        command.add_argument('--policy', type=Path, required=True)
        command.add_argument('--expected-policy-sha256', required=True)
        for location in ('prepared', 'data', 'hkdf', 'cache', 'junit', 'maven', 'maven-repository'):
            command.add_argument('--' + location, type=Path)
        if name != 'admit':
            command.add_argument('--output', type=Path, required=True)
        if name in ('qualify', 'measure'):
            for operand in ('project', 'library', 'bundle', 'runtime', 'jdk21', 'jdk25'):
                command.add_argument('--' + operand, type=Path, required=True)
    args = parser.parse_args(argv)
    A.require(sys.flags.isolated and sys.flags.dont_write_bytecode, 'epoch CLI requires Python -I -B')
    if args.mode == '_api':
        return api_worker(args.request, args.expected_request_sha256)
    loader = A.load_source_policy if args.mode in ('prepare-source', 'measure') else A.load_policy
    policy = loader(args.root, args.policy, args.expected_policy_sha256)
    A.bind_runtime(policy, **{n: getattr(args, n) for n in ('prepared', 'data', 'hkdf', 'cache', 'junit', 'maven', 'maven_repository')
                            if getattr(args, n) is not None})
    if args.mode == 'admit':
        result = {'status': 'selected data admitted', 'qualification': False, 'retained': check_retained(args.root, policy),
                  'hkdf': check_hkdf(args.root, policy)}
    elif args.mode in ('prepare', 'prepare-source'):
        result = {'status': 'prepared', 'qualification': False, 'project': str(prepare_project(args.root, policy, args.output))}
    elif args.mode == 'measure':
        result = measure(args.project, policy, args.output, args.library, args.bundle, args.runtime, args.jdk21, args.jdk25)
    else:
        result = qualify(args.project, policy, args.output, args.library, args.bundle, args.runtime, args.jdk21, args.jdk25)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, AssertionError) as exc:
        print('HKDF EPOCH REJECTED: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
