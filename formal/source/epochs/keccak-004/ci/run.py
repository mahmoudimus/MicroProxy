#!/usr/bin/env python3
"""One selected retained-Darwin epoch, plus fresh checkout/class byte identity."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys
import types

SCHEMA = 'microproxy.keccak004-ci-selection/1'
SCOPE = 'retained-Darwin-arm64-plus-current-checkout-identity'
BASE = 'formal/source/epochs/keccak-004/'
PARENT = BASE + 'parent/parent.py'
POLICY = BASE + 'parent/policy.json'
EXTRACTOR = BASE + 'capsule/safeextract.py'
ARCHIVE = BASE + 'capsule/retained-darwin-arm64.tar.gz'
FIXED = {'parent_sha256': '28a891c07dd5f4124343f5d50ac406dd1222d90fa17078e5f45f3ee598d46845',
         'policy_sha256': '8bb7b5d157f46db802ce5bd118c79ef365377f708667580bc0d89c1bf1c317d2',
         'extractor_sha256': '3ef0b190bb255cf50dbf6800395b69d39951e6af9c094f8f79ea26f2be4cf182',
         'capsule_archive_sha256': '13b4ec1c9175179c3eddcc42f919ddc838447d413766e1c7ba21239a750d79f1',
         'capsule_sha256': 'fc8f3d1b90bab8af9d40285237c79be60bf802721299594321d4d7abdb5083a3'}
COMPONENTS = ('poly', 'shake', 'native', 'stage', 'ownership-api', 'select', 'keccak', 'coverage')
HERE = Path(__file__).absolute().parent


def require(test, message):
    if not test:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def captured(path, expected):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts
            and not any(p.is_symlink() for p in (path, *path.parents)), 'unsafe selected file path')
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'selected file alias/special')
    raw = path.read_bytes()
    after = path.stat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, n) == getattr(after, n) for n in fields) and sha(raw) == expected,
            'selected file changed: ' + str(path))
    return raw


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def selection(path, expected):
    value = json.loads(captured(path, expected), object_pairs_hook=unique)
    require(type(value) is dict and set(value) == {'schema', 'scope', *FIXED,
            'retained_index_sha256', 'current_checkout_sha256'}, 'CI selection inventory')
    require(value['schema'] == SCHEMA and value['scope'] == SCOPE
            and all(value[n] == pin for n, pin in FIXED.items()), 'unsupported CI epoch/profile selection')
    for name in ('retained_index_sha256', 'current_checkout_sha256'):
        pin = value[name]
        require(type(pin) is str and len(pin) == 64 and set(pin) <= set('0123456789abcdef'), 'external retained-data authority required')
    return value


def module(name, path, expected):
    raw = captured(path, expected)
    result = types.ModuleType(name)
    result.__file__ = str(path)
    sys.modules[name] = result
    exec(compile(raw, str(path), 'exec', dont_inherit=True), result.__dict__)
    return result


def authorities(args):
    selected = selection(args.selection, args.expected_selection_sha256)
    repository = Path(args.repository)
    p = module('selected_epoch_parent', repository / PARENT, selected['parent_sha256'])
    repository = p.absolute(repository)
    policy = p.read_json(repository / POLICY, selected['policy_sha256'])
    p.validate_policy(policy)
    require(set(policy['evidence']) == set(COMPONENTS), 'all eight current prerequisites are mandatory')
    return p, policy, selected, repository


def prepare(args):
    p, policy, selected, repository = authorities(args)
    out = p.output_admission(args.output, [repository, args.selection.parent, HERE])
    extractor = module('selected_capsule_extractor', repository / EXTRACTOR, selected['extractor_sha256'])
    out.mkdir(mode=0o700)
    extraction = extractor.extract_capsule(repository / ARCHIVE, selected['capsule_archive_sha256'],
                                            selected['capsule_sha256'], out / 'capsule')
    p.admit_capsule(out / 'capsule', selected['capsule_sha256'], policy)
    views = p.construct(policy, repository, out / 'views', out / 'capsule/fixtures', repository)
    receipt = {'schema': 'microproxy.keccak004-ci-prepared/1', 'scope': SCOPE, 'qualification': False,
               'selection_sha256': args.expected_selection_sha256,
               'capsule': str(out / 'capsule'), 'views': str(out / 'views'),
               'historical_root': str(out / 'views/baf-project'), 'epoch_project': str(out / 'views/epoch-project'),
               'views_sha256': sha(p.file_bytes(out / 'views/receipt.json')),
               'view_maps': {'baf': p.map_sha(views['baf_files']), 'epoch': p.map_sha(views['epoch_files'])},
               'input_pins': {PARENT: selected['parent_sha256'], POLICY: selected['policy_sha256'],
                              EXTRACTOR: selected['extractor_sha256'], ARCHIVE: selected['capsule_archive_sha256']},
               'extraction': extraction}
    p.check_pins(repository, receipt['input_pins'])
    selection(args.selection, args.expected_selection_sha256)
    p.write_json(out / 'receipt.json', receipt)
    return {**{n: receipt[n] for n in ('capsule', 'views', 'views_sha256', 'historical_root', 'epoch_project')},
            'prepared_receipt_sha256': sha(p.file_bytes(out / 'receipt.json'))}


def admitted_preparation(p, policy, selected, args):
    root = p.absolute(args.prepared)
    receipt = p.read_json(root / 'receipt.json', args.expected_prepared_sha256)
    require(receipt['schema'] == 'microproxy.keccak004-ci-prepared/1' and receipt['scope'] == SCOPE
            and receipt['qualification'] is False and receipt['selection_sha256'] == args.expected_selection_sha256,
            'stale or unsupported preparation')
    for name, relative in [('capsule', 'capsule'), ('views', 'views'),
                           ('historical_root', 'views/baf-project'), ('epoch_project', 'views/epoch-project')]:
        require(receipt[name] == str(root / relative), 'prepared path substitution')
    p.admit_capsule(root / 'capsule', selected['capsule_sha256'], policy)
    views = p.admit_constructed(policy, root / 'views', receipt['views_sha256'])
    require(receipt['view_maps'] == {'baf': p.map_sha(views['baf_files']), 'epoch': p.map_sha(views['epoch_files'])},
            'prepared map binding changed')
    return receipt


def epoch_checkout(p, repository, policy, prepared):
    source_views = p.parse_json(p.file_bytes(Path(prepared['views']) / 'source-views/receipt.json'))
    p.check_pins(repository, source_views['views']['current']['files'])
    p.check_pins(repository, {**policy['code'], **policy['overlays']})
    p.check_pins(repository, prepared['input_pins'])


def parent_completion(cold, retained):
    require(retained.get('status') == 'selected-current-epoch-validated'
            and retained.get('artifact_API_called') is True
            and retained.get('complete_before_after_maps_match') is True
            and retained.get('policy_sha256') == FIXED['policy_sha256'], 'retained parent qualification incomplete')
    require(cold.get('status') == 'current-prerequisites-validated' and cold.get('artifact_API_called') is False
            and cold.get('complete_before_after_maps_match') is True
            and cold.get('policy_sha256') == FIXED['policy_sha256']
            and type(cold.get('current')) is dict and cold['current']
            and cold['current'] == retained['current'], 'current eight-component replay differs from retained qualification')


def checkout_identity(p, repository, classes, sealed):
    sources, compiled = p.pin_map(sealed['source_files']), p.pin_map(sealed['class_files'])
    require(len(sources) == 467 and len(compiled) == 468 and all(n.endswith('.class') for n in compiled),
            'complete sealed467-input/468-class inventory required')
    p.check_pins(repository, sources)
    for prefix, count in [('quic/src/main/java/', 269), ('quic/src/main/resources/', 3),
                          ('quic/target/test-classes/', None)]:
        wanted = {n[len(prefix):]: h for n, h in sources.items() if n.startswith(prefix)}
        require(wanted and (count is None or len(wanted) == count), 'sealed source inventory changed: ' + prefix)
        p.check_tree(repository / prefix, wanted)
    resources = {n[len('quic/src/main/resources/'):]: h for n, h in sources.items()
                 if n.startswith('quic/src/main/resources/')}
    p.check_tree(classes, {**compiled, **resources})
    return resources


def retained_data(p, policy, selected, data_root, project, capsule, cold):
    index = p.read_json(data_root / 'index.json', selected['retained_index_sha256'])
    require(set(index) == {'schema', 'scope', 'files', 'parent_report', 'api_report', 'delivery_receipt',
                           'bundle_receipt', 'current_checkout'}
            and index['schema'] == 'microproxy.keccak004-retained-qualification/1'
            and index['scope'] == 'retained-Darwin-arm64', 'retained execution scope/index changed')
    pins = p.pin_map(index['files'])
    require('index.json' not in pins, 'retained index cannot authorize itself')
    p.check_tree(data_root, {**pins, 'index.json': selected['retained_index_sha256']})
    reports = {}
    for name in ('parent_report', 'api_report', 'delivery_receipt', 'bundle_receipt', 'current_checkout'):
        relative = p.relative(index[name])
        require(relative in pins, 'unindexed retained report')
        reports[name] = p.read_json(data_root / relative, pins[relative])
    parent, api, delivery, bundle, sealed = (reports[n] for n in
        ('parent_report', 'api_report', 'delivery_receipt', 'bundle_receipt', 'current_checkout'))
    parent_completion(cold, parent)
    require(parent['artifact_report_sha256'] == pins[index['api_report']]
            and api['schema'] == 'microproxy.crypto-current-release-artifact-validation/v1'
            and api['status'] == 'complete' and api['repository_root'] == api['tool_root'], 'retained actual API did not complete')
    require(pins[index['current_checkout']] == selected['current_checkout_sha256']
            and set(sealed) == {'schema', 'source_files', 'class_files', 'parent_report_sha256',
                               'api_report_sha256', 'stage_receipt_sha256'}
            and sealed['schema'] == 'microproxy.keccak004-current-checkout/1'
            and sealed['parent_report_sha256'] == pins[index['parent_report']]
            and sealed['api_report_sha256'] == pins[index['api_report']], 'sealed checkout is not externally selected for this qualification')
    stage_pin = policy['evidence']['stage']['receipt_sha256']
    stage = p.read_json(capsule / 'evidence/stage/receipt.json', stage_pin)
    inputs = api['inputs']
    require(sealed['stage_receipt_sha256'] == inputs['stage_receipt_sha256'] == stage_pin
            and inputs['delivery_manifest_sha256'] == p.CONFIG
            and inputs['runtime_sha256'] == policy['artifact_prerequisites']['runtime_sha256'], 'artifact stage/config/runtime drift')
    require(api['delivery']['receipt_sha256'] == pins[index['delivery_receipt']]
            and api['bundle']['receipt_sha256'] == pins[index['bundle_receipt']], 'API receipt chain changed')
    p.check_pins(project, api['tools'])
    p.captured_module('delivery', project / 'formal/crypto/delivery.py', policy['code']['formal/crypto/delivery.py'])
    validator = p.captured_module('selected_artifact_receipt_rules', project / 'scripts/security/crypto_current_release.py',
                                  policy['code']['scripts/security/crypto_current_release.py'])
    checked_delivery = validator._check_delivery_receipt(delivery, stage_receipt=stage,
        library_sha=inputs['library_sha256'], stage_sha=stage_pin)
    checked_bundle = validator._check_bundle_receipt(bundle, delivery_receipt=delivery,
        library_sha=inputs['library_sha256'], bundle_sha=inputs['bundle_sha256'], runtime_sha=inputs['runtime_sha256'],
        delivery_receipt_sha=pins[index['delivery_receipt']], stage_sha=stage_pin,
        tool_hashes=api['tools'], java_homes={n: Path(h) for n, h in api['java_homes'].items()})
    require(sealed['class_files'] == checked_delivery['classes'], 'sealed468 classes differ from actual qualification')
    require(all(delivery['classes'].get(n) == pin for n, pin in stage['canonical_classes'].items())
            and all(stage['runtime_classmap'].get(n) == pin for n, pin in bundle['runtime_classes'].items()),
            'canonical/runtime class bytes disconnected from selected stage')
    require(bundle['fixture_classes'] == policy['artifact_prerequisites']['fixture_classes']
            and bundle['jdk_inputs'][api['java_homes']['21']] == stage['jdk_files']
            and bundle['jdk_inputs'][api['java_homes']['25']] == policy['artifact_prerequisites']['jdk_files'][1],
            'retained fixture/JDK identity differs from fixed qualification inputs')
    for name in ('class_count', 'generated_class_count', 'handwritten_sources', 'stage_receipt_sha256', 'jar_sha256'):
        require(api['delivery'][name] == checked_delivery[name], 'API delivery summary differs')
    require(all(api['bundle'][n] == v for n, v in checked_bundle.items()), 'API bundle summary differs')
    api_parent, bundle_parent = Path(index['api_report']).parent, Path(index['bundle_receipt']).parent
    require([r['label'] for r in api['commands']] == ['jdk-0-version', 'jdk-1-version', 'delivery-check', 'bundle-check'],
            'retained API command inventory changed')
    require([r['label'] for r in bundle['commands']] == ['version-0', 'version-1', 'compile-harness',
        'jdk21-bundle-smoke', 'jdk25-bundle-smoke', 'compile-nonce-smoke', 'jdk21-nonce-smoke', 'jdk25-nonce-smoke'],
        'retained bundle command inventory changed')
    for row in api['commands']:
        require(type(row['exit']) is int and row['exit'] == 0, 'retained API command failed')
        for stream in ('stdout', 'stderr'):
            name = (api_parent / (row['label'] + '.' + stream + '.log')).as_posix()
            require(pins.get(name) == row[stream + '_sha256'], 'retained API raw log unbound')
    for row in bundle['commands']:
        name = (bundle_parent / (row['label'] + '.log')).as_posix()
        require(type(row['exit']) is int and row['exit'] == 0 and pins.get(name) == row['log_sha256'], 'retained bundle raw log unbound')
    for major in ('21', '25'):
        for suffix, record in [('classload', bundle['runs'][major]), ('nonce-classload', bundle['nonce_smoke']['runs'][major])]:
            require(pins.get((bundle_parent / ('jdk' + major + '-' + suffix + '.log')).as_posix()) == record['classload_sha256'],
                    'retained class-load log unbound')
    return sealed, bundle['resources']


def check(args):
    p, policy, selected, repository = authorities(args)
    prepared = admitted_preparation(p, policy, selected, args)
    data_root, classes = p.absolute(args.retained_data), p.absolute(args.classes)
    epoch_checkout(p, repository, policy, prepared)
    index = p.read_json(data_root / 'index.json', selected['retained_index_sha256'])
    checkout_path = p.relative(index['current_checkout'])
    require(index['files'].get(checkout_path) == selected['current_checkout_sha256'], 'unselected current checkout')
    before = p.read_json(data_root / checkout_path, selected['current_checkout_sha256'])
    checkout_identity(p, repository, classes, before)
    out = p.output_admission(args.output, [repository, args.prepared, data_root, classes, args.selection.parent, HERE])
    out.mkdir(mode=0o700)
    runner = out / 'runner'
    runner.mkdir()
    (runner / 'parent.py').write_bytes(captured(repository / PARENT, selected['parent_sha256']))
    (runner / 'policy.json').write_bytes(captured(repository / POLICY, selected['policy_sha256']))
    env = p.child_environment(out / 'child')
    p.run([sys.executable, '-I', '-B', runner / 'parent.py', 'check', '--policy', runner / 'policy.json',
           '--expected-policy-sha256', selected['policy_sha256'], '--views', prepared['views'],
           '--expected-views-sha256', prepared['views_sha256'], '--capsule', prepared['capsule'],
           '--expected-capsule-sha256', selected['capsule_sha256'], '--output', out / 'cold'],
          cwd=out, env=env, log=out / 'cold-command.log', timeout=1800)
    cold = p.parse_json(p.file_bytes(out / 'cold/report.json'))
    sealed, resources = retained_data(p, policy, selected, data_root, Path(prepared['epoch_project']),
                                      Path(prepared['capsule']), cold)
    require(checkout_identity(p, repository, classes, sealed) == resources, 'fresh resource bytes differ from retained bundle')
    admitted_preparation(p, policy, selected, args)
    p.check_tree(data_root, {**p.read_json(data_root / 'index.json', selected['retained_index_sha256'])['files'],
                             'index.json': selected['retained_index_sha256']})
    selection(args.selection, args.expected_selection_sha256)
    epoch_checkout(p, repository, policy, prepared)
    checkout_identity(p, repository, classes, sealed)
    result = {'schema': 'microproxy.keccak004-ci-result/1', 'status': 'complete', 'scope': SCOPE,
              'qualification': False, 'retained_execution': 'Darwin-arm64', 'fresh_Linux_proof_or_API': False,
              'current_sources': 467, 'fresh_classes': 468, 'selection_sha256': args.expected_selection_sha256,
              'prepared_receipt_sha256': args.expected_prepared_sha256,
              'cold_report_sha256': sha(p.file_bytes(out / 'cold/report.json')), 'outstanding': p.OUTSTANDING}
    p.write_json(out / 'report.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    for name in ('prepare', 'check'):
        mode = modes.add_parser(name)
        for field in ('repository', 'selection', 'output'):
            mode.add_argument('--' + field, type=Path, required=True)
        mode.add_argument('--expected-selection-sha256', required=True)
        if name == 'check':
            for field in ('prepared', 'classes', 'retained-data'):
                mode.add_argument('--' + field, type=Path, required=True)
            mode.add_argument('--expected-prepared-sha256', required=True)
    args = parser.parse_args()
    require(sys.flags.isolated and sys.flags.dont_write_bytecode, 'CI helper requires Python -I -B')
    print(json.dumps(prepare(args) if args.mode == 'prepare' else check(args), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print('CURRENT EPOCH CI REJECTED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
