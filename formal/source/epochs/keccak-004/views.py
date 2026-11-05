#!/usr/bin/env python3
"""Construct authenticated source inventories only; never qualify a theorem."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

SCHEMA = 'microproxy.keccak-source-epoch/1'
RECEIPT_SCHEMA = 'microproxy.keccak-source-views/1'
PREDECESSOR_COMMIT = 'baf0e693c7d4344c7232ea3c3b9d64e1fac03ab3'
PREDECESSOR_TREE = 'c62fced90b167d19bc6bc5a46fb68ba448490abc'
PREDECESSOR_MAP_SHA256 = 'dcae80f69109f9d02e3a47c328082b9270479be0dc19d68286cb553f10630f9a'
CURRENT_MAP_SHA256 = '4cd8e0957af4d15b3620fa4541dbfbeda4b664f9eb2b848f31353548fbacc9fb'
CHANGES = {
    'formal/crypto/NativeKeccak.dfy': 'd1682b1b9f6014d2d8d290841801bd70d4771feaf90581bde6bb0791723d60df',
    'formal/crypto/NativeShake.dfy': '97a25d13a672b46b2e947af1537a6eabbd1ada5d3912c83c0f5a8457e31df816',
    'formal/crypto/native_shake_domain.dfy': '0029621ea31b6edf10c69b62c197f904f0202270e5f6b3f45b789a031622e084',
}
SELECT_ROOT = 'formal/source/select'
LEGACY_VALIDATOR = 'scripts/security/check_select_source.py'
LEGACY_VALIDATOR_SHA = '1f5eada16b4586af16b4caa612f318df507419b199929d448bcfcf4d1e8c3bc7'
HARNESS_TEMPLATE = 'formal/source/keccak/NativeKeccakTraceHarness.dfy.in'
HARNESS_SHA = '39f8f06a75437df0614655b600a75ac4bd443df4872e7514bec07240a1f599b5'
HARNESS_TARGET = 'formal/source/NativeKeccakTraceHarness.dfy'
CONSUMERS = {'ownership': 'formal/source/inputs.json',
             'api': 'assurance/shake-api/inputs.json',
             'polynomial': 'formal/source/polynomial/inputs.json'}
TOOLING = frozenset('formal/source/keccak/' + path for path in (
    'method-checker/KeccakMethodCoverage.cs', 'method-checker/KeccakMethodCoverage.csproj',
    'function-checker/KeccakFunctionCoverage.cs', 'function-checker/KeccakFunctionCoverage.csproj',
    'encoder/NativeCanonicalEncoderPolicy.cs', 'coverage_replay.py',
    'encoder/build_authority.py', 'encoder/net6-targeting-packs.json'))
CHECKERS = {
    'formal/source/keccak/method-checker/KeccakMethodCoverage.cs': 'f106ea52f289062c2110c31981ad916017c0735c25f294c5dc925ea793e1fab3',
    'formal/source/keccak/function-checker/KeccakFunctionCoverage.cs': 'fd2b09dc7ff564b821a18c9ae6ae5b7a1607a4f621ffff196c0cf50a5425b90b',
    'formal/source/keccak/encoder/NativeCanonicalEncoderPolicy.cs': '27115848f259786cd928d9d477fe0b51d84c7fc21efb5f98d83f5182358c0734',
}
SHA = re.compile(r'[0-9a-f]{64}\Z')


class ViewError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ViewError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def map_sha(mapping):
    return digest((json.dumps(mapping, sort_keys=True, separators=(',', ':')) + '\n').encode())


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def load_bytes(raw, label):
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ViewError(label + ': invalid JSON') from error
    require(type(value) is dict, label + ': expected JSON object')
    return value


def keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), label + ': unknown/missing keys')


def relative(name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name
            and all(ord(c) >= 32 for c in name), 'unsafe relative input path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name
            and all(p not in ('', '.', '..') for p in name.split('/')), 'unsafe relative input path: ' + name)
    return name


def pin_map(value, label):
    require(type(value) is dict and value, label + ': empty/invalid hash map')
    for path, pin in value.items():
        relative(path)
        require(isinstance(pin, str) and SHA.fullmatch(pin), label + ': invalid digest: ' + path)
    require(len({n.casefold() for n in value}) == len(value), label + ': case aliases')
    return value


def absolute(path):
    path = Path(path)
    require(path.is_absolute(), 'path must be absolute: ' + str(path))
    require('..' not in path.parts, 'parent traversal is unsupported')
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        require(not cursor.is_symlink(), 'symlink path component: ' + str(cursor))
    return path


def file_bytes(path, identities=None):
    path = absolute(path)
    try:
        before = path.stat(follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                'input must be a regular, unaliased file: ' + str(path))
        identity = (before.st_dev, before.st_ino)
        if identities is not None:
            require(identity not in identities, 'input identity alias: ' + str(path))
            identities.add(identity)
        data = path.read_bytes()
        after = path.stat(follow_symlinks=False)
        require((after.st_dev, after.st_ino, after.st_nlink, after.st_size)
                == (before.st_dev, before.st_ino, 1, len(data)), 'input identity changed: ' + str(path))
        return data, identity
    except OSError as error:
        raise ViewError('missing/unreadable input: ' + str(path)) from error


def file_tree(root):
    root = absolute(root)
    require(root.is_dir(), 'missing input directory: ' + str(root))
    result = {}
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(parent) / name
            require(not path.is_symlink(), 'symlink in input tree: ' + str(path))
        for name in files:
            path = Path(parent) / name
            require(path.is_file(), 'special input file: ' + str(path))
            result[path.relative_to(root).as_posix()] = path
    return result


def production_paths(root):
    return {('formal/' + name): path for name, path in file_tree(root / 'formal').items()
            if name.lower().endswith('.dfy') and not name.startswith('source/select/')}


def directory_ancestry(path):
    """Return physical identities without assuming pathname case semantics."""
    result = []
    for directory in (path, *path.parents):
        try:
            entry = directory.stat(follow_symlinks=False)
        except OSError as error:
            raise ViewError('missing/unreadable directory: ' + str(directory)) from error
        require(stat.S_ISDIR(entry.st_mode), 'not a directory: ' + str(directory))
        result.append((entry.st_dev, entry.st_ino))
    return result


def output_admission(output, protected):
    output = absolute(output)
    require(output.parent.is_dir(), 'output parent must already exist')
    parent_ancestors = set(directory_ancestry(output.parent))
    existing_identity = None
    if os.path.lexists(output):
        entry = output.stat(follow_symlinks=False)
        if stat.S_ISDIR(entry.st_mode):
            existing_identity = (entry.st_dev, entry.st_ino)
    for root in protected:
        root = absolute(root)
        root_ancestors = directory_ancestry(root)
        require(root_ancestors[0] not in parent_ancestors
                and existing_identity not in root_ancestors,
                'output overlaps a protected input: ' + str(root))
    require(not os.path.lexists(output), 'output already exists: ' + str(output))
    return output


def validate_manifest(m):
    keys(m, {'schema', 'epoch', 'qualification', 'scope', 'predecessor', 'current',
             'predecessor_snapshots', 'support_inputs', 'legacy_consumers', 'legacy_select',
             'current_tooling', 'paired_harness'}, 'manifest')
    require(m['schema'] == SCHEMA and m['epoch'] == 'keccak-004'
            and m['qualification'] is False and m['scope'] == 'source-views-only', 'manifest scope/schema')
    keys(m['predecessor'], {'git_commit', 'git_tree', 'sources', 'map_sha256'}, 'predecessor')
    keys(m['current'], {'sources', 'map_sha256'}, 'current')
    require(m['predecessor']['git_commit'] == PREDECESSOR_COMMIT
            and m['predecessor']['git_tree'] == PREDECESSOR_TREE, 'predecessor Git identity')
    old = pin_map(m['predecessor']['sources'], 'predecessor sources')
    new = pin_map(m['current']['sources'], 'current sources')
    require(len(old) == len(new) == 85 and set(old) == set(new), 'exact 85 source inventory required')
    require(map_sha(old) == m['predecessor']['map_sha256'] == PREDECESSOR_MAP_SHA256,
            'predecessor map differs from fixed reviewed epoch')
    require(map_sha(new) == m['current']['map_sha256'] == CURRENT_MAP_SHA256,
            'current map differs from fixed reviewed epoch')
    require({n: new[n] for n in new if new[n] != old[n]} == CHANGES, 'exact three source changes required')
    keys(m['predecessor_snapshots'], CHANGES, 'predecessor snapshots')
    for rel, snapshot in m['predecessor_snapshots'].items():
        keys(snapshot, {'path', 'sha256', 'git_path'}, 'snapshot')
        require(snapshot == {'path': 'predecessor/' + Path(rel).name + '.in',
                             'sha256': old[rel], 'git_path': rel}, 'snapshot origin/path changed')
    support = pin_map(m['support_inputs'], 'support inputs')
    require(not set(support) & set(old), 'support/source domains overlap')
    require(support.get(LEGACY_VALIDATOR) == LEGACY_VALIDATOR_SHA, 'legacy validator identity')
    keys(m['legacy_select'], {'package_root', 'package_files', 'used_inputs', 'validator'}, 'legacy Select')
    legacy = m['legacy_select']
    require(legacy['package_root'] == SELECT_ROOT and legacy['validator'] == LEGACY_VALIDATOR,
            'legacy Select root substitution')
    package = pin_map(legacy['package_files'], 'Select package')
    require(len(package) == 311 and all(n.startswith(SELECT_ROOT + '/') for n in package),
            'exact legacy Select package domain required')
    used = pin_map(legacy['used_inputs'], 'Select used inputs')
    require(len(used) == 8, 'exact Select used-input count required')
    require(all(support.get(n) == h for n, h in package.items()), 'Select/support hash disagreement')
    combined = dict(old, **support)
    require(all(combined.get(n) == h for n, h in used.items()), 'Select used-input disagreement')
    keys(m['legacy_consumers'], CONSUMERS, 'legacy consumers')
    expected_support = set(package) | (set(used) - set(old)) | {LEGACY_VALIDATOR,
        'formal/source/polynomial/SOURCE-EVIDENCE.json', 'formal/source/polynomial-baseline.json'}
    for name, path in CONSUMERS.items():
        item = m['legacy_consumers'][name]
        keys(item, {'manifest', 'inputs'}, 'legacy consumer')
        require(item['manifest'] == path and path in support, 'legacy consumer manifest substitution')
        inputs = pin_map(item['inputs'], 'legacy consumer inputs')
        require(all(combined.get(n) == h for n, h in inputs.items()), 'legacy input domain disagreement')
        expected_support |= {path} | (set(inputs) - set(old))
    require(set(support) == expected_support, 'support domain missing/extra input')
    tooling = pin_map(m['current_tooling'], 'current tooling')
    require(set(tooling) == TOOLING and all(tooling[n] == h for n, h in CHECKERS.items()),
            'current checker/tooling identity')
    keys(m['paired_harness'], {'template', 'sha256', 'stage_target'}, 'paired harness')
    require(m['paired_harness'] == {'template': HARNESS_TEMPLATE, 'sha256': HARNESS_SHA,
                                  'stage_target': HARNESS_TARGET}, 'paired harness identity/stage target')
    domains = [set(new), set(support), set(tooling), {HARNESS_TEMPLATE}]
    require(sum(map(len, domains)) == len(set().union(*domains)), 'copy input domains overlap')
    return old, new, support, tooling


def build_views(*, manifest, expected_manifest_sha256, candidate_root, output):
    require(isinstance(expected_manifest_sha256, str) and SHA.fullmatch(expected_manifest_sha256),
            'mandatory external expected manifest SHA256 is invalid')
    manifest = absolute(manifest)
    candidate_root = absolute(candidate_root)
    require(candidate_root.is_dir(), 'candidate root is missing')
    constructor = absolute(Path(__file__).absolute())
    output = output_admission(output, [candidate_root, manifest.parent, constructor.parent])
    identities = set()
    raw, identity = file_bytes(manifest, identities)
    require(digest(raw) == expected_manifest_sha256, 'manifest differs from external expected digest')
    m = load_bytes(raw, 'manifest')  # Authority checked BEFORE parsing any declared input.
    old, new, support, tooling = validate_manifest(m)
    snapshot_names = {Path(rel).name + '.in' for rel in CHANGES}
    require(set(file_tree(manifest.parent / 'predecessor')) == snapshot_names,
            'predecessor snapshot inventory missing/extra')
    expected = {**new, **support, **tooling, HARNESS_TEMPLATE: HARNESS_SHA}
    require(set(production_paths(candidate_root)) == set(new), 'production source inventory missing/extra')
    actual_package = {SELECT_ROOT + '/' + n for n in file_tree(candidate_root / SELECT_ROOT)}
    require(actual_package == set(m['legacy_select']['package_files']), 'Select package inventory missing/extra')
    data = {}
    protected = {manifest: (expected_manifest_sha256, identity)}
    for rel, wanted in sorted(expected.items()):
        path = candidate_root / relative(rel)
        blob, identity = file_bytes(path, identities)
        require(digest(blob) == wanted, 'current input hash changed: ' + rel)
        data[rel] = blob
        protected[path] = (wanted, identity)
    historical = dict(data)
    for rel, item in m['predecessor_snapshots'].items():
        path = manifest.parent / item['path']
        blob, identity = file_bytes(path, identities)
        require(digest(blob) == old[rel], 'predecessor snapshot hash changed: ' + rel)
        historical[rel] = blob
        protected[path] = (old[rel], identity)
    ctor_bytes, identity = file_bytes(constructor, identities)
    protected[constructor] = (digest(ctor_bytes), identity)
    for item in m['legacy_consumers'].values():
        parsed = load_bytes(data[item['manifest']], 'legacy consumer manifest')
        require(parsed.get('inputs') == item['inputs'], 'legacy manifest complete input map changed')
    output_admission(output, [candidate_root, manifest.parent, constructor.parent])
    output.mkdir(mode=0o700)
    try:
        views = {}
        for name, content, sources in [('current', data, new), ('historical', historical, old)]:
            root = output / name
            root.mkdir(mode=0o700)
            for rel, blob in content.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(blob)
            files = {rel: digest(blob) for rel, blob in content.items()}
            require({n: digest(p.read_bytes()) for n, p in file_tree(root).items()} == files,
                    'constructed view file map changed')
            require({n: digest(p.read_bytes()) for n, p in production_paths(root).items()} == sources,
                    'constructed production source map changed')
            views[name] = {'root': str(root), 'sources': sources, 'source_map_sha256': map_sha(sources),
                           'files': files, 'file_map_sha256': map_sha(files),
                           'source_origins': {rel: {'kind': 'predecessor-snapshot' if name == 'historical' and rel in CHANGES else 'candidate',
                              'path': str(manifest.parent / m['predecessor_snapshots'][rel]['path']) if name == 'historical' and rel in CHANGES else str(candidate_root / rel),
                              'sha256': pin} for rel, pin in sources.items()}}
        # Import only the authenticated, copied, unchanged legacy guard.
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec = importlib.util.spec_from_file_location('epoch004_legacy_select', output / 'historical' / LEGACY_VALIDATOR)
            guard = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(guard)
            facts = guard.validate_current_inputs(output / 'historical')
        finally:
            sys.dont_write_bytecode = previous
        require((facts['dafny_files'], facts['package_files'], facts['used_inputs']) == (85, 311, 8),
                'legacy admission counts changed')
        for path, (wanted, identity) in protected.items():
            blob, after_identity = file_bytes(path)
            require(digest(blob) == wanted and after_identity == identity, 'input changed during construction: ' + str(path))
        require(set(production_paths(candidate_root)) == set(new), 'candidate source inventory changed during construction')
        require({SELECT_ROOT + '/' + n for n in file_tree(candidate_root / SELECT_ROOT)}
                == set(m['legacy_select']['package_files']), 'package inventory changed during construction')
        require(set(file_tree(manifest.parent / 'predecessor')) == snapshot_names,
                'predecessor snapshot inventory changed during construction')
        for item in views.values():
            require({n: digest(p.read_bytes()) for n, p in file_tree(Path(item['root'])).items()} == item['files'],
                    'output view changed during admission')
        result = {'schema': RECEIPT_SCHEMA, 'status': 'complete', 'qualification': False,
                  'scope': 'source-views-only', 'manifest_sha256': expected_manifest_sha256,
                  'constructor_sha256': digest(ctor_bytes), 'candidate_root': str(candidate_root),
                  'output_root': str(output), 'changed_sources': CHANGES,
                  'views': views, 'support_inputs': support, 'current_tooling': tooling,
                  'paired_harness': m['paired_harness'], 'legacy_select': {
                      'validator_sha256': LEGACY_VALIDATOR_SHA, 'dafny_files': 85, 'package_files': 311,
                      'used_inputs': 8, 'profiles': {n: v['sha256'] for n, v in facts['profiles'].items()}},
                  'historical_consumer_scope': 'historical-only; no current-source admission',
                  'inputs_before_after_match': True,
                  'limits': 'Inventory/byte authentication only. No compiler/parser closure, proof, current Select/poly/API, NI, release or physical-timing qualification.'}
        for name in views:
            root = output / name
            for path in root.rglob('*'):
                if path.is_file():
                    path.chmod(0o444)
            for path in sorted(root.rglob('*'), reverse=True):
                if path.is_dir():
                    path.chmod(0o555)
            root.chmod(0o555)
        (output / 'receipt.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        return result
    except Exception as error:
        (output / 'receipt.json').write_text(json.dumps({'schema': RECEIPT_SCHEMA,
            'status': 'failed', 'qualification': False, 'scope': 'source-views-only',
            'error': type(error).__name__ + ': ' + str(error)}, indent=2) + '\n')
        if isinstance(error, ViewError):
            raise
        raise ViewError('source view construction failed: ' + str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--candidate-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_views(manifest=args.manifest, expected_manifest_sha256=args.expected_manifest_sha256,
                             candidate_root=args.candidate_root, output=args.output)
    except (ViewError, OSError) as error:
        print('SOURCE-VIEWS REJECTED: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({'status': result['status'], 'qualification': False, 'scope': result['scope'],
                      'receipt': str(args.output / 'receipt.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
