#!/usr/bin/env python3
"""Explicit Keccak epoch dispatch; old ledger facts remain historical."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import time
import types

SCHEMA = 'microproxy.keccak004-parent-policy/1'
REPORT_SCHEMA = 'microproxy.keccak004-parent-validation/1'
BAF = 'baf0e693c7d4344c7232ea3c3b9d64e1fac03ab3'
TREE = 'c62fced90b167d19bc6bc5a46fb68ba448490abc'
EPOCH = '294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec'
CONFIG = '51cae8d5ca9f8562dbccda60be3a00818e0d996e5da87afcbc641c6f5857f0ca'
SUCCESSOR = '8a4655a0ec7121b24ce52eafdd534c289526f395dd1f9908e26b50ad5c64a2d6'
REPLACEMENTS = {'V4': ['shake'], 'V5/V6': ['native', 'stage', 'artifact'],
                'Select': ['select'], 'ownership/API': ['ownership-api'],
                'Keccak': ['keccak', 'coverage'], 'polynomial': ['poly']}
OUTSTANDING = ['global-V7', 'all-complete', 'JVM-physical-timing', 'independent-external-expert-review',
               'crypto-hardness', 'broader-SHAKE-MLKEM-HKDF-adapter-trace-composition']
CLOSURES = ['checker-controls', 'field', 'field-compatibility', 'observation-vocabulary',
            'paired-harness', 'polynomial', 'source-trace']
SHA = re.compile(r'[0-9a-f]{64}\Z')
BAD = re.compile(r'timed out|out of resource|resource limit|inconclusive|internal error|Unhandled exception|parse errors detected', re.I)
BANNER = "Warning: this way of using the CLI is deprecated. Use 'dafny --help' to see help for the new Dafny CLI format"
HERE = Path(__file__).absolute().parent


class ParentError(ValueError):
    pass


def require(test, message):
    if not test:
        raise ParentError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def map_sha(value):
    return digest((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())


def relative(name):
    require(type(name) is str and name and '\\' not in name and ':' not in name
            and all(ord(c) >= 32 for c in name), 'unsafe relative path')
    p = PurePosixPath(name)
    require(not p.is_absolute() and str(p) == name and not {'.', '..', ''} & set(name.split('/')),
            'unsafe relative path: ' + name)
    return name


def absolute(path):
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts, 'absolute nontraversing path required')
    cursor = Path(p.anchor)
    for part in p.parts[1:]:
        cursor /= part
        require(not cursor.is_symlink(), 'symlink path: ' + str(cursor))
    return p


def file_bytes(path):
    p = absolute(path)
    try:
        before = p.stat(follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular unaliased file required: ' + str(p))
        raw = p.read_bytes()
        after = p.stat(follow_symlinks=False)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, len(raw), after.st_mtime_ns, after.st_ctime_ns)
                and after.st_nlink == 1, 'input changed while capturing: ' + str(p))
        return raw
    except OSError as error:
        raise ParentError('missing/unreadable input: ' + str(p)) from error


def no_duplicates(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, 'duplicate JSON key: ' + k)
        result[k] = v
    return result


def parse_json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ParentError('invalid JSON') from error
    require(type(value) is dict, 'JSON object required')
    return value


def read_json(path, expected):
    require(type(expected) is str and SHA.fullmatch(expected), 'external SHA256 required')
    raw = file_bytes(path)
    require(digest(raw) == expected, 'external input authority mismatch: ' + str(path))
    return parse_json(raw)


def pin_map(pins):
    require(type(pins) is dict and pins, 'nonempty exact pin map required')
    for n, h in pins.items():
        relative(n)
        require(type(h) is str and SHA.fullmatch(h), 'invalid file pin')
    require(len({n.casefold() for n in pins}) == len(pins), 'case aliases in pin map')
    return pins


def files(root):
    root = absolute(root)
    require(root.is_dir(), 'missing input tree: ' + str(root))
    result = {}
    for folder, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            p = Path(folder) / name
            require(not p.is_symlink(), 'symlink in tree: ' + str(p))
        for name in names:
            p = Path(folder) / name
            rel = relative(p.relative_to(root).as_posix())
            result[rel] = digest(file_bytes(p))
    require(len({n.casefold() for n in result}) == len(result), 'tree case aliases')
    return result


def check_tree(root, pins):
    require(files(root) == pin_map(pins), 'missing, extra or changed input tree: ' + str(root))


def check_pins(root, pins):
    for n, h in pin_map(pins).items():
        require(digest(file_bytes(absolute(root) / n)) == h, 'changed pinned input: ' + n)


def output_admission(output, protected):
    p = absolute(output)
    require(p.parent.is_dir() and not os.path.lexists(p), 'fresh output with existing parent required')
    ancestry = {(s.stat().st_dev, s.stat().st_ino) for s in [p.parent, *p.parent.parents]}
    for root in protected:
        r = absolute(root)
        require(r.exists(), 'protected input missing')
        if r.is_file():
            r = r.parent
        require((r.stat().st_dev, r.stat().st_ino) not in ancestry,
                'output overlaps protected input')
        require(not r.is_relative_to(p), 'output contains protected input')
    return p


def write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def captured_module(name, path, expected):
    raw = file_bytes(path)
    require(digest(raw) == expected, 'executable input changed: ' + str(path))
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ''
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


def child_environment(root):
    root = absolute(root)
    root.mkdir(mode=0o700)
    home, temp = root / 'home', root / 'tmp'
    home.mkdir(mode=0o700)
    temp.mkdir(mode=0o700)
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
            'HOME': str(home), 'TMPDIR': str(temp), 'TMP': str(temp), 'TEMP': str(temp),
            'PYTHONDONTWRITEBYTECODE': '1'}


def run(argv, *, cwd, env, log, timeout=900):
    process = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    def cleanup_group():
        # A wrapper may have exited while descendants retain its stdout or keep
        # running with closed stdout. The process group's lifetime is independent
        # of the direct child's poll result.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                return
            if sig == signal.SIGTERM:
                time.sleep(0.1)
    try:
        try:
            raw, _ = process.communicate(timeout=timeout)
        except BaseException:
            cleanup_group()
            raw, _ = process.communicate(timeout=5)
            Path(log).write_bytes(raw)
            raise
    finally:
        cleanup_group()
        process.wait(timeout=5)
    Path(log).write_bytes(raw)
    require(process.returncode == 0, 'child rejected: ' + str(log) + '\n' + raw.decode(errors='replace')[-2000:])
    return {'argv': list(map(str, argv)), 'exit': process.returncode, 'log': Path(log).name,
            'log_sha256': digest(raw), 'environment': env,
            'cleanup': 'TERM/KILL owned process group after every exit, independent of direct-child state'}


def accept_artifact_result(result):
    require(result.get('schema') == 'microproxy.crypto-current-release-artifact-validation/v1'
            and result.get('status') == 'complete', 'fresh artifact API did not complete')


def validate_policy(p):
    require(set(p) == {'schema', 'epoch', 'qualification', 'historical', 'source', 'delivery',
                       'code', 'overlays', 'replacements', 'reuse', 'outstanding', 'evidence',
                       'platform_scope', 'artifact_prerequisites'}, 'parent policy inventory')
    require(p['schema'] == SCHEMA and p['epoch'] == 'keccak-004' and p['qualification'] is False,
            'parent policy schema/scope')
    require(p['historical'] == {'commit': BAF, 'tree': TREE, 'files': 3142, 'status': 'HISTORICAL'},
            'complete Baf Git authority required')
    require(p['source']['manifest_sha256'] == EPOCH and p['source']['source_files'] == 85
            and p['source']['view_files'] == 434, 'current source-view authority')
    require(p['delivery'] == {'manifest_sha256': SUCCESSOR, 'config_sha256': CONFIG,
                             'predecessor_config_sha256': 'e7d1dce38c3d83aa692cc1c89be284b597b5f370903459018e26683ce51fa054'},
            'explicit delivery successor required')
    require(p['replacements'] == REPLACEMENTS, 'mandatory current replacement matrix changed')
    require(p['reuse'] == CLOSURES, 'only seven exact polynomial theorem closures may be reused')
    require(p['outstanding'] == OUTSTANDING, 'unsupported global promotion')
    require(p['platform_scope'] == {'instance': 'retained-Darwin-arm64',
            'cold_validation': 'host-independent-Python-and-Git-byte-validation',
            'fresh_artifact_API': 'Darwin-arm64-only',
            'fresh_proof_instances': 'unsupported-require-separate-external-selection'},
            'platform/fresh-instance scope changed')
    require(set(p['evidence']) == {'poly', 'shake', 'native', 'stage', 'ownership-api', 'select', 'keccak', 'coverage'},
            'mandatory prerequisite omitted')
    pin_map(p['code'])
    pin_map(p['overlays'])
    artifact = p['artifact_prerequisites']
    require(set(artifact) == {'junit', 'fixture_classes', 'runtime_sha256', 'distribution', 'jdk_files', 'official_asset'}
            and len(pin_map(artifact['junit'])) == 4 and len(pin_map(artifact['fixture_classes'])) == 5
            and len(pin_map(artifact['distribution'])) == 285 and len(artifact['jdk_files']) == 2
            and artifact['runtime_sha256'] == 'dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6',
            'explicit artifact fixture/JUnit/runtime/tool authority incomplete')
    for pins in artifact['jdk_files']:
        pin_map(pins)
    for name, e in p['evidence'].items():
        require(set(e) == {'receipt', 'receipt_sha256', 'files', 'checks', 'pair_fields', 'assertions', 'producer_root'},
                'evidence contract inventory: ' + name)
        relative(e['receipt'])
        pin_map(e['files'])
        require(e['files'].get(e['receipt']) == e['receipt_sha256'], 'receipt/file authority disagreement')
        require(type(e['checks']) is list and e['checks'], 'raw evidence rules required')
    return p


def parser_edges(row, text):
    require(row['exit'] == 0 and not BAD.search(text), 'parser failure')
    lines = text.splitlines()
    require(lines and lines.pop(0) == BANNER, 'parser banner changed')
    root = Path(row['cwd'])
    require(root.is_absolute() and '..' not in root.parts, 'invalid recorded parser root')
    found = set()
    for line in lines:
        require(line and line.strip() == line, 'parser output lexical ambiguity')
        for name in line.split(';'):
            p = Path(name)
            require(p.is_absolute() and '..' not in p.parts and p.is_relative_to(root), 'parser include escapes recorded view')
            found.add(relative(p.relative_to(root).as_posix()))
    return found


def replay_parser(rows, texts, pins, entry):
    pending, seen = {entry}, set()
    require(len(rows) == len(texts) and rows, 'parser inventory incomplete')
    for row, text in zip(rows, texts):
        argv = row.get('argv', row.get('command'))
        root = Path(row['cwd'])
        require(argv[1:3] == ['/printIncludes:Immediate', '/noResolve']
                and argv[3:] == [str(root / n) for n in sorted(pending)], 'parser round operands differ')
        found = parser_edges(row, text)
        require(found <= set(pins), 'omitted/unadmitted parser dependency')
        seen.update(pending)
        pending = found - seen
    require(not pending and seen == set(pins), 'recorded parser closure incomplete')
    return seen


def error_locations(text):
    return [{'file': f.replace('\\', '/'), 'line': int(l), 'column': int(c), 'message': m}
            for f, l, c, m in re.findall(r'^(.+\.dfy)\((\d+),(\d+)\): Error: (.+)$', text, re.M)]


def classify_log(rule, status, text):
    if rule['kind'] == 'bytes':
        require(status is None and digest(text.encode()) == rule['sha256'], 'non-command data bytes changed')
        return
    require(type(status) is int and status >= 0 and not BAD.search(text), 'crash/resource failure is not evidence')
    kind = rule['kind']
    if kind == 'proof':
        counts = re.findall(r'^Dafny program verifier finished with (\d+) (assertions )?verified, (\d+) errors?$', text, re.M)
        expected = rule['counts']
        require(len(re.findall(r'^Dafny program verifier finished with .*$', text, re.M)) == 1
                and counts == [(str(expected[0]), rule.get('unit', ''), str(expected[1]))]
                and status == (4 if expected[1] else 0), 'exact proof result changed')
        require(error_locations(text) == rule.get('errors', [])
                and text.count('Error:') == len(rule.get('errors', []))
                and 'Warning:' not in text, 'intended proof diagnostic changed')
    elif kind == 'audit':
        require(status == 0 and re.findall(r'Dafny auditor completed with (\d+) findings?\b', text) == [str(rule['findings'])]
                and text.count('Warning:') == rule['findings'] and 'Error:' not in text,
                'audit findings changed')
        for warning in rule.get('warnings', []):
            require(warning in text, 'intended audit warning missing')
    elif kind == 'parser':
        parser_edges(rule['row'], text)
    elif kind == 'literal':
        require(status == rule['exit'] and digest(text.encode()) == rule['sha256'], 'exact diagnostic output changed')
    else:
        raise ParentError('unknown raw classification rule')


def json_at(value, path):
    for key in path:
        value = value[int(key)] if type(value) is list else value[key]
    return value


def authenticate_evidence(name, root, contract):
    check_pins(root, contract['files'])
    data = read_json(absolute(root) / contract['receipt'], contract['receipt_sha256'])
    for before, after in contract['pair_fields']:
        require(json_at(data, before) == json_at(data, after), name + ': before/after map drift')
    for item in contract['assertions']:
        require(json_at(data, item['path']) == item['value'], name + ': fixed scoped assertion changed')
    for row in contract['checks']:
        text = file_bytes(absolute(root) / relative(row['log'])).decode('utf-8')
        require(digest(text.encode()) == contract['files'][row['log']], 'raw log changed')
        classify_log(row['rule'], row['exit'], text)
    check_pins(root, contract['files'])
    return data


def git_bytes(repository, args):
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C'}
    proc = subprocess.run(['/usr/bin/git', '--no-replace-objects', '-C', str(repository), *args],
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    require(proc.returncode == 0, 'Git authentication failed: ' + proc.stderr.decode(errors='replace')[:500])
    return proc.stdout


def git_inventory(repository, commit=BAF, tree=TREE):
    require(git_bytes(repository, ['rev-parse', commit + '^{tree}']).decode().strip() == tree, 'Git tree identity mismatch')
    result = {}
    for line in git_bytes(repository, ['ls-tree', '-r', '-z', commit]).split(b'\0'):
        if not line:
            continue
        meta, name = line.split(b'\t', 1)
        mode, kind, oid = meta.decode().split()
        name = relative(name.decode('utf-8'))
        require(mode in ('100644', '100755') and kind == 'blob', 'Git special/submodule entry unsupported')
        result[name] = {'mode': mode, 'git_blob': oid}
    require(len({n.casefold() for n in result}) == len(result), 'Git inventory case aliases')
    return result


def git_tree_identity(inventory):
    """Recompute the complete Git tree without trusting receipt tree labels."""
    tree = {}
    for name, row in inventory.items():
        parts = relative(name).split('/')
        cursor = tree
        for part in parts[:-1]:
            require(part not in cursor or type(cursor[part]) is dict, 'Git file/directory alias')
            cursor = cursor.setdefault(part, {})
        require(parts[-1] not in cursor and row['mode'] in ('100644', '100755')
                and re.fullmatch('[0-9a-f]{40}', row['git_blob']), 'Git leaf identity')
        cursor[parts[-1]] = (row['mode'], row['git_blob'])
    def encode(node):
        entries = []
        for name, value in node.items():
            directory = type(value) is dict
            mode, oid = ('40000', encode(value)) if directory else value
            entries.append(((name + ('/' if directory else '')).encode('utf-8'),
                            mode.encode() + b' ' + name.encode('utf-8') + b'\0' + bytes.fromhex(oid)))
        raw = b''.join(row for _, row in sorted(entries))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return encode(tree)


def construct(policy, repository, output, fixture_root, selected_root):
    """Create a complete Git Baf project, current434 views, and full delivery project."""
    validate_policy(policy)
    repository = absolute(repository)
    selected_root = absolute(selected_root)
    check_pins(selected_root, policy['code'])
    check_pins(selected_root, policy['overlays'])
    inventory = git_inventory(repository)
    require(len(inventory) == policy['historical']['files'], 'complete Git inventory required')
    output = output_admission(output, [repository, selected_root, fixture_root, HERE])
    output.mkdir(mode=0o700)
    baf = output / 'baf-project'
    epoch = output / 'epoch-project'
    baf.mkdir(mode=0o700)
    epoch.mkdir(mode=0o700)
    # Archive extraction is deliberately not used. Each admitted Git blob is
    # captured, independently checked against its object ID, then written safely.
    import io
    payload = b''.join((v['git_blob'] + '\n').encode() for v in inventory.values())
    proc = subprocess.run(['/usr/bin/git', '--no-replace-objects', '-C', str(repository), 'cat-file', '--batch'],
                          input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1',
                               'GIT_CONFIG_GLOBAL': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C'}, timeout=180)
    require(proc.returncode == 0, 'Git blob capture failed')
    stream = io.BytesIO(proc.stdout)
    for name, entry in inventory.items():
        oid, kind, size = stream.readline().decode().strip().split()
        raw = stream.read(int(size))
        require(stream.read(1) == b'\n' and oid == entry['git_blob'] and kind == 'blob'
                and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == oid,
                'Git blob identity mismatch')
        entry['sha256'] = digest(raw)
        for root in (baf, epoch):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o755 if entry['mode'] == '100755' else 0o644)
    require(not stream.read(), 'unexpected Git batch output')
    epoch_manifest = read_json(selected_root / 'formal/source/epochs/keccak-004/manifest.json', EPOCH)
    ctor_rel = 'formal/source/epochs/keccak-004/views.py'
    view = captured_module('parent_current_source_constructor', selected_root / ctor_rel, policy['code'][ctor_rel])
    old, new, support, tooling = view.validate_manifest(epoch_manifest)
    expected434 = {**new, **support, **tooling, view.HARNESS_TEMPLATE: view.HARNESS_SHA}
    require(len(new) == 85 and len(expected434) == 434, 'current source/support inventory changed')
    # The full epoch is Baf plus a closed, explicitly selected overlay. New epoch
    # validators are copied physically; executable helpers keep their real paths.
    overlays = {**policy['code'], **policy['overlays']}
    for name, pin in overlays.items():
        raw = file_bytes(selected_root / name)
        require(digest(raw) == pin, 'epoch overlay changed: ' + name)
        target = epoch / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    config = epoch / 'formal/crypto/delivery.json'
    config.write_bytes(file_bytes(selected_root / 'formal/crypto/epochs/keccak-004/delivery/delivery.json'))
    require(digest(file_bytes(config)) == CONFIG, 'canonical successor configuration mismatch')
    check_pins(epoch, expected434)
    view.build_views(manifest=epoch / 'formal/source/epochs/keccak-004/manifest.json',
                     expected_manifest_sha256=EPOCH, candidate_root=epoch, output=output / 'source-views')
    # These five explicit finite-test inputs are not part of the Git Baf view.
    # They are included only in the complete current artifact project.
    fixtures = policy['artifact_prerequisites']['fixture_classes']
    check_pins(fixture_root, fixtures)
    for name in fixtures:
        target = epoch / 'quic/target/test-classes' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_bytes(absolute(fixture_root) / name))
    baf_map = {n: v['sha256'] for n, v in inventory.items()}
    check_tree(baf, baf_map)
    epoch_map = files(epoch)
    require(git_inventory(repository) == {n: {k: v[k] for k in ('mode', 'git_blob')} for n, v in inventory.items()},
            'Git inventory drift')
    check_pins(selected_root, policy['code'])
    check_pins(selected_root, policy['overlays'])
    receipt = {'schema': 'microproxy.keccak004-parent-views/1', 'qualification': False,
               'scope': 'authenticated-three-view-inventory-only', 'historical_status': 'HISTORICAL',
               'git_commit': BAF, 'git_tree': TREE, 'git_inventory': inventory,
               'baf_files': baf_map, 'epoch_files': epoch_map,
               'source_views_receipt_sha256': digest(file_bytes(output / 'source-views/receipt.json')),
               'policy_sha256': map_sha(policy), 'before_after_match': True}
    write_json(output / 'receipt.json', receipt)
    return receipt


def frozen_text(root, row, stream=None, contract=None):
    # Absolute producer locations are metadata. Only explicitly recorded relative
    # names selected in policy are opened under the captured evidence directory.
    if stream:
        require(contract is not None, 'explicit recorded producer-root authority required')
        producer = Path(contract['producer_root'])
        require(producer.is_absolute() and '..' not in producer.parts, 'unsafe recorded producer root')
        name = relative(Path(row[stream]).relative_to(producer).as_posix())
        require(digest(file_bytes(root / name)) == row[stream + '_sha256'], 'relocated stream hash mismatch')
    else:
        name = row.get('log', row['label'] + '.log')
        relative(name)
    return file_bytes(root / name).decode('utf-8')


def current_components(policy, project, views, roots):
    require(set(roots) == set(policy['evidence']), 'exact explicit evidence root inventory required')
    checked = {n: authenticate_evidence(n, absolute(roots[n]), c) for n, c in policy['evidence'].items()}
    epoch_path = project / 'formal/source/epochs/keccak-004'
    manifest = read_json(epoch_path / 'manifest.json', EPOCH)
    current = manifest['current']['sources']
    helper = captured_module('delivery', project / 'formal/crypto/delivery.py', policy['code']['formal/crypto/delivery.py'])
    config = read_json(project / 'formal/crypto/delivery.json', CONFIG)
    helper.check_native_contract(config['native_evidence'])
    # The unchanged exact full native evidence contract is evaluated, not a pass
    # dictionary constructed for the old ledger.
    native = checked['native']
    stage = checked['stage']
    helper.validate_native_evidence(native, roots['native'], stage['sources'], stage['native_replay_inputs'],
                                    config['native_evidence'], config['runtime']['sha256'])
    require(stage['manifest_sha256'] == CONFIG and len(stage['sources']) == 20
            and set(stage['proofs']) == set(stage['sources']) and sum(stage['proofs'].values()) == 9834
            and stage['source_transforms'] == [] and len(stage['canonical_classes']) == 66,
            'full current canonical stage coverage changed')
    for name, pin in stage['sources'].items():
        require(current.get(name) == pin, 'canonical stage is not the current source epoch')
    check_tree(roots['stage'] / 'inputs', stage['inputs'])
    check_tree(roots['stage'] / 'classes', stage['canonical_classes'])
    check_tree(roots['stage'] / 'sources', stage['delivered_sources'])
    check_pins(project, {'quic/src/main/java/' + name: pin for name, pin in stage['delivered_sources'].items()})
    # Reconstruct both recorded parser closures without opening producer paths.
    for prefix in ('frozen', 'current'):
        rows = [r for r in stage['commands'] if r['label'].startswith(prefix + '-dependencies-')]
        for row in rows:
            row['cwd'] = str(Path(row['argv'][3]).parents[2])
        replay_parser(rows, [frozen_text(roots['stage'], r) for r in rows], stage['sources'], stage['entry'])
    # Each complete frozen source is compared with the full selected project.
    check_pins(project, stage['inputs'])
    shake = checked['shake']
    shake_inputs = read_json(project / 'formal/crypto/epochs/keccak-004/shake/inputs.json',
                            policy['code']['formal/crypto/epochs/keccak-004/shake/inputs.json'])
    require(shake['source_map_before'] == current and len(shake['proofs']) == len(shake['audits']) == 8
            and set(shake['proofs']) == set(shake_inputs['closure'])
            and set(shake['controls']) == {r['name'] for r in shake_inputs['controls']}
            and len(shake['controls']) == 22 and [r['major'] for r in shake['java']] == [21, 25],
            'complete current SHAKE functional inventory required')
    check_pins(project, shake['frozen_inputs_before'])
    own = checked['ownership-api']
    own_authority = read_json(epoch_path / 'ownership-api/inputs-v2.json',
                             policy['code']['formal/source/epochs/keccak-004/ownership-api/inputs-v2.json'])
    require(own['execution_policy'] == 'raw-source-isolated-child/v2' and own['view_before'] ==
            files(views / 'current'), 'ownership/API current434 view mismatch')
    for kind, spec in own_authority['consumers'].items():
        require(own['consumers'][kind]['source_graph'] == spec['sources']
                and own['inputs_before'][kind] == spec['inputs'], 'ownership/API source/input closure changed')
        check_pins(project, spec['inputs'])
    # Reuse the reviewed raw Select checker, proof, CSV and parser classifier.
    rel = 'formal/source/epochs/keccak-004/select_replay.py'
    select = captured_module('parent_current_select', project / rel, policy['code'][rel])
    sroot = roots['select'] / 'run-004'
    fragment = read_json(sroot / 'semantics.json', checked['select']['semantics_sha256'])
    spolicy = select.load_expectations(epoch_path / 'select-current/expectations.json',
                                      checked['select']['expectations_sha256'])
    legacy_select = captured_module('parent_select_package_helper', project / 'formal/source/select/replay.py',
                                   manifest['support_inputs']['formal/source/select/replay.py'])
    package = parse_json(file_bytes(project / 'formal/source/select/package.json'))
    require(checked['select']['current85'] == current, 'Select source epoch mismatch')
    result = select.check_semantic_evidence(fragment, sroot, spolicy, legacy_select, package, manifest)
    require(result == checked['select']['evidence'], 'current Select reclassification differs')
    # Keccak body/assumption/observation controls use their original captured classifier.
    rel = 'formal/source/epochs/keccak-004/keccak/replay.py'
    keccak = captured_module('parent_current_keccak', project / rel, policy['code'][rel])
    kp = read_json(epoch_path / 'keccak/inputs.json', policy['code']['formal/source/epochs/keccak-004/keccak/inputs.json'])
    body = checked['keccak']
    require(body['source_map'] == current and len(body['commands']) == 44
            and len(kp['tasks']) == 44, 'full current Keccak task/source inventory changed')
    require([r['label'] for r in body['commands']] == [r['label'] for r in kp['tasks']], 'Keccak task order changed')
    for row, task in zip(body['commands'], kp['tasks']):
        require(row['rule'] == task['rule'], 'Keccak independently selected rule differs')
        text = frozen_text(roots['keccak'], row, 'stdout', policy['evidence']['keccak']) + frozen_text(roots['keccak'], row, 'stderr', policy['evidence']['keccak'])
        require(keccak.classify(task['rule'], row['exit'], text) == row['classification'], 'Keccak classification changed')
    require(body['counts']['private_address_tasks'] == 15 and body['counts']['private_branch_tasks'] == 6
            and body['counts']['body_roots'] == 9 and body['counts']['clean_audits'] == 9,
            'Keccak full15-root observation/body coverage required')
    coverage = checked['coverage']
    require(coverage['source_map'] == body['coverage_before']['source_map']
            and coverage['package_map'] == kp['coverage_package_map']
            and coverage['counts'] == body['coverage_before']['counts'], 'coverage prerequisite disconnected')
    for gate, total in [('method', 61), ('function', 18)]:
        rows = coverage['cases'][gate]
        require(len(rows) == total and {r['name'] for r in rows} == set(kp['coverage_case_diagnostics'][gate]),
                'coverage case inventory mismatch')
        for case in rows:
            plain, plugin = case['commands']
            text = frozen_text(roots['coverage'], plain, 'stdout', policy['evidence']['coverage']) + frozen_text(roots['coverage'], plain, 'stderr', policy['evidence']['coverage'])
            keccak.classify({'kind': 'resolve'}, plain['exit'], text)
            text = frozen_text(roots['coverage'], plugin, 'stdout', policy['evidence']['coverage']) + frozen_text(roots['coverage'], plugin, 'stderr', policy['evidence']['coverage'])
            require(not BAD.search(text) and case['inputs_unchanged'] is True, 'coverage case inconclusive')
            diagnostics = re.findall(r'^.*: Error: .+$', text, re.M)
            require(diagnostics == kp['coverage_case_diagnostics'][gate][case['name']], 'coverage intended rejection changed')
            if case['expected_error'] is None:
                keccak.classify({'kind': gate}, plugin['exit'], text)
            else:
                require(plugin['exit'] == 2 and diagnostics and text.count('Error:') == len(diagnostics)
                        and all(case['expected_error'] in x for x in diagnostics), 'coverage negative did not reject as intended')
    combined = coverage['combined']['command']
    keccak.classify({'kind': 'combined'}, combined['exit'],
                   frozen_text(roots['coverage'], combined, 'stdout', policy['evidence']['coverage']) + frozen_text(roots['coverage'], combined, 'stderr', policy['evidence']['coverage']))
    # Polynomial theorem reuse is EXACT parser-closure identity, not old whole
    # package/MLKEM composition/erasure linkage. Recheck each of the50 parser calls.
    poly = checked['poly']
    require(sorted(poly['closures']) == CLOSURES and len(poly['commands']) == 50,
            'only seven unchanged polynomial closures may be reused')
    for name, row in poly['closures'].items():
        for source, pin in row['sources'].items():
            require(manifest['predecessor']['sources'].get(source, manifest['support_inputs'].get(source)) == pin
                    and current.get(source, manifest['support_inputs'].get(source)) == pin,
                    'reused polynomial closure changed')
        for view in ('historical', 'current'):
            rows = [r for r in poly['commands'] if r['proof'] == name and r['view'] == view]
            replay_parser(rows, [frozen_text(roots['poly'], r) for r in rows], row['sources'], row['target'])
        baf = views.parent / 'baf-project'
        historical = read_json(baf / 'formal/source/polynomial/SOURCE-EVIDENCE.json',
                               poly['historical_receipt_sha256'])
        proofs = [r for r in historical['proofs'] if r['label'] == name]
        require(len(proofs) == 1, 'historical polynomial theorem identity missing')
        proof = proofs[0]
        require(proof['target'] == row['target'] and proof['flags'] == row['proof_flags']
                and proof['verified'] == row['historical_proof_verified']
                and proof['log_sha256'] == row['proof_log_sha256'] and proof['exit'] == 0,
                'polynomial theorem reuse is not bound to its actual original proof')
        log = baf / 'formal/crypto/evidence/2026-11-04-poly/source/logs' / Path(proof['log']).name
        text = file_bytes(log).decode('utf-8')
        require(digest(text.encode()) == row['proof_log_sha256'], 'historical polynomial raw proof changed')
        classify_log({'kind': 'proof', 'counts': [row['historical_proof_verified'], 0]}, 0, text)
    changed = poly['changed_composition_not_reused']
    require(changed['current_proof_required'] is True and changed['changed_sources'] ==
            ['formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeShake.dfy'], 'old composition reuse is forbidden')
    for view in ('historical', 'current'):
        rows = [r for r in poly['commands'] if r['proof'] == 'mlkem-composition' and r['view'] == view]
        replay_parser(rows, [frozen_text(roots['poly'], r) for r in rows], changed[view], changed['target'])
    return {'current_source_files': 85, 'current_view_files': 434,
            'shake_roots': 8, 'shake_controls': 22, 'supported_JDKs': [21, 25],
            'native_commands': 34, 'native_controls': 11, 'bytecode_controls': 3,
            'canonical_stage_roots': 20, 'canonical_overlapping_checks': 9834,
            'canonical_classes': 66, 'select': result, 'keccak_tasks': 44,
            'keccak_observation_roots': 15, 'coverage_cases': 79,
            'poly_unchanged_closures': CLOSURES, 'poly_parser_commands': 50,
            'historical_MLKEM_composition_reused': False, 'historical_erasure_package_linkage_reused': False}


def explicit_roots(pairs, policy):
    roots = {n: absolute(path) for n, path in pairs}
    require(len(pairs) == len(roots) and set(roots) == set(policy['evidence']),
            'missing/duplicate explicit evidence roots')
    identities = []
    for name, root in roots.items():
        require(root.is_dir(), 'missing evidence root: ' + name)
        identity = root.stat().st_dev, root.stat().st_ino
        require(identity not in identities, 'evidence directory identity alias')
        identities.append(identity)
    for a in roots:
        for b in roots:
            require(a == b or not roots[a].is_relative_to(roots[b]), 'evidence roots overlap')
    return roots


def pack(policy, selected_root, fixture_root, pairs, output):
    roots = explicit_roots(pairs, policy)
    selected_root, fixture_root = absolute(selected_root), absolute(fixture_root)
    out = output_admission(output, [selected_root, fixture_root, HERE, *roots.values()])
    selected = {**policy['code'], **policy['overlays']}
    check_pins(selected_root, selected)
    check_pins(fixture_root, policy['artifact_prerequisites']['fixture_classes'])
    out.mkdir(mode=0o700)
    domains = {'project-inputs': (selected_root, selected),
               'fixtures': (fixture_root, policy['artifact_prerequisites']['fixture_classes'])}
    domains.update({'evidence/' + n: (roots[n], c['files']) for n, c in policy['evidence'].items()})
    for folder, (root, pins) in domains.items():
        check_pins(root, pins)
        for name, pin in pins.items():
            raw = file_bytes(root / name)
            require(digest(raw) == pin, 'pack input changed during capture')
            target = out / folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        check_tree(out / folder, pins)
        check_pins(root, pins)
    root_map = {n: {'producer_root_metadata': c['producer_root'], 'capsule_root': 'evidence/' + n}
                for n, c in policy['evidence'].items()}
    write_json(out / 'root-map.json', root_map)
    write_json(out / 'capsule.json', {'schema': 'microproxy.keccak004-retained-capsule/1',
               'qualification': False, 'scope': 'retained-Darwin-arm64-cold-evidence-only',
               'policy_map_sha256': map_sha(policy), 'root_map': root_map, 'files': files(out)})
    return {'status': 'packed', 'capsule_sha256': digest(file_bytes(out / 'capsule.json'))}


def admit_capsule(path, expected, policy):
    root = absolute(path)
    capsule = read_json(root / 'capsule.json', expected)
    require(set(capsule) == {'schema', 'qualification', 'scope', 'policy_map_sha256', 'root_map', 'files'}
            and capsule['schema'] == 'microproxy.keccak004-retained-capsule/1'
            and capsule['qualification'] is False and capsule['scope'] == 'retained-Darwin-arm64-cold-evidence-only'
            and capsule['policy_map_sha256'] == map_sha(policy), 'capsule authority/scope mismatch')
    expected_roots = {n: {'producer_root_metadata': c['producer_root'], 'capsule_root': 'evidence/' + n}
                      for n, c in policy['evidence'].items()}
    require(capsule['root_map'] == expected_roots, 'explicit root relocation map changed')
    require('capsule.json' not in capsule['files'], 'capsule index cannot hash itself')
    require(parse_json(file_bytes(root / 'root-map.json')) == expected_roots, 'root-map file differs')
    check_tree(root, {**capsule['files'], 'capsule.json': expected})
    check_tree(root / 'project-inputs', {**policy['code'], **policy['overlays']})
    check_tree(root / 'fixtures', policy['artifact_prerequisites']['fixture_classes'])
    for name, c in policy['evidence'].items():
        check_tree(root / 'evidence' / name, c['files'])
    return {n: root / value['capsule_root'] for n, value in expected_roots.items()}


def check_artifact_jdks(homes, policy, authenticated_stage, helper):
    """Keep the selected stage's full JDK21 link identities, including targets."""
    flat = policy['artifact_prerequisites']['jdk_files']
    stage21 = authenticated_stage['jdk_files']
    require(type(stage21) is dict and set(stage21) == set(flat[0]), 'stage JDK21 byte pins differ from fixed policy')
    byte_pins = {}
    for name, value in stage21.items():
        if type(value) is dict:
            require(set(value) == {'link', 'target', 'sha256'}
                    and all(type(v) is str for v in value.values()), 'invalid selected stage JDK21 link record')
            byte_pins[name] = value['sha256']
        else:
            byte_pins[name] = value
    require(byte_pins == flat[0], 'stage JDK21 byte pins differ from fixed policy')
    expected = [stage21, flat[1]]
    require(len(homes) == 2 and len(set(map(str, homes))) == 2, 'both explicit JDKs required')
    for home, pins in zip(homes, expected):
        require(helper.tool_tree(absolute(home)) == pins, 'explicit JDK input map changed')
    return expected


def prepare_artifact_inputs(request, policy, project, helper, authenticated_stage):
    """No implicit ~/.m2 or compiler cache fallback may reach the artifact API."""
    import platform
    require(platform.system() + '-' + platform.machine() == 'Darwin-arm64', 'fresh artifact profile is Darwin-arm64 only')
    require(set(request) == {'stage', 'classes', 'library', 'bundle', 'runtime', 'java_homes',
                            'junit_root', 'dafny_cache'}, 'artifact request inventory')
    spec = policy['artifact_prerequisites']
    runtime = absolute(request['runtime'])
    require(digest(file_bytes(runtime)) == spec['runtime_sha256'], 'explicit runtime changed')
    fixture_root = project / 'quic/target/test-classes'
    check_tree(fixture_root, spec['fixture_classes'])
    junit_root = absolute(request['junit_root'])
    check_pins(junit_root, spec['junit'])
    cache = absolute(request['dafny_cache'])
    asset = spec['official_asset']
    check_tree(cache / asset['directory'], spec['distribution'])
    require(digest(file_bytes(cache / asset['archive'])) == asset['sha256'], 'official archive pin mismatch')
    jdk_authorities = check_artifact_jdks(request['java_homes'], policy, authenticated_stage, helper)
    # The unchanged CLI defaults are confined to this fresh, private worker HOME.
    home = absolute(os.environ['HOME'])
    require(not (home / '.m2').exists() and not (home / '.cache').exists(), 'private tool/JUnit state is not fresh')
    for name, pin in spec['junit'].items():
        target = home / '.m2/repository' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_bytes(junit_root / name))
    for name, pin in {asset['directory'] + '/' + n: h for n, h in spec['distribution'].items()}.items():
        origin = cache / name
        target = home / '.cache/microproxy-formal' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_bytes(origin))
        target.chmod(origin.stat().st_mode & 0o777)
    target = home / '.cache/microproxy-formal' / asset['archive']
    target.write_bytes(file_bytes(cache / asset['archive']))
    check_tree(home / '.m2/repository', spec['junit'])
    check_tree(home / '.cache/microproxy-formal',
               {**{asset['directory'] + '/' + n: h for n, h in spec['distribution'].items()},
                asset['archive']: asset['sha256']})
    return {'junit': spec['junit'], 'fixture_classes': spec['fixture_classes'],
            'official_distribution': map_sha(spec['distribution']), 'official_archive': asset['sha256'],
            'runtime_sha256': spec['runtime_sha256'], 'JDKs': [map_sha(n) for n in jdk_authorities]}


def restrict_worker_opens(roots):
    """Deny undeclared Python file opens; recorded producer paths grant no access.

    Python/stdlib and native extension loading remain host trust boundaries.
    Cold validation launches no tool subprocesses. The fresh artifact API's
    subprocess/tool trust is reported separately.
    """
    allowed = set(absolute(p) for p in roots)
    allowed.update(Path(p).resolve() for p in (sys.base_prefix, sys.base_exec_prefix))
    observed = set()
    def audit(event, args):
        if event != 'open' or type(args[0]) is int:
            return
        path = Path(os.fsdecode(args[0]))
        path = Path(os.path.abspath(path))
        require(path == Path('/dev/null') or any(path == r or path.is_relative_to(r) for r in allowed),
                'undeclared file open denied: ' + str(path))
        observed.add(str(path))
    sys.addaudithook(audit)
    return allowed, observed


def admit_constructed(policy, views, expected):
    receipt = read_json(views / 'receipt.json', expected)
    require(receipt['schema'] == 'microproxy.keccak004-parent-views/1'
            and receipt['policy_sha256'] == map_sha(policy) and receipt['git_commit'] == BAF
            and receipt['git_tree'] == TREE and receipt['historical_status'] == 'HISTORICAL'
            and len(receipt['git_inventory']) == len(receipt['baf_files']) == 3142,
            'constructed complete Baf/source/epoch authority changed')
    require({n: row['sha256'] for n, row in receipt['git_inventory'].items()} == receipt['baf_files'],
            'Git/view inventory disagreement')
    require(git_tree_identity(receipt['git_inventory']) == TREE, 'complete Baf Git tree authentication failed')
    check_tree(views / 'baf-project', receipt['baf_files'])
    for name, row in receipt['git_inventory'].items():
        path = views / 'baf-project' / name
        raw = file_bytes(path)
        require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob']
                and bool(path.stat().st_mode & 0o111) == (row['mode'] == '100755'),
                'Baf Git blob/mode mismatch: ' + name)
    expected_epoch = derive_epoch_map(policy, receipt['baf_files'])
    require(receipt['epoch_files'] == expected_epoch,
            'epoch map must equal authenticated full Baf plus only the selected overlay/config/fixtures')
    check_tree(views / 'epoch-project', receipt['epoch_files'])
    source_views = read_json(views / 'source-views/receipt.json', receipt['source_views_receipt_sha256'])
    epoch = views / 'epoch-project'
    manifest = read_json(epoch / 'formal/source/epochs/keccak-004/manifest.json', EPOCH)
    rel = 'formal/source/epochs/keccak-004/views.py'
    constructor = captured_module('parent_admission_source_policy', epoch / rel, policy['code'][rel])
    old, new, support, tooling = constructor.validate_manifest(manifest)
    common = {**support, **tooling, constructor.HARNESS_TEMPLATE: constructor.HARNESS_SHA}
    require(source_views['manifest_sha256'] == EPOCH
            and source_views['constructor_sha256'] == policy['code'][rel], 'source434 independent authority changed')
    for name in ('historical', 'current'):
        sources = old if name == 'historical' else new
        expected_files = {**sources, **common}
        require(len(expected_files) == 434 and source_views['views'][name]['files'] == expected_files
                and source_views['views'][name]['sources'] == sources,
                'source434 map must derive from independently selected epoch manifest')
        check_tree(views / 'source-views' / name, expected_files)
    return receipt


def derive_epoch_map(policy, baf_map):
    result = {**baf_map, **policy['code'], **policy['overlays']}
    result['formal/crypto/delivery.json'] = CONFIG
    result.update({'quic/target/test-classes/' + n: pin
                   for n, pin in policy['artifact_prerequisites']['fixture_classes'].items()})
    return result


def worker(request, expected):
    require(sys.flags.isolated and sys.flags.dont_write_bytecode, 'worker requires Python -I -B')
    args = read_json(request, expected)
    require(digest(file_bytes(Path(__file__).absolute())) == args['runner_sha256'], 'captured dispatcher changed')
    policy = read_json(absolute(args['policy']), args['policy_sha256'])
    validate_policy(policy)
    views = absolute(args['views'])
    allowed, opened = restrict_worker_opens([views, absolute(args['output'])])
    before = admit_constructed(policy, views, args['views_sha256'])
    project, baf = views / 'epoch-project', views / 'baf-project'
    ledger = baf / 'formal/crypto-obligations.json'
    require(ledger.is_relative_to(baf), 'ledger must be inside full Baf view')
    captured_module('check_select_source', baf / 'scripts/security/check_select_source.py',
                    before['baf_files']['scripts/security/check_select_source.py'])
    legacy = captured_module('parent_historical_ledger', baf / 'scripts/security/check_crypto_obligations.py',
                             before['baf_files']['scripts/security/check_crypto_obligations.py'])
    historical = legacy.validate_ledger(baf, ledger)
    # Never pass this legacy result to a current release API or rename its flags.
    write_json(absolute(args['output']) / 'HISTORICAL-ledger.json',
               {'status': 'HISTORICAL', 'git_commit': BAF, 'git_tree': TREE, 'result': historical})
    roots = {n: absolute(p) for n, p in args['evidence'].items()}
    current = current_components(policy, project, views / 'source-views', roots)
    report = {'schema': REPORT_SCHEMA, 'status': 'current-prerequisites-validated', 'qualification': False,
              'scope': 'Selected source epoch component evidence and full canonical delivery prerequisites only',
              'historical': {'status': 'HISTORICAL', 'commit': BAF, 'tree': TREE},
              'current': current, 'policy_sha256': args['policy_sha256'], 'views_sha256': args['views_sha256'],
              'outstanding': OUTSTANDING, 'artifact_API_called': False,
              'cold_file_open_audit': {'policy': 'only complete authenticated views, captured output/evidence and host Python',
                  'old_producer_paths_authorize_no_reads': True, 'unique_opened_paths': sorted(opened)}}
    if args.get('artifact_request'):
        artifact = read_json(absolute(args['artifact_request']), args['artifact_request_sha256'])
        require(absolute(artifact['stage']) == absolute(args['original_evidence']['stage']),
                'artifact stage must be the explicitly selected authenticated current stage')
        helper = sys.modules['delivery']
        for key in ('classes', 'library', 'bundle', 'runtime', 'junit_root', 'dafny_cache'):
            allowed.add(absolute(artifact[key]))
        allowed.update(absolute(p) for p in artifact['java_homes'])
        # Old source paths never grant access. These two explicit stage input
        # receipt files are separately authenticated inputs to the unchanged API.
        artifact_stage = read_json(roots['stage'] / policy['evidence']['stage']['receipt'],
                                   policy['evidence']['stage']['receipt_sha256'])
        for path, pin in artifact_stage['external_inputs'].items():
            allowed.add(absolute(path))
            require(digest(file_bytes(absolute(path))) == pin, 'recorded API input receipt changed')
        report['artifact_prerequisites'] = prepare_artifact_inputs(artifact, policy, project, helper, artifact_stage)
        rel = 'scripts/security/crypto_current_release.py'
        api = captured_module('parent_selected_artifact_API', project / rel, policy['code'][rel])
        result = api.validate_current_release(project, tool_root=project, stage=roots['stage'],
                    classes=artifact['classes'], library=artifact['library'], bundle=artifact['bundle'],
                    runtime=artifact['runtime'], java_homes=artifact['java_homes'],
                    output=absolute(args['output']) / 'actual-artifacts')
        accept_artifact_result(result)
        artifact_spec = policy['artifact_prerequisites']
        check_pins(absolute(artifact['junit_root']), artifact_spec['junit'])
        cache, asset = absolute(artifact['dafny_cache']), artifact_spec['official_asset']
        check_tree(cache / asset['directory'], artifact_spec['distribution'])
        require(digest(file_bytes(cache / asset['archive'])) == asset['sha256'], 'explicit archive drift')
        check_artifact_jdks(artifact['java_homes'], policy, artifact_stage, helper)
        report.update(status='selected-current-epoch-validated', qualification=False,
                      artifact_API_called=True, artifact_report_sha256=digest(file_bytes(
                          absolute(args['output']) / 'actual-artifacts/report.json')))
        report['scope'] = 'Selected current source/component/canonical and fresh actual artifact identity checks; no global V7, physical timing or expert-review closure'
    admit_constructed(policy, views, args['views_sha256'])
    require(digest(file_bytes(absolute(args['policy']))) == args['policy_sha256'],
            'parent policy drift')
    for name, contract in policy['evidence'].items():
        check_tree(roots[name], contract['files'])
    report['complete_before_after_maps_match'] = True
    require(digest(file_bytes(Path(__file__).absolute())) == args['runner_sha256'], 'captured dispatcher drift')
    write_json(absolute(args['output']) / 'report.json', report)
    return report


def dispatch(args, policy):
    views = absolute(args.views)
    artifact_raw, artifact_path, artifact_inputs = None, None, []
    if getattr(args, 'artifact_request', None):
        artifact_path = absolute(args.artifact_request)
        artifact_raw = file_bytes(artifact_path)
        require(digest(artifact_raw) == args.expected_artifact_request_sha256,
                'external artifact request authority mismatch')
        artifact = parse_json(artifact_raw)
        paths = ('stage', 'classes', 'library', 'bundle', 'runtime', 'junit_root', 'dafny_cache')
        require(set(artifact) == set(paths) | {'java_homes'}
                and type(artifact['java_homes']) is list and len(artifact['java_homes']) == 2
                and all(type(artifact[n]) is str for n in paths)
                and all(type(home) is str for home in artifact['java_homes']), 'artifact request inventory')
        artifact_inputs = [artifact_path, *(absolute(artifact[n]) for n in paths),
                           *(absolute(home) for home in artifact['java_homes'])]
    roots = (admit_capsule(args.capsule, args.expected_capsule_sha256, policy) if args.capsule else
             explicit_roots(args.evidence, policy))
    admit_constructed(policy, views, args.expected_views_sha256)
    out = output_admission(args.output, [views, args.policy.parent, HERE, *roots.values(), *artifact_inputs])
    out.mkdir(mode=0o700)
    runner_before = digest(file_bytes(Path(__file__).absolute()))
    (out / 'policy.json').write_bytes(file_bytes(args.policy))
    (out / 'parent.py').write_bytes(file_bytes(Path(__file__).absolute()))
    captured = out / 'evidence'
    captured.mkdir()
    for name, contract in policy['evidence'].items():
        check_pins(roots[name], contract['files'])
        target = captured / name
        for rel, pin in contract['files'].items():
            raw = file_bytes(roots[name] / rel)
            require(digest(raw) == pin, 'evidence changed during capture')
            p = target / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw)
        check_tree(target, contract['files'])
    request = {'policy': str(out / 'policy.json'), 'policy_sha256': args.expected_policy_sha256,
               'views': str(views), 'views_sha256': args.expected_views_sha256,
               'output': str(out), 'evidence': {n: str(captured / n) for n in roots},
               'original_evidence': {n: str(p) for n, p in roots.items()}, 'runner_sha256': runner_before}
    if artifact_raw is not None:
        (out / 'artifact-request.json').write_bytes(artifact_raw)
        request.update(artifact_request=str(out / 'artifact-request.json'),
                       artifact_request_sha256=args.expected_artifact_request_sha256)
    write_json(out / 'request.json', request)
    env = child_environment(out / 'child')
    try:
        command = run([sys.executable, '-I', '-B', out / 'parent.py', '_worker', '--request', out / 'request.json',
                       '--expected-request-sha256', digest(file_bytes(out / 'request.json'))],
                      cwd=out, env=env, log=out / 'worker.log', timeout=15000)
        write_json(out / 'execution.json', command)
        for name, c in policy['evidence'].items():
            check_pins(roots[name], c['files'])
        admit_constructed(policy, views, args.expected_views_sha256)
        require(digest(file_bytes(args.policy)) == args.expected_policy_sha256, 'external policy drift')
        if artifact_raw is not None:
            require(file_bytes(artifact_path) == artifact_raw, 'external artifact request drift')
        require(digest(file_bytes(Path(__file__).absolute())) == runner_before
                == digest(file_bytes(out / 'parent.py')), 'parent dispatcher source changed')
        return parse_json(file_bytes(out / 'report.json'))
    except BaseException as error:
        write_json(out / 'FAILED.json', {'schema': REPORT_SCHEMA, 'status': 'failed', 'qualification': False,
                                       'error': type(error).__name__ + ': ' + str(error), 'outstanding': OUTSTANDING})
        raise


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest='mode', required=True)
    construct_p = subs.add_parser('construct')
    construct_p.add_argument('--repository', type=Path, required=True)
    construct_p.add_argument('--fixture-root', type=Path, required=True)
    construct_p.add_argument('--selected-root', type=Path, required=True)
    pack_p = subs.add_parser('pack')
    pack_p.add_argument('--selected-root', type=Path, required=True)
    pack_p.add_argument('--fixture-root', type=Path, required=True)
    pack_p.add_argument('--evidence', nargs=2, action='append', metavar=('NAME', 'ROOT'), required=True)
    for name in ('check', 'qualify'):
        c = subs.add_parser(name)
        c.add_argument('--views', type=Path, required=True)
        c.add_argument('--expected-views-sha256', required=True)
        group = c.add_mutually_exclusive_group(required=True)
        group.add_argument('--evidence', nargs=2, action='append', metavar=('NAME', 'ROOT'))
        group.add_argument('--capsule', type=Path)
        c.add_argument('--expected-capsule-sha256')
        if name == 'qualify':
            c.add_argument('--artifact-request', type=Path, required=True)
            c.add_argument('--expected-artifact-request-sha256', required=True)
    w = subs.add_parser('_worker')
    w.add_argument('--request', type=Path, required=True)
    w.add_argument('--expected-request-sha256', required=True)
    for c in (construct_p, pack_p, *[subs.choices[n] for n in ('check', 'qualify')]):
        c.add_argument('--policy', type=Path, required=True)
        c.add_argument('--expected-policy-sha256', required=True)
        c.add_argument('--output', type=Path, required=True)
    args = p.parse_args(argv)
    require(sys.flags.isolated and sys.flags.dont_write_bytecode, 'dispatcher requires Python -I -B')
    if args.mode == '_worker':
        worker(absolute(args.request), args.expected_request_sha256)
        return 0
    policy = read_json(absolute(args.policy), args.expected_policy_sha256)
    runner_before = digest(file_bytes(Path(__file__).absolute()))
    validate_policy(policy)
    if args.mode == 'construct':
        result = construct(policy, absolute(args.repository), absolute(args.output),
                           absolute(args.fixture_root), absolute(args.selected_root))
    elif args.mode == 'pack':
        result = pack(policy, absolute(args.selected_root), absolute(args.fixture_root),
                      args.evidence, absolute(args.output))
    else:
        result = dispatch(args, policy)
    require(read_json(absolute(args.policy), args.expected_policy_sha256) == policy
            and digest(file_bytes(Path(__file__).absolute())) == runner_before, 'parent authority/source drift')
    print(json.dumps({'status': result.get('status', 'constructed'), 'qualification': False,
                      'output': str(args.output)}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ParentError, KeyError, ValueError, OSError) as error:
        print('PARENT REJECTED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
