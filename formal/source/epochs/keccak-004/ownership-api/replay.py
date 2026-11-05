#!/usr/bin/env python3
"""Requalify current SHAKE source ownership/API-state consumers for epoch 004.

No old main is invoked, no legacy module global is changed, and no manifest in
an old package is current-source authority. Observation and requalification are
separate externally pinned invocations; neither qualifies the parent epoch.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import signal
import subprocess
import types
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
from zipfile import ZipFile

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
SCHEMA = 'microproxy.keccak-004-ownership-api-inputs/1'
EPOCH_MANIFEST = '294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec'
CONSTRUCTOR = '65eb424c4c0b5ce44498ded72cb8600c02252e18122b8d1f28fcfb0b00eaa3eb'
SOURCE_MAP = '4cd8e0957af4d15b3620fa4541dbfbeda4b664f9eb2b848f31353548fbacc9fb'
FILE_MAP = 'b8c2991319e63b6986a3fa672ee8f7a7de4d9450623b6cfcaec4bc701bcbe843'
FLAGS = ['--verification-time-limit', '30', '--resource-limit', '50000000',
         '--solver-option', 'O:smt.case_split=0', '--cores', '2']
PACKAGE_FILES = {'replay.py', 'test_replay.py', 'README.md'}
EXECUTION_POLICY = 'raw-source-isolated-child/v2'
LEGACY_MANIFESTS = {'ownership': 'formal/source/inputs.json', 'api': 'assurance/shake-api/inputs.json'}
REQUIRED_CONTROLS = {
    'ownership': ['factory-alias', 'output-alias', 'external-footprint', 'included-assumption'],
    'api': ['empty-read-phase', 'phase-before-bounds', 'invalid-slice', 'destroy-phase',
            'next-boundary-position', 'included-assumption'],
    'parser': ['bom-include', 'inline-comment-include', 'entry-proofs', 'entry-audit', 'complete-audit'],
}
CHANGES = {
    'formal/crypto/NativeKeccak.dfy': 'd1682b1b9f6014d2d8d290841801bd70d4771feaf90581bde6bb0791723d60df',
    'formal/crypto/NativeShake.dfy': '97a25d13a672b46b2e947af1537a6eabbd1ada5d3912c83c0f5a8457e31df816',
    'formal/crypto/native_shake_domain.dfy': '0029621ea31b6edf10c69b62c197f904f0202270e5f6b3f45b789a031622e084',
}
BAD = re.compile(r'warning:|out of resources?|timed?\s*out|timeout|parse(?:r)? errors?|'
                 r'resolution/type errors?|internal error|\bexception\b|System\.\w*Exception|'
                 r'crash|inconclusive|CASE-TIMEOUT|\bskipped\b', re.I)
SUMMARY = re.compile(r'^Dafny program verifier finished with (\d+) verified, (\d+) errors?\s*$', re.M)
ERROR_LOCATION = re.compile(r'^(.+?\.dfy)\((\d+),\d+\): Error: assertion might not hold\s*$', re.M)
SHA = re.compile(r'[0-9a-f]{64}\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def map_sha(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute path without traversal required')
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        require(not cursor.is_symlink(), 'symlink path component: ' + str(cursor))
    return path


def regular(path, identities=None):
    path = absolute(path)
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular unaliased file required: ' + str(path))
    identity = (before.st_dev, before.st_ino)
    if identities is not None:
        require(identity not in identities, 'physical input alias: ' + str(path))
        identities.add(identity)
    raw = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    require((after.st_dev, after.st_ino, after.st_size, after.st_nlink) ==
            (before.st_dev, before.st_ino, len(raw), 1), 'input identity changed: ' + str(path))
    return raw


def validate_pin_map(pins):
    require(type(pins) is dict and pins, 'nonempty exact pin map required')
    require(len({str(n).casefold() for n in pins}) == len(pins), 'case alias in input map')
    for name, pin in pins.items():
        require(isinstance(name, str) and name and '\\' not in name and ':' not in name
                and all(ord(c) >= 32 for c in name), 'unsafe relative input')
        path = PurePosixPath(name)
        require(not path.is_absolute() and str(path) == name
                and all(p not in ('', '.', '..') for p in name.split('/')), 'unsafe relative input')
        require(isinstance(pin, str) and SHA.fullmatch(pin), 'invalid input digest')
    return pins


def read_map(root, pins):
    root = absolute(root)
    identities, data = set(), {}
    for name, pin in validate_pin_map(pins).items():
        raw = regular(root / name, identities)
        require(hashlib.sha256(raw).hexdigest() == pin, 'input hash changed: ' + name)
        data[name] = raw
    return data


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def authenticated_json(path, expected):
    require(isinstance(expected, str) and SHA.fullmatch(expected), 'invalid external expected digest')
    raw = regular(path)
    require(hashlib.sha256(raw).hexdigest() == expected, 'input differs from external expected digest')
    value = json.loads(raw, object_pairs_hook=no_duplicates)
    require(type(value) is dict, 'expected JSON object')
    return value, raw


def directory_ancestry(path):
    result = []
    for current in (path, *path.parents):
        record = current.stat(follow_symlinks=False)
        require(stat.S_ISDIR(record.st_mode), 'directory required: ' + str(current))
        result.append((record.st_dev, record.st_ino))
    return result


def output_admission(output, protected):
    output = absolute(output)
    require(output.parent.is_dir(), 'output parent must exist')
    parent_ids = set(directory_ancestry(output.parent))
    existing = output.stat(follow_symlinks=False) if os.path.lexists(output) else None
    identity = (existing.st_dev, existing.st_ino) if existing else None
    for root in protected:
        ancestry = directory_ancestry(absolute(root))
        require(ancestry[0] not in parent_ids and identity not in ancestry, 'output overlaps protected input')
    require(not os.path.lexists(output), 'output already exists')
    return output


def file_map(root):
    result = {}
    identities = set()
    for parent, dirs, files in os.walk(absolute(root), followlinks=False):
        for name in dirs:
            require(not (Path(parent) / name).is_symlink(), 'linked input directory')
        for name in files:
            path = Path(parent) / name
            result[path.relative_to(root).as_posix()] = hashlib.sha256(regular(path, identities)).hexdigest()
    return dict(sorted(result.items()))


def check_controls(controls):
    require(controls == REQUIRED_CONTROLS, 'required semantic/parser control inventory changed')


def negative_result(status, text, expected, entry, line, anchor):
    matches = SUMMARY.findall(text)
    locations = ERROR_LOCATION.findall(text)
    require(not BAD.search(text) and matches == [(str(expected), '1')] and status == 4
            and len(locations) == 1 and text.count(': Error:') == 1
            and (locations[0][0] == entry or locations[0][0].endswith('/' + entry))
            and int(locations[0][1]) == line and anchor in text,
            'expected exact named assertion failure; tool/precondition/skipped failures are invalid')
    return {'verified': expected, 'errors': 1, 'file': entry, 'assertion_line': line, 'assertion': anchor}


def load_module(path, name, expected):
    """Execute exactly the authenticated captured source; never consult .pyc."""
    require(isinstance(expected, str) and SHA.fullmatch(expected), 'expected module pin required')
    path = absolute(path)
    raw = regular(path)
    require(hashlib.sha256(raw).hexdigest() == expected, 'module hash changed: ' + str(path))
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = name.rpartition('.')[0]
    module.__loader__ = None
    module.__cached__ = None
    module.__spec__ = importlib.util.spec_from_loader(name, loader=None, origin=str(path))
    absent = object()
    previous = sys.modules.get(name, absent)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), 'exec', dont_inherit=True, optimize=0), module.__dict__)
    except BaseException:
        if previous is absent:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


def child_environment(root):
    """Fixed allowlist; no inherited Python, managed/native loader or tool options."""
    root = absolute(root)
    root.mkdir(mode=0o700, exist_ok=False)
    directories = {}
    for name in ('home', 'temporary', 'xdg-config', 'xdg-cache', 'xdg-data', 'dotnet-home'):
        path = root / name
        path.mkdir(mode=0o700)
        require(stat.S_IMODE(path.stat().st_mode) == 0o700 and not any(path.iterdir()),
                'fresh empty private child configuration directory required')
        directories[name] = str(path)
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
            'HOME': directories['home'], 'TMPDIR': directories['temporary'],
            'TMP': directories['temporary'], 'TEMP': directories['temporary'],
            'XDG_CONFIG_HOME': directories['xdg-config'], 'XDG_CACHE_HOME': directories['xdg-cache'],
            'XDG_DATA_HOME': directories['xdg-data'], 'DOTNET_CLI_HOME': directories['dotnet-home']}


def child_command(command):
    command = list(map(str, command))
    require(command and Path(command[0]).is_absolute(), 'explicit absolute child executable required')
    if Path(command[0]).resolve() == Path(sys.executable).resolve():
        # Preserve all program arguments; normalize only the initial isolation flags.
        offset = 1
        while offset < len(command) and command[offset] in ('-I', '-B'):
            offset += 1
        command = [str(Path(sys.executable).resolve()), '-I', '-B', *command[offset:]]
    return command


def execute(command, log, cwd, timeout=900, *, child_root):
    """Version 2 executor: original merged logs/timeout semantics, isolated state."""
    command = child_command(command)
    environment = child_environment(child_root)
    sidecar = Path(log).with_suffix('.environment.json')
    require(not sidecar.exists(), 'child environment record already exists')
    sidecar.write_text(json.dumps({'policy': EXECUTION_POLICY, 'argv': command,
        'environment': environment, 'configuration_initially_empty': True,
        'private_directory_mode': '0700'}, indent=2, sort_keys=True) + '\n')
    with Path(log).open('w') as output:
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output.write('\nCASE-TIMEOUT\n')
            status = 124
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    return status, Path(log).read_text()


def validate_manifest(m):
    require(set(m) == {'schema', 'epoch', 'qualification', 'mode', 'scope', 'epoch_manifest_sha256',
            'constructor_sha256', 'view_source_map_sha256', 'view_file_map_sha256', 'current_sources',
            'legacy_manifests', 'consumers', 'controls', 'flags', 'tools', 'package_inputs', 'observed_from'},
            'unknown/missing successor authority key')
    require(m['schema'] == SCHEMA and m['epoch'] == 'keccak-004' and m['qualification'] is False
            and m['mode'] in {'observation', 'requalification'}
            and m['scope'] == 'current-source-ownership-and-api-state-only', 'successor authority scope')
    require((m['epoch_manifest_sha256'], m['constructor_sha256'], m['view_source_map_sha256'],
             m['view_file_map_sha256']) == (EPOCH_MANIFEST, CONSTRUCTOR, SOURCE_MAP, FILE_MAP), 'epoch authority substitution')
    sources = validate_pin_map(m['current_sources'])
    require(len(sources) == 85 and map_sha(sources) == SOURCE_MAP
            and all(sources.get(n) == pin for n, pin in CHANGES.items()), 'current 85-source authority changed')
    require(set(m['legacy_manifests']) == set(LEGACY_MANIFESTS), 'legacy manifest inventory changed')
    for kind, path in LEGACY_MANIFESTS.items():
        item = m['legacy_manifests'][kind]
        require(set(item) == {'path', 'sha256'} and item['path'] == path and SHA.fullmatch(item['sha256']), 'legacy manifest authority')
    check_controls(m['controls'])
    require(m['flags'] == FLAGS and set(m['consumers']) == {'ownership', 'api'}, 'consumer policy changed')
    for item in m['consumers'].values():
        require(set(item) == {'sources', 'inputs', 'proof_counts'}, 'consumer authority keys changed')
        validate_pin_map(item['sources']); validate_pin_map(item['inputs'])
        require(len(item['sources']) >= 7 and len(item['inputs']) == len(item['sources']) + 6, 'consumer source/input domain narrowed or support omitted')
        counts = item['proof_counts']
        require(set(counts) == {'complete_source', 'root'}, 'proof count inventory changed')
        if m['mode'] == 'observation':
            require(counts == {'complete_source': None, 'root': None} and m['observed_from'] is None, 'observation cannot reuse proof counts')
        else:
            require(all(type(x) is int and x > 0 for x in counts.values()), 'reviewed positive counts required')
            require(isinstance(m['observed_from'], str) and SHA.fullmatch(m['observed_from']), 'external observed report identity required')
    require(set(m['package_inputs']) == PACKAGE_FILES, 'successor package inputs omitted/added')
    validate_pin_map(m['package_inputs'])
    require(set(m['tools']) == {'version', 'platform', 'archive', 'dafny', 'solver'}
            and m['tools']['version'] == '4.9.1' and m['tools']['platform'] == 'Darwin-arm64'
            and all(SHA.fullmatch(m['tools'][n]) for n in ['archive', 'dafny', 'solver']), 'explicit pinned tools required')


def admit_view(view, receipt, m):
    require(receipt.get('schema') == 'microproxy.keccak-source-views/1' and receipt.get('status') == 'complete'
            and receipt.get('qualification') is False and receipt.get('scope') == 'source-views-only'
            and receipt.get('manifest_sha256') == EPOCH_MANIFEST and receipt.get('constructor_sha256') == CONSTRUCTOR
            and receipt.get('changed_sources') == CHANGES and receipt.get('inputs_before_after_match') is True,
            'view construction authority differs')
    current = receipt['views']['current']
    require(current['root'] == str(view) and current['sources'] == m['current_sources']
            and current['source_map_sha256'] == SOURCE_MAP and current['file_map_sha256'] == FILE_MAP
            and len(current['files']) == 434 and map_sha(current['files']) == FILE_MAP,
            'current view/source map substitution')
    actual = file_map(view)
    require(actual == current['files'], 'complete current view files changed')
    for kind, item in m['consumers'].items():
        legacy = m['legacy_manifests'][kind]
        require(actual.get(legacy['path']) == legacy['sha256'], 'legacy package identity changed')
        old = json.loads(regular(view / legacy['path']), object_pairs_hook=no_duplicates)
        # Domain and unchanged bytes are inherited, never an old current-source admission.
        for key in ('sources', 'inputs'):
            expected = {n: CHANGES.get(n, pin) for n, pin in old[key].items()}
            require(all(item[key].get(n) == pin for n, pin in expected.items()),
                    'historical consumer source/input domain narrowed or substituted')
        require(set(item['inputs']) == set(item['sources']) | (set(old['inputs']) - set(old['sources'])),
                'current consumer replay input omitted/added')
        require(all(actual.get(n) == pin for n, pin in item['inputs'].items()), 'current consumer pins differ from actual view')
    return actual


def verify_tools(dafny, solver, archive, pins, tools):
    require(sha(archive) == pins['archive'] and sha(dafny) == pins['dafny'] and sha(solver) == pins['solver'], 'tool hash changed')
    require(dafny.name == 'dafny' and solver == dafny.parent / 'z3/bin/z3-4.12.1', 'explicit solver/distribution path changed')
    root = dafny.parent.parent
    expected = {}
    with ZipFile(archive) as bundle:
        for member in bundle.infolist():
            tools.validate_member(member)
            if not member.is_dir():
                require(member.filename not in expected, 'duplicate tool archive entry')
                expected[member.filename] = hashlib.sha256(bundle.read(member)).hexdigest()
    actual = file_map(root)
    require(actual == expected, 'complete extracted tool distribution differs from pinned archive')
    return {'archive': sha(archive), 'dafny': sha(dafny), 'solver': sha(solver),
            'distribution': actual, 'distribution_map_sha256': map_sha(actual)}


def admit_observation(path, m):
    require(path is not None, 'requalification requires the preserved observation report')
    observed, _ = authenticated_json(absolute(path), m['observed_from'])
    require(observed.get('schema') == 'microproxy.keccak-004-ownership-api/1'
            and observed.get('status') == 'observed' and observed.get('mode') == 'observation'
            and observed.get('qualification') is False and observed.get('scope') == m['scope']
            and observed.get('inputs_before') == observed.get('inputs_after') ==
                {k: v['inputs'] for k, v in m['consumers'].items()}, 'invalid preserved observation authority')
    for kind, item in m['consumers'].items():
        record = observed['consumers'][kind]
        require(record['source_graph'] == item['sources']
                and {k: r['verified'] for k, r in record['proofs'].items()} == item['proof_counts']
                and all(r['errors'] == 0 for r in record['proofs'].values())
                and set(record['controls']) == set(REQUIRED_CONTROLS[kind]), 'observed counts/consumer graph differ')
    require(set(observed['parser_controls']) - {'graph'} == set(REQUIRED_CONTROLS['parser']), 'observed parser control omitted')
    logs = {}
    for command in observed['commands']:
        name = command['log']
        require(Path(name).name == name and name not in logs, 'unsafe/duplicate observed raw log')
        logs[name] = command['log_sha256']
    read_map(absolute(path).parent, logs)
    return logs


def requalify(args):
    manifest_path, receipt_path = absolute(args.manifest), absolute(args.view_receipt)
    view, dafny, solver, archive = map(absolute, (args.view, args.dafny, args.solver, args.archive))
    m, manifest_bytes = authenticated_json(manifest_path, args.expected_manifest_sha256)
    validate_manifest(m)
    receipt, receipt_bytes = authenticated_json(receipt_path, args.expected_view_receipt_sha256)
    observed_logs = admit_observation(args.observation_report, m) if m['mode'] == 'requalification' else None
    package_before = read_map(HERE, m['package_inputs'])
    view_before = admit_view(view, receipt, m)
    out = output_admission(args.output, [view, receipt_path.parent, manifest_path.parent, HERE, dafny.parent.parent])
    # Validate tools before creating any output or launching a child process.
    tools = load_module(view / 'formal/dafny/toolchain.py', 'epoch004_pinned_tools',
                        m['consumers']['ownership']['inputs']['formal/dafny/toolchain.py'])
    tool_before = verify_tools(dafny, solver, archive, m['tools'], tools)
    out.mkdir(mode=0o700)
    child_state = out / 'child-state'; child_state.mkdir(mode=0o700)
    package_snapshot = out / 'successor-package'; package_snapshot.mkdir()
    for name, raw in package_before.items():
        (package_snapshot / name).write_bytes(raw)
    (out / 'successor-manifest.json').write_bytes(manifest_bytes)
    (out / 'view-receipt.json').write_bytes(receipt_bytes)
    report = {'schema': 'microproxy.keccak-004-ownership-api/1', 'status': 'incomplete', 'qualification': False,
              'parent_epoch_status': 'pending', 'scope': m['scope'], 'mode': m['mode'],
              'execution_policy': EXECUTION_POLICY,
              'manifest_sha256': args.expected_manifest_sha256, 'view_receipt_sha256': args.expected_view_receipt_sha256,
              'observed_from': m['observed_from'], 'commands': [], 'consumers': {}, 'parser_controls': {},
              'inputs_before': {k: v['inputs'] for k, v in m['consumers'].items()},
              'view_before': view_before, 'package_before': m['package_inputs'], 'tools_before': tool_before,
              'not_claimed': ['SHAKE operation-trace composition', 'whole-crypto composition', 'current Select qualification',
                              'Java/compiler/JVM refinement', 'exclusive Java ownership', 'physical timing/erasure', 'parent epoch qualification']}
    def save():
        (out / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    save()
    try:
        frozen = out / 'frozen'
        union = {}
        for item in m['consumers'].values():
            for name, pin in item['inputs'].items():
                require(name not in union or union[name] == pin, 'consumer overlap has conflicting bytes')
                union[name] = pin
        for name, raw in read_map(view, union).items():
            target = frozen / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        read_map(frozen, union)
        ownership = load_module(frozen / 'formal/source/replay.py', 'epoch004_pinned_ownership', union['formal/source/replay.py'])
        api = load_module(frozen / 'assurance/shake-api/replay.py', 'epoch004_pinned_api', union['assurance/shake-api/replay.py'])
        discovery = load_module(frozen / 'formal/crypto/delivery.py', 'epoch004_pinned_parser', union['formal/crypto/delivery.py'])
        def call(label, command, cwd=frozen):
            log = out / (label + '.log')
            require(not log.exists(), 'duplicate command/log label')
            status, text = execute(command, log, cwd, timeout=1800, child_root=child_state / label)
            environment_path = log.with_suffix('.environment.json')
            environment_record = json.loads(environment_path.read_text())
            report['commands'].append({'label': label, 'argv': list(map(str, command)), 'cwd': str(cwd),
                                       'exit': status, 'log': log.name, 'log_sha256': sha(log),
                                       'actual_argv': environment_record['argv'],
                                       'environment': environment_record['environment'],
                                       'environment_record': environment_path.name,
                                       'environment_sha256': sha(environment_path)})
            save()
            return status, text
        # Rerun all unchanged old helper regressions under their unchanged policies.
        for kind, entry in [('ownership', 'formal/source'), ('api', 'assurance/shake-api')]:
            status, text = call(kind + '-legacy-regressions', [sys.executable, '-I', '-B', '-m', 'unittest', 'discover', '-s', entry, '-p', 'test_replay.py'])
            require(status == 0 and re.search(r'^Ran \d+ tests? in ', text, re.M) and re.search(r'^OK\s*$', text, re.M), 'unchanged legacy helper regressions failed')
        for kind, helper in [('ownership', ownership), ('api', api)]:
            item = m['consumers'][kind]
            helper.check_inventory(item['sources'], item['inputs'])
            entries = (ownership.ENTRY, ownership.DOMAIN) if kind == 'ownership' else (api.ENTRY, api.CONTROL_ENTRY)
            def parser_call(label, command):
                require(Path(command[0]) == dafny, 'unexpected dependency parser executable')
                return call(kind + '-' + label, command)
            graph = ownership.closure(frozen, entries, dafny, discovery.source_closure, call=parser_call)
            require(graph == item['sources'], 'complete current parser graph differs from current manifest')
            record = {'source_graph': graph, 'proofs': {}, 'audits': {}, 'controls': {}}
            report['consumers'][kind] = record
            for label, source_entries, included in [('complete_source', entries if kind == 'ownership' else (api.ENTRY,), True), ('root', (entries[0],), False)]:
                arguments = [dafny, 'verify', *source_entries]
                if included:
                    arguments += ['--verify-included-files']
                status, text = call(kind + '-' + label, [*arguments, *FLAGS, '--solver-path', solver])
                expected = item['proof_counts'][label]
                record['proofs'][label] = ownership.proof_result(status, text, expected=expected)
                require(not BAD.search(text), 'forbidden proof diagnostic')
            for index, name in enumerate(graph):
                status, text = call(kind + '-audit-' + str(index), [dafny, 'audit', name])
                record['audits'][name] = {'findings': api.audit_result(status, text)}
            api.check_audits(graph, record['audits'])
            if kind == 'ownership':
                original = (frozen / ownership.ENTRY).read_text()
                for label, (old, new, symbol) in ownership.CONTROLS.items():
                    require(original.count(old) == 1, 'ownership control anchor changed')
                    control = 'formal/source/Control-' + label + '.dfy'
                    mutant = original.replace(old, new, 1)
                    target = frozen / control
                    target.write_text(mutant)
                    line = next(i for i, value in enumerate(mutant.splitlines(), 1) if new in value)
                    status, text = call(kind + '-control-' + label, [dafny, 'verify', control, '--filter-symbol', symbol, *FLAGS, '--solver-path', solver])
                    ownership.proof_result(status, text, negative=new)
                    record['controls'][label] = negative_result(status, text, 1, control, line, new)
            else:
                controls = (frozen / api.CONTROL_ENTRY).read_text()
                for label, method in api.CONTROL_NAMES.items():
                    anchors = [(i, line.split('//')[0].strip()) for i, line in enumerate(controls.splitlines(), 1) if line.strip().endswith('// NEGATIVE ' + label)]
                    require(len(anchors) == 1, 'API control anchor changed')
                    line, anchor = anchors[0]
                    status, text = call(kind + '-control-' + label, [dafny, 'verify', api.CONTROL_ENTRY, '--filter-symbol', 'ShakeApiControls.' + method, *FLAGS, '--solver-path', solver])
                    api.proof_result(status, text, 0, negative=(api.CONTROL_ENTRY, line, anchor))
                    record['controls'][label] = negative_result(status, text, 0, api.CONTROL_ENTRY, line, anchor)
            mutant_root = out / (kind + '-included-assumption')
            shutil.copytree(frozen, mutant_root)
            native = mutant_root / 'formal/crypto/NativeShake.dfy'
            original = native.read_text(); anchor = '    ghost var before := sponge.Model();'
            require(original.count(anchor) == 1, 'included assumption anchor changed')
            native.write_text(original.replace(anchor, '    assume {:axiom} false;\n' + anchor, 1))
            status, text = call(kind + '-control-included-assumption', [dafny, 'audit', *(mutant_root / name for name in graph)])
            finding = api.audit_result(status, text, expected=1, anchor='Xof: Definition has `assume {:axiom}` statement in body')
            require('NativeShake.dfy' in text, 'included assumption in wrong source')
            if kind == 'ownership':
                ownership.audit_result(status, text, negative=True)
            record['controls']['included-assumption'] = {'findings': finding, 'file': 'formal/crypto/NativeShake.dfy', 'injected_line': original[:original.index(anchor)].count('\n') + 1}
            require(set(record['controls']) == set(REQUIRED_CONTROLS[kind]), 'omitted semantic control')
            save()
        # Preserve the real parser BOM/comment controls, including why entry-only
        # verification/audit cannot certify an entire included graph.
        graph_root = out / 'parser-control'; graph_root.mkdir()
        (graph_root / 'Hidden.dfy').write_text('module Hidden { lemma Impossible() ensures false { assume {:axiom} false; } }\n')
        graph_entries = []
        for name, prefix in [('Bom', '\ufeff'), ('Inline', '/* header */ ')]:
            path = graph_root / (name + '.dfy')
            path.write_text(prefix + 'include "Hidden.dfy"\nmodule ' + name + ' { import H = Hidden method Claim() { H.Impossible(); assert false; } }\n')
            graph_entries.append(path.name)
        graph = ownership.closure(graph_root, graph_entries, dafny, discovery.source_closure,
            call=lambda label, command: call('parser-control-' + label, command, graph_root))
        require(set(graph) == {'Hidden.dfy', 'Bom.dfy', 'Inline.dfy'}, 'BOM/comment parser graph omitted include')
        report['parser_controls'].update({'bom-include': {'discovered': 'Hidden.dfy'}, 'inline-comment-include': {'discovered': 'Hidden.dfy'}, 'graph': graph})
        status, text = call('parser-control-entry-proofs', [dafny, 'verify', *graph_entries, *FLAGS, '--solver-path', solver], graph_root)
        report['parser_controls']['entry-proofs'] = ownership.proof_result(status, text, expected=2)
        status, text = call('parser-control-entry-audit', [dafny, 'audit', *graph_entries], graph_root)
        report['parser_controls']['entry-audit'] = {'findings': api.audit_result(status, text)}
        status, text = call('parser-control-complete-audit', [dafny, 'audit', *sorted(graph)], graph_root)
        report['parser_controls']['complete-audit'] = {'findings': api.audit_result(status, text, expected=1, anchor='Impossible: Definition has `assume {:axiom}` statement in body')}
        require(set(report['parser_controls']) - {'graph'} == set(REQUIRED_CONTROLS['parser']), 'omitted parser control')
        read_map(frozen, union)
        require(admit_view(view, receipt, m) == view_before, 'view changed during replay')
        require(read_map(HERE, m['package_inputs']) == package_before, 'successor package changed during replay')
        require(regular(manifest_path) == manifest_bytes and regular(receipt_path) == receipt_bytes, 'authority changed during replay')
        if observed_logs is not None:
            authenticated_json(absolute(args.observation_report), m['observed_from'])
            read_map(absolute(args.observation_report).parent, observed_logs)
        tool_after = verify_tools(dafny, solver, archive, m['tools'], tools)
        require(tool_after == tool_before, 'tools changed during replay')
        report.update(status='observed' if m['mode'] == 'observation' else 'complete',
                      inputs_after={k: v['inputs'] for k, v in m['consumers'].items()}, view_after=view_before,
                      package_after=m['package_inputs'], tools_after=tool_after,
                      current_consumer_status='observed-only' if m['mode'] == 'observation' else 'requalified-awaiting-parent-epoch')
        save()
        return report
    except BaseException as error:
        report.update(status='incomplete' if isinstance(error, KeyboardInterrupt) else 'failed',
                      error_type=type(error).__name__, error=str(error))
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['manifest', 'view', 'view-receipt', 'dafny', 'solver', 'archive', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ['expected-manifest-sha256', 'expected-view-receipt-sha256']:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--observation-report', type=Path)
    args = parser.parse_args()
    try:
        report = requalify(args)
        print(json.dumps({'status': report['status'], 'qualification': False, 'parent_epoch_status': 'pending',
                          'proofs': {k: r['proofs'] for k, r in report['consumers'].items()}}))
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print(json.dumps({'status': 'rejected-or-failed', 'qualification': False, 'error': str(error)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
