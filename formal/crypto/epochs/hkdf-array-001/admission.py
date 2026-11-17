"""Closed data authority for the HKDF array epoch. No proof execution here."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

SHA = re.compile(r'[0-9a-f]{64}\Z')
SCHEMA = 'microproxy.hkdf-array-epoch-inputs/1'
SOURCE_SCHEMA = 'microproxy.hkdf-array-source-inputs/1'


class EpochError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EpochError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def map_sha(value):
    return digest((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())


def absolute(path):
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts, 'absolute nontraversing path required')
    for part in (p, *p.parents):
        require(not part.is_symlink(), 'symlink input component: ' + str(part))
    return p


def relative(name):
    require(type(name) is str and name and '\\' not in name and ':' not in name
            and all(ord(c) >= 32 for c in name), 'unsafe relative path')
    p = PurePosixPath(name)
    require(not p.is_absolute() and str(p) == name and not {'.', '..', ''} & set(name.split('/')),
            'noncanonical relative path: ' + name)
    return name


def captured(path):
    p = absolute(path)
    try:
        before = p.stat(follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular unaliased input required: ' + str(p))
        with p.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read()
            after = os.fstat(stream.fileno())
        current = p.stat(follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, n) == getattr(opened, n) == getattr(after, n) == getattr(current, n)
                    for n in fields) and len(raw) == after.st_size,
                'input changed during capture: ' + str(p))
        return raw
    except OSError as exc:
        raise EpochError('missing/unreadable input: ' + str(p)) from exc


def sha(path):
    return digest(captured(path))


def unique(pairs):
    value = {}
    for name, item in pairs:
        require(name not in value, 'duplicate JSON key: ' + name)
        value[name] = item
    return value


def parse_json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, EpochError):
            raise
        raise EpochError('invalid JSON input') from exc
    require(type(value) is dict, 'JSON object required')
    return value


def pin(value):
    require(type(value) is str and SHA.fullmatch(value), 'SHA256 required')
    return value


def pin_map(value, *, empty=False):
    require(type(value) is dict and (value or empty), 'nonempty exact pin map required')
    for name, expected in value.items():
        relative(name)
        pin(expected)
    require(len({n.casefold() for n in value}) == len(value), 'case aliases in input map')
    return value


def inventory(value, names, label):
    require(type(value) is dict and set(value) == set(names), label + ' inventory')


def build_outputs(value, inputs):
    """Finite Maven output locations, each bound to one selected reactor POM."""
    inventory(value, ('directories', 'files'), 'build-output')
    all_names = []
    for kind, leaf in (('directories', 'target'), ('files', '.flattened-pom.xml')):
        require(type(value[kind]) is dict, 'build-output location map required')
        for name, ref in value[kind].items():
            relative(name)
            reference(ref)
            pom = PurePosixPath(ref['path'])
            require(pom.name == 'pom.xml' and name == str(pom.parent / leaf), 'build-output must be an exact POM-owned Maven location')
            require(inputs.get(ref['path']) == ref['sha256'], 'build-output POM is not a selected input')
            all_names.append(name)
    require(len(set(all_names)) == len(all_names) and len({n.casefold() for n in all_names}) == len(all_names),
            'build-output case/path aliases')
    return value


def reference(value):
    inventory(value, ('path', 'sha256'), 'file reference')
    relative(value['path'])
    pin(value['sha256'])
    return value


def read_reference(root, value):
    reference(value)
    raw = captured(absolute(root) / value['path'])
    require(digest(raw) == value['sha256'], 'selected input reference changed: ' + value['path'])
    return raw


def check_pins(root, value):
    for name, expected in pin_map(value).items():
        require(sha(absolute(root) / name) == expected, 'candidate input changed: ' + name)


def candidate_origin(root, policy, name):
    # A single explicit constructor mapping. The source checkout's canonical
    # historical config is never rewritten merely to construct a successor.
    if name == 'formal/crypto/delivery.json':
        ref = policy['delivery']['config']
        require(policy['candidate']['inputs'][name] == ref['sha256'], 'canonical configuration pin differs from selected successor')
        return absolute(root) / ref['path']
    return absolute(root) / name


def check_candidate_sources(root, policy):
    for name, expected in pin_map(policy['candidate']['inputs']).items():
        require(sha(candidate_origin(root, policy, name)) == expected, 'candidate input changed: ' + name)


def files(root):
    root = absolute(root)
    require(root.is_dir(), 'missing input directory: ' + str(root))
    value = {}
    for folder, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            require(not (Path(folder) / name).is_symlink(), 'symlink in input tree')
        for name in names:
            p = Path(folder) / name
            value[relative(p.relative_to(root).as_posix())] = sha(p)
    return pin_map(dict(sorted(value.items())), empty=True)


def check_tree(root, expected):
    require(files(root) == pin_map(expected, empty=True), 'missing, extra or changed input tree: ' + str(root))


def load_module(name, path, expected):
    """Execute the captured pinned bytes, never SourceFileLoader or cached .pyc."""
    raw = captured(path)
    require(digest(raw) == pin(expected), 'raw Python source pin mismatch: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


def check_delta(before, after, allowed):
    before, after = pin_map(before, empty=True), pin_map(after, empty=True)
    inventory(allowed, ('changed', 'added', 'removed'), 'delta')
    pin_map(allowed['added'], empty=True)
    pin_map(allowed['removed'], empty=True)
    require(type(allowed['changed']) is dict, 'changed delta map required')
    for name, row in allowed['changed'].items():
        relative(name)
        inventory(row, ('before', 'after'), 'changed delta')
        pin(row['before'])
        pin(row['after'])
        require(row['before'] != row['after'], 'delta authorizes unchanged input')
    union = [*allowed['changed'], *allowed['added'], *allowed['removed']]
    require(len(set(union)) == len(union) and len({n.casefold() for n in union}) == len(union), 'overlapping/aliased delta')
    actual = {'changed': {n: {'before': before[n], 'after': after[n]} for n in sorted(before.keys() & after.keys())
                          if before[n] != after[n]},
              'added': {n: after[n] for n in sorted(after.keys() - before.keys())},
              'removed': {n: before[n] for n in sorted(before.keys() - after.keys())}}
    require(actual == allowed, 'exact selected delta mismatch')
    return actual


class EpochPolicy(dict):
    """JSON authority plus uncommitted, explicitly supplied runtime locations."""
    def __init__(self, data, root, path, expected):
        super().__init__(data)
        self.root, self.path, self.expected = root, path, expected
        self.locations = {}


def load_policy(root: Path, policy: Path, expected_sha256: str) -> dict:
    return _load_policy(root, policy, expected_sha256, source_only=False)


def load_source_policy(root: Path, policy: Path, expected_sha256: str) -> dict:
    """Source-only construction cannot authorize a candidate class/artifact claim."""
    return _load_policy(root, policy, expected_sha256, source_only=True)


def _load_policy(root, policy, expected_sha256, *, source_only):
    root, policy = absolute(root), absolute(policy)
    require(policy.is_relative_to(root), 'policy must be inside the selected source root')
    raw = captured(policy)
    require(digest(raw) == pin(expected_sha256), 'externally selected policy SHA256 mismatch')
    data = parse_json(raw)
    inventory(data, ('schema', 'epoch', 'qualification', 'predecessor', 'candidate', 'allowed',
                     'retained', 'hkdf', 'delivery', 'tools'), 'epoch policy')
    require(data['schema'] == (SOURCE_SCHEMA if source_only else SCHEMA)
            and data['epoch'] == 'hkdf-array-001' and data['qualification'] is False,
            'unsupported epoch subject/scope')
    inventory(data['allowed'], ('inputs',) if source_only else ('inputs', 'classes'), 'allowed delta')
    for name in ('predecessor', 'candidate'):
        fields = ('inputs',) if source_only and name == 'candidate' else ('inputs', 'classes')
        inventory(data[name], fields, name)
        pin_map(data[name]['inputs'])
        if 'classes' in fields:
            pin_map(data[name]['classes'])
            require(all(n.endswith('.class') for n in data[name]['classes']), 'non-class in whole class map')
    for name in (('inputs',) if source_only else ('inputs', 'classes')):
        check_delta(data['predecessor'][name], data['candidate'][name], data['allowed'][name])
    if not source_only:
        require(data['allowed']['classes']['changed'] or data['allowed']['classes']['added'] or data['allowed']['classes']['removed'],
                'old whole class map cannot qualify as the new HKDF subject')
    inventory(data['retained'], ('ci', 'selection', 'prepared_receipt_sha256'), 'retained')
    pin(data['retained']['prepared_receipt_sha256'])
    inventory(data['hkdf'], ('manifest', 'receipt', 'projector', 'raw_files', 'producers', 'tool_map_sha256'), 'HKDF')
    pin_map(data['hkdf']['raw_files'])
    pin_map(data['hkdf']['producers'])
    pin(data['hkdf']['tool_map_sha256'])
    inventory(data['delivery'], ('predecessor', 'config', 'native_evidence', 'api', 'timeout', 'build_outputs'), 'delivery')
    build_outputs(data['delivery']['build_outputs'], data['candidate']['inputs'])
    require(type(data['delivery']['timeout']) is int and 0 < data['delivery']['timeout'] <= 7200, 'delivery timeout policy')
    tool_fields = ('runtime_sha256', 'jdk21_tree_sha256', 'jdk25_tree_sha256', 'maven_tree_sha256', 'python_sha256')
    inventory(data['tools'], tool_fields if source_only else (*tool_fields, 'maven_repository_tree_sha256'), 'tool authority')
    for expected in data['tools'].values():
        pin(expected)
    references = [data['retained'][n] for n in ('ci', 'selection')]
    references += [data['hkdf'][n] for n in ('manifest', 'receipt', 'projector')]
    references += [data['delivery'][n] for n in ('predecessor', 'config', 'native_evidence', 'api')]
    for ref in references:
        reference(ref)
        require(data['candidate']['inputs'].get(ref['path']) == ref['sha256'], 'reference outside selected candidate input authority')
    for name, expected in data['hkdf']['producers'].items():
        require(data['candidate']['inputs'].get(name) == expected, 'stale producer outside selected input authority')
    require(str(policy.relative_to(root)) not in data['candidate']['inputs'], 'policy cannot hash/authorize itself')
    check_candidate_sources(root, data)
    return EpochPolicy(data, root, policy, expected_sha256)


def reauthenticate(policy):
    require(isinstance(policy, EpochPolicy), 'externally loaded epoch policy required')
    raw = captured(policy.path)
    require(digest(raw) == policy.expected and parse_json(raw) == dict(policy), 'selected policy authority changed')


def bind_runtime(policy, **locations):
    reauthenticate(policy)
    require(set(locations) <= {'prepared', 'data', 'hkdf', 'cache', 'junit', 'maven', 'maven_repository'}, 'runtime location inventory')
    for name, path in locations.items():
        p = absolute(path)
        require(p.is_dir(), 'missing explicit runtime root: ' + name)
        require(name not in policy.locations or policy.locations[name] == p, 'runtime location rebinding: ' + name)
        policy.locations[name] = p
    return policy


def location(policy, name):
    reauthenticate(policy)
    require(name in policy.locations, 'missing explicit runtime location: ' + name)
    return absolute(policy.locations[name])


def output_admission(output, protected):
    output = absolute(output)
    for name, root in protected.items():
        root = absolute(root)
        require(not output.is_relative_to(root) and not root.is_relative_to(output), 'output overlap in either direction: ' + name)
    require(not os.path.lexists(output) and output.parent.is_dir(), 'fresh output with existing parent required')
    return output
