"""Verbatim finite admission helpers from the pinned repository Keccak replay.

Only these pure/profile functions are copied: the original module loads its own
helper implicitly at import. HKDF loads every executable dependency explicitly
from authenticated bytes instead. No Keccak coverage/build policy is changed.
"""
import hashlib, json, os, platform, sys
from pathlib import Path
class GateError(ValueError): pass
REPO = Path(__file__).resolve().parents[4]
PROFILE_PINS = {
    'macos-sdk10.0.400': ('9ec9f05ce8dd1083071e6fc0aecea69d9972abe7d94ca8e7be0266c032e99f84', 'macos-arm64'),
    'linux-sdk10.0.400': ('89c444a9e5c4d473912fd57db16e53b71d06733f1751fe648bf9995c0a4deab1', 'linux-x64'),
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def within(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False

def no_symlink_components(path):
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            raise GateError('symlink input component is unsupported: ' + str(cursor))

def output_admission_error(output, source_root, repo=REPO):
    p = Path(output)
    if not p.is_absolute():
        return 'output must be absolute'
    try:
        resolved = p.resolve(strict=False)
    except OSError as error:
        return 'output cannot be resolved: ' + str(error)
    if within(resolved, repo.resolve()) or within(resolved, source_root.resolve()):
        return 'output is inside the repository or input source root'
    if any(os.path.lexists(parent / '.git') for parent in resolved.parents):
        return 'output has a Git ancestor'
    if os.path.lexists(p):
        return 'output already exists'
    cursor = Path(p.anchor)
    for part in p.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            return 'output has a symlink ancestor'
        if cursor.exists() and not cursor.is_dir():
            return 'output ancestor is not a directory'
        if not cursor.exists():
            break
    return None

def host_platform():
    machine = platform.machine().lower()
    if sys.platform == 'darwin' and machine in ('arm64', 'aarch64'):
        return 'macos-arm64'
    if sys.platform.startswith('linux') and machine in ('x86_64', 'amd64'):
        return 'linux-x64'
    return 'unsupported'

def validate_profile(identifier, raw):
    if identifier not in PROFILE_PINS:
        raise GateError('unsupported reviewed profile: ' + identifier)
    expected, target = PROFILE_PINS[identifier]
    if digest(raw) != expected:
        raise GateError('reviewed profile missing or changed')
    profile = json.loads(raw)
    mandatory = {'schema', 'platform', 'dafny_version', 'dotnet_sdk', 'dafny_sha256',
                 'dafny_core_sha256', 'dotnet_launcher_sha256', 'boogie',
                 'runtime_sha256', 'z3_sha256'}
    if not mandatory <= profile.keys() or profile['schema'] != 'microproxy.select-tool-profile/2':
        raise GateError('missing reviewed profile fields/schema')
    if profile['platform'] != target or target != host_platform():
        raise GateError('profile does not match the supported host platform')
    if profile['dotnet_sdk'] != '10.0.400' or profile['dafny_version'] != '4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2':
        raise GateError('unsupported SDK/Dafny profile')
    if not isinstance(profile['boogie'], dict) or len(profile['boogie']) != 13:
        raise GateError('reviewed Boogie inventory is incomplete')
    return profile

def include_paths(text):
    """Read literal include directives, ignoring nested comments and strings.

    This only freezes inputs; event/operation semantics come from resolved ASTs.
    Unreviewed include forms and escaped include paths fail closed.
    """
    tokens, i, size = [], 0, len(text)
    while i < size:
        if text.startswith('//', i):
            end = text.find('\n', i + 2)
            i = size if end < 0 else end + 1
        elif text.startswith('/*', i):
            depth, i = 1, i + 2
            while i < size and depth:
                if text.startswith('/*', i): depth, i = depth + 1, i + 2
                elif text.startswith('*/', i): depth, i = depth - 1, i + 2
                else: i += 1
            if depth: raise GateError('unterminated source comment')
        elif text[i] == '"':
            start, escaped, i = i + 1, False, i + 1
            value = []
            while i < size and text[i] != '"':
                if text[i] == '\\':
                    escaped = True
                    if i + 1 >= size: raise GateError('unterminated source string')
                    value.extend(text[i:i + 2]); i += 2
                else: value.append(text[i]); i += 1
            if i >= size: raise GateError('unterminated source string')
            tokens.append(('string', ''.join(value), escaped)); i += 1
        elif text[i].isalpha() or text[i] == '_':
            start = i
            while i < size and (text[i].isalnum() or text[i] == '_'): i += 1
            tokens.append(('word', text[start:i], False))
        elif text[i].isspace(): i += 1
        else: tokens.append(('punctuation', text[i], False)); i += 1
    includes = []
    for index, token in enumerate(tokens):
        if token[:2] != ('word', 'include'): continue
        if index + 1 >= len(tokens) or tokens[index + 1][0] != 'string' or tokens[index + 1][2]:
            raise GateError('unsupported nonliteral/escaped include directive')
        includes.append(tokens[index + 1][1])
    return includes

def file_map(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}

def tool_map(dafny_root, dotnet_root):
    return {str(p): sha(p) for root in (dafny_root, dotnet_root)
            for p in sorted(root.rglob('*')) if p.is_file()}

def check_tool_pins(profile, dafny, dotnet):
    dafny, dotnet = dafny.resolve(), dotnet.resolve()
    if not dafny.is_file() or not dotnet.is_file(): raise GateError('missing explicit tool launcher')
    if not (dotnet.parent / 'sdk' / profile['dotnet_sdk']).is_dir():
        raise GateError('explicit dotnet installation lacks the exact reviewed SDK')
    expected = {dafny: profile['dafny_sha256'], dotnet: profile['dotnet_launcher_sha256'],
                dafny.parent / 'DafnyCore.dll': profile['dafny_core_sha256'],
                dafny.parent / 'z3/bin/z3-4.12.1': profile['z3_sha256']}
    expected.update({dafny.parent / name: value for name, value in profile['boogie'].items()})
    for path, value in expected.items():
        if not path.is_file() or sha(path) != value:
            raise GateError('reviewed tool pin mismatch: ' + str(path))
    return dafny, dotnet, {str(path): value for path, value in expected.items()}
