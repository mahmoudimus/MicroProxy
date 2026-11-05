#!/usr/bin/env python3
"""Portable, fail-closed Keccak AST coverage replay; always qualification:false.

The C# observers and this orchestration are trusted tooling. This resolver-only
component does not establish source value proofs, noninterference, Java erasure,
delivery qualification, physical timing, or general compiler refinement.
"""
import argparse
import hashlib
import types
import io
import stat
import zipfile
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
COMPONENT = Path('formal/source/keccak')
ENTRY = 'formal/crypto/NativeKeccak.dfy'
COMBINED_ENTRIES = ('formal/crypto/NativeMlKem.dfy',
                    'formal/source/NativeKeccakTraceHarness.dfy',
                    'formal/crypto/native_shake_domain.dfy')
METHOD_NAMES = ('NewOffsets', 'NewSources', 'SetLane', 'Iota', 'Theta', 'RhoPi',
                'Chi', 'Round', 'PermuteScratch', 'Permute', 'Wipe')
METHOD_ROOTS = {'NativeKeccak.' + name for name in METHOD_NAMES}
EXPECTED_DLLS = {
    'method': 'a4905de3b46e39fd819dc7ad5e5245bbae449080bc8f2e6039cc2de69f33b3fd',
    'function': 'af1f0fec7e98cd51e4172b8ff98826ed830eee18df4d8beaa91c812d617e68dd',
}
FUNCTION_ROOTS = ('NativeKeccak.Rotate', 'NativeKeccak.Constant',
                  'NativeKeccak.Offset', 'NativeKeccak.Source')
METHOD_SUCCESS = 'KECCAK-METHOD-COVERAGE OK: exact methods'
FUNCTION_SUCCESS = ('KECCAK-FUNCTION-OBSERVATIONS OK: exact functions [' +
                    ','.join(FUNCTION_ROOTS) + ']; FUNCTION-ONLY DEVELOPMENT SCOPE')
PROFILE_PINS = {
    'macos-sdk10.0.400': ('9ec9f05ce8dd1083071e6fc0aecea69d9972abe7d94ca8e7be0266c032e99f84', 'macos-arm64'),
    'linux-sdk10.0.400': ('89c444a9e5c4d473912fd57db16e53b71d06733f1751fe648bf9995c0a4deab1', 'linux-x64'),
}
CS_PINS = {
    'method-checker/KeccakMethodCoverage.cs': 'f106ea52f289062c2110c31981ad916017c0735c25f294c5dc925ea793e1fab3',
    'function-checker/KeccakFunctionCoverage.cs': 'fd2b09dc7ff564b821a18c9ae6ae5b7a1607a4f621ffff196c0cf50a5425b90b',
    'encoder/NativeCanonicalEncoderPolicy.cs': '27115848f259786cd928d9d477fe0b51d84c7fc21efb5f98d83f5182358c0734',
}
PACKAGE_FILES = tuple(COMPONENT / name for name in CS_PINS) + (
    COMPONENT / 'method-checker/KeccakMethodCoverage.csproj',
    COMPONENT / 'function-checker/KeccakFunctionCoverage.csproj',
    COMPONENT / 'coverage_replay.py',
    COMPONENT / 'encoder/build_authority.py',
    COMPONENT / 'encoder/net6-targeting-packs.json',)
AUTHORITY_MODULE = Path(__file__).resolve().parent / 'encoder/build_authority.py'
AUTHORITY_BYTES = AUTHORITY_MODULE.read_bytes()
_build_authority = types.ModuleType('keccak_build_authority')
_build_authority.__file__ = str(AUTHORITY_MODULE)
exec(compile(AUTHORITY_BYTES, str(AUTHORITY_MODULE), 'exec'), _build_authority.__dict__)
AUTHORITY = None
BUILD_TOOLS = None
PROFILE_DIR = Path('formal/source/select/profiles')
BAD_TOOL_OUTPUT = re.compile(
    r'parse[rd]? errors? detected|Error: unresolved identifier|Error: incorrect argument type|'
    r'Error: wrong number of arguments|Error: this expression has type|'
    r'timed?\s*out|out of resource|out of memory|internal error|unhandled exception|CLI: Error', re.I)
SCOPE = ('Keccak resolved-AST method and pure-function observation coverage only; '
         'no value/body-proof, NI, Java, delivery, or physical timing qualification')


class GateError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def json_write(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')


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


def clean_env():
    if AUTHORITY is None:
        raise GateError('isolated build authority is not initialized')
    return AUTHORITY.environment()


def run(argv, cwd, logs, label, timeout=180, environment=None):
    started = time.monotonic()
    try:
        result = subprocess.run(list(map(str, argv)), cwd=cwd, env=clean_env() if environment is None else environment,
                                capture_output=True, text=True, timeout=timeout)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code = 'timeout'
        stdout = error.stdout.decode(errors='replace') if isinstance(error.stdout, bytes) else error.stdout or ''
        stderr = error.stderr.decode(errors='replace') if isinstance(error.stderr, bytes) else error.stderr or ''
    stdout_path, stderr_path = logs / (label + '.stdout.log'), logs / (label + '.stderr.log')
    stdout_path.write_text(stdout, encoding='utf-8')
    stderr_path.write_text(stderr, encoding='utf-8')
    row = {'argv': list(map(str, argv)), 'cwd': str(cwd), 'exit': code,
           'seconds': time.monotonic() - started, 'stdout': str(stdout_path),
           'stderr': str(stderr_path), 'stdout_sha256': sha(stdout_path),
           'stderr_sha256': sha(stderr_path)}
    return row, stdout + stderr


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


def freeze_source_bytes(source_root):
    source_root = Path(source_root)
    if not source_root.is_absolute() or not source_root.is_dir():
        raise GateError('--source-root must be an existing absolute directory')
    no_symlink_components(source_root)
    source_root = source_root.resolve()
    contents, edges, todo = {}, {}, list(COMBINED_ENTRIES)
    while todo:
        rel = todo.pop()
        if rel in contents: continue
        path = source_root / rel
        no_symlink_components(path)
        if not path.is_file(): raise GateError('missing actual source graph member: ' + rel)
        actual = path.resolve()
        if not within(actual, source_root): raise GateError('include escapes source root: ' + rel)
        raw = path.read_bytes()
        contents[rel] = raw
        includes = []
        for include in include_paths(raw.decode('utf-8')):
            if not include or Path(include).is_absolute() or '\\' in include:
                raise GateError('unsupported absolute/backslash include path: ' + include)
            target = (path.parent / include).resolve()
            if not within(target, source_root): raise GateError('include escapes source root: ' + include)
            target_rel = str(target.relative_to(source_root))
            includes.append(target_rel)
            todo.append(target_rel)
        edges[rel] = includes
    if ENTRY not in contents: raise GateError('actual combined graph does not include NativeKeccak')
    return contents, edges


def materialize(root, contents):
    root.mkdir(parents=True, exist_ok=False)
    for rel, raw in contents.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


def file_map(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def tool_map(dafny_root, dotnet_root):
    return {str(p): sha(p) for root in (dafny_root, dotnet_root)
            for p in sorted(root.rglob('*')) if p.is_file()}


def freeze_package_bytes(profile_id):
    files = {}
    for rel in PACKAGE_FILES:
        path = REPO / rel
        no_symlink_components(path)
        if not path.is_file(): raise GateError('missing coverage component input: ' + str(rel))
        files[str(rel)] = path.read_bytes()
    if files[str(COMPONENT / 'encoder/build_authority.py')] != AUTHORITY_BYTES:
        raise GateError('build authority helper changed after loading')
    for relative, expected in CS_PINS.items():
        if digest(files[str(COMPONENT / relative)]) != expected:
            raise GateError('unreviewed coverage C# source: ' + relative)
    profile_rel = PROFILE_DIR / (profile_id + '.json')
    path = REPO / profile_rel
    if not path.is_file(): raise GateError('mandatory reviewed profile is missing')
    files[str(profile_rel)] = path.read_bytes()
    profile = validate_profile(profile_id, files[str(profile_rel)])
    files['global.json'] = (json.dumps({'sdk': {'version': profile['dotnet_sdk'], 'rollForward': 'disable'}}) + '\n').encode()
    return files, profile


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


def build_plugins(package, out, label, dafny, dotnet, logs):
    build = out / label
    shutil.copytree(package, build)
    before = file_map(build)
    dlls, commands, evaluations, assets = {}, [], {}, {}
    query_properties = ','.join([*AUTHORITY.properties(), 'MSBuildAllProjects'])
    for gate, directory, assembly in (('method', 'method-checker', 'KeccakMethodCoverage'),
                                       ('function', 'function-checker', 'KeccakFunctionCoverage')):
        project = COMPONENT / directory / (assembly + '.csproj')
        AUTHORITY.verify()
        common = [dotnet, 'msbuild', project, *AUTHORITY.arguments(dafny.parent)]
        row, text = run([*common, '-t:Restore', '-v:minimal'], build, logs, label + '-' + gate + '-restore')
        commands.append(row)
        if row['exit'] != 0: raise GateError('isolated offline restore failed: ' + text[-1000:])
        assets[gate] = AUTHORITY.validate_assets(build / project.parent / 'obj/project.assets.json')
        row, text = run([*common, '-t:Build', '-v:minimal',
                         '-getProperty:' + query_properties,
                         '-getItem:ReferencePath,ReferencePathWithRefAssemblies,Compile,Analyzer,EditorConfigFiles,GlobalAnalyzerConfigFiles,AnalyzerConfigFiles'],
                        build, logs, label + '-' + gate + '-build')
        commands.append(row)
        if row['exit'] != 0: raise GateError('isolated ' + gate + ' checker build failed: ' + text[-1000:])
        # MSBuild10 emits its requested evaluation JSON after build messages.
        start = text.find('{\n')
        if start < 0: raise GateError('missing actual MSBuild evaluation JSON')
        evaluated, _ = json.JSONDecoder().raw_decode(text[start:])
        evaluations[gate] = AUTHORITY.validate_evaluation(json.dumps(evaluated), build,
                                      build / project.parent, assembly, BUILD_TOOLS)
        dll = build / COMPONENT / directory / 'bin/Debug/net6.0' / (assembly + '.dll')
        if not dll.is_file(): raise GateError('checker build did not produce its DLL')
        if sha(dll) != EXPECTED_DLLS[gate]: raise GateError('corrected offline DLL differs from reviewed identity: ' + gate)
        dlls[gate] = dll
    if any(sha(build / rel) != value for rel, value in before.items()):
        raise GateError('isolated build modified frozen source inputs')
    AUTHORITY.verify()
    return dlls, {'directory': str(build), 'inputs': before, 'commands': commands,
                  'evaluations': evaluations, 'assets': assets, 'generated_files': file_map(build),
                  'dlls': {key: {'path': str(value), 'sha256': sha(value)} for key, value in dlls.items()}}


def method_success(text):
    roots = re.findall(r'^KECCAK-METHOD-COVERAGE ROOT OK: (.+)$', text, re.M)
    return len(roots) == 11 and set(roots) == METHOD_ROOTS and text.count(METHOD_SUCCESS) == 1


def function_success(text):
    return text.count(FUNCTION_SUCCESS) == 1


def replace1(text, old, new):
    if text.count(old) != 1: raise GateError('nonunique mutation anchor: ' + repr(old[:100]))
    return text.replace(old, new, 1)


def mutate_function(text, name, edit):
    start = text.index('  function ' + name + '(')
    match = re.search(r'^  (?:ghost )?(?:function|method|lemma)\b', text[start + 3:], re.M)
    end = start + 3 + match.start() if match else len(text)
    return text[:start] + edit(text[start:end]) + text[end:]


def rotate_mutation(text, old, new):
    return mutate_function(text, 'Rotate', lambda body: replace1(body, old, new))


def function_mutations():
    cases = []
    def add(name, target, edit, needle): cases.append((name, target, edit, needle))
    add('positive', ENTRY, lambda s: s, None)
    add('missing-rotate-branch', ENTRY, lambda s: rotate_mutation(s, '(v, ghost ST.Branch(0,true))', '(v, ghost [])'), 'trace omits/changes actual branch')
    add('wrong-rotate-outcome', ENTRY, lambda s: rotate_mutation(s, '(v, ghost ST.Branch(0,true))', '(v, ghost ST.Branch(0,false))'), 'trace omits/changes actual branch')
    add('missing-rotate-ops', ENTRY, lambda s: rotate_mutation(s, 'ST.Branch(0,false) + ST.Ops(0,1,0,0,0,1,2)', 'ST.Branch(0,false)'), 'omits actual scalar operation')
    add('wrong-shift-count', ENTRY, lambda s: rotate_mutation(s, 'ST.Ops(0,1,0,0,0,1,2)', 'ST.Ops(0,1,0,0,0,1,1)'), 'scalar operation count mismatch')
    add('higher-order-identity', ENTRY, lambda s: rotate_mutation(s, '(v, ghost ST.Branch(0,true))', '(((x: bv64) => x)(v), ghost ST.Branch(0,true))'), 'unsupported actual value expression')
    add('inconsistent-constant-site', ENTRY, lambda s: mutate_function(s, 'Constant', lambda b: b.replace('ST.Branch(0,false)', 'ST.Branch(999,false)', 1)), 'inconsistent static site')
    add('reused-constant-site', ENTRY, lambda s: mutate_function(s, 'Constant', lambda b: b.replace('ST.Branch(1,', 'ST.Branch(0,')), 'different actual guards reuse')
    add('extra-executable-function', ENTRY, lambda s: replace1(s, '  function Rotate(', '  function Extra(): int {0}\n  function Rotate('), 'function inventory differs')
    add('extern-rotate', ENTRY, lambda s: replace1(s, '  function Rotate(', '  function {:extern} Rotate('), 'not concrete')
    add('opaque-rotate', ENTRY, lambda s: replace1(s, '  function Rotate(', '  function {:opaque} Rotate('), 'not concrete')
    add('ghost-trace-extra', ENTRY, lambda s: rotate_mutation(s, '(v, ghost ST.Branch(0,true))', '(v, ghost ST.Branch(0,true) + ST.Branch(999,true))'), 'unexpected extra observations')
    add('forged-branch-wrapper', 'formal/source/SourceTrace.dfy', lambda s: replace1(s, '{ O.Encode(O.Branch(site, taken)) }', '{ [] }'), 'marker body is not exact canonical')
    add('reordered-read-wrapper', 'formal/source/SourceTrace.dfy', lambda s: replace1(s, 'O.Read(site, role, address)', 'O.Read(role, site, address)'), 'marker changes/reorders formal')
    add('forged-canonical-encode', 'formal/source/vocabulary/ObservationVocabulary.dfy', lambda s: replace1(s, 'case Read(site, role, address) => [3, site, role, address]', 'case Read(site, role, address) => [3, site, role, 0]'), 'canonical Encode does not implement')
    add('reordered-canonical-encode', 'formal/source/vocabulary/ObservationVocabulary.dfy', lambda s: replace1(s, 'case Read(site, role, address) => [3, site, role, address]', 'case Read(site, role, address) => [3, role, site, address]'), 'canonical Encode does not implement')
    add('faithful-private-branch', ENTRY, lambda s: rotate_mutation(s, '(v, ghost ST.Branch(0,true))', '(if v == 0 then (0, ghost ST.Branch(0,true) + ST.Branch(1,true)) else (v, ghost ST.Branch(0,true) + ST.Branch(1,false)))'), None)
    add('omitted-private-branch', ENTRY, lambda s: rotate_mutation(s, '(v, ghost ST.Branch(0,true))', '(if v == 0 then (0, ghost ST.Branch(0,true)) else (v, ghost ST.Branch(0,true)))'), 'trace omits/changes actual branch')
    return cases
def method_mutations(s):
    result=[]
    def c(name,old,new,code): result.append((name,replace1(s,old,new),code))
    c('missing-ops','ST.Read(0,0,0) + ST.Ops(0,0,0,0,0,1,0);','ST.Read(0,0,0);','KMC004')
    c('missing-read','trace := ST.Read(0,0,0) + ST.Ops(0,0,0,0,0,1,0);','trace := ST.Ops(0,0,0,0,0,1,0);','KMC004')
    c('missing-write','trace := ST.Write(0,0,index as int);','trace := [];','KMC004')
    c('missing-call','trace := trace + ST.Call(1,10,3) + childTrace;','trace := trace + childTrace;','KMC004')
    c('missing-alloc','trace := ST.Alloc(0,25);\n    r := new T.I[25];\n    trace := trace + ST.LoopBound(1,0) + ST.LoopBound(2,25);\n    OffsetsUpToZero();','trace := [];\n    r := new T.I[25];\n    trace := trace + ST.LoopBound(1,0) + ST.LoopBound(2,25);\n    OffsetsUpToZero();','KMC004')
    c('missing-loopcheck','trace := trace + ST.LoopCheck(3,false,25);\n  }\n\n  function Source','\n  }\n\n  function Source','KMC011')
    c('wrong-loop-iterator','ST.LoopCheck(3,true,i as int) + ST.Call(4,23,1)','ST.LoopCheck(3,true,0) + ST.Call(4,23,1)','KMC011')
    c('mutated-loop-end','      a[i] := 0;\n      WipeUpToSucc(i as int);','      a[i] := 0;\n      length := 0;\n      WipeUpToSucc(i as int);','KMC011')
    c('stale-address-scalar-gap','+ ST.Write(19,0,i as int);\n        assert i%5 == x && i/5 == y;','+ ST.Write(19,0,i as int);\n        i := 0;\n        assert i%5 == x && i/5 == y;','KMC004')
    c('wrong-loop-end','ST.LoopCheck(3,false,25);\n  }\n\n  function Source','ST.LoopCheck(3,false,24);\n  }\n\n  function Source','KMC011')
    c('delayed-callee-child','childTrace := SetLane(a,0,value);\n    trace := trace + ST.Call(1,10,3) + childTrace;','childTrace := SetLane(a,0,value);\n    assert true;\n    trace := trace + ST.Call(1,10,3) + childTrace;','KMC005')
    c('dropped-callee-child','trace := trace + ST.Call(1,10,3) + childTrace;','trace := trace + ST.Call(1,10,3);','KMC005')
    c('duplicate-callee-child','trace := trace + ST.Call(1,10,3) + childTrace;','trace := trace + ST.Call(1,10,3) + childTrace + childTrace;','KMC005')
    c('reordered-callee-child','trace := trace + ST.Call(1,10,3) + childTrace;','trace := trace + childTrace + ST.Call(1,10,3);','KMC004')
    c('wrong-private-snapshot','ghost var callWitness := Rotate(c[(x+1)%5],1);','ghost var callWitness := Rotate(0,1);','KMC006')
    c('stale-snapshot-gap','assert callWitness == Rotate(c[(x+1)%5],1);','c[0] := c[0]^1;\n      assert callWitness == Rotate(c[(x+1)%5],1);','KMC006')
    c('snapshot-ghost-reassignment','ghost var callWitness := Rotate(c[(x+1)%5],1);','ghost var callWitness := Rotate(c[(x+1)%5],1);\n      if true { callWitness := Rotate(0,1); }','KMC006')
    c('snapshot-suchthat','ghost var callWitness := Rotate(c[(x+1)%5],1);','ghost var callWitness := Rotate(c[(x+1)%5],1);\n      callWitness :| true;','KMC006')
    c('snapshot-fabricated','ghost var callWitness := Rotate(c[(x+1)%5],1);','ghost var callWitness := (0 as bv64, ghost RotateTrace(1));','KMC006')
    c('wrong-callee-snapshot','ghost var callWitness := Rotate(c[(x+1)%5],1);','ghost var callWitness := Constant(0);','KMC006')
    c('full-tuple-assert-not-last','assert callWitness == Rotate(c[(x+1)%5],1);','assert callWitness == Rotate(c[(x+1)%5],1);\n      assert true;','KMC006')
    c('missing-full-tuple-assert','assert callWitness == Rotate(c[(x+1)%5],1);','assert true;','KMC006')
    c('assumed-full-tuple','assert callWitness == Rotate(c[(x+1)%5],1);','assume {:axiom} callWitness == Rotate(c[(x+1)%5],1);','KMC006')
    c('wrong-width-snapshot','ghost var callWitness := Rotate(c[(x+1)%5],1);','ghost var callWitness := Rotate((c[(x+1)%5] as bv8) as bv64,1);','KMC006')
    c('prefix-unbound-call','trace := ST.Read(0,0,0) + ST.Ops(0,0,0,0,0,1,0);','var unbound := Rotate(rc,1).0;\n    trace := ST.Read(0,0,0) + ST.Ops(0,0,0,0,0,1,0);','KMC006')
    c('trailing-unbound-call','trace := trace + ST.Call(1,10,3) + childTrace;','trace := trace + ST.Call(1,10,3) + childTrace;\n    var unbound := Rotate(rc,1).0;','KMC006')
    c('parallel-trace-mutation','trace := trace + ST.Call(1,10,3) + childTrace;','trace, value := trace + ST.Call(1,10,3) + childTrace, value;','KMC003')
    c('suchthat-trace-mutation','trace := trace + ST.Call(1,10,3) + childTrace;','trace :| trace == trace;','KMC003')
    c('hidden-ghost-trace-write','trace := trace + ST.Call(1,10,3) + childTrace;','trace := trace + ST.Call(1,10,3) + childTrace;\n    if true { trace := []; }','KMC003')
    c('late-trace-reset','trace := trace + ST.Call(1,10,3) + childTrace;','trace := trace + ST.Call(1,10,3) + childTrace;\n    trace := [];','KMC003')
    c('call-output-trace-clobber','childTrace := SetLane(a,0,value);','trace := SetLane(a,0,value);','KMC003')
    c('extra-import-alias','  import T = NativeTypes','  import T = NativeTypes\n  import ExtraAlias = NativeTypes','KMC001')
    c('wrong-import-target','  import T = NativeTypes','  import T = FakeNativeTypes','KMC001')
    c('extra-native-class','  method NewOffsets()','  class Extra {}\n\n  method NewOffsets()','KMC001')
    c('extra-native-datatype','  method NewOffsets()','  datatype Extra = ExtraValue\n\n  method NewOffsets()','KMC001')
    c('extra-native-newtype','  method NewOffsets()','  newtype Extra = x: int | 0 <= x witness 0\n\n  method NewOffsets()','KMC001')
    c('extra-native-iterator','  method NewOffsets()','  iterator Extra() yields (v: int) { yield 0; }\n\n  method NewOffsets()','KMC001')
    result.append(('foreign-uncalled-module',s+'\nmodule ForeignUncalled { class Extra {} function Rotate(): int {0} method Wipe() {} }\n',None))
    c('extra-executable-constant','  method NewOffsets()','  const ExtraConstant: int := 0\n\n  method NewOffsets()','KMC001')
    c('extra-executable-method','  method NewOffsets()','  method Extra() {}\n\n  method NewOffsets()','KMC001')
    ms=replace1(s,'childTrace := SetLane(a,0,value);','childTrace := T.SetLane(a,0,value);')
    result.append(('shadow-method',ms,'KMC005'))
    fs=s
    for old,new in [('ghost var callWitness := Rotate(c[(x+1)%5],1);','ghost var callWitness := T.Rotate(c[(x+1)%5],1);'),('assert callWitness == Rotate(c[(x+1)%5],1);','assert callWitness == T.Rotate(c[(x+1)%5],1);'),('var d := c[(x+4)%5] ^ Rotate(c[(x+1)%5],1).0;','var d := c[(x+4)%5] ^ T.Rotate(c[(x+1)%5],1).0;')]: fs=replace1(fs,old,new)
    result.append(('shadow-function',fs,'KMC006'))
    c('extern-pure','  function Rotate(v:', '  function {:extern} Rotate(v:', 'KMC002')
    c('bymethod-pure','ST.Ops(0,1,0,0,0,1,2)) }\n  function Constant','ST.Ops(0,1,0,0,0,1,2)) } by method { return (v, ghost []); }\n  function Constant','KMC002')
    c('extra-executable-function','  method NewOffsets()','  function Extra(): int {0}\n\n  method NewOffsets()','KMC001')
    result.append(('missing-method',s.replace('method Wipe(a:', 'method WipeRenamed(a:').replace(':= Wipe(',':= WipeRenamed('),'KMC001'))
    c('extern-root','  method Wipe(a: array<bv64>)','  method {:extern} Wipe(a: array<bv64>)','KMC002')
    c('unknown-runtime-string','var value := a[0]^rc;','var unknown := \"unobserved\";\n    var value := a[0]^rc;','KMC008')
    c('runtime-print','var value := a[0]^rc;','var value := a[0]^rc;\n    print rc;','KMC008')
    c('unknown-runtime-ite','var value := a[0]^rc;','var value := if rc == 0 then a[0]^rc else a[0]^rc;','KMC008')
    c('unsupported-array-initializer','var b := new bv64[25];','var b := new bv64[25](i => 0);','KMC010')
    c('parallel-child-redefinition','trace := trace + ST.Call(1,10,3) + childTrace;','trace := trace + ST.Call(1,10,3) + childTrace;\n    childTrace, childTrace := [], [];','KMC005')
    addr='((((rc%2) as bv4) as T.I)*4)*4'
    faithful=replace1(s,'trace := ST.Read(0,0,0) + ST.Ops(0,0,0,0,0,1,0);','trace := ST.Ops(0,0,0,0,1,0,0) + ST.Ops(0,0,1,0,0,0,0) + ST.Ops(0,0,1,0,0,0,0) + ST.Read(0,0,('+addr+') as int) + ST.Ops(0,0,0,0,0,1,0);')
    faithful=replace1(faithful,'var value := a[0]^rc;','var value := a['+addr+']^rc;')
    result.append(('faithful-private-address',faithful,None))
    forged=replace1(faithful,'ST.Read(0,0,('+addr+') as int)','ST.Read(0,0,((((rc%2) as bv4)*4)*4) as int)')
    result.append(('forged-typed-address',forged,'KMC007'))
    branch=replace1(s,'var value := a[0]^rc;','var value := a[0]^rc;\n    trace := trace + ST.Branch(1,rc == 0);\n    if rc == 0 { value := value; } else {}')
    branch=replace1(branch,'ST.Call(1,10,3) + childTrace;','ST.Call(2,10,3) + childTrace;')
    result.append(('faithful-private-branch',branch,None))
    result.append(('missing-private-branch',replace1(branch,'    trace := trace + ST.Branch(1,rc == 0);\n',''),'KMC012'))
    result.append(('forged-private-branch-true',replace1(branch,'ST.Branch(1,rc == 0)','ST.Branch(1,true)'),'KMC012'))
    result.append(('forged-private-branch-false',replace1(branch,'ST.Branch(1,rc == 0)','ST.Branch(1,false)'),'KMC012'))
    result.append(('canonical-wrapper',s,'KMC009'))
    result.append(('canonical-encoder',s,'KMC009'))
    return result

METHOD_INTENDED = {'extra-executable-constant': 'non-ghost field/constant initialization is '
                              'outside the exact NativeKeccak executable '
                              'inventory',
 'forged-private-branch-false': 'Branch event does not match the actual '
                                'guard/site',
 'forged-private-branch-true': 'Branch event does not match the actual '
                               'guard/site',
 'forged-typed-address': 'address is not typed-identical to the actual index '
                         'expression',
 'full-tuple-assert-not-last': 'direct full-tuple assertion must be the LAST',
 'mutated-loop-end': 'loop end expression variable is assigned inside the loop '
                     'body',
 'prefix-unbound-call': 'unbound actual pure call has no exact full-tuple '
                        'ghost witness',
 'shadow-function': 'inline call resolves to an unregistered/shadow pure '
                    'declaration',
 'shadow-method': 'unregistered effectful callee',
 'snapshot-ghost-reassignment': 'exactly one definition across the entire '
                                'method',
 'snapshot-suchthat': 'exactly one definition across the entire method',
 'stale-address-scalar-gap': 'executable statement between PRE packet and its '
                             'operation',
 'stale-snapshot-gap': 'executable effect between snapshot capture and actual '
                       'call',
 'trailing-unbound-call': 'unbound actual pure call has no exact full-tuple '
                          'ghost witness',
 'unknown-runtime-string': 'unsupported executable leaf type'}


def method_case_bytes(base):
    cases = []
    for name, text, code in [('full-positive', base[ENTRY].decode('utf-8'), None)] + method_mutations(base[ENTRY].decode('utf-8')):
        files = dict(base)
        if name == 'wrong-import-target':
            text += '\n' + replace1(base['formal/crypto/NativeTypes.dfy'].decode('utf-8'),
                                     'module NativeTypes {', 'module FakeNativeTypes {')
        files[ENTRY] = text.encode('utf-8')
        if name in ('shadow-method', 'shadow-function'):
            original = base['formal/crypto/NativeTypes.dfy'].decode('utf-8')
            addition = ('  method SetLane(a: array<bv64>, i: I, v: bv64) returns(ghost trace: seq<int>) modifies a { trace := []; }'
                        if name == 'shadow-method' else
                        '  function Rotate(v: bv64, n: I): (bv64, ghost seq<int>) { (v, ghost []) }')
            files['formal/crypto/NativeTypes.dfy'] = (original[:original.rfind('}')] + addition + '\n}\n').encode('utf-8')
        if name == 'canonical-wrapper':
            target = 'formal/source/SourceTrace.dfy'
            files[target] = replace1(base[target].decode('utf-8'), 'O.Call(site, target, arity)', 'O.Call(target, site, arity)').encode('utf-8')
        if name == 'canonical-encoder':
            target = 'formal/source/vocabulary/ObservationVocabulary.dfy'
            files[target] = replace1(base[target].decode('utf-8'), '[1, site, target, arity]', '[1, target, site, arity]').encode('utf-8')
        cases.append((name, files, code, METHOD_INTENDED.get(name)))
    if len(cases) != 61: raise GateError('method control inventory is not exactly61')
    return cases


def function_case_bytes(base):
    cases = []
    for name, target, edit, needle in function_mutations():
        files = dict(base)
        files[target] = edit(base[target].decode('utf-8')).encode('utf-8')
        cases.append((name, files, 'KFC:' if needle is not None else None, needle))
    if len(cases) != 18: raise GateError('function control inventory is not exactly18')
    return cases


def check_case(gate, case, out, dafny, dll):
    name, files, expected, needle = case
    folder = out / 'cases' / gate / name
    materialize(folder, files)
    before = file_map(folder)
    maps = out / 'case-maps'
    json_write(maps / (gate + '-' + name + '-before.json'), before)
    plain, plain_text = run([dafny, 'resolve', ENTRY, '--allow-external-contracts'],
                            folder, out / 'logs', gate + '-' + name + '-plain')
    checked, checked_text = run([dafny, 'resolve', ENTRY, '--allow-external-contracts', '--plugin', dll],
                                folder, out / 'logs', gate + '-' + name + '-plugin')
    after = file_map(folder)
    json_write(maps / (gate + '-' + name + '-after.json'), after)
    success = method_success(checked_text) if gate == 'method' else function_success(checked_text)
    named_success = METHOD_SUCCESS in checked_text if gate == 'method' else 'KECCAK-FUNCTION-OBSERVATIONS OK' in checked_text
    if expected is None:
        accepted = checked['exit'] == 0 and success and 'Error:' not in checked_text
    else:
        accepted = (checked['exit'] == 2 and expected in checked_text and
                    (needle is None or needle in checked_text) and not named_success)
    good = (plain['exit'] == 0 and accepted and before == after and
            not BAD_TOOL_OUTPUT.search(plain_text + checked_text))
    return {'name': name, 'gate': gate, 'passed': good, 'expected_error': expected,
            'expected_message': needle, 'typed_without_plugin': plain['exit'] == 0,
            'inputs': before, 'inputs_unchanged': before == after,
            'commands': [plain, checked]}


def combined_resolve(source, out, logs, label, dafny, dlls):
    before = file_map(source)
    argv = [dafny, 'resolve', *COMBINED_ENTRIES, '--allow-external-contracts',
            '--plugin', dlls['method'], '--plugin', dlls['function']]
    row, text = run(argv, source, logs, label)
    good = (row['exit'] == 0 and method_success(text) and function_success(text) and
            'Error:' not in text and not BAD_TOOL_OUTPUT.search(text) and before == file_map(source))
    return {'passed': good, 'command': row, 'method_roots': sorted(METHOD_ROOTS),
            'function_roots': list(FUNCTION_ROOTS), 'inputs': before,
            'inputs_unchanged': before == file_map(source)}


def snapshot_paths(root):
    return {str(p.relative_to(root)): ('symlink:' + os.readlink(p) if p.is_symlink() else
                                      'directory' if p.is_dir() else sha(p))
            for p in root.rglob('*')}


def admission_tests(out, source_root, profile_id, profile_raw):
    root = out / 'admission-tests'
    root.mkdir()
    sentinel = root / 'existing-file'
    sentinel.write_bytes(b'preserve-admission-sentinel\n')
    directory = root / 'existing-directory'
    directory.mkdir()
    target = root / 'target'
    target.mkdir()
    (root / 'dangling').symlink_to(root / 'missing-target')
    (root / 'linked-parent').symlink_to(target, target_is_directory=True)
    mock_git = root / 'mock-worktree'
    mock_git.mkdir()
    (mock_git / '.git').write_text('gitdir: never-opened-by-this-test\n', encoding='utf-8')
    candidates = {
        'existing-file': sentinel, 'existing-directory': directory,
        'dangling-symlink': root / 'dangling', 'symlink-ancestor': root / 'linked-parent/new-output',
        'git-ancestor': mock_git / 'new-output', 'repository-output': REPO / 'coverage-output-never-created',
        'source-output': source_root / 'coverage-output-never-created', 'relative-output': Path('relative-output'),
    }
    before = snapshot_paths(root)
    records = []
    for name, candidate in candidates.items():
        message = output_admission_error(candidate, source_root)
        records.append({'name': name, 'passed': message is not None, 'diagnostic': message})
    for name, identifier, raw in (
            ('unsupported-profile', 'unsupported-profile', profile_raw),
            ('changed-profile', profile_id, profile_raw + b' '),
            ('missing-profile-bytes', profile_id, b'')):
        try:
            validate_profile(identifier, raw)
            records.append({'name': name, 'passed': False})
        except GateError as error:
            records.append({'name': name, 'passed': True, 'diagnostic': str(error)})
    unchanged = before == snapshot_paths(root) and sentinel.read_bytes() == b'preserve-admission-sentinel\n'
    return {'passed': unchanged and all(row['passed'] for row in records),
            'unchanged': unchanged, 'records': records}


def immutable_input_probe(source, package, source_bytes, package_bytes, out, dafny, dotnet, dlls):
    simulation = out / 'mutable-input-simulation'
    materialize(simulation, {**source_bytes, **package_bytes})
    original = file_map(simulation)
    for rel in CS_PINS:
        (simulation / COMPONENT / rel).write_text('THIS IS DELIBERATELY INVALID C#\n', encoding='utf-8')
    (simulation / ENTRY).write_text('THIS IS DELIBERATELY INVALID DAFNY\n', encoding='utf-8')
    poisoned = file_map(simulation)
    rebuilt, record = build_plugins(package, out, 'immutable-rebuild', dafny, dotnet, out / 'logs')
    same = all(sha(rebuilt[gate]) == sha(dlls[gate]) for gate in dlls)
    combined = combined_resolve(source, out, out / 'logs', 'immutable-combined-resolve', dafny, rebuilt)
    return {'passed': original != poisoned and same and combined['passed'],
            'simulation_before': original, 'simulation_poisoned': poisoned,
            'same_dlls': same, 'rebuild': record, 'combined': combined,
            'scope': 'poisoned private checkout/source simulation; real input roots never changed'}


def build_boundary_controls(package, out, dafny, dotnet):
    """Real negative controls for authority, environment, imports and packs."""
    F = types.SimpleNamespace(AUTHORITY=AUTHORITY, COMPONENT=COMPONENT, json_write=json_write,
                              run=run, build_plugins=build_plugins, sha=sha, _build_authority=_build_authority)
    O = out / 'build-boundary-controls'
    O.mkdir()
    (O / 'logs').mkdir()
    shutil.copytree(package, O / 'frozen-package')
    raw = AUTHORITY.manifest_raw
    manifest = json.loads(raw)
    archives = AUTHORITY.archives
    rows=[]
    def record(name,passed,**data):
     rows.append({'name':name,'passed':passed,**data});F.json_write(O/'result.json',{'qualification':False,'records':rows,'passed':all(r['passed'] for r in rows)});print(name,passed,flush=True)
    # The attack executes against the actual frozen checker project under the old policy.
    marker=O/'POISON_EXECUTED';poison=O/'outside-frozen.targets';badcs=O/'outside-frozen.cs';badcs.write_text('#error P1_POISONED_COMPILE_INPUT\n')
    poison.write_text(f'<Project><ItemGroup><Compile Include="{badcs}" /></ItemGroup><Target Name="P1Poison" BeforeTargets="BeforeBuild"><WriteLinesToFile File="{marker}" Lines="executed" Overwrite="true" /><Error Text="P1_SELECTOR_EXECUTED" /></Target></Project>')
    old=O/'old-policy-build';shutil.copytree(O/'frozen-package',old)
    proj=F.COMPONENT/'method-checker/KeccakMethodCoverage.csproj'
    env=F.AUTHORITY.environment();env['CustomBeforeMicrosoftCommonTargets']=str(poison)
    cmd=[dotnet,'msbuild',proj,*AUTHORITY.arguments(dafny.parent),'-t:Build','-v:minimal']
    r,t=F.run(cmd,old,O/'logs','vulnerable-selector-control',environment=env)
    record('vulnerable-selector-executes',r['exit']==1 and marker.exists() and 'P1_SELECTOR_EXECUTED' in t,command=r)
    marker.unlink(missing_ok=True)
    # Poison all six private user hook locations; false globals must win even here.
    root=F.AUTHORITY.root/'msbuild-user/Current'
    for folder in ['Imports/Microsoft.Common.props/ImportBefore','Imports/Microsoft.Common.props/ImportAfter','Microsoft.Common.targets/ImportBefore','Microsoft.Common.targets/ImportAfter','Microsoft.CSharp.targets/ImportBefore','Microsoft.CSharp.targets/ImportAfter']:
     p=root/folder/'POISON.targets';p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(poison.read_bytes())
    poisoned=O/'poisoned-package';shutil.copytree(O/'frozen-package',poisoned)
    for directory in [poisoned,poisoned/F.COMPONENT/'method-checker',poisoned/F.COMPONENT/'function-checker']:
     (directory/'Directory.Packages.props').write_bytes(poison.read_bytes())
     (directory/'.editorconfig').write_text('root = true\n[*]\ncharset = utf-8\n')
     (directory/'.globalconfig').write_text('is_global = true\n')
     (directory/'Directory.Build.props').write_bytes(poison.read_bytes())
     (directory/'Directory.Build.targets').write_bytes(poison.read_bytes())
     for name in ['Directory.Build.rsp','MSBuild.rsp']:(directory/name).write_text('-p:CustomBeforeMicrosoftCommonTargets='+str(poison)+'\n')
    for home in [F.AUTHORITY.root/'home/.nuget/NuGet',F.AUTHORITY.root/'config/NuGet']:
     home.mkdir(parents=True,exist_ok=True);(home/'NuGet.Config').write_text('<configuration><packageSources><add key="POISON" value="https://untrusted.invalid/never" /></packageSources></configuration>')
    keys={'CustomBeforeMicrosoftCommonTargets':str(poison),'CustomAfterMicrosoftCommonTargets':str(poison),'MSBuildUserExtensionsPath':str(O/'ambient-user-targets'),'NUGET_PACKAGES':str(Path.home() / '.nuget/packages'),'RestoreConfigFile':str(O/'ambient-NuGet.Config'),'DirectoryPackagesPropsPath':str(poison),'CompilerResponseFile':str(O/'ambient-csc.rsp')}
    saved={k:os.environ.get(k) for k in keys};os.environ.update(keys)
    try:
     dlls,build=F.build_plugins(poisoned,O,'hardened-poison-build',dafny,dotnet,O/'logs')
     record('selectors-user-hooks-directory-packages-response-config-blocked',not marker.exists() and F.sha(dlls['method'])=='a4905de3b46e39fd819dc7ad5e5245bbae449080bc8f2e6039cc2de69f33b3fd' and F.sha(dlls['function'])=='af1f0fec7e98cd51e4172b8ff98826ed830eee18df4d8beaa91c812d617e68dd',build=build,poison_inputs={str(p):F.sha(p) for p in [poison,badcs]},environment_keys=sorted(keys))
    finally:
     for k,v in saved.items():
      if v is None:os.environ.pop(k,None)
      else:os.environ[k]=v
    # Missing installed pack: the host's normal caches exist, but the SDK must fail closed.
    missing=O/'missing-pack-root';shutil.copytree(F.AUTHORITY.root/'packs',missing);shutil.rmtree(missing/'Microsoft.NETCore.App.Ref')
    mbuild=O/'missing-pack-build';shutil.copytree(O/'frozen-package',mbuild)
    args=[dotnet,'msbuild',proj,*F.AUTHORITY.arguments(dafny.parent,packs=missing)]
    a,ta=F.run([*args,'-t:Restore','-v:minimal'],mbuild,O/'logs','missing-pack-restore')
    b,tb=F.run([*args,'-t:Build','-v:minimal'],mbuild,O/'logs','missing-pack-build')
    record('missing-private-pack-no-user-cache-fallback',a['exit']==0 and b['exit']==1 and 'NETSDK1127' in tb and not (mbuild/F.COMPONENT/'method-checker/bin/Debug/net6.0/KeccakMethodCoverage.dll').exists(),commands=[a,b])
    # Tampering the private config must reject before a process can consume it.
    original=F.AUTHORITY.config.read_bytes();F.AUTHORITY.config.write_text('<configuration><packageSources><add key="BAD" value="https://untrusted.invalid" /></packageSources></configuration>')
    try:
     try:F.AUTHORITY.verify();good=False
     except ValueError as e:good='isolated NuGet.Config changed' in str(e)
     record('tampered-private-config-rejected',good)
    finally:F.AUTHORITY.config.write_bytes(original)
    # Untrusted archive variants are rejected before any restore.
    first=manifest['packages'][0]['filename']
    def badzip(kind):
     stream=io.BytesIO()
     with zipfile.ZipFile(stream,'w') as z:
      if kind=='duplicate':z.writestr('dup','1');z.writestr('dup','2')
      elif kind=='symlink-member':
       i=zipfile.ZipInfo('link');i.create_system=3;i.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(i,'outside')
      else:z.writestr({'absolute':'/outside','traversal':'../outside','backslash':'dir\\outside'}[kind],'bad')
     return stream.getvalue()
    for name,needle in [('missing','missing/extra names'),('extra','missing/extra names'),('symlink-archive','symlink/nonfile'),('hash','authority hash'),('duplicate','duplicate'),('absolute','unsafe'),('traversal','unsafe'),('backslash','unsafe'),('symlink-member','symlink/special')]:
     d=O/'archive-controls'/name;d.mkdir(parents=True)
     for n,data in archives.items():(d/n).write_bytes(data)
     if name=='missing':(d/first).unlink()
     elif name=='extra':(d/'untrusted.nupkg').write_bytes(b'bad')
     elif name=='symlink-archive':(d/first).unlink();(d/first).symlink_to(F.AUTHORITY.root/'archives'/first)
     elif name=='hash':
      stream=io.BytesIO()
      with zipfile.ZipFile(stream,'w') as z:z.writestr('valid-but-unpinned','bad')
      (d/first).write_bytes(stream.getvalue())
     else:(d/first).write_bytes(badzip(name))
     try:F._build_authority.admit_archives(d,raw);good=False;error='accepted'
     except (ValueError,zipfile.BadZipFile) as e:error=str(e);good=needle in error
     record('archive-'+name+'-rejected',good,diagnostic=error)
    record('authority-still-immutable',F.AUTHORITY.immutable_before==F.AUTHORITY.immutable_map(),authority=F.AUTHORITY.record())
    passed = all(row['passed'] for row in rows)
    # These fixtures were deliberately visible at the private user paths, but
    # never imported. Return production isolation directories to their empty state.
    for root in (AUTHORITY.root / 'msbuild-user', AUTHORITY.root / 'home/.nuget',
                 AUTHORITY.root / 'config/NuGet'):
        if root.exists():
            for child in root.iterdir():
                if child.is_dir() and not child.is_symlink(): shutil.rmtree(child)
                else: child.unlink()
    return {'passed': passed, 'records': rows, 'fixture_files': file_map(O)}


def run_gate(args, source_bytes, edges, package_bytes, profile, dafny, dotnet, pins, pack_inputs):
    global AUTHORITY, BUILD_TOOLS
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    (out / 'logs').mkdir()
    (out / 'case-maps').mkdir()
    result = {'schema': 'microproxy.keccak-coverage/1', 'qualification': False,
              'scope': SCOPE, 'status': 'running', 'profile': args.profile,
              'source_root': str(args.source_root), 'combined_entries': list(COMBINED_ENTRIES),
              'source_map': {name: digest(data) for name, data in sorted(source_bytes.items())},
              'include_edges': edges, 'package_map': {name: digest(data) for name, data in sorted(package_bytes.items())},
              'tool_pins': pins, 'unused_profile_scope': 'legacy Select DLL, JDK and Maven runtime fields are not coverage inputs; solver is not invoked', 'cases': {'method': [], 'function': []}}
    def save(): json_write(out / 'result.json', result)
    save()
    try:
        source, package = out / 'frozen-source', out / 'frozen-package'
        materialize(source, source_bytes)
        materialize(package, package_bytes)
        manifest_raw = package_bytes[str(COMPONENT / 'encoder/net6-targeting-packs.json')]
        manifest, archives, payloads = pack_inputs
        AUTHORITY = _build_authority.BuildAuthority(out / 'build-authority', manifest_raw, archives, payloads, dotnet.parent)
        before = {'source': file_map(source), 'package': file_map(package),
                  'tools': tool_map(dafny.parent, dotnet.parent)}
        before['build_authority'] = AUTHORITY.immutable_before
        BUILD_TOOLS = before['tools']
        result['build_authority'] = AUTHORITY.record()
        json_write(out / 'inputs-before.json', before)
        result['versions'] = []
        for label, argv, expected in (
                ('dafny', [dafny, '--version'], profile['dafny_version']),
                ('sdk', [dotnet, '--version'], profile['dotnet_sdk'])):
            row, text = run(argv, package, out / 'logs', label + '-version', timeout=60)
            result['versions'].append(row)
            if row['exit'] != 0 or text.strip() != expected:
                raise GateError('reviewed tool version mismatch: ' + label)
        dlls, result['build'] = build_plugins(package, out, 'checker-build', dafny, dotnet, out / 'logs')
        save()
        result['admission_tests'] = admission_tests(out, args.source_root, args.profile,
                                                   package_bytes[str(PROFILE_DIR / (args.profile + '.json'))])
        result['combined'] = combined_resolve(source, out, out / 'logs', 'combined-resolve', dafny, dlls)
        if not result['combined']['passed']: raise GateError('combined same-program coverage failed')
        result['build_boundary_controls'] = build_boundary_controls(package, out, dafny, dotnet)
        if not result['build_boundary_controls']['passed']: raise GateError('build authority negative controls failed')
        result['immutable_input_probe'] = immutable_input_probe(source, package, source_bytes, package_bytes,
                                                               out, dafny, dotnet, dlls)
        save()
        for gate, cases in [('method', method_case_bytes(source_bytes)),
                            ('function', function_case_bytes(source_bytes))]:
            for case in cases:
                row = check_case(gate, case, out, dafny, dlls[gate])
                result['cases'][gate].append(row)
                save()
                print(gate, row['name'], 'PASS' if row['passed'] else 'FAIL', flush=True)
        after = {'source': file_map(source), 'package': file_map(package),
                 'tools': tool_map(dafny.parent, dotnet.parent)}
        after['build_authority'] = AUTHORITY.immutable_map()
        result['build_authority'] = AUTHORITY.record()
        json_write(out / 'inputs-after.json', after)
        result['inputs_unchanged'] = before == after
        result['dlls_after'] = {gate: sha(path) for gate, path in dlls.items()}
        result['dlls_unchanged'] = all(result['build']['dlls'][gate]['sha256'] == value
                                     for gate, value in result['dlls_after'].items())
        result['counts'] = {gate: {'total': len(rows), 'passed': sum(row['passed'] for row in rows),
                                   'positive': sum(row['expected_error'] is None for row in rows),
                                   'negative': sum(row['expected_error'] is not None for row in rows)}
                            for gate, rows in result['cases'].items()}
        passed = (result['build_boundary_controls']['passed'] and result['admission_tests']['passed'] and result['immutable_input_probe']['passed'] and
                  result['inputs_unchanged'] and result['dlls_unchanged'] and
                  result['counts']['method']['total'] == result['counts']['method']['passed'] == 61 and
                  result['counts']['function']['total'] == result['counts']['function']['passed'] == 18)
        result['status'] = 'passed' if passed else 'failed'
        save()
        print(json.dumps({'qualification': False, 'status': result['status'],
                          'counts': result['counts'], 'output': str(out)}, sort_keys=True))
        return 0 if passed else 1
    except Exception as error:
        result.update(status='failed', failure_kind='runner-or-tool-failure',
                      error_type=type(error).__name__, error=str(error))
        save()
        print(json.dumps({'qualification': False, 'status': 'failed', 'error': str(error),
                          'output': str(out)}, sort_keys=True))
        return 1


class Parser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({'qualification': False, 'status': 'rejected', 'error': message}, sort_keys=True))
        raise SystemExit(2)


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path, help='absolute complete actual source stage (no cache fallback)')
    parser.add_argument('--dafny', required=True, type=Path, help='absolute reviewed Dafny4.9.1 launcher')
    parser.add_argument('--dotnet', required=True, type=Path, help='absolute reviewed .NET launcher with SDK10.0.400')
    parser.add_argument('--profile', required=True, help='reviewed profile ID: ' + ', '.join(PROFILE_PINS))
    parser.add_argument('--targeting-packs', required=True, type=Path, help='absolute exact two-archive offline targeting-pack input directory')
    parser.add_argument('--output', required=True, type=Path, help='fresh absolute output outside Git/input roots')
    args = parser.parse_args(argv)
    try:
        for name in ('source_root', 'dafny', 'dotnet', 'targeting_packs', 'output'):
            if not getattr(args, name).is_absolute(): raise GateError('--' + name.replace('_', '-') + ' must be absolute')
        message = output_admission_error(args.output, args.source_root)
        if message is not None: raise GateError(message)
        if within(args.output.resolve(), args.targeting_packs.resolve()):
            raise GateError('output is inside the targeting-pack input root')
        if args.profile not in PROFILE_PINS: raise GateError('unsupported reviewed profile: ' + args.profile)
        package_bytes, profile = freeze_package_bytes(args.profile)
        dafny, dotnet, pins = check_tool_pins(profile, args.dafny, args.dotnet)
        pack_inputs = _build_authority.admit_archives(args.targeting_packs, package_bytes[str(COMPONENT / 'encoder/net6-targeting-packs.json')])
        for path in (args.output, dafny.parent, dotnet.parent):
            if any(c in str(path) for c in ';%$\r\n'):
                raise GateError('unsupported MSBuild property path characters')
        source_bytes, edges = freeze_source_bytes(args.source_root)
        return run_gate(args, source_bytes, edges, package_bytes, profile, dafny, dotnet, pins, pack_inputs)
    except Exception as error:
        print(json.dumps({'qualification': False, 'status': 'rejected', 'error': str(error)}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
