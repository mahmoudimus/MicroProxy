#!/usr/bin/env python3
"""Current-epoch native SHAKE functional consumer, with explicit external input authorities.

Preserves the original replay's proof/audit/control/oracle/runtime policy. This successor changes
only source-root authority and the five mutation anchors whose ABI gained erased ghost results.
No parent-epoch qualification, delivery, timing, erasure, or production-adoption claim is made.
"""
import argparse
import hashlib
import _hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import ssl
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
SHA = re.compile(r'[0-9a-f]{64}\Z')
PORTS = {
    'wipe-scratch': ['wipeScratchTrace := K.Wipe(scratch);', 'wipeScratchTrace := [];'],
    'wipe-parity': ['wipeParityTrace := K.Wipe(parity);', 'wipeParityTrace := [];'],
    'round-constant': ['{ if i == 0 then (0x0000000000000001, ghost', '{ if i == 0 then (0x0000000000000000, ghost'],
    'rotation-table': ['else if i == 2 then (62, ghost', 'else if i == 2 then (61, ghost'],
    'source-table': ['else if i == 1 then (6, ghost', 'else if i == 1 then (7, ghost'],
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def map_sha(mapping):
    return digest((json.dumps(mapping, sort_keys=True, separators=(',', ':')) + '\n').encode())


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute path without parent traversal required')
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        require(not cursor.is_symlink(), 'symlink path component: ' + str(cursor))
    return path


def file_bytes(path):
    path = absolute(path)
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular unaliased input required: ' + str(path))
    data = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    require((before.st_dev, before.st_ino, before.st_size, before.st_nlink) ==
            (after.st_dev, after.st_ino, len(data), 1), 'input identity changed: ' + str(path))
    return data


def sha(path):
    return digest(file_bytes(path))


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def authenticated_json(path, expected):
    require(isinstance(expected, str) and SHA.fullmatch(expected), 'invalid external expected digest')
    raw = file_bytes(path)
    require(digest(raw) == expected, 'input differs from external expected digest: ' + str(path))
    value = json.loads(raw, object_pairs_hook=no_duplicates)
    require(type(value) is dict, 'expected JSON object')
    return value


def relative(name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name
            and all(ord(c) >= 32 for c in name), 'unsafe relative input')
    p = PurePosixPath(name)
    require(not p.is_absolute() and str(p) == name and all(x not in ('', '.', '..') for x in name.split('/')),
            'unsafe relative input: ' + name)
    return name


def mapped_files(root):
    root = absolute(root)
    result = {}
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            require(not (Path(parent) / name).is_symlink(), 'symlink in input tree')
        for name in files:
            p = Path(parent) / name
            result[p.relative_to(root).as_posix()] = sha(p)
    return result


def check_map(root, pins):
    for name, expected in pins.items():
        require(SHA.fullmatch(expected) and sha(root / relative(name)) == expected, 'input hash changed: ' + name)


def include_closure(root, pins, entry):
    root = absolute(root)
    found = set()

    def visit(path):
        # Resolve lexical '..' in legitimate local includes, then require a mapped root-local file.
        require(not path.is_symlink(), 'symlink include')
        path = path.resolve()
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError('unmapped include outside source root') from error
        require(name in pins, 'unmapped include: ' + name)
        require(sha(path) == pins[name], 'include source hash changed: ' + name)
        if name in found:
            return
        found.add(name)
        source = file_bytes(path).decode()
        includes = re.findall(r'^\s*include\s+"([^"\n]+)"\s*$', source, re.M)
        require(len(includes) == len(re.findall(r'^\s*include\b', source, re.M)), 'unsupported include syntax: ' + name)
        for child in includes:
            require(not Path(child).is_absolute() and '\\' not in child and ':' not in child, 'unsafe include syntax')
            visit(path.parent / child)

    visit(root / relative(entry))
    return sorted(found)


def error_locations(output):
    return [{'file': m[1], 'line': int(m[2]), 'column': int(m[3]), 'message': m[4]}
            for m in re.finditer(r'^(formal/[^()\n]+)\((\d+),(\d+)\): Error: (.+)$', output, re.M)]


def require_errors(output, expected):
    actual = error_locations(output)
    require(actual == expected, 'intended semantic error locations changed: ' + repr(actual))
    return actual


def output_admission(output, protected):
    output = absolute(output)
    require(output.parent.is_dir(), 'output parent must exist')
    parent_ids = {(p.stat().st_dev, p.stat().st_ino) for p in (output.parent, *output.parent.parents)}
    existing_id = (output.stat().st_dev, output.stat().st_ino) if output.exists() else None
    for root in protected:
        root = absolute(root)
        ancestors = (root, *root.parents)
        root_ids = {(p.stat().st_dev, p.stat().st_ino) for p in ancestors}
        require((root.stat().st_dev, root.stat().st_ino) not in parent_ids and existing_id not in root_ids,
                'output overlaps a protected input: ' + str(root))
    require(not os.path.lexists(output), 'output already exists')


def load(name, path, expected):
    data = file_bytes(path)
    require(isinstance(expected, str) and SHA.fullmatch(expected) and digest(data) == expected,
            'executable bytes differ from selected digest: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Execute the authenticated source bytes, never a timestamp-valid but unpinned .pyc.
    # Registration preserves ordinary module context for annotations and imports.
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(data, str(path), 'exec'), module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


def authenticate_source(root, epoch, authority):
    require(epoch['schema'] == 'microproxy.keccak-source-epoch/1' and epoch['epoch'] == 'keccak-004', 'source epoch changed')
    sources = epoch['current']['sources']
    require(len(sources) == 85 and map_sha(sources) == authority['source_map_sha256'] == epoch['current']['map_sha256'],
            'current 85-source authority changed')
    files = {**sources, **epoch['support_inputs'], **epoch['current_tooling'],
             epoch['paired_harness']['template']: epoch['paired_harness']['sha256']}
    require(mapped_files(root) == files, 'authenticated current view inventory/hash differs')
    closure = include_closure(root, sources, authority['entry'])
    require(closure == authority['closure'], 'complete include closure changed')
    return sources, files, closure


def checked_controls(helper, authority):
    controls = authority['controls']
    originals = [(r['name'], r['source'], r['symbol'], *r['original']) for r in controls]
    require(originals == helper.CONTROLS and len(controls) == 22, 'original control inventory changed')
    for row in controls:
        require(row['mutation'] == PORTS.get(row['name'], row['original']), 'unapproved mutation port')
        require(row['errors'], 'missing intended semantic error locations')
    require(authority['flags'] == helper.FLAGS and authority['expected_tests'] == helper.EXPECTED_TESTS,
            'original solver policy/test inventory changed')
    return controls


def tool_snapshot(helper, dafny, archive, runtime, homes):
    oracle = [Path(sys.executable).resolve(), Path(hashlib.__file__).resolve(), Path(_hashlib.__file__).resolve()]
    return {'dafny_distribution': helper.tree(dafny.parent.parent),
            'dafny_archive_sha256': helper.sha(archive),
            'selected_runtime': {'path': str(runtime), 'sha256': helper.sha(runtime)},
            'java_homes': [{'home': str(home), 'files': helper.tree(home)} for home in homes],
            'python_oracle': helper.snapshot(oracle), 'python': sys.version,
            'openssl': ssl.OPENSSL_VERSION, 'platform': platform.platform()}


def child_environment(parent, home, temporary):
    # Commands are absolute pinned executables. Retain host locale settings only;
    # unknown JVM, compiler, managed/native loader and future option selectors never pass through.
    home, temporary = absolute(home), absolute(temporary)
    require(home.is_dir() and temporary.is_dir() and not any(home.iterdir()) and not any(temporary.iterdir()),
            'fresh private child home and temporary directories required')
    allowed = ('LANG', 'LC_ALL', 'LC_CTYPE', 'TZ')
    env = {key: parent[key] for key in allowed if key in parent}
    env.update({'HOME': str(home), 'TMPDIR': str(temporary), 'TMP': str(temporary), 'TEMP': str(temporary)})
    env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'
    return env


def java_command(java_home, tool, home, temporary, arguments):
    require(tool in ('java', 'javac', 'javap'), 'unsupported JVM tool')
    prefix = '' if tool == 'java' else '-J'
    properties = [prefix + '-Duser.home=' + str(home), prefix + '-Djava.io.tmpdir=' + str(temporary)]
    return list(map(str, [java_home / 'bin' / tool, *properties, *arguments]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inputs', 'source-root', 'source-manifest', 'helper-root', 'tools-manifest', 'dafny-cache',
                 'runtime-jar', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('expected-inputs-sha256', 'expected-source-manifest-sha256', 'expected-tools-sha256', 'runtime-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--java-home', type=Path, action='append', required=True, help='JDK21, then JDK25; exactly two')
    args = parser.parse_args()
    require(len(args.java_home) == 2, 'select exactly JDK21 and JDK25 in order')
    homes = [p.resolve(strict=True) for p in args.java_home]
    source_root, helper_root = absolute(args.source_root), absolute(args.helper_root)
    authority = authenticated_json(args.inputs, args.expected_inputs_sha256)
    require(authority['schema'] == 'microproxy.keccak004-shake-inputs/1' and authority['qualification'] is False
            and authority['scope'] == 'functional-consumer-only', 'successor scope/schema changed')
    require(args.expected_source_manifest_sha256 == authority['source_epoch_manifest_sha256'], 'source authority selection changed')
    epoch = authenticated_json(args.source_manifest, args.expected_source_manifest_sha256)
    constructor = helper_root / 'formal/source/epochs/keccak-004/views.py'
    require(sha(constructor) == authority['source_view_constructor_sha256'], 'source-view constructor hash changed')
    view = load('current_shake_source_view_policy', constructor, authority['source_view_constructor_sha256'])
    view.validate_manifest(epoch)
    source_map, view_files, closure = authenticate_source(source_root, epoch, authority)
    check_map(helper_root, authority['helpers'])  # authenticate executable helpers BEFORE importing.
    tools = authenticated_json(args.tools_manifest, args.expected_tools_sha256)
    require(tools['schema'] == 'microproxy.keccak004-shake-tools/1', 'tool authority schema changed')
    runtime = absolute(args.runtime_jar)
    require(args.runtime_sha256 == authority['runtime_sha256'] == sha(runtime), 'selected Maven runtime identity changed')
    official_tools = authenticated_json(helper_root / 'formal/dafny/tools.json',
                                       authority['helpers']['formal/dafny/tools.json'])
    selected_asset = official_tools['assets'][platform.system() + '-' + platform.machine()]
    protected = [source_root, helper_root, args.inputs.parent, args.source_manifest.parent,
                 args.tools_manifest.parent, args.dafny_cache / selected_asset['directory'],
                 args.dafny_cache / selected_asset['archive'], runtime, *homes]
    output_admission(args.output, protected)
    before = {'source_view': view_files, 'helpers': dict(authority['helpers']),
              'source_manifest': sha(args.source_manifest), 'inputs_manifest': sha(args.inputs),
              'tools_manifest': sha(args.tools_manifest), 'source_view_constructor': sha(constructor),
              'runner': sha(Path(__file__).absolute())}
    out = args.output
    out.mkdir(mode=0o700)
    frozen = out / 'inputs'
    # The complete current source view is frozen byte-for-byte; helper files add no production sources.
    for name in sorted(set(view_files) | set(authority['helpers'])):
        origin = source_root / name if name in view_files else helper_root / name
        if name in view_files and name in authority['helpers']:
            require(view_files[name] == authority['helpers'][name], 'source/helper authority disagreement')
        target = frozen / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_bytes(origin))
    for name, origin in [('inputs.json', args.inputs), ('source-manifest.json', args.source_manifest),
                         ('tools-manifest.json', args.tools_manifest), ('replay.py', Path(__file__).absolute())]:
        (out / name).write_bytes(file_bytes(origin))
    frozen_map = mapped_files(frozen)
    require(frozen_map == {**view_files, **authority['helpers']}, 'frozen input copy differs')
    require(include_closure(frozen, source_map, authority['entry']) == closure, 'frozen include graph changed')
    helper = load('current_shake_unchanged_native_helper', frozen / 'formal/crypto/native_shake_checks.py',
                  authority['helpers']['formal/crypto/native_shake_checks.py'])
    controls = checked_controls(helper, authority)
    toolchain = load('current_shake_unchanged_toolchain', frozen / 'formal/dafny/toolchain.py',
                     authority['helpers']['formal/dafny/toolchain.py'])
    dafny, _, manifest, asset = toolchain.install(absolute(args.dafny_cache))
    require(manifest['version'] == '4.9.1', 'official Dafny version changed')
    solver = dafny.parent / 'z3/bin/z3-4.12.1'
    flags = [*helper.FLAGS, '--solver-path', str(solver)]
    tools_before = tool_snapshot(helper, dafny, args.dafny_cache / asset['archive'], runtime, homes)
    require(tools_before == tools['identities'], 'installed tools differ from externally selected identities')
    receipt = {'schema': 'microproxy.keccak004-shake-functional/1', 'qualification': False,
               'scope': 'functional-consumer-only', 'status': 'running', 'commands': [], 'proofs': {},
               'audits': {}, 'controls': {}, 'java': [], 'source_root': str(source_root),
               'source_manifest': str(args.source_manifest), 'inputs_manifest': str(args.inputs),
               'tools_manifest': str(args.tools_manifest), 'snapshot_root': str(frozen),
               'inputs_before': before, 'tools_before': tools_before, 'toolchain_asset': asset,
               'limits': 'Finite functional replay only. Parent current epoch/delivery qualification is pending; no timing, erasure or adoption claim.'}
    # Read-only snapshots make accidental source writes fail early, with hashes still rechecked at end.
    for p in frozen.rglob('*'):
        if p.is_file():
            p.chmod(0o444)
    child_home, child_temporary = out / 'child-home', out / 'child-temporary'
    child_home.mkdir(mode=0o700)
    child_temporary.mkdir(mode=0o700)
    env = child_environment(os.environ, child_home, child_temporary)
    receipt['child_environment'] = {'values': env, 'home_initial_files': mapped_files(child_home),
                                    'temporary_initial_files': mapped_files(child_temporary),
                                    'policy': 'only host locale/TZ; fresh empty private HOME/temp; fixed system PATH',
                                    'jvm_properties': {'user.home': str(child_home), 'java.io.tmpdir': str(child_temporary)}}

    def jdk(home, tool, *arguments):
        return java_command(home, tool, child_home, child_temporary, arguments)

    def call(label, argv, cwd=frozen):
        argv = list(map(str, argv))
        print(label, flush=True)
        started = time.monotonic()
        process = subprocess.Popen(argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            output, _ = process.communicate(timeout=600)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
            (out / (label + '.log')).write_text(output)
            raise
        log = out / (label + '.log')
        log.write_text(output)
        record = {'label': label, 'command': argv, 'cwd': str(cwd), 'exit': process.returncode,
                  'seconds': time.monotonic() - started, 'log': log.name, 'log_sha256': sha(log)}
        receipt['commands'].append(record)
        # Progress is deliberately not a success receipt; failure exits cannot emit status complete.
        (out / 'progress.json').write_text(json.dumps(receipt, indent=2) + '\n')
        return process.returncode, output

    status, version = call('dafny-version', [dafny, '--version'])
    require(status == 0 and version.startswith('4.9.1+'), 'Dafny version mismatch')
    status, version = call('z3-version', [solver, '--version'])
    require(status == 0 and 'Z3 version 4.12.1' in version, 'Z3 version mismatch')
    for name in closure:
        target = frozen / name
        status, output = call('audit-' + target.stem, [dafny, 'audit', target])
        require(status == 0 and not helper.shared.BAD_DIAGNOSTIC.search(output)
                and 'Dafny auditor completed with 0 findings' in output, 'assumption audit failed: ' + name)
        receipt['audits'][name] = 0
        status, output = call('proof-' + target.stem, [dafny, 'verify', target, *flags])
        receipt['proofs'][name] = helper.proof_result(status, output)
    for row in controls:
        name, stem, symbol = row['name'], row['source'], row['symbol']
        folder = out / 'controls' / name
        witness = helper.mutations(folder, [frozen / n for n in closure], name, stem, *row['mutation'], frozen)
        target = folder / 'formal/crypto' / ('native_shake_domain.dfy' if name.startswith('domain-') else stem + '.dfy')
        mutant_before = helper.tree(folder, '*.dfy')
        extra = []
        if name == 'round-count':
            positions = [i+1 for i, line in enumerate(target.read_text().splitlines()) if line.strip() == 'assert completed == 24;']
            require(len(positions) == 1, 'erased round-count assertion changed')
            extra = ['--isolate-assertions', '--filter-position', target.name + ':' + str(positions[0])]
        status, output = call('resolve-' + name, [dafny, 'resolve', target], folder)
        require(status == 0 and not helper.shared.BAD_DIAGNOSTIC.search(output), 'control did not plainly resolve: ' + name)
        status, output = call('control-' + name, [dafny, 'verify', target, '--filter-symbol', symbol, *extra, *flags], folder)
        result = helper.proof_result(status, output, negative=True)
        result['errors_at'] = require_errors(output, row['errors'])
        require(mutant_before == helper.tree(folder, '*.dfy'), 'mutant source drift: ' + name)
        result.update({'inputs_before': mutant_before, 'inputs_after': helper.tree(folder, '*.dfy'),
                       'symbol': symbol, 'plain_resolve_exit': 0, 'ported_anchor': name in PORTS})
        if witness:
            result['negative_control_witness'] = witness
        receipt['controls'][name] = result
    vectors = out / 'hashlib-vectors.tsv'
    inventory = helper.shared.vectors(vectors)
    tests = helper.expected_inventory(inventory)
    require(sha(vectors) == authority['vectors_sha256'], 'pinned independent vector inventory changed')
    status, output = call('generate-java', [dafny, 'translate', 'java', frozen / 'formal/crypto/NativeShake.dfy',
                                          '--output', out / 'NativeShake', *flags])
    receipt['generation'] = helper.proof_result(status, output)
    generated = out / 'NativeShake-java'
    generated_before = helper.tree(generated, '*.java')
    require(generated_before, 'no generated Java')
    classes = out / 'classes'
    classes.mkdir()
    status, output = call('javac', jdk(homes[0], 'javac', '--release', '21', '-cp', runtime, '-d', classes,
                                  *sorted(generated.rglob('*.java')),
                                  frozen / 'formal/crypto/native_shake_java/io/github/mahmoudimus/quic/tls/NativeShakeTest.java',
                                  frozen / 'formal/crypto/reference/Shake.java'))
    require(status == 0 and 'warning:' not in output.lower(), 'generated compilation failed or warned')
    classes_before = helper.tree(classes, '*.class')
    for major, home in zip((21, 25), homes):
        status, version = call('java-' + str(major) + '-version', jdk(home, 'java', '-version'))
        require(status == 0 and re.search(r'version "' + str(major) + r'[.\"]', version), 'JDK version mismatch')
        status, output = call('java-' + str(major), jdk(home, 'java', '-Xmx1024m', '-ea', '-cp',
            str(classes) + os.pathsep + str(runtime), 'io.github.mahmoudimus.quic.tls.NativeShakeTest', vectors))
        matches = re.findall(r'^PASS NativeShakeTest (\{.*\})$', output, re.M)
        require(status == 0 and len(matches) == 1 and json.loads(matches[0]) == tests, 'exact Java inventory failed')
        receipt['java'].append({'major': major, 'version': version, 'tests': json.loads(matches[0])})
    status, bytecode = call('native-bytecode', jdk(homes[0], 'javap', '-c', '-p', '-cp', classes,
                            'NativeKeccak.__default', 'NativeShake.__default', 'NativeShake.Sponge'))
    require(status == 0, 'native bytecode inspection failed')
    receipt['native_runtime_audit'] = helper.native_audit(generated, bytecode)
    for label, cp, classname in [('types', classes, 'NativeTypes.I'), ('euclidean', runtime, 'dafny.DafnyEuclidean'),
                                ('helpers', runtime, 'dafny.Helpers'), ('descriptor', runtime, 'dafny.TypeDescriptor')]:
        status, _ = call('runtime-' + label + '-bytecode', jdk(homes[0], 'javap', '-c', '-p', '-cp', cp, classname))
        require(status == 0, 'runtime inspection failed: ' + classname)
    source_after, view_after, closure_after = authenticate_source(source_root, epoch, authority)
    check_map(helper_root, authority['helpers'])
    after = {'source_view': view_after, 'helpers': {n: sha(helper_root / n) for n in authority['helpers']},
             'source_manifest': sha(args.source_manifest), 'inputs_manifest': sha(args.inputs),
             'tools_manifest': sha(args.tools_manifest), 'source_view_constructor': sha(constructor),
             'runner': sha(Path(__file__).absolute())}
    require(before == after and source_after == source_map and closure_after == closure, 'source/input drift')
    require(mapped_files(frozen) == frozen_map, 'frozen inputs changed')
    tools_after = tool_snapshot(helper, dafny, args.dafny_cache / asset['archive'], runtime, homes)
    require(tools_before == tools_after, 'compiler/solver/runtime/JDK/Python oracle drift')
    generated_after, classes_after = helper.tree(generated, '*.java'), helper.tree(classes, '*.class')
    require(generated_before == generated_after and classes_before == classes_after, 'generated or compiled artifact drift')
    require(sha(vectors) == authority['vectors_sha256'], 'independent vectors changed')
    require(len(receipt['controls']) == 22 and len(receipt['proofs']) == len(closure) == 8, 'incomplete proof/control inventory')
    receipt.update({'status': 'complete', 'inputs_after': after, 'tools_after': tools_after,
                    'frozen_inputs_before': frozen_map, 'frozen_inputs_after': mapped_files(frozen),
                    'source_map_before': source_map, 'source_map_after': source_after,
                    'generated_java_before': generated_before, 'generated_java_after': generated_after,
                    'compiled_classes_before': classes_before, 'compiled_classes_after': classes_after,
                    'vectors': {'sha256': sha(vectors), 'count': len(inventory), 'inventory': inventory},
                    'runtime_sha256': sha(runtime), 'complete_include_closure': closure,
                    'inputs_before_after_match': True})
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'output': str(out), 'qualification': False, 'scope': receipt['scope'],
                      'proofs': receipt['proofs'], 'controls': len(receipt['controls']), 'java': receipt['java']}, indent=2))


if __name__ == '__main__':
    main()
