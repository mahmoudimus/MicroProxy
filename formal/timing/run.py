#!/usr/bin/env python3
"""Replay the V7 secret-trace certificate against actual generated classes.

Steps (any failure leaves an incomplete/failed report, never old success):
  1. verify pinned inputs and tool identities,
  2. verify SecretTrace.dfy and the compiled positive control,
  3. rebuild the pinned crypto sources with javac and require class identity
     with the selected canonical class directory (source -> class binding),
  4. extract a certificate from actual javap bytecode for every root, run the
     independent Python audit, and have Dafny check Structure and the universal
     two-run theorem,
  5. compile and check bytecode controls (positive constant-time fixture plus
     secret-branch/index/early-compare/exception/alloc/loop-bound mutants),
  6. mutate the actual Select certificate and require Dafny rejection,
  7. report generated-HKDF root status and the structured open roots/callees.

JVM timing is not addressed here. See threat-model.md.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import bytecode_trace as bt  # noqa: E402

# Reuse the reviewed bounded-process / report / pin helpers from formal/dafny.
sys.path.insert(0, str(HERE.parent / 'dafny'))
spec = importlib.util.spec_from_file_location('trace_replay_support', HERE.parent / 'dafny/run.py')
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
sys.path.pop(0)

DEFAULT_DAFNY = Path.home() / '.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'
DEFAULT_RUNTIME = Path.home() / '.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar'
FLAGS = ['--verification-time-limit', '30', '--resource-limit', '50000000',
         '--solver-option', 'O:smt.case_split=0']
VERIFIED = r'Dafny program verifier finished with (\d+) verified, (\d+) errors?'
EXPECTED_DAFNY_BUILD = '4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2'
EXPECTED_RUNTIME_SHA = 'dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6'
SHARED_TOOL_PINS = ('formal/dafny/run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json')


def require_exact_build(version: str):
    if version.strip() != EXPECTED_DAFNY_BUILD:
        raise RuntimeError('Unexpected Dafny build; require ' + EXPECTED_DAFNY_BUILD)


def check_runtime(runtime: Path):
    if not runtime.is_file():
        raise RuntimeError('DafnyRuntime 4.9.1 JAR not found at ' + str(runtime))
    actual = digest(runtime)
    if actual != EXPECTED_RUNTIME_SHA:
        raise RuntimeError('Unexpected DafnyRuntime checksum ' + actual + '; require ' + EXPECTED_RUNTIME_SHA)
    return actual


def tool_identity(jdk: Path) -> dict:
    result = {}
    for name in ('java', 'javac', 'javap'):
        path = java_tool(jdk, name)
        if not path.is_file():
            raise RuntimeError('Missing JDK tool ' + str(path))
        result[name] = {'path': str(path), 'sha256': digest(path)}
    for name in ('java', 'javac', 'javap'):
        command = [str(java_tool(jdk, name)), '-version']
        completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if completed.returncode:
            raise RuntimeError('JDK tool failed: ' + name)
        result[name]['version'] = (completed.stdout + completed.stderr).strip()
    return result


def check_toolchain(requested: Path, cache: Path, pins: dict) -> dict:
    for name in SHARED_TOOL_PINS:
        if name not in pins:
            raise RuntimeError('Shared tool installation policy is not pinned: ' + name)
    sys.path.insert(0, str(ROOT / 'formal/dafny'))
    try:
        from toolchain import install
    finally:
        sys.path.pop(0)
    official, compiler_runtime, manifest, asset = install(cache)
    requested = requested.expanduser().resolve()
    if requested != official.resolve():
        raise RuntimeError('Replay requires the checksum-pinned official Dafny distribution at '
                           + str(official.resolve()))
    version = subprocess.check_output([official, '--version'], text=True, timeout=30).strip()
    require_exact_build(version)
    solver = official.parent / 'z3/bin/z3-4.12.1'
    if not solver.is_file():
        raise RuntimeError('Pinned distribution has no reviewed solver at ' + str(solver))
    solver_version = subprocess.check_output([solver, '--version'], text=True, timeout=30).strip()
    if '4.12.1' not in solver_version:
        raise RuntimeError('Unexpected pinned solver version: ' + solver_version)
    return {
        'binary': str(official.resolve()), 'solver': str(solver.resolve()),
        'version': version, 'solver_version': solver_version,
        'binary_sha256': digest(official), 'solver_sha256': digest(solver),
        'compiler_runtime_sha256': digest(compiler_runtime),
        'archive_sha256': asset['sha256'], 'manifest_version': manifest['version'],
    }


def check_outside_target(output: Path):
    target = (ROOT / 'quic/target').resolve()
    if output.resolve().is_relative_to(target):
        raise RuntimeError('Evidence must not be written inside quic/target')


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_inputs(pins: dict):
    for name, expected in pins.items():
        path = ROOT / name
        if not path.is_file() or digest(path) != expected:
            raise RuntimeError('Pinned input changed; review before renewing: ' + name)


def java_tool(jdk: Path, name: str) -> Path:
    return jdk / 'bin' / name


def rebuild_classes(workspace: Path, jdk: Path, runtime: Path) -> Path:
    out = workspace / 'rebuilt-classes'
    out.mkdir()
    sources = [str(p) for p in (ROOT / 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto').rglob('*.java')]
    sources += [str(p) for p in (ROOT / 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf').rglob('*.java')]
    sources += [str(p) for p in (ROOT / 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto').rglob('*.java')]
    command = [str(java_tool(jdk, 'javac')), '-g', '--release', '21', '-cp', str(runtime), '-d', str(out)] + sources
    status, text = shared.execute(command, workspace / 'rebuild-javac.log', 600)
    if status:
        raise RuntimeError('Could not rebuild pinned crypto sources; see rebuild-javac.log')
    return out


ROOT_CLASSES = [
    'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/__default.class',
    'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.class',
    'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.class',
]
CRYPTO_CLASS_PREFIXES = (
    'io/github/mahmoudimus/quic/internal/verifiedcrypto/',
    'io/github/mahmoudimus/quic/internal/verifiedhkdf/',
    'io/github/mahmoudimus/verifiedcrypto/',
)


def bind_classes(workspace: Path, rebuilt: Path, production: Path) -> dict:
    if not production.is_dir():
        raise RuntimeError(str(production) + ' missing; provide a built canonical class directory')
    rebuilt_names = {p.relative_to(rebuilt).as_posix() for p in rebuilt.rglob('*.class')
                     if p.relative_to(rebuilt).as_posix().startswith(CRYPTO_CLASS_PREFIXES)}
    production_names = {p.relative_to(production).as_posix() for p in production.rglob('*.class')
                        if p.relative_to(production).as_posix().startswith(CRYPTO_CLASS_PREFIXES)}
    if not set(ROOT_CLASSES).issubset(rebuilt_names) or rebuilt_names != production_names:
        raise RuntimeError('Crypto class inventory differs between pinned-source rebuild and inspected classes')
    binding = {}
    for relative in sorted(rebuilt_names):
        prod = production / relative
        new = rebuilt / relative
        if not prod.is_file() or not new.is_file():
            raise RuntimeError('Missing class for binding: ' + relative)
        prod_hash, new_hash = digest(prod), digest(new)
        if prod_hash != new_hash:
            raise RuntimeError('Production class differs from a fresh build of pinned sources: ' + relative)
        binding[relative] = {'class_sha256': prod_hash, 'source_rebuild_sha256': new_hash}
    return binding


def owned_contracts(roots: list, policy: dict) -> list:
    """Expose every opaque owned call actually used by a certified caller.

    Class identity is checked separately. A callee's presence here is an
    assumption of the caller certificate, not a callee trace theorem.
    """
    targets = sorted({target for root in roots for target in root['call_targets']
                      if target.startswith('io/github/mahmoudimus/')})
    declared = set(policy.get('unchecked_owned_callees', []))
    if not set(targets).issubset(declared):
        raise RuntimeError('Opaque owned callee omitted from unchecked scope: '
                           + ', '.join(sorted(set(targets) - declared)))
    return [{'target': target, 'trace_status': 'assumed-not-traced',
             'kind': 'handwritten-JDK-adapter' if '/JdkHmac.' in target else 'generated-owned-helper',
             'contract': policy['calls'][target]} for target in targets]


def disassemble_root(javap: Path, classpath: Path, root: dict) -> bt.Method:
    methods = bt.disassemble(javap, classpath, root['class'])
    key = f"{root['name']}:{root['descriptor']}"
    if key not in methods:
        raise RuntimeError('Missing method ' + key + ' in ' + root['class'])
    return methods[key]


def emit_certificate(workspace: Path, name: str, result: dict) -> tuple[Path, str]:
    text = bt.certificate_module(name, result)
    text = text.replace('include "SecretTrace.dfy"',
                        'include "' + (HERE / 'SecretTrace.dfy').as_posix() + '"')
    path = workspace / (name + '.dfy')
    path.write_text(text)
    return path, text


def verify_certificate(workspace: Path, dafny: Path, solver: Path, path: Path,
                       timeout=300, flags=None) -> int:
    status, output = shared.execute([dafny, 'verify', path, '--solver-path', str(solver),
                                     *(flags or FLAGS)], path.with_suffix('.log'), timeout)
    return shared.check_verified(status, output, 1)


def mutate(result: dict, kind: str) -> dict:
    """Return a deep-ish copy of a certificate with one injected defect."""
    import copy
    mutant = copy.deepcopy(result)
    sec = [r for r, t in mutant['reg_taints'].items() if t == 'sec' and r < mutant['registers']]
    if not sec:
        raise RuntimeError('No secret register available for mutation')
    if kind in ('secret-guard', 'early-compare-guard'):
        inst = next(i for i in mutant['code'] if i['type'] == 'branch')
        inst['cond'] = sec[-1]
    elif kind == 'secret-index':
        inst = next(i for i in mutant['code']
                    if i['type'] == 'step' and i['kind'][0] in ('load', 'store'))
        if inst['kind'][0] == 'load':
            inst['kind'] = ('load', inst['kind'][1], sec[-1])
        else:
            inst['kind'] = ('store', inst['kind'][1], sec[-1], inst['kind'][3])
    elif kind == 'public-taint-launder':
        target = next(r for r in mutant['reg_taints']
                      if r < mutant['registers']
                      and mutant['reg_taints'][r] == 'sec'
                      and any(i['type'] == 'step' and i['dst'] == r and i['kind'][0] == 'load'
                              for i in mutant['code']))
        mutant['reg_taints'][target] = 'pub'
    else:
        raise RuntimeError('unknown mutation ' + kind)
    return mutant


def fixture_policy(policy: dict, fixture: dict) -> dict:
    return {
        'calls': {**policy['calls'], **fixture.get('calls', {})},
        'statics': policy['statics'],
        'classes': {fixture['class']: {
            'methods': {fixture['method']: {'params': fixture['params']}},
            'fields': fixture.get('fields', {}),
        }},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/timing-verification')
    parser.add_argument('--dafny', type=Path, default=DEFAULT_DAFNY)
    default_java = os.environ.get('JAVA_HOME') or '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'
    parser.add_argument('--java-home', type=Path, default=Path(default_java))
    parser.add_argument('--runtime', type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument('--classes', type=Path, default=ROOT / 'quic/target/classes',
                        help='Class directory to inspect (frozen canonical snapshot if provided).')
    parser.add_argument('--cache', type=Path,
                        default=Path(os.environ.get('MICROPROXY_FORMAL_CACHE', Path.home() / '.cache/microproxy-formal')))
    args = parser.parse_args(argv)
    output = args.output.expanduser().resolve()
    check_outside_target(output)
    output.mkdir(parents=True, exist_ok=True)
    with (output / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report_path = output / 'report.json'
        report_path.unlink(missing_ok=True)
        shared.atomic_report(report_path, {'status': 'incomplete'})
        old = signal.getsignal(signal.SIGTERM)
        def cancel(signum, frame):
            raise KeyboardInterrupt('timing replay cancelled')
        signal.signal(signal.SIGTERM, cancel)
        try:
            report = pipeline(args, output)
            shared.atomic_report(report_path, report)
        except Exception as error:  # noqa: BLE001 - report every failure
            shared.atomic_report(report_path, {'status': 'failed', 'error': str(error)})
            print(str(error), file=sys.stderr)
            return 1
        finally:
            signal.signal(signal.SIGTERM, old)
    print('Complete: ' + str(report_path), flush=True)
    return 0


def pipeline(args, output):
    workspace = Path(tempfile.mkdtemp(prefix='replay-', dir=output))
    pins = json.loads((HERE / 'inputs.json').read_text())['inputs']
    check_inputs(pins)
    policy = json.loads((HERE / 'policy.json').read_text())
    jdk = args.java_home.expanduser().resolve()
    runtime = args.runtime.expanduser().resolve()
    if not (jdk / 'bin/javac').is_file():
        raise RuntimeError('Set --java-home/JAVA_HOME to a JDK 21+ installation')
    # Identity gates run before any proof or bytecode execution.
    jdk_before = tool_identity(jdk)
    runtime_sha = check_runtime(runtime)
    tools = check_toolchain(args.dafny, args.cache, pins)
    dafny = Path(tools['binary'])
    solver = Path(tools['solver'])
    version = tools['version']
    solver_version = tools['solver_version']
    javap = java_tool(jdk, 'javap')
    commands = []

    def call(name, command, timeout=300):
        commands.append({'step': name, 'command': [str(c) for c in command]})
        return shared.execute(command, workspace / (name + '.log'), timeout)
    status, java_version = call('java-version', [java_tool(jdk, 'java'), '-version'])
    if status:
        raise RuntimeError('JDK unavailable')

    model = shared.check_verified(*call('secret-trace-model', [dafny, 'verify', HERE / 'SecretTrace.dfy', '--solver-path', str(solver), *FLAGS]), 40)
    shape = shared.check_verified(*call('hkdf-source-shape', [dafny, 'verify', HERE / 'HkdfShape.dfy',
        '--allow-external-contracts', '--solver-path', str(solver), *FLAGS]), 15)
    model_dir = workspace / 'model'
    model_dir.mkdir()
    for name in ('SecretTrace.dfy', 'PositiveTraceCheck.dfy'):
        shutil.copyfile(HERE / name, model_dir / name)
    status, run_out = call('positive-compiled', [dafny, 'run', '--no-verify', model_dir / 'PositiveTraceCheck.dfy'])
    if status or 'positive-control-ok' not in run_out:
        raise RuntimeError('Compiled positive control failed')
    positive = 'executed'

    rebuilt = rebuild_classes(workspace, jdk, runtime)
    inspected = args.classes.expanduser().resolve()
    binding = bind_classes(workspace, rebuilt, inspected)

    roots = []
    for root in policy['roots']:
        name = root['class'].split('.')[-1] + '_' + root['name']
        method = disassemble_root(javap, inspected, root)
        class_policy = policy['classes'][root['class'].replace('.', '/')]
        result = bt.translate(method, policy, class_policy)
        failures = bt.audit_certificate(result)
        if failures:
            raise RuntimeError(f'{name}: independent audit rejected the certificate: {failures[:3]}')
        path, _ = emit_certificate(workspace, name, result)
        limits = policy.get('limits', {}).get(root['name'], {})
        if limits:
            root_flags = ['--verification-time-limit', str(limits['time']),
                          '--resource-limit', str(limits['resources'])]
            for option in limits.get('solver_options', ['O:smt.case_split=0']):
                root_flags.extend(['--solver-option', option])
        else:
            root_flags = FLAGS
        verified = verify_certificate(workspace, dafny, solver, path, flags=root_flags)
        source = root['class'].replace('.', '/') + '.java'
        roots.append({
            'verify_command': [str(dafny), 'verify', str(path), '--solver-path', str(solver), *root_flags],
            'class': root['class'], 'method': f"{method.name}:{method.descriptor}", 'status': 'checked',
            'obligations': verified, 'certificate': path.name,
            'certificate_sha256': digest(path),
            'registers': result['registers'], 'instructions': len(result['code']),
            'instructions_reachable': result['instructions_reachable'],
            'cfg_edges_checked': result.get('cfg_edges_checked', False),
            'roles': result['roles'], 'call_targets': result['call_targets'],
            'bytecode_sites': result['sites'],
            'source_sha256': digest(ROOT / ('quic/src/main/java/' + source)),
            'source_rebuild_sha256': binding_root(binding, root['class']),
            'solver_limits': limits or {'time': 30, 'resources': 50000000},
        })

    fixture_root = workspace / 'fixtures'
    fixture_root.mkdir()
    fixture_sources = sorted((HERE / 'fixtures').glob('*.java'))
    status, text = call('fixture-compile', [str(java_tool(jdk, 'javac')), '-g', '--release', '21',
                                            '-d', str(fixture_root)] + [str(p) for p in fixture_sources])
    if status:
        raise RuntimeError('Fixture compilation failed')
    fixtures = {}
    for spec in policy['fixtures']:
        methods = bt.disassemble(javap, fixture_root, spec['class'])
        key = spec['method']
        fp = fixture_policy(policy, {'class': spec['class'], 'method': key, 'params': spec['params'],
                                     'fields': spec.get('fields', {}), 'calls': spec.get('calls', {})})
        try:
            result = bt.translate(methods[key], fp, fp['classes'][spec['class']])
            failures = bt.audit_certificate(result)
            rejected = bool(failures)
            reason = failures[0]['problem'] if failures else None
        except bt.PolicyError as error:
            result, rejected, reason = None, True, str(error)
        if spec['expect'] == 'accept':
            if rejected:
                raise RuntimeError('Positive bytecode fixture was rejected: ' + str(reason))
            path, _ = emit_certificate(workspace, 'Fixture_' + spec['class'], result)
            if result['instructions_reachable'] != len(result['code']):
                raise RuntimeError('Positive fixture certificate is not fully reachable: ' + spec['class'])
            fixtures[spec['class']] = {'expect': 'accept', 'status': 'checked',
                                       'obligations': verify_certificate(workspace, dafny, solver, path),
                                       'instructions': len(result['code']),
                                       'instructions_reachable': result['instructions_reachable'],
                                       'cfg_edges_checked': result.get('cfg_edges_checked', False),
                                       'certificate_sha256': digest(path)}
        else:
            if not rejected:
                raise RuntimeError('Mutant bytecode fixture was accepted: ' + spec['class'])
            fixtures[spec['class']] = {'expect': 'reject', 'status': 'rejected', 'reason': reason}

    select = next(r for r in roots if r['method'].startswith('Select:'))
    select_method = disassemble_root(javap, inspected, {'class': select['class'], 'name': 'Select',
                                                        'descriptor': select['method'].split(':', 1)[1]})
    class_policy = policy['classes'][select['class'].replace('.', '/')]
    select_result = bt.translate(select_method, policy, class_policy)
    mutants = {}
    for kind in ('secret-guard', 'secret-index', 'early-compare-guard', 'public-taint-launder'):
        mutant = mutate(select_result, kind)
        text = bt.certificate_module('Mutant_' + kind.replace('-', '_'), mutant, check_only=True)
        text = text.replace('include "SecretTrace.dfy"',
                            'include "' + (HERE / 'SecretTrace.dfy').as_posix() + '"')
        path = workspace / ('Mutant_' + kind.replace('-', '_') + '.dfy')
        path.write_text(text)
        status, out = call('mutant-' + kind, [dafny, 'verify', path, '--solver-path', str(solver), *FLAGS])
        if status != 4 or not re.search(r'Error:.*(postcondition|precondition|assertion)', out):
            raise RuntimeError('Mutant did not fail a proof obligation cleanly: ' + kind)
        if re.search(r'time.?out|out of resource|out of memory|internal error|unhandled exception', out, re.I):
            raise RuntimeError('Mutant failure was a resource/crash, not a proof obligation: ' + kind)
        mutants[kind] = {'status': 'proof-obligation-rejected',
                         'diagnostic': re.search(r'Error:[^\n]*', out).group(0)}

    hkdf = {'generated_package': 'io.github.mahmoudimus.quic.internal.verifiedhkdf',
            'checked_roots': [r['method'] for r in roots if 'verifiedhkdf' in r['class']],
            'open_roots': [r for r in policy.get('open_roots', []) if 'verifiedhkdf' in r['class']],
            'note': 'Generated functional kernel roots are checked. The final canonical21 build exists; '
                    'HKDF adapter/bridge roots remain open only because of owned object/type/dispatch/'
                    'exception restrictions and the reviewed adapter boundary, not a missing build.'}

    check_inputs(pins)
    # Revalidate tool/runtime/JDK identities after the full replay.
    tools_after = check_toolchain(dafny, args.cache, pins)
    if tools_after != tools:
        raise RuntimeError('Pinned tool distribution changed during replay')
    if check_runtime(runtime) != runtime_sha:
        raise RuntimeError('DafnyRuntime changed during replay')
    jdk_after = tool_identity(jdk)
    if jdk_after != jdk_before:
        raise RuntimeError('JDK inputs changed during replay')
    return {
        'status': 'complete',
        'scope': 'Extracted actual-bytecode certificates under the SecretTrace observer',
        'jvm_timing': 'deferred; no JVM/JIT/CPU/provider timing claim',
        'dafny_version': version.strip(), 'solver_version': solver_version.strip(),
        'solver_options': FLAGS, 'java_version': java_version.strip(),
        'runtime_sha256': runtime_sha,
        'tools': tools, 'jdk_identity': jdk_before,
        'model_obligations': model, 'hkdf_shape_obligations': shape,
        'positive_control': positive,
        'roots': roots, 'fixtures': fixtures, 'certificate_mutants': mutants,
        'hkdf': hkdf, 'inputs': pins, 'class_binding': binding,
        'open_roots': policy.get('open_roots', []),
        'unchecked_owned_callees': policy.get('unchecked_owned_callees', []),
        'assumed_owned_callees': owned_contracts(roots, policy),
        'caller_skeleton': [r for r in policy.get('open_roots', []) if r.get('status') == 'caller-skeleton-unsupported'],
        'commands': commands, 'workspace': str(workspace),
        'trusted': ['Dafny/Boogie/Z3', 'javap parser and operand mapping',
                    'declared policy of public/secret parameters, fields, allocations and call results',
                    'javac/JVM word-operation observer (atomic, operand-independent cost)',
                    'enumerated external contracts: JDK HMAC/SHA3, DafnyRuntime, JDK BigInteger/String/boxed deterministic calls',
                    'opaque owned helper/adapter contracts listed in assumed_owned_callees; these are not callee trace proofs'],
        'excluded': ['JVM/JIT/CPU/GC/provider timing', 'implicit JVM exceptions and null checks',
                     'exact arithmetic/value refinement (dependency shape only)',
                     'cryptographic hardness and entropy',
                     'physical secret erasure', 'unchecked owned callee closure (Encrypt/Decrypt/ExpandMatrix/etc.)',
                     'adapter/bridge trace roots open for semantic refinement; final canonical21 build exists', 'JVM dispatch type/identity theorem'],
    }


def binding_root(binding: dict, class_name: str) -> dict:
    path = class_name.replace('.', '/') + '.class'
    return binding.get(path, {})


if __name__ == '__main__':
    raise SystemExit(main())
