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
import composition as comp  # noqa: E402
import trace_exec  # noqa: E402

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
    'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.class',
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


def check_proof_rejected(status: int, output: str) -> str:
    """Strict acceptance gate for a *normal* proof-obligation failure.

    Same shape as `formal/dafny/run.py:check_rejected` (single completed summary
    line with non-zero errors, no crash/timeout/resource text) plus the
    diagnostics Dafny emits for the generated `forall`/`assert` structure. Used
    for both the `Select` mutants and the callee mutants so neither can be
    recorded as rejected by a resource/crash result (F9).
    """
    summaries = re.findall(shared.SUMMARY, output)
    bad_run = re.search(r'time.?out|out of resource|out of memory|internal error|unhandled exception',
                        output, re.I)
    obligation = re.search(
        r'Error:.*(possible violation of (pre|post)?condition'
        r'|(postcondition|precondition|assertion) (could not be proved|might not hold))', output)
    if status != 4 or bad_run or obligation is None or len(summaries) != 1:
        raise RuntimeError('Control did not fail a proof obligation; crash/timeout is not evidence')
    if int(summaries[0][1]) == 0:
        raise RuntimeError('Control reported a proof-obligation diagnostic but zero errors')
    return obligation.group(0)


def check_apply_probe(output: str) -> dict:
    """Compare the compiled `ApplyProbe.dfy` table against `trace_exec.apply`.

    This is the cross-check that the bounded interpreter used for witness
    execution controls implements the *pinned model's* operand semantics, not
    just a private mirror of itself.
    """
    rows = 0
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            continue
        kind, a, b, observed = (int(p) for p in parts)
        mirrored = trace_exec.apply(kind, a, b)
        if observed != mirrored:
            raise RuntimeError(
                'Apply mirror differs from the compiled model for kind %d (%d, %d): '
                'model=%d mirror=%d' % (kind, a, b, observed, mirrored))
        rows += 1
    if rows == 0 or 'apply-probe-ok' not in output:
        raise RuntimeError('Apply probe produced no comparable rows')
    return {'rows': rows, 'status': 'mirror-equals-compiled-model'}


def check_inline_bindings(events: list, callee_records: dict) -> None:
    """Shape-bind every inlined body to its callee's direct translation.

    This is direct-translation *self-consistency* (the hash is a digest of an
    in-process `bt.translate` shape, not of the emitted certificate or of JVM
    behavior) plus the trusted splice. It detects a corrupted or substituted
    body; it is not a semantic theorem about the JVM.
    """
    for event in events:
        record = callee_records.get(event['target'])
        if record is None:
            raise RuntimeError('inlined target has no separate callee certificate: '
                               + event['target'])
        if event['callee_shape_sha256'] != record['direct_shape_sha256']:
            raise RuntimeError('inlined body shape differs from the certified callee: '
                               + event['target'])


def witness_status(result: dict, witness: dict | None) -> str:
    if witness is None:
        return ('not-emitted: concrete state too large for the size limit'
                if comp.has_secret(result) else 'public-only')
    if witness.get('execution') is None:
        return 'hypothesis-only: no finite execution within the step cap'
    return 'validated-finite-execution'


def check_witness_contract(name: str, root: dict, result: dict,
                           witness: dict | None) -> dict:
    """Fail-closed witness obligations derived from the recorded contract (M2).

    The facts come from the validated finite execution (`trace_exec`), never
    from state initialisation:

      * a callee with a private scalar parameter must keep the secret live in a
        register that is **not** a parameter register of the certified program
        (the dead-parameter case is rejected);
      * a callee whose contract records `parameter-array-clear` must zero every
        *secret parameter array role* (not just any array role) and must execute
        at least as many stores to that role as the witness array length.

    This is a helper-model abstraction: the model's `ProviderResult` depends only
    on public arguments, so a secret value passed to an atomic external call is
    not required to reappear in the returned register.
    """
    contract = root.get('contract') or {}
    declared = list(contract.get('params') or [])
    private_scalar = any(taint == 'sec' for taint in declared)
    clearing = contract.get('heap') == 'parameter-array-clear'
    param_regs = sorted(set(result.get('param_regs') or []))
    report = {'parameter_registers': param_regs}
    if not private_scalar and not clearing:
        report['status'] = 'not-required'
        return report
    execution = witness.get('execution') if witness else None
    if execution is None:
        raise RuntimeError(
            name + ': private-input callee has no validated witness execution '
            '(status ' + witness_status(result, witness) + ')')
    differing = list(execution.get('differing_registers') or [])
    param_set = set(param_regs)
    non_parameter = [r for r in differing if r not in param_set]
    report.update({'differing_registers': differing,
                   'non_parameter_differing': non_parameter})
    if private_scalar:
        if not non_parameter:
            raise RuntimeError(
                name + ': witness secret liveness is parameter-only; the validated '
                'execution has no non-parameter register differing (dead private input)')
        report['liveness'] = 'non-parameter-secret-live'
    if clearing:
        owner = root['class'].replace('.', '/')
        role_names = sorted(result['roles'])
        expected = []
        for index, taint in enumerate(declared):
            if not str(taint).startswith(('array_sec', 'seq_sec')):
                continue
            role = f'{owner}.{root["name"]}#p{index}'
            if role not in result['roles'] or result['roles'][role] != 'sec':
                raise RuntimeError(
                    name + ': clearing contract has no secret parameter array role '
                    + repr(role) + ' in the certificate')
            expected.append(role)
        if not expected:
            raise RuntimeError(
                name + ': parameter-array-clear contract declares no secret parameter array')
        store_counts = list(execution.get('role_store_counts') or [])
        zeroed = set(execution.get('zeroed_roles') or [])
        cleared = []
        for role in expected:
            role_id = role_names.index(role)
            size = len(witness['heap_s'][role_id])
            if role_id not in zeroed:
                raise RuntimeError(
                    name + ': modelled clear did not zero the secret parameter role '
                    + repr(role))
            count = store_counts[role_id] if role_id < len(store_counts) else 0
            if count < size:
                raise RuntimeError(
                    name + ': modelled clear wrote ' + str(count) + ' of ' + str(size)
                    + ' elements of secret parameter role ' + repr(role))
            cleared.append(role)
        report['cleared_parameter_roles'] = cleared
    return report


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


def emit_certificate(workspace: Path, name: str, result: dict,
                     witness: dict | None = None) -> tuple[Path, str]:
    text = bt.certificate_module(name, result, witness=witness)
    text = text.replace('include "SecretTrace.dfy"',
                        'include "' + (HERE / 'SecretTrace.dfy').as_posix() + '"')
    path = workspace / (name + '.dfy')
    path.write_text(text)
    return path, text


def verification_flags(policy: dict, root: dict) -> list[str]:
    limits = root.get('limits') or policy.get('limits', {}).get(root['name'], {})
    if not limits:
        return list(FLAGS)
    flags = ['--verification-time-limit', str(limits['time']),
             '--resource-limit', str(limits['resources'])]
    for option in limits.get('solver_options', ['O:smt.case_split=0']):
        flags.extend(['--solver-option', option])
    return flags


def verify_certificate(workspace: Path, dafny: Path, solver: Path, path: Path,
                       timeout=300, flags=None) -> int:
    status, output = shared.execute([dafny, 'verify', path, '--solver-path', str(solver),
                                     *(flags or FLAGS)], path.with_suffix('.log'), timeout)
    return shared.check_verified(status, output, 1)


def mutate_callee(result: dict, kind: str) -> dict:
    """Inject one normal proof-obligation defect into a callee certificate."""
    import copy
    mutant = copy.deepcopy(result)
    if kind == 'secret-branch-cond':
        inst = next(i for i in mutant['code'] if i['type'] == 'branch')
        mutant['reg_taints'][inst['cond']] = 'sec'
    elif kind == 'secret-store-index':
        inst = next(i for i in mutant['code']
                    if i['type'] == 'step' and i['kind'][0] == 'store')
        mutant['reg_taints'][inst['kind'][2]] = 'sec'
    elif kind == 'public-result-from-secret-arg':
        inst = next(i for i in mutant['code']
                    if i['type'] == 'step' and i['kind'][0] == 'call'
                    and not (len(i['kind']) > 4 and i['kind'][4])
                    and any(mutant['reg_taints'].get(a, 'sec') == 'sec' for a in i['kind'][2]))
        mutant['reg_taints'][inst['dst']] = 'pub'
    elif kind == 'secret-runtime-arg':
        inst = next(i for i in mutant['code']
                    if i['type'] == 'step' and i['kind'][0] == 'call')
        mutant['reg_taints'][inst['kind'][2][0]] = 'sec'
    else:
        raise RuntimeError('unknown callee mutation ' + kind)
    return mutant


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
    # F4: the admission tables that the extractor and audit enforce live in
    # bytecode_trace.py; the policy only records them. Fail closed on drift.
    classification = bt.check_runtime_classification(policy)
    classified_euclidean = set(classification.get('euclidean_families', []))
    for target in policy.get('calls', {}):
        if target.startswith('dafny/DafnyEuclidean.'):
            if target not in classified_euclidean:
                raise RuntimeError('Euclidean runtime call family not classified: ' + target)
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
    for name in ('SecretTrace.dfy', 'PositiveTraceCheck.dfy', 'ApplyProbe.dfy'):
        shutil.copyfile(HERE / name, model_dir / name)
    status, run_out = call('positive-compiled', [dafny, 'run', '--no-verify', model_dir / 'PositiveTraceCheck.dfy'])
    if status or 'positive-control-ok' not in run_out:
        raise RuntimeError('Compiled positive control failed')
    positive = 'executed'
    # Cross-check the bounded interpreter's operand table against compiled Dafny
    # (the same frozen model), so witness execution controls are not a private
    # self-consistent mirror (F1/F5).
    status, probe_out = call('apply-probe', [dafny, 'run', '--no-verify', model_dir / 'ApplyProbe.dfy'])
    if status:
        raise RuntimeError('Compiled Apply probe failed')
    apply_probe = check_apply_probe(probe_out)

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

    # Owned-callee roots: actual bytecode certificates for the exact helpers
    # whose opaque contracts the caller certificates previously assumed. An
    # entry may inline a certified supporting helper (Extract -> Pow2) so the
    # callee root itself has no remaining opaque owned call.
    callee_specs = comp.load_callee_specs(policy, javap, inspected, policy.get('callee_roots', []))
    callee_records = {}
    callee_roots = []
    callee_inline_events = []
    for root in policy.get('callee_roots', []):
        name = 'Callee_' + root['name']
        method = disassemble_root(javap, inspected, root)
        class_policy = policy['classes'][root['class'].replace('.', '/')]
        direct = bt.translate(method, policy, class_policy)
        direct_count = len(direct['code'])
        direct_shape = hashlib.sha256(
            json.dumps(comp.shape_signature(direct), sort_keys=True).encode()).hexdigest()
        inline_set = set(root.get('inline', []))
        unknown = inline_set - set(callee_specs)
        if unknown:
            raise RuntimeError(name + ': inlines an uncertified target: ' + ', '.join(sorted(unknown)))
        result = comp.inline_owned_callees(direct, {t: callee_specs[t] for t in inline_set}, policy)
        result['call_targets'] = comp.active_targets(result)
        failures = bt.audit_certificate(result)
        if failures:
            raise RuntimeError(f'{name}: independent audit rejected the certificate: {failures[:3]}')
        if result['instructions_reachable'] != len(result['code']):
            raise RuntimeError(name + ': callee certificate is not fully reachable')
        witness = comp.witness(result)
        witness_contract = check_witness_contract(name, root, result, witness)
        path, _ = emit_certificate(workspace, name, result, witness=witness)
        flags = verification_flags(policy, root)
        verified = verify_certificate(workspace, dafny, solver, path, flags=flags)
        source = root['class'].replace('.', '/') + '.java'
        record = {
            'verify_command': [str(dafny), 'verify', str(path), '--solver-path', str(solver), *flags],
            'class': root['class'], 'method': f"{method.name}:{method.descriptor}",
            'status': 'checked', 'role': root.get('role', 'owned-callee'),
            'contract': root.get('contract', {}),
            'obligations': verified, 'certificate': path.name,
            'certificate_sha256': digest(path),
            'direct_instructions': direct_count,
            'direct_shape_sha256': direct_shape,
            'instructions': len(result['code']),
            'instructions_reachable': result['instructions_reachable'],
            'cfg_edges_checked': ('component-cfgs-and-splice-reachability'
                                  if result.get('inlined') else result.get('cfg_edges_checked', False)),
            'composition_trusted': bool(result.get('inlined')),
            'registers': result['registers'], 'roles': result['roles'],
            'call_targets': result['call_targets'],
            'inlined': result.get('inlined', []),
            'parameter_registers': result.get('param_regs', []),
            'witness': witness_status(result, witness),
            'witness_execution': witness.get('execution') if witness else None,
            'witness_contract': witness_contract,
            'bytecode_sites': result['sites'],
            'source_sha256': digest(ROOT / ('quic/src/main/java/' + source)),
            'source_rebuild_sha256': binding_root(binding, root['class']),
            'solver_limits': root.get('limits') or {'time': 30, 'resources': 50000000},
            'mutants': {},
        }
        for kind in policy.get('callee_mutants', {}).get(root['name'], []):
            mutant = mutate_callee(result, kind)
            text = bt.certificate_module('CalleeMutant_' + root['name'] + '_' + kind.replace('-', '_'),
                                         mutant, check_only=True)
            text = text.replace('include "SecretTrace.dfy"',
                                'include "' + (HERE / 'SecretTrace.dfy').as_posix() + '"')
            mpath = workspace / ('CalleeMutant_' + root['name'] + '_' + kind.replace('-', '_') + '.dfy')
            mpath.write_text(text)
            status, out = call('callee-mutant-' + root['name'] + '-' + kind,
                               [dafny, 'verify', mpath, '--solver-path', str(solver), *flags])
            record['mutants'][kind] = {
                'status': 'proof-obligation-rejected',
                'diagnostic': check_proof_rejected(status, out)}
        callee_inline_events.extend(result.get('inlined', []))
        callee_records[root['class'].replace('.', '/') + '.' + root['name'] + ':' + root['descriptor']] = record
        callee_roots.append(record)

    # F8: nested callee-root inlines are shape-bound too, after every callee
    # record exists (Extract inlines Pow2 before Pow2 is certified).
    check_inline_bindings(callee_inline_events, callee_records)

    composed_roots = []
    composition_records = []
    for root in policy.get('composed_roots', []):
        name = 'Composed_' + root['name']
        method = disassemble_root(javap, inspected, root)
        class_policy = policy['classes'][root['class'].replace('.', '/')]
        result = bt.translate(method, policy, class_policy)
        before_owned = {t for t in result['call_targets'] if t.startswith('io/github/mahmoudimus/')}
        inline_set = set(root.get('inline', []))
        discharged = set(root.get('discharged', []))
        supporting = set(root.get('supporting', []))
        if not discharged <= inline_set:
            raise RuntimeError(name + ': discharged targets are not in the inline set')
        if not supporting <= inline_set:
            raise RuntimeError(name + ': supporting targets are not in the inline set')
        unknown = inline_set - set(callee_specs)
        if unknown:
            raise RuntimeError(name + ': inlines an uncertified target: ' + ', '.join(sorted(unknown)))
        result = comp.inline_owned_callees(result, {t: callee_specs[t] for t in inline_set}, policy)
        result['call_targets'] = comp.active_targets(result)
        failures = bt.audit_certificate(result)
        if failures:
            raise RuntimeError(f'{name}: independent audit rejected the composed certificate: {failures[:3]}')
        if result['instructions_reachable'] != len(result['code']):
            raise RuntimeError(name + ': composed certificate is not fully reachable')
        after_owned = {t for t in result['call_targets'] if t.startswith('io/github/mahmoudimus/')}
        expected = before_owned - discharged
        if after_owned != expected:
            raise RuntimeError(name + ': composition changed the owned-callee set unexpectedly; missing='
                               + ', '.join(sorted(expected - after_owned))
                               + ' added=' + ', '.join(sorted(after_owned - expected)))
        if discharged & after_owned:
            raise RuntimeError(name + ': discharged target remains an opaque owned call')
        if not after_owned <= set(policy.get('unchecked_owned_callees', [])):
            raise RuntimeError(name + ': composed owned callee omitted from unchecked scope: '
                               + ', '.join(sorted(after_owned - set(policy.get('unchecked_owned_callees', [])))))
        check_inline_bindings(result.get('inlined', []), callee_records)
        witness = comp.witness(result)
        witness_contract = check_witness_contract(name, root, result, witness)
        path, _ = emit_certificate(workspace, name, result, witness=witness)
        flags = verification_flags(policy, root)
        verified = verify_certificate(workspace, dafny, solver, path, flags=flags)
        source = root['class'].replace('.', '/') + '.java'
        record = {
            'verify_command': [str(dafny), 'verify', str(path), '--solver-path', str(solver), *flags],
            'class': root['class'], 'method': f"{method.name}:{method.descriptor}",
            'status': 'checked', 'role': root.get('role', 'composed-caller'),
            'obligations': verified, 'certificate': path.name,
            'certificate_sha256': digest(path),
            'instructions': len(result['code']),
            'instructions_reachable': result['instructions_reachable'],
            'cfg_edges_checked': ('component-cfgs-and-splice-reachability'
                                  if result.get('inlined') else result.get('cfg_edges_checked', False)),
            'composition_trusted': bool(result.get('inlined')),
            'registers': result['registers'], 'roles': result['roles'],
            'call_targets': result['call_targets'],
            'inlined': result.get('inlined', []),
            'parameter_registers': result.get('param_regs', []),
            'witness': witness_status(result, witness),
            'witness_execution': witness.get('execution') if witness else None,
            'witness_contract': witness_contract,
            'bytecode_sites': result['sites'],
            'source_sha256': digest(ROOT / ('quic/src/main/java/' + source)),
            'source_rebuild_sha256': binding_root(binding, root['class']),
            'solver_limits': root.get('limits') or {'time': 30, 'resources': 50000000},
        }
        composed_roots.append(record)
        caller_union = {t for rec in roots for t in rec['call_targets']
                        if t.startswith('io/github/mahmoudimus/')}
        replacement_union = (caller_union - discharged) | after_owned
        composition_records.append({
            'status': 'checked-inline-expansion',
            'composed_root': f"{root['class']}.{root['name']}:{root['descriptor']}",
            'certificate': path.name,
            'certificate_sha256': digest(path),
            'discharged': sorted(discharged),
            'supporting': sorted(supporting),
            'feed_original_assumed': sorted(before_owned),
            'feed_composed_assumed': sorted(after_owned),
            'removed_from_feed': sorted(before_owned - after_owned),
            'added_to_feed': sorted(after_owned - before_owned),
            'caller_union_assumed': sorted(caller_union),
            'composed_replacement_union_assumed': sorted(replacement_union),
            'target_identity': 'exact class + method name + descriptor',
            'shape_binding': ('direct-translation self-consistency: each inlined body shape hash is compared '
                              'with the in-process direct translation shape of the same callee (nested '
                              'callee-root inlines included). It detects a corrupted/substituted body; it is '
                              "not a hash of the emitted certificate and not a JVM-semantics theorem."),
            'rule': policy['composition']['rule'],
            'owned_helper_boundaries': policy['composition'].get('owned_helper_boundaries', []),
            'residuals': policy['composition']['residuals'],
            'not_a_closure': ('the five caller certificates in roots still assume the 19-target union; '
                              'the composed Feed certificate removes exactly the three named targets from '
                              "Feed's 10 and still assumes its other 7. The five-certificate union would be 16 "
                              'only if this composed certificate replaced the Feed caller certificate, which '
                              'this replay does not claim.'),
            'solver_limits': root.get('limits') or {'time': 30, 'resources': 50000000},
        })

    fixture_root = workspace / 'fixtures'
    fixture_root.mkdir()
    fixture_sources = sorted((HERE / 'fixtures').glob('*.java'))
    status, text = call('fixture-compile', [str(java_tool(jdk, 'javac')), '-g', '--release', '21',
                                            '-cp', str(runtime), '-d', str(fixture_root)]
                       + [str(p) for p in fixture_sources])
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
        mutants[kind] = {'status': 'proof-obligation-rejected',
                         'diagnostic': check_proof_rejected(status, out)}

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
        'apply_probe': apply_probe,
        'execution_controls': {
            'machine_mirror': ('trace_exec.py: bounded interpreter of the frozen SecretTrace '
                               'Apply/DoStep/Exec semantics used only for witness execution '
                               'and copy-operand controls'),
            'mirror_cross_check': ('compiled ApplyProbe.dfy table compared row-by-row with '
                                   'trace_exec.apply; a mismatch fails the replay'),
            'witness_execution': ('a witness is reported as validated-finite-execution only '
                                  'when both runs reach a terminal instruction; otherwise the '
                                  'emitted lemma is hypothesis-only and no completed run is claimed'),
            'truncation': 'a fuel-truncated prefix is never recorded as a completed execution',
            'scope': ('model-level operand/execution control; not a JVM value-refinement or '
                      'timing theorem'),
        },
        'roots': roots, 'callee_roots': callee_roots,
        'composed_roots': composed_roots, 'composition': composition_records,
        'fixtures': fixtures, 'certificate_mutants': mutants,
        'hkdf': hkdf, 'inputs': pins, 'class_binding': binding,
        'runtime_classification': policy.get('runtime_classification', {}),
        'open_roots': policy.get('open_roots', []),
        'unchecked_owned_callees': policy.get('unchecked_owned_callees', []),
        'assumed_owned_callees': owned_contracts(roots, policy),
        'callee_root_assumptions': owned_contracts(callee_roots, policy),
        'composition_not_a_closure': (
            'The five caller certificates in roots keep their 19 opaque owned contracts. '
            'The composed Feed certificate is a separate artifact that discharges only '
            'NativeCodec.Extract, PublicMod and Wipe by inlining their certified bodies. '
            'No other owned callee or open root is closed by this replay.'),
        'caller_skeleton': [r for r in policy.get('open_roots', []) if r.get('status') == 'caller-skeleton-unsupported'],
        'commands': commands, 'workspace': str(workspace),
        'trusted': ['Dafny/Boogie/Z3', 'javap parser and operand mapping',
                    'declared policy of public/secret parameters, fields, allocations and call results',
                    'javac/JVM word-operation observer (atomic, operand-independent cost)',
                    'enumerated external contracts: JDK HMAC/SHA3, DafnyRuntime, JDK BigInteger/String/boxed deterministic calls',
                    'opaque owned helper/adapter contracts listed in assumed_owned_callees; these are not callee trace proofs',
                    'inline expansion of exact static certified owned callees: plain parameter-role identity, register renaming, entry and return copies (shape-bound to the direct translation, mutation-tested, not a JVM-semantics theorem)'],
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
