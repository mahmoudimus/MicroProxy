#!/usr/bin/env python3
"""Verify isolated Keccak/field kernels, then test exact Dafny-generated Java."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / 'dafny'))
spec = importlib.util.spec_from_file_location('primitives_support', HERE.parent / 'dafny/run.py')
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
sys.path.pop(0)

REFERENCES = ['quic/src/main/java/io/github/mahmoudimus/quic/tls/' + n + '.java'
              for n in ('Shake', 'MlKem768')]
SUPPORT = ['formal/dafny/' + n for n in ('run.py', 'toolchain.py', 'tools.json')]
JAVA_MINIMUMS = {'one_bit_states': 1600, 'keccak_states': 1698,
                 'rotation_cases': 4096, 'field_cases': 31247, 'assertions': 40000}


def zero_audit(status, text):
    if status or 'Warning:' in text or 'Dafny auditor completed with 0 findings' not in text:
        raise RuntimeError('Unexpected assumption or skipped proof; see audit log')


def required_inputs():
    return {str(p.relative_to(ROOT)) for p in HERE.rglob('*') if p.suffix in {'.dfy', '.py', '.java'}} | set(REFERENCES + SUPPORT)


def parse_tests(text):
    matches = re.findall(r'^PASS GeneratedPrimitivesTest (\{.*\})$', text, re.M)
    if len(matches) != 1:
        raise RuntimeError('Missing or duplicate Java test receipt')
    receipt = json.loads(matches[0])
    if set(receipt) != set(JAVA_MINIMUMS) or any(type(receipt[k]) is not int or receipt[k] < v
                                               for k, v in JAVA_MINIMUMS.items()):
        raise RuntimeError('Partial Java test inventory')
    return receipt


def domain_harness(folder):
    return f'''include "{(folder / 'Keccak.dfy').as_posix()}"
include "{(folder / 'Field.dfy').as_posix()}"
module PublicDomain {{
  import K = VerifiedKeccak
  import S = KeccakSpec
  import F = VerifiedField
  method Lanes(s: seq<bv64>, v: bv64, shift: nat)
    requires |s| == 25 && shift < 64
  {{
    var rotated := K.Rotate(v, shift);
    assert rotated == S.Rotate(v, shift);
    var p := K.Permute(s);
    assert p == S.Iter(s, 24);
  }}
  method Fields(a: int, b: int, c: int, d: int, once: int, wide: int)
    requires 0 <= a < 3329 && 0 <= b < 3329 && 0 <= c < 3329 && 0 <= d < 3329
    requires 0 <= once < 6658 && 0 <= wide <= 22154496
  {{
    var x := F.ReduceOnce(once); assert x == once%3329;
    var y := F.Reduce(wide); assert y == wide%3329;
    var z := F.Add(a,b); assert z == (a+b)%3329;
    z := F.Sub(a,b); assert z == (a-b)%3329;
    z := F.Mul(a,b); assert z == (a*b)%3329;
    z := F.MulSub(a,b,c); assert z == (a*(b-c))%3329;
    z := F.AddMul(a,b,c,d); assert z == (a*b+c*d)%3329;
  }}
}}
'''


def mutations(kernel, source):
    replacements = {
        'Keccak': {
            'rotation': ('if n == 0 then v else (v << n) | (v >> (64-n))', 'v'),
            'round-count': ('for i := 0 to 24', 'for i := 0 to 23'),
            'round-constant': ('function Constants(): seq<bv64>\n    ensures Constants() == S.Constants()',
                               'function Constants(): seq<bv64>\n    ensures Constants() == S.Constants()'),
            'lane-domain': ('requires |a| == 25 ensures r == S.Iter(a, 24)',
                            'requires |a| == 25 && a[0] == 0 ensures r == S.Iter(a, 24)')},
        'Field': {
            'once-result': ('r := (x+(x/32768)*Q)%65536;', 'r := x%65536;'),
            'barrett-multiplier': ('(a*5039)/16777216', '(a*5038)/16777216'),
            'field-domain': ('requires 0 <= a <= MaxReduce', 'requires 0 <= a < 16777216')}
    }[kernel]
    result = {}
    for name, (old, new) in replacements.items():
        if source.count(old) != 1:
            raise RuntimeError('Mutation anchor changed: ' + name)
        if name == 'round-constant':
            # Change only the executable table, never its reference specification.
            start = source.index(old)
            result[name] = source[:start] + source[start:].replace('0x0000000000000001,', '0x0000000000000002,', 1)
        else:
            result[name] = source.replace(old, new, 1)
    return result


def pipeline(args, output):
    pins = json.loads((HERE / 'inputs.json').read_text())['inputs']
    if set(pins) != required_inputs():
        raise RuntimeError('Proof input inventory changed; review manifest')
    shared.check_inputs(ROOT, pins)
    dafny, runtime, tools, asset = shared.install(args.cache)
    workspace = Path(tempfile.mkdtemp(prefix='replay-', dir=output))
    commands = []
    solver = dafny.parent / 'z3/bin/z3-4.12.1'
    flags = ['--verification-time-limit', '30', '--resource-limit', '50000000', '--solver-path', str(solver)]

    def call(label, command, timeout=300):
        print(label, flush=True)
        log = workspace / (label + '.log')
        commands.append({'step': label, 'command': [str(c) for c in command], 'log': str(log)})
        return shared.execute(command, log, timeout)

    status, version = call('dafny-version', [dafny, '--version'])
    if status or not version.strip().startswith(tools['version'] + '+'):
        raise RuntimeError('Unexpected Dafny version')
    status, solver_version = call('solver-version', [solver, '--version'])
    if status or 'Z3 version 4.12.1' not in solver_version:
        raise RuntimeError('Unexpected pinned solver')
    counts = {}
    for kernel in ('Keccak', 'Field'):
        source = HERE / (kernel + '.dfy')
        zero_audit(*call('audit-' + kernel, [dafny, 'audit', source]))
        counts[kernel] = shared.check_verified(*call('prove-' + kernel, [dafny, 'verify', source, *flags]),
                                               {'Keccak': 122, 'Field': 15}[kernel])
    domain = workspace / 'Domain.dfy'
    domain.write_text(domain_harness(HERE))
    counts['domain'] = shared.check_verified(*call('public-domain', [dafny, 'verify', domain,
                                          '--verify-included-files', *flags]), 139)
    controls = {}
    for kernel in ('Keccak', 'Field'):
        for name, changed in mutations(kernel, (HERE / (kernel + '.dfy')).read_text()).items():
            folder = workspace / name
            folder.mkdir()
            for part in ('Keccak', 'Field'):
                (folder / (part + '.dfy')).write_text(changed if part == kernel else (HERE / (part + '.dfy')).read_text())
            target = folder / (kernel + '.dfy')
            extra = []
            if name.endswith('-domain'):
                target = folder / 'Domain.dfy'
                target.write_text(domain_harness(folder))
                extra = ['--verify-included-files']
            shared.check_rejected(*call('control-' + name, [dafny, 'verify', target, *extra, *flags]))
            controls[name] = 'proof-obligation-rejected'
    source = (HERE / 'Field.dfy').read_text()
    for name, changed in (
        ('extra-assumption', source.replace('module VerifiedField {', 'module VerifiedField {\n lemma {:axiom} Unchecked()')),
        ('skipped-proof', source.replace('method ReduceOnce(', 'method {:verify false} ReduceOnce(', 1))):
        target = workspace / (name + '.dfy')
        target.write_text(changed)
        status, audit = call('control-' + name, [dafny, 'audit', target])
        if status or 'Dafny auditor completed with 1 findings' not in audit:
            raise RuntimeError('Audit control did not run')
        try:
            zero_audit(status, audit)
        except RuntimeError:
            controls[name] = 'audit-rejected'
        else:
            raise RuntimeError('Audit control accepted')
    prefix = workspace / 'Kernels'
    shared.check_verified(*call('generate-java', [dafny, 'translate', 'java', HERE / 'Keccak.dfy',
                          HERE / 'Field.dfy', '--output', prefix, *flags]), 55)
    generated = workspace / 'Kernels-java'
    generated_pins = shared.snapshot(generated, '*.java')
    for package in ('VerifiedKeccak', 'VerifiedField'):
        if not (generated / package / '__default.java').is_file():
            raise RuntimeError('Missing generated kernel: ' + package)
    if not os.environ.get('JAVA_HOME'):
        raise RuntimeError('Set JAVA_HOME to a JDK21+ installation')
    jdk = Path(os.environ['JAVA_HOME'])
    classes = workspace / 'classes'
    classes.mkdir()
    sources = sorted(generated.rglob('*.java')) + sorted((HERE / 'java').rglob('*.java'))
    status, _ = call('compile-java', [jdk / 'bin/javac', '--release', '21', '-cp', runtime,
                                   '-d', classes, *sources, *[ROOT / p for p in REFERENCES]])
    if status:
        raise RuntimeError('Exact generated Java compilation failed')
    class_pins = shared.snapshot(classes, '*.class')
    runs = []
    for i, home in enumerate([jdk, *args.java_home]):
        status, java_version = call(f'jdk-{i}-version', [home / 'bin/java', '-version'])
        if status:
            raise RuntimeError('Java runtime unavailable')
        status, tests = call(f'jdk-{i}-tests', [home / 'bin/java', '-ea', '-cp', f'{classes}{os.pathsep}{runtime}',
                        'io.github.mahmoudimus.quic.tls.GeneratedPrimitivesTest'], 300)
        if status:
            raise RuntimeError('Generated Java integration failed')
        runs.append({'version': java_version.strip(), 'receipt': parse_tests(tests),
                     'java_sha256': shared.digest(home / 'bin/java')})
    shared.check_inputs(ROOT, pins)
    shared.check_generated(generated, generated_pins)
    if shared.snapshot(classes, '*.class') != class_pins:
        raise RuntimeError('Classes changed during integration tests')
    return {'status': 'complete', 'scope': 'Isolated lane-level Keccak permutation and scalar field helpers',
            'verified': counts, 'controls': controls, 'inputs': pins, 'tool_asset': asset,
            'dafny_version': version.strip(), 'solver_version': solver_version.strip(),
            'flags': flags, 'runtime_sha256': shared.digest(runtime),
            'generated_java': generated_pins, 'classes': class_pins, 'java_runs': runs,
            'commands': commands, 'workspace': str(workspace), 'production_dependencies_added': 0,
            'footprint': {'generated_java_bytes': sum(p.stat().st_size for p in generated.rglob('*.java')),
                          'generated_class_bytes': sum(p.stat().st_size for name in ('VerifiedKeccak', 'VerifiedField')
                                                       for p in (classes/name).rglob('*.class')),
                          'harness_runtime_bytes': runtime.stat().st_size},
            'trusted': ['standards-to-lane/table specification review', 'Dafny/Boogie/Z3',
                        'Dafny Java compiler/runtime', 'javac/JVM and Java test adapters'],
            'not_proved': ['production Java refinement', 'bit-string/lane refinement and SHAKE sponge',
                           'polynomial caller invariants/NTT/codecs/sampling/full ML-KEM',
                           'secret-trace/physical timing', 'cryptographic hardness/security reduction']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/dafny-primitives')
    parser.add_argument('--cache', type=Path, default=Path(os.environ.get('MICROPROXY_FORMAL_CACHE', Path.home() / '.cache/microproxy-formal')))
    parser.add_argument('--java-home', type=Path, action='append', default=[])
    args = parser.parse_args(argv)
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    with (output / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report = output / 'report.json'
        report.unlink(missing_ok=True)  # Marker failure must not preserve old success.
        shared.atomic_report(report, {'status': 'incomplete'})
        previous = signal.getsignal(signal.SIGTERM)
        def cancel(signum, frame):
            raise KeyboardInterrupt('Primitive replay cancelled')
        signal.signal(signal.SIGTERM, cancel)
        try:
            try:
                result = pipeline(args, output)
                shared.atomic_report(report, result)
            except Exception as error:
                shared.atomic_report(report, {'status': 'failed', 'error': str(error)})
                print(str(error), file=sys.stderr)
                return 1
        finally:
            signal.signal(signal.SIGTERM, previous)
    print('Complete: ' + str(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
