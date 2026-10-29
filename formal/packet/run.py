#!/usr/bin/env python3
"""Replay scoped packet functional/trace proofs against actual production Java."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile

from bytecode_guard import disassemble, flatten, check_io, check_length_guard
from lowering import lower

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
# Reuse the independently tested bounded process cleanup/report/input helpers.
sys.path.insert(0, str(HERE.parent / 'dafny'))
spec = importlib.util.spec_from_file_location('hkdf_replay_support', HERE.parent / 'dafny/run.py')
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
sys.path.pop(0)

PACKAGE = 'io.github.mahmoudimus.quic.internal.verified.__default'
GENERATED = 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verified/__default.java'
PRODUCTION = [GENERATED, 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/HeaderKey.java',
              'quic/src/main/java/io/github/mahmoudimus/quic/packet/PacketNumber.java',
              'quic/src/main/java/io/github/mahmoudimus/quic/packet/ProtectedPacket.java',
              'quic/src/test/java/io/github/mahmoudimus/quic/packet/HeaderProtectionTimingTest.java']
CLASSES = ['io/github/mahmoudimus/quic/internal/verified/__default.class',
           'io/github/mahmoudimus/quic/crypto/HeaderKey.class',
           'io/github/mahmoudimus/quic/packet/PacketNumber.class',
           'io/github/mahmoudimus/quic/packet/ProtectedPacket.class']
SCALARS = {'ShiftRight', 'ShiftLeft', 'Less', 'SignedLess', 'Decode', 'ReadPrefix', 'Unprotect'}


def module_clean_command():
    return ['mvn', '--batch-mode', '-pl', 'quic', 'clean']


def zero_audit(status, text):
    if status or 'Warning:' in text or 'Dafny auditor completed with 0 findings' not in text:
        raise RuntimeError('Unexpected proof assumption or skipped verification; see audit log')


def check_classes(pins):
    for path, expected in pins.items():
        if shared.digest(path) != expected:
            raise RuntimeError('Class changed during certification: ' + str(path))


def domain_harness(source):
    return 'include "' + source.as_posix() + '''"
module PublicPacketDomain {
  import K = io.github.mahmoudimus.quic.internal.verified
  import S = PacketSpec
  method LegalInputs(a: bv64, b: bv64, length: bv64, count: bv64)
    requires 1 <= length <= 4
    requires count < 64
  {
    var d := K.Decode(a,b,length);
    assert d == S.Decode(a,b,length);
    var p := K.ReadPrefix(a,length);
    assert p == S.Prefix(a,length);
    var h := K.Unprotect(a,b);
    assert h == S.Unprotect(a,b);
    var l := K.Less(a,b);
    assert l == (if a < b then 1 else 0);
    var s := K.SignedLess(a,b);
    assert s == (if S.SL(a,b) then 1 else 0);
    var r := K.ShiftRight(a,count);
    assert r == a >> (count & 63);
    var w := K.ShiftLeft(a,count);
    assert w == a << (count & 63);
  }
}
'''


def trace_harness(source, programs):
    text = 'include "' + source.as_posix() + '"\nmodule ExtractedPacketTraces {\n import T = PacketTrace\n'
    for name, program in programs.items():
        inputs = program['inputs']
        chunks = [program['nodes'][i:i+32] for i in range(0, len(program['nodes']), 32)]
        body = 'var code:seq<T.Node> := [];\n'
        offset = 0
        for i, chunk in enumerate(chunks):
            nodes = ',\n'.join('T.Node(%d,%d,%d,%d)' % tuple(n) for n in chunk)
            body += f'var chunk{i}:seq<T.Node> := [{nodes}];\n'
            body += f'assert T.Valid(chunk{i},{inputs},{offset});\n'
            body += f'T.ValidAppend(code,chunk{i},{inputs},0);\n'
            body += f'var next{i} := code + chunk{i};\n'
            body += f'assert T.Valid(next{i},{inputs},0);\n'
            body += f'var code{i} := next{i};\n'
            # Dafny function bodies permit immutable shadowing via nested lets.
            body += f'var code := code{i};\n'
            offset += len(chunk)
        text += f''' ghost function Code{name}():seq<T.Node>
 ensures T.Valid(Code{name}(),{inputs},0)
 {{ {body} code }}
 lemma {name}TwoRun(left:seq<bv64>,right:seq<bv64>, operation:(nat,bv64,bv64)->bv64)
 requires |left|=={inputs} && |right|=={inputs}
 ensures T.Run(Code{name}(),left,[],operation).1 == T.Run(Code{name}(),right,[],operation).1
 {{ T.TwoRun(Code{name}(),left,right,[],[],operation); }}
'''
    return text + '}\n'


def trace_leak_control(source):
    anchors = [
        ('Observe(code[0]) + tail.1', 'Observe(code[0]) + [value as nat] + tail.1'),
        ('ensures Run(code, inputs, registers, operation).1 == ProgramTrace(code)', 'ensures true'),
        ('ensures Run(code, left, a, operation).1 == Run(code, right, b, operation).1', 'ensures true')]
    for old, new in anchors:
        if source.count(old) != 1:
            raise RuntimeError('Trace control anchor changed')
        source = source.replace(old, new, 1)
    # Weaken only the mutant's generic lemmas and expose a concrete relational
    # counterexample. The positive universal theorem remains unchanged.
    witness = '''
  lemma SecretTraceWitness()
    ensures Run([Node(1,0,0,0)], [0], [], (k:nat,x:bv64,y:bv64) => x+y).1
      == Run([Node(1,0,0,0)], [1], [], (k:nat,x:bv64,y:bv64) => x+y).1
  {}
'''
    at = source.rfind('}')
    return source[:at] + witness + source[at:]


def pipeline(args, output):
    cleaned = (ROOT / 'quic/target').resolve()
    if output.is_relative_to(cleaned) or args.cache.expanduser().resolve().is_relative_to(cleaned):
        raise RuntimeError('Evidence and tool cache must be outside the cleaned quic/target directory')
    pins = json.loads((HERE / 'inputs.json').read_text())['inputs']
    required = {str(p.relative_to(ROOT)) for p in HERE.iterdir() if p.suffix in ('.py', '.dfy')}
    required.update(PRODUCTION)
    required.update(('formal/dafny/run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json'))
    if set(pins) != required:
        raise RuntimeError('Packet proof input inventory changed; review pins')
    shared.check_inputs(ROOT, pins)
    if not os.environ.get('JAVA_HOME'):
        raise RuntimeError('Set JAVA_HOME to a JDK21+ installation')
    jdk = Path(os.environ['JAVA_HOME']).resolve()
    dafny, _, tools, asset = shared.install(args.cache)
    solver = dafny.parent / 'z3/bin/z3-4.12.1'
    flags = ['--verification-time-limit', '30', '--resource-limit', '50000000',
             '--solver-path', str(solver), '--solver-option', 'O:smt.case_split=0']
    workspace = Path(tempfile.mkdtemp(prefix='replay-', dir=output))
    commands = []

    def call(name, command, timeout=300):
        print(name, flush=True)
        commands.append({'step': name, 'command': [str(c) for c in command]})
        return shared.execute(command, workspace / (name + '.log'), timeout)

    code, version = call('dafny-version', [dafny, '--version'])
    if code or not version.strip().startswith(tools['version'] + '+'):
        raise RuntimeError('Pinned Dafny could not start; see version log (Linux needs libicu)')
    code, solver_version = call('solver-version', [solver, '--version'])
    if code or '4.12.1' not in solver_version:
        raise RuntimeError('Unexpected solver version')
    kernel, trace = HERE / 'PacketKernel.dfy', HERE / 'TraceMachine.dfy'
    for name, path in [('kernel', kernel), ('trace', trace)]:
        zero_audit(*call(name + '-audit', [dafny, 'audit', path]))
    verified = shared.check_verified(*call('kernel-proof', [dafny, 'verify', kernel, *flags]), 46)
    trace_verified = shared.check_verified(*call('trace-model', [dafny, 'verify', trace, *flags]), 8)
    domain = workspace / 'Domain.dfy'
    domain.write_text(domain_harness(kernel))
    shared.check_verified(*call('public-domain', [dafny, 'verify', domain, '--verify-included-files', *flags]), 18)
    source = kernel.read_text()
    changes = {
        'reconstruction-selection': ('var add := (1 - above) & room;', 'var add := above & room;'),
        'prefix-byte-order': ('word & 0xffffffff, 8 * (4 - length)', 'word & 0xffffffff, 7 * (4 - length)'),
        'following-ciphertext': ('var ge2 := 1 ^ lt2;', 'var ge2 := 0 ^ lt2;'),
        'shift-domain': ('requires count < 64\n    ensures r == value >> count', 'requires count <= 64\n    ensures r == value >> count'),
        'narrow-domain': ('ensures r == S.Prefix(word, length)', 'requires length == 4\n    ensures r == S.Prefix(word, length)')
    }
    controls = {}
    for name, (old, new) in changes.items():
        if source.count(old) != 1:
            raise RuntimeError('Control anchor changed: ' + name)
        folder = workspace / name
        folder.mkdir()
        mutant = folder / 'PacketKernel.dfy'
        mutant.write_text(source.replace(old, new, 1))
        target, extra = mutant, []
        if name == 'narrow-domain':
            target = folder / 'Domain.dfy'
            target.write_text(domain_harness(mutant))
            extra = ['--verify-included-files']
        shared.check_rejected(*call('control-' + name, [dafny, 'verify', target, *extra, *flags]))
        controls[name] = 'proof-obligation-rejected'
    leak = workspace / 'SecretTraceLeak.dfy'
    leak.write_text(trace_leak_control(trace.read_text()))
    shared.check_rejected(*call('control-secret-trace', [dafny, 'verify', leak, *flags]))
    controls['secret-trace'] = 'paired-trace-obligation-rejected'
    axiom = workspace / 'UnexpectedAssumption.dfy'
    axiom.write_text(source.replace('module PacketSpec {', 'module PacketSpec {\n lemma {:axiom} Unchecked()'))
    status, audit = call('control-assumption', [dafny, 'audit', axiom])
    if status or 'Dafny auditor completed with 1 findings' not in audit:
        raise RuntimeError('Assumption control did not run')
    try:
        zero_audit(status, audit)
    except RuntimeError:
        controls['extra-assumption'] = 'audit-rejected'
    else:
        raise RuntimeError('Unexpected axiom accepted')
    shared.check_verified(*call('generate-java', [dafny, 'translate', 'java', kernel,
                          '--output', workspace / 'Kernel', *flags]), 17)
    raw = workspace / 'Kernel-java/io/github/mahmoudimus/quic/internal/verified/__default.java'
    packaged = lower(raw.read_text())
    if packaged != (ROOT / GENERATED).read_text():
        raise RuntimeError('Canonical generated Java differs; review generation/lowering before updating')
    isolated = workspace / 'dependency-free-classes'
    isolated.mkdir()
    status, _ = call('compile-without-runtime', [jdk / 'bin/javac', '--release', '21', '-d', isolated, ROOT / GENERATED])
    if status:
        raise RuntimeError('Scalar kernel must compile without DafnyRuntime or other classpath')
    status, _ = call('clean-production-classes', module_clean_command())
    if status:
        raise RuntimeError('Could not clean selected production module')
    status, _ = call('integration-tests', ['mvn', '--batch-mode', '-pl', 'quic', '-am', 'test',
        '-Dtest=HeaderProtectionTimingTest,PacketNumberTest,PacketProtectionVectorsTest,FingerprintSslContextTest',
        '-Dsurefire.failIfNoSpecifiedTests=false'], 600)
    if status:
        raise RuntimeError('Canonical production integration/fingerprint tests failed')
    classes = workspace / 'classes'
    for relative in CLASSES:
        target = classes / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'quic/target/classes' / relative, target)
    class_pins = {p: shared.digest(p) for p in classes.rglob('*.class')}
    methods = disassemble(jdk / 'bin/javap', classes, PACKAGE)
    if set(methods) != SCALARS | {PACKAGE, 'toString'}:
        raise RuntimeError('Generated method inventory changed')
    if any(methods[n]['descriptor'] != ('(JJJ)J' if n == 'Decode' else '(JJ)J') for n in SCALARS):
        raise RuntimeError('Generated scalar signatures changed')
    programs = {name: flatten(methods, name) for name in ('Decode', 'ReadPrefix', 'Unprotect')}
    (workspace / 'programs.json').write_text(json.dumps(programs, indent=2) + '\n')
    header = disassemble(jdk / 'bin/javap', classes, 'io.github.mahmoudimus.quic.crypto.HeaderKey')
    pn = disassemble(jdk / 'bin/javap', classes, 'io.github.mahmoudimus.quic.packet.PacketNumber')
    io = {'header': check_io(header['unprotect']), 'prefix': check_io(pn['readProtected'], True, (2,)),
          'decode': check_io(pn['decode'], True, (0, 1, 2)),
          'validation': check_length_guard(pn['checkLength'])}
    if io['header'].count('buffer-read') != 5 or io['header'].count('buffer-write') != 5 or io['prefix'].count('buffer-read') != 4:
        raise RuntimeError('Fixed-address access inventory changed')
    extracted = workspace / 'ExtractedTraces.dfy'
    extracted.write_text(trace_harness(trace, programs))
    applied = shared.check_verified(*call('actual-class-traces', [dafny, 'verify', extracted, '--verify-included-files', *flags]), 14)
    shared.check_inputs(ROOT, pins)
    check_classes(class_pins)
    status, java_version = call('java-version', [jdk / 'bin/java', '-version'])
    if status:
        raise RuntimeError('JVM unavailable')
    return {'status': 'complete', 'scope': 'Generated scalar kernels and fixed-address adapters under explicit observer',
        'kernel_verified': verified, 'trace_model_verified': trace_verified, 'extracted_trace_verified': applied,
        'controls': controls, 'inputs': pins, 'generated_raw_sha256': shared.digest(raw),
        'packaged_java_sha256': shared.digest(ROOT / GENERATED),
        'classes': {str(p.relative_to(classes)): v for p, v in class_pins.items()},
        'io_events': io, 'program_nodes': {n: len(p['nodes']) for n, p in programs.items()},
        'dafny_version': version.strip(), 'solver_version': solver_version.strip(), 'solver_options': flags,
        'java_version': java_version.strip(), 'tool_asset': asset, 'commands': commands, 'workspace': str(workspace),
        'trusted': ['Dafny/Boogie/Z3', 'Java backend and bounded-shift lowering', 'javac/JVM/word-instruction observer',
                    'javap and structural/taint/range checker', 'handwritten buffer value packing and domain bridge',
                    'ByteBuffer/provider sampling and heap-role correspondence'],
        'excluded': ['JIT/CPU/provider/GC timing', 'downstream AEAD/key-phase/metadata handling',
                     'whole-record constant time', 'cryptographic security reduction', 'ML-KEM/SHAKE'],
        'production_runtime_dependencies_added': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/packet-verification')
    parser.add_argument('--cache', type=Path, default=Path(os.environ.get('MICROPROXY_FORMAL_CACHE', Path.home() / '.cache/microproxy-formal')))
    args = parser.parse_args(argv)
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    with (output / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report = output / 'report.json'
        shared.atomic_report(report, {'status': 'incomplete'})
        old = signal.getsignal(signal.SIGTERM)
        def cancel(signum, frame):
            raise KeyboardInterrupt('Packet replay cancelled')
        signal.signal(signal.SIGTERM, cancel)
        try:
            try:
                result = pipeline(args, output)
                shared.atomic_report(report, result)
            except Exception as error:
                shared.atomic_report(report, {'status': 'failed', 'error': str(error)})
                print(str(error), file=sys.stderr)
                return 1
            print('Complete: ' + str(report), flush=True)
        finally:
            signal.signal(signal.SIGTERM, old)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
