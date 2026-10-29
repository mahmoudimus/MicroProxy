#!/usr/bin/env python3
"""Verify HKDF, audit assumptions, generate Java and exercise its real JCE boundary."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
from zipfile import ZipFile

from toolchain import digest, install

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FLAGS = ['--allow-external-contracts', '--verification-time-limit', '30', '--resource-limit', '10000000']
SUMMARY = r'Dafny program verifier finished with (\d+) verified, (\d+) errors?'


def atomic_report(path, report):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(path)


def check_inputs(root, pins):
    for name, expected in pins.items():
        path = root / name
        if not path.is_file() or digest(path) != expected:
            raise RuntimeError(f'Input changed; review before renewing pin: {name}')
    return dict(pins)


def snapshot(root, pattern):
    return {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob(pattern)) if p.is_file()}


def check_generated(root, expected):
    if snapshot(root, '*.java') != expected:
        raise RuntimeError('Generated Java changed during replay')


def live_group(group):
    # Darwin returns EPERM for killpg(0) on zombie-only groups. Inspect state
    # rather than confusing that with a surviving, unsignalable child.
    states = subprocess.check_output(['ps', '-axo', 'pgid=,stat='], text=True, timeout=1)
    return any(int(parts[0]) == group and not parts[1].startswith('Z')
               for line in states.splitlines() if len(parts := line.split()) == 2)


def stop_group(process):
    quiescent = False
    try:
        os.killpg(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + .5
        while time.monotonic() < deadline:
            # Keep the leader unreaped until the final signal: reaping here can
            # detach/recycle the process-group identity (Darwin may return EPERM).
            try:
                quiescent = not live_group(process.pid)
            except (OSError, subprocess.SubprocessError):
                # Inspection is optional; failure must force the kill path.
                break
            if quiescent:
                break
            time.sleep(.02)
    except ProcessLookupError:
        quiescent = True
    finally:
        try:
            if not quiescent:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            # Reaping is attempted even if signaling or ps failed. No diagnostic
            # subprocess is a prerequisite for this last termination attempt.
            process.wait(timeout=1)


def execute(command, log, timeout=180):
    with log.open('w') as stream:
        process = None
        completed = False
        pending = []
        handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        try:
            # Defer cancellation during Popen so ownership is recorded before a
            # Python signal handler can raise. Children do not inherit handlers
            # across exec; no blocked signal mask is inherited.
            for s in handlers:
                signal.signal(s, lambda signum, frame: pending.append(signum))
            try:
                process = subprocess.Popen([str(c) for c in command], cwd=ROOT, stdout=stream,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            finally:
                for s, handler in handlers.items():
                    signal.signal(s, handler)
            if pending:
                raise KeyboardInterrupt('Cancelled while starting tool')
            status = process.wait(timeout=timeout)
            completed = True
        except subprocess.TimeoutExpired:
            status = 124
            stream.write('\nRunner timeout; terminating process group.\n')
        finally:
            # wait() reaps the leader. Do not signal a possibly recycled process
            # group after normal completion of a trusted tool.
            if process is not None and not completed:
                stop_group(process)
    return status, log.read_text(errors='replace')


def check_verified(status, output, minimum):
    summaries = re.findall(SUMMARY, output)
    if status != 0 or len(summaries) != 1 or int(summaries[0][0]) < minimum or int(summaries[0][1]) != 0:
        raise RuntimeError('Expected completed Dafny verification; see log')
    return int(summaries[0][0])


def check_rejected(status, output):
    summaries = re.findall(SUMMARY, output)
    bad_run = re.search(r'time.?out|out of resource|out of memory|internal error|unhandled exception', output, re.I)
    obligation = re.search(r'postcondition could not be proved|assertion might not hold|precondition.*could not be proved', output)
    if status != 4 or not obligation or bad_run or len(summaries) != 1 or int(summaries[0][1]) == 0:
        raise RuntimeError('Control did not fail a proof obligation; crash/timeout/parser errors are not evidence')


def check_audit(status, output):
    warnings = [line for line in output.splitlines() if 'Warning:' in line]
    allowed = r'.*\(\d+,\d+\): Warning: Mac: Declaration has explicit `\{:\s*axiom\}` attribute\. Possible mitigation: Provide a proof or test\.'
    if (status != 0 or len(warnings) != 1 or not re.fullmatch(allowed, warnings[0])
            or 'Dafny auditor completed with 1 findings' not in output):
        raise RuntimeError('Unexpected Dafny trust assumption; see audit log')


def domain_harness(source):
    return '''include "''' + source.as_posix() + '''"
module PublicDomain {
  import VerifiedHkdf
  method AllInputs(h: int, a: seq<bv8>, b: seq<bv8>, u: seq<bv16>, length: int) {
    var x := VerifiedHkdf.Extract(h, a, b);
    assert x == VerifiedHkdf.ExtractSpec(h, a, b);
    var y := VerifiedHkdf.Expand(h, a, b, length);
    assert y == VerifiedHkdf.ExpandSpec(h, a, b, length);
    var z := VerifiedHkdf.LabelInfo(u, b, length);
    assert z == VerifiedHkdf.LabelInfoSpec(u, b, length);
    var w := VerifiedHkdf.ExpandLabel(h, a, u, b, length);
    assert w == VerifiedHkdf.ExpandLabelSpec(h, a, u, b, length);
  }
}
'''


def mutations(source):
    replacements = {
        'counter': ('var counter := i + 1;', 'var counter := i;'),
        'feedback': ('previous + info + [counter as bv8]', 'info + [counter as bv8]'),
        'truncation': ('r := Success(output[..length]);', 'r := Success(output);'),
        'prefix': ('var prefix: seq<bv8> := [116,', 'var prefix: seq<bv8> := [117,'),
        'public-domain': ('method Extract(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>) returns (r: BytesResult)',
                          'method Extract(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>) returns (r: BytesResult)\n    requires false')
    }
    results = {}
    for name, (old, new) in replacements.items():
        if source.count(old) != 1:
            raise RuntimeError(f'Mutation anchor changed: {name}; review controls')
        results[name] = source.replace(old, new, 1)
    return results


def pipeline(args, output):
    manifest = json.loads((HERE / 'inputs.json').read_text())
    pins = manifest['inputs']
    required = {str(p.relative_to(ROOT)) for p in HERE.rglob('*')
                if p.suffix in {'.dfy', '.java', '.py'} or p.name == 'tools.json'}
    required.add('quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java')
    if set(pins) != required:
        raise RuntimeError('Proof input inventory changed; review manifest')
    check_inputs(ROOT, pins)
    dafny, runtime, tools, asset = install(args.cache)
    workspace = Path(tempfile.mkdtemp(prefix='replay-', dir=output))
    commands = []

    def call(label, command, timeout=180):
        print(label, flush=True)
        commands.append({'step': label, 'command': [str(c) for c in command], 'log': str(workspace / f'{label}.log')})
        return execute(command, workspace / f'{label}.log', timeout)

    code, version = call('dafny-version', [dafny, '--version'])
    if code or not version.strip().startswith(tools['version'] + '+'):
        raise RuntimeError('Unexpected Dafny version')
    source = HERE / 'hkdf/Hkdf.dfy'
    check_audit(*call('assumption-audit', [dafny, 'audit', source, '--allow-external-contracts']))
    verified = check_verified(*call('kernel-proof', [dafny, 'verify', source, *FLAGS]), 21)
    harness = workspace / 'PublicDomain.dfy'
    harness.write_text(domain_harness(source))
    domain_count = check_verified(*call('public-domain', [dafny, 'verify', harness, '--verify-included-files', *FLAGS]), 22)
    controls = {}
    for name, mutation in mutations(source.read_text()).items():
        folder = workspace / name
        folder.mkdir()
        mutated = folder / 'Hkdf.dfy'
        mutated.write_text(mutation)
        target = mutated
        extra = []
        if name == 'public-domain':
            target = folder / 'PublicDomain.dfy'
            target.write_text(domain_harness(mutated))
            extra = ['--verify-included-files']
        check_rejected(*call('control-' + name, [dafny, 'verify', target, *extra, *FLAGS]))
        controls[name] = 'proof-obligation-rejected'
    extra_assumption = workspace / 'ExtraAssumption.dfy'
    extra_assumption.write_text(source.read_text().replace('module VerifiedHkdf {',
                               'module VerifiedHkdf {\n  lemma {:axiom} ExtraAssumption()'))
    status, audit = call('control-assumption', [dafny, 'audit', extra_assumption, '--allow-external-contracts'])
    if status != 0 or 'Dafny auditor completed with 2 findings' not in audit:
        raise RuntimeError('Extra-assumption audit control did not run successfully')
    try:
        check_audit(status, audit)
    except RuntimeError:
        controls['extra-assumption'] = 'audit-rejected'
    else:
        raise RuntimeError('Extra assumption was accepted')
    skipped_proof = workspace / 'SkippedProof.dfy'
    skipped_proof.write_text(source.read_text().replace('method Extract(', 'method {:verify false} Extract(', 1))
    status, audit = call('control-skipped-proof', [dafny, 'audit', skipped_proof, '--allow-external-contracts'])
    if status != 0 or 'Dafny auditor completed with 2 findings' not in audit:
        raise RuntimeError('Skipped-proof audit control did not run successfully')
    try:
        check_audit(status, audit)
    except RuntimeError:
        controls['skipped-proof'] = 'audit-rejected'
    else:
        raise RuntimeError('Skipped proof was accepted')

    prefix = workspace / 'Kernel'
    check_verified(*call('generate-java', [dafny, 'translate', 'java', '--output', prefix, source, *FLAGS]), 21)
    generated = workspace / 'Kernel-java'
    generated_hashes = snapshot(generated, '*.java')
    if not generated_hashes or not (generated / 'VerifiedHkdf/__default.java').is_file():
        raise RuntimeError('Missing generated HKDF implementation')
    classes = workspace / 'classes'
    classes.mkdir()
    java_home = Path(os.environ.get('JAVA_HOME', ''))
    if not os.environ.get('JAVA_HOME'):
        raise RuntimeError('Set JAVA_HOME to a JDK 21+ installation')
    javac, java = java_home / 'bin/javac', java_home / 'bin/java'
    status, javac_version = call('javac-version', [javac, '-version'])
    if status:
        raise RuntimeError('JDK compiler unavailable')
    java_sources = sorted(generated.rglob('*.java')) + sorted((HERE / 'java').rglob('*.java'))
    java_sources.append(ROOT / 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java')
    status, _ = call('javac', [javac, '--release', '21', '-cp', runtime, '-d', classes, *java_sources])
    if status:
        raise RuntimeError('Generated Java compilation failed')
    runtimes = [java] + [home / 'bin/java' for home in args.java_home]
    java_results = []
    for index, executable in enumerate(runtimes):
        status, runtime_version = call(f'java-{index}-version', [executable, '-version'])
        if status:
            raise RuntimeError('JDK runtime unavailable')
        status, tests = call(f'java-{index}-tests', [executable, '-ea', '-cp', f'{classes}{os.pathsep}{runtime}',
                            'io.github.mahmoudimus.verifiedcrypto.GeneratedHkdfTest'])
        if status or not re.search(r'43 cases.*2745 assertions', tests):
            raise RuntimeError('Generated Java regression tests failed or test inventory changed')
        java_results.append({'version': runtime_version.strip(), 'tests': tests.strip(),
                             'executable_sha256': digest(executable)})
    check_inputs(ROOT, pins)
    check_generated(generated, generated_hashes)
    class_hashes = snapshot(classes, '*.class')
    # Snapshot includes the canonical handwritten reference and test harness;
    # footprint below counts the generated implementation separately.
    generated_classes = [p for p in (classes / 'VerifiedHkdf').rglob('*.class')]
    with ZipFile(runtime) as jar:
        runtime_classes = len([n for n in jar.namelist() if n.endswith('.class')])
    return {
        'status': 'complete', 'scope': 'Generated HKDF component; production Hkdf remains unchanged',
        'claims': ['Dafny Extract/Expand/TLS label functional equations relative to abstract HMAC',
                   'Public methods callable for all mathematical inputs; errors returned as data',
                   'Generated Java tested with real JCE; compiler, runtime and Java adapters trusted'],
        'not_proved': ['HMAC security/correctness', 'Java adapter refinement', 'JVM/provider timing',
                       'constant-time traces', 'secret erasure', 'production Hkdf refinement', 'ML-KEM/SHAKE'],
        'inputs': pins, 'dafny_version': version.strip(), 'tool_asset': asset,
        'verified': verified, 'public_domain_verified': domain_count,
        'assumptions': ['VerifiedHkdf.Mac: deterministic external HMAC with fixed output length'],
        'controls': controls, 'generated_java': generated_hashes, 'classes': class_hashes,
        'javac_version': javac_version.strip(), 'java_runs': java_results,
        'runtime_sha256': digest(runtime),
        'footprint': {'generated_java_files': len(generated_hashes),
                      'generated_java_bytes': sum(p.stat().st_size for p in generated.rglob('*.java')),
                      'generated_classes': len(generated_classes),
                      'generated_class_bytes': sum(p.stat().st_size for p in generated_classes),
                      'dafny_runtime_bytes': runtime.stat().st_size, 'dafny_runtime_classes': runtime_classes},
        'commands': commands, 'workspace': str(workspace)
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/dafny-hkdf')
    parser.add_argument('--cache', type=Path, default=Path(os.environ.get('MICROPROXY_FORMAL_CACHE', Path.home() / '.cache/microproxy-formal')))
    parser.add_argument('--java-home', type=Path, action='append', default=[], help='Additional JDK runtime to test')
    args = parser.parse_args(argv)
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    with (output / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report = output / 'report.json'
        atomic_report(report, {'status': 'incomplete'})
        previous = signal.getsignal(signal.SIGTERM)
        def cancel(signum, frame):
            raise KeyboardInterrupt('Proof replay terminated')
        signal.signal(signal.SIGTERM, cancel)
        try:
            try:
                result = pipeline(args, output)
            except Exception as error:
                atomic_report(report, {'status': 'failed', 'error': str(error)})
                print(str(error), file=sys.stderr)
                return 1
            atomic_report(report, result)
            print(f'Complete: {report}', flush=True)
        finally:
            signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
