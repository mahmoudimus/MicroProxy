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
OUTER_MODULE = 'io.github.mahmoudimus.quic.internal.verifiedhkdf'
OUTPUT_NAME = 'HkdfCrypto'
GENERATED_MODULE = 'VerifiedHkdf'
GENERATED_PACKAGE = Path(*OUTER_MODULE.split('.')) / GENERATED_MODULE
GENERATED_SOURCE = ROOT / 'quic/src/main/java' / GENERATED_PACKAGE
GENERATED_RECEIPT = 'formal/dafny/hkdf/GENERATED.json'
PRODUCTION_INPUTS = (
    'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java',
    'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java',
    'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java',
)


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


def generated_class_sources(generated):
    package = generated / GENERATED_PACKAGE
    return {str(p.relative_to(package)): digest(p) for p in sorted(package.rglob('*.java'))}


def check_delivered_generated(generated):
    """Require the committed production package to be byte-identical to fresh translation."""
    fresh = generated_class_sources(generated)
    committed = {str(p.relative_to(GENERATED_SOURCE)): digest(p)
                 for p in sorted(GENERATED_SOURCE.rglob('*.java'))}
    missing = sorted(set(fresh) - set(committed))
    extra = sorted(set(committed) - set(fresh))
    changed = sorted(name for name in set(fresh) & set(committed) if fresh[name] != committed[name])
    if missing or extra or changed:
        raise RuntimeError('Committed generated HKDF sources diverge from fresh translation: '
                           f'missing={missing} extra={extra} changed={changed}')
    return committed


def check_aggregator(path):
    clean = re.sub(r'//[^\n]*', '', path.read_text())
    if re.sub(r'\bimport\s+[\w.*]+\s*;', '', clean).strip():
        raise RuntimeError('Unexpected executable top-level generated file')


def live_group(group):
    # Darwin returns EPERM for killpg(0) on zombie-only groups. Inspect state
    # rather than confusing that with a surviving, unsignalable child.
    states = subprocess.check_output(['ps', '-axo', 'pgid=,stat='], text=True, timeout=1)
    return any(int(parts[0]) == group and not parts[1].startswith('Z')
               for line in states.splitlines() if len(parts := line.split()) == 2)


def signal_group(group, sig):
    try:
        os.killpg(group, sig)
    except PermissionError:
        # Darwin can return EPERM for zombie-only groups. The owned leader is
        # still unreaped here, so its group identity cannot have been recycled.
        # Never ignore a signaling failure for a group with a live member.
        if live_group(group):
            raise


def stop_group(process):
    quiescent = False
    try:
        signal_group(process.pid, signal.SIGTERM)
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
                signal_group(process.pid, signal.SIGKILL)
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
    var x, {:ghost} tracex := VerifiedHkdf.Extract(h, a, b);
    assert x == VerifiedHkdf.ExtractSpec(h, a, b);
    var y, {:ghost} tracey := VerifiedHkdf.Expand(h, a, b, length);
    assert y == VerifiedHkdf.ExpandSpec(h, a, b, length);
    var z, {:ghost} tracez := VerifiedHkdf.LabelInfo(u, b, length);
    assert z == VerifiedHkdf.LabelInfoSpec(u, b, length);
    var w, {:ghost} tracew := VerifiedHkdf.ExpandLabel(h, a, u, b, length);
    assert w == VerifiedHkdf.ExpandLabelSpec(h, a, u, b, length);
  }
}
'''


def mutations(source):
    replacements = {
        'counter': ('var counter := i + 1;', 'var counter := i;'),
        'feedback': ('var next := Mac(hashLen, prk, previous + info + [counter as bv8]);',
                     'var next := Mac(hashLen, prk, info + [counter as bv8]);'),
        'truncation': ('r := Success(output[..length]);', 'r := Success(output);'),
        'prefix': ('var prefix: seq<bv8> := [116,', 'var prefix: seq<bv8> := [117,'),
        'public-domain': ('method Extract(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>) returns (r: BytesResult, ghost trace: seq<int>)',
                          'method Extract(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>) returns (r: BytesResult, ghost trace: seq<int>)\n    requires false')
    }
    results = {}
    for name, (old, new) in replacements.items():
        if source.count(old) != 1:
            raise RuntimeError(f'Mutation anchor changed: {name}; review controls')
        results[name] = source.replace(old, new, 1)
    return results


def input_inventory():
    required = {str(p.relative_to(ROOT)) for p in HERE.rglob('*')
                if p.suffix in {'.dfy', '.java', '.py'} or p.name == 'tools.json'}
    required.update(PRODUCTION_INPUTS)
    required.update(str(p.relative_to(ROOT)) for p in GENERATED_SOURCE.rglob('*.java'))
    required.add(GENERATED_RECEIPT)
    return required


def pipeline(args, output):
    manifest = json.loads((HERE / 'inputs.json').read_text())
    pins = manifest['inputs']
    required = input_inventory()
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

    prefix = workspace / OUTPUT_NAME
    check_verified(*call('generate-java', [dafny, 'translate', 'java', '--outer-module', OUTER_MODULE,
        '--output', prefix, source, *FLAGS]), 21)
    generated = workspace / f'{OUTPUT_NAME}-java'
    generated_hashes = snapshot(generated, '*.java')
    aggregator = generated / f'{OUTPUT_NAME}.java'
    if not generated_hashes or not (generated / GENERATED_PACKAGE / '__default.java').is_file():
        raise RuntimeError('Missing generated HKDF implementation')
    if not aggregator.is_file():
        raise RuntimeError('Missing generated top-level translation file')
    check_aggregator(aggregator)
    delivered = check_delivered_generated(generated)
    classes = workspace / 'classes'
    classes.mkdir()
    java_home = Path(os.environ.get('JAVA_HOME', ''))
    if not os.environ.get('JAVA_HOME'):
        raise RuntimeError('Set JAVA_HOME to a JDK 21+ installation')
    javac, java = java_home / 'bin/javac', java_home / 'bin/java'
    status, javac_version = call('javac-version', [javac, '-version'])
    if status:
        raise RuntimeError('JDK compiler unavailable')
    java_sources = (sorted((generated / GENERATED_PACKAGE).rglob('*.java'))
                    + sorted((HERE / 'java').rglob('*.java'))
                    + [ROOT / name for name in PRODUCTION_INPUTS])
    status, diagnostics = call('javac', [javac, '--release', '21', '-g:lines,vars,source', '-encoding', 'UTF-8',
        '-Xpkginfo:always', '-Xlint:all,-serial,-cast,-rawtypes', '-cp', runtime, '-d', classes, *java_sources])
    if status or diagnostics.strip():
        raise RuntimeError('Generated Java compilation failed or emitted diagnostics: ' + diagnostics[-4000:])
    status, diagnostics = call('adapter-discipline', [sys.executable,
        HERE / 'check_adapter_discipline.py', '--java-home', java_home,
        '--classes', classes, '--runtime', runtime])
    if status:
        raise RuntimeError('Adapter discipline gate failed: ' + diagnostics[-4000:])
    status, diagnostics = call('adapter-control', [sys.executable,
        HERE / 'check_adapter_discipline.py', '--java-home', java_home,
        '--classes', classes, '--runtime', runtime, '--self-test'])
    if status:
        raise RuntimeError('Adapter discipline negative control failed: ' + diagnostics[-4000:])
    controls['adapter-select-loop'] = 'bytecode-rejected'
    controls['adapter-bare-cast'] = 'bytecode-rejected'
    controls['adapter-dead-decoy'] = 'bytecode-rejected'
    strict = workspace / 'strict-handwritten'
    strict.mkdir()
    status, diagnostics = call('handwritten-javac', [javac, '--release', '21', '-g:lines,vars,source', '-encoding', 'UTF-8',
        '-Xpkginfo:always', '-Xlint:all,-serial', '-cp', f'{classes}{os.pathsep}{runtime}', '-d', strict,
        *[ROOT / name for name in PRODUCTION_INPUTS]])
    if status or diagnostics.strip():
        raise RuntimeError('Strict handwritten production compilation failed or emitted diagnostics: '
                           + diagnostics[-4000:])
    runtimes = [java] + [home / 'bin/java' for home in args.java_home]
    java_results = []
    for index, executable in enumerate(runtimes):
        status, runtime_version = call(f'java-{index}-version', [executable, '-version'])
        if status:
            raise RuntimeError('JDK runtime unavailable')
        status, tests = call(f'java-{index}-tests', [executable, '-ea', '-cp', f'{classes}{os.pathsep}{runtime}',
                            'io.github.mahmoudimus.verifiedcrypto.GeneratedHkdfTest'])
        if status or not re.search(r'45 cases.*2766 assertions', tests):
            raise RuntimeError('Generated Java regression tests failed or test inventory changed')
        java_results.append({'version': runtime_version.strip(), 'tests': tests.strip(),
                             'executable_sha256': digest(executable)})
    check_inputs(ROOT, pins)
    check_generated(generated, generated_hashes)
    class_hashes = snapshot(classes, '*.class')
    # Snapshot includes the canonical handwritten reference and test harness;
    # footprint below counts the generated implementation separately.
    generated_classes = [p for p in (classes / GENERATED_PACKAGE).rglob('*.class')]
    with ZipFile(runtime) as jar:
        runtime_classes = len([n for n in jar.namelist() if n.endswith('.class')])
    return {
        'status': 'complete', 'scope': 'Generated HKDF adopted by quic.Hkdf via the reviewed HkdfBridge/JdkHmac boundary',
        'claims': ['Dafny Extract/Expand/TLS label functional equations relative to abstract HMAC',
                   'Committed production generated sources equal fresh pinned translation byte for byte',
                   'Generated Java and reviewed Java adapters tested with real JCE; production facade compiled with strict lint'],
        'production_test_note': 'quic HkdfTest and HkdfGeneratedAdoptionTest are run separately; this replay does not execute them',
        'not_proved': ['HMAC security/correctness', 'Java adapter refinement', 'JVM/provider timing',
                       'constant-time traces', 'secret erasure', 'whole-bytecode equivalence', 'ML-KEM/SHAKE'],
        'inputs': pins, 'dafny_version': version.strip(), 'tool_asset': asset,
        'verified': verified, 'public_domain_verified': domain_count,
        'assumptions': ['VerifiedHkdf.Mac: deterministic external HMAC with fixed output length'],
        'controls': controls,
        'adapter_discipline': 'JdkHmac.bytes has a guarded toRawArray/instanceof [B/branch/checkcast/areturn shape; HkdfBridge delegates; select/Byte rejected',
        'generated_java': generated_hashes, 'delivered_generated_java': delivered,
        'top_level_aggregator_sha256': digest(aggregator),
        'translation_metadata_sha256': digest(generated / f'{OUTPUT_NAME}-java.dtr'),
        'classes': class_hashes,
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
        report.unlink(missing_ok=True)  # Marker failure must not preserve old success.
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
