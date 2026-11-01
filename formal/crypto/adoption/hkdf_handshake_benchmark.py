#!/usr/bin/env python3
"""Measure generated HKDF in complete handshakes using frozen class snapshots.

Only Hkdf.class changes between the two classpaths. SHAKE/ML-KEM, TLS fixtures,
providers and runtime are held identical. This is performance evidence, not a
timing-security test. Compile current main and test classes before running it.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import delivery


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-revision', default='743a367fd935aa13791486e3ed77ff744ebf913b')
    parser.add_argument('--java-home', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--warmup', type=int, default=4096)
    args = parser.parse_args()
    root, output = delivery.ROOT, args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'microproxy.hkdf-handshake-performance/v1', 'status': 'incomplete',
              'platform': platform.platform(), 'started_unix': time.time(), 'commands': [],
              'scope': 'Complete in-memory nonresumed hybrid TLS handshake with bidirectional QUIC application data; HKDF-only backend difference. No network capacity or timing-security claim.',
              'methodology': f'Three fresh JVM forks per backend/JDK, alternating order; {args.warmup} warmup then 9 batches of32 complete handshakes, fixed256MiB heap. Median of fork medians; shared-host/JIT/GC noise remains.',
              'warmup': args.warmup,
              'results': {}}

    def call(label, command, expected=0):
        result = subprocess.run(list(map(str, command)), text=True, capture_output=True, timeout=240)
        text = result.stdout + result.stderr
        (output / (label + '.log')).write_text(text)
        report['commands'].append({'label': label, 'argv': list(map(str, command)), 'exit': result.returncode,
                                   'log_sha256': delivery.digest(output / (label + '.log'))})
        if result.returncode != expected:
            raise RuntimeError(label + ' failed: ' + text[-2000:])
        return text

    try:
        jdks = {}
        for jdk in args.java_home:
            version = call('version-' + str(len(jdks)), [jdk / 'bin/java', '-version'])
            major = version.split('"')[1].split('.')[0]
            if major in jdks:
                raise RuntimeError('Duplicate JDK major version')
            jdks[major] = jdk.resolve()
        if set(jdks) != {'21', '25'}:
            raise RuntimeError('Require exactly JDK21 and25')
        report['jdk_inputs'] = {str(jdk): delivery.tool_tree(jdk) for jdk in jdks.values()}
        runtime = Path.home() / '.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar'
        if delivery.digest(runtime) != json.loads((HERE.parent / 'delivery.json').read_text())['runtime']['sha256']:
            raise RuntimeError('Unexpected Dafny runtime')
        report['runtime_sha256'] = delivery.digest(runtime)
        snapshots = {}
        for name, source, prefixes in [
            ('main', root / 'quic/target/classes', ['']),
            ('fixtures', root / 'quic/target/test-classes', [
                'io/github/mahmoudimus/quic/tls/Handshakes', 'io/github/mahmoudimus/quic/tls/TestCerts'])]:
            pins = delivery.class_map(source, prefixes)
            if not pins:
                raise RuntimeError('Missing compiled ' + name)
            delivery.freeze_inputs(source, pins, output / name)
            snapshots[name] = pins
        report['class_inputs'] = snapshots
        owner = 'io/github/mahmoudimus/quic/Hkdf.class'
        delivery.freeze_inputs(output / 'main', {owner: snapshots['main'][owner]}, output / 'generated')
        source_name = 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java'
        baseline = subprocess.check_output(['git', '-C', str(root), 'show', args.baseline_revision + ':' + source_name])
        source = output / 'baseline-source/io/github/mahmoudimus/quic/Hkdf.java'
        source.parent.mkdir(parents=True)
        source.write_bytes(baseline)
        report['baseline'] = {'revision': subprocess.check_output([
            'git', '-C', str(root), 'rev-parse', args.baseline_revision], text=True).strip(),
            'source_sha256': hashlib.sha256(baseline).hexdigest()}
        call('compile-baseline', [jdks['21'] / 'bin/javac', '--release', '21', '-g', '-d', output / 'baseline', source])
        snapshots['baseline'] = delivery.class_map(output / 'baseline', [''])
        snapshots['generated'] = delivery.class_map(output / 'generated', [''])
        if set(snapshots['baseline']) != {owner} or set(snapshots['generated']) != {owner}:
            raise RuntimeError('Backend overlays must contain exactly Hkdf.class')
        junit = [Path.home() / '.m2/repository' / path for path in [
            'org/junit/jupiter/junit-jupiter-api/5.11.4/junit-jupiter-api-5.11.4.jar',
            'org/junit/platform/junit-platform-commons/1.11.4/junit-platform-commons-1.11.4.jar',
            'org/opentest4j/opentest4j/1.3.0/opentest4j-1.3.0.jar',
            'org/apiguardian/apiguardian-api/1.1.2/apiguardian-api-1.1.2.jar']]
        report['junit_inputs'] = {str(p): delivery.digest(p) for p in junit}
        sources = [HERE / 'HybridHandshakeBenchmark.java', HERE / 'HkdfHandshakeBenchmark.java', Path(__file__),
                   root / source_name, root / 'quic/src/test/java/io/github/mahmoudimus/quic/tls/Handshakes.java',
                   root / 'quic/src/test/java/io/github/mahmoudimus/quic/tls/TestCerts.java']
        report['source_inputs'] = {p.relative_to(root).as_posix(): delivery.digest(p) for p in sources}
        support = [output / 'main', output / 'fixtures', *junit, runtime]
        harness = output / 'harness'
        harness.mkdir()
        call('compile-harness', [jdks['21'] / 'bin/javac', '--release', '21', '-g', '-Xlint:all,-serial',
             '-cp', ':'.join(map(str, support)), '-d', harness, *sources[:2]])
        snapshots['harness'] = delivery.class_map(harness, [''])
        java_owner = 'io.github.mahmoudimus.quic.tls.HkdfHandshakeBenchmark'
        wrong = call('negative-wrong-origin', [jdks['21'] / 'bin/java', '-cp', ':'.join(map(str, [
            output / 'generated', *support, harness])), java_owner, output / 'baseline', output / 'main',
            output / 'fixtures', harness, 'true', '0', '1', runtime], expected=1)
        if 'Unexpected HKDF class origin' not in wrong:
            raise RuntimeError('Wrong-origin control did not reach its assertion')
        certificate_pins = set()
        for version, jdk in jdks.items():
            groups = {'baseline': [], 'generated': []}
            for fork in range(3):
                for backend in (['baseline', 'generated'] if fork % 2 == 0 else ['generated', 'baseline']):
                    front = output / backend
                    log = call(f'jdk{version}-{backend}-fork{fork}', [jdk / 'bin/java', '-Xms256m', '-Xmx256m',
                        '-cp', ':'.join(map(str, [front, *support, harness])), java_owner, front, output / 'main',
                        output / 'fixtures', harness, str(backend == 'generated').lower(), str(args.warmup), '32', runtime])
                    rows = [json.loads(line) for line in log.splitlines() if line.startswith('{')]
                    certificate_pins.add(rows[0]['certificate_chain_sha256'])
                    samples = [row for row in rows if 'completed_full_handshakes' in row]
                    if len(samples) != 9 or any(row['completed_full_handshakes'] != 32 for row in samples):
                        raise RuntimeError('Incomplete full-handshake samples')
                    values = {key: statistics.median(row[key] / 32 for row in samples)
                              for key in ('wall_ns', 'cpu_ns', 'allocated_bytes')}
                    values['full_handshakes_per_second'] = 1e9 / values['wall_ns']
                    groups[backend].append({'fork': fork, 'median': values, 'samples': samples})
            report['results'][version] = {backend: {'forks': forks, 'median': {
                key: statistics.median(fork['median'][key] for fork in forks)
                for key in ('wall_ns', 'cpu_ns', 'allocated_bytes', 'full_handshakes_per_second')}}
                for backend, forks in groups.items()}
        if len(certificate_pins) != 1:
            raise RuntimeError('Certificates differ across forks')
        report['certificate_chain_sha256'] = next(iter(certificate_pins))
        for name, pins in snapshots.items():
            delivery.check_tree(output / name, pins)
        delivery.check_pins(root, report['source_inputs'])
        for path, pins in report['jdk_inputs'].items():
            if delivery.tool_tree(Path(path)) != pins:
                raise RuntimeError('JDK changed during measurement')
        for path, digest in report['junit_inputs'].items():
            if delivery.digest(Path(path)) != digest:
                raise RuntimeError('JUnit changed during measurement')
        if delivery.digest(runtime) != report['runtime_sha256']:
            raise RuntimeError('Runtime changed during measurement')
        report.update(status='complete', completed_unix=time.time())
    except BaseException as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        (output / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print(output / 'receipt.json')


if __name__ == '__main__':
    main()
