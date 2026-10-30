#!/usr/bin/env python3
"""Measure complete hybrid TLS handshakes with frozen baseline/candidate overlays."""
import argparse
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import delivery


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    candidate, output = args.candidate.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema':'microproxy.crypto-hybrid-handshake-performance/v1', 'status':'incomplete',
              'scope':'In-memory TLS1.3 client+server, negotiated X25519MLKEM768, certificate/Finished validation and bidirectional QUIC 1-RTT application-data checks; no socket/transport throughput or timing-security claim',
              'platform':platform.platform(), 'started_unix':time.time(), 'commands':[],
              'methodology':'3 fresh JVM forks per backend/JDK, alternating backend order; 512 warmup and 9 batches of32 complete handshakes per fork. Median of fork medians. Both endpoints execute on the measured main thread. Fixed seeded test certificates/randomness, AES128GCM/SHA256, h3, no resumption/retry. 256MiB fixed heap. Shared-host/JIT/GC noise remains.',
              'warmup':512, 'samples':9, 'batch':32, 'forks':3}

    def call(label, command, expected=0):
        result = subprocess.run(list(map(str, command)), text=True, capture_output=True, timeout=180)
        log = result.stdout+result.stderr
        (output/(label+'.log')).write_text(log)
        report['commands'].append({'label':label, 'argv':list(map(str,command)), 'exit':result.returncode,
                                   'log_sha256':delivery.digest(output/(label+'.log'))})
        if result.returncode != expected:
            raise RuntimeError(label+' failed: '+log[-3000:])
        return log

    try:
        measured = json.loads((candidate/'diagnostic-measurements.json').read_text())
        runtime = Path.home()/'.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar'
        if delivery.digest(runtime) != measured['runtime_sha256']:
            raise RuntimeError('Runtime differs from the measured candidate')
        report['runtime_sha256'] = delivery.digest(runtime)
        snapshots = {}
        for directory, field in [('baseline-classes','baseline_class_pins'), ('facade-classes','facade_class_pins'),
                                 ('canonical-classes','generated_class_pins')]:
            delivery.check_tree(candidate/directory, measured[field])
            delivery.freeze_inputs(candidate/directory, measured[field], output/directory)
            snapshots[directory] = measured[field]
        shared = delivery.class_map(delivery.ROOT/'quic/target/classes', [''])
        shared = {name:sha for name,sha in shared.items()
                  if not name.startswith(('io/github/mahmoudimus/quic/tls/MlKem768',
                                          'io/github/mahmoudimus/quic/tls/Shake',
                                          'io/github/mahmoudimus/quic/internal/verifiedcrypto/',
                                          'io/github/mahmoudimus/verifiedcrypto/'))}
        fixtures = delivery.class_map(delivery.ROOT/'quic/target/test-classes',
                    ['io/github/mahmoudimus/quic/tls/Handshakes', 'io/github/mahmoudimus/quic/tls/TestCerts'])
        if not shared or len(fixtures) < 4:
            raise RuntimeError('Missing compiled main classes or existing handshake fixtures')
        delivery.freeze_inputs(delivery.ROOT/'quic/target/classes', shared, output/'shared-main')
        delivery.freeze_inputs(delivery.ROOT/'quic/target/test-classes', fixtures, output/'fixtures')
        snapshots.update({'shared-main':shared, 'fixtures':fixtures})
        report['class_inputs'] = snapshots
        source_paths = [Path(__file__).resolve(), Path(__file__).with_name('HybridHandshakeBenchmark.java').resolve(),
                        delivery.ROOT/'quic/src/test/java/io/github/mahmoudimus/quic/tls/Handshakes.java',
                        delivery.ROOT/'quic/src/test/java/io/github/mahmoudimus/quic/tls/TestCerts.java',
                        delivery.ROOT/'formal/crypto/reference/Shake.java', delivery.ROOT/'formal/crypto/reference/MlKem768.java',
                        Path(__file__).with_name('Shake.java').resolve(), Path(__file__).with_name('MlKem768.java').resolve()]
        report['source_inputs'] = {str(p.relative_to(delivery.ROOT)):delivery.digest(p) for p in source_paths}
        report['shared_main_source_inputs'] = {
            p.relative_to(delivery.ROOT).as_posix():delivery.digest(p)
            for p in (delivery.ROOT/'quic/src/main/java').rglob('*.java')
            if not p.name in ('Shake.java','MlKem768.java')
            and '/internal/verifiedcrypto/' not in p.as_posix()
            and '/mahmoudimus/verifiedcrypto/' not in p.as_posix()}
        report['crypto_class_footprint_bytes'] = {
            directory:sum((output/directory/name).stat().st_size for name in snapshots[directory])
            for directory in ('baseline-classes','facade-classes','canonical-classes')}
        report['runtime_jar_bytes'] = runtime.stat().st_size
        junit = [Path(p) for p in json.loads((candidate/'diagnostic-receipt.json').read_text())['junit_inputs']]
        report['junit_inputs'] = {str(p):delivery.digest(p) for p in junit}
        report['jdk_inputs'] = {str(p.resolve()):delivery.tool_tree(p.resolve()) for p in args.java_home}
        report['jdk_versions'] = {str(p.resolve()):call('version-'+str(i), [p/'bin/java','-version'])
                                  for i,p in enumerate(args.java_home)}
        versions = [v.split('"')[1].split('.')[0] for v in report['jdk_versions'].values()]
        if sorted(versions) != ['21','25']:
            raise RuntimeError('Require explicit JDK21 and JDK25')
        harness = output/'harness'
        harness.mkdir()
        support = [output/'shared-main',output/'fixtures',*junit,runtime]
        cp = ':'.join(map(str,[output/'baseline-classes',*support]))
        call('compile-harness', [args.java_home[versions.index('21')]/'bin/javac', '--release','21','-g',
             '-Xlint:all,-serial','-cp',cp,'-d',harness,Path(__file__).with_name('HybridHandshakeBenchmark.java')])
        report['harness_classes'] = delivery.class_map(harness,[''])
        owner = 'io.github.mahmoudimus.quic.tls.HybridHandshakeBenchmark'
        wrong = call('negative-wrong-origin', [args.java_home[0]/'bin/java','-cp',cp+':'+str(harness),owner,
                     output/'shared-main',output/'shared-main',output/'fixtures',harness,'none','0','1'],expected=1)
        if 'Unexpected class origin' not in wrong:
            raise RuntimeError('Wrong-origin control did not reach its assertion')
        report['results'] = {}
        certificate_pins = set()
        for jdk, version in zip(args.java_home,versions):
            groups = {'baseline':[],'generated':[]}
            for fork in range(3):
                for backend in (['baseline','generated'] if fork % 2 == 0 else ['generated','baseline']):
                    front = output/('baseline-classes' if backend == 'baseline' else 'facade-classes')
                    native = 'none' if backend == 'baseline' else str(output/'canonical-classes')
                    classpath = ':'.join(map(str,[front,*([output/'canonical-classes'] if backend == 'generated' else []),*support,harness]))
                    log = call(f'jdk{version}-{backend}-fork{fork}', [jdk/'bin/java','-Xms256m','-Xmx256m','-cp',classpath,
                        owner,front,output/'shared-main',output/'fixtures',harness,native,'512','32'])
                    rows = [json.loads(line) for line in log.splitlines() if line.startswith('{')]
                    certificate_pins.add(rows[0]['certificate_chain_sha256'])
                    samples = [row for row in rows if 'completed_full_handshakes' in row]
                    if len(samples) != 9 or any(row['completed_full_handshakes'] != 32 for row in samples):
                        raise RuntimeError('Incomplete full-handshake samples')
                    values = {key:statistics.median(row[key]/32 for row in samples)
                              for key in ('wall_ns','cpu_ns','allocated_bytes')}
                    values['full_handshakes_per_second'] = 1e9/values['wall_ns']
                    groups[backend].append({'fork':fork,'median':values,'samples':samples})
            report['results'][version] = {backend:{'forks':forks, 'median':{
                key:statistics.median(fork['median'][key] for fork in forks)
                for key in ('wall_ns','cpu_ns','allocated_bytes','full_handshakes_per_second')}}
                for backend,forks in groups.items()}
        if len(certificate_pins) != 1:
            raise RuntimeError('Certificates differ across baseline/candidate/JDK forks')
        report['certificate_chain_sha256'] = next(iter(certificate_pins))
        for directory,pins in snapshots.items():
            delivery.check_tree(output/directory,pins)
        delivery.check_tree(harness, report['harness_classes'])
        delivery.check_pins(delivery.ROOT, report['source_inputs'])
        delivery.check_pins(delivery.ROOT, report['shared_main_source_inputs'])
        for name,pin in report['junit_inputs'].items():
            if delivery.digest(Path(name)) != pin:
                raise RuntimeError('JUnit support changed during measurement')
        for name,pins in report['jdk_inputs'].items():
            if delivery.tool_tree(Path(name)) != pins:
                raise RuntimeError('JDK changed during measurement')
        if delivery.digest(runtime) != report['runtime_sha256']:
            raise RuntimeError('Runtime changed during measurement')
        report.update({'status':'complete','completed_unix':time.time()})
    except BaseException as error:
        report['status'] = 'failed'
        report['error'] = str(error)
        raise
    finally:
        (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(output/'receipt.json')


if __name__ == '__main__':
    main()
