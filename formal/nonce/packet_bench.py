#!/usr/bin/env python3
"""Baseline-vs-candidate PacketKey packet-protection benchmark.

The candidate overlay contains ONLY the reviewed PacketKey.java and the frozen
generated VerifiedNonce class. Everything else comes from the pinned
main-21 baseline class tree. The driver measures actual PacketKey.seal/open
round trips with synthetic public key/IV/packet-number/payload data, on JDK 21
and JDK 25, in separate fresh JVMs with alternating mode order.

This is performance evidence on one shared host. It is not a constant-time,
side-channel, security, throughput or capacity claim. Baseline/candidate runs
are separate JVMs, not contemporaneous fork pairs, so no paired statistics are
reported.

Persistent evidence:
  /Users/mahmoud/.cache/microproxy-formal/issue117-20261101/nonce/packet-integration
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOOLS = HERE / 'tools.json'
BASELINE = Path.home() / '.cache/microproxy-formal/issue117-20261101/baseline-main21/classes'
PACKETKEY_SOURCE = ROOT / 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java'
GENERATED_SOURCE = (ROOT / 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/'
                    'verifiednonce/VerifiedNonce/__default.java')
TEST_SOURCE = (ROOT / 'quic/src/test/java/io/github/mahmoudimus/quic/crypto/'
               'PacketKeyNonceTest.java')
DRIVER_SOURCE = HERE / 'bench/PacketKeyBenchmark.java'
DEFAULT_OUTPUT = Path.home() / '.cache/microproxy-formal/issue117-20261101/nonce/packet-integration'
EXPECTED_BASELINE_CLASSES = 467
EXPECTED_BASELINE_TREE_SHA256 = 'e5781bc243596013b0a16946ab87b8eba3480987469e42b062503003f3c70340'
EXPECTED_BASELINE_PACKETKEY_SHA256 = '61f7d592724838530ad4eeaead2d34c3b0eb055c5a1d878514904a2282694880'
EXPECTED_TESTS = 8
PACKETKEY_CLASS = 'io/github/mahmoudimus/quic/crypto/PacketKey.class'
GENERATED_CLASS = ('io/github/mahmoudimus/quic/crypto/internal/verifiednonce/'
                   'VerifiedNonce/__default.class')
SIZES = (64, 1200)
DEFAULT_ITERATIONS = {64: 100_000, 1200: 10_000}


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot(root, pattern):
    return {str(path.relative_to(root)): digest(path)
            for path in sorted(Path(root).rglob(pattern)) if path.is_file()}


def tree_hash(values):
    return hashlib.sha256(json.dumps(values, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def atomic_report(path, report):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(path)


def execute(command, log, timeout, label):
    with Path(log).open('w') as stream:
        try:
            result = subprocess.run([str(part) for part in command], cwd=ROOT,
                                    stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=timeout)
        except subprocess.TimeoutExpired as error:
            stream.write(f'\n{label} timed out after {timeout}s\n')
            raise RuntimeError(f'{label} timed out after {timeout}s') from error
    return result.returncode, Path(log).read_text(errors='replace')


def javac(java_home, classpath, output, sources, label, workspace, lint):
    output.mkdir(parents=True, exist_ok=True)
    command = [java_home / 'bin/javac', '--release', '21', '-g', '-encoding', 'UTF-8',
               *lint, '-cp', os.pathsep.join(map(str, classpath)), '-d', output,
               *map(str, sources)]
    status, text = execute(command, workspace / f'{label}.log', 300, label)
    if status or 'error:' in text.lower():
        raise RuntimeError(f'{label} failed: {text[-4000:]}')
    if 'warning:' in text.lower():
        raise RuntimeError(f'{label} emitted a warning: {text[-4000:]}')
    return command


def java_json(java_home, classpath, arguments, label, workspace, timeout=300):
    command = [java_home / 'bin/java', '-ea', '-cp',
               os.pathsep.join(map(str, classpath)),
               'io.github.mahmoudimus.nonce.packetbench.PacketKeyBenchmark',
               *map(str, arguments)]
    status, text = execute(command, workspace / f'{label}.log', timeout, label)
    if status:
        raise RuntimeError(f'{label} failed: {text[-4000:]}')
    for line in text.splitlines():
        if line.startswith('{') and '"mode"' in line:
            return json.loads(line), text
    raise RuntimeError(f'{label} produced no benchmark record: {text[-4000:]}')


def junit_jars():
    home = Path.home() / '.m2/repository'
    paths = [
        home / 'org/junit/jupiter/junit-jupiter-api/5.11.4/junit-jupiter-api-5.11.4.jar',
        home / 'org/junit/jupiter/junit-jupiter-engine/5.11.4/junit-jupiter-engine-5.11.4.jar',
        home / 'org/junit/jupiter/junit-jupiter-params/5.11.4/junit-jupiter-params-5.11.4.jar',
        home / 'org/junit/platform/junit-platform-commons/1.11.4/junit-platform-commons-1.11.4.jar',
        home / 'org/junit/platform/junit-platform-engine/1.11.4/junit-platform-engine-1.11.4.jar',
        home / 'org/junit/platform/junit-platform-launcher/1.11.4/junit-platform-launcher-1.11.4.jar',
        home / 'org/opentest4j/opentest4j/1.2.0/opentest4j-1.2.0.jar',
        home / 'org/apiguardian/apiguardian-api/1.1.2/apiguardian-api-1.1.2.jar',
    ]
    if not all(path.is_file() for path in paths):
        return None
    return paths


JUNIT_RUNNER = '''import java.io.PrintWriter;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

public final class PacketKeyJUnitRunner {
  public static void main(String[] args) {
    LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
        .selectors(selectClass(args[0])).build();
    Launcher launcher = LauncherFactory.create();
    SummaryGeneratingListener listener = new SummaryGeneratingListener();
    launcher.registerTestExecutionListeners(listener);
    launcher.execute(request);
    TestExecutionSummary summary = listener.getSummary();
    PrintWriter out = new PrintWriter(System.out);
    summary.printTo(out);
    summary.printFailuresTo(out);
    out.flush();
    if (summary.getTotalFailureCount() > 0) {
      System.exit(1);
    }
    System.out.println("PACKETKEY-TEST-OK tests=" + summary.getTestsSucceededCount()
        + " failed=" + summary.getTestsFailedCount());
  }
}
'''


def stats(values, key):
    available = [record[key] for record in values
                 if record.get('available') and record.get(key, -1) >= 0]
    if not available:
        return None
    return {'median': statistics.median(available), 'min': min(available),
            'max': max(available), 'values': available,
            'forks': len(available)}


def jdk_key(java_home, log):
    status, text = execute([java_home / 'bin/java', '-version'], log, 60, 'java-version')
    if status:
        raise RuntimeError(f'JDK unavailable: {java_home}')
    line = next((line for line in text.splitlines() if 'version' in line), text.strip())
    number = ''
    for token in line.split('"'):
        if token and token[0].isdigit():
            number = token.split('.')[0]
            break
    return f'jdk{number or "unknown"}', line.strip()


def pipeline(args, output, lock):
    tools = json.loads(TOOLS.read_text())
    baseline = args.baseline_classes.expanduser().resolve()
    runtime = args.runtime.expanduser().resolve()
    if digest(runtime) != tools['runtime']['sha256']:
        raise RuntimeError('Pinned Maven Dafny runtime checksum mismatch')
    primary = args.java_home.expanduser().resolve()
    homes = [primary]
    if args.extra_java_home:
        homes.append(args.extra_java_home.expanduser().resolve())
    workspace = Path(tempfile.mkdtemp(prefix='packet-benchmark-', dir=output))
    resolved_homes = []
    for index, home in enumerate(homes):
        key, version = jdk_key(home, workspace / f'jdk-{index}-version.log')
        resolved_homes.append((home, key, version))
    if len({key for _, key, _ in resolved_homes}) != len(resolved_homes):
        raise RuntimeError('Duplicate JDK keys; pass distinct runtimes')

    if not baseline.is_dir():
        raise RuntimeError(f'Missing frozen baseline classes: {baseline}')
    baseline_before = snapshot(baseline, '*.class')
    if len(baseline_before) != EXPECTED_BASELINE_CLASSES:
        raise RuntimeError(f'Baseline class count changed: {len(baseline_before)}')
    baseline_hash = tree_hash(baseline_before)
    if (baseline_hash != EXPECTED_BASELINE_TREE_SHA256
            or baseline_before.get(PACKETKEY_CLASS) != EXPECTED_BASELINE_PACKETKEY_SHA256):
        raise RuntimeError('Frozen baseline identity mismatch')

    source_before = {
        'runner': digest(Path(__file__)),
        'tools': digest(TOOLS),
        'packetkey': digest(PACKETKEY_SOURCE),
        'generated': digest(GENERATED_SOURCE),
        'test': digest(TEST_SOURCE),
        'driver': digest(DRIVER_SOURCE),
        'runtime': digest(runtime),
        'jdk': {key: {'java': digest(home / 'bin/java'),
                      'javac': digest(home / 'bin/javac')}
                for home, key, _ in resolved_homes},
    }
    commands = []
    started_utc = datetime.now(timezone.utc).isoformat()
    load_before = os.getloadavg()

    def call_compile(label, command):
        commands.append({'step': label, 'command': [str(c) for c in command],
                         'log': str(workspace / f'{label}.log'),
                         'timeout': 300})
        return execute(command, workspace / f'{label}.log', 300, label)

    overlay = workspace / 'overlay'
    overlay.mkdir()
    overlay_command = javac(
        primary, [baseline, runtime], overlay,
        [PACKETKEY_SOURCE, GENERATED_SOURCE], 'overlay-javac', workspace,
        ['-Xlint:all,-serial,-cast,-rawtypes'])
    commands.append({'step': 'overlay-javac',
                     'command': [str(c) for c in overlay_command],
                     'log': str(workspace / 'overlay-javac.log'), 'timeout': 300})
    overlay_classes = snapshot(overlay, '*.class')
    expected_overlay = {PACKETKEY_CLASS, GENERATED_CLASS}
    if set(overlay_classes) != expected_overlay:
        raise RuntimeError(f'Candidate overlay contains unexpected classes: {sorted(overlay_classes)}')
    if overlay_classes[PACKETKEY_CLASS] == baseline_before.get(PACKETKEY_CLASS):
        raise RuntimeError('Candidate PacketKey class is identical to baseline; expected bridge')
    if GENERATED_CLASS in baseline_before:
        raise RuntimeError('Generated nonce class unexpectedly present in baseline')
    if snapshot(baseline, '*.class') != baseline_before:
        raise RuntimeError('Baseline classes changed while compiling the overlay')
    javap_status, javap_text = call_compile(
        'overlay-javap',
        [primary / 'bin/javap', '-classpath', overlay, '-p', '-c',
         'io.github.mahmoudimus.quic.crypto.PacketKey'])
    if javap_status:
        raise RuntimeError('Cannot inspect candidate PacketKey bytecode')
    bridge_symbol = ('io/github/mahmoudimus/quic/crypto/internal/verifiednonce/'
                     'VerifiedNonce/__default.Nonce')
    if bridge_symbol not in javap_text:
        raise RuntimeError('Candidate PacketKey does not call the generated Nonce method')
    baseline_status, baseline_javap = call_compile(
        'baseline-javap',
        [primary / 'bin/javap', '-classpath', baseline, '-p', '-c',
         'io.github.mahmoudimus.quic.crypto.PacketKey'])
    if baseline_status or bridge_symbol in baseline_javap:
        raise RuntimeError('Baseline PacketKey bytecode is not the frozen non-bridge class')

    driver_classes = workspace / 'driver'
    driver_command = javac(primary, [baseline, runtime], driver_classes,
                           [DRIVER_SOURCE], 'driver-javac', workspace,
                           ['-Xlint:all,-serial'])
    commands.append({'step': 'driver-javac',
                     'command': [str(c) for c in driver_command],
                     'log': str(workspace / 'driver-javac.log'), 'timeout': 300})
    driver_classes_map = snapshot(driver_classes, '*.class')

    junit = junit_jars()
    test_results = {}
    if junit is None:
        test_results['status'] = 'skipped'
        test_results['reason'] = 'Pinned JUnit 5.11.4/1.11.4 jars were not found locally'
    else:
        runner_source = workspace / 'PacketKeyJUnitRunner.java'
        runner_source.write_text(JUNIT_RUNNER)
        test_classes = workspace / 'test-classes'
        junit_cp = [overlay, baseline, runtime, *junit]
        test_compile = javac(primary, junit_cp, test_classes,
                             [TEST_SOURCE, runner_source], 'test-javac', workspace,
                             ['-Xlint:all,-serial'])
        commands.append({'step': 'test-javac',
                         'command': [str(c) for c in test_compile],
                         'log': str(workspace / 'test-javac.log'), 'timeout': 300})
        for home, key, version in resolved_homes:
            classpath = [test_classes, overlay, baseline, runtime, *junit]
            status, text = execute(
                [home / 'bin/java', '-ea', '-cp', os.pathsep.join(map(str, classpath)),
                 'PacketKeyJUnitRunner', 'io.github.mahmoudimus.quic.crypto.PacketKeyNonceTest'],
                workspace / f'{key}-tests.log', 300, f'{key}-tests')
            if status or f'PACKETKEY-TEST-OK tests={EXPECTED_TESTS} failed=0' not in text:
                raise RuntimeError(f'{key} PacketKeyNonceTest failed: {text[-4000:]}')
            test_results[key] = {'version': version,
                                 'output': [line for line in text.splitlines()
                                            if 'PACKETKEY-TEST-OK' in line or 'tests successful' in line]}

    baseline_cp = [driver_classes, baseline, runtime]
    candidate_cp = [driver_classes, overlay, baseline, runtime]
    validation = {}
    for home, key, version in resolved_homes:
        baseline_record, _ = java_json(home, baseline_cp, ['validate'],
                                       f'{key}-validate-baseline', workspace)
        candidate_record, _ = java_json(home, candidate_cp, ['validate'],
                                        f'{key}-validate-candidate', workspace)
        if (baseline_record.get('digest') != candidate_record.get('digest')
                or baseline_record.get('cases') != candidate_record.get('cases')
                or baseline_record.get('suites') != candidate_record.get('suites')
                or baseline_record.get('skipped') != candidate_record.get('skipped')):
            raise RuntimeError(f'{key} baseline/candidate validation mismatch')
        validation[key] = {'version': version, 'baseline': baseline_record,
                           'candidate': candidate_record}

    raw = []
    timing_records = {}
    for home, key, version in resolved_homes:
        for suite in ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384',
                      'TLS_CHACHA20_POLY1305_SHA256']:
            for size in SIZES:
                iterations = args.iterations_64 if size == 64 else args.iterations_1200
                for fork in range(args.forks):
                    order = ('baseline', 'candidate') if fork % 2 == 0 else ('candidate', 'baseline')
                    for mode in order:
                        classpath = baseline_cp if mode == 'baseline' else candidate_cp
                        record, _ = java_json(
                            home, classpath,
                            ['time', suite, size, iterations, args.rounds, fork],
                            f'{key}-{suite}-{size}-{mode}-fork{fork}', workspace)
                        record.update({'jdk_key': key, 'jdk_version': version, 'mode': mode})
                        raw.append(record)
                        timing_records.setdefault((key, suite, size, mode), []).append(record)

    configurations = []
    for key, suite, size in sorted({(key, suite, size)
                                     for key, suite, size, _ in timing_records}):
        baseline_records = timing_records.get((key, suite, size, 'baseline'), [])
        candidate_records = timing_records.get((key, suite, size, 'candidate'), [])
        if not baseline_records or not candidate_records:
            continue
        if not all(record.get('available') for record in baseline_records + candidate_records):
            configurations.append({
                'jdk': key, 'suite': suite, 'size': size, 'available': False,
                'note': 'AEAD suite unavailable in at least one mode'})
            continue
        cpu_base = stats(baseline_records, 'cpu_ns_per_iteration')
        cpu_cand = stats(candidate_records, 'cpu_ns_per_iteration')
        wall_base = stats(baseline_records, 'ns_per_iteration')
        wall_cand = stats(candidate_records, 'ns_per_iteration')
        alloc_base = stats(baseline_records, 'allocated_bytes_per_iteration')
        alloc_cand = stats(candidate_records, 'allocated_bytes_per_iteration')
        def ratio(a, b):
            return (a['median'] / b['median']) if a and b and b['median'] else None
        def delta(a, b):
            return (a['median'] - b['median']) if a and b else None
        configurations.append({
            'jdk': key, 'suite': suite, 'size': size, 'available': True,
            'iterations': args.iterations_64 if size == 64 else args.iterations_1200,
            'rounds': args.rounds, 'forks': args.forks,
            'cpu_ns_per_iteration': {
                'baseline': cpu_base, 'candidate': cpu_cand,
                'ratio_of_medians_candidate_over_baseline': ratio(cpu_cand, cpu_base),
                'delta_ns_per_iteration': delta(cpu_cand, cpu_base)},
            'wall_ns_per_iteration': {
                'baseline': wall_base, 'candidate': wall_cand,
                'ratio_of_medians_candidate_over_baseline': ratio(wall_cand, wall_base),
                'delta_ns_per_iteration': delta(wall_cand, wall_base)},
            'allocated_bytes_per_iteration': {
                'baseline': alloc_base, 'candidate': alloc_cand},
            'pairing': 'none; separate fresh JVMs, alternating order, not contemporaneous pairs'})

    baseline_after = snapshot(baseline, '*.class')
    source_after = {
        'runner': digest(Path(__file__)),
        'tools': digest(TOOLS),
        'packetkey': digest(PACKETKEY_SOURCE),
        'generated': digest(GENERATED_SOURCE),
        'test': digest(TEST_SOURCE),
        'driver': digest(DRIVER_SOURCE),
        'runtime': digest(runtime),
        'jdk': {key: {'java': digest(home / 'bin/java'),
                      'javac': digest(home / 'bin/javac')}
                for home, key, _ in resolved_homes},
    }
    if baseline_after != baseline_before:
        raise RuntimeError('Baseline classes changed during the benchmark')
    if source_after != source_before:
        raise RuntimeError('Candidate/source/runtime/JDK hashes changed during the benchmark')
    if snapshot(overlay, '*.class') != overlay_classes:
        raise RuntimeError('Candidate overlay classes changed during the benchmark')

    load_after = os.getloadavg()
    finished_utc = datetime.now(timezone.utc).isoformat()
    return {
        'schema': 'microproxy.packetkey-nonce-benchmark/v1',
        'status': 'complete',
        'scope': 'baseline main-30d7c3c PacketKey vs overlay candidate PacketKey + generated nonce; actual seal/open round trips',
        'not_proved': [
            'constant-time execution', 'side-channel resistance', 'security or PRF hardness',
            'JVM/JIT/GC/CPU timing model', 'throughput or capacity',
            'production JAR/Maven/CI acceptance', 'full-handshake performance',
            'nonce-only cost (each iteration performs two nonce calls and two AEAD operations)',
        ],
        'methodology': {
            'baseline': 'frozen baseline-main21 classes, 467 classes, unchanged',
            'candidate_overlay': 'only PacketKey.java and generated __default.java compiled with JDK21 --release 21 -g into a private overlay',
            'workload': 'PacketKey.seal then PacketKey.open, 64- and 1200-byte payloads, all available suites',
            'packet': '20-byte synthetic header/AAD, fixed synthetic key and IV per suite, packet numbers increasing from 0x0102030405060708',
            'iterations': {'64': args.iterations_64, '1200': args.iterations_1200},
            'warmup_rounds': 2, 'measured_rounds': args.rounds, 'forks': args.forks,
            'order': 'alternating baseline/candidate by fork; each mode is a separate fresh JVM',
            'statistics': 'median of per-fork medians, min/max; no paired/fork-pair statistics',
            'metrics': 'thread CPU time primary, wall clock and thread allocation also recorded',
            'escape': 'volatile sink every iteration and volatile buffer escape every 64 iterations',
        },
        'environment': {
            'platform': platform.platform(), 'machine': platform.machine(),
            'processor': platform.processor(),
            'started_utc': started_utc, 'finished_utc': finished_utc,
            'load_average_before': load_before, 'load_average_after': load_after,
            'shared_host_note': 'host load and JIT/GC state are not controlled across separate JVMs; absolute values are diagnostic',
        },
        'baseline': {'path': str(baseline), 'classes': len(baseline_before),
                     'tree_sha256': baseline_hash, 'before_after_equal': True},
        'overlay': {'classes': overlay_classes,
                    'expected_classes': sorted(expected_overlay),
                    'baseline_packetkey_sha256': baseline_before.get(PACKETKEY_CLASS),
                    'candidate_packetkey_sha256': overlay_classes[PACKETKEY_CLASS],
                    'generated_nonce_sha256': overlay_classes[GENERATED_CLASS],
                    'bridge_symbol': bridge_symbol,
                    'baseline_packetkey_has_bridge': False},
        'sources': {'before': source_before, 'after': source_after,
                    'unchanged': True,
                    'packetkey_path': str(PACKETKEY_SOURCE),
                    'generated_path': str(GENERATED_SOURCE),
                    'test_path': str(TEST_SOURCE),
                    'driver_path': str(DRIVER_SOURCE)},
        'driver_classes': driver_classes_map,
        'validation': validation,
        'tests': test_results,
        'configurations': configurations,
        'raw': raw,
        'commands': commands,
        'workspace': str(workspace),
        'jdks': {key: {'path': str(home), 'version': version,
                       'java_sha256': digest(home / 'bin/java'),
                       'javac_sha256': digest(home / 'bin/javac')}
                 for home, key, version in resolved_homes},
        'limitations': [
            'Each timed iteration performs two nonce constructions (seal and open) plus two AEAD operations; this is not a pure nonce microbenchmark.',
            'Baseline classes were compiled earlier by the frozen Maven build; the candidate overlay was compiled with the pinned JDK21 in this run.',
            'Baseline and candidate runs are separate JVMs; no fork-pair statistical pairing or confidence interval is claimed.',
            'Host load, JIT, GC, CPU frequency and provider internals are uncontrolled; numbers are diagnostic for this host and date.',
            'No absolute overhead cap or adoption verdict is expressed here; root must weigh packet/handshake results.',
            'No constant-time, security, throughput, capacity or production-JAR claim is made.',
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--baseline-classes', type=Path, default=BASELINE)
    parser.add_argument('--runtime', type=Path,
                        default=Path.home() / '.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar')
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--extra-java-home', type=Path)
    parser.add_argument('--iterations-64', type=int, default=DEFAULT_ITERATIONS[64])
    parser.add_argument('--iterations-1200', type=int, default=DEFAULT_ITERATIONS[1200])
    parser.add_argument('--rounds', type=int, default=7)
    parser.add_argument('--forks', type=int, default=5)
    args = parser.parse_args(argv)
    if args.iterations_64 < 1 or args.iterations_1200 < 1:
        parser.error('iterations must be positive')
    if args.rounds < 3 or args.forks < 3:
        parser.error('rounds and forks must be at least 3')
    for home in [args.java_home, args.extra_java_home]:
        if home is not None and not (home / 'bin/java').is_file():
            parser.error(f'Missing JDK: {home}')
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    with (output / '.lock').open('w') as lock:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report = output / 'report.json'
        report.unlink(missing_ok=True)
        atomic_report(report, {'status': 'incomplete'})
        try:
            result = pipeline(args, output, lock)
        except Exception as error:
            atomic_report(report, {'status': 'failed', 'error': str(error)})
            print(str(error), file=sys.stderr)
            return 1
        atomic_report(report, result)
        print(f'Complete: {report}', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
