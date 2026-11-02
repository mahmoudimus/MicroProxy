#!/usr/bin/env python3
"""Isolated old-vs-new QUIC nonce benchmark.

Compiles the frozen pre-adoption clone/XOR reference and the checked-in
Dafny-generated production class into private class directories, then runs
fresh JVMs alternating mode order. It never writes Maven/CI build directories.
Results are performance evidence only, not a timing, constant-time or
side-channel proof.

The workload is one 12-byte nonce allocation plus the IV copy and packet-number
XOR. Warmup, forced array escape, wall clock, thread CPU time and thread
allocation are recorded. Each JDK gets independent fresh forks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
GENERATED = ROOT / 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/VerifiedNonce'
JAVA_HARNESS = HERE / 'java/io/github/mahmoudimus/nonce/ReferenceNonce.java'
DRIVER = HERE / 'bench/NonceBenchmark.java'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot(root, pattern):
    return {str(path.relative_to(root)): digest(path)
            for path in sorted(Path(root).rglob(pattern)) if path.is_file()}


def execute(command, timeout, label):
    try:
        result = subprocess.run([str(part) for part in command], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f'{label} timed out after {timeout}s') from error
    return result.returncode, result.stdout


def javac(java_home, classpath, output, sources, label):
    output.mkdir(parents=True, exist_ok=True)
    command = [java_home / 'bin/javac', '--release', '21', '-g:lines,vars,source',
               '-encoding', 'UTF-8', '-Xpkginfo:always',
               '-Xlint:all,-serial,-cast,-rawtypes', '-Werror',
               '-cp', os.pathsep.join(map(str, classpath)), '-d', output,
               *map(str, sources)]
    status, log = execute(command, 300, label)
    if status or log.strip():
        raise RuntimeError(f'{label} failed or warned: {log[-4000:]}')


def java_record(java_home, classpath, arguments, label, heap_mb):
    command = [java_home / 'bin/java', '-Xms512m', f'-Xmx{heap_mb}m',
               '-cp', os.pathsep.join(map(str, classpath)),
               'io.github.mahmoudimus.nonce.bench.NonceBenchmark',
               *map(str, arguments)]
    status, output = execute(command, 300, label)
    if status:
        raise RuntimeError(f'{label} failed: {output[-4000:]}')
    for line in output.splitlines():
        if line.startswith('{') and '"mode"' in line:
            return json.loads(line)
    raise RuntimeError(f'{label} produced no benchmark record: {output[-4000:]}')


def medians(records):
    wall = statistics.median(record['ns_per_iteration'] for record in records)
    cpus = [record['cpu_ns_per_iteration'] for record in records]
    allocations = [record['allocated_bytes_per_iteration'] for record in records]
    return {
        'forks': len(records),
        'wall_ns_per_iteration_median_of_forks': wall,
        'cpu_ns_per_iteration_median_of_forks': (
            statistics.median(cpus) if all(value >= 0 for value in cpus) else None),
        'allocated_bytes_per_iteration_median_of_forks': (
            statistics.median(allocations) if all(value >= 0 for value in allocations) else None),
        'jdk': records[0]['jdk'],
        'vm': records[0]['vm'],
    }


def run_jdk(java_home, runtime, args, workspace, key):
    old_classes = workspace / f'{key}-old'
    new_classes = workspace / f'{key}-new'
    driver_classes = workspace / f'{key}-driver'
    javac(java_home, [runtime], old_classes, [JAVA_HARNESS], f'{key}-old-javac')
    javac(java_home, [runtime], new_classes, sorted(GENERATED.rglob('*.java')),
          f'{key}-new-javac')
    javac(java_home, [old_classes, new_classes, runtime], driver_classes, [DRIVER],
          f'{key}-driver-javac')
    classpath = [driver_classes, old_classes, new_classes, runtime]
    _, javac_version = execute([java_home / 'bin/javac', '-version'], 60, f'{key}-javac-version')
    _, java_version = execute([java_home / 'bin/java', '-version'], 60, f'{key}-java-version')
    raw = []
    by_mode = {'old': [], 'new': []}
    for fork in range(args.forks):
        order = ('old', 'new') if fork % 2 == 0 else ('new', 'old')
        for mode in order:
            record = java_record(java_home, classpath,
                                 [mode, args.iterations, args.rounds, fork],
                                 f'{key}-{mode}-fork{fork}', args.heap_mb)
            record['jdk_key'] = key
            raw.append(record)
            by_mode[mode].append(record)
    old = medians(by_mode['old'])
    new = medians(by_mode['new'])
    old_by_fork = {record['fork']: record for record in by_mode['old']}
    new_by_fork = {record['fork']: record for record in by_mode['new']}
    paired_wall = [new_by_fork[fork]['ns_per_iteration'] / old_by_fork[fork]['ns_per_iteration']
                   for fork in sorted(old_by_fork)]
    paired_cpu = [new_by_fork[fork]['cpu_ns_per_iteration'] / old_by_fork[fork]['cpu_ns_per_iteration']
                  for fork in sorted(old_by_fork)
                  if old_by_fork[fork]['cpu_ns_per_iteration'] > 0
                  and new_by_fork[fork]['cpu_ns_per_iteration'] > 0]
    summary = {
        'old': old,
        'new': new,
        'median_of_fork_wall_medians_ratio': (new['wall_ns_per_iteration_median_of_forks']
                                              / old['wall_ns_per_iteration_median_of_forks']),
        'paired_wall_ratio_new_over_old': {
            'median': statistics.median(paired_wall),
            'min': min(paired_wall), 'max': max(paired_wall)},
        'paired_cpu_ratio_new_over_old': ({
            'median': statistics.median(paired_cpu),
            'min': min(paired_cpu), 'max': max(paired_cpu)} if paired_cpu else None),
    }
    cpu_text = ('CPU unavailable' if not paired_cpu else
                f"paired CPU ratio median={statistics.median(paired_cpu):.2f}x "
                f"[{min(paired_cpu):.2f}, {max(paired_cpu):.2f}]")
    print(f'{key}: {old["jdk"]} / {new["vm"]}; '
          f'old={old["wall_ns_per_iteration_median_of_forks"]:.2f} ns/op, '
          f'new={new["wall_ns_per_iteration_median_of_forks"]:.2f} ns/op; {cpu_text}; '
          f'alloc old={old["allocated_bytes_per_iteration_median_of_forks"]} B, '
          f'new={new["allocated_bytes_per_iteration_median_of_forks"]} B', flush=True)
    return {
        'environment': {
            'platform': platform.platform(), 'machine': platform.machine(),
            'processor': platform.processor(), 'java_home': str(java_home),
            'javac_version': javac_version.strip(), 'java_version': java_version.strip(),
            'javac_sha256': digest(java_home / 'bin/javac'),
            'java_sha256': digest(java_home / 'bin/java'),
        },
        'class_pins': {'old': snapshot(old_classes, '*.class'),
                       'new': snapshot(new_classes, '*.class'),
                       'driver': snapshot(driver_classes, '*.class')},
        'summary': summary,
        'raw': raw,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True,
                        help='primary JDK 21+ (JDK 21 in this replay)')
    parser.add_argument('--extra-java-home', type=Path, action='append', default=[],
                        help='additional JDK runtime to benchmark (JDK 25 in this replay)')
    parser.add_argument('--runtime', type=Path, required=True,
                        help='pinned DafnyRuntime-4.9.1.jar')
    parser.add_argument('--iterations', type=int, default=200_000)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--forks', type=int, default=5)
    parser.add_argument('--heap-mb', type=int, default=2048)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.iterations < 1 or args.rounds < 3 or args.forks < 1:
        parser.error('Use positive iterations, at least 3 rounds and at least 1 fork')
    homes = []
    for home in [args.java_home, *args.extra_java_home]:
        home = home.expanduser().resolve()
        if not (home / 'bin/javac').is_file() or not (home / 'bin/java').is_file():
            parser.error(f'Missing JDK: {home}')
        _, banner = execute([home / 'bin/java', '-version'], 60, f'{home.name}-version')
        match = __import__('re').search(r'version "(\d+)', banner)
        if not match:
            parser.error(f'Cannot identify JDK version: {home}')
        key = f'jdk{match.group(1)}'
        if any(existing == key for existing, _ in homes):
            key = f'{key}-{home.name}'
        homes.append((home, key))
    runtime = args.runtime.expanduser().resolve()
    if not (GENERATED / '__default.java').is_file():
        parser.error(f'Missing checked-in generated package: {GENERATED}')
    receipt = {
        'schema': 'microproxy.nonce-benchmark/v1',
        'status': 'diagnostic',
        'scope': 'one 12-byte QUIC nonce construction; wall clock, thread CPU time and thread allocation only',
        'not_proved': ['constant-time execution', 'JVM/CPU timing model',
                       'side channels', 'network throughput or capacity',
                       'JIT behavior on other hosts', 'cryptographic hardness'],
        'workload': 'one fresh 12-byte nonce (IV copy + 8-byte big-endian XOR) per iteration',
        'methodology': {
            'forks': args.forks, 'rounds': args.rounds, 'iterations': args.iterations,
            'order': 'alternating old/new by fork',
            'jvm': f'-Xms512m -Xmx{args.heap_mb}m',
            'warmup': 'two full rounds before samples',
            'escape': 'volatile array store every 64 iterations plus byte sink',
            'aggregate': 'median of per-fork round medians',
        },
        'source_pins': {
            'generated': snapshot(GENERATED, '*.java'),
            'reference': {str(JAVA_HARNESS.relative_to(ROOT)): digest(JAVA_HARNESS)},
            'driver': {str(DRIVER.relative_to(ROOT)): digest(DRIVER)},
            'runtime_sha256': digest(runtime),
        },
        'jdk_runs': {},
    }
    with tempfile.TemporaryDirectory(prefix='nonce-benchmark-') as name:
        workspace = Path(name)
        for home, key in homes:
            receipt['jdk_runs'][key] = run_jdk(home, runtime, args, workspace, key)
    receipt['comparison_note'] = (
        'Performance is diagnostic and host-specific. The generated class allocates the same '
        '12-byte output as the old implementation; it also pays Dafny runtime helper and '
        'constant array-index overhead. No constant-time claim is made.')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix('.tmp')
    temporary.write_text(json.dumps(receipt, indent=2) + '\n')
    temporary.replace(args.output)
    print(f'Receipt: {args.output}', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
