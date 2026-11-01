#!/usr/bin/env python3
"""Isolated old-vs-new HKDF key-schedule benchmark.

Compiles the frozen pre-adoption reference and the current generated production facade into
private temporary class directories, then runs fresh JVMs alternating mode order. It never writes
the Maven/CI build directories. Results are performance evidence only, not a timing proof.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile

import run


def digest_tree(root):
    return run.snapshot(root, '*.class')


def javac(java_home, classpath, output, sources, workspace, label):
    output.mkdir(parents=True, exist_ok=True)
    status, log = run.execute(
        [java_home / 'bin/javac', '--release', '21', '-g:lines,vars,source', '-encoding', 'UTF-8',
         '-Xpkginfo:always', '-Xlint:all,-serial,-cast,-rawtypes',
         '-cp', os.pathsep.join(map(str, classpath)), '-d', output, *map(str, sources)],
        workspace / f'{label}.log', timeout=300)
    if status or log.strip():
        raise RuntimeError(f'{label} compilation failed or warned: {log[-4000:]}')


def execute_java(java_home, classpath, arguments, workspace, label, heap_mb):
    status, output = run.execute(
        [java_home / 'bin/java', '-Xms512m', f'-Xmx{heap_mb}m', '-cp',
         os.pathsep.join(map(str, classpath)), 'HkdfBenchmark', *map(str, arguments)],
        workspace / f'{label}.log', timeout=600)
    if status:
        raise RuntimeError(f'{label} failed: {output[-4000:]}')
    for line in output.splitlines():
        if line.startswith('{"mode"'):
            return json.loads(line)
    raise RuntimeError(f'{label} produced no benchmark record')


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=4000)
    parser.add_argument('--rounds', type=int, default=7)
    parser.add_argument('--forks', type=int, default=3)
    parser.add_argument('--heap-mb', type=int, default=2048,
                        help='heap cap; a large heap separates compute cost from benchmark-induced GC')
    parser.add_argument('--output', type=Path,
                        help='write the full raw receipt here (isolated path recommended)')
    parser.add_argument('--java-home', type=Path, default=Path(os.environ.get('JAVA_HOME', '')))
    parser.add_argument('--cache', type=Path,
                        default=Path(os.environ.get('MICROPROXY_FORMAL_CACHE', Path.home() / '.cache/microproxy-formal')))
    args = parser.parse_args(argv)
    java_home = args.java_home.expanduser().resolve()
    if not (java_home / 'bin/javac').is_file():
        parser.error('Set JAVA_HOME (or pass --java-home) to a JDK 21+ installation')
    if args.iterations < 1 or args.rounds < 3 or args.forks < 1:
        parser.error('Use positive iterations, at least 3 rounds and at least 1 fork')
    _, runtime, _, _ = run.install(args.cache)
    with tempfile.TemporaryDirectory(prefix='hkdf-benchmark-') as name:
        workspace = Path(name)
        old_classes = workspace / 'old'
        new_classes = workspace / 'new'
        driver_classes = workspace / 'driver'
        javac(java_home, [runtime], old_classes,
              [run.HERE / 'java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java'],
              workspace, 'old-javac')
        new_sources = sorted(run.GENERATED_SOURCE.rglob('*.java'))
        new_sources += [run.ROOT / name for name in run.PRODUCTION_INPUTS]
        javac(java_home, [runtime], new_classes, new_sources, workspace, 'new-javac')
        javac(java_home, [old_classes, new_classes, runtime], driver_classes,
              [run.HERE / 'bench/HkdfBenchmark.java'], workspace, 'driver-javac')
        classpath = [driver_classes, old_classes, new_classes, runtime]
        _, javac_version = run.execute([java_home / 'bin/javac', '-version'],
                                       workspace / 'javac-version.log')
        _, java_version = run.execute([java_home / 'bin/java', '-version'],
                                      workspace / 'java-version.log')
        raw = []
        medians_by_key = {}
        for hash_name in ('sha256', 'sha384'):
            for fork in range(args.forks):
                order = ('old', 'new') if fork % 2 == 0 else ('new', 'old')
                for mode in order:
                    record = execute_java(java_home, classpath,
                                          [mode, hash_name, args.iterations, args.rounds, fork],
                                          workspace, f'{hash_name}-{mode}-fork{fork}', args.heap_mb)
                    raw.append(record)
                    medians_by_key.setdefault((hash_name, mode), []).append(record)
        summary = {}
        for hash_name in ('sha256', 'sha384'):
            old_records = medians_by_key[(hash_name, 'old')]
            new_records = medians_by_key[(hash_name, 'new')]
            old = medians(old_records)
            new = medians(new_records)
            by_fork_old = {record['fork']: record for record in old_records}
            by_fork_new = {record['fork']: record for record in new_records}
            # Paired per-fork ratios share the same host/JIT conditions; report both the
            # median and the observed range instead of hiding shared-host variation.
            paired_wall = [by_fork_new[fork]['ns_per_iteration'] / by_fork_old[fork]['ns_per_iteration']
                           for fork in sorted(by_fork_old)]
            paired_cpu = [by_fork_new[fork]['cpu_ns_per_iteration'] / by_fork_old[fork]['cpu_ns_per_iteration']
                          for fork in sorted(by_fork_old)
                          if by_fork_old[fork]['cpu_ns_per_iteration'] > 0
                          and by_fork_new[fork]['cpu_ns_per_iteration'] > 0]
            summary[hash_name] = {
                'old': old, 'new': new,
                'median_of_fork_wall_medians_ratio': (new['wall_ns_per_iteration_median_of_forks']
                                                      / old['wall_ns_per_iteration_median_of_forks']),
                'paired_wall_ratio_new_over_old': {
                    'median': statistics.median(paired_wall), 'min': min(paired_wall), 'max': max(paired_wall)},
                'paired_cpu_ratio_new_over_old': ({
                    'median': statistics.median(paired_cpu), 'min': min(paired_cpu), 'max': max(paired_cpu)}
                    if paired_cpu else None),
            }
            cpu_text = ('CPU unavailable' if not paired_cpu else
                        f'paired CPU ratio median={statistics.median(paired_cpu):.2f}x '
                        f'[{min(paired_cpu):.2f}, {max(paired_cpu):.2f}]')
            print(f'{hash_name}: CPU old={old["cpu_ns_per_iteration_median_of_forks"]} '
                  f'new={new["cpu_ns_per_iteration_median_of_forks"]} ns/schedule, {cpu_text}; '
                  f'wall old={old["wall_ns_per_iteration_median_of_forks"]:.1f} '
                  f'new={new["wall_ns_per_iteration_median_of_forks"]:.1f} ns/schedule; '
                  f'alloc old={old["allocated_bytes_per_iteration_median_of_forks"]} B, '
                  f'new={new["allocated_bytes_per_iteration_median_of_forks"]} B', flush=True)
        receipt = {
            'schema': 'microproxy.hkdf-benchmark/v1',
            'status': 'diagnostic',
            'scope': 'TLS 1.3-shaped key schedule + QUIC key/iv/hp expansion; thread CPU time, wall clock and thread allocation only',
            'not_proved': ['constant-time execution', 'JVM/CPU timing model', 'network throughput or capacity',
                           'provider internals', 'all input sizes'],
            'workload': '3 Extract + 21 Expand-Label per iteration',
            'metrics': 'thread CPU time, wall clock and thread allocation; CPU is the primary component metric',
            'methodology': {'forks': args.forks, 'rounds': args.rounds, 'iterations': args.iterations,
                            'order': 'alternating old/new by fork',
                            'jvm': f'-Xms512m -Xmx{args.heap_mb}m',
                            'aggregate': 'median of per-fork round medians'},
            'environment': {'platform': platform.platform(), 'machine': platform.machine(),
                            'processor': platform.processor(), 'java_home': str(java_home),
                            'javac_version': javac_version.strip(), 'java_version': java_version.strip()},
            'class_pins': {'old': digest_tree(old_classes), 'new': digest_tree(new_classes),
                           'driver': digest_tree(driver_classes)},
            'summary': summary,
            'raw': raw,
        }
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(receipt, indent=2) + '\n')
            print(f'Receipt: {args.output}', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
