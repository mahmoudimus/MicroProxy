#!/usr/bin/env python3
"""Replay the pinned upstream HKDF target or its complete include closure.

This is provenance evidence, separate from MicroProxy's stronger local contracts.
In particular, verifying the target does not verify its included dependencies.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
INCLUDE = re.compile(r'^\s*include\s+"([^"]+)"', re.M)
SUMMARY = re.compile(r'Dafny program verifier finished with (\d+) verified, (\d+) errors')
RESOURCE_ERROR = re.compile(r'out of resource|timed? out|timeout|inconclusive|internal error|crash', re.I)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_path(root, name):
    relative = PurePosixPath(name)
    if relative.is_absolute() or not relative.parts or '..' in relative.parts or '\\' in name:
        raise ValueError('Unsafe reference path: ' + name)
    path = root.joinpath(*relative.parts)
    if path.resolve() != path or not path.is_file():
        raise ValueError('Missing or redirected reference input: ' + name)
    return path


def check_inputs(root, pins):
    for name, digest in {**pins['inputs'], **pins['recipe_inputs']}.items():
        if not re.fullmatch(r'[a-f0-9]{64}', digest) or sha(checked_path(root, name)) != digest:
            raise ValueError('Changed reference input: ' + name)
    seen = set()

    def visit(name):
        if name in seen:
            return
        path = checked_path(root, name)
        seen.add(name)
        for included in INCLUDE.findall(path.read_text()):
            target = (path.parent / included).resolve()
            try:
                relative = target.relative_to(root).as_posix()
            except ValueError as error:
                raise ValueError('Include escapes reference checkout') from error
            visit(relative)

    visit(pins['entry'])
    if seen != set(pins['inputs']):
        raise ValueError('Upstream include inventory changed')
    for directory, revision in [('.', pins['commit']), *pins['submodules'].items()]:
        actual = subprocess.check_output(['git', '-C', str(root / directory), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != revision:
            raise ValueError('Changed reference revision: ' + directory)


def verified(status, output):
    summaries = SUMMARY.findall(output)
    if status != 0 or len(summaries) != 1 or RESOURCE_ERROR.search(output) or 'Error:' in output:
        raise ValueError('Reference replay failed or was inconclusive')
    count, errors = map(int, summaries[0])
    if count < 9 or errors != 0:
        raise ValueError('Missing upstream HKDF obligations')
    return count


def check_tool(cache, requested, pins):
    # Reuse the reviewed installer: it checks the archive and EVERY extracted
    # assembly/solver against that archive, not just the executable's version.
    for name, digest in pins['tool_inputs'].items():
        if sha(checked_path(REPOSITORY, name)) != digest:
            raise ValueError('Changed reference tool installation policy: ' + name)
    sys.path.insert(0, str(REPOSITORY / 'formal/dafny'))
    from toolchain import install
    official, _, _, asset = install(cache)
    if requested.resolve() != official.resolve():
        raise ValueError('Reference replay requires the checksum-pinned official Dafny distribution')
    version = subprocess.check_output([official, '--version'], text=True).strip()
    if version != pins['dafny_build']:
        raise ValueError('Unexpected Dafny build')
    return {'binary_sha256': sha(official), 'archive_sha256': asset['sha256'], 'version': version}


def closure_verified(count, pins):
    minimum = pins['closure_verified_minimum']
    if type(minimum) is not int or minimum <= 9 or minimum < len(pins['inputs']):
        raise ValueError('No reviewed successful full-closure baseline exists; full graph stays unverified')
    if count < minimum:
        raise ValueError('Closure replay did not discharge the reviewed full-graph obligation count')


def execute(command, timeout):
    # The owned process group bounds cleanup to this replay and its solver children.
    with tempfile.TemporaryFile(mode='w+') as capture:
        process = subprocess.Popen(command, stdout=capture, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except BaseException as failure:
            cleanup_errors = []
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as error:
                cleanup_errors.append(str(error))
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            finally:
                # Solver children may outlive a leader which obeyed SIGTERM.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    cleanup_errors.append(str(error))
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                cleanup_errors.append(str(error))
            if cleanup_errors:
                raise RuntimeError(str(failure) + '; owned-process cleanup failed: ' + '; '.join(cleanup_errors)) from failure
            raise
        capture.seek(0)
        return status, capture.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--dafny', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=Path.home() / '.cache/microproxy-formal')
    parser.add_argument('--scope', choices=['target', 'closure'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.checkout.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'microproxy.aws-hkdf-reference-replay/v1', 'status': 'failed',
              'scope': args.scope, 'full_dependency_graph_verified': False}
    # Invalidate a previous success before any checkout/tool/replay operation.
    pending = args.output / 'report.json.tmp'
    pending.write_text(json.dumps({**report, 'status': 'running'}, indent=2) + '\n')
    pending.replace(args.output / 'report.json')
    try:
        pins = json.loads((HERE / 'inputs.json').read_text())
        report.update(manifest_sha256=sha(HERE / 'inputs.json'), trust=pins['trust'],
                      limitations=pins['limitations'])
        check_inputs(root, pins)
        report['tool_identity'] = check_tool(args.cache, args.dafny, pins)
        command = [str(args.dafny), 'verify', *pins['flags']]
        if args.scope == 'closure':
            command.append('--verify-included-files')
        command.append(str(root / pins['entry']))
        report.update(command=command, dafny_sha256=sha(args.dafny), inputs=pins['inputs'])
        status, output = execute(command, 1800)
        (args.output / 'verification.log').write_text(output)
        report.update(exit_code=status, log_sha256=sha(args.output / 'verification.log'))
        report['verified'] = verified(status, output)
        if args.scope == 'closure':
            closure_verified(report['verified'], pins)
        check_inputs(root, pins)
        if check_tool(args.cache, args.dafny, pins) != report['tool_identity']:
            raise ValueError('Reference tool distribution changed during replay')
        report.update(status='complete', full_dependency_graph_verified=args.scope == 'closure')
    except BaseException as error:
        report['error'] = str(error)
    temporary = args.output / 'report.json.tmp'
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(args.output / 'report.json')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'full_dependency_graph_verified')}))
    return 0 if report['status'] == 'complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
