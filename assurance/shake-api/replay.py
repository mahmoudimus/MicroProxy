#!/usr/bin/env python3
"""Qualify direct SHAKE API public-state/status proofs; no operation-trace claim."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENTRY = 'assurance/shake-api/ApiStateHarness.dfy'
CONTROL_ENTRY = 'assurance/shake-api/controls/NegativeControls.dfy'
REPLAY_INPUTS = {
    'assurance/shake-api/replay.py', 'assurance/shake-api/test_replay.py',
    'assurance/shake-api/README.md', 'formal/crypto/delivery.py',
    'formal/dafny/toolchain.py', 'formal/dafny/tools.json',
}
FLAGS = ['--verification-time-limit', '30', '--resource-limit', '50000000',
         '--solver-option', 'O:smt.case_split=0', '--cores', '2']
# Set only from the reviewed actual frozen harness qualification, before success.
FULL_COUNT = 1558
HARNESS_COUNT = 51
NEGATIVE_COUNT = 0
CONTROL_NAMES = {
    'empty-read-phase': 'WrongEmptyReadPhase',
    'phase-before-bounds': 'WrongPhaseBeforeBounds',
    'invalid-slice': 'WrongInvalidSlice',
    'destroy-phase': 'WrongDestroyPhase',
    'next-boundary-position': 'WrongNextBoundaryPosition',
}
SUMMARY = re.compile(r'^Dafny program verifier finished with (\d+) verified, (\d+) errors?\s*$', re.M)
BAD = re.compile(r'warning:|out of resources?|timed?\s*out|timeout|parse(?:r)? errors?|'
                 r'resolution/type errors?|internal error|\bexception\b|System\.\w*Exception|crash|inconclusive|'
                 r'CASE-TIMEOUT', re.I)
ERROR_LOCATION = re.compile(r'^(.+?\.dfy)\((\d+),\d+\): Error: assertion might not hold\s*$', re.M)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked_file(root, name):
    if (not isinstance(name, str) or not name or '\\' in name or
            Path(name).is_absolute() or '..' in Path(name).parts or
            name != Path(name).as_posix()):
        raise ValueError('Unsafe input path: ' + str(name))
    root = Path(root).resolve()
    path = root
    for part in Path(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('Linked input component: ' + name)
    if not path.is_file() or root not in path.resolve().parents:
        raise ValueError('Missing or escaping input: ' + name)
    return path


def check_pins(root, pins):
    if not isinstance(pins, dict):
        raise ValueError('Expected an exact input map')
    for name, digest in pins.items():
        path = checked_file(root, name)
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or sha(path) != digest:
            raise ValueError('Input changed: ' + name)


def check_inventory(sources, inputs):
    if set(inputs) != set(sources) | REPLAY_INPUTS:
        raise ValueError('Included source/replay input inventory omitted or added files')
    if any(inputs[name] != digest for name, digest in sources.items()):
        raise ValueError('Source/input maps disagree')


def discover_graph(root, dafny, discover, call=None):
    graph = {}
    for index, entry in enumerate((ENTRY, CONTROL_ENTRY)):
        callback = (lambda label, command, i=index: call(f'graph-{i}-{label}', command)) if call else None
        found = discover(root, root / entry, dafny, call=callback)
        for name, digest in found.items():
            if name in graph and graph[name] != digest:
                raise ValueError('Source changed between parser traversals: ' + name)
            graph[name] = digest
    return dict(sorted(graph.items()))


def check_graph(actual, declared):
    if actual != declared:
        raise ValueError('Parser-discovered transitive source graph differs from manifest')


def check_manifest(path, expected):
    if Path(path).read_bytes() != expected:
        raise ValueError('Manifest changed during replay')


def admit_output(root, output):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists; refusing without mutation')
    root = Path(root).resolve()
    resolved = output.resolve()
    if resolved == root or (root in resolved.parents and root / 'target' not in resolved.parents):
        raise ValueError('Output must be outside checkout or below target/')
    output.mkdir(parents=True, exist_ok=False)
    return output.resolve()


def proof_result(status, text, expected, negative=None):
    summaries = SUMMARY.findall(text)
    if len(summaries) != 1 or BAD.search(text) or expected < 0 or (negative is None and expected == 0):
        raise ValueError('Missing clean nonempty verifier summary or forbidden diagnostic')
    verified, errors = map(int, summaries[0])
    if verified != expected:
        raise ValueError('Reviewed proof inventory changed')
    if negative is None:
        if status != 0 or errors != 0 or 'Error:' in text:
            raise ValueError('Expected complete successful verification')
    else:
        name, line, anchor = negative
        locations = ERROR_LOCATION.findall(text)
        if (status != 4 or errors != 1 or len(locations) != 1 or
                not (locations[0][0] == name or locations[0][0].endswith('/' + name)) or
                int(locations[0][1]) != line or anchor not in text or text.count(': Error:') != 1):
            raise ValueError('Expected the exact named assertion failure, not a tool/precondition failure')
    return {'verified': verified, 'errors': errors}


def audit_result(status, text, expected=0, anchor=None):
    counts = re.findall(r'^Dafny auditor completed with (\d+) findings?\s*$', text, re.M)
    cleaned = text.replace('Warning:', '') if expected else text
    if (status != 0 or counts != [str(expected)] or BAD.search(cleaned) or 'Error:' in text or
            (expected and (not anchor or anchor not in text or
                           len(re.findall('warning:', text, re.I)) != expected))):
        raise ValueError('Unexpected source audit diagnostic or finding')
    return expected


def check_audits(graph, records):
    if set(graph) != set(records) or any(r.get('findings') != 0 for r in records.values()):
        raise ValueError('Missing included-file audit or unexpected finding')


def execute(command, log, cwd, timeout=900):
    with Path(log).open('w') as output:
        process = subprocess.Popen(list(map(str, command)), cwd=cwd, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            # A tool parent may exit while an owned child ignores SIGTERM.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output.write('\nCASE-TIMEOUT\n')
            status = 124
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    return status, Path(log).read_text()


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=Path.home() / '.cache/microproxy-formal')
    args = parser.parse_args(argv)
    try:
        out = admit_output(ROOT, args.output)
    except (ValueError, OSError) as error:
        print(json.dumps({'status': 'rejected', 'error': str(error)}))
        return 1
    report = {'schema': 'microproxy.shake-api-state/1', 'status': 'incomplete',
              'scope': 'Actual SHAKE public API state/status coupling only',
              'not_claimed': ['operation trace independence', 'observer completeness',
                              'Java/JVM refinement', 'physical timing or erasure',
                              'cryptographic hardness', 'external expert review'],
              'commands': [], 'proofs': {}, 'audits': {}, 'controls': {}}
    report_path = out / 'report.json'
    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    save()
    try:
        manifest_path = checked_file(ROOT, 'assurance/shake-api/inputs.json')
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        if set(manifest) != {'schema', 'sources', 'inputs'} or manifest['schema'] != 'microproxy.shake-api-state-inputs/1':
            raise ValueError('Unexpected source manifest schema')
        sources, pins = manifest['sources'], manifest['inputs']
        check_inventory(sources, pins)
        check_pins(ROOT, pins)
        frozen = out / 'frozen'
        for name in pins:
            target = frozen / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(checked_file(ROOT, name), target)
        check_pins(frozen, pins)
        tools = load_module(frozen / 'formal/dafny/toolchain.py', 'shake_pinned_tools')
        discovery = load_module(frozen / 'formal/crypto/delivery.py', 'shake_pinned_discovery')
        dafny, _, tool_manifest, asset = tools.install(args.cache)
        if tool_manifest['version'] != '4.9.1':
            raise ValueError('Expected checksum-pinned Dafny 4.9.1')
        solver = dafny.parent / 'z3/bin/z3-4.12.1'
        identities = {'dafny': sha(dafny), 'solver': sha(solver), 'archive': asset['sha256']}
        report.update(manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
                      inputs_before=pins, tools=identities)
        def call(label, command):
            log = out / (label + '.log')
            status, text = execute(command, log, frozen)
            report['commands'].append({'label': label, 'argv': list(map(str, command)),
                                       'cwd': str(frozen), 'exit': status,
                                       'log': log.name, 'log_sha256': sha(log)})
            save()
            return status, text
        graph = discover_graph(frozen, dafny, discovery.source_closure, call=call)
        check_graph(graph, sources)
        report['source_graph'] = graph
        status, text = call('complete-source', [dafny, 'verify', ENTRY, '--verify-included-files',
                                               *FLAGS, '--solver-path', solver])
        report['proofs']['complete_source'] = proof_result(status, text, FULL_COUNT)
        status, text = call('api-domain', [dafny, 'verify', ENTRY, *FLAGS, '--solver-path', solver])
        report['proofs']['api_domain'] = proof_result(status, text, HARNESS_COUNT)
        for index, name in enumerate(graph):
            status, text = call(f'audit-{index}', [dafny, 'audit', name])
            report['audits'][name] = {'findings': audit_result(status, text)}
        check_audits(graph, report['audits'])
        control_text = (frozen / CONTROL_ENTRY).read_text()
        for label, method in CONTROL_NAMES.items():
            matches = [(i, line.strip()) for i, line in enumerate(control_text.splitlines(), 1)
                       if line.strip().endswith('// NEGATIVE ' + label)]
            if len(matches) != 1:
                raise ValueError('Missing/duplicated semantic control anchor: ' + label)
            line, anchor = matches[0]
            status, text = call('control-' + label,
                [dafny, 'verify', CONTROL_ENTRY, '--filter-symbol', 'ShakeApiControls.' + method,
                 *FLAGS, '--solver-path', solver])
            record = proof_result(status, text, NEGATIVE_COUNT,
                                  negative=(CONTROL_ENTRY, line, anchor.split('//')[0].strip()))
            report['controls'][label] = {**record, 'method': method, 'assertion_line': line}
        mutant = out / 'included-assumption'
        shutil.copytree(frozen, mutant)
        native = mutant / 'formal/crypto/NativeShake.dfy'
        original = native.read_text()
        anchor = '    ghost var before := sponge.Model();'
        if original.count(anchor) != 1:
            raise ValueError('Included-body assumption control anchor changed')
        native.write_text(original.replace(anchor, '    assume {:axiom} false;\n' + anchor, 1))
        status, text = call('control-included-assumption', [dafny, 'audit', native])
        report['included_assumption_findings'] = audit_result(status, text, expected=1,
            anchor='Xof: Definition has `assume {:axiom}` statement in body')
        check_pins(frozen, pins)
        check_pins(ROOT, pins)
        check_manifest(manifest_path, manifest_bytes)
        final_dafny, _, _, _ = tools.install(args.cache)
        if final_dafny != dafny or identities != {
                'dafny': sha(dafny), 'solver': sha(solver), 'archive': asset['sha256']}:
            raise ValueError('Tool distribution changed during replay')
        report.update(status='complete', inputs_after=pins)
    except Exception as error:
        report.update(status='FAILED', error_type=type(error).__name__, error=str(error))
        save()
        print(json.dumps({k: report[k] for k in ('status', 'error_type', 'error')}))
        return 1
    except KeyboardInterrupt:
        report.update(status='incomplete', failure_kind='interrupted')
        save()
        return 130
    save()
    print(json.dumps({'status': report['status'], 'proofs': report['proofs'],
                      'audited_files': len(report['audits']), 'controls': len(report['controls'])}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
