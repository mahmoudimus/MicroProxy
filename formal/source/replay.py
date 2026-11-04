#!/usr/bin/env python3
"""Replay direct SHAKE ownership proofs over the production Dafny bodies.

This component proves source object/frame properties. It does not establish
source trace completeness, Java refinement, exclusive Java ownership or timing.
The existing generation and supplied-artifact gates provide separate evidence.
"""
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
ROOT = HERE.parent.parent
ENTRY = 'formal/source/ShakeOwnership.dfy'
DOMAIN = 'formal/crypto/native_shake_domain.dfy'
REPLAY_FILES = {'formal/source/replay.py', 'formal/source/test_replay.py',
                'formal/source/README.md', 'formal/crypto/delivery.py', 'formal/dafny/toolchain.py',
                'formal/dafny/tools.json'}
FLAGS = ['--verification-time-limit', '30', '--resource-limit', '50000000',
         '--solver-option', 'O:smt.case_split=0', '--cores', '2']
SUMMARY = re.compile(r'^Dafny program verifier finished with (\d+) verified, '
                     r'(\d+) errors?\s*$', re.M)
BAD = re.compile(r'warning:|out of resources?|timed?\s*out|timeout|parse errors?|'
                 r'resolution/type errors?|internal error|crash|inconclusive', re.I)
CONTROLS = {
    'factory-alias': ('assert FactoryOwned(s) && fresh(Footprint(s)) && |Footprint(s)| == 6;',
                      'assert s.lanes == s.scratch;', 'NativeShakeOwnership.NewOwned'),
    'output-alias': ('assert (output as object) != (input as object);',
                     'assert (output as object) == (input as object);',
                     'NativeShakeOwnership.XofOwned'),
    'external-footprint': ('assert (buffer as object) !in Footprint(s);',
                           'assert (buffer as object) == (s.offsets as object);',
                           'NativeShakeOwnership.ExternalAliased'),
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def proof_result(status, output, negative=None, expected=None):
    summaries = SUMMARY.findall(output)
    if len(summaries) != 1 or BAD.search(output):
        raise ValueError('Missing clean proof summary or forbidden diagnostic')
    verified, errors = map(int, summaries[0])
    if negative is None:
        if status != 0 or errors or verified == 0 or 'Error:' in output:
            raise ValueError('Expected a nonempty successful verification')
        if expected is not None and verified != expected:
            raise ValueError('Reviewed proof inventory changed')
    elif (status != 4 or verified != 1 or errors != 1 or negative not in output or
          'Error: assertion might not hold' not in output):
        raise ValueError('Expected a named assertion failure, not a tool failure')
    return {'verified': verified, 'errors': errors}


def audit_result(status, output, negative=False):
    counts = re.findall(r'^Dafny auditor completed with (\d+) findings?\s*$', output, re.M)
    if status or len(counts) != 1 or 'Error:' in output:
        raise ValueError('Expected a completed source audit')
    if negative:
        if (counts != ['1'] or 'NativeShake.dfy' not in output or
                'Xof: Definition has `assume {:axiom}` statement in body' not in output or
                BAD.search(output.replace('Warning:', ''))):
            raise ValueError('Expected the included-body assumption audit finding')
    elif counts != ['0'] or BAD.search(output):
        raise ValueError('Unexpected source trust assumption or audit diagnostic')
    return int(counts[0])


def check_pins(root, pins):
    for name, expected in pins.items():
        path = root / name
        if (not name or Path(name).is_absolute() or '..' in Path(name).parts or
                path.resolve() != path or not path.is_file() or
                not re.fullmatch('[0-9a-f]{64}', expected) or digest(path) != expected):
            raise ValueError('Changed or unsafe source-assurance input: ' + name)


def check_inventory(sources, pins):
    if set(pins) != set(sources) | REPLAY_FILES:
        raise ValueError('Source-assurance input inventory omitted or added files')


def closure(root, entries, dafny, discover, call=None):
    """Use the pinned compiler's actual parser, including BOM/comment syntax."""
    found = {}
    for index, entry in enumerate(entries):
        record = (lambda label, command, i=index: call(f'graph-{i}-{label}', command)) if call else None
        graph = discover(root, root / entry, dafny, call=record)
        for name, value in graph.items():
            if name in found and found[name] != value:
                raise ValueError('Source changed between parser traversals: ' + name)
            found[name] = value
    return dict(sorted(found.items()))


def execute(command, log, cwd, timeout=600):
    with log.open('w') as output:
        process = subprocess.Popen(list(map(str, command)), cwd=cwd, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            raise
    return status, log.read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=Path.home() / '.cache/microproxy-formal')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'microproxy.dafny-source-ownership/v1', 'status': 'incomplete',
              'scope': 'Direct SHAKE source ownership/freshness/frames only',
              'not_claimed': ['source trace completeness', 'whole crypto trace closure',
                              'Java/JVM refinement', 'global exclusive Java ownership',
                              'physical erasure', 'physical timing', 'external expert review'],
              'commands': [], 'proofs': {}, 'controls': {}}
    try:
        manifest_path = HERE / 'inputs.json'
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        if manifest.get('schema') != 'microproxy.dafny-source-inputs/v1':
            raise ValueError('Unexpected source-assurance input schema')
        report['manifest_sha256'] = hashlib.sha256(manifest_bytes).hexdigest()
        pins = manifest['inputs']
        check_pins(ROOT, pins)
        sources = manifest['sources']
        check_inventory(sources, pins)
        frozen = out / 'frozen'
        for name in pins:
            target = frozen / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        check_pins(frozen, pins)
        spec = importlib.util.spec_from_file_location('source_pinned_toolchain',
                                                     frozen / 'formal/dafny/toolchain.py')
        tools = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tools)
        spec = importlib.util.spec_from_file_location('source_pinned_discovery',
                                                     frozen / 'formal/crypto/delivery.py')
        discovery = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(discovery)
        dafny, _, tool_manifest, asset = tools.install(args.cache)
        if tool_manifest['version'] != '4.9.1':
            raise ValueError('Expected checksum-pinned Dafny 4.9.1')
        solver = dafny.parent / 'z3/bin/z3-4.12.1'
        tool_before = {'dafny': digest(dafny), 'solver': digest(solver),
                       'archive': asset['sha256']}
        report.update(inputs_before=pins, tools=tool_before)

        def call(label, arguments):
            log = out / (label + '.log')
            command = [dafny, *arguments]
            status, text = execute(command, log, frozen)
            report['commands'].append({'label': label, 'command': list(map(str, command)),
                                       'exit': status, 'log_sha256': digest(log)})
            return status, text

        def parser_call(label, command):
            if Path(command[0]) != dafny:
                raise ValueError('Unexpected dependency parser executable')
            return call(label, command[1:])

        sources = closure(frozen, (ENTRY, DOMAIN), dafny,
                          discovery.source_closure, call=parser_call)
        check_inventory(sources, pins)
        if sources != manifest['sources']:
            raise ValueError('Complete Dafny source inventory changed or omitted')
        report['source_graph'] = sources

        status, text = call('actual-bodies-and-domain',
                            ['verify', ENTRY, DOMAIN, '--verify-included-files',
                             *FLAGS, '--solver-path', solver])
        # Renew these reviewed counts only after replaying and reviewing source
        # changes. Without included-body verification this graph has only 45.
        report['proofs']['complete_source_graph'] = proof_result(status, text, expected=1552)
        status, text = call('ownership-domain', ['verify', ENTRY, *FLAGS,
                                                '--solver-path', solver])
        report['proofs']['ownership_domain'] = proof_result(status, text, expected=20)
        # The auditor does not audit included files implicitly, even when the
        # verifier was given --verify-included-files. Enumerate the whole graph.
        status, text = call('audit', ['audit', *sorted(sources)])
        report['audit_findings'] = audit_result(status, text)
        original = (frozen / ENTRY).read_text()
        for name, (old, new, symbol) in CONTROLS.items():
            if original.count(old) != 1:
                raise ValueError('Negative-control anchor changed: ' + name)
            target = frozen / 'formal/source' / ('Control-' + name + '.dfy')
            target.write_text(original.replace(old, new, 1))
            status, text = call('control-' + name,
                                ['verify', target, '--filter-symbol', symbol,
                                 *FLAGS, '--solver-path', solver])
            report['controls'][name] = proof_result(status, text, negative=new)
        assumption_root = out / 'assumption-control'
        shutil.copytree(frozen, assumption_root)
        native = assumption_root / 'formal/crypto/NativeShake.dfy'
        native_text = native.read_text()
        anchor = '    ghost var before := sponge.Model();'
        if native_text.count(anchor) != 1:
            raise ValueError('Included-body assumption control anchor changed')
        native.write_text(native_text.replace(anchor,
            '    assume {:axiom} false;\n' + anchor, 1))
        status, text = call('control-included-assumption',
                            ['audit', *(assumption_root / name for name in sorted(sources))])
        report['assumption_control_findings'] = audit_result(status, text, negative=True)

        # Real syntax controls: a regex missed these includes while the entry
        # proof and entry-only audit both passed through a hidden assumption.
        graph_root = out / 'graph-control'
        graph_root.mkdir()
        (graph_root / 'Hidden.dfy').write_text(
            'module Hidden { lemma Impossible() ensures false { assume {:axiom} false; } }\n')
        graph_entries = []
        for name, prefix in (('Bom', '\ufeff'), ('Inline', '/* header */ ')):
            target = graph_root / (name + '.dfy')
            target.write_text(prefix + 'include "Hidden.dfy"\nmodule ' + name +
                              ' { import H = Hidden method Claim() { H.Impossible(); assert false; } }\n')
            graph_entries.append(target.name)
        graph = closure(graph_root, graph_entries, dafny, discovery.source_closure,
                        call=lambda label, command: parser_call('control-' + label, command))
        if set(graph) != {'Hidden.dfy', 'Bom.dfy', 'Inline.dfy'}:
            raise ValueError('Compiler parser failed the BOM/comment include controls')
        status, text = call('control-graph-entry-proofs',
                            ['verify', *(graph_root / name for name in graph_entries),
                             *FLAGS, '--solver-path', solver])
        graph_proof = proof_result(status, text, expected=2)
        status, text = call('control-graph-entry-audit',
                            ['audit', *(graph_root / name for name in graph_entries)])
        audit_result(status, text)
        status, text = call('control-graph-complete-audit',
                            ['audit', *(graph_root / name for name in sorted(graph))])
        if (status or not re.search(r'^Dafny auditor completed with 1 findings?\s*$', text, re.M)
                or 'Impossible: Definition has `assume {:axiom}` statement in body' not in text
                or BAD.search(text.replace('Warning:', ''))):
            raise ValueError('Expected the parser-discovered hidden assumption audit finding')
        report['source_graph_control'] = {'sources': graph, 'entry_proof': graph_proof,
                                          'entry_audit_findings': 0, 'complete_audit_findings': 1}
        check_pins(frozen, pins)
        check_pins(ROOT, pins)
        if manifest_path.read_bytes() != manifest_bytes:
            raise ValueError('Input manifest changed during replay')
        final_dafny, _, _, _ = tools.install(args.cache)
        if final_dafny != dafny or tool_before != {
                'dafny': digest(dafny), 'solver': digest(solver), 'archive': asset['sha256']}:
            raise ValueError('Tool distribution changed during replay')
        report.update(status='complete', inputs_after=pins)
    except Exception as error:
        report['error'] = str(error)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'scope')}))
    return 0 if report['status'] == 'complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
