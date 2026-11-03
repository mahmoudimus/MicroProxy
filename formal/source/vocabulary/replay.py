#!/usr/bin/env python3
"""Reproducible verifier for the ghost source-observation vocabulary kernel.

This runner checks:
  * every source file in this component is pinned before and after the run;
  * every .dfy file is audited individually (Dafny audit does not traverse
    includes) and also scanned for axioms/assumes/bodyless declarations;
  * the typed Event/Encode/EncodeTrace/Decode/DecodeTrace kernel verifies
    universally with the canonical 30 s / 50,000,000 / case_split=0 policy;
  * intentionally defective encodings fail at named assertions rather than at
    parser/resource/CLI errors;
  * a small runtime client translates to exactly the same generated files with
    and without the ghost vocabulary, at the same source basename, including
    the absence of a generated vocabulary class.

The Dafny compiler/backend remains trusted.  This is a finite erasure experiment,
not a universal compiler-correctness proof.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = 'formal/source/vocabulary/'
KERNEL = COMPONENT + 'ObservationVocabulary.dfy'
BASE_CLIENT = COMPONENT + 'erasure/base/Client.dfy'
TRACE_CLIENT = COMPONENT + 'erasure/trace/Client.dfy'
SHARED_INPUTS = {'formal/source/replay.py', 'formal/dafny/toolchain.py',
                 'formal/dafny/tools.json', 'formal/crypto/delivery.py'}
FLAGS = ['--verification-time-limit', '30', '--resource-limit', '50000000',
         '--solver-option', 'O:smt.case_split=0', '--cores', '2']
SUMMARY = re.compile(r'^Dafny program verifier finished with (\d+) verified, '
                     r'(\d+) errors?\s*$', re.M)
BAD = re.compile(r'warning:|out of resources?|timed?\s*out|timeout|parse errors?|'
                 r'resolution/type errors?|internal error|crash|inconclusive', re.I)
CONTROLS = {
    'branch-constant': 'control-branch-constant',
    'read-role': 'control-read-role',
    'lost-address': 'control-lost-address',
    'call-target': 'control-call-target',
    'flattened-ambiguous': 'control-flattened-ambiguous',
    'ops-width': 'control-ops-width',
}
EXPECTED_KERNEL_CHECKS = 29
DECL = re.compile(r'^\s*(lemma|function|predicate|method)\b')
BODY = re.compile(r'\{')
NEXT = re.compile(r'^\s*(lemma|function|predicate|method|datatype|codatatype|'
                  r'module|class|trait|type|const|var|import|include)\b')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, log, cwd, timeout=900):
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
    elif (status != 4 or verified != 0 or errors != 1 or
          len(re.findall(r'Error:', output)) != 1 or
          not re.search(r'Error: ' + re.escape(negative) + r'\s*$', output, re.M)):
        raise ValueError('Expected exactly one named assertion failure')
    return {'verified': verified, 'errors': errors}


def source_files():
    files = {str(path.relative_to(ROOT)) for path in HERE.rglob('*.dfy')}
    files.update(COMPONENT + name for name in ('replay.py', 'test_replay.py', 'README.md'))
    return sorted(files | SHARED_INPUTS)


def check_pins(root, pins):
    for name, expected in pins.items():
        path = root / name
        if (not name or Path(name).is_absolute() or '..' in Path(name).parts or
                path.resolve() != path or not path.is_file() or
                not re.fullmatch('[0-9a-f]{64}', expected) or digest(path) != expected):
            raise ValueError('Changed or unsafe source input: ' + name)


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def audit_text(name, text):
    code = strip_comments(text)
    findings = []
    if re.search(r'\bassume\b', code):
        findings.append('assume')
    if re.search(r'\baxiom\b|\{:\s*axiom\s*\}', code):
        findings.append('axiom')
    if re.search(r'\{:\s*verify\s+false\s*\}|--verify\s+false', code, re.I):
        findings.append('verify-false')
    lines = code.splitlines()
    for index, line in enumerate(lines):
        if not DECL.search(line):
            continue
        found_body = bool(BODY.search(line))
        for following in lines[index + 1:]:
            if BODY.search(following):
                found_body = True
                break
            if NEXT.search(following) or following.strip() == '}':
                break
        if not found_body:
            findings.append('bodyless-declaration:' + str(index + 1))
    return findings


def platform_key():
    return platform.system() + '-' + platform.machine()


def tool_hashes(dafny):
    root = dafny.parent
    solver = root / 'z3/bin/z3-4.12.1'
    return {
        'dafny': digest(dafny),
        'DafnyCore.dll': digest(root / 'DafnyCore.dll'),
        'solver': digest(solver),
    }


def java_inventory(directory):
    return {str(path.relative_to(directory)): digest(path)
            for path in sorted(directory.rglob('*.java'))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=Path.home() / '.cache/microproxy-formal')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    logs = out / 'logs'
    logs.mkdir()
    evidence = {
        'schema': 'microproxy.source-observation-vocabulary/v1',
        'status': 'incomplete',
        'scope': 'Typed ghost event encoding, injectivity and decoder proofs only',
        'not_claimed': [
            'source observer completeness',
            'actual source call/array-role/AST coverage',
            'constant time or physical timing',
            'Java/JVM refinement or compiler correctness',
            'whole crypto trace closure',
            'external expert review',
        ],
        'commands': [],
        'proofs': {},
        'controls': {},
        'audit': {},
        'erasure': {},
    }
    try:
        manifest_path = HERE / 'inputs.json'
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        if manifest.get('schema') != 'microproxy.source-observation-vocabulary-inputs/v1':
            raise ValueError('Unexpected input manifest schema')
        evidence['manifest_sha256'] = hashlib.sha256(manifest_bytes).hexdigest()
        pins = manifest['inputs']
        check_pins(ROOT, pins)
        if set(pins) != set(source_files()):
            raise ValueError('Source input inventory omitted or added files')

        frozen = out / 'frozen'
        for name in pins:
            target = frozen / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        check_pins(frozen, pins)

        def load(name, relative):
            spec = importlib.util.spec_from_file_location(name, frozen / relative)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

        # Pin and freeze shared Python modules before executing either module.
        shared = load('vocabulary_pinned_helpers', 'formal/source/replay.py')
        installer = load('vocabulary_pinned_toolchain', 'formal/dafny/toolchain.py')
        discovery = load('vocabulary_pinned_discovery', 'formal/crypto/delivery.py')
        source_names = sorted(name for name in pins if name.endswith('.dfy'))
        dafny, _, tools, asset = installer.install(args.cache)
        if tools['version'] != '4.9.1':
            raise ValueError('Expected official checksum-pinned Dafny 4.9.1')
        solver = dafny.parent / 'z3/bin/z3-4.12.1'
        before_tools = tool_hashes(dafny)
        version = subprocess.run([dafny, '--version'], text=True, capture_output=True,
                                 check=True).stdout.strip()
        evidence.update(dafny_version=version, platform=platform_key(),
                        tools=before_tools, archive_sha256=asset['sha256'],
                        solver=str(solver))

        def call(label, arguments, cwd=frozen):
            log = logs / (label + '.log')
            command = [dafny, *arguments]
            status, text = run(command, log, cwd)
            evidence['commands'].append({
                'label': label, 'command': list(map(str, command)),
                'exit': status, 'log_sha256': digest(log)})
            return status, text

        def parser_call(label, command):
            if Path(command[0]) != dafny:
                raise ValueError('Unexpected dependency parser executable')
            return call(label, command[1:])

        graph = shared.closure(frozen, source_names, dafny,
                               discovery.source_closure, call=parser_call)
        if set(graph) != set(source_names):
            raise ValueError('Unlisted included source in vocabulary graph')
        evidence['source_graph'] = graph

        # Audit every source file individually.  Dafny audit itself does not
        # traverse includes, and the manual scan catches bodyless declarations.
        for name in source_names:
            log_name = 'audit-' + name.replace('/', '_')
            status, text = call(log_name, ['audit', name])
            shared.audit_result(status, text)
            findings = audit_text(name, (frozen / name).read_text())
            evidence['audit'][name] = {'dafny_findings': 0, 'text_findings': findings}
            if findings:
                raise ValueError('Forbidden source construct: ' + name + ': ' + ','.join(findings))

        status, text = call('kernel-universal-proofs',
                            ['verify', KERNEL, *FLAGS, '--solver-path', solver])
        evidence['proofs']['kernel'] = proof_result(status, text, expected=EXPECTED_KERNEL_CHECKS)

        for name, marker in CONTROLS.items():
            control = COMPONENT + 'controls/' + name + '.dfy'
            if not (frozen / control).is_file():
                raise ValueError('Missing proof control: ' + name)
            status, text = call('control-' + name,
                                ['verify', control, *FLAGS, '--solver-path', solver])
            evidence['controls'][name] = proof_result(status, text, negative=marker)

        # Finite ghost-erasure experiment: same source basename, same output
        # basename, one translation with the vocabulary and one without.
        status, text = call('erasure-base-verify',
                            ['verify', BASE_CLIENT, *FLAGS, '--solver-path', solver])
        evidence['proofs']['erasure_base_client'] = proof_result(status, text, expected=2)
        status, text = call('erasure-trace-verify',
                            ['verify', TRACE_CLIENT, *FLAGS, '--solver-path', solver])
        evidence['proofs']['erasure_trace_client'] = proof_result(status, text, expected=3)

        for side, client in (('base', BASE_CLIENT), ('trace', TRACE_CLIENT)):
            cwd = frozen / client
            cwd = cwd.parent
            generated = out / 'erasure' / side / 'generated' / 'Client'
            generated.parent.mkdir(parents=True, exist_ok=True)
            status, text = call('erasure-' + side + '-translate',
                                ['translate', 'java', Path(client).name, '--no-verify',
                                 '-o', generated], cwd=cwd)
            if status != 0:
                raise ValueError('Java translation failed for erasure side: ' + side)
            java_dir = Path(str(generated) + '-java')
            inventory = java_inventory(java_dir)
            if not inventory:
                raise ValueError('No generated Java files for erasure side: ' + side)
            if any('SourceObservationVocabulary' in name for name in inventory):
                raise ValueError('Ghost vocabulary emitted a Java class: ' + side)
            evidence['erasure'][side] = {
                'generated_dir': str(java_dir),
                'java': inventory,
                'all_files': {str(path.relative_to(java_dir)): digest(path)
                              for path in sorted(java_dir.rglob('*')) if path.is_file()},
            }
        if evidence['erasure']['base']['java'] != evidence['erasure']['trace']['java']:
            raise ValueError('Generated Java differs with/without ghost vocabulary')
        if evidence['erasure']['base']['all_files'] != evidence['erasure']['trace']['all_files']:
            raise ValueError('Total generated file inventory differs with/without ghost vocabulary')

        check_pins(frozen, pins)
        check_pins(ROOT, pins)
        if manifest_path.read_bytes() != manifest_bytes:
            raise ValueError('Input manifest changed during the run')
        final_dafny, _, _, _ = installer.install(args.cache)
        if final_dafny != dafny or tool_hashes(dafny) != before_tools:
            raise ValueError('Tool distribution changed during the run')
        evidence.update(status='complete', inputs_before=pins, inputs_after=pins)
    except Exception as error:  # keep a machine-readable failure receipt
        evidence['error'] = str(error)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'status': evidence['status'],
                      'scope': evidence['scope'],
                      'error': evidence.get('error')}))
    return 0 if evidence['status'] == 'complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
