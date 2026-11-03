#!/usr/bin/env python3
"""Reproducible verifier for the ghost source-observation vocabulary kernel.

This runner checks:
  * every source file in this component is pinned before and after the run;
  * every .dfy file is audited individually (Dafny audit does not traverse
    includes) and the complete official parser closure is checked by a tiny
    resolved-AST plugin for owned declarations without implementations;
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
CHECKER_CS = COMPONENT + 'checker/ObservationDeclarations.cs'
CHECKER_CSPROJ = COMPONENT + 'checker/ObservationDeclarations.csproj'
CHECKER_INPUTS = {CHECKER_CS, CHECKER_CSPROJ}
PLUGIN_FILE = 'OBSERVATION-DECLARATIONS FILE '
PLUGIN_OK = re.compile(r'^OBSERVATION-DECLARATIONS OK: files=(\d+) modules=(\d+) '
                       r'types=(\d+) members=(\d+)\s*$', re.M)
POLICY = re.compile(r'Error: ((?:owned declaration missing implementation|'
                    r'unsupported owned )[^\n]+)')

# Each control is generated under the fresh output directory.  The entry is
# parsed by the official closure discovery, then the pinned plugin checks every
# file in that closure.  ``expect_ok`` controls must be accepted.
DECLARATION_CONTROLS = {
    'hidden-oracle': {
        'files': {'Hidden.dfy': 'module M {\n  ghost function HiddenOracle(): int\n'
                                '  function G(): int { 1 }\n}\n'},
        'entry': 'Hidden.dfy',
        'expect': ['owned declaration missing implementation: function M._default.HiddenOracle'],
        'forbid': ['function M._default.G'],
    },
    'attribute-bodyless': {
        'files': {'Attr.dfy': 'module M {\n  ghost function {:note "{ // }"} F(): int\n'
                              '  function G(): int { 1 }\n}\n'},
        'entry': 'Attr.dfy',
        'expect': ['owned declaration missing implementation: function M._default.F'],
        'forbid': ['function M._default.G'],
    },
    'forged-generated-origin': {
        'files': {'Forged.dfy': 'module M {\n'
                                 '  ghost function {:auto_generated} F(): int\n'
                                 '  method {:auto_generated} M()\n'
                                 '  const {:auto_generated} C: int\n'
                                 '  function G(): int { 1 }\n}\n'},
        'entry': 'Forged.dfy',
        'expect': ['owned declaration missing implementation: function M._default.F',
                   'owned declaration missing implementation: method M._default.M',
                   'owned declaration missing implementation: const M._default.C'],
        'forbid': ['function M._default.G'],
    },
    'bare-const': {
        'files': {'Const.dfy': 'module M {\n  const C: int\n  function G(): int { 1 }\n}\n'},
        'entry': 'Const.dfy',
        'expect': ['owned declaration missing implementation: const M._default.C'],
        'forbid': [],
    },
    'abstract-type': {
        'files': {'Type.dfy': 'module M {\n  type T\n  function G(): int { 1 }\n}\n'},
        'entry': 'Type.dfy',
        'expect': ['unsupported owned abstract type: M.T'],
        'forbid': [],
    },
    'opaque-type': {
        'files': {'OpaqueType.dfy': 'module M {\n  type {:opaque} T = int\n}\n'},
        'entry': 'OpaqueType.dfy',
        'expect': ['unsupported owned opaque type: M.T'],
        'forbid': [],
    },
    'abstract-module': {
        'files': {'Abstract.dfy': 'module M { abstract module A { function F(): int } }\n'},
        'entry': 'Abstract.dfy',
        'expect': ['unsupported owned abstract module: M.A'],
        'forbid': [],
    },
    'trait': {
        'files': {'Trait.dfy': 'module M {\n  trait Tr { function TF(): int }\n}\n'},
        'entry': 'Trait.dfy',
        'expect': ['unsupported owned trait: M.Tr'],
        'forbid': [],
    },
    'bodyless-constructor': {
        'files': {'Ctor.dfy': 'class C {\n  var v: int\n  constructor()\n}\n'},
        'entry': 'Ctor.dfy',
        'expect': ['owned declaration missing implementation: constructor _module.C._ctor'],
        'forbid': [],
    },
    'bodyless-method-lemma': {
        'files': {'Method.dfy': 'module M {\n  method M()\n  lemma L()\n}\n'},
        'entry': 'Method.dfy',
        'expect': ['owned declaration missing implementation: method M._default.M',
                   'owned declaration missing implementation: lemma M._default.L'],
        'forbid': [],
    },
    'next-declaration-body': {
        'files': {'Next.dfy': 'module M {\n  function F(): int\n'
                              '  function G(): int { 1 }\n}\n'},
        'entry': 'Next.dfy',
        'expect': ['owned declaration missing implementation: function M._default.F'],
        'forbid': ['function M._default.G'],
    },
    'quoted-comment-marker': {
        'files': {'Quoted.dfy': 'module M { function F(): string { "//" } '
                                'function G(): int }\n'},
        'entry': 'Quoted.dfy',
        'expect': ['owned declaration missing implementation: function M._default.G'],
        'forbid': ['function M._default.F'],
    },
    'contract-set-literal': {
        'files': {'Contract.dfy': 'module M {\n  function F(x: int): int\n'
                                  '    requires x in {1, 2}\n'
                                  '  function G(x: int): int\n'
                                  '    requires x in {1, 2}\n  { 0 }\n}\n'},
        'entry': 'Contract.dfy',
        'expect': ['owned declaration missing implementation: function M._default.F'],
        'forbid': ['function M._default.G'],
    },
    'requires-set-literal': {
        'files': {'Requires.dfy': 'module M {\n'
                                  '  function P(s: set<int>): bool { true }\n'
                                  '  function F(): int\n    requires P({})\n'
                                  '  function G(): int\n    requires P({})\n  { 0 }\n}\n'},
        'entry': 'Requires.dfy',
        'expect': ['owned declaration missing implementation: function M._default.F'],
        'forbid': ['function M._default.G'],
    },
    'include-only-closure': {
        'files': {'IncludeOnly.dfy': 'include "Hidden.dfy"\n',
                  'Hidden.dfy': 'module Hidden {\n  ghost function HiddenOracle(): int\n}\n'},
        'entry': 'IncludeOnly.dfy',
        'expect': ['owned declaration missing implementation: function Hidden._default.HiddenOracle'],
        'forbid': [],
    },
    'positive-shapes': {
        'files': {'Positive.dfy': 'module M {\n  datatype D = A | B(x: int)\n'
                                  '  class C {\n    var v: int\n'
                                  '    constructor(x: int) { v := x; }\n'
                                  '    function Get(): int { v }\n  }\n'
                                  '  type T = int\n  newtype N = x: int | x > 0\n'
                                  '  type Sub = x: int | x > 0\n'
                                  '  const K: int := 3\n'
                                  '  function F(): int { 1 }\n'
                                  '  method G() { }\n  lemma L() { }\n}\n'},
        'entry': 'Positive.dfy',
        'expect_ok': True,
    },
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, log, cwd, timeout=900, env=None):
    with log.open('w') as output:
        process = subprocess.Popen(list(map(str, command)), cwd=cwd, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True,
                                   env=env)
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
    return sorted(files | SHARED_INPUTS | CHECKER_INPUTS)


def check_pins(root, pins):
    for name, expected in pins.items():
        path = root / name
        if (not name or Path(name).is_absolute() or '..' in Path(name).parts or
                path.resolve() != path or not path.is_file() or
                not re.fullmatch('[0-9a-f]{64}', expected) or digest(path) != expected):
            raise ValueError('Changed or unsafe source input: ' + name)


def policy_findings(output):
    return POLICY.findall(output)


def plugin_files(output):
    return {line[len(PLUGIN_FILE):].strip()
            for line in output.splitlines() if line.startswith(PLUGIN_FILE)}


def plugin_ok_result(status, output, expected_files):
    findings = policy_findings(output)
    matches = PLUGIN_OK.findall(output)
    files = plugin_files(output)
    if status != 0 or findings or BAD.search(output) or len(matches) != 1:
        raise ValueError('Owned declaration policy scan failed')
    if files != set(map(str, expected_files)):
        raise ValueError('Declaration policy did not cover the exact parser closure')
    count, modules, types, members = map(int, matches[0])
    if count != len(files):
        raise ValueError('Declaration policy file count is inconsistent')
    return {'files': sorted(files), 'modules': modules, 'types': types,
            'members': members}


def plugin_rejection_result(status, output, expected, expected_files, forbidden):
    findings = policy_findings(output)
    files = plugin_files(output)
    if status == 0 or not all(any(item in finding for finding in findings)
                              for item in expected):
        raise ValueError('Expected an exact owned-declaration policy rejection')
    if any(any(item in finding for finding in findings) for item in forbidden):
        raise ValueError('Unexpected owned-declaration policy rejection')
    if ('parse errors detected' in output or
            'Error: assertion might not hold' in output or SUMMARY.search(output)):
        raise ValueError('Policy rejection was not a clean resolved-AST rejection')
    if not set(map(str, expected_files)).issubset(files):
        raise ValueError('Policy rejection did not cover the official closure')
    return {'files': sorted(files), 'findings': findings}


def seed_dotnet_packages(build_root):
    """Copy already-cached net6 reference packs locally; otherwise restore downloads."""
    target = build_root / 'nuget-packages'
    for package in ('microsoft.netcore.app.ref', 'microsoft.aspnetcore.app.ref'):
        source = Path.home() / '.nuget/packages' / package / '6.0.36'
        destination = target / package / '6.0.36'
        if source.is_dir() and not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, destination)


def build_checker(out, frozen, dafny):
    build_root = out.parent / (out.name + '-checker')
    source_dir = build_root / 'src'
    source_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(frozen / CHECKER_CS, source_dir / 'ObservationDeclarations.cs')
    shutil.copyfile(frozen / CHECKER_CSPROJ, source_dir / 'ObservationDeclarations.csproj')
    env = dict(os.environ)
    env.update({
        'DOTNET_CLI_HOME': str(build_root / 'home'),
        'NUGET_PACKAGES': str(build_root / 'nuget-packages'),
        'DOTNET_NOLOGO': '1',
        'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
        'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1',
    })
    seed_dotnet_packages(build_root)
    try:
        sdk = subprocess.run(['dotnet', '--version'], env=env, text=True,
                             capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError('dotnet SDK is required to build the declaration checker') from error
    command = ['dotnet', 'build', 'ObservationDeclarations.csproj', '-c', 'Release',
               '-v', 'q', '--nologo', '-p:DafnyHome=' + str(Path(dafny).parent)]
    log = out / 'logs/checker-build.log'
    status, text = run(command, log, source_dir, env=env)
    if status != 0:
        raise ValueError('Declaration checker build failed: ' + text[-4000:])
    assembly = source_dir / 'bin/Release/net6.0/ObservationDeclarations.dll'
    if not assembly.is_file():
        raise ValueError('Declaration checker assembly is missing')
    return assembly, {
        'sdk_version': sdk.stdout.strip(),
        'build_command': list(map(str, command)),
        'assembly_sha256': digest(assembly),
        'source_sha256': digest(frozen / CHECKER_CS),
        'project_sha256': digest(frozen / CHECKER_CSPROJ),
        'dafny_home': str(Path(dafny).parent),
        'build_log_sha256': digest(log),
    }


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
        'scope': ('Typed ghost event encoding, injectivity and decoder proofs, '
                  'and owned-declaration body policy only'),
        'not_claimed': [
            'source observer completeness',
            'actual source call/array-role/AST coverage',
            'Dafny parser/resolver or C# plugin adapter correctness',
            'constant time or physical timing',
            'Java/JVM refinement or compiler correctness',
            'whole crypto trace closure',
            'external expert review',
        ],
        'commands': [],
        'proofs': {},
        'controls': {},
        'audit': {},
        'declaration_policy': {},
        'declaration_controls': {},
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
        plugin, checker_info = build_checker(out, frozen, dafny)
        evidence['checker'] = checker_info

        def call(label, arguments, cwd=frozen, env=None):
            log = logs / (label + '.log')
            command = [dafny, *arguments]
            status, text = run(command, log, cwd, env=env)
            evidence['commands'].append({
                'label': label, 'command': list(map(str, command)),
                'exit': status, 'log_sha256': digest(log)})
            return status, text

        def parser_call(label, command):
            if Path(command[0]) != dafny:
                raise ValueError('Unexpected dependency parser executable')
            return call(label, command[1:])

        closures = {}
        found = {}
        for index, entry in enumerate(source_names):
            record = (lambda label, command, i=index:
                      parser_call(f'graph-{i}-{label}', command))
            entry_graph = discovery.source_closure(frozen, frozen / entry, dafny,
                                                   call=record)
            closures[entry] = sorted(entry_graph)
            for name, value in entry_graph.items():
                if name in found and found[name] != value:
                    raise ValueError('Source changed between parser traversals: ' + name)
                found[name] = value
        graph = dict(sorted(found.items()))
        if set(graph) != set(source_names):
            raise ValueError('Unlisted included source in vocabulary graph')
        evidence['source_graph'] = graph
        evidence['source_closures'] = closures

        # The official parser closure is the only source inventory.  The tiny
        # plugin checks every declaration authored in every file of that closure
        # for an implementation, using Dafny's resolved AST (never a text scan).
        covered = set()
        for index, entry in enumerate(source_names):
            expected_files = {str((frozen / name).resolve())
                              for name in closures[entry]}
            env = dict(os.environ)
            env['OBSERVATION_DECLARATION_FILES'] = '\n'.join(sorted(expected_files))
            status, text = call('declaration-policy-' + entry.replace('/', '_'),
                                ['resolve', entry, '--plugin', str(plugin)],
                                env=env)
            result = plugin_ok_result(status, text, expected_files)
            covered.update(result['files'])
            evidence['declaration_policy'][entry] = result
        if covered != {str((frozen / name).resolve()) for name in graph}:
            raise ValueError('Declaration policy did not cover the complete parsed source closure')

        control_root = out / 'declaration-controls'
        control_root.mkdir()
        for name, spec in DECLARATION_CONTROLS.items():
            folder = control_root / name
            folder.mkdir()
            for filename, source in spec['files'].items():
                (folder / filename).write_text(source)
            entry = folder / spec['entry']

            def control_parser_call(label, command, folder=folder, name=name):
                if Path(command[0]) != dafny:
                    raise ValueError('Unexpected dependency parser executable')
                return call('declaration-control-graph-' + name + '-' + label,
                            command[1:], cwd=folder)

            closure = discovery.source_closure(folder, entry, dafny,
                                               call=control_parser_call)
            expected_files = {str((folder / item).resolve()) for item in closure}
            env = dict(os.environ)
            env['OBSERVATION_DECLARATION_FILES'] = '\n'.join(sorted(expected_files))
            status, text = call('declaration-control-' + name,
                                ['resolve', spec['entry'], '--allow-warnings',
                                 '--plugin', str(plugin)], cwd=folder, env=env)
            if spec.get('expect_ok'):
                result = plugin_ok_result(status, text, expected_files)
            else:
                result = plugin_rejection_result(status, text, spec['expect'],
                                                 expected_files, spec['forbid'])
            result['closure'] = sorted(closure)
            evidence['declaration_controls'][name] = result

        # Audit every source file individually.  Dafny audit itself does not
        # traverse includes; it catches axioms/assumes/verify-false/unproved
        # contracts, while the plugin above adds the owned-body policy.
        for name in source_names:
            log_name = 'audit-' + name.replace('/', '_')
            status, text = call(log_name, ['audit', name])
            shared.audit_result(status, text)
            evidence['audit'][name] = {'dafny_findings': 0}

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
