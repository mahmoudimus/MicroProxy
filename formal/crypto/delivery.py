#!/usr/bin/env python3
"""Checked Dafny Java delivery, with no source rewriting or opcode abstraction.

`stage --component NativeShake` is explicitly provisional and cannot be published.
Full `stage` requires the complete, frozen input-evidence envelope described below.
Every closure file is audited and verified again; an envelope is never a proof.
Reference, native kernel and native composition roots use their explicitly
pinned per-source solver strategies, with unchanged common limits and coverage. Translation
then uses --no-verify on that same frozen, fully verified graph; this avoids silently
replacing the reference solver policy with the native policy in a combined pass.
`publish` requires a separately recorded performance/compatibility adoption decision bound to
the successful full stage. `check` compares actual Maven classes AND JAR bytes to
the canonical javac output, including all attributes. It separately compiles all
handwritten main Java with the original -Xlint:all,-serial policy, and compares
those exact class bytes too. No debug data is discarded. Test compilation keeps
the original lint settings through Maven's default-testCompile execution.
The existing packet compiler output is excluded from handwritten lint only by an
explicit exact source pin; it is compiled separately and its class bytes checked.

Input evidence (paths relative to the envelope's directory):
  {"schema":"microproxy.crypto-input-evidence/v1", "status":"complete",
   "scope":"full", "inputs_before":{repo_relative_dfy:sha256, ...},
   "inputs_after":{same complete closure},
   "receipts":[{"path":"native-kem/receipt.json", "sha256":"..."}, ...]}
The evidence envelope asserts review of those complete receipts; this tool also
requires a full native-KEM receipt covering the exact closure, all three proof
partitions (composition, reference graph, native kernels) and Java generation,
semantic controls, both JDK replays, four provider declarations/two primitives and
the selected Maven runtime. Model-only and owned/partial receipts cannot qualify.
The explicit microproxy.native-kem-evidence-contract/v2 in delivery.json pins
the runner schema, all named semantic controls, every supported-JDK replay count
and successful command phases, including compiled selector controls and both
JDK byte-conversion inspections. It requires the exact reviewed helper and
caller inventory, selector bounds1088/32, only two public loop branches, and zero
payload scalar boxing. These are source/bytecode discipline checks, not a timing
theorem. Its exact input map also covers the domain graph,
runner, Java harness, provider and both reference Java sources. These inputs and
all referenced JSON receipts are pinned before/after; runner drift fails closed.

Approval (paths relative to the approval's directory):
  {"schema":"microproxy.crypto-delivery-approval/v1", "status":"approved",
   "scope":"full", "approved_by":"user", "decision":"explicit tradeoff decision",
   "stage_receipt_sha256":"...",
   "compatibility_receipts":[{"path":"compatibility.json", "sha256":"..."}],
   "performance_receipt":{"path":"performance.json", "sha256":"..."}}
Previously authorized adoption can use a separate delegated evaluation:
  {"schema":"microproxy.crypto-delivery-approval/v2", "status":"approved",
   "scope":"full", "mode":"user-delegated",
   "prior_user_authorization":{"path":"authorization.json", "sha256":"..."},
   "agent_evaluation":{"evaluated_by":"codex/root", "decision":"evidence-based decision",
     "stage_receipt_sha256":"...", "source_map_sha256":"...",
     "compatibility_receipts":[{"path":"compatibility.json", "sha256":"..."}],
     "performance_receipt":{"path":"performance.json", "sha256":"..."}}}
The separately pinned authorization record uses schema
microproxy.crypto-user-authorization/v1, authority "user", action
"integrate-after-checks", the prior instruction and its trusted conversation
source. The source_map_sha256 is json_digest(stage["sources"]). This records
prior user authority separately from the agent's later evidence evaluation; it
never claims that the user reviewed a future exact stage. Authorization is a
policy input, never inferred from elapsed time or passing tests.
Compiler/runtime/provider correctness and JVM timing remain explicit trust.
"""
import argparse
from contextlib import contextmanager
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SUMMARY = re.compile(r'^Dafny program verifier finished with (\d+) (?:assertions )?verified, (\d+) errors?\s*$', re.M)
BAD = re.compile(r'warning:|timed? ?out|out of resources?|resource limit|out of memory|'
                 r'parse errors?|parser errors?|resolution/type errors?|internal error|unhandled exception', re.I)
SHA256 = re.compile(r'[0-9a-f]{64}')
FULL_NATIVE_PROOF_PHASES = frozenset(('proof-native-composition', 'proof-reference-graph',
                                     'proof-native-kernels', 'generate-java'))


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def json_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def safe_path(root, relative):
    name = PurePosixPath(relative)
    if name.is_absolute() or '..' in name.parts or '\\' in relative or not name.parts:
        raise RuntimeError('Unsafe relative path: '+str(relative))
    if Path(root).is_symlink():
        raise RuntimeError('Unexpected root symlink: '+str(root))
    root = Path(root).resolve()
    path = root.joinpath(*name.parts)
    if any(p.is_symlink() for p in [path, *path.parents] if p != root and root in p.parents):
        raise RuntimeError('Unexpected symlink: '+str(path))
    return path


def file_map(root):
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError('Missing or symlink artifact directory: '+str(root))
    files = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('Unexpected artifact symlink: '+str(path))
        if path.is_file():
            files[path.relative_to(root).as_posix()] = digest(path)
        elif not path.is_dir():
            raise RuntimeError('Unexpected artifact type: '+str(path))
    return files


def check_tree(root, expected):
    if file_map(root) != expected:
        raise RuntimeError('Missing, extra or changed artifact: '+str(root))


def check_pins(root, expected):
    for name, sha in expected.items():
        path = safe_path(root, name)
        if not isinstance(sha, str) or not SHA256.fullmatch(sha) or not path.is_file() or digest(path) != sha:
            raise RuntimeError('Missing or changed input: '+str(name))


def freeze_inputs(root, pins, destination):
    check_pins(root, pins)
    Path(destination).mkdir(parents=True, exist_ok=False)
    for name in pins:
        target = safe_path(destination, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe_path(root, name), target)
    check_tree(destination, pins)
    check_pins(root, pins)


DEPENDENCY_OPTIONS = ('/printIncludes:Immediate', '/noResolve')
LEGACY_PARSER_BANNER = ("Warning: this way of using the CLI is deprecated. "
                        "Use 'dafny --help' to see help for the new Dafny CLI format")


def check_dependency_path_encoding(root):
    # Immediate has no quoting/escaping for semicolon-delimited paths. Refuse
    # ambiguous filesystem names throughout this root, rather than interpreting
    # one real dependency name as multiple different existing source files.
    if any(char in str(root) for char in (';', '\r', '\n')):
        raise RuntimeError('Unsupported dependency path: '+str(root))
    def walk_error(error):
        raise RuntimeError('Cannot inspect dependency path names') from error
    for directory, folders, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in folders+files:
            if any(char in name for char in (';', '\r', '\n')):
                raise RuntimeError('Unsupported dependency path: '+str(Path(directory)/name))


def dependency_paths(status, output, root):
    """Pinned 4.9.1's Immediate output is a semicolon-delimited adjacency list.

    Transitive prints no graph in this distribution. Recursing over Immediate
    uses Dafny's parser without resolution for every dependency, including
    BOMs, comments, escaped strings and multiline directives. Only its exact legacy-CLI banner is
    consumed here; source/parser diagnostics and proof warnings remain fatal.
    """
    lines = output.splitlines()
    if status or not lines or lines.pop(0) != LEGACY_PARSER_BANNER or BAD.search('\n'.join(lines)):
        raise RuntimeError('Dafny dependency parser failed or emitted diagnostics: '+output[-4000:])
    result = set()
    for line in lines:
        if not line or line.strip() != line:
            raise RuntimeError('Unexpected Dafny dependency parser output')
        for name in line.split(';'):
            path = Path(name)
            if not path.is_absolute() or any(char in name for char in ('\r', '\n', ';')):
                raise RuntimeError('Unsupported dependency path: '+name)
            # safe_path also rejects symlinks. Do not resolve before this check.
            try:
                relative = Path(os.path.abspath(path)).relative_to(root).as_posix()
            except ValueError as error:
                raise RuntimeError('Include escapes repository') from error
            result.add(safe_path(root, relative))
    return result


def source_closure(root, entry, dafny, *, timeout=1800, call=None):
    lexical_root = Path(os.path.abspath(root))
    root = Path(root).resolve()
    entry = Path(os.path.abspath(entry))
    # macOS /var and /private/var spellings may differ for the root, but a
    # source symlink itself is never canonicalized away.
    try:
        relative = entry.relative_to(root).as_posix()
    except ValueError:
        try:
            relative = entry.relative_to(lexical_root).as_posix()
        except ValueError as error:
            raise RuntimeError('Include escapes repository') from error
    check_dependency_path_encoding(root)
    pending, seen = {safe_path(root, relative)}, {}
    with tempfile.TemporaryDirectory(prefix='crypto-delivery-dependencies-') as temporary:
        round_number = 0
        while pending:
            current = sorted(pending)
            for path in current:
                name = path.relative_to(root).as_posix()
                if any(char in str(path) for char in (';', '\r', '\n')):
                    raise RuntimeError('Unsupported dependency path: '+name)
                if path.suffix != '.dfy' or not path.is_file():
                    raise RuntimeError('Missing Dafny input: '+name)
                raw = path.read_bytes()
                try:
                    decoded = raw.decode('utf-8-sig')
                except UnicodeError as error:
                    raise RuntimeError('Dafny inputs must use UTF-8: '+name) from error
                if '\x00' in decoded:
                    raise RuntimeError('Dafny inputs must use UTF-8 without NUL: '+name)
                seen[name] = hashlib.sha256(raw).hexdigest()
            label = 'dependencies-'+str(round_number)
            command = [dafny, *DEPENDENCY_OPTIONS, *current]
            status, output = (call(label, command) if call else
                              run_command(command, Path(temporary)/(label+'.log'), root, timeout))
            discovered = dependency_paths(status, output, root)
            pending = {path for path in discovered if path.relative_to(root).as_posix() not in seen}
            round_number += 1
        check_dependency_path_encoding(root)
        check_pins(root, seen)
    return dict(sorted(seen.items()))


def source_verify_options(source, manifest):
    """Only an explicit reviewed solver strategy may override a source policy.

    Budgets and method/source coverage remain in the common verification flags;
    this map cannot introduce a filter, library, no-verify or different limit.
    """
    overrides = manifest['dafny'].get('source_solver_case_split', {})
    if not isinstance(overrides, dict):
        raise RuntimeError('Invalid per-source solver strategy map')
    for name, strategy in overrides.items():
        if (not isinstance(name, str) or not name.endswith('.dfy') or '\\' in name
                or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                or PurePosixPath(name).as_posix() != name or type(strategy) is not int or strategy not in (0, 3)):
            raise RuntimeError('Unsupported per-source solver strategy')
    if source in overrides:
        return ['--solver-option', 'O:smt.case_split='+str(overrides[source])]
    return list(manifest['dafny']['native_verify_options']) if Path(source).name.startswith('Native') else []


def proof_result(status, output, minimum=1):
    matches = SUMMARY.findall(output)
    if status or len(matches) != 1 or BAD.search(output) or int(matches[0][0]) < minimum or int(matches[0][1]):
        raise RuntimeError('Expected completed nonempty verification without diagnostics')
    return int(matches[0][0])


def generation_result(status, output):
    if status or output.strip() != 'Dafny program verifier did not attempt verification':
        raise RuntimeError('Translation failed or emitted unexpected diagnostics: '+output[-4000:])
    return {'status':'translated', 'verification':'all immutable input roots verified separately before translation'}


def audit_result(status, output, root, expected):
    findings = []
    for line in output.splitlines():
        if 'Warning:' not in line:
            continue
        match = re.fullmatch(r'(.+\.dfy)\(\d+,\d+\): Warning: (\w+): Declaration has explicit `\{:\s*axiom\}` attribute\. Possible mitigation: Provide a proof or test\.', line)
        if not match:
            raise RuntimeError('Unexpected assumption audit warning')
        try:
            owner = Path(match[1]).resolve().relative_to(Path(root).resolve()).as_posix()
        except ValueError as error:
            raise RuntimeError('Assumption owner escapes repository') from error
        findings.append((owner, match[2]))
    summaries = re.findall(r'^Dafny auditor completed with (\d+) findings\s*$', output, re.M)
    cleaned = '\n'.join(line for line in output.splitlines() if 'Warning:' not in line)
    if (status or summaries != [str(len(expected))] or BAD.search(cleaned)
            or sorted(findings) != sorted(map(tuple, expected))):
        raise RuntimeError('Unexpected Dafny assumption declarations or owners')
    return findings


def receipt_reference(base, reference):
    if not isinstance(reference, dict) or set(reference) != {'path', 'sha256'}:
        raise RuntimeError('Missing pinned receipt reference')
    check_pins(base, {reference['path']:reference['sha256']})
    path = safe_path(base, reference['path'])
    try:
        data = json.loads(path.read_text())
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('Invalid receipt JSON: '+str(path)) from error
    if not isinstance(data, dict) or not data:
        raise RuntimeError('Empty receipt: '+str(path))
    return path


NATIVE_EVIDENCE_SCHEMA = 'microproxy.native-kem-evidence-contract/v2'
BYTECODE_CONTROL_REJECTIONS = {
    'selector-narrow-helper':'Unreviewed or payload-sensitive runtime helper',
    'selector-payload-branch':'Selector payload branch or changed loop control',
    'selector-payload-boxing':'Payload scalar boxing:'}
BOXING_INSTRUCTION = re.compile(
    r'\d+: invokestatic\s+#\d+\s+// Method java/lang/(Byte|Integer|Long)\.valueOf:'
    r'\(([BIJ])\)Ljava/lang/\1;')


def check_native_contract(contract):
    if (not isinstance(contract, dict) or contract.get('schema') != NATIVE_EVIDENCE_SCHEMA
            or set(contract.get('proof_phases', [])) != FULL_NATIVE_PROOF_PHASES
            or contract.get('jdk_majors') != [21, 25]
            or not isinstance(contract.get('semantic_controls'), list) or not contract['semantic_controls']
            or len(set(contract['semantic_controls'])) != len(contract['semantic_controls'])
            or not isinstance(contract.get('replay_inventory'), dict) or not contract['replay_inventory']
            or any(type(value) is not int or value <= 0 for value in contract['replay_inventory'].values())
            or not isinstance(contract.get('runner'), dict) or set(contract['runner']) != {'path', 'sha256'}
            or contract['runner']['path'] not in contract.get('additional_inputs', [])
            or not isinstance(contract.get('required_source_pins'), dict) or not contract['required_source_pins']
            or any(not isinstance(sha, str) or not SHA256.fullmatch(sha)
                   for sha in contract['required_source_pins'].values())
            or contract.get('bytecode_control_rejections') != BYTECODE_CONTROL_REJECTIONS
            or not isinstance(contract.get('native_runtime_guard'), dict)):
        raise RuntimeError('Unsupported or incomplete versioned native evidence contract')
    expected_exits = dict.fromkeys(['dafny-version', 'solver-version', 'audit',
        'proof-native-composition', 'proof-reference-graph', 'proof-native-kernels'], 0)
    expected_exits.update({'control-'+name:4 for name in contract['semantic_controls']})
    expected_exits.update(dict.fromkeys(['generate-java', 'javac', 'native-runtime-bytecode',
                                        'runtime-helpers-bytecode', 'jdk-byte-conversions'], 0))
    for name in BYTECODE_CONTROL_REJECTIONS:
        expected_exits.update(dict.fromkeys(['compile-'+name, 'inspect-'+name], 0))
    for index in range(2):
        expected_exits.update(dict.fromkeys([f'java-{index}-version', f'java-{index}-byte-conversions',
                                            f'java-{index}'], 0))
    if (not isinstance(contract.get('command_exits'), dict)
            or list(contract['command_exits'].items()) != list(expected_exits.items())):
        raise RuntimeError('Native evidence command contract is incomplete or out of order')
    policy = contract['native_runtime_guard']
    inventory = policy.get('caller_inventory', {})
    zero_boxes = policy.get('constant_zero_boxings', {})
    if (not isinstance(policy.get('fixed_fields'), dict) or not policy['fixed_fields']
            or type(inventory.get('count')) is not int or inventory['count'] <= 0
            or not isinstance(inventory.get('sha256'), str) or not SHA256.fullmatch(inventory['sha256'])
            or not isinstance(inventory.get('files'), list) or not inventory['files']
            or len(set(inventory['files'])) != len(inventory['files'])
            or not isinstance(policy.get('caller_review'), dict) or not policy['caller_review']
            or type(zero_boxes.get('count')) is not int or zero_boxes['count'] <= 0
            or set(zero_boxes.get('kinds', {})) != {'Byte', 'Integer', 'Long'}
            or any(type(count) is not int or count <= 0 for count in zero_boxes['kinds'].values())
            or sum(zero_boxes['kinds'].values()) != zero_boxes['count']
            or zero_boxes.get('source') != 'fixed public zero/Witness0'):
        raise RuntimeError('Incomplete native runtime guard policy')


def native_input_pins(root, sources, contract, dafny, *, timeout=1800):
    """Exact current runner input set, including the full domain dependency graph."""
    check_native_contract(contract)
    check_pins(root, {contract['runner']['path']:contract['runner']['sha256']})
    check_pins(root, contract['required_source_pins'])
    domain = source_closure(root, safe_path(root, contract['domain_source']), dafny, timeout=timeout)
    if any(domain.get(name) != sha for name, sha in sources.items()):
        raise RuntimeError('Native domain does not cover the complete delivery source graph')
    inputs = dict(domain)
    for name in contract['additional_inputs']:
        path = safe_path(root, name)
        if not path.is_file():
            raise RuntimeError('Missing native replay input: '+name)
        inputs[name] = digest(path)
    check_pins(root, inputs)
    return dict(sorted(inputs.items()))


def validate_native_runtime_guard(receipt, contract):
    """Require the entire reviewed discipline report; this is not a timing proof."""
    guard = receipt.get('native_runtime_guard')
    policy = contract['native_runtime_guard']
    fixed = policy['fixed_fields']
    if (not isinstance(guard, dict) or set(guard) != set(fixed).union(
            ('constant_zero_boxings', 'caller_inventory', 'caller_review'))
            or json_digest({key:guard[key] for key in fixed}) != json_digest(fixed)
            or guard.get('caller_review') != policy['caller_review']):
        raise RuntimeError('Missing, partial or changed native runtime guard')
    inventory = guard['caller_inventory']
    expected = policy['caller_inventory']
    if (not isinstance(inventory, list) or len(inventory) != expected['count']
            or any(not isinstance(site, dict) or set(site) != {'file', 'method', 'line', 'source'}
                   or not isinstance(site['file'], str) or site['file'] not in receipt.get('generated_java', {})
                   or not isinstance(site['method'], str) or not re.fullmatch(r'[A-Za-z_$]\w*', site['method'])
                   or type(site['line']) is not int or site['line'] <= 0
                   or not isinstance(site['source'], str) or not site['source'].strip() for site in inventory)
            or sorted({site['file'] for site in inventory}) != expected['files']
            or json_digest(inventory) != expected['sha256']):
        raise RuntimeError('Incomplete or changed native runtime caller inventory')
    boxes = guard['constant_zero_boxings']
    zero_policy = policy['constant_zero_boxings']
    counts = Counter()
    if not isinstance(boxes, list) or len(boxes) != zero_policy['count']:
        raise RuntimeError('Incomplete fixed public boxing inventory')
    for box in boxes:
        match = (BOXING_INSTRUCTION.fullmatch(box.get('instruction', ''))
                 if isinstance(box, dict) and isinstance(box.get('instruction'), str) else None)
        if (not match or set(box) != {'instruction', 'source'} or box['source'] != zero_policy['source']
                or match[2] != {'Byte':'B', 'Integer':'I', 'Long':'J'}[match[1]]):
            raise RuntimeError('Changed fixed public boxing inventory')
        counts[match[1]] += 1
    if counts != zero_policy['kinds']:
        raise RuntimeError('Changed fixed public boxing kind inventory')
    controls = receipt.get('bytecode_controls')
    if not isinstance(controls, dict) or set(controls) != set(BYTECODE_CONTROL_REJECTIONS):
        raise RuntimeError('All three compiled selector discipline controls are required')
    for name, reason in BYTECODE_CONTROL_REJECTIONS.items():
        control = controls[name]
        if not isinstance(control, dict) or set(control) != {'rejected'} or not isinstance(control['rejected'], str):
            raise RuntimeError('Incomplete compiled selector control rejection: '+name)
        rejection = control['rejected']
        if name == 'selector-payload-boxing':
            instruction = rejection.removeprefix(reason+' ')
            match = BOXING_INSTRUCTION.fullmatch(instruction)
            genuine = rejection.startswith(reason+' ') and match and (match[1], match[2]) == ('Byte', 'B')
        else:
            genuine = rejection == reason
        if not genuine:
            raise RuntimeError('Wrong compiled selector control rejection: '+name)


def validate_native_evidence(receipt, path, sources, expected_inputs, contract, runtime_sha256):
    inputs = receipt.get('inputs', {})
    source_match = (inputs == expected_inputs and all(inputs.get(name) == sha for name, sha in sources.items())
                    and all(sources.get(name) == sha for name, sha in contract['required_source_pins'].items())
                    and receipt.get('inputs_before', inputs) == inputs
                    and receipt.get('inputs_after', inputs) == inputs)
    proofs = receipt.get('proofs', {})
    graph_proofs = (isinstance(proofs, dict) and set(proofs) == set(contract['proof_phases'])
                    and all(type(proofs[name]) is int and proofs[name] > 0 for name in contract['proof_phases']))
    controls = receipt.get('controls', {})
    failed_controls = (isinstance(controls, dict) and set(controls) == set(contract['semantic_controls'])
        and all(isinstance(control, dict) and set(control) == {'verified', 'errors'}
                and type(control['verified']) is int and control['verified'] >= 0
                and type(control['errors']) is int and control['errors'] > 0 for control in controls.values()))
    commands = receipt.get('commands', [])
    successful_phases = (isinstance(commands, list) and all(isinstance(command, dict) for command in commands)
        and [command.get('label') for command in commands] == list(contract['command_exits'])
        and all(type(command.get('exit')) is int and command['exit'] == contract['command_exits'][command['label']]
                and isinstance(command.get('command'), list) and command['command']
                and all(isinstance(arg, str) and arg for arg in command['command']) for command in commands))
    java = receipt.get('java', [])
    majors = []
    complete_replays = isinstance(java, list) and len(java) == len(contract['jdk_majors'])
    if complete_replays:
        for run in java:
            match = (re.search(r'^(?:openjdk|java) version "(21|25)(?:\.|\")', run.get('version', ''), re.M)
                     if isinstance(run, dict) and isinstance(run.get('version'), str) else None)
            tests = run.get('tests') if isinstance(run, dict) else None
            if (not match or not isinstance(tests, dict) or tests != contract['replay_inventory']
                    or any(type(value) is not int for value in tests.values())):
                complete_replays = False
                break
            majors.append(int(match[1]))
        complete_replays = complete_replays and sorted(majors) == contract['jdk_majors']
    assumptions = receipt.get('provider_assumptions', {})
    artifacts = all(isinstance(receipt.get(name), dict) and receipt[name]
                    and all(isinstance(sha, str) and SHA256.fullmatch(sha) for sha in receipt[name].values())
                    for name in ('generated_java', 'compiled_classes'))
    runtime = receipt.get('runtime_sha256', '')
    validate_native_runtime_guard(receipt, contract)
    if (receipt.get('scope') != 'full' or receipt.get('status') not in (None, 'complete', 'passed')
            or not source_match or not graph_proofs or not failed_controls or not successful_phases
            or not complete_replays or not artifacts or not isinstance(assumptions, dict)
            or assumptions.get('primitive_count') != 2 or assumptions.get('declaration_count') != 4
            or receipt.get('runtime_coordinate') != 'org.dafny:DafnyRuntime:4.9.1'
            or not isinstance(runtime, str) or not SHA256.fullmatch(runtime) or runtime != runtime_sha256):
        raise RuntimeError('Incomplete, stale, model-only or incompatible full native receipt: '+str(path))


def validate_input_evidence(data, base, sources, runtime_sha256, *, expected_inputs, contract, root=ROOT):
    check_native_contract(contract)
    # Rechecking every current non-Dafny input matters: staging repeats proofs,
    # but does not repeat this receipt's semantic controls or finite JDK replays.
    if not set(sources).union(contract['additional_inputs'], [contract['domain_source']]) <= set(expected_inputs):
        raise RuntimeError('Native receipt expected input map omits required replay inputs')
    check_pins(root, expected_inputs)
    check_pins(root, contract['required_source_pins'])
    check_pins(root, {contract['runner']['path']:contract['runner']['sha256']})
    if (not isinstance(data, dict) or data.get('schema') != 'microproxy.crypto-input-evidence/v1'
            or data.get('status') != 'complete' or data.get('scope') != 'full'
            or data.get('inputs_before') != sources or data.get('inputs_after') != sources
            or not isinstance(data.get('receipts'), list) or not data['receipts']):
        raise RuntimeError('Complete frozen full-closure input receipts are required')
    paths = [receipt_reference(base, ref) for ref in data['receipts']]
    complete_native = False
    for path in paths:
        receipt = json.loads(path.read_text())
        if receipt.get('status') not in (None, 'complete', 'passed'):
            raise RuntimeError('Incomplete or failed referenced receipt: '+str(path))
        if receipt.get('scope') != 'full':
            continue
        validate_native_evidence(receipt, path, sources, expected_inputs, contract, runtime_sha256)
        complete_native = True
    if not complete_native:
        raise RuntimeError('A complete full native implementation receipt is required')
    return paths


def validate_approval(data, base, stage_receipt):
    if not isinstance(data, dict) or data.get('status') != 'approved' or data.get('scope') != 'full':
        raise RuntimeError('Explicit stage-bound compatibility/performance approval required')
    references = []
    if data.get('schema') == 'microproxy.crypto-delivery-approval/v2' and data.get('mode') == 'user-delegated':
        authority_path = receipt_reference(base, data.get('prior_user_authorization'))
        authority = json.loads(authority_path.read_text())
        if (authority.get('schema') != 'microproxy.crypto-user-authorization/v1'
                or authority.get('authority') != 'user' or authority.get('action') != 'integrate-after-checks'
                or any(not isinstance(authority.get(key), str) or not authority[key].strip()
                       for key in ('instruction', 'source'))):
            raise RuntimeError('A recorded prior user authorization to integrate after checks is required')
        evaluation = data.get('agent_evaluation')
        stage_data = json.loads(Path(stage_receipt).read_text())
        if (not isinstance(evaluation, dict) or not isinstance(stage_data.get('sources'), dict)
                or not stage_data['sources'] or not isinstance(evaluation.get('evaluated_by'), str)
                or not evaluation['evaluated_by'].strip() or evaluation['evaluated_by'] == 'user'
                or evaluation.get('source_map_sha256') != json_digest(stage_data['sources'])):
            raise RuntimeError('Separate agent compatibility/performance evaluation must bind exact stage sources')
        references.append(authority_path)
    elif data.get('schema') == 'microproxy.crypto-delivery-approval/v1' and data.get('approved_by') == 'user':
        evaluation = data
    else:
        raise RuntimeError('Explicit user or user-delegated adoption decision required')
    if (not isinstance(evaluation.get('decision'), str) or not evaluation['decision'].strip()
            or evaluation.get('stage_receipt_sha256') != digest(stage_receipt)
            or not isinstance(evaluation.get('compatibility_receipts'), list)
            or not evaluation['compatibility_receipts'] or not evaluation.get('performance_receipt')):
        raise RuntimeError('Explicit stage-bound compatibility/performance approval required')
    return references+[receipt_reference(base, ref) for ref in
                       evaluation['compatibility_receipts']+[evaluation['performance_receipt']]]


def generated_inventory(root, namespace, output_name):
    prefix = namespace.replace('.', '/')+'/'
    files = file_map(root)
    sources = {}
    for relative, sha in files.items():
        path = Path(root)/relative
        if relative == output_name+'-java.dtr':
            continue  # Translation metadata is pinned in the full generation map.
        if relative == output_name+'.java':
            # Dafny emits one import-only top-level file, which defines no class.
            clean = re.sub(r'//[^\n]*', '', path.read_text())
            if re.sub(r'\bimport\s+[\w.*]+\s*;', '', clean).strip():
                raise RuntimeError('Unexpected executable top-level generated file')
            continue
        if not relative.startswith(prefix) or not relative.endswith('.java'):
            raise RuntimeError('Unexpected generated namespace or file: '+relative)
        packages = re.findall(r'^package ([\w.]+);\s*$', path.read_text(), re.M)
        expected = str(PurePosixPath(relative).parent).replace('/', '.')
        if packages != [expected]:
            raise RuntimeError('Generated namespace/path mismatch: '+relative)
        sources[relative] = sha
    if not sources:
        raise RuntimeError('No generated Java modules')
    return sources


def provider_inventory(root, providers):
    result = {}
    for provider in providers:
        check_pins(root, {provider['source']:provider['sha256']})
        text = safe_path(root, provider['source']).read_text()
        owner = provider['owner']
        package, classname = owner.rsplit('.', 1)
        if (re.findall(r'^package ([\w.]+);\s*$', text, re.M) != [package]
                or re.findall(r'public final class (\w+)\s*\{', text) != [classname]):
            raise RuntimeError('Provider owner mismatch: '+owner)
        result[owner.replace('.', '/')+'.java'] = provider['sha256']
    return result


def class_owner(data):
    """Read identity only. Actual identity checking compares every class byte."""
    if len(data) < 10 or data[:4] != b'\xca\xfe\xba\xbe':
        raise RuntimeError('Invalid JVM class')
    count = struct.unpack_from('>H', data, 8)[0]
    pool, at, index = {}, 10, 1
    try:
        while index < count:
            tag = data[at]
            at += 1
            if tag == 1:
                size = struct.unpack_from('>H', data, at)[0]
                at += 2
                # String constants use modified UTF-8 and may contain encoded
                # NUL. They remain opaque; only the actual class name is read.
                pool[index] = data[at:at+size]
                at += size
            elif tag == 7:
                pool[index] = struct.unpack_from('>H', data, at)[0]
                at += 2
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                at += 4
            elif tag in (5, 6):
                at += 8
                index += 1
            elif tag in (8, 16, 19, 20):
                at += 2
            elif tag == 15:
                at += 3
            else:
                raise RuntimeError('Unknown class constant-pool tag')
            index += 1
        this_class = struct.unpack_from('>H', data, at+2)[0]
        name = pool[pool[this_class]]
        if not isinstance(name, bytes):
            raise RuntimeError('Invalid JVM class owner')
        return name.decode('utf-8')
    except (IndexError, KeyError, struct.error, UnicodeError) as error:
        raise RuntimeError('Malformed JVM class identity') from error


def class_map(root, prefixes):
    files = file_map(root)
    result = {}
    for name, sha in files.items():
        if name.endswith('.class') and any(name.startswith(prefix) for prefix in prefixes):
            if class_owner((Path(root)/name).read_bytes())+'.class' != name:
                raise RuntimeError('Class namespace/owner mismatch: '+name)
            result[name] = sha
    if not result:
        raise RuntimeError('No delivered classes in expected namespace')
    return result


def jar_class_map(path, prefixes):
    result = {}
    with ZipFile(path) as bundle:
        for item in bundle.infolist():
            name = item.filename
            if name.startswith('META-INF/versions/'):
                versioned = '/'.join(name.split('/')[3:])
                if versioned.endswith('.class') and any(versioned.startswith(prefix) for prefix in prefixes):
                    raise RuntimeError('Unexpected multi-release owned JAR class: '+name)
            if name.endswith('.class') and any(name.startswith(prefix) for prefix in prefixes):
                if name in result or item.external_attr >> 16 & 0o170000 == 0o120000:
                    raise RuntimeError('Duplicate or symlink JAR class')
                data = bundle.read(item)
                if class_owner(data)+'.class' != name:
                    raise RuntimeError('JAR class namespace/owner mismatch: '+name)
                result[name] = hashlib.sha256(data).hexdigest()
    return result


def compare_delivered(expected, classes, jar, prefixes):
    if class_map(classes, prefixes) != expected:
        raise RuntimeError('Actual Maven classes differ from canonical generation')
    if jar_class_map(jar, prefixes) != expected:
        raise RuntimeError('Actual Maven JAR classes differ from canonical generation')


@contextmanager
def staging_directory(destination):
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise RuntimeError('Stage destination must not exist')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.crypto-delivery-', dir=destination.parent) as temporary:
        work = Path(temporary)/'stage'
        work.mkdir()
        yield work
        work.rename(destination)


def run_command(command, log, cwd, timeout=1800):
    process = None
    pending = []
    handlers = {s:signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

    def cancel(signum, frame):
        # selectors/select treat InterruptedError as retryable EINTR, which
        # would silently swallow cancellation while communicate() is waiting.
        raise KeyboardInterrupt('Delivery tool cancelled by signal '+str(signum))

    try:
        # Record ownership before a cancellation is allowed to raise.
        for sig in handlers:
            signal.signal(sig, lambda signum, frame: pending.append(signum))
        try:
            process = subprocess.Popen(list(map(str, command)), cwd=cwd, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, start_new_session=True)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, cancel if handler == signal.SIG_DFL else handler)
        if pending:
            raise KeyboardInterrupt('Cancelled while starting delivery tool')
        output, _ = process.communicate(timeout=timeout)
    except BaseException as error:
        if process is not None:
            try:
                if process.returncode is None:
                    os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                output, _ = process.communicate()
                Path(log).write_text(output)
        if isinstance(error, subprocess.TimeoutExpired):
            raise RuntimeError('Delivery tool timeout; owned process group reaped') from error
        raise
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    Path(log).write_text(output)
    return process.returncode, output


def handwritten_inventory(source_root, namespace, existing_generated_sources=None):
    generated_prefix = namespace.replace('.', '/')+'/'
    return {name:sha for name, sha in file_map(source_root).items()
            if name.endswith('.java') and not name.startswith(generated_prefix)
            and name not in (existing_generated_sources or {})}


def compile_handwritten(source_root, namespace, java_home, classpath, output, options, timeout=1800,
                        existing_generated_sources=None):
    """Restore the original lint policy outside the exact generated namespace."""
    lint = options.get('handwritten_lint')
    if lint != ['-Xlint:all,-serial']:
        raise RuntimeError('Handwritten Java must retain the original strict lint categories')
    source_root = Path(source_root).resolve()
    java_home = Path(java_home).resolve()
    classpath = [Path(path).resolve() for path in classpath]
    existing_generated_sources = existing_generated_sources or {}
    check_pins(source_root, existing_generated_sources)
    sources = handwritten_inventory(source_root, namespace, existing_generated_sources)
    if not sources:
        raise RuntimeError('No handwritten source coverage for the strict lint replacement')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    frozen = output/'inputs'
    all_inputs = dict(sources, **existing_generated_sources)
    freeze_inputs(source_root, all_inputs, frozen)
    classes = output/'classes'
    classes.mkdir()
    existing_classes = {}
    if existing_generated_sources:
        generated_command = [Path(java_home)/'bin/javac', '--release', '21', '-g:'+options['debug'],
            '-encoding', options['encoding'], *options.get('common_args', []), *options['lint'], '-sourcepath', '',
            '-cp', os.pathsep.join(map(str, classpath)), '-d', classes,
            *[frozen/name for name in existing_generated_sources]]
        status, diagnostics = run_command(generated_command, output/'existing-generated-javac.log', source_root, timeout)
        if status or diagnostics.strip():
            raise RuntimeError('Pinned existing compiler output failed compilation: '+diagnostics[-4000:])
        existing_classes = class_map(classes, [''])
    command = [Path(java_home)/'bin/javac', '--release', '21', '-g:'+options['debug'],
               '-encoding', options['encoding'], *options.get('common_args', []), *lint, '-sourcepath', '',
               '-cp', os.pathsep.join(map(str, [classes, *classpath])), '-d', classes,
               *[frozen/name for name in sources]]
    status, diagnostics = run_command(command, output/'javac.log', source_root, timeout)
    if status or diagnostics.strip():
        raise RuntimeError('Strict handwritten Java compilation failed or warned: '+diagnostics[-4000:])
    if handwritten_inventory(source_root, namespace, existing_generated_sources) != sources:
        raise RuntimeError('Handwritten Java source set changed during strict compilation')
    check_pins(source_root, existing_generated_sources)
    check_tree(frozen, all_inputs)
    compiled = class_map(classes, [''])
    check_tree(classes, compiled)
    if any(compiled.get(name) != sha for name, sha in existing_classes.items()):
        raise RuntimeError('Existing generated classes changed during handwritten compilation')
    return {'sources':sources, 'classes':compiled, 'lint':lint, 'command':list(map(str, command)),
            'existing_generated_sources':existing_generated_sources, 'existing_generated_classes':existing_classes}


def tool_tree(root):
    """JDK legal-file symlinks are recorded with link text and target contents."""
    root = Path(root).resolve()
    result = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = path.resolve(strict=True)
            if not target.is_file():
                raise RuntimeError('Unsupported JDK directory symlink')
            result[name] = {'link':os.readlink(path), 'target':str(target), 'sha256':digest(target)}
        elif path.is_file():
            result[name] = digest(path)
    return result


def official_distribution(cache, manifest):
    key = platform.system()+'-'+platform.machine()
    asset = manifest['dafny']['assets'].get(key)
    if asset is None:
        raise RuntimeError('No reviewed official Dafny distribution for '+key)
    archive = Path(cache)/asset['archive']
    check_pins(cache, {asset['archive']:asset['sha256']})
    directory = Path(cache)/asset['directory']
    expected = {}
    with ZipFile(archive) as bundle:
        for member in bundle.infolist():
            name = PurePosixPath(member.filename)
            if (name.is_absolute() or '..' in name.parts or '\\' in member.filename
                    or not name.parts or name.parts[0] != 'dafny'
                    or member.external_attr >> 16 & 0o170000 == 0o120000):
                raise RuntimeError('Unsafe official distribution archive member')
            if not member.is_dir():
                if member.filename in expected:
                    raise RuntimeError('Duplicate official distribution member')
                expected[member.filename] = hashlib.sha256(bundle.read(member)).hexdigest()
    check_tree(directory, expected)
    executable = directory/'dafny/dafny'
    runtime = directory/'dafny/DafnyRuntime.jar'
    if digest(runtime) != asset['runtime_sha256']:
        raise RuntimeError('Official bundled runtime pin changed')
    return executable, runtime, asset


def check_runtime(runtime, manifest):
    if digest(runtime) != manifest['runtime']['sha256']:
        raise RuntimeError('Maven Dafny runtime checksum mismatch')
    classes = jar_class_map(runtime, [''])
    if json_digest(classes) != manifest['runtime']['classmap_sha256']:
        raise RuntimeError('Maven Dafny runtime class inventory mismatch')
    return classes


def check_bindings(sources, manifest, root=ROOT):
    expected = [binding for binding in manifest['provider_bindings'] if binding['source'] in sources]
    actual = []
    for name in sources:
        text = safe_path(root, name).read_text()
        matches = re.findall(r'(?:function|method)\s+\{:extern "([\w.]+)", "(\w+)"\}\s+\{:axiom\}\s*(\w+)', text)
        if text.count('{:extern') != len(matches):
            raise RuntimeError('Unexpected external declaration: '+name)
        for owner, method, symbol in matches:
            actual.append({'source':name, 'owner':owner, 'method':method, 'symbol':symbol})
    order = lambda binding: (binding['source'], binding['owner'], binding['method'], binding['symbol'])
    if sorted(actual, key=order) != sorted(expected, key=order):
        raise RuntimeError('Provider external owner/method ABI mismatch')


def check_pom(manifest):
    import xml.etree.ElementTree as ET
    ns = {'m':'http://maven.apache.org/POM/4.0.0'}
    pom = ET.parse(ROOT/'quic/pom.xml').getroot()
    dependencies = [d for d in pom.findall('m:dependencies/m:dependency', ns)
                    if d.findtext('m:groupId', namespaces=ns) == 'org.dafny']
    if (len(dependencies) != 1 or dependencies[0].findtext('m:artifactId', namespaces=ns) != 'DafnyRuntime'
            or dependencies[0].findtext('m:version', namespaces=ns) != '4.9.1'
            or dependencies[0].findtext('m:scope', default='compile', namespaces=ns) != 'compile'):
        raise RuntimeError('Maven runtime dependency contract changed')
    compiler = next((p for p in pom.findall('m:build/m:plugins/m:plugin', ns)
                     if p.findtext('m:artifactId', namespaces=ns) == 'maven-compiler-plugin'), None)
    if compiler is None:
        raise RuntimeError('Missing Maven compiler configuration')
    config = compiler.find('m:configuration', ns)
    if (config.findtext('m:debug', namespaces=ns) != 'true'
            or config.findtext('m:debuglevel', namespaces=ns) != 'lines,vars,source'
            or config.findtext('m:encoding', namespaces=ns) != 'UTF-8'
            or [e.text for e in config.findall('m:compilerArgs/m:arg', ns)] != manifest['javac']['common_args']+manifest['javac']['lint']):
        raise RuntimeError('Maven/canonical compiler options differ')
    test_executions = [e for e in compiler.findall('m:executions/m:execution', ns)
                       if e.findtext('m:id', namespaces=ns) == 'default-testCompile']
    if (len(test_executions) != 1 or [e.text for e in test_executions[0].findall(
            'm:configuration/m:compilerArgs/m:arg', ns)] != manifest['javac']['common_args']+manifest['javac']['handwritten_lint']
            or test_executions[0].find('m:configuration/m:compilerArgs', ns).get('combine.self') != 'override'):
        raise RuntimeError('Maven handwritten test compilation lost its original strict lint policy')
    parent = ET.parse(ROOT/'pom.xml').getroot()
    if parent.findtext('m:properties/m:maven.compiler.release', namespaces=ns) != '21':
        raise RuntimeError('Maven release contract changed')


def stage(args, manifest):
    if json.loads((HERE/'delivery.json').read_text()) != manifest:
        raise RuntimeError('Delivery configuration changed after loading')
    dafny, bundled, asset = official_distribution(args.cache, manifest)
    if manifest['dafny']['dependency_options'] != list(DEPENDENCY_OPTIONS):
        raise RuntimeError('Dafny dependency parser policy changed')
    component = args.component
    entry_name = 'formal/crypto/'+component+'.dfy' if component else manifest['entry']
    entry = safe_path(ROOT, entry_name)
    sources = source_closure(ROOT, entry, dafny, timeout=args.timeout)
    evidence_paths = []
    replay_inputs = {}
    if not component:
        if args.evidence is None:
            raise RuntimeError('Full stage requires --evidence with complete native input receipts')
        replay_inputs = native_input_pins(ROOT, sources, manifest['native_evidence'], dafny, timeout=args.timeout)
        evidence_paths = [args.evidence.resolve()]
        evidence_paths += validate_input_evidence(json.loads(args.evidence.read_text()), args.evidence.parent, sources,
            manifest['runtime']['sha256'], expected_inputs=replay_inputs, contract=manifest['native_evidence'])
    provider_list = [p for p in manifest['providers'] if any(b['source'] in sources and b['owner'] == p['owner'] for b in manifest['provider_bindings'])]
    provider_sources = provider_inventory(ROOT, provider_list)
    check_bindings(sources, manifest)
    check_pom(manifest)
    local_inputs = dict(sources, **replay_inputs)
    # The reviewed handwritten boundary is part of the stage, too. Comparing
    # Maven classes with a fresh compilation of arbitrary current facade source
    # would establish artifact identity without preserving the reviewed calls.
    for facade in manifest.get('facades', []):
        check_pins(ROOT, {facade['source']:facade['sha256']})
        local_inputs[facade['source']] = facade['sha256']
    for path in [HERE/'delivery.py', HERE/'delivery.json', ROOT/'pom.xml', ROOT/'quic/pom.xml']+[ROOT/p['source'] for p in provider_list]:
        local_inputs[path.relative_to(ROOT).as_posix()] = digest(path)
    external_inputs = {str(p.resolve()):digest(p) for p in evidence_paths}
    runtime_classes = check_runtime(args.runtime, manifest)
    solver = dafny.parent/'z3/bin/z3-4.12.1'
    java_home = args.java_home.resolve()
    jdk_before = tool_tree(java_home)
    if not jdk_before:
        raise RuntimeError('Missing explicit JDK home')
    with staging_directory(args.output) as work:
        frozen = work/'inputs'
        freeze_inputs(ROOT, local_inputs, frozen)
        report = {'schema':'microproxy.crypto-delivery-stage/v1', 'status':'component-only' if component else 'complete',
                  'component':component, 'entry':entry_name, 'sources':sources, 'inputs':local_inputs,
                  'input_evidence':str(args.evidence.resolve()) if args.evidence else None,
                  'native_evidence_contract':manifest['native_evidence']['schema'] if not component else None,
                  'native_replay_inputs':replay_inputs,
                  'external_inputs':external_inputs, 'manifest_sha256':digest(HERE/'delivery.json'),
                  'commands':[], 'proofs':{}, 'jdk_home':str(java_home), 'jdk_files':jdk_before,
                  'source_verification_options':{name:source_verify_options(name, manifest) for name in sources},
                  'compiler_options':manifest['javac'], 'dependency_options':list(DEPENDENCY_OPTIONS),
                  'runtime_sha256':digest(args.runtime),
                  'runtime_classmap':runtime_classes, 'official_asset':asset,
                  'trust':manifest['trust'], 'source_transforms':[], 'class_comparison':'exact full class bytes; no attributes ignored'}

        def call(label, command):
            status, output = run_command(command, work/(label+'.log'), ROOT, args.timeout)
            report['commands'].append({'label':label, 'argv':list(map(str, command)), 'exit':status})
            return status, output

        if source_closure(frozen, frozen/entry_name, dafny, timeout=args.timeout, call=
                lambda label, command: call('frozen-'+label, command)) != sources:
            raise RuntimeError('Frozen source/include closure mismatch')
        status, version = call('dafny-version', [dafny, '--version'])
        if status or version.strip() != manifest['dafny']['version_string']:
            raise RuntimeError('Unexpected official Dafny version')
        status, version = call('solver-version', [solver, '--version'])
        if status or version.strip() != manifest['dafny']['solver_version_string']:
            raise RuntimeError('Unexpected official solver version')
        status, version = call('javac-version', [java_home/'bin/javac', '-version'])
        if status or not re.fullmatch(r'javac (?:21|25)(?:[.][\w.+-]+)*\s*', version):
            raise RuntimeError('Expected explicit JDK21 or JDK25 compiler')
        report['javac_version'] = version.strip()
        expected_audit = [(b['source'], b['symbol']) for b in manifest['provider_bindings'] if b['source'] in sources]
        report['provider_assumptions'] = audit_result(*call('audit', [dafny, 'audit', *[frozen/p for p in sources]]), frozen, expected_audit)
        flags = [*manifest['dafny']['verify_options'], '--solver-path', str(solver)]
        provider_only = {binding['source'] for binding in manifest['provider_bindings']}
        # Each root is verified; included files are never silently assumed proven.
        for number, source in enumerate(sources):
            extra = source_verify_options(source, manifest)
            status, output = call('proof-'+str(number), [dafny, 'verify', frozen/source, *flags, *extra])
            try:
                report['proofs'][source] = proof_result(status, output, minimum=0 if source in provider_only else 1)
            except RuntimeError as error:
                raise RuntimeError('Proof failed for '+source+': '+output[-4000:]) from error
        check_tree(frozen, local_inputs)
        generated_name = manifest['output_name']
        report['generation'] = generation_result(*call('generate', [dafny, 'translate', 'java', frozen/entry_name,
            '--no-verify', '--outer-module', manifest['namespace'], '--output', work/generated_name]))
        generated = work/(generated_name+'-java')
        generated_files = file_map(generated)
        delivered = generated_inventory(generated, manifest['namespace'], generated_name)
        canonical_sources = work/'sources'
        canonical_sources.mkdir()
        for name in delivered:
            path = canonical_sources/name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(generated/name, path)
        for provider in provider_list:
            name = provider['owner'].replace('.', '/')+'.java'
            path = canonical_sources/name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(frozen/provider['source'], path)
        source_files = file_map(canonical_sources)
        if source_files != dict(delivered, **provider_sources):
            raise RuntimeError('Canonical generated/provider source inventory mismatch')
        classes = work/'classes'
        classes.mkdir()
        options = manifest['javac']
        status, output = call('javac', [java_home/'bin/javac', '--release', '21', '-g:'+options['debug'],
            '-encoding', options['encoding'], *options['common_args'], *options['lint'], '-cp', args.runtime, '-d', classes,
            *[canonical_sources/name for name in source_files]])
        if status or output.strip():
            raise RuntimeError('Canonical Java compilation failed or emitted diagnostics: '+output[-4000:])
        # Provider prefixes match their class and any nested classes, without
        # sweeping unrelated classes in the containing package into this gate.
        prefixes = [manifest['namespace'].replace('.', '/')+'/']+[p['owner'].replace('.', '/') for p in provider_list]
        canonical_classes = class_map(classes, prefixes)
        if file_map(classes) != canonical_classes:
            raise RuntimeError('Unexpected canonical compiler outputs')
        check_pins(ROOT, local_inputs)
        check_tree(frozen, local_inputs)
        if source_closure(ROOT, entry, dafny, timeout=args.timeout, call=
                lambda label, command: call('current-'+label, command)) != sources:
            raise RuntimeError('Dafny source/include closure changed during generation')
        for path, sha in external_inputs.items():
            if digest(path) != sha:
                raise RuntimeError('Input receipt changed during generation')
        official_distribution(args.cache, manifest)
        check_runtime(args.runtime, manifest)
        if tool_tree(java_home) != jdk_before:
            raise RuntimeError('JDK/compiler inputs changed during generation')
        check_tree(generated, generated_files)
        check_tree(canonical_sources, source_files)
        check_tree(classes, canonical_classes)
        report.update({'generated_files':generated_files, 'delivered_sources':source_files,
                       'canonical_classes':canonical_classes, 'class_prefixes':prefixes})
        (work/'receipt.json').write_text(json.dumps(report, indent=2)+'\n')
    return args.output/'receipt.json'


def load_stage(args, manifest):
    stage_dir = args.stage.resolve()
    receipt = stage_dir/'receipt.json'
    data = json.loads(receipt.read_text())
    if (data.get('schema') != 'microproxy.crypto-delivery-stage/v1' or data.get('status') != 'complete'
            or data.get('component') is not None or data.get('entry') != manifest['entry']
            or data.get('manifest_sha256') != digest(HERE/'delivery.json')):
        raise RuntimeError('A current complete full stage is required')
    check_pins(ROOT, data['inputs'])
    check_tree(stage_dir/'inputs', data['inputs'])
    dafny, _, _ = official_distribution(args.cache, manifest)
    if source_closure(ROOT, ROOT/data['entry'], dafny, timeout=args.timeout) != data['sources']:
        raise RuntimeError('Stale stage source closure')
    for path, sha in data['external_inputs'].items():
        if digest(path) != sha:
            raise RuntimeError('Stale stage input receipt')
    check_tree(stage_dir/'sources', data['delivered_sources'])
    check_tree(stage_dir/'classes', data['canonical_classes'])
    check_tree(stage_dir/(manifest['output_name']+'-java'), data['generated_files'])
    official_distribution(args.cache, manifest)
    check_runtime(args.runtime, manifest)
    if tool_tree(Path(data['jdk_home'])) != data['jdk_files']:
        raise RuntimeError('Stage JDK/compiler changed')
    return receipt, data


def production_sources(manifest, expected):
    for facade in manifest.get('facades', []):
        check_pins(ROOT, {facade['source']:facade['sha256'], facade['destination']:facade['sha256']})
    source_root = ROOT/manifest['destination']
    prefixes = [manifest['namespace'].replace('.', '/')+'/']+[p['owner'].replace('.', '/') for p in manifest['providers']]
    actual = {name:sha for name, sha in file_map(source_root).items() if any(name.startswith(p) for p in prefixes)}
    if actual != expected:
        raise RuntimeError('Missing, extra or stale production source artifact')


def reproduce_stage(args, manifest, data):
    """Never trust an editable local class-hash receipt as the canonical oracle."""
    if not data.get('input_evidence'):
        raise RuntimeError('Full stage lacks its complete input-evidence path')
    with tempfile.TemporaryDirectory(prefix='crypto-delivery-reproduce-') as temporary:
        replay = argparse.Namespace(**vars(args))
        replay.component = None
        replay.evidence = Path(data['input_evidence'])
        replay.java_home = Path(data['jdk_home'])
        replay.output = Path(temporary)/'canonical'
        receipt = stage(replay, manifest)
        reproduced = json.loads(receipt.read_text())
        for field in ('sources', 'delivered_sources', 'canonical_classes', 'generated_files', 'class_prefixes'):
            if reproduced[field] != data[field]:
                raise RuntimeError('Stage differs from fresh canonical generation: '+field)


@contextmanager
def initial_sources(canonical, destination, pins):
    """Exclusive initial installation; roll back only files created by this call."""
    check_tree(canonical, pins)
    created = []
    directories = []
    try:
        for name, sha in pins.items():
            target = safe_path(destination, name)
            if target.exists():
                if not target.is_file() or digest(target) != sha:
                    raise RuntimeError('Refusing stale existing production artifact: '+name)
                continue
            absent = []
            parent = target.parent
            while not parent.exists():
                absent.append(parent)
                parent = parent.parent
            target.parent.mkdir(parents=True, exist_ok=True)
            directories.extend(reversed(absent))
            with target.open('xb') as stream:
                identity = os.fstat(stream.fileno())
                created.append((target, identity.st_dev, identity.st_ino))
                stream.write((Path(canonical)/name).read_bytes())
            if digest(target) != sha:
                raise RuntimeError('Production source changed while copying: '+name)
        yield
    except BaseException:
        for path, device, inode in reversed(created):
            if path.exists() and not path.is_symlink():
                identity = path.stat()
                if (identity.st_dev, identity.st_ino) == (device, inode):
                    path.unlink()
        for directory in reversed(directories):
            try:
                directory.rmdir()
            except OSError:
                pass  # Preserve any directory that acquired other work.
        raise


def publish(args, manifest):
    receipt, data = load_stage(args, manifest)
    if args.approval is None:
        raise RuntimeError('Publish requires --approval after performance/compatibility review')
    approval_sha = digest(args.approval)

    def check_decision():
        if digest(args.approval) != approval_sha:
            raise RuntimeError('Adoption decision changed during canonical reproduction')
        validate_approval(json.loads(args.approval.read_text()), args.approval.parent, receipt)
        if digest(args.approval) != approval_sha:
            raise RuntimeError('Adoption decision changed during evidence validation')

    check_decision()
    reproduce_stage(args, manifest, data)
    check_decision()
    # Initial adoption only: never delete or overwrite an existing stale file.
    # Regeneration with changed files requires an explicitly reviewed migration.
    source_root = ROOT/manifest['destination']
    with initial_sources(args.stage/'sources', source_root, data['delivered_sources']):
        production_sources(manifest, data['delivered_sources'])
        load_stage(args, manifest)
        check_decision()
    return {'status':'published', 'stage_receipt_sha256':digest(receipt), 'source_files':len(data['delivered_sources'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('mode', choices=('stage', 'publish', 'check', 'runtime'))
    parser.add_argument('--cache', type=Path, default=Path.home()/'.cache/microproxy-formal')
    parser.add_argument('--runtime', type=Path, default=Path.home()/'.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar')
    parser.add_argument('--java-home', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--component', choices=('NativeShake', 'NativeCodec', 'NativeSampling', 'NativePolynomial'))
    parser.add_argument('--stage', type=Path)
    parser.add_argument('--approval', type=Path)
    parser.add_argument('--classes', type=Path, default=ROOT/'quic/target/classes')
    parser.add_argument('--jar', type=Path, default=ROOT/'quic/target/quic-0.6.0.jar')
    parser.add_argument('--timeout', type=int, default=1800)
    args = parser.parse_args()
    for name in ('cache', 'runtime', 'java_home', 'output', 'evidence', 'stage', 'approval', 'classes', 'jar'):
        path = getattr(args, name)
        if path is not None:
            setattr(args, name, path.expanduser().resolve())
    manifest = json.loads((HERE/'delivery.json').read_text())
    if args.mode == 'runtime':
        _, bundled, _ = official_distribution(args.cache, manifest)
        maven = check_runtime(args.runtime, manifest)
        official = jar_class_map(bundled, [''])
        result = {'maven_sha256':digest(args.runtime), 'bundled_sha256':digest(bundled),
                  'only_maven':sorted(maven.keys()-official.keys()), 'only_bundled':sorted(official.keys()-maven.keys()),
                  'changed_classes':[name for name in sorted(maven.keys() & official.keys()) if maven[name] != official[name]],
                  'trust':manifest['trust']}
    elif args.mode == 'stage':
        if args.output is None or args.java_home is None:
            parser.error('stage requires --output and an explicit --java-home')
        result = {'receipt':str(stage(args, manifest))}
    else:
        if args.stage is None:
            parser.error(args.mode+' requires --stage')
        if args.mode == 'publish':
            result = publish(args, manifest)
        else:
            receipt, data = load_stage(args, manifest)
            reproduce_stage(args, manifest, data)
            production_sources(manifest, data['delivered_sources'])
            with tempfile.TemporaryDirectory(prefix='crypto-delivery-handwritten-') as temporary:
                handwritten = compile_handwritten(ROOT/manifest['destination'], manifest['namespace'],
                    Path(data['jdk_home']), [args.stage/'classes', args.runtime],
                    Path(temporary)/'strict', manifest['javac'], args.timeout,
                    existing_generated_sources=manifest['existing_generated_sources'])
                expected = dict(data['canonical_classes'])
                for name, sha in handwritten['classes'].items():
                    if name in expected and expected[name] != sha:
                        raise RuntimeError('Handwritten provider differs between strict and canonical compilation: '+name)
                    expected[name] = sha
                # Every main class is now covered, including handwritten facades
                # and providers; never promote a mutable actual-class snapshot
                # to the expected oracle between the two comparisons.
                jar_sha = digest(args.jar)
                compare_delivered(expected, args.classes, args.jar, [''])
                load_stage(args, manifest)
                production_sources(manifest, data['delivered_sources'])
                check_pins(ROOT/manifest['destination'], manifest['existing_generated_sources'])
                if handwritten_inventory(ROOT/manifest['destination'], manifest['namespace'],
                                         manifest['existing_generated_sources']) != handwritten['sources']:
                    raise RuntimeError('Handwritten sources changed during delivery acceptance')
                compare_delivered(expected, args.classes, args.jar, [''])
                if digest(args.jar) != jar_sha:
                    raise RuntimeError('Maven JAR changed during delivery check')
                result = {'status':'checked', 'stage_receipt_sha256':digest(receipt), 'jar_sha256':jar_sha,
                          'class_count':len(expected), 'generated_class_count':len(data['canonical_classes']),
                          'handwritten_sources':len(handwritten['sources']), 'handwritten_lint':handwritten['lint'],
                          'existing_generated_sources':manifest['existing_generated_sources'],
                          'comparison':'exact class bytes including all debug attributes'}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print('Delivery rejected: '+str(error), file=sys.stderr)
        raise SystemExit(1)
