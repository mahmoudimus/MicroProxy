"""Official fully-expanded Keccak trace replay component.

This module is the reusable, official-only entry point for the seven reviewed
NativeKeccak bodies (Rotate/Theta/RhoPi/Iota/Chi/Round/PermuteScratch).  It:

  * enforces the actual reviewed left+right shift admission at entry (no
    monkeypatch, no scratch bypass); the current official extractor/policy carry
    exactly that set, and any drift/right-only regression fails closed;
  * runs ``runtime_primitives.replay`` for the actual pinned DafnyRuntime jar;
  * binds the loaded trusted Python modules and the Dafny/policy/input files to
    their canonical paths and pinned hashes before and after use;
  * binds the actual NativeKeccak source/class and combines the verified
    ``dafny/Helpers.class`` entry with the caller's inspected classpath;
  * inlines the actual Helpers shift bodies and every private NativeKeccak
    helper, leaving only the exact public provider whitelist;
  * emits compact ``ExecP`` certificates using the original generic
    PublicProvider.dfy plus the PublicProviderPublic.dfy public-call layer and a
    target-free WordArithmetic.dfy, with per-root actual target ids;
  * runs honest finite controls/prefer a ``ProgramView`` oracle subclass, records
    event/state hashes and counts, and requires full PermuteScratch 24 rounds;
  * runs compiled Dafny oracle KATs over the actual public domain (division/mod
    0..24 by 5, rotate 0..63, identity BigInteger.ZERO, signum 0..63);
  * records genuine structure, public-call, unknown-target and private-count proof
    failures plus binding/body-identity metadata.

Scope is deliberately narrow: no Permute wrapper (array-return composition is
unsupported), no Sponge ownership/NI, no closure of the 13 open roots / 19
assumptions / 31 labels, and no JVM value/timing/exception refinement.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# Deliberately use the top-level module instances: composition.py and
# runtime_primitives.py import these names by bare module name.  Using package
# relative imports here would create a second bytecode_trace instance and make
# the admission check silently disagree with the extractor used for inlining.
import bytecode_trace as bt
import compact_certificates as compact
import composition as comp
import runtime_primitives as rp
import trace_exec

BUDGET = ('--verification-time-limit', '30', '--resource-limit', '50000000',
          '--solver-option', 'O:smt.case_split=0')
PROOF_TIMEOUT = 300
STEP_CAP = 1 << 20
MASK64 = (1 << 64) - 1
TWO63 = 1 << 63
TWO64 = 1 << 64

NATIVE_OWNER = 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default'
NATIVE_CLASS = NATIVE_OWNER.replace('/', '.')
NATIVE_SOURCE_REL = ('quic/src/main/java/io/github/mahmoudimus/quic/internal/'
                     'verifiedcrypto/NativeKeccak/__default.java')
EXPECTED_NATIVE_SOURCE_SHA256 = '539f3cee594139794fde8be11853f8a09470177d42a23f5f422433ae57e3b75e'
EXPECTED_NATIVE_CLASS_SHA256 = '5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91'
HELPER_OWNER = 'dafny/Helpers'
HELPER_CLASS = 'dafny.Helpers'
HELPER_ENTRY = 'dafny/Helpers.class'
LEFT_SHIFT = 'dafny/Helpers.bv64ShiftLeft:(JB)J'
RIGHT_SHIFT = 'dafny/Helpers.bv64ShiftRight:(JB)J'
REVIEWED_SHIFT_SET = {LEFT_SHIFT, RIGHT_SHIFT}

ROOT_KEYS = (
    'Rotate:(JI)J', 'Theta:([J[J)V', 'RhoPi:([J[J[I[I)V', 'Iota:([JJ)V',
    'Chi:([J[J)V', 'Round:([J[J[J[I[IJ)V', 'PermuteScratch:([J[J[J[I[I)V',
)
ROOT_NAMES = {key: key.split(':', 1)[0] for key in ROOT_KEYS}
ROOT_SHAPES = {
    'Rotate': [], 'Theta': [25, 5], 'RhoPi': [25, 25, 25, 25],
    'Iota': [25], 'Chi': [25, 25],
    'Round': [25, 25, 5, 25, 25], 'PermuteScratch': [25, 25, 5, 25, 25],
}
PUBLIC_TABLE_ROLE = {
    'RhoPi': {2: 'offsets', 3: 'sources'},
    'Round': {3: 'offsets', 4: 'sources'},
    'PermuteScratch': {3: 'offsets', 4: 'sources'},
}
METHOD_PARAMS = {
    'Rotate:(JI)J': ['sec', 'pub'],
    'Constant:(I)J': ['pub'],
    'SetLane:([JIJ)V': ['array_sec', 'pub', 'sec'],
    'Iota:([JJ)V': ['array_sec', 'pub'],
    'Theta:([J[J)V': ['array_sec', 'array_sec'],
    'RhoPi:([J[J[I[I)V': ['array_sec', 'array_sec', 'array_pub', 'array_pub'],
    'Chi:([J[J)V': ['array_sec', 'array_sec'],
    'Round:([J[J[J[I[IJ)V': ['array_sec', 'array_sec', 'array_sec', 'array_pub',
                              'array_pub', 'pub'],
    'PermuteScratch:([J[J[J[I[I)V': ['array_sec', 'array_sec', 'array_sec',
                                      'array_pub', 'array_pub'],
}
PRIVATE_CALL_RESULTS = {
    'Rotate:(JI)J': 'args', 'Constant:(I)J': 'pub', 'SetLane:([JIJ)V': 'sec',
    'Iota:([JJ)V': 'sec', 'Theta:([J[J)V': 'sec', 'RhoPi:([J[J[I[I)V': 'sec',
    'Chi:([J[J)V': 'sec', 'Round:([J[J[J[I[IJ)V': 'sec',
    'PermuteScratch:([J[J[J[I[I)V': 'sec',
}
HEAP_EFFECT = {
    'SetLane:([JIJ)V': 'parameter-array-write', 'Iota:([JJ)V': 'parameter-array-write',
    'Theta:([J[J)V': 'parameter-array-write', 'RhoPi:([J[J[I[I)V': 'parameter-array-write',
    'Chi:([J[J)V': 'parameter-array-write', 'Round:([J[J[J[I[IJ)V': 'parameter-array-write',
}
SEMANTIC_TARGETS = {
    'dafny/DafnyEuclidean.EuclideanDivision:(II)I': (
        'TARGET_EUCLIDEAN_DIVISION', 2,
        'WordDivision(publicArgs[0].value, publicArgs[1].value)'),
    'dafny/DafnyEuclidean.EuclideanModulus:(II)I': (
        'TARGET_EUCLIDEAN_MODULUS', 2,
        'WordModulus(publicArgs[0].value, publicArgs[1].value)'),
    'dafny/Helpers.toInt:(I)I': (
        'TARGET_TO_INT', 1, 'ToIntIntWord(publicArgs[0].value)'),
    'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I': (
        'TARGET_TO_INT_BIG_INTEGER', 1, 'ToIntBigIntegerWord(publicArgs[0].value)'),
    'java/lang/Integer.signum:(I)I': (
        'TARGET_INTEGER_SIGNUM', 1, 'SignumWord(publicArgs[0].value)'),
}
ALLOWED_PUBLIC_TARGETS = set(SEMANTIC_TARGETS)
PRIVATE_TARGETS = {f'{NATIVE_OWNER}.{key}' for key in ROOT_KEYS}
EXPECTED_PUBLIC_PROVIDER_CHECKS = 16
EXPECTED_PUBLIC_LAYER_CHECKS = 9
EXPECTED_WORD_ARITHMETIC_CHECKS = 56
EXPECTED_ROOT_CHECKS = {
    'Rotate': 48, 'Theta': 163, 'RhoPi': 80, 'Iota': 29,
    'Chi': 67, 'Round': 294, 'PermuteScratch': 472,
}
PUBLIC_LAYER = HERE / 'PublicProviderPublic.dfy'


class KeccakTraceError(RuntimeError):
    """A binding, admission, proof, control or scope gate failed closed."""


class AdmissionError(KeccakTraceError):
    """The actual reviewed shift admission is not present."""


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(path: Path) -> str:
    return sha_bytes(Path(path).read_bytes())


def _json_sha(value) -> str:
    return sha_bytes(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def _canonical(path: Path, expected: Path, label: str) -> Path:
    actual = Path(path).expanduser().resolve()
    want = Path(expected).resolve()
    if actual != want:
        raise KeccakTraceError(f'{label} must be the canonical path {want}, got {actual}')
    return actual


def require_reviewed_admission(actual=None, declared=None) -> dict:
    """Fail closed unless the actual and declared shift sets are exactly left+right.

    ``actual``/``declared`` parameters are for fast unit tests of the gate; the
    official replay passes the real loaded module set and the policy declaration.
    """
    actual_set = set(bt.SHIFT_COUNT_PUBLIC_RUNTIME_CALLS if actual is None else actual)
    if actual_set != REVIEWED_SHIFT_SET:
        missing = sorted(REVIEWED_SHIFT_SET - actual_set)
        extra = sorted(actual_set - REVIEWED_SHIFT_SET)
        raise AdmissionError(
            'official Keccak replay requires exactly {left,right} shift-count public '
            f'runtime calls; actual={sorted(actual_set)} missing={missing} extra={extra}. '
            'Root must update the official extractor admission and policy pin first; '
            'this component never monkeypatches admission.')
    if declared is not None:
        declared_set = set(declared)
        if declared_set != REVIEWED_SHIFT_SET:
            raise AdmissionError(
                'policy runtime classification is not exactly {left,right}: '
                f'{sorted(declared_set)}')
    return {'actual': sorted(actual_set),
            'declared': None if declared is None else sorted(set(declared)),
            'expected': sorted(REVIEWED_SHIFT_SET)}


def _bind_modules(inputs_path: Path) -> dict:
    canonical = {
        'bytecode_trace': HERE / 'bytecode_trace.py',
        'composition': HERE / 'composition.py',
        'trace_exec': HERE / 'trace_exec.py',
        'runtime_primitives': HERE / 'runtime_primitives.py',
        'compact_certificates': HERE / 'compact_certificates.py',
        'keccak_traces': HERE / 'keccak_traces.py',
    }
    modules = {
        'bytecode_trace': bt, 'composition': comp, 'trace_exec': trace_exec,
        'runtime_primitives': rp, 'compact_certificates': compact,
        'keccak_traces': sys.modules[__name__],
    }
    try:
        return rp.bind_loaded_modules(modules, inputs_path=Path(inputs_path),
                                      canonical=canonical)
    except Exception as error:  # noqa: BLE001 - preserve fail-closed type/message
        raise KeccakTraceError('loaded trusted module binding failed: ' + str(error)) from error


def _bind_files(inputs_path: Path, policy_path: Path) -> dict:
    mapping = {
        'policy': policy_path,
        'secret_trace': HERE / 'SecretTrace.dfy',
        'public_provider': HERE / 'PublicProvider.dfy',
        'public_provider_public': PUBLIC_LAYER,
        'word_arithmetic': HERE / 'WordArithmetic.dfy',
        'native_source': REPO / NATIVE_SOURCE_REL,
    }
    try:
        return rp.check_input_pins(Path(inputs_path), mapping)
    except Exception as error:  # noqa: BLE001
        raise KeccakTraceError('trusted source/file pin binding failed: ' + str(error)) from error


def bind_all(inputs_path: Path, policy_path: Path) -> dict:
    inputs_path = Path(inputs_path).expanduser().resolve()
    policy_path = Path(policy_path).expanduser().resolve()
    return {
        'inputs': {'path': str(inputs_path), 'sha256': sha(inputs_path)},
        'modules': _bind_modules(inputs_path),
        'files': _bind_files(inputs_path, policy_path),
    }


def _validate_native_identity(classpath: Path) -> dict:
    classpath = Path(classpath).expanduser().resolve()
    source = (REPO / NATIVE_SOURCE_REL).resolve()
    class_file = (classpath / (NATIVE_OWNER + '.class')).resolve()
    if not source.is_file():
        raise KeccakTraceError('NativeKeccak source not found: ' + str(source))
    if not class_file.is_file():
        raise KeccakTraceError('NativeKeccak class not found under classpath: ' + str(class_file))
    source_sha = sha(source)
    class_sha = sha(class_file)
    if source_sha != EXPECTED_NATIVE_SOURCE_SHA256:
        raise KeccakTraceError(
            'NativeKeccak source hash is not the reviewed hash: '
            f'{source_sha} != {EXPECTED_NATIVE_SOURCE_SHA256}')
    if class_sha != EXPECTED_NATIVE_CLASS_SHA256:
        raise KeccakTraceError(
            'NativeKeccak class hash is not the reviewed hash: '
            f'{class_sha} != {EXPECTED_NATIVE_CLASS_SHA256}')
    return {'classpath': str(classpath), 'source': str(source),
            'source_sha256': source_sha, 'class': str(class_file),
            'class_sha256': class_sha}


def _overlay_policy(base: dict) -> tuple[dict, dict]:
    policy = copy.deepcopy(base)
    delta = {'classes': [], 'calls': [], 'helpers_methods': []}

    def class_entry(owner: str) -> dict:
        entry = policy.setdefault('classes', {}).setdefault(owner, {'fields': {}, 'methods': {}})
        if not isinstance(entry, dict):
            raise KeccakTraceError('existing class policy is not an object: ' + owner)
        if entry.get('fields') not in (None, {}):
            raise KeccakTraceError('unexpected class fields for ' + owner)
        entry.setdefault('fields', {})
        entry.setdefault('methods', {})
        return entry

    native = class_entry(NATIVE_OWNER)
    for key, params in METHOD_PARAMS.items():
        existing = native['methods'].get(key)
        expected = {'params': list(params)}
        if existing is not None and existing != expected:
            raise KeccakTraceError(
                f'existing NativeKeccak method policy differs for {key}: {existing!r}')
        if existing is None:
            delta['classes'].append(f'classes[{NATIVE_OWNER}].methods[{key}]')
        native['methods'][key] = expected
    for key, result in PRIVATE_CALL_RESULTS.items():
        target = f'{NATIVE_OWNER}.{key}'
        expected = {'kind': 'call', 'result': result}
        existing = policy.setdefault('calls', {}).get(target)
        if existing is not None and existing != expected:
            raise KeccakTraceError(
                f'existing NativeKeccak call rule differs for {key}: {existing!r}')
        if existing is None:
            delta['calls'].append(target)
        policy['calls'][target] = expected

    helpers = class_entry(HELPER_OWNER)
    for key in ('bv64ShiftLeft:(JB)J', 'bv64ShiftRight:(JB)J'):
        expected = {'params': ['sec', 'pub']}
        existing = helpers['methods'].get(key)
        if existing is not None and existing != expected:
            raise KeccakTraceError(
                f'existing Helpers method policy differs for {key}: {existing!r}')
        if existing is None:
            delta['helpers_methods'].append(f'{HELPER_OWNER}.{key}')
        helpers['methods'][key] = expected

    for key in base:
        if key not in ('classes', 'calls') and policy.get(key) != base.get(key):
            raise KeccakTraceError('overlay changed shared policy key ' + key)
    return policy, delta


def _make_entries(policy: dict) -> list[dict]:
    entries = []
    for key, params in METHOD_PARAMS.items():
        if key == 'PermuteScratch:([J[J[J[I[I)V':
            continue
        name, desc = key.split(':', 1)
        result_type = bt.descriptor_types(desc)[1]
        recorded = 'V' if result_type == 'V' else PRIVATE_CALL_RESULTS[key]
        heap = HEAP_EFFECT.get(key, 'none')
        roles = {f'p{i}': taint for i, taint in enumerate(params)}
        entries.append({
            'class': NATIVE_CLASS, 'name': name, 'descriptor': desc,
            'role': 'owned-callee',
            'contract': {'params': list(params), 'result': recorded, 'heap': heap,
                         'reading': 'reviewed inline contract', 'roles': roles},
            'limits': {'time': 30, 'resources': 50000000,
                       'solver_options': ['O:smt.case_split=0']},
        })
    for key in ('bv64ShiftLeft:(JB)J', 'bv64ShiftRight:(JB)J'):
        name, desc = key.split(':', 1)
        params = ['sec', 'pub']
        roles = {f'p{i}': taint for i, taint in enumerate(params)}
        entries.append({
            'class': HELPER_CLASS, 'name': name, 'descriptor': desc,
            'role': 'runtime-body',
            'contract': {'params': params,
                         'result': policy['calls'][f'{HELPER_OWNER}.{key}'].get('result', 'args'),
                         'heap': 'none', 'reading': 'pinned Helpers.class body',
                         'roles': roles},
            'limits': {'time': 30, 'resources': 50000000,
                       'solver_options': ['O:smt.case_split=0']},
        })
    return entries


def _run(cmd: list, timeout: int = PROOF_TIMEOUT) -> dict:
    done = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, timeout=timeout)
    return {'command': [str(c) for c in cmd], 'returncode': done.returncode,
            'stdout': done.stdout, 'stderr': done.stderr,
            'text': done.stdout + done.stderr}


def _write_log(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record['text'])


def _verify(path: Path, log: Path, dafny: Path, solver: Path,
            expected_verified: int | None = None) -> dict:
    record = _run([dafny, 'verify', path, '--solver-path', solver, *BUDGET])
    _write_log(log, record)
    classified = rp.classify_dafny(record['returncode'], record['text'],
                                   expected_verified=expected_verified)
    if classified['status'] != 'verified':
        raise KeccakTraceError(f'{path}: proof did not verify: {classified}')
    classified.update({'log': str(log), 'log_sha256': sha(log),
                       'source_sha256': sha(path),
                       'command': record['command']})
    return classified


def _proof_failure_record(record: dict, log_path: Path, label: str,
                          patterns: list[str], *, reject_structure: bool = False) -> dict:
    classified = rp.classify_dafny(record['returncode'], record['text'])
    if classified['status'] != 'proof_failed':
        raise KeccakTraceError(f'{label}: expected genuine proof failure, got {classified}')
    text = record['text']
    missing = [pattern for pattern in patterns if not re.search(pattern, text)]
    if missing:
        raise KeccakTraceError(f'{label}: diagnostic did not match {missing}: {text[:800]}')
    if re.search(r'out of resource|timed out|resolution/type errors|parse errors|crash',
                 text, re.I):
        raise KeccakTraceError(f'{label}: failure is not a normal proof obligation')
    structure_error = bool(re.search(r'InstrOK|StepOK|Structure', text))
    if reject_structure and structure_error:
        raise KeccakTraceError(f'{label}: unexpected Structure/InstrOK failure: {text[:500]}')
    classified.update({'log': str(log_path), 'log_sha256': sha(log_path),
                       'command': record['command'],
                       'error_lines': [line.strip() for line in text.splitlines()
                                       if 'Error:' in line or 'Related location' in line][:8],
                       'contains_structure_error': structure_error})
    return classified


def _require_structure_proof_failure(record: dict, log_path: Path, label: str,
                                     patterns: list[str]) -> dict:
    return _proof_failure_record(record, log_path, label, patterns)


def _require_public_call_proof_failure(record: dict, log_path: Path, label: str,
                                       patterns: list[str]) -> dict:
    return _proof_failure_record(record, log_path, label, patterns,
                                 reject_structure=True)


def _callee_body_record(method, class_sha256: str) -> dict:
    body = {
        'owner': method.owner, 'name': method.name, 'descriptor': method.descriptor,
        'static': method.static, 'exception_table': method.exception_table,
        'handlers': method.handlers,
        'bytecode': [[insn.offset, insn.op, insn.operand] for insn in method.insns],
    }
    return {'callee_bytecode_sha256': _json_sha(body),
            'callee_class_sha256': class_sha256,
            'callee_body': body,
            'callee_shape_sha256_is_body_identity': False}


def _enrich_inlined(result: dict, specs: dict, class_hashes: dict[str, str]) -> dict:
    enriched = []
    for entry in result.get('inlined', []):
        target = entry['target']
        spec = specs.get(target)
        if spec is None:
            raise KeccakTraceError('inlined target has no bound CalleeSpec: ' + target)
        if spec.owner not in class_hashes:
            raise KeccakTraceError('inlined owner has no actual class hash: ' + spec.owner)
        merged = dict(entry)
        merged.update(_callee_body_record(spec.method, class_hashes[spec.owner]))
        enriched.append(merged)
    result['inlined'] = enriched
    return result


def _check_helper_pin(policy: dict, runtime: dict) -> dict:
    pinned = (policy.get('runtime_classification') or {}).get('pinned_runtime') or {}
    declared_entry = pinned.get('helpers_entry_sha256')
    actual_entry = (runtime.get('artifact_binding') or {}).get('entry_sha256')
    if not declared_entry:
        raise KeccakTraceError('policy has no pinned_runtime.helpers_entry_sha256')
    if declared_entry != actual_entry:
        raise KeccakTraceError(
            'policy helpers_entry_sha256 does not match actual runtime binding: '
            f'{declared_entry!r} != {actual_entry!r}')
    declared_jar = pinned.get('jar_sha256')
    actual_jar = (runtime.get('artifact_binding') or {}).get('jar_sha256')
    if declared_jar != actual_jar:
        raise KeccakTraceError(
            'policy jar_sha256 does not match actual runtime binding: '
            f'{declared_jar!r} != {actual_jar!r}')
    return {'declared_helpers_entry_sha256': declared_entry,
            'actual_helpers_entry_sha256': actual_entry,
            'declared_jar_sha256': declared_jar,
            'actual_jar_sha256': actual_jar,
            'matches': True}



# --------------------------------------------------------------------------- #
# actual tables / compiled oracle KATs
# --------------------------------------------------------------------------- #
def _table_probe(work: Path, classpath: Path, jar: Path, java_home: Path) -> dict:
    folder = work / 'table-adapter'
    folder.mkdir(parents=True, exist_ok=True)
    source = folder / 'TableProbe.java'
    source.write_text('''import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default;
public final class TableProbe {
  public static void main(String[] args) {
    int[] offsets = __default.NewOffsets();
    int[] sources = __default.NewSources();
    System.out.print("offsets");
    for (int v : offsets) System.out.print(" " + v);
    System.out.println();
    System.out.print("sources");
    for (int v : sources) System.out.print(" " + v);
    System.out.println();
  }
}
''')
    classes = folder / 'classes'
    classes.mkdir(exist_ok=True)
    cp = f'{classpath}{os.pathsep}{jar}'
    compile_cmd = [java_home / 'bin/javac', '-cp', cp, '-d', classes, source]
    compiled = _run(compile_cmd, timeout=300)
    _write_log(folder / 'javac.log', compiled)
    if compiled['returncode']:
        raise KeccakTraceError('table adapter compile failed: ' + compiled['text'][:500])
    run_cmd = [java_home / 'bin/java', '-cp', f'{classes}{os.pathsep}{cp}', 'TableProbe']
    ran = _run(run_cmd, timeout=300)
    _write_log(folder / 'java.log', ran)
    if ran['returncode']:
        raise KeccakTraceError('table adapter run failed: ' + ran['text'][:500])
    tables = {}
    for line in ran['stdout'].splitlines():
        parts = line.split()
        if parts and parts[0] in ('offsets', 'sources'):
            tables[parts[0]] = [int(x) for x in parts[1:]]
    if len(tables.get('offsets', [])) != 25 or len(tables.get('sources', [])) != 25:
        raise KeccakTraceError('actual constructor adapter did not return two 25-entry tables')
    return {'tables': tables, 'source': str(source), 'source_sha256': sha(source),
            'compile_command': compiled['command'], 'compile_log_sha256': sha(folder / 'javac.log'),
            'run_command': ran['command'], 'run_log_sha256': sha(folder / 'java.log'),
            'offsets_sha256': _json_sha(tables['offsets']),
            'sources_sha256': _json_sha(tables['sources'])}


def _word_div(a: int, b: int) -> int:
    def signed(v: int) -> int:
        v &= MASK64
        return v - TWO64 if v >= TWO63 else v
    if b == 0:
        return 0
    aa, bb = signed(a), signed(b)
    mod = aa % bb
    return (aa - mod) // bb % TWO64


def _word_mod(a: int, b: int) -> int:
    def signed(v: int) -> int:
        v &= MASK64
        return v - TWO64 if v >= TWO63 else v
    if b == 0:
        return 0
    return (signed(a) % signed(b)) % TWO64


def _signum_word(a: int) -> int:
    x = a & MASK64
    if x >= TWO63:
        x -= TWO64
    return (-1 if x < 0 else (0 if x == 0 else 1)) % TWO64


def _rotate_word(word: int, n: int) -> int:
    word &= MASK64
    n %= 64
    if n == 0:
        return word
    return ((word << n) & MASK64) | (word >> (64 - n))


def _public_kats() -> list[tuple[str, tuple[int, ...], int]]:
    out = []
    for i in range(25):
        out.append(('div', (i,), i // 5))
        out.append(('mod', (i,), i % 5))
    words = (0x0123456789ABCDEF, 0xFEDCBA9876543210)
    for wi, word in enumerate(words):
        for n in range(64):
            out.append(('rot', (wi, n), _rotate_word(word, n)))
    for n in range(64):
        out.append(('signum', (n,), 0 if n == 0 else 1))
    out.append(('tointbigzero', (), 0))
    return out


def _oracle_probe_source(word_arithmetic: Path) -> str:
    lines = [
        '// Generated by formal/timing/keccak_traces.py -- KAT only, not a proof.',
        'include "%s"' % Path(word_arithmetic).resolve().as_posix(),
        'module OracleKAT {',
        '  import opened SecretTrace',
        '  import opened WordArithmetic',
        '  method Main() {',
    ]
    for i in range(25):
        lines.append('    print "div %d ", (WordDivision(ToWord(%d), ToWord(5)) as int), "\\n";'
                     % (i, i))
        lines.append('    print "mod %d ", (WordModulus(ToWord(%d), ToWord(5)) as int), "\\n";'
                     % (i, i))
    words = (0x0123456789ABCDEF, 0xFEDCBA9876543210)
    for wi, word in enumerate(words):
        for n in range(64):
            lines.append('    print "rot %d %d ", (RotateWord(ToWord(%d), %d) as int), "\\n";'
                         % (wi, n, word, n))
    for n in range(64):
        lines.append('    print "signum %d ", (SignumWord(ToWord(%d)) as int), "\\n";' % (n, n))
    lines.append('    print "tointbigzero ", (ToIntBigIntegerWord(ToWord(0)) as int), "\\n";')
    lines += ['  }', '}', '']
    return '\n'.join(lines)


def _compiled_oracle_kats(work: Path, dafny: Path, solver: Path) -> dict:
    folder = work / 'oracle-kat'
    folder.mkdir(parents=True, exist_ok=True)
    probe = folder / 'OracleProbe.dfy'
    probe.write_text(_oracle_probe_source(HERE / 'WordArithmetic.dfy'))
    record = _run([dafny, 'run', probe, '--solver-path', solver, *BUDGET], timeout=PROOF_TIMEOUT)
    _write_log(folder / 'oracle-kat.log', record)
    if record['returncode']:
        raise KeccakTraceError('compiled Dafny oracle KAT failed: ' + record['text'][:500])
    actual = []
    for line in record['stdout'].splitlines():
        parts = line.split()
        if not parts or parts[0] not in ('div', 'mod', 'rot', 'signum', 'tointbigzero'):
            continue
        key = parts[0]
        values = [int(x) for x in parts[1:]]
        if key in ('tointbigzero',):
            actual.append((key, (), values[0]))
        elif key == 'signum':
            actual.append((key, (values[0],), values[1]))
        elif key in ('div', 'mod'):
            actual.append((key, (values[0],), values[1]))
        elif key == 'rot':
            actual.append((key, (values[0], values[1]), values[2]))
    expected = _public_kats()
    if actual != expected:
        for index, (got, want) in enumerate(zip(actual, expected)):
            if got != want:
                raise KeccakTraceError(
                    f'compiled Dafny/Python oracle KAT mismatch at {index}: got {got}, want {want}')
        raise KeccakTraceError(
            'compiled Dafny/Python oracle KAT length mismatch: '
            f'{len(actual)} != {len(expected)}')
    return {'status': 'compiled-dafny-equals-python-kat',
            'cases': len(expected), 'source': str(probe), 'source_sha256': sha(probe),
            'log': str(folder / 'oracle-kat.log'), 'log_sha256': sha(folder / 'oracle-kat.log'),
            'command': record['command'], 'sample': [list(x) for x in expected[:3]]}


# --------------------------------------------------------------------------- #
# translation / oracle / certificate
# --------------------------------------------------------------------------- #
def _validate_remaining_calls(result: dict) -> dict:
    id_to_target = {value: key for key, value in result['call_targets'].items()}
    seen = {}
    for inst in result['code']:
        if inst['type'] != 'step' or inst['kind'][0] != 'call':
            continue
        target = id_to_target.get(inst['kind'][1])
        if target is None:
            raise KeccakTraceError('unclassified call target id ' + repr(inst['kind'][1]))
        if target.startswith(NATIVE_OWNER) or target in PRIVATE_TARGETS or target in REVIEWED_SHIFT_SET:
            raise KeccakTraceError('private/owned call remains: ' + target)
        if target not in ALLOWED_PUBLIC_TARGETS:
            raise KeccakTraceError('unknown public provider target: ' + target)
        if inst['kind'][3]:
            raise KeccakTraceError('public provider with heap arguments is not whitelisted: ' + target)
        secret = [a for a in inst['kind'][2]
                  if result['reg_taints'].get(a, 'sec') != 'pub']
        if secret:
            raise KeccakTraceError(
                'public provider receives secret scalar argument(s) '
                f'{secret} for {target}')
        expected_arity = SEMANTIC_TARGETS[target][1]
        actual_arity = len(inst['kind'][2])
        if actual_arity != expected_arity:
            raise KeccakTraceError(
                f'public provider arity mismatch for {target}: '
                f'expected {expected_arity}, got {actual_arity}')
        seen[target] = seen.get(target, 0) + 1
    return seen


def _translate_root(methods: dict, policy: dict, specs: dict, key: str) -> tuple[dict, dict]:
    result = bt.translate(methods[key], policy, policy['classes'][NATIVE_OWNER])
    direct = {'instructions': len(result['code']), 'registers': result['registers'],
              'call_targets': dict(result['call_targets']), 'roles': dict(result['roles']),
              'audit_failures': bt.audit_certificate(result)}
    result = comp.inline_owned_callees(copy.deepcopy(result), specs, policy)
    result['call_targets'] = comp.active_targets(result)
    audit = bt.audit_certificate(result)
    if audit:
        raise KeccakTraceError(f'{key}: composed audit failed: {audit[:3]}')
    _validate_remaining_calls(result)
    return result, direct


def _target_map(result: dict) -> dict[str, int]:
    return dict(result['call_targets'])


def _oracle_source(module: str, target_ids: dict[str, int]) -> str:
    present = [target for target in target_ids if target in SEMANTIC_TARGETS]
    unknown = sorted(set(target_ids) - ALLOWED_PUBLIC_TARGETS)
    if unknown:
        raise KeccakTraceError(f'{module}: unknown public targets {unknown}')
    lines = ['// Generated by formal/timing/keccak_traces.py -- do not edit.',
             'include "%s"' % PUBLIC_LAYER.as_posix(),
             'module %s {' % module,
             '  import opened SecretTrace',
             '  import opened PublicProvider',
             '  import opened PublicProviderPublic',
             '  import opened WordArithmetic', '']
    for target in sorted(present):
        const_name, _, _ = SEMANTIC_TARGETS[target]
        lines.append(f'  const {const_name}: nat := {target_ids[target]}')
    ids_expr = ', '.join(str(target_ids[target]) for target in sorted(present))
    arity_entries = ', '.join(f'{target_ids[target]} := {SEMANTIC_TARGETS[target][1]}'
                              for target in sorted(present))
    lines.append(f'  const KNOWN_PUBLIC_IDS: set<nat> := {{{ids_expr}}}')
    lines.append(f'  const KNOWN_PUBLIC_ARITY: map<nat, nat> := map[{arity_entries}]')
    lines.append('')
    lines.append('  // Total, defined fallback for unknown targets.  CallsOnly proves every')
    lines.append('  // call instruction targets KNOWN_PUBLIC_IDS with its exact arity, so this')
    lines.append('  // branch is unreachable for concrete calls; not partial/assert-false.')
    lines.append('  function FallbackOracle(target: nat, publicArgs: seq<Arg>): bv64 { 0 }')
    lines.append('')
    lines.append('  function PublicOracle(target: nat, publicArgs: seq<Arg>): bv64 {')
    if not present:
        lines.append('    FallbackOracle(target, publicArgs)')
    else:
        for index, target in enumerate(sorted(present)):
            const_name, arity, expr = SEMANTIC_TARGETS[target]
            lines.append(('    if ' if index == 0 else '    else if ')
                         + f'target == {const_name} && |publicArgs| == {arity} then')
            lines.append('      ' + expr)
        lines.append('    else')
        lines.append('      FallbackOracle(target, publicArgs)')
    lines += ['  }', '', '  lemma TargetBinding()']
    for target in sorted(present):
        const_name, arity, _ = SEMANTIC_TARGETS[target]
        lines.append(f'    ensures {const_name} == {target_ids[target]}')
        lines.append(f'    ensures KNOWN_PUBLIC_ARITY[{const_name}] == {arity}')
    if present:
        set_expr = '{' + ', '.join(SEMANTIC_TARGETS[t][0] for t in sorted(present)) + '}'
        map_expr = 'map[' + ', '.join(
            f'{SEMANTIC_TARGETS[t][0]} := {SEMANTIC_TARGETS[t][1]}' for t in sorted(present)) + ']'
        lines.append(f'    ensures KNOWN_PUBLIC_IDS == {set_expr}')
        lines.append(f'    ensures KNOWN_PUBLIC_ARITY == {map_expr}')
        lines.append('    ensures KNOWN_PUBLIC_IDS == KNOWN_PUBLIC_ARITY.Keys')
    else:
        lines.append('    ensures KNOWN_PUBLIC_IDS == {}')
        lines.append('    ensures KNOWN_PUBLIC_ARITY == map[]')
        lines.append('    ensures KNOWN_PUBLIC_IDS == KNOWN_PUBLIC_ARITY.Keys')
    lines += ['  {}', '}', '']
    return '\n'.join(lines)


def _public_chunk_lemmas(result: dict) -> str:
    n = len(result['code'])
    chunks = [list(range(i, min(i + 32, n))) for i in range(0, n, 32)]
    out = []
    for ci, indices in enumerate(chunks):
        inner = '\n'.join('        } else if j == %d {' % i for i in range(1, len(indices)))
        out.append(f'''  lemma PublicChunk{ci}()
    ensures forall j :: 0 <= j < |Layout().chunks[{ci}]| ==>
      PublicProviderInsn(Layout(), KNOWN_PUBLIC_ARITY, Layout().chunks[{ci}][j])
  {{
    var p := Layout();
    assert |p.chunks| == {len(chunks)};
    assert |p.chunks[{ci}]| == {len(indices)};
    forall j | 0 <= j < |p.chunks[{ci}]|
      ensures PublicProviderInsn(p, KNOWN_PUBLIC_ARITY, p.chunks[{ci}][j])
    {{
      if j == 0 {{
{inner}
      }} else {{
        assert false;
      }}
    }}
  }}''')
    calls = '\n'.join(f'    PublicChunk{i}();' for i in range(len(chunks)))
    if len(chunks) == 1:
        split = '      if c == 0 { PublicChunk0(); } else { assert false; }'
    else:
        split = '\n'.join(['      if c == 0 { PublicChunk0(); }'] +
                          [f'      else if c == {i} {{ PublicChunk{i}(); }}'
                           for i in range(1, len(chunks))] + ['      else { assert false; }'])
    out.append(f'''  lemma PublicWellFormed()
    ensures PublicOnly(Layout(), KNOWN_PUBLIC_ARITY)
  {{
    var p := Layout();
    assert p.instructions == {n};
    assert |p.chunks| == {len(chunks)};
{calls}
    forall c | 0 <= c < |p.chunks|
      ensures forall i :: 0 <= i < |p.chunks[c]| ==>
        PublicProviderInsn(p, KNOWN_PUBLIC_ARITY, p.chunks[c][i])
    {{
{split}
    }}
    assert CallsOnly(p, KNOWN_PUBLIC_ARITY);
  }}''')
    return '\n\n'.join(out)


def _emit_root_certificate(work: Path, name: str, result: dict,
                           target_ids: dict[str, int]) -> dict:
    module = 'Oracle_' + name
    oracle = work / 'oracles' / (module + '.dfy')
    oracle.parent.mkdir(parents=True, exist_ok=True)
    oracle.write_text(_oracle_source(module, target_ids))
    source = compact.certificate_module(name + 'Provider', result)
    source, count = re.subn(r'^include ".*"$', 'include "%s"' % oracle.resolve().as_posix(),
                            source, count=1, flags=re.M)
    if count != 1:
        raise KeccakTraceError('compact certificate has no include line')
    source = source.replace('  import opened SecretTrace\n',
                            '  import opened SecretTrace\n'
                            '  import opened PublicProvider\n'
                            '  import opened PublicProviderPublic\n'
                            '  import opened WordArithmetic\n'
                            '  import opened %s\n' % module, 1)
    if 'ensures Exec(P(), 0, s, fuel).1 == Exec(P(), 0, t, fuel).1' in source:
        source = source.replace(
            'ensures Exec(P(), 0, s, fuel).1 == Exec(P(), 0, t, fuel).1',
            'ensures ExecP(P(), 0, s, fuel, PublicOracle).1 == '
            'ExecP(P(), 0, t, fuel, PublicOracle).1')
    elif 'ensures ExecP(' not in source:
        raise KeccakTraceError('compact certificate has no recognisable TwoRun ensures')
    if 'ExecTwoRun(P(), 0, s, t, fuel);' in source:
        source = source.replace('ExecTwoRun(P(), 0, s, t, fuel);',
                                'ExecPTwoRun(P(), 0, s, t, fuel, PublicOracle);')
    elif 'ExecPTwoRun(P(), 0, s, t, fuel,' not in source:
        raise KeccakTraceError('compact certificate has no recognisable TwoRun body')
    n = len(result['code'])
    old_p = f'''  opaque function P(): Program
    ensures Structure(P())
    ensures P().instructions == {n}
  {{
    WellFormed();
    Layout()
  }}'''
    if old_p not in source:
        raise KeccakTraceError('compact certificate has unexpected P body')
    new_p = f'''  opaque function P(): Program
    ensures Structure(P())
    ensures P().instructions == {n}
    ensures PublicOnly(P(), KNOWN_PUBLIC_ARITY)
  {{
    WellFormed();
    PublicWellFormed();
    Layout()
  }}

  lemma PublicCalls()
    ensures PublicOnly(P(), KNOWN_PUBLIC_ARITY)
  {{
    var p := P();
  }}

  lemma EveryCallTargetKnown(c: nat, i: nat)
    requires 0 <= c < |P().chunks| && 0 <= i < |P().chunks[c]|
    requires P().chunks[c][i].IStep? && P().chunks[c][i].kind.Call?
    ensures P().chunks[c][i].kind.target in KNOWN_PUBLIC_IDS
    ensures P().chunks[c][i].kind.target in KNOWN_PUBLIC_ARITY
  {{
    PublicCalls();
    var inst := P().chunks[c][i];
    assert InstrInProgram(P(), inst);
    CallsOnlyTarget(P(), KNOWN_PUBLIC_ARITY, inst);
    assert inst.kind.target in KNOWN_PUBLIC_IDS;
  }}

  lemma EveryCallArityMatches(c: nat, i: nat)
    requires 0 <= c < |P().chunks| && 0 <= i < |P().chunks[c]|
    requires P().chunks[c][i].IStep? && P().chunks[c][i].kind.Call?
    ensures |P().chunks[c][i].kind.args| ==
            KNOWN_PUBLIC_ARITY[P().chunks[c][i].kind.target]
  {{
    PublicCalls();
    var inst := P().chunks[c][i];
    assert InstrInProgram(P(), inst);
    CallsOnlyArity(P(), KNOWN_PUBLIC_ARITY, inst);
  }}

  lemma DefaultOracleMatches(s: State, fuel: nat)
    requires Shape(P(), s)
    ensures ExecP(P(), 0, s, fuel, DefaultOracle) == Exec(P(), 0, s, fuel)
  {{
    ExecPDefault(P(), 0, s, fuel);
  }}'''
    source = source.replace(old_p, new_p, 1)
    marker = '  opaque function P(): Program'
    if marker not in source:
        raise KeccakTraceError('compact certificate is missing P marker')
    source = source.replace(marker, _public_chunk_lemmas(result) + '\n\n' + marker, 1)
    cert = work / 'certs' / (name + 'Provider.dfy')
    cert.parent.mkdir(parents=True, exist_ok=True)
    cert.write_text(source)
    return {'certificate': str(cert), 'certificate_sha256': sha(cert),
            'oracle': str(oracle), 'oracle_sha256': sha(oracle),
            'oracle_module': module, 'oracle_function': 'PublicOracle',
            'known_public_ids': sorted(target_ids.values()),
            'known_public_arity': {str(target_ids[t]): SEMANTIC_TARGETS[t][1]
                                   for t in sorted(target_ids) if t in SEMANTIC_TARGETS},
            'known_public_targets': sorted(target_ids),
            'unknown_oracle_case': 'FallbackOracle (total, defined 0; proved unreachable by CallsOnly/arity)',
            'public_only_postcondition': 'PublicOnly(P(), KNOWN_PUBLIC_ARITY)',
            'every_call_target_known_lemma': 'EveryCallTargetKnown',
            'every_call_arity_matches_lemma': 'EveryCallArityMatches',
            'default_oracle_matches_lemma': 'DefaultOracleMatches'}



# --------------------------------------------------------------------------- #
# finite controls
# --------------------------------------------------------------------------- #
def _public_oracle(name: str, public_args: list[tuple[str, int]]) -> int:
    values = [value for _, value in public_args]
    if name == 'dafny/DafnyEuclidean.EuclideanDivision:(II)I' and len(values) >= 2:
        return _word_div(values[0], values[1])
    if name == 'dafny/DafnyEuclidean.EuclideanModulus:(II)I' and len(values) >= 2:
        return _word_mod(values[0], values[1])
    if name == 'dafny/Helpers.toInt:(I)I' and len(values) >= 1:
        return values[0] & MASK64
    if name == 'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I' and len(values) >= 1:
        return 0 if values[0] == 0 else values[0] & MASK64
    if name == 'java/lang/Integer.signum:(I)I' and len(values) >= 1:
        return _signum_word(values[0])
    raise KeccakTraceError('finite control: unbound public target ' + name)


class OracleView(trace_exec.ProgramView):
    """Frozen ProgramView plus the public oracle; no global monkeypatch."""

    def __init__(self, result: dict):
        super().__init__(result)
        self.id_to_name = {value: key for key, value in result['call_targets'].items()}

    def provider_result(self, target, regs, args):
        name = self.id_to_name.get(target)
        if name is None:
            raise KeccakTraceError('finite control: unknown call target id ' + repr(target))
        return _public_oracle(name, self.public_args(regs, args))


def _parameter_index(role: str) -> int | None:
    if '#p' not in role:
        return None
    return int(role.rsplit('#p', 1)[1])


def _seed_states(name: str, result: dict, tables: dict, *, vary_inputs: bool = True) -> dict:
    view = OracleView(result)
    roles = sorted(result['roles'])
    shapes = ROOT_SHAPES[name]
    lengths = []
    for role in roles:
        p = _parameter_index(role)
        if p is None or p >= len(shapes):
            raise KeccakTraceError(f'{name}: unexpected role {role}')
        lengths.append(shapes[p])
    ordinals = {r: i for i, r in enumerate(result.get('param_regs') or [])
                if view.reg_taint(r) == 'sec'}
    regs_s = [1 if view.reg_taint(r) == 'pub'
              else (11 + 3 * ordinals[r] if r in ordinals else 0)
              for r in range(result['registers'])]
    regs_t = [1 if view.reg_taint(r) == 'pub'
              else (13 + 5 * ordinals[r] if r in ordinals else 0)
              for r in range(result['registers'])]
    heap_s, heap_t = [], []
    for role, length in zip(roles, lengths):
        p = _parameter_index(role)
        table_name = PUBLIC_TABLE_ROLE.get(name, {}).get(p)
        if result['roles'][role] == 'pub':
            if table_name is None:
                raise KeccakTraceError(f'{name}: public role {role} has no actual table')
            values = list(tables[table_name])
            if len(values) != length:
                raise KeccakTraceError(f'{name}: table length mismatch for {role}')
            heap_s.append(values)
            heap_t.append(list(values))
        else:
            heap_s.append([1 + i for i in range(length)])
            heap_t.append([101 + i for i in range(length)] if vary_inputs
                          else [1 + i for i in range(length)])
    if not vary_inputs:
        regs_t = list(regs_s)
    return {'view': view, 'roles': roles, 'lengths': lengths, 'ordinals': ordinals,
            'regs_s': regs_s, 'regs_t': regs_t, 'heap_s': heap_s, 'heap_t': heap_t}


def _state_hash(regs: list[int], heap: list[list[int]]) -> str:
    return _json_sha({'regs': [v & MASK64 for v in regs],
                      'heap': [[v & MASK64 for v in role] for role in heap]})


def control(name: str, result: dict, tables: dict, *, vary_inputs: bool = True,
            step_cap: int = STEP_CAP) -> dict:
    seeded = _seed_states(name, result, tables, vary_inputs=vary_inputs)
    view, roles, lengths = seeded['view'], seeded['roles'], seeded['lengths']
    start = max(32, len(result['code']) + 8)
    run_s = trace_exec.run_to_completion(view, seeded['regs_s'], seeded['heap_s'],
                                         start, step_cap)
    if run_s is None:
        return {'status': 'FAILED', 'reason': 'no finite execution (s)'}
    run_t = trace_exec.run_to_completion(view, seeded['regs_t'], seeded['heap_t'],
                                         run_s['fuel_used'], run_s['fuel_used'])
    if run_t is None:
        return {'status': 'FAILED', 'reason': 'no finite execution (t)'}
    public = [r for r in range(result['registers']) if view.reg_taint(r) == 'pub']
    differing = trace_exec.differing_registers(view, run_s['regs'], run_t['regs'])
    heap_output_differs = [role for i, role in enumerate(roles)
                           if run_s['heap'][i] != run_t['heap'][i]]
    input_differs = [role for i, role in enumerate(roles)
                     if seeded['heap_s'][i] != seeded['heap_t'][i]]
    public_heap_equal = all(run_s['heap'][i] == run_t['heap'][i]
                            for i, role in enumerate(roles)
                            if result['roles'][role] == 'pub')
    provider_args: dict[str, set[tuple[int, ...]]] = {}
    for event in run_s['events']:
        if event[0] == 'call':
            target_id, public_args = event[2]
            target_name = view.id_to_name[target_id]
            provider_args.setdefault(target_name, set()).add(
                tuple(value for _, value in public_args))
    top_guards = {'total': 0, 'taken': 0}
    for event in run_s['events']:
        if event[0] == 'guard' and result['sites'][event[1]]['method'] == name:
            top_guards['total'] += 1
            top_guards['taken'] += 1 if event[2] else 0
    if top_guards['total'] == 25 and (top_guards['taken'] == 24
                                      or top_guards['total'] - top_guards['taken'] == 24):
        rounds = 24
    else:
        rounds = None
    record = {
        'status': 'pending',
        'role_lengths': dict(zip(roles, lengths)),
        'parameter_registers': sorted(seeded['ordinals']),
        'terminal': {'s': run_s['terminal'], 't': run_t['terminal']},
        'fault_events': {side: [e for e in run['events'] if e[0] in ('fault', 'fault-ip')]
                         for side, run in (('s', run_s), ('t', run_t))},
        'steps': {'s': run_s['steps'], 't': run_t['steps']},
        'fuel': run_s['fuel_used'],
        'event_counts': {'s': run_s['counts'], 't': run_t['counts']},
        'events_sha256': {'s': _json_sha(run_s['events']), 't': _json_sha(run_t['events'])},
        'initial_state_sha256': {'s': _state_hash(seeded['regs_s'], seeded['heap_s']),
                                 't': _state_hash(seeded['regs_t'], seeded['heap_t'])},
        'final_state_sha256': {'s': _state_hash(run_s['regs'], run_s['heap']),
                               't': _state_hash(run_t['regs'], run_t['heap'])},
        'trace_equal': run_s['events'] == run_t['events'],
        'public_registers_equal': all(run_s['regs'][r] == run_t['regs'][r] for r in public),
        'differing_registers': differing,
        'heap_shape': {role: [len(run_s['heap'][i]), len(run_t['heap'][i])]
                       for i, role in enumerate(roles)},
        'secret_input_roles_differ': input_differs,
        'heap_output_differs': heap_output_differs,
        'public_heap_equal': public_heap_equal,
        'provider_public_args': {target: [list(values) for values in sorted(argument_sets)]
                                 for target, argument_sets in sorted(provider_args.items())},
        'top_level_guards': top_guards,
        'rounds_executed': rounds,
    }
    checks = {
        'both_terminal_stop': record['terminal'] == {'s': 'stop', 't': 'stop'},
        'no_fault_event': not record['fault_events']['s'] and not record['fault_events']['t'],
        'trace_equal': record['trace_equal'],
        'public_registers_equal': record['public_registers_equal'],
        'public_heap_equal': record['public_heap_equal'],
        'role_lengths_honest': [pair[0] for pair in record['heap_shape'].values()] == lengths,
        'heap_shape_preserved': all(pair == [length, length]
                                    for pair, length in zip(record['heap_shape'].values(),
                                                            lengths)),
    }
    if any(result['roles'][role] == 'sec' for role in roles):
        checks['private_heap_output_live'] = bool(heap_output_differs)
    if name == 'PermuteScratch':
        private_inputs = [role for role in roles
                          if result['roles'][role] == 'sec'
                          and _parameter_index(role) in (0, 1)]
        checks['both_private_input_roles_vary'] = all(role in input_differs
                                                       for role in private_inputs)
        checks['both_private_outputs_live'] = all(role in heap_output_differs
                                                   for role in private_inputs)
        checks['24_rounds_executed'] = rounds == 24
        big_args = record['provider_public_args'].get(
            'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I', [])
        checks['to_int_big_integer_only_zero_argument'] = (
            bool(big_args) and all(args == [0] for args in big_args))
    record['checks'] = checks
    record['status'] = 'ok' if all(checks.values()) else 'FAILED'
    if record['status'] != 'ok':
        record['reason'] = ', '.join(key for key, value in checks.items() if not value)
    return record


def validate_control(record: dict, *, final: bool = False) -> None:
    if record.get('status') != 'ok':
        raise KeccakTraceError('control failed: ' + record.get('reason', 'not ok'))
    if record.get('terminal') != {'s': 'stop', 't': 'stop'}:
        raise KeccakTraceError('control did not terminate at stop/stop')
    if record.get('fault_events', {}).get('s') or record.get('fault_events', {}).get('t'):
        raise KeccakTraceError('control contains a fault event')
    if not all(record.get('checks', {}).values()):
        raise KeccakTraceError('control checks failed')
    if final:
        for key in ('both_private_input_roles_vary', 'both_private_outputs_live',
                    '24_rounds_executed', 'to_int_big_integer_only_zero_argument',
                    'public_heap_equal'):
            if record['checks'].get(key) is not True:
                raise KeccakTraceError('final control missing ' + key)
        if record.get('rounds_executed') != 24:
            raise KeccakTraceError('final control did not execute 24 rounds')


# --------------------------------------------------------------------------- #
# mutants
# --------------------------------------------------------------------------- #
def _structure_mutants(work: Path, final_result: dict, final_ids: dict[str, int],
                       dafny: Path, solver: Path) -> dict:
    out = {}
    branch_result = copy.deepcopy(final_result)
    branch = next(inst for inst in branch_result['code']
                  if inst['type'] == 'branch'
                  and branch_result['reg_taints'].get(inst['cond'], 'sec') == 'pub')
    branch_result['reg_taints'][branch['cond']] = 'sec'
    emitted = _emit_root_certificate(work, 'Mutant_Branch', branch_result, final_ids)
    cert = Path(emitted['certificate'])
    record = _run([dafny, 'verify', cert, '--solver-path', solver, *BUDGET])
    log = work / 'mutants' / 'Mutant_Branch.log'
    _write_log(log, record)
    out['branch'] = {
        'mutation': {'kind': 'branch_condition_taint',
                     'site': branch.get('site'), 'register': branch['cond']},
        'certificate': str(cert), 'certificate_sha256': sha(cert),
        'proof': _require_structure_proof_failure(
            record, log, 'branch mutant',
            [r'Mutant_BranchProvider\.dfy\(', r'ensures InstrOK\(',
             r'SecretTrace\.dfy\(227,', r'RegTaint\(p, cond\) == Pub'])}
    index_result = copy.deepcopy(final_result)
    inst = next(item for item in index_result['code']
                if item['type'] == 'step' and item['kind'][0] in ('load', 'store')
                and index_result['reg_taints'].get(item['kind'][2], 'sec') == 'pub')
    index_reg = inst['kind'][2]
    index_result['reg_taints'][index_reg] = 'sec'
    emitted = _emit_root_certificate(work, 'Mutant_Index', index_result, final_ids)
    cert = Path(emitted['certificate'])
    record = _run([dafny, 'verify', cert, '--solver-path', solver, *BUDGET])
    log = work / 'mutants' / 'Mutant_Index.log'
    _write_log(log, record)
    out['index'] = {
        'mutation': {'kind': 'load_store_index_taint',
                     'site': inst.get('site'), 'register': index_reg,
                     'operation': inst['kind'][0]},
        'certificate': str(cert), 'certificate_sha256': sha(cert),
        'proof': _require_structure_proof_failure(
            record, log, 'index mutant',
            [r'Mutant_IndexProvider\.dfy\(', r'ensures InstrOK\(',
             r'SecretTrace\.dfy\(224,', r'StepOK\(p, dst, kind\)'])}
    return out


def _synthetic_public_call_program(target_name: str, target_id: int, arity: int, *,
                                   secret_arg_index: int | None = None,
                                   include_heap: bool = False,
                                   arg_count: int | None = None) -> dict:
    count = arity if arg_count is None else arg_count
    dst = count
    registers = max(count + 1, 1)
    reg_taints = {i: 'pub' for i in range(count)}
    reg_taints[dst] = 'sec' if secret_arg_index is not None or include_heap else 'pub'
    if secret_arg_index is not None:
        reg_taints[secret_arg_index] = 'sec'
    roles = {'p': 'sec'} if include_heap else {}
    heap_args = ['p'] if include_heap else []
    return {
        'registers': registers, 'inputs': count,
        'reg_taints': reg_taints, 'roles': roles,
        'call_targets': {target_name: target_id},
        'code': [
            {'type': 'step', 'site': 0, 'dst': dst,
             'kind': ('call', target_id, list(range(count)), heap_args, False),
             'ann': reg_taints[dst]},
            {'type': 'stop', 'ret': None}],
        'param_regs': [],
    }


def _public_mutant_flags(proof: dict, label: str) -> dict:
    """Derive Structure/PublicOnly flags from the actual proof record."""
    if proof.get('status') != 'proof_failed':
        raise KeccakTraceError(f'{label}: public mutant proof is not proof_failed')
    if proof.get('contains_structure_error'):
        raise KeccakTraceError(f'{label}: public mutant also broke Structure')
    return {'structure_valid': True, 'public_only_false': True,
            'derived_from_proof': True,
            'proof_status': proof.get('status'),
            'contains_structure_error': proof.get('contains_structure_error')}


def _public_call_mutants(work: Path, final_result: dict, final_ids: dict[str, int],
                         dafny: Path, solver: Path) -> dict:
    known_target = next(target for target in sorted(final_ids)
                        if target in SEMANTIC_TARGETS and SEMANTIC_TARGETS[target][1] >= 2)
    known_id = final_ids[known_target]
    arity = SEMANTIC_TARGETS[known_target][1]
    out = {}
    cases = {
        'private_argument': (
            _synthetic_public_call_program(known_target, known_id, arity,
                                           secret_arg_index=0),
            [r'Mutant_PrivateArgProvider\.dfy\(', r'PublicProviderInsn\(',
             r'PublicProviderPublic\.dfy\(28,', r'forall k'],
            {'kind': 'one_secret_scalar_argument', 'arity': arity}),
        'unknown_target': (
            _synthetic_public_call_program('java/lang/Unknown:(I)I',
                                           max(final_ids.values()) + 1000, 1),
            [r'Mutant_UnknownTargetProvider\.dfy\(', r'PublicProviderInsn\(',
             r'PublicProviderPublic\.dfy\(26,', r'target in arity'],
            {'kind': 'unknown_target_all_public', 'arity': 1}),
        'private_heap_argument': (
            _synthetic_public_call_program(known_target, known_id, arity,
                                           include_heap=True),
            [r'Mutant_PrivateHeapProvider\.dfy\(', r'PublicProviderInsn\(',
             r'PublicProviderPublic\.dfy\(27,', r'\|heapArgs\| == 0'],
            {'kind': 'private_heap_argument', 'arity': arity}),
        'wrong_arity': (
            _synthetic_public_call_program(known_target, known_id, arity,
                                           arg_count=max(1, arity - 1)),
            [r'Mutant_WrongArityProvider\.dfy\(', r'PublicProviderInsn\(',
             r'PublicProviderPublic\.dfy\(29,', r'\|args\| == arity\[target\]'],
            {'kind': 'known_target_wrong_arity', 'expected_arity': arity,
             'actual_arity': max(1, arity - 1)}),
    }
    titles = {'private_argument': 'Mutant_PrivateArg',
              'unknown_target': 'Mutant_UnknownTarget',
              'private_heap_argument': 'Mutant_PrivateHeap',
              'wrong_arity': 'Mutant_WrongArity'}
    for label, (result, patterns, mutation) in cases.items():
        name = titles[label]
        emitted = _emit_root_certificate(work, name, result, final_ids)
        cert = Path(emitted['certificate'])
        record = _run([dafny, 'verify', cert, '--solver-path', solver, *BUDGET])
        log = work / 'mutants' / (name + '.log')
        _write_log(log, record)
        proof = _require_public_call_proof_failure(record, log, label, patterns)
        flags = _public_mutant_flags(proof, label)
        out[label] = {
            'certificate': str(cert), 'certificate_sha256': sha(cert),
            'mutation': mutation,
            **flags,
            'proof': proof,
        }
    return out



def _private_count_negatives(runtime_evidence: dict) -> dict:
    out = {}
    for key in ('left', 'right'):
        record = runtime_evidence.get('negative_controls', {}).get(key)
        if not isinstance(record, dict) or 'dafny' not in record:
            raise KeccakTraceError('runtime replay has no private-count negative for ' + key)
        proof = record['dafny']
        if proof.get('status') != 'proof_failed':
            raise KeccakTraceError(f'{key}: runtime private-count proof did not fail: {proof}')
        log_path = Path(proof.get('log', ''))
        if not log_path.is_file():
            raise KeccakTraceError(f'{key}: runtime private-count log missing')
        text = log_path.read_text()
        if not re.search(r'InstrOK|Structure|possible violation of postcondition', text):
            raise KeccakTraceError(f'{key}: private-count failure is not a Structure obligation')
        if re.search(r'out of resource|timed out|resolution/type errors|parse errors', text, re.I):
            raise KeccakTraceError(f'{key}: private-count failure was not a normal proof failure')
        out[key] = {'mutation': 'public shift count declared secret',
                    'proof': proof, 'log_sha256': sha(log_path),
                    'obligation_named': True}
    return out


def _binding_controls(javap: Path, classpath: Path, policy: dict) -> dict:
    """Actual load-path negatives: wrong class/target/descriptor/shape reject."""
    out = {}
    base = next(entry for entry in _make_entries(policy) if entry['name'] == 'Rotate')

    def attempt(entries: list[dict]) -> dict:
        try:
            comp.load_callee_specs(policy, javap, classpath, entries)
        except Exception as error:  # noqa: BLE001 - a rejection is the control
            return {'rejected': True, 'exception': type(error).__name__, 'message': str(error)}
        return {'rejected': False, 'exception': None, 'message': 'accepted'}

    wrong_class = copy.deepcopy(base)
    wrong_class['class'] = NATIVE_CLASS + 'Wrong'
    out['wrong_class'] = attempt([wrong_class])
    wrong_desc = copy.deepcopy(base)
    wrong_desc['descriptor'] = '(JI)I'
    out['wrong_descriptor'] = attempt([wrong_desc])
    wrong_name = copy.deepcopy(base)
    wrong_name['name'] = 'Rotat'
    out['wrong_target_name'] = attempt([wrong_name])
    wrong_shape = copy.deepcopy(next(entry for entry in _make_entries(policy)
                                     if entry['name'] == 'Chi'))
    wrong_shape['contract']['heap'] = 'none'
    out['wrong_shape_contract'] = attempt([wrong_shape])
    wrong_roles = copy.deepcopy(base)
    wrong_roles['contract']['roles'] = {'p0': 'pub', 'p1': 'pub'}
    out['wrong_roles'] = attempt([wrong_roles])
    out['all_rejected'] = all(item['rejected'] for item in out.values())
    return out


# --------------------------------------------------------------------------- #
# official replay
# --------------------------------------------------------------------------- #
def _write_evidence(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')
    temp.replace(path)


def replay(output: Path, *, jar: Path, dafny: Path, solver: Path, java_home: Path,
           classpath: Path, policy_path: Path = HERE / 'policy.json',
           inputs_path: Path = HERE / 'inputs.json') -> dict:
    """Run the complete official Keccak trace replay.  There is no skip flag.

    The caller supplies already-validated tool/artifact paths; this function
    binds them and all loaded trusted modules/files to canonical paths and the
    canonical ``inputs.json`` pins before and after use.  It fails closed unless
    the actual reviewed left+right shift admission is already present.
    """
    output = Path(output).expanduser().resolve()
    if 'quic/target' in output.as_posix():
        raise KeccakTraceError('refusing to write evidence inside quic/target')
    output.mkdir(parents=True, exist_ok=True)
    evidence_path = output / 'keccak-traces.json'
    policy_path = _canonical(policy_path, HERE / 'policy.json', 'policy_path')
    inputs_path = _canonical(inputs_path, HERE / 'inputs.json', 'inputs_path')
    jar = Path(jar).expanduser().resolve()
    dafny = Path(dafny).expanduser().resolve()
    solver = Path(solver).expanduser().resolve()
    java_home = Path(java_home).expanduser().resolve()
    classpath = Path(classpath).expanduser().resolve()
    work = Path(tempfile.mkdtemp(prefix='keccak-traces-', dir=output))
    evidence = {
        'schema': 1, 'status': 'incomplete',
        'scope': {
            'roots': list(ROOT_KEYS),
            'excluded': ['Permute:([J)V (array-return NewOffsets/NewSources unsupported)'],
            'not_claimed': ['Sponge ownership/NI', '13-root closure', 'JVM value/timing',
                            'physical erasure', 'external expert review'],
        },
        'limits': {'budget': list(BUDGET), 'proof_timeout_seconds': PROOF_TIMEOUT,
                   'step_cap': STEP_CAP, 'no_resource_bump': True},
    }
    try:
        # 1. Admission gate happens before any path/tool is touched.
        admitted = require_reviewed_admission()
        policy = json.loads(policy_path.read_text())
        declared = (policy.get('runtime_classification') or {}).get('shift_count_public', [])
        admitted = require_reviewed_admission(declared=declared)
        try:
            bt.check_runtime_classification(policy)
        except Exception as error:  # noqa: BLE001
            raise AdmissionError('policy/extractor runtime classification drift: ' + str(error)) from error
        evidence['admission'] = admitted
        # 2. Bind all loaded modules and trusted files before using them.
        binding_before = bind_all(inputs_path, policy_path)
        native = _validate_native_identity(classpath)
        evidence['binding'] = {'before': binding_before, 'native': native,
                               'artifacts': {
                                   'jar': {'path': str(jar), 'sha256': sha(jar)},
                                   'dafny': {'path': str(dafny), 'sha256': sha(dafny)},
                                   'solver': {'path': str(solver), 'sha256': sha(solver)},
                                   'java_home': str(java_home),
                                   'classpath': str(classpath),
                               }}
        # 3. Actual runtime replay, no optional/skip modes.
        runtime = rp.replay(output / 'runtime-primitives', policy_path=policy_path,
                            inputs_path=inputs_path, extractor_path=Path(bt.__file__),
                            jar=jar, dafny=dafny, solver=solver, java_home=java_home)
        if runtime.get('status') != 'verified':
            raise KeccakTraceError('runtime_primitives.replay did not return verified')
        for key in ('left', 'right'):
            proofs = runtime['proofs'][key]
            if proofs['with_witness']['verified'] != 12 or proofs['without_witness']['verified'] != 11:
                raise KeccakTraceError('runtime primitive proof count changed for ' + key)
        helper_cp = Path(runtime['artifact_binding']['classpath'])
        helper_entry = helper_cp / HELPER_ENTRY
        if sha(helper_entry) != runtime['artifact_binding']['entry_sha256']:
            raise KeccakTraceError('runtime replay Helpers.class entry changed after replay')
        combined = work / 'classpath'
        combined.mkdir(parents=True, exist_ok=True)
        dest_helper = combined / HELPER_ENTRY
        dest_helper.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(helper_entry, dest_helper)
        dest_native = combined / (NATIVE_OWNER + '.class')
        dest_native.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(classpath / (NATIVE_OWNER + '.class'), dest_native)
        if sha(dest_helper) != runtime['artifact_binding']['entry_sha256']:
            raise KeccakTraceError('combined Helpers.class copy changed bytes')
        if sha(dest_native) != EXPECTED_NATIVE_CLASS_SHA256:
            raise KeccakTraceError('combined NativeKeccak.class copy changed bytes')
        evidence['runtime_replay'] = {
            'evidence': str(output / 'runtime-primitives' / 'runtime-primitives.json'),
            'status': runtime['status'], 'jar_sha256': runtime['artifact_binding']['jar_sha256'],
            'helpers_entry_sha256': runtime['artifact_binding']['entry_sha256'],
            'proofs': {key: {'with_witness': runtime['proofs'][key]['with_witness']['verified'],
                             'without_witness': runtime['proofs'][key]['without_witness']['verified']}
                       for key in ('left', 'right')},
            'java_adapter': runtime.get('java_adapter', {}).get('comparison'),
            'private_count': {key: runtime['negative_controls'][key]['dafny']['status']
                              for key in ('left', 'right')},
        }
        evidence['helper_entry_pin'] = _check_helper_pin(policy, runtime)
        # 4. Policy overlay and actual bytecode specs.
        policy, overlay_delta = _overlay_policy(policy)
        bt.check_runtime_classification(policy)
        evidence['overlay'] = {'delta': overlay_delta,
                               'runtime_classification_unchanged': True,
                               'no_generic_heap_exception': not bt.PUBLIC_HEAP_EXCEPTIONS,
                               'private_safe_calls': sorted(bt.PRIVATE_SAFE_RUNTIME_CALLS)}
        entries = _make_entries(policy)
        specs = comp.load_callee_specs(policy, java_home / 'bin/javap', combined, entries)
        methods = bt.disassemble(java_home / 'bin/javap', combined, NATIVE_CLASS)
        tables = _table_probe(work, classpath, jar, java_home)
        evidence['actual_tables'] = tables
        # 5. Model proofs.
        evidence['model_proofs'] = {
            'PublicProvider': _verify(HERE / 'PublicProvider.dfy',
                                      output / 'logs' / 'PublicProvider.log',
                                      dafny, solver, EXPECTED_PUBLIC_PROVIDER_CHECKS),
            'PublicProviderPublic': _verify(PUBLIC_LAYER,
                                            output / 'logs' / 'PublicProviderPublic.log',
                                            dafny, solver, EXPECTED_PUBLIC_LAYER_CHECKS),
            'WordArithmetic': _verify(HERE / 'WordArithmetic.dfy',
                                      output / 'logs' / 'WordArithmetic.log',
                                      dafny, solver, EXPECTED_WORD_ARITHMETIC_CHECKS),
        }
        # 6. Per-root composition, compact ExecP certificate, finite control.
        roots = {}
        final_result = None
        final_oracle = None
        final_module = None
        class_hashes = {NATIVE_OWNER: EXPECTED_NATIVE_CLASS_SHA256,
                        HELPER_OWNER: runtime['artifact_binding']['entry_sha256']}
        for key in ROOT_KEYS:
            name = ROOT_NAMES[key]
            result, direct = _translate_root(methods, policy, specs, key)
            ids = _target_map(result)
            _enrich_inlined(result, specs, class_hashes)
            emitted = _emit_root_certificate(work, name, result, ids)
            proof = _verify(Path(emitted['certificate']),
                            output / 'logs' / (name + 'Provider.log'),
                            dafny, solver, EXPECTED_ROOT_CHECKS[name])
            ctl = control(name, result, tables['tables'])
            validate_control(ctl, final=(name == 'PermuteScratch'))
            root = {
                'source_method': key, 'direct': direct,
                'instructions': len(result['code']), 'registers': result['registers'],
                'roles': result['roles'], 'param_regs': result.get('param_regs'),
                'call_targets': ids,
                'ir_sha256': _json_sha({'code': result['code'],
                                        'reg_taints': result['reg_taints'],
                                        'roles': result['roles'],
                                        'call_targets': ids}),
                'remaining_calls': _validate_remaining_calls(result),
                'inlined': result.get('inlined', []),
                'inlined_count': len(result.get('inlined', [])),
                'audit_failures': bt.audit_certificate(result),
                'certificate': emitted, 'proof': proof, 'control': ctl,
                'public_contract': {
                    'known_public_ids': emitted['known_public_ids'],
                    'known_public_arity': emitted['known_public_arity'],
                    'known_public_targets': emitted['known_public_targets'],
                    'unknown_oracle_case': emitted['unknown_oracle_case'],
                    'public_only_postcondition': emitted['public_only_postcondition'],
                    'every_call_target_known_lemma': emitted['every_call_target_known_lemma'],
                    'every_call_arity_matches_lemma': emitted['every_call_arity_matches_lemma'],
                    'default_oracle_matches_lemma': emitted['default_oracle_matches_lemma'],
                    'every_call_target_known_verified': proof['status'] == 'verified',
                },
            }
            roots[name] = root
            if name == 'PermuteScratch':
                final_result, final_oracle, final_module = result, Path(emitted['oracle']), emitted['oracle_module']
        evidence['roots'] = roots
        specs_after = comp.load_callee_specs(policy, java_home / 'bin/javap', combined, entries)
        body_binding_after = {}
        for name, root in roots.items():
            for entry in root['inlined']:
                target = entry['target']
                spec = specs_after.get(target)
                if spec is None:
                    raise KeccakTraceError('inlined target disappeared after roots: ' + target)
                after = _callee_body_record(spec.method, class_hashes[spec.owner])
                if (after['callee_bytecode_sha256'] != entry['callee_bytecode_sha256'] or
                        after['callee_class_sha256'] != entry['callee_class_sha256']):
                    raise KeccakTraceError('inlined callee body changed after roots: ' + target)
                body_binding_after[target] = {
                    'callee_bytecode_sha256': after['callee_bytecode_sha256'],
                    'callee_class_sha256': after['callee_class_sha256']}
        evidence['inlined_body_binding_after'] = body_binding_after
        # 7. Compiled Dafny oracle KATs.
        evidence['oracle_kats'] = _compiled_oracle_kats(work, dafny, solver)
        # 8. Negative/control mutants.
        final_ids = _target_map(final_result)
        evidence['mutants'] = _structure_mutants(work, final_result, final_ids,
                                                 dafny, solver)
        evidence['public_call_mutants'] = _public_call_mutants(
            work, final_result, final_ids, dafny, solver)
        evidence['private_count'] = _private_count_negatives(runtime)
        evidence['binding_controls'] = _binding_controls(java_home / 'bin/javap', combined, policy)
        # 9. Non-completion controls: out-of-bounds, fuel, equal-inputs skip.
        seeded = _seed_states('PermuteScratch', final_result, tables['tables'])
        view = seeded['view']
        oob_heap = [list(role) for role in seeded['heap_s']]
        oob_index = next(i for i, role in enumerate(seeded['roles'])
                         if final_result['roles'][role] == 'sec')
        oob_heap[oob_index] = oob_heap[oob_index][:24]
        oob = trace_exec.run_to_completion(view, seeded['regs_s'], oob_heap,
                                           max(32, len(final_result['code']) + 8), STEP_CAP)
        if oob is None or oob['terminal'] != 'fault':
            raise KeccakTraceError('out-of-bounds control did not fault')
        fuel = trace_exec.execute(view, seeded['regs_s'], seeded['heap_s'], 32)
        if fuel['terminal'] != 'fuel':
            raise KeccakTraceError('low-fuel control was not reported as fuel-truncated')
        equal_inputs = control('PermuteScratch', final_result, tables['tables'],
                               vary_inputs=False)
        if equal_inputs.get('status') == 'ok':
            raise KeccakTraceError('equal-input liveness skip was accepted as ok')
        evidence['noncompletion_controls'] = {
            'out_of_bounds': {'terminal': oob['terminal'],
                              'fault_events': [e for e in oob['events']
                                               if e[0] in ('fault', 'fault-ip')][:3],
                              'accepted_as_complete': False},
            'fuel': {'terminal': fuel['terminal'], 'steps': fuel['steps'],
                     'accepted_as_complete': False},
            'equal_inputs': {'status': equal_inputs.get('status'),
                             'reason': equal_inputs.get('reason'),
                             'accepted_as_complete': False},
        }
        # 10. Re-bind everything after use.
        binding_after = bind_all(inputs_path, policy_path)
        if binding_after != binding_before:
            raise KeccakTraceError('trusted module/file binding changed during replay')
        if sha(jar) != evidence['binding']['artifacts']['jar']['sha256']:
            raise KeccakTraceError('DafnyRuntime jar changed during replay')
        if sha(helper_entry) != runtime['artifact_binding']['entry_sha256']:
            raise KeccakTraceError('Helpers.class entry changed during replay')
        evidence['binding']['after'] = binding_after
        evidence['status'] = 'verified'
        return evidence
    except Exception as error:  # noqa: BLE001 - evidence records the failing gate
        evidence['status'] = 'failed'
        evidence['error'] = str(error)
        raise
    finally:
        _write_evidence(evidence_path, evidence)
