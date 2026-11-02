"""Reusable replay for the two approved DafnyRuntime 64-bit shift primitives.

This module is a *runtime-primitive* companion to ``bytecode_trace.py``.  It does
not change the extractor, the policy, the frozen ``SecretTrace`` model or the
report of any checked root.  It answers one narrow question with fresh evidence:

    does the *actual* ``dafny/Helpers.class`` entry from the pinned
    DafnyRuntime 4.9.1 jar contain ``bv64ShiftLeft:(JB)J`` and
    ``bv64ShiftRight:(JB)J`` bodies whose extracted certificates prove the
    approved contract (private word, **public** count, no calls/heap)?

The current official repository state admits **both** shifts:
``bytecode_trace.SHIFT_COUNT_PUBLIC_RUNTIME_CALLS`` and `policy.json` now list
``bv64ShiftLeft`` together with ``bv64ShiftRight``.  This module does not mutate
admission and adds no exception; it proves the two actual body contracts under
the reviewed private-word/public-count classification.  For reproducible
historical fixtures it also accepts exactly the earlier right-only reviewed
state, but the current official A state is left+right.

What is bound
-------------
* the full jar SHA-256 and the ``dafny/Helpers.class`` jar-entry SHA-256;
* the exact owner/name/descriptor and the exact 9-instruction bytecode body;
* the current policy, extractor, model and composition/executor hashes through
  the canonical ``inputs.json`` pins, including the loaded module files;
* Dafny and solver build identity, and the reviewed solver limits
  (30 s / 50 M / ``smt.case_split=0``; never resource-bumped).

What is proved
--------------
For each primitive, the emitted certificate proves ``Structure`` and the
universal two-run theorem, with and without a non-vacuity witness.  The finite
controls execute the *emitted program text* (through the frozen ``trace_exec``
mirror) for the review counts, including signed-byte aliases, and the Java
adapter replays the loaded jar on the same finite inputs.  The private-count
mutant is rejected by both the Python audit and an actual Dafny failure.

What is **not** proved
----------------------
This is not Keccak/``NativeKeccak`` closure, not a value/bitvector refinement
theorem and not a JVM timing statement.  The bytecode -> program bridge, the JVM
``long`` word cost, solver determinism and the compiler that produced the jar
remain trusted.  ``SecretTrace.Apply`` uses abstract bv64 words (``b % 64`` for
shifts); the Java adapter is finite adapter evidence only.  The actual guard is
``count == 64``, not ``count >= 64``: for 65..127 and negative byte counts the
bytecode falls through to the JVM shift, whose low-six-bits masking is mirrored
by ``b % 64`` in the model.
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import bytecode_trace as bt  # noqa: E402
import composition as comp  # noqa: E402
import trace_exec  # noqa: E402

DEFAULT_POLICY = HERE / 'policy.json'
DEFAULT_INPUTS = HERE / 'inputs.json'
DEFAULT_EXTRACTOR = HERE / 'bytecode_trace.py'
DEFAULT_DAFNY = Path.home() / '.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'
DEFAULT_SOLVER = DEFAULT_DAFNY.parent / 'z3/bin/z3-4.12.1'
DEFAULT_JAVA_HOME = Path(
    os.environ.get('JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))
DEFAULT_JAR = Path.home() / '.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar'

#: Pins reviewed for the actual DafnyRuntime artifact.  The jar hash is also
#: recorded in ``policy.json``; both must agree.  The entry hash is not a
#: source-name guess: it is the SHA-256 of the ``dafny/Helpers.class`` bytes read
#: from that jar.
EXPECTED_JAR_SHA256 = 'dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6'
EXPECTED_HELPERS_ENTRY_SHA256 = '4e5ec798394565756a1bc8438eb1638c2ad79eca264ae105ac576f537451e76c'
HELPERS_ENTRY = 'dafny/Helpers.class'
EXPECTED_DAFNY_BUILD = '4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2'
EXPECTED_Z3 = '4.12.1'

#: Reviewed limits.  These are the defaults used by the existing timing replay;
#: a primitive certificate must not silently inherit a larger root budget.
VERIFICATION_FLAGS = (
    '--verification-time-limit', '30',
    '--resource-limit', '50000000',
    '--solver-option', 'O:smt.case_split=0',
)
EXPECTED_VERIFIED = {'with_witness': 12, 'without_witness': 11}
#: The emitted private-count mutant has one named Chunk0/InstrOK branch
#: postcondition failure plus its cascading TwoRun/Structure precondition.
PRIVATE_COUNT_EXPECTED = {'verified': 9, 'errors': 2}
CHUNK0_INSTR_POSTCONDITION = 'ensures InstrOK(p, p.chunks[0][j])'
BRANCH_REQUIREMENT = 'RegTaint(p, cond) == Pub'
PROOF_TIMEOUT = 300

MASK64 = (1 << 64) - 1
LEFT_SHIFT_CALL = 'dafny/Helpers.bv64ShiftLeft:(JB)J'
RIGHT_SHIFT_CALL = 'dafny/Helpers.bv64ShiftRight:(JB)J'


def reviewed_admission_state(admitted: set[str]) -> str:
    """Return the reviewed admission state; this module never mutates it.

    The current official A state is exactly ``{right, left}``.  The earlier
    right-only state is accepted only as a reproducible historical fixture.  The
    body proofs use the same in-memory body contracts in either state; no other
    admission set is allowed here.
    """
    if admitted == {RIGHT_SHIFT_CALL}:
        return 'right-only (historical pre-admission state)'
    if admitted == {RIGHT_SHIFT_CALL, LEFT_SHIFT_CALL}:
        return 'right-plus-left (current official A)'
    raise RuntimePrimitiveError(
        'unexpected shift-count admission set: ' + repr(sorted(admitted)))


#: Counts required by the integration contract.  The extra negative/aliased
#: values exercise the JVM ``byte`` cast: 255 -> -1, 128 -> -128, 192 -> -64.
SAMPLED_COUNTS = (0, 1, 15, 24, 63, 64, 65, 127, 255, -128, -64, -1, 128, 192)
SAMPLE_WORDS = (0x0123456789ABCDEF, 0xFEDCBA9876543210)


class RuntimePrimitiveError(RuntimeError):
    """A pin, body, proof or control gate failed closed."""


#: The only trusted Python modules this replay uses.  Their *loaded* files, not
#: just on-disk neighbours, must be the canonical reviewed sources and must
#: match the canonical input pins.  This runs at import, before any helper
#: semantics are used, and again before/after the replay.
MODULE_FILES = {
    'bytecode_trace': HERE / 'bytecode_trace.py',
    'composition': HERE / 'composition.py',
    'trace_exec': HERE / 'trace_exec.py',
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def bind_loaded_modules(modules: dict, *, inputs_path: Path = DEFAULT_INPUTS,
                        canonical: dict = MODULE_FILES) -> dict:
    """Bind the *loaded* modules to canonical source paths and pinned hashes.

    A preloaded ``composition`` or ``trace_exec`` shadow with a different
    ``__file__`` fails here even if the on-disk canonical files still match
    their pins.  This covers all helper semantics in the module, not just the
    names selected by ``inputs.json``.
    """
    pins = json.loads(Path(inputs_path).read_text()).get('inputs')
    if not isinstance(pins, dict):
        raise RuntimePrimitiveError('inputs.json has no inputs table')
    records = {}
    for name, module in modules.items():
        if name not in canonical:
            raise RuntimePrimitiveError('no canonical source path for module ' + name)
        canonical_path = Path(canonical[name]).resolve()
        loaded_path = Path(getattr(module, '__file__', '')).resolve()
        if loaded_path != canonical_path:
            raise RuntimePrimitiveError(
                f'loaded {name} module is not the canonical source: '
                f'loaded {loaded_path}, required {canonical_path}')
        try:
            key = canonical_path.relative_to(REPO).as_posix()
        except ValueError as error:
            raise RuntimePrimitiveError(
                f'canonical {name} source is outside the repository: {canonical_path}') from error
        expected = pins.get(key)
        if expected is None:
            raise RuntimePrimitiveError(f'loaded {name} module is not pinned: {key}')
        actual = _sha256_file(loaded_path)
        if actual != expected:
            raise RuntimePrimitiveError(
                f'loaded {name} module hash mismatch: expected {expected}, got {actual}')
        records[name] = {'module': name, 'path': str(loaded_path), 'sha256': actual,
                         'pin_key': key, 'expected_sha256': expected}
    return records


#: Import-time binding: fail before constructing PRIMITIVES or calling any helper.
LOADED_MODULE_BINDING = bind_loaded_modules(
    {'bytecode_trace': bt, 'composition': comp, 'trace_exec': trace_exec})


@dataclasses.dataclass(frozen=True)
class PrimitiveSpec:
    key: str
    owner: str
    name: str
    descriptor: str
    params: tuple[str, str]
    #: (bytecode offset, opcode, operand) of the exact pinned jar method body.
    bytecode: tuple[tuple[int, str, str], ...]
    #: Certificate ``Op`` name and numeric ``bytecode_trace.KIND`` id.
    op: str
    op_kind: int
    label: str


_LEFT_BYTECODE = (
    (0, 'iload_2', ''), (1, 'bipush', '64'), (3, 'if_icmpne', '8'),
    (6, 'lconst_0', ''), (7, 'lreturn', ''),
    (8, 'lload_0', ''), (9, 'iload_2', ''), (10, 'lshl', ''), (11, 'lreturn', ''),
)
_RIGHT_BYTECODE = tuple(
    (offset, 'lushr' if op == 'lshl' else op, operand)
    for offset, op, operand in _LEFT_BYTECODE
)

PRIMITIVES = (
    PrimitiveSpec('left', 'dafny/Helpers', 'bv64ShiftLeft', '(JB)J', ('sec', 'pub'),
                  _LEFT_BYTECODE, 'shl', bt.KIND['shl'], 'ShiftLeft'),
    PrimitiveSpec('right', 'dafny/Helpers', 'bv64ShiftRight', '(JB)J', ('sec', 'pub'),
                  _RIGHT_BYTECODE, 'ushr', bt.KIND['ushr'], 'ShiftRight'),
)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    return digest_bytes(Path(path).read_bytes())


def _relative_pin_key(path: Path) -> str | None:
    try:
        return path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return None


def check_input_pins(inputs_path: Path, paths: dict[str, Path]) -> dict:
    """Fail closed unless each supplied file still matches its current pin.

    ``paths`` is ``{label: path}``.  A path outside the repository or absent
    from the canonical ``inputs.json`` is an error: this official replay binds
    the *current loaded* reviewed files, not an arbitrary scratch copy.
    """
    pins = json.loads(Path(inputs_path).read_text()).get('inputs')
    if not isinstance(pins, dict):
        raise RuntimePrimitiveError('inputs.json has no inputs table')
    records = {}
    for label, path in paths.items():
        key = _relative_pin_key(path)
        if key is None:
            raise RuntimePrimitiveError(
                f'{label} is outside the repository, so it cannot be pin-checked: {path}')
        expected = pins.get(key)
        if expected is None:
            raise RuntimePrimitiveError(f'{label} is not pinned in inputs.json: {key}')
        actual = digest(path)
        if actual != expected:
            raise RuntimePrimitiveError(
                f'pinned input changed for {label} ({key}): expected {expected}, got {actual}')
        records[label] = {'path': str(path), 'pin_key': key,
                          'expected_sha256': expected, 'actual_sha256': actual}
    return records


def check_jar_identity(jar: Path, expected: str = EXPECTED_JAR_SHA256) -> str:
    jar = Path(jar)
    if not jar.is_file():
        raise RuntimePrimitiveError('pinned DafnyRuntime jar not found: ' + str(jar))
    actual = digest(jar)
    if actual != expected:
        raise RuntimePrimitiveError(
            'DafnyRuntime jar identity mismatch: expected ' + expected + ', got ' + actual)
    return actual


def read_helpers_entry(jar: Path) -> bytes:
    jar = Path(jar)
    try:
        with zipfile.ZipFile(jar) as archive:
            names = set(archive.namelist())
            if HELPERS_ENTRY not in names:
                raise RuntimePrimitiveError(
                    'jar has no ' + HELPERS_ENTRY + ' entry: ' + str(jar))
            return archive.read(HELPERS_ENTRY)
    except zipfile.BadZipFile as error:
        raise RuntimePrimitiveError('not a jar: ' + str(jar)) from error


def check_entry_identity(data: bytes, expected: str = EXPECTED_HELPERS_ENTRY_SHA256) -> str:
    actual = digest_bytes(data)
    if actual != expected:
        raise RuntimePrimitiveError(
            'Helpers.class jar-entry identity mismatch: expected ' + expected
            + ', got ' + actual)
    return actual


def bind_helpers(jar: Path, first_dir: Path, *,
                 expected_jar_sha: str = EXPECTED_JAR_SHA256,
                 expected_entry_sha: str = EXPECTED_HELPERS_ENTRY_SHA256) -> dict:
    """Verify the jar and its exact class entry, then extract that entry.

    The returned ``classpath`` directory contains only the pinned
    ``dafny/Helpers.class`` entry.  ``java_primitive_replay`` disassembles that
    directory with ``javap``; the body is never synthesised from a source name.
    """
    jar = Path(jar).resolve()
    jar_sha = check_jar_identity(jar, expected_jar_sha)
    entry = read_helpers_entry(jar)
    entry_sha = check_entry_identity(entry, expected_entry_sha)
    classpath = Path(first_dir) / 'helpers-entry'
    target = classpath / HELPERS_ENTRY
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(entry)
    if digest(target) != entry_sha:
        raise RuntimePrimitiveError('extracted Helpers.class does not match the jar entry')
    return {'jar': str(jar), 'jar_sha256': jar_sha, 'entry': HELPERS_ENTRY,
            'entry_sha256': entry_sha, 'classpath': str(classpath)}


def require_policy_artifact_pins(policy: dict, bound: dict) -> dict:
    """Require the policy's pinned runtime metadata to equal the actual jar/entry."""
    runtime = (policy.get('runtime_classification') or {}).get('pinned_runtime') or {}
    if not isinstance(runtime, dict):
        raise RuntimePrimitiveError('policy runtime_classification.pinned_runtime is not an object')
    declared_jar = runtime.get('jar_sha256')
    declared_entry = runtime.get('helpers_entry_sha256')
    if declared_jar != bound['jar_sha256']:
        raise RuntimePrimitiveError(
            'policy pinned_runtime.jar_sha256 disagrees with the actual jar: '
            f'{declared_jar!r} != {bound["jar_sha256"]!r}')
    if declared_entry != EXPECTED_HELPERS_ENTRY_SHA256:
        raise RuntimePrimitiveError(
            'policy pinned_runtime.helpers_entry_sha256 is missing or not the reviewed entry: '
            f'{declared_entry!r} != {EXPECTED_HELPERS_ENTRY_SHA256!r}')
    if declared_entry != bound['entry_sha256']:
        raise RuntimePrimitiveError(
            'policy pinned_runtime.helpers_entry_sha256 disagrees with the actual jar entry: '
            f'{declared_entry!r} != {bound["entry_sha256"]!r}')
    return {'jar_sha256': declared_jar, 'helpers_entry_sha256': declared_entry}


def disassemble_helpers(javap: Path, classpath: Path, owner: str = 'dafny/Helpers') -> dict:
    """Disassemble the exact extracted entry; wrong owner fails in ``javap``."""
    try:
        return bt.disassemble(Path(javap), Path(classpath), owner)
    except bt.PolicyError as error:
        raise RuntimePrimitiveError(str(error)) from error


def verify_body(method: bt.Method, spec: PrimitiveSpec) -> None:
    """Bind the exact method identity and 9-instruction body."""
    if method.owner != spec.owner:
        raise RuntimePrimitiveError(
            f'{spec.key}: owner mismatch: expected {spec.owner}, got {method.owner}')
    if method.name != spec.name or method.descriptor != spec.descriptor:
        raise RuntimePrimitiveError(
            f'{spec.key}: method identity mismatch: expected '
            f'{spec.name}:{spec.descriptor}, got {method.name}:{method.descriptor}')
    if not method.static:
        raise RuntimePrimitiveError(f'{spec.key}: primitive is not static')
    if method.exception_table or method.handlers:
        raise RuntimePrimitiveError(f'{spec.key}: exception table outside the approved body')
    actual = tuple((insn.offset, insn.op, insn.operand) for insn in method.insns)
    if actual != spec.bytecode:
        raise RuntimePrimitiveError(
            f'{spec.key}: bytecode body differs from the reviewed body: {actual!r}')
    if any(insn.op.startswith('invoke') or insn.op in ('new', 'athrow', 'monitorenter',
                                                       'monitorexit')
           for insn in method.insns):
        raise RuntimePrimitiveError(f'{spec.key}: body contains an unapproved call/exception op')


def bind_method(methods: dict, spec: PrimitiveSpec, *,
                owner: str | None = None, name: str | None = None,
                descriptor: str | None = None) -> bt.Method:
    """Select one exact method and bind its body.

    The optional identity overrides exist for negative controls: a wrong owner,
    name or descriptor must fail rather than fall back to a look-alike method.
    """
    want_owner = spec.owner if owner is None else owner
    want_name = spec.name if name is None else name
    want_descriptor = spec.descriptor if descriptor is None else descriptor
    if want_owner != spec.owner:
        raise RuntimePrimitiveError(
            f'{spec.key}: wrong owner {want_owner}; approved owner is {spec.owner}')
    if want_name != spec.name:
        raise RuntimePrimitiveError(
            f'{spec.key}: wrong name {want_name}; approved name is {spec.name}')
    if want_descriptor != spec.descriptor:
        raise RuntimePrimitiveError(
            f'{spec.key}: wrong descriptor {want_descriptor}; approved descriptor is {spec.descriptor}')
    key = f'{want_name}:{want_descriptor}'
    method = methods.get(key)
    if method is None:
        raise RuntimePrimitiveError(f'{spec.key}: method {key} not present in the jar entry')
    verify_body(method, spec)
    return method


def primitive_policy(base_policy: dict, *,
                     params_overrides: dict[str, tuple[str, str]] | None = None) -> tuple[dict, dict]:
    """Overlay only the two approved body contracts, in memory.

    The base policy's ``calls``, ``runtime_classification`` and ``limits`` are
    preserved byte-for-byte.  No class field, heap role or private-helper
    exception is added.  A pre-existing method entry with different params is a
    hard error (never silently widened).
    """
    overrides = dict(params_overrides or {})
    unknown = set(overrides) - {spec.key for spec in PRIMITIVES}
    if unknown:
        raise RuntimePrimitiveError('unknown primitive override: ' + ', '.join(sorted(unknown)))
    policy = copy.deepcopy(base_policy)
    classes = policy.setdefault('classes', {})
    changes = {}
    for spec in PRIMITIVES:
        params = tuple(overrides.get(spec.key, spec.params))
        class_policy = classes.setdefault(spec.owner, {'fields': {}, 'methods': {}})
        if 'fields' in class_policy and not isinstance(class_policy['fields'], dict):
            raise RuntimePrimitiveError(f'{spec.owner}: existing fields entry is not an object')
        methods = class_policy.setdefault('methods', {})
        key = f'{spec.name}:{spec.descriptor}'
        existing = methods.get(key)
        if existing is not None:
            prior = tuple(existing.get('params') or ())
            if prior and prior != params:
                raise RuntimePrimitiveError(
                    f'{spec.owner}.{key}: existing params {prior!r} differ from approved '
                    f'{params!r}; refusing to widen or narrow the contract')
            entry = dict(existing)
            entry['params'] = list(params)
        else:
            entry = {'params': list(params)}
        methods[key] = entry
        changes[f'{spec.owner}.{key}'] = {'params': list(params)}
    for key in ('calls', 'runtime_classification', 'limits', 'roots', 'callee_roots',
                'composed_roots', 'helper_roots'):
        if policy.get(key) != base_policy.get(key):
            raise RuntimePrimitiveError('primitive overlay changed shared policy key: ' + key)
    return policy, changes


def assert_primitive_shape(result: dict, spec: PrimitiveSpec) -> dict:
    """Require the exact reviewed emitted program, including the ``== 64`` guard."""
    code = result['code']
    expected = [
        ('step', 0, 3, ('lit', 64)),
        ('step', 1, 4, ('op', 'ne', 2, 3)),
        ('branch', 2, None, None),
        ('step', 3, 5, ('lit', 0)),
        ('stop', None, None, None),
        ('step', 4, 6, ('op', spec.op, 1, 2)),
        ('stop', None, None, None),
    ]
    if len(code) != len(expected):
        raise RuntimePrimitiveError(f'{spec.key}: expected 7 emitted instructions, got {len(code)}')
    for index, (want, got) in enumerate(zip(expected, code)):
        if want[0] != got.get('type'):
            raise RuntimePrimitiveError(f'{spec.key}: instruction {index} type {want[0]} != {got.get("type")}')
        if want[0] == 'step':
            if (got.get('site'), got.get('dst'), tuple(got.get('kind') or ())) != want[1:]:
                raise RuntimePrimitiveError(
                    f'{spec.key}: instruction {index} shape {got!r} != {want!r}')
        elif want[0] == 'branch':
            if (got.get('site'), got.get('cond'), got.get('thn'), got.get('els')) != (2, 4, 5, 3):
                raise RuntimePrimitiveError(
                    f'{spec.key}: branch is not the reviewed count==64 guard: {got!r}')
    if result['registers'] != 7 or result['inputs'] != 3:
        raise RuntimePrimitiveError(f'{spec.key}: unexpected register/input count')
    if result.get('param_regs') != [1, 2]:
        raise RuntimePrimitiveError(f'{spec.key}: unexpected parameter registers {result.get("param_regs")}')
    if result['roles'] or result['call_targets']:
        raise RuntimePrimitiveError(f'{spec.key}: approved body must have no heap roles and no calls')
    if result['instructions_reachable'] != len(code) or not result.get('cfg_edges_checked'):
        raise RuntimePrimitiveError(f'{spec.key}: emitted CFG is not fully reachable/checked')
    expected_taints = {0: 'pub', 1: 'sec', 2: 'pub', 3: 'pub', 4: 'pub', 5: 'pub', 6: 'sec'}
    actual_taints = {r: result['reg_taints'].get(r, 'sec') for r in range(7)}
    if actual_taints != expected_taints:
        raise RuntimePrimitiveError(f'{spec.key}: unexpected register taints {actual_taints}')
    if result['sites'][2]['offset'] != 3 or result['sites'][2]['method'] != spec.name:
        raise RuntimePrimitiveError(f'{spec.key}: guard site is not the actual if_icmpne at offset 3')
    return {'registers': 7, 'inputs': 3, 'param_regs': [1, 2],
            'instructions': len(code), 'instructions_reachable': result['instructions_reachable'],
            'cfg_edges_checked': result['cfg_edges_checked'],
            'roles': result['roles'], 'call_targets': result['call_targets'],
            'reg_taints': actual_taints, 'guard_site_offset': 3,
            'guard_relation': 'count != 64 (if_icmpne), not count >= 64',
            'emitted': [{'type': item['type'], **{k: item[k] for k in ('site', 'dst', 'kind',
                                                                       'cond', 'thn', 'els')
                                                   if k in item}} for item in code]}


def translate_primitive(method: bt.Method, policy: dict, spec: PrimitiveSpec) -> dict:
    class_policy = policy['classes'][spec.owner]
    try:
        result = bt.translate(method, policy, class_policy)
    except bt.PolicyError as error:
        raise RuntimePrimitiveError(f'{spec.key}: translation rejected: {error}') from error
    shape = assert_primitive_shape(result, spec)
    failures = bt.audit_certificate(result)
    if failures:
        raise RuntimePrimitiveError(f'{spec.key}: independent audit rejected: {failures[:3]}')
    return {'result': result, 'shape': shape, 'audit': failures}


def _certificate_text(name: str, result: dict, model: Path,
                      witness: dict | None = None) -> str:
    text = bt.certificate_module(name, result, witness=witness)
    rewritten, count = re.subn(r'^include ".*"$', 'include "%s"' % Path(model).resolve().as_posix(),
                               text, count=1, flags=re.M)
    if count != 1:
        raise RuntimePrimitiveError('generated certificate has no include line to bind')
    return rewritten


def _write_certificate(outdir: Path, name: str, result: dict, model: Path,
                       witness: dict | None = None) -> Path:
    folder = Path(outdir) / 'certificates'
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (name + '.dfy')
    text = _certificate_text(name, result, model, witness=witness)
    path.write_text(text)
    return path


def classify_dafny(status, log: str, *, expected_verified: int | None = None) -> dict:
    """Strict proof-status classification.

    A timeout, resource exhaustion, crash, missing input, or a truncated/
    multiple summary is never a genuine positive or negative proof control.
    """
    summaries = re.findall(r'Dafny program verifier finished with (\d+) verified, (\d+) errors?',
                           log or '')
    bad = re.search(
        r'time.?out|timed out|out of resource|resource limit|out of memory|internal error|'
        r'unhandled exception|stack overflow|file not found|does not exist|could not open|'
        r'No such file', log or '', re.I)
    obligation = re.search(
        r'Error:.*(possible violation of (pre|post)?condition'
        r'|(postcondition|precondition|assertion) (could not be proved|might not hold))',
        log or '')
    record = {
        'returncode': status,
        'verified': None if not summaries else int(summaries[0][0]),
        'errors': None if not summaries else int(summaries[0][1]),
        'summary_count': len(summaries),
        'bad_run': bool(bad),
        'bad_match': bad.group(0) if bad else None,
        'obligation': obligation.group(0) if obligation else None,
        'log_sha256': digest_bytes((log or '').encode()),
    }
    if len(summaries) != 1:
        record['status'] = 'no_single_summary'
        return record
    if bad:
        record['status'] = 'timeout_resource_or_crash'
        return record
    if status == 0 and record['errors'] == 0:
        if expected_verified is not None and record['verified'] != expected_verified:
            record['status'] = 'unexpected_verified_count'
        else:
            record['status'] = 'verified'
        return record
    if status == 4 and record['errors'] and record['errors'] > 0 and obligation:
        record['status'] = 'proof_failed'
        return record
    record['status'] = 'not_a_proof_result'
    return record


def _run_proof(command: list[str], log_path: Path) -> dict:
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run([str(c) for c in command], capture_output=True,
                                   text=True, timeout=PROOF_TIMEOUT)
        status = completed.returncode
        log = completed.stdout + completed.stderr
    except subprocess.TimeoutExpired as error:
        status = -1
        log = (error.stdout or '') + (error.stderr or '')
        log += '\nHARNESS TIMEOUT after %d seconds\n' % PROOF_TIMEOUT
    except OSError as error:
        status = -1
        log = 'HARNESS EXEC ERROR: %s\n' % error
    log_path.write_text(log)
    record = classify_dafny(status, log)
    record['command'] = [str(c) for c in command]
    record['log'] = str(log_path)
    return record


def _require_proof(record: dict, *, expected_verified: int | None, label: str) -> dict:
    if record['status'] != 'verified':
        raise RuntimePrimitiveError(
            f'{label}: not a genuine successful proof: {record["status"]} '
            f'(rc={record["returncode"]}, verified={record["verified"]}, '
            f'errors={record["errors"]}); a timeout/crash/partial result is not evidence')
    if expected_verified is not None and record['verified'] != expected_verified:
        raise RuntimePrimitiveError(
            f'{label}: expected {expected_verified} verified obligations, got {record["verified"]}')
    return record


def _require_proof_failure(record: dict, label: str) -> dict:
    if record['status'] != 'proof_failed':
        raise RuntimePrimitiveError(
            f'{label}: expected a normal proof-obligation failure, got {record["status"]} '
            f'(rc={record["returncode"]}, errors={record["errors"]}, obligation={record["obligation"]!r})')
    return record


def _statement_line(path: Path, statement: str, label: str) -> tuple[int, str]:
    lines = Path(path).read_text().splitlines()
    for number, line in enumerate(lines, 1):
        if statement in line:
            return number, line.strip()
    raise RuntimePrimitiveError(f'{label}: missing statement {statement!r} in {path}')


def parse_dafny_diagnostics(log: str) -> list[dict]:
    """Parse Dafny ``file(line,col): Error/Related location: message`` blocks.

    The path is greedy up to the final ``(line,col):`` pair, so absolute UN*X
    paths (including paths with spaces or parentheses) are handled without
    assuming the current directory.
    """
    pattern = re.compile(r'^(?P<path>.+)\((?P<line>\d+),(?P<col>\d+)\): (?P<message>.*)$')
    entries: list[dict] = []
    current = None
    for raw in (log or '').splitlines():
        match = pattern.match(raw)
        if not match:
            continue
        entry = {'path': match['path'], 'line': int(match['line']),
                 'col': int(match['col']), 'message': match['message']}
        if match['message'].startswith('Error:'):
            entry['related'] = []
            entries.append(entry)
            current = entry
        elif match['message'].startswith('Related location:') and current is not None:
            current['related'].append(entry)
    return entries


def private_count_anchor(certificate_path: Path, model_path: Path, log: str) -> dict:
    """Require the named Chunk0/InstrOK branch postcondition diagnostic.

    An unrelated postcondition/assertion failure, a failure in another file, a
    precondition outside Chunk0, a malformed log, or a missing related
    ``RegTaint(p, cond) == Pub`` location is not a private-count control.
    """
    certificate = Path(certificate_path).resolve()
    model = Path(model_path).resolve()
    chunk_line, chunk_statement = _statement_line(
        certificate, CHUNK0_INSTR_POSTCONDITION, 'private-count certificate')
    branch_line, branch_statement = _statement_line(
        model, BRANCH_REQUIREMENT, 'pinned SecretTrace branch requirement')
    diagnostics = parse_dafny_diagnostics(log)
    if not diagnostics:
        raise RuntimePrimitiveError('private-count anchor: no Dafny diagnostics parsed')
    for error in diagnostics:
        if Path(error['path']).resolve() != certificate:
            continue
        if error['line'] != chunk_line:
            continue
        if 'possible violation of postcondition of forall statement' not in error['message']:
            continue
        related = [item for item in error['related']
                   if Path(item['path']).resolve() == model
                   and item['line'] == branch_line
                   and 'Related location:' in item['message']]
        if related:
            return {
                'certificate': str(certificate), 'certificate_line': chunk_line,
                'certificate_statement': chunk_statement,
                'model': str(model), 'model_line': branch_line,
                'model_statement': branch_statement,
                'error_message': error['message'],
                'related_message': related[0]['message'],
                'obligation': 'Chunk0.InstrOK universal postcondition on secret branch taint',
                'diagnostics': diagnostics,
            }
    raise RuntimePrimitiveError(
        'private-count anchor: missing named Chunk0/InstrOK branch postcondition '
        f'for certificate {certificate} line {chunk_line} and model branch line {branch_line}')


def _require_private_count_failure(record: dict, *, certificate_path: Path,
                                   model_path: Path, label: str) -> dict:
    """Strict private-count control: genuine proof failure plus named anchor."""
    _require_proof_failure(record, label)
    if record.get('verified') != PRIVATE_COUNT_EXPECTED['verified']:
        raise RuntimePrimitiveError(
            f'{label}: expected {PRIVATE_COUNT_EXPECTED["verified"]} verified obligations, '
            f'got {record.get("verified")}')
    if record.get('errors') != PRIVATE_COUNT_EXPECTED['errors']:
        raise RuntimePrimitiveError(
            f'{label}: expected {PRIVATE_COUNT_EXPECTED["errors"]} errors, '
            f'got {record.get("errors")}')
    anchor = private_count_anchor(certificate_path, model_path,
                                  Path(record['log']).read_text())
    record['anchor'] = anchor
    record['anchor_status'] = 'proof_failed_named_chunk0_branch_postcondition'
    return record


def _structural_code(result: dict) -> list[dict]:
    """Instructions with taint annotations removed, for the positive/mutant diff."""
    return [{key: value for key, value in instruction.items() if key != 'ann'}
            for instruction in result['code']]


def _private_count_program_diff(positive: dict, mutant: dict) -> dict:
    """Require the private-count mutant to differ only in approved annotations."""
    if _structural_code(positive) != _structural_code(mutant):
        raise RuntimePrimitiveError('private-count mutant changed executable instructions')
    for key in ('registers', 'roles', 'sites', 'call_targets', 'inputs', 'param_regs',
                'static', 'instructions_reachable', 'cfg_edges_checked'):
        if positive.get(key) != mutant.get(key):
            raise RuntimePrimitiveError(f'private-count mutant changed {key}')
    taint_diff = {r: {'positive': positive['reg_taints'].get(r, 'sec'),
                      'mutant': mutant['reg_taints'].get(r, 'sec')}
                  for r in range(positive['registers'])
                  if positive['reg_taints'].get(r, 'sec')
                  != mutant['reg_taints'].get(r, 'sec')}
    expected = {2: {'positive': 'pub', 'mutant': 'sec'},
                4: {'positive': 'pub', 'mutant': 'sec'}}
    if taint_diff != expected:
        raise RuntimePrimitiveError(
            f'private-count mutant taint diff is not the exact expected annotations: {taint_diff}')
    pos_source = bt.certificate_source(positive)
    mutant_source = bt.certificate_source(mutant)
    if pos_source['role_names'] != mutant_source['role_names'] or \
            pos_source['functions'] != mutant_source['functions']:
        raise RuntimePrimitiveError('private-count mutant changed generated functions/roles')
    normalize = lambda text: re.sub(r'annots := \[\[.*?\]\]', 'annots := [[...]]', text)
    if normalize(pos_source['dafny']) != normalize(mutant_source['dafny']):
        raise RuntimePrimitiveError('private-count mutant changed generated program beyond annots')
    return {'executable_instructions_equal': True, 'generated_functions_equal': True,
            'taint_diff': taint_diff, 'expected_taint_diff': expected,
            'unrelated_false_assertions': False}


def _tool_version(command: list[str]) -> str:
    try:
        completed = subprocess.run([str(c) for c in command], capture_output=True, text=True,
                                   timeout=60)
        return (completed.stdout + completed.stderr).strip()
    except OSError as error:
        raise RuntimePrimitiveError('tool unavailable: ' + ' '.join(map(str, command))) from error


def check_tools(dafny: Path, solver: Path, java_home: Path) -> dict:
    tools = {}
    for name, path in (('dafny', dafny), ('solver', solver),
                       ('javap', java_home / 'bin/javap'),
                       ('javac', java_home / 'bin/javac'),
                       ('java', java_home / 'bin/java')):
        path = Path(path)
        if not path.is_file():
            raise RuntimePrimitiveError(f'required tool missing: {name} at {path}')
        tools[name] = {'path': str(path.resolve()), 'sha256': digest(path)}
    dafny_version = _tool_version([dafny, '--version'])
    if dafny_version != EXPECTED_DAFNY_BUILD:
        raise RuntimePrimitiveError(
            f'unexpected Dafny build: {dafny_version!r}; require {EXPECTED_DAFNY_BUILD}')
    solver_version = _tool_version([solver, '--version'])
    if EXPECTED_Z3 not in solver_version:
        raise RuntimePrimitiveError(f'unexpected Z3 version: {solver_version!r}')
    tools['dafny']['version'] = dafny_version
    tools['solver']['version'] = solver_version
    tools['javap']['version'] = _tool_version([java_home / 'bin/javap', '-version'])
    tools['javac']['version'] = _tool_version([java_home / 'bin/javac', '-version'])
    tools['java']['version'] = _tool_version([java_home / 'bin/java', '-version'])
    return tools


def signed_byte_value(count: int) -> int:
    """The JVM ``(byte) count`` value, sign-extended to a Python int."""
    value = int(count) & 0xFF
    return value - 0x100 if value >= 0x80 else value


def count_word(count: int) -> int:
    """The 64-bit word passed as the ``B`` parameter's JVM int value."""
    return signed_byte_value(count) & MASK64


def expected_shift_result(spec: PrimitiveSpec, word: int, count: int) -> int:
    """Model/bytecode value semantics for the finite adapter check."""
    shifted = signed_byte_value(count)
    if shifted == 64:
        return 0
    word &= MASK64
    amount = shifted & 63
    return ((word << amount) & MASK64) if spec.op == 'shl' else (word >> amount)


def _state(result: dict, word: int, count: int) -> list[int]:
    word_reg, count_reg = result['param_regs']
    regs = [0] * result['registers']
    regs[word_reg] = word & MASK64
    regs[count_reg] = count_word(count)
    return regs


def finite_control(result: dict, spec: PrimitiveSpec,
                   counts: tuple[int, ...] = SAMPLED_COUNTS,
                   words: tuple[int, int] = SAMPLE_WORDS) -> list[dict]:
    """Execute the emitted program text for each count and two private words."""
    view = trace_exec.ProgramView(result)
    shift_reg = next(insn['dst'] for insn in result['code']
                     if insn['type'] == 'step' and insn['kind'][0] == 'op'
                     and insn['kind'][1] == spec.op)
    word_reg, count_reg = result['param_regs']
    rows = []
    for requested in counts:
        value = signed_byte_value(requested)
        word_count = count_word(requested)
        run_s = trace_exec.run_to_completion(view, _state(result, words[0], requested), [], 64)
        run_t = trace_exec.run_to_completion(view, _state(result, words[1], requested), [], 64)
        if run_s is None or run_t is None:
            raise RuntimePrimitiveError(f'{spec.key}: no completed finite run at count {requested}')
        if run_s['terminal'] != 'stop' or run_t['terminal'] != 'stop':
            raise RuntimePrimitiveError(
                f'{spec.key}: count {requested} did not terminate at stop '
                f'({run_s["terminal"]}/{run_t["terminal"]})')
        events_s, events_t = run_s['events'], run_t['events']
        public = [r for r in range(result['registers']) if view.reg_taint(r) == 'pub']
        public_equal = all(view.get(run_s['regs'], r) == view.get(run_t['regs'], r)
                           for r in public)
        branch = [event for event in events_s if event[0] == 'guard']
        # The emitted ``IBranch(cond=(count != 64), thn=shift, els=zero)`` takes
        # the shift edge whenever cond is non-zero.  The zero edge is reached
        # only when the JVM ``if_icmpne 64`` falls through, i.e. count == 64.
        taken = len(branch) == 1 and bool(branch[0][2])
        zero_branch = len(branch) == 1 and not bool(branch[0][2])
        expected_results = [expected_shift_result(spec, w, requested) for w in words]
        observed_results = [view.get(run_s['regs'], shift_reg), view.get(run_t['regs'], shift_reg)]
        if observed_results != expected_results:
            raise RuntimePrimitiveError(
                f'{spec.key}: count {requested} program result {observed_results} != '
                f'bytecode/model value {expected_results}')
        if taken != (value != 64) or zero_branch != (value == 64):
            raise RuntimePrimitiveError(
                f'{spec.key}: count {requested} branch shift={taken}/zero={zero_branch}, '
                f'but the actual relation is count == 64 (value {value})')
        row = {
            'requested_count': requested,
            'signed_byte_value': value,
            'count_word': word_count,
            'terminal': run_s['terminal'] + '/' + run_t['terminal'],
            'trace_equal': events_s == events_t,
            'public_registers_equal': public_equal,
            'branch_taken': taken,
            'zero_branch_taken': zero_branch,
            'expected_branch_taken': value != 64,
            'expected_zero_branch_taken': value == 64,
            'result_is_zero': observed_results == [0, 0],
            'difference_is_input_only': view.get(run_s['regs'], word_reg)
            != view.get(run_t['regs'], word_reg),
            'differing_registers': trace_exec.differing_registers(view, run_s['regs'], run_t['regs']),
            'shift_register': shift_reg,
            'word_register': word_reg,
            'count_register': count_reg,
            'model_results': observed_results,
        }
        if not (row['trace_equal'] and row['public_registers_equal']):
            raise RuntimePrimitiveError(f'{spec.key}: count {requested} finite trace equality failed')
        rows.append(row)
    return rows


def _java_source(counts: tuple[int, ...], words: tuple[int, int]) -> str:
    return '''// Generated by formal/timing/runtime_primitives.py -- do not edit.
public final class RuntimeShiftProbe {
  public static void main(String[] args) {
    long[] words = { 0x%016XL, 0x%016XL };
    int[] counts = { %s };
    for (long word : words) {
      for (int count : counts) {
        System.out.println(Long.toUnsignedString(word) + " " + count + " "
            + Long.toUnsignedString(dafny.Helpers.bv64ShiftLeft(word, (byte) count)) + " "
            + Long.toUnsignedString(dafny.Helpers.bv64ShiftRight(word, (byte) count)));
      }
    }
  }
}
''' % (words[0], words[1], ', '.join(str(c) for c in counts))


def java_adapter(outdir: Path, jar: Path, java_home: Path, *,
                 counts: tuple[int, ...] = SAMPLED_COUNTS,
                 words: tuple[int, int] = SAMPLE_WORDS) -> dict:
    """Finite replay of the loaded jar's real Helpers on the same inputs.

    This is adapter evidence, not a refinement proof.  It checks that the actual
    ``long`` results returned by the pinned jar agree with the values the emitted
    program produces for these finitely many ``(word, byte count)`` pairs.
    """
    folder = Path(outdir) / 'java-adapter'
    folder.mkdir(parents=True, exist_ok=True)
    source = folder / 'RuntimeShiftProbe.java'
    source.write_text(_java_source(counts, words))
    classes = folder / 'classes'
    classes.mkdir(exist_ok=True)
    javac = Path(java_home) / 'bin/javac'
    java = Path(java_home) / 'bin/java'
    compile_cmd = [str(javac), '-cp', str(jar), '-d', str(classes), str(source)]
    compiled = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=180)
    (folder / 'javac.log').write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimePrimitiveError('Java adapter failed to compile: '
                                    + (compiled.stdout + compiled.stderr)[:400])
    classpath = str(classes) + os.pathsep + str(jar)
    run_cmd = [str(java), '-cp', classpath, 'RuntimeShiftProbe']
    completed = subprocess.run(run_cmd, capture_output=True, text=True, timeout=180)
    (folder / 'java.log').write_text(completed.stdout + completed.stderr)
    if completed.returncode:
        raise RuntimePrimitiveError('Java adapter failed to run: '
                                    + (completed.stdout + completed.stderr)[:400])
    rows = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        try:
            word, count, left, right = (int(part) for part in parts)
        except ValueError:
            continue
        rows.append({'word': word, 'requested_count': count,
                     'left': left, 'right': right})
    expected_rows = 2 * len(counts)
    if len(rows) != expected_rows:
        raise RuntimePrimitiveError(
            f'Java adapter produced {len(rows)} rows; expected {expected_rows}')
    return {'source': str(source), 'compile_command': compile_cmd, 'run_command': run_cmd,
            'rows': rows, 'row_count': len(rows),
            'claim': 'finite adapter equality on the listed inputs only'}


def check_java_adapter(java_rows: list[dict], model_rows: dict[str, list[dict]],
                       specs: tuple[PrimitiveSpec, ...] = PRIMITIVES,
                       words: tuple[int, int] = SAMPLE_WORDS) -> dict:
    """Compare real Java results with the emitted program's finite results."""
    by_key = {}
    for spec in specs:
        for row in model_rows[spec.key]:
            for word, value in zip(words, row['model_results']):
                by_key[(spec.key, word, row['requested_count'])] = value
    compared = 0
    for row in java_rows:
        for spec in specs:
            key = (spec.key, row['word'], row['requested_count'])
            if key not in by_key:
                raise RuntimePrimitiveError('Java adapter row has no model counterpart: ' + repr(key))
            if row[spec.key] != by_key[key]:
                raise RuntimePrimitiveError(
                    f'Java/model mismatch for {spec.key} word={row["word"]} '
                    f'count={row["requested_count"]}: java={row[spec.key]} model={by_key[key]}')
            compared += 1
    if compared != len(java_rows) * len(specs):
        raise RuntimePrimitiveError('Java adapter comparison is incomplete')
    return {'status': 'finite-java-equals-model', 'comparisons': compared,
            'inputs': len(java_rows)}


def _jar_controls(jar: Path, entry: bytes, workdir: Path) -> dict:
    controls = {}
    fake = Path(workdir) / 'not-the-runtime.jar'
    fake.write_bytes(b'not the pinned runtime')
    try:
        check_jar_identity(fake)
    except RuntimePrimitiveError as error:
        controls['wrong_jar'] = {'rejected': True, 'error': str(error)}
    else:
        raise RuntimePrimitiveError('wrong jar was accepted')
    tampered = bytearray(entry)
    tampered[-1] ^= 0xFF
    controls['tampered_entry'] = {
        'recorded_entry_sha256': digest_bytes(entry),
        'tampered_entry_sha256': digest_bytes(bytes(tampered)),
    }
    try:
        check_entry_identity(bytes(tampered))
    except RuntimePrimitiveError as error:
        controls['tampered_entry'].update({'rejected': True, 'error': str(error)})
    else:
        raise RuntimePrimitiveError('tampered jar entry was accepted')
    return controls


def _body_controls(methods: dict, workdir: Path) -> dict:
    controls = {}
    wrong_owner = None
    for spec in PRIMITIVES:
        try:
            bind_method(methods, spec, owner='dafny/Helper')
        except RuntimePrimitiveError as error:
            wrong_owner = str(error)
        else:
            raise RuntimePrimitiveError('wrong owner was accepted')
    controls['wrong_owner'] = {'rejected': True, 'error': wrong_owner}
    for field, value in (('name', 'bv64ShiftLeft2'), ('descriptor', '(JB)I')):
        errors = []
        for spec in PRIMITIVES:
            try:
                bind_method(methods, spec, **{field: value})
            except RuntimePrimitiveError as error:
                errors.append(str(error))
            else:
                raise RuntimePrimitiveError(f'wrong {field} was accepted')
        controls['wrong_' + field] = {'rejected': True, 'error': errors[0]}
    mutants = {}
    for spec in PRIMITIVES:
        method = methods[f'{spec.name}:{spec.descriptor}']
        for label, index, replacement in (
                ('guard_literal_65', 1, bt.Insn(1, 'bipush', '65', '1: bipush 65')),
                ('guard_ge_not_eq', 2, bt.Insn(3, 'if_icmpge', '8', '3: if_icmpge 8')),
                ('wrong_shift_op', 7, bt.Insn(10, 'lushr' if spec.op == 'shl' else 'lshl',
                                              '', '10: wrong shift'))):
            mutant = dataclasses.replace(method, insns=list(method.insns))
            mutant.insns[index] = replacement
            try:
                verify_body(mutant, spec)
            except RuntimePrimitiveError as error:
                mutants[f'{spec.key}:{label}'] = {'rejected': True, 'error': str(error)}
            else:
                raise RuntimePrimitiveError(f'{spec.key}: body mutant {label} was accepted')
    controls['body_mutants'] = mutants
    return controls


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)


def require_stable_binding(module_before: dict, module_after: dict,
                           pins_before: dict, pins_after: dict) -> dict:
    """Enforce that the after-replay binding equals the before-replay binding."""
    if module_before != module_after:
        changed = sorted(set(module_before) | set(module_after))
        changed = [name for name in changed
                   if module_before.get(name) != module_after.get(name)]
        raise RuntimePrimitiveError(
            'loaded module binding changed during replay: ' + ', '.join(changed))
    if pins_before != pins_after:
        changed = sorted(set(pins_before) | set(pins_after))
        changed = [name for name in changed
                   if pins_before.get(name) != pins_after.get(name)]
        raise RuntimePrimitiveError(
            'pinned input binding changed during replay: ' + ', '.join(changed))
    return {'module_binding_equal': True, 'pins_equal': True}


def replay(output: Path, *, policy_path: Path = DEFAULT_POLICY,
           inputs_path: Path = DEFAULT_INPUTS, extractor_path: Path = DEFAULT_EXTRACTOR,
           jar: Path = DEFAULT_JAR, dafny: Path = DEFAULT_DAFNY,
           solver: Path = DEFAULT_SOLVER, java_home: Path = DEFAULT_JAVA_HOME) -> dict:
    """Run the complete official primitive replay and write evidence.

    There is no partial/skip mode.  The canonical ``inputs.json`` pins and the
    actual loaded ``bytecode_trace``/``composition``/``trace_exec`` modules are
    verified before any tool or proof, and again after the replay.  The function
    then disassembles the pinned jar entry, verifies all positive certificates,
    the private-count Dafny mutants, the finite controls and the Java adapter.
    Any failed gate raises ``RuntimePrimitiveError``; only a complete run gets
    ``status: verified``.
    """
    output = Path(output).expanduser().resolve()
    if 'quic/target' in output.as_posix():
        raise RuntimePrimitiveError('refusing to write evidence inside quic/target')
    output.mkdir(parents=True, exist_ok=True)
    evidence_path = output / 'runtime-primitives.json'
    policy_path = Path(policy_path).expanduser().resolve()
    inputs_path = Path(inputs_path).expanduser().resolve()
    if inputs_path != DEFAULT_INPUTS.resolve():
        raise RuntimePrimitiveError(
            'official replay requires the canonical inputs.json: ' + str(DEFAULT_INPUTS.resolve()))
    extractor_path = Path(extractor_path).expanduser().resolve()
    if Path(bt.__file__).resolve() != extractor_path:
        raise RuntimePrimitiveError(
            'extractor_path must be the currently imported bytecode_trace module: '
            f'loaded {Path(bt.__file__).resolve()}, requested {extractor_path}')
    # Re-bind the loaded modules immediately before any policy/tool/proof use.
    module_binding_before = bind_loaded_modules(
        {'bytecode_trace': bt, 'composition': comp, 'trace_exec': trace_exec},
        inputs_path=inputs_path)
    jar = Path(jar).expanduser().resolve()
    dafny = Path(dafny).expanduser().resolve()
    solver = Path(solver).expanduser().resolve()
    java_home = Path(java_home).expanduser().resolve()
    work = Path(tempfile.mkdtemp(prefix='runtime-primitives-', dir=output))
    evidence = {
        'schema': 1,
        'status': 'incomplete',
        'scope': {
            'primitives': [f'{spec.owner}.{spec.name}:{spec.descriptor}' for spec in PRIMITIVES],
            'contract': 'argument 0 = private word (sec), argument 1 = public shift count (pub); '
                        'result sec; no heap roles; no calls',
            'admission_change': False,
            'left_shift_admission': 'not added by this replay',
            'admission_state': 'filled below',
            'kept_frozen': ['SecretTrace.dfy', 'composition.py', 'trace_exec.py',
                            'bytecode_trace.py', 'policy.json'],
        },
        'limits': {
            'verification': list(VERIFICATION_FLAGS),
            'proof_process_timeout_seconds': PROOF_TIMEOUT,
            'finite_step_cap': comp.WITNESS_STEP_CAP,
            'sampled_counts': list(SAMPLED_COUNTS),
            'sampled_words': list(SAMPLE_WORDS),
            'no_resource_bump': True,
            'no_partial_proof_counts': True,
            'expected_verified': dict(EXPECTED_VERIFIED),
        },
        'value_boundary': {
            'model': 'abstract bv64 words; SecretTrace.Apply shifts use b % 64',
            'java_adapter': 'finite adapter equality only; not a value/bitvector refinement proof',
            'jvm_timing': 'not addressed; JVM/JIT/CPU timing remains outside the claim',
            'guard': 'actual bytecode is count == 64 (if_icmpne); count 65..127 and negative '
                     'bytes fall through to lshr/lushr with low-six-bits masking',
        },
        'trust_boundary': {
            'bound': 'loaded Python module source paths and SHA-256 hashes, canonical '
                     'inputs.json pins, jar and extracted Helpers.class entry, exact method '
                     'body, Dafny/Z3/JDK tool identities and the passed solver path',
            'outside': 'Python __pycache__/bytecode caches, an already-compromised interpreter '
                       'or malicious process inside the same trust domain are not attested; '
                       'this is a source-file binding receipt, not a remote attestation',
        },
    }
    try:
        base_policy = json.loads(policy_path.read_text())
        bt.check_runtime_classification(base_policy)
        admission_state = reviewed_admission_state(set(bt.SHIFT_COUNT_PUBLIC_RUNTIME_CALLS))
        evidence['module_binding'] = {'before': module_binding_before}
        evidence['pins'] = check_input_pins(inputs_path, {
            'policy': policy_path,
            'extractor': Path(bt.__file__),
            'model': HERE / 'SecretTrace.dfy',
            'composition': Path(comp.__file__),
            'trace_exec': Path(trace_exec.__file__),
        })
        evidence['artifacts'] = {
            'policy': {'path': str(policy_path), 'sha256': digest(policy_path)},
            'inputs': {'path': str(inputs_path), 'sha256': digest(inputs_path)},
            'extractor': {'path': str(Path(bt.__file__)), 'sha256': _sha256_file(Path(bt.__file__))},
            'model': {'path': str(HERE / 'SecretTrace.dfy'),
                      'sha256': digest(HERE / 'SecretTrace.dfy')},
            'loaded_modules': module_binding_before,
        }
        tools = check_tools(dafny, solver, java_home)
        evidence['tools'] = tools
        bound = bind_helpers(jar, work)
        evidence['artifact_binding'] = bound
        policy_pins = require_policy_artifact_pins(base_policy, bound)
        evidence['artifact_binding']['policy_pinned_runtime_jar_sha256'] = policy_pins['jar_sha256']
        evidence['artifact_binding']['policy_pinned_runtime_helpers_entry_sha256'] = \
            policy_pins['helpers_entry_sha256']
        methods = disassemble_helpers(Path(java_home) / 'bin/javap', Path(bound['classpath']))
        evidence['methods'] = {}
        for spec in PRIMITIVES:
            method = bind_method(methods, spec)
            evidence['methods'][spec.key] = {
                'owner': method.owner, 'name': method.name, 'descriptor': method.descriptor,
                'key': method.key, 'static': method.static,
                'bytecode': [{'offset': insn.offset, 'op': insn.op, 'operand': insn.operand}
                             for insn in method.insns],
                'exception_table': method.exception_table,
                'bytecode_sha256': digest_bytes(json.dumps(
                    [[i.offset, i.op, i.operand] for i in method.insns]).encode()),
            }
        policy, overlay = primitive_policy(base_policy)
        evidence['policy_overlay'] = {
            'in_memory_only': True,
            'changes': overlay,
            'admission_tables_unchanged': {
                'calls': policy.get('calls') == base_policy.get('calls'),
                'runtime_classification': policy.get('runtime_classification')
                == base_policy.get('runtime_classification'),
                'limits': policy.get('limits') == base_policy.get('limits'),
                'fields': all(policy['classes'].get(spec.owner, {}).get('fields', {})
                              == base_policy.get('classes', {}).get(spec.owner, {}).get('fields', {})
                              for spec in PRIMITIVES),
            },
        }
        if not all(evidence['policy_overlay']['admission_tables_unchanged'].values()):
            raise RuntimePrimitiveError('primitive overlay changed a shared policy table')
        evidence['scope']['admission_state'] = admission_state
        evidence['scope']['admitted_shift_targets'] = sorted(bt.SHIFT_COUNT_PUBLIC_RUNTIME_CALLS)
        evidence['scope']['left_shift_admission'] = (
            'present in the official extractor; this replay does not add or mutate it'
            if LEFT_SHIFT_CALL in bt.SHIFT_COUNT_PUBLIC_RUNTIME_CALLS
            else 'historical right-only state; this replay does not add the left shift')
        evidence['proofs'] = {}
        model_rows = {}
        positive_results = {}
        for spec in PRIMITIVES:
            method = bind_method(methods, spec)
            translated = translate_primitive(method, policy, spec)
            result = translated['result']
            positive_results[spec.key] = result
            witness = comp.witness(result)
            if witness is None:
                raise RuntimePrimitiveError(f'{spec.key}: no non-vacuity witness')
            execution = witness.get('execution')
            if execution is None:
                raise RuntimePrimitiveError(f'{spec.key}: witness execution did not complete')
            if execution.get('terminal') != 'stop':
                raise RuntimePrimitiveError(f'{spec.key}: witness terminal is not stop')
            if not execution.get('public_registers_agree'):
                raise RuntimePrimitiveError(f'{spec.key}: witness public registers differ')
            if not execution.get('differing_registers'):
                raise RuntimePrimitiveError(f'{spec.key}: witness has no private liveness')
            spec_proofs = {'shape': translated['shape'], 'audit': translated['audit'],
                           'witness': {'fuel': witness.get('fuel'),
                                       'execution': execution,
                                       'nonvacuity': True}}
            for mode, use_witness in (('without_witness', None), ('with_witness', witness)):
                name = f'Runtime{spec.label}_{mode}'
                path = _write_certificate(output, name, result, HERE / 'SecretTrace.dfy',
                                          witness=use_witness)
                command = [str(dafny), 'verify', str(path), '--solver-path', str(solver),
                           *VERIFICATION_FLAGS]
                record = _run_proof(command, work / (name + '.log'))
                expected = EXPECTED_VERIFIED[mode]
                _require_proof(record, expected_verified=expected, label=f'{spec.key}:{mode}')
                record['certificate'] = str(path)
                record['certificate_sha256'] = digest(path)
                record['expected_verified'] = expected
                spec_proofs[mode] = record
            model_rows[spec.key] = finite_control(result, spec)
            spec_proofs['finite_controls'] = model_rows[spec.key]
            for row in model_rows[spec.key]:
                if row['requested_count'] == 64:
                    if not (row['zero_branch_taken'] and row['result_is_zero']):
                        raise RuntimePrimitiveError(
                            f'{spec.key}: count 64 must take the zero branch')
                elif not row['branch_taken']:
                    raise RuntimePrimitiveError(
                        f'{spec.key}: count {row["requested_count"]} incorrectly took the zero branch')
                elif row['model_results'][0] == row['model_results'][1]:
                    raise RuntimePrimitiveError(
                        f'{spec.key}: count {row["requested_count"]} has no private liveness')
            evidence['proofs'][spec.key] = spec_proofs
        # Private-count mutant: audit *and* the actual Dafny proof must fail.
        secret_policy, secret_overlay = primitive_policy(
            base_policy, params_overrides={spec.key: ('sec', 'sec') for spec in PRIMITIVES})
        evidence['negative_controls'] = {
            'policy_overlay_for_private_count': secret_overlay,
        }
        for spec in PRIMITIVES:
            method = bind_method(methods, spec)
            # The positive-path helper treats an audit failure as an error, so
            # translate directly here: a private count must produce a *named*
            # audit failure and then a real Dafny proof failure.
            class_policy = secret_policy['classes'][spec.owner]
            try:
                result = bt.translate(method, secret_policy, class_policy)
            except bt.PolicyError as error:
                raise RuntimePrimitiveError(
                    f'{spec.key}: private-count translation was rejected before audit: '
                    + str(error)) from error
            failures = bt.audit_certificate(result)
            named = [item['problem'] for item in failures]
            if not any('secret branch condition' in item for item in named):
                raise RuntimePrimitiveError(
                    f'{spec.key}: private count did not produce a named secret-branch audit failure')
            program_diff = _private_count_program_diff(positive_results[spec.key], result)
            name = f'Runtime{spec.label}_PrivateCount_audit'
            path = _write_certificate(output, name, result, HERE / 'SecretTrace.dfy')
            command = [str(dafny), 'verify', str(path), '--solver-path', str(solver),
                       *VERIFICATION_FLAGS]
            record = _run_proof(command, work / (name + '.log'))
            _require_private_count_failure(
                record, certificate_path=path, model_path=HERE / 'SecretTrace.dfy',
                label=f'{spec.key}:private-count')
            evidence['negative_controls'][spec.key] = {
                'audit': named, 'dafny': record,
                'certificate': str(path), 'certificate_sha256': digest(path),
                'audit_alone_is_not_a_universal_theorem': True,
                'dafny_obligation_failed': record['obligation'],
                'anchor_status': record['anchor_status'],
                'anchor': record['anchor'],
                'program_diff': program_diff,
            }
        entry = read_helpers_entry(jar)
        evidence['binding_controls'] = _jar_controls(jar, entry, work)
        evidence['binding_controls'].update(_body_controls(methods, work))
        java_rows = java_adapter(output, jar, java_home)
        evidence['java_adapter'] = java_rows
        evidence['java_adapter']['comparison'] = check_java_adapter(
            java_rows['rows'], model_rows)
        # Bind the artifact and the loaded modules again after the proofs and
        # controls: a jar or pinned source changed mid-run must not leave a
        # successful-looking report.
        if digest(jar) != bound['jar_sha256']:
            raise RuntimePrimitiveError('DafnyRuntime changed during replay')
        if digest_bytes(read_helpers_entry(jar)) != bound['entry_sha256']:
            raise RuntimePrimitiveError('Helpers.class entry changed during replay')
        module_binding_after = bind_loaded_modules(
            {'bytecode_trace': bt, 'composition': comp, 'trace_exec': trace_exec},
            inputs_path=inputs_path)
        evidence['module_binding']['after'] = module_binding_after
        evidence['pins_after'] = check_input_pins(inputs_path, {
            'policy': policy_path,
            'extractor': Path(bt.__file__),
            'model': HERE / 'SecretTrace.dfy',
            'composition': Path(comp.__file__),
            'trace_exec': Path(trace_exec.__file__),
        })
        evidence['binding_stability'] = require_stable_binding(
            module_binding_before, module_binding_after,
            evidence['pins'], evidence['pins_after'])
        evidence['status'] = 'verified'
        return evidence
    except Exception as error:  # noqa: BLE001 - evidence records the failing gate
        evidence['status'] = 'failed'
        evidence['error'] = str(error)
        raise
    finally:
        evidence['generated_at'] = _tool_version(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'])
        _write_json(evidence_path, evidence)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=REPO / 'target/runtime-primitives')
    parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
    parser.add_argument('--inputs', type=Path, default=DEFAULT_INPUTS)
    parser.add_argument('--extractor', type=Path, default=DEFAULT_EXTRACTOR)
    parser.add_argument('--jar', type=Path, default=DEFAULT_JAR)
    parser.add_argument('--dafny', type=Path, default=DEFAULT_DAFNY)
    parser.add_argument('--solver', type=Path, default=DEFAULT_SOLVER)
    parser.add_argument('--java-home', type=Path, default=DEFAULT_JAVA_HOME)
    args = parser.parse_args(argv)
    try:
        evidence = replay(args.output, policy_path=args.policy, inputs_path=args.inputs,
                          extractor_path=args.extractor, jar=args.jar, dafny=args.dafny,
                          solver=args.solver, java_home=args.java_home)
    except Exception as error:  # noqa: BLE001 - CLI reports the failed gate
        print(str(error), file=sys.stderr)
        print('Failed: ' + str((Path(args.output) / 'runtime-primitives.json').resolve()),
              file=sys.stderr)
        return 1
    print('Complete: ' + str((Path(args.output) / 'runtime-primitives.json').resolve()))
    print('Proofs: ' + ', '.join(
        f'{key}={value["with_witness"]["verified"]}/{value["without_witness"]["verified"]}'
        for key, value in evidence['proofs'].items()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
