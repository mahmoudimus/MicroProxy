"""Fail-closed bytecode -> SecretTrace certificate extractor.

This module is the *trusted implementation bridge* for formal/timing. It reads a
real class file through ``javap``, structurally rejects anything outside the
reviewed language, and emits a `SecretTrace.Program` (a flat control-flow
machine) plus taint annotations derived only from the declarative policy.

What is checked by Dafny (`SecretTrace.Structure`) over the emitted program:

  * every branch condition register is public,
  * every array index register is public,
  * every allocation size register is public,
  * every provider/dispatch target is a fixed policy constant with declared
    public arguments,
  * a public call result may not depend on a secret argument,
  * reading a secret array cannot be annotated public, and a public array may
    only be written with public data at public indices.

What this bridge itself asserts (trusted, unit- and mutation-tested, not
formally verified):

  * the operand mapping from JVM slots/stack to certificate registers,
  * the policy classification of method parameters, fields, allocations and
    call results,
  * that every JVM instruction is translated (anything unlisted fails closed),
  * the control-flow graph and exception-free shape of the reviewed methods,
  * that ``javap`` faithfully describes the actual class file.

Excluded: JVM/JIT/CPU/provider timing, implicit JVM exceptions, GC, and exact
arithmetic/value refinement (the certificate records dependency shape and an
abstract deterministic word operation, not machine semantics).
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

# IR step kinds (shared with SecretTrace.Apply's illustrative switch); values
# beyond the switch fall through to a deterministic fallback and are still
# distinguished by their integer kind in the trace.
KIND = {
    'add': 2, 'sub': 5, 'mul': 6, 'and': 3, 'or': 4, 'xor': 0,
    'neg': 7, 'cast': 8, 'shl': 9, 'shr': 10, 'ushr': 11,
    'cmp': 1, 'copy': 12, 'test': 13,
    'eq': 14, 'ne': 15, 'gt': 16, 'ge': 17, 'lt': 18, 'le': 19,
}


class PolicyError(RuntimeError):
    pass


# Mandatory classification for enumerated external runtime/JDK calls. The
# extractor and the independent audit both enforce it; it is not a JSON success
# flag. The pinned DafnyRuntime 4.9.1 `DafnyEuclidean` overloads branch on the
# dividend/divisor value (e.g. EuclideanModulus(II)I offsets 22/50/64/120), so
# admitting them with a secret argument would hide known private control flow.
# `Helpers.bv64ShiftRight` branches only on the shift count; the shifted value
# may be private. `Byte.toUnsignedLong/Int` are branch-free casts.
#
# The default covers **every scalar argument and every heap (array/sequence)
# content argument** of an ordinary external `Call` step. Secret array/sequence
# contents are the same kind of value-dependent input as a secret scalar: the
# runtime may branch on them, and the model's `Call` step is atomic, so it cannot
# see those branches. Checked roots need no heap-content exception; abstract
# array load/length instructions (`Load`/`LenOf`/`Alloc`) are separate model
# steps and are not ordinary calls, so they are unaffected by this gate.
PRIVATE_SAFE_RUNTIME_CALLS = {
    'java/lang/Byte.toUnsignedLong:(B)J',
    'java/lang/Byte.toUnsignedInt:(B)I',
}
SHIFT_COUNT_PUBLIC_RUNTIME_CALLS = {
    # Both exact pinned-runtime bodies are replayed by runtime_primitives.py
    # before the mandatory Keccak helper certificates. Counts must be public;
    # words may be private. Private counts fail the audit and body proof.
    'dafny/Helpers.bv64ShiftLeft:(JB)J',
    'dafny/Helpers.bv64ShiftRight:(JB)J',
}
#: Reviewed targets whose *heap contents* may be secret even though the call is
#: an ordinary external `Call`. Empty by construction: the checked roots pass no
#: secret array/sequence content to any external call, and a target may only be
#: listed here with a per-target justification. Adding an entry here is the
#: documented review point for a future constant-time primitive.
PUBLIC_HEAP_EXCEPTIONS: dict[str, str] = {}
#: Enumerated *modeled* external kinds: the extractor replaces these with
#: abstract `alloc`/`load`/`len`/`fill` steps instead of an atomic `Call`, so
#: their real runtime code is a reviewed memory/shape primitive rather than an
#: opaque dispatch (DafnySequence length/select/concat/toRawArray, TypeDescriptor
#: newArray/fillThenReturnArray, Object identity/requireNonNull). The
#: public-argument gate below applies to ordinary `Call` steps only; every other
#: kind must be in this set, so an unknown kind cannot dodge the gate.
MODELED_PRIMITIVE_KINDS = frozenset({
    'identity', 'requireNonNull', 'length', 'getfield', 'alloc', 'empty',
    'seq_of', 'seq_concat', 'seq_take', 'seq_to_array', 'clone', 'seq_load',
    'fill', 'new',
})
#: Enumerated standard-runtime/Dafny package prefixes whose *ordinary* calls are
#: governed by the public-argument gate above. Deliberately an exhaustive list of
#: reviewed runtime namespaces (`dafny/` = pinned DafnyRuntime, `java/`, `javax/`,
#: `jdk/`, `sun/`, `com/sun/` = JDK modules, including the JDK's own internal
#: provider code). A target under any *other* prefix is not admitted by any
#: checked certificate and is outside this claim: arbitrary third-party library
#: calls are not covered. The list is drift-checked against `policy.json`
#: (`external_runtime_prefixes`) so a policy edit cannot silently widen or narrow
#: what the report claims to have enforced.
EXTERNAL_RUNTIME_PREFIXES = ('dafny/', 'java/', 'javax/', 'jdk/', 'sun/', 'com/sun/')


def runtime_call_public_ok(target: str, arg_taints: list[str],
                          heap_taints: list[str] = ()) -> bool:
    """Whether an external runtime/JDK call is admitted for these taints.

    Owned calls return True here; their opaque contracts are reported separately.
    For external calls the default is public scalar **and** public heap-content
    arguments. The only reviewed exceptions are the branch-free byte casts (any
    scalar taint, no heap arguments in practice) and bv64ShiftRight (the shift
    count argument must be public; the shifted value may be secret).
    """
    if not target.startswith(EXTERNAL_RUNTIME_PREFIXES):
        return True
    heap_public = all(t == 'pub' for t in heap_taints)
    if not heap_public and target not in PUBLIC_HEAP_EXCEPTIONS:
        return False
    if target in PRIVATE_SAFE_RUNTIME_CALLS:
        return True
    if target in SHIFT_COUNT_PUBLIC_RUNTIME_CALLS:
        return len(arg_taints) >= 2 and arg_taints[1] == 'pub'
    return all(t == 'pub' for t in arg_taints)


def runtime_call_problem(target: str, arg_taints: list[str],
                         heap_taints: list[str] = ()):
    if runtime_call_public_ok(target, arg_taints, heap_taints):
        return None
    secret_heap = [t for t in heap_taints if t != 'pub']
    if secret_heap and target not in PUBLIC_HEAP_EXCEPTIONS:
        return f'public-argument-only runtime call {target} with secret heap argument'
    return f'public-argument-only runtime call {target} with secret argument'


def check_runtime_classification(policy: dict) -> dict:
    """Fail closed on drift between the declared and enforced classification.

    The admission tables that the extractor and audit actually use live in this
    module. `policy.json` records the same sets for review and reporting; this
    gate refuses to run if the record and the code disagree, so the report can
    never describe a classification that was not enforced.
    """
    declared = policy.get('runtime_classification')
    if not isinstance(declared, dict):
        raise RuntimeError('runtime classification is not declared in the policy')
    checks = (
        ('private_safe', 'private-safe runtime call',
         set(declared.get('private_safe', [])), PRIVATE_SAFE_RUNTIME_CALLS),
        ('shift_count_public', 'shift-count-public runtime call',
         set(declared.get('shift_count_public', [])), SHIFT_COUNT_PUBLIC_RUNTIME_CALLS),
        ('public_heap_exceptions', 'public-heap runtime call exception',
         set(declared.get('public_heap_exceptions', [])), set(PUBLIC_HEAP_EXCEPTIONS)),
        ('modeled_primitive_kinds', 'modeled external primitive kind',
         set(declared.get('modeled_primitive_kinds', [])), set(MODELED_PRIMITIVE_KINDS)),
        ('external_runtime_prefixes', 'external runtime prefix',
         set(declared.get('external_runtime_prefixes', [])), set(EXTERNAL_RUNTIME_PREFIXES)),
    )
    for key, label, recorded, enforced in checks:
        if recorded != enforced:
            raise RuntimeError(
                'runtime classification drift for ' + label + ': policy='
                + repr(sorted(recorded)) + ' code=' + repr(sorted(enforced)))
    for entry in declared.get('public_heap_exceptions', []):
        if entry not in PUBLIC_HEAP_EXCEPTIONS:
            raise RuntimeError('public-heap exception has no code justification: ' + entry)
    return declared


@dataclass
class Insn:
    offset: int
    op: str
    operand: str
    text: str


@dataclass
class Method:
    owner: str
    name: str
    descriptor: str
    static: bool
    flags: set[str]
    insns: list[Insn]
    handlers: list[tuple[int, int, int, str]] = field(default_factory=list)
    switches: dict[int, tuple[list[tuple[int, int]], int]] = field(default_factory=dict)
    #: `javap` printed an `Exception table:` block for this method. Recorded
    #: independently of `handlers` so that an empty or unparseable table still
    #: fails closed; the translator rejects any method with a declared table.
    exception_table: bool = False

    @property
    def key(self) -> str:
        return f'{self.owner}.{self.name}:{self.descriptor}'


#: `javap` writes this non-numeric header row before the exception-table rows.
#: It is not a row: treating it as one ended table parsing before any real row
#: was read, so a method with handlers parsed as handler-free.
EXCEPTION_TABLE_HEADER = re.compile(r'^from\s+to\s+target\s+type$')

#: A real `javap` exception-table row: `start end handler type`, where the type
#: is `Class <name>`, `any`, or another javap class reference.
EXCEPTION_TABLE_ROW = re.compile(r'^(\d+)\s+(\d+)\s+(\d+)\s+(\S.*)$')

#: `javap` prints a method declaration's `throws` clause instead of a trailing
#: `);` when the method declares checked or runtime exceptions. The old header
#: rule missed these declarations, so their `descriptor:`/`Code:` block was
#: attributed to the preceding method (duplicate offsets, silently dropped body).
THROWS_DECLARATION = re.compile(r'\)\s*throws\s+[\w.$]+(?:\s*,\s*[\w.$]+)*\s*;\s*$')


def is_member_declaration(raw: str, line: str) -> bool:
    """True for a javap member declaration line (field, method or `static {}`).

    `javap -c -p -s` prints every member declaration with exactly two spaces of
    indentation and terminates it with `;`; attributes and instructions are
    indented deeper, so this distinguishes a member boundary from a `descriptor:`,
    `flags:`, `Code:` or instruction line without guessing from content.
    """
    return (raw.startswith('  ') and raw[2:3] not in ('', ' ', '\t')
            and line.endswith(';'))


def check_offsets(method: Method) -> None:
    """Fail closed unless bytecode offsets are strictly increasing.

    A member body merged into the wrong `Method` (or a hand-built one) shows up
    as a repeated or backwards offset. Checking before CFG construction keeps
    such a body out of a certificate instead of letting it silently reshape the
    control-flow graph.
    """
    previous = -1
    for insn in method.insns:
        if insn.offset <= previous:
            raise PolicyError(
                f'{method.key}: non-increasing bytecode offset {insn.offset} after '
                f'{previous}; refusing to build a control-flow graph')
        previous = insn.offset


def parse(text: str, owner: str) -> dict[str, Method]:
    """Parse javap -c -p -s output into methods keyed by name:descriptor.

    Member boundaries come from javap's layout: a member declaration is a line
    indented by exactly two spaces and terminated by `;` (fields, methods
    including `throws` clauses, and `static {};`). Every `descriptor:`, `Code:`
    array and exception table is bound to the most recent declaration; a
    descriptor or `Code:` array that cannot be bound to a recognised method is a
    hard error instead of being attributed to the preceding method, and offsets
    must be strictly increasing. `-c -p -s` is the supported javap mode.
    """
    methods: dict[str, Method] = {}
    current: Method | None = None
    state = None  # 'code' | 'table' | 'switch' | None
    pending_switch = None
    member = None  # None | 'method' | 'field' | 'unknown' (last declaration seen)
    descriptor_seen = False  # the current member's `descriptor:` has been bound
    code_seen = False        # the current method's `Code:` array has been opened
    for raw in text.splitlines():
        line = raw.strip()
        if line in ('static {};', 'static {}'):
            current = Method(owner, '<clinit>', '()V', True, {'ACC_STATIC'}, [], [])
            methods['<clinit>:()V'] = current
            state = 'header'
            member = 'method'
            descriptor_seen = False
            code_seen = False
            continue
        if is_member_declaration(raw, line):
            name_match = None
            if '(' in line and (re.search(r'\);\s*$', line) or THROWS_DECLARATION.search(line)):
                name_match = re.search(r'([\w.$<>]+)\(', line)
            if name_match:
                current = Method(owner, name_match[1], '', bool(re.search(r'\bstatic\b', line)),
                                 {'ACC_STATIC'} if re.search(r'\bstatic\b', line) else set(), [], [])
                state = 'header'
                member = 'method'
            else:
                # A field declaration or a method declaration this parser cannot
                # recognise. Neither may inherit the preceding method's state, and
                # a `Code:` array under it is rejected below (orphan body).
                member = 'field' if '(' not in line else 'unknown'
                state = None
            descriptor_seen = False
            code_seen = False
            continue
        # Table presence is detected from the actual javap header in every
        # parser state, before any state-specific handling can consume the line.
        if line.startswith('Exception table:'):
            if current is None or member != 'method':
                raise PolicyError(f'{owner}: exception table outside a method body: {line}')
            current.exception_table = True
            state = 'table'
            continue
        if state == 'switch' and current is not None:
            m = re.match(r'^(-?\d+):\s*(\d+)$', line)
            if m:
                pending_switch[0].append((int(m.group(1)), int(m.group(2))))
                continue
            m = re.match(r'^default:\s*(\d+)$', line)
            if m:
                pending_switch[1] = int(m.group(1))
                continue
            if line in ('}', ''):
                if pending_switch is not None and pending_switch[2] is not None:
                    current.switches[pending_switch[2]] = (pending_switch[0], pending_switch[1])
                pending_switch = None
                state = 'code'
                continue
            raise PolicyError(f'unparsed switch table line: {line}')
        if state == 'table' and current is not None:
            if EXCEPTION_TABLE_HEADER.match(line):
                continue
            row = EXCEPTION_TABLE_ROW.match(line)
            if row:
                current.handlers.append((int(row[1]), int(row[2]), int(row[3]), row[4].strip()))
                continue
            if re.match(r'^\d', line):
                # A row-shaped line that does not parse must never be skipped:
                # the protected ranges it describes would be silently lost.
                raise PolicyError(f'{current.key}: malformed exception table row: {line}')
            state = None
            # The line is not a table row; fall through so the remaining rules
            # see it. `exception_table` already forces rejection for this method.
        if state == 'code' and current is not None:
            code = re.match(r'^(\d+):\s+(\w+)\s*(.*)$', line)
            if code:
                insn = Insn(int(code[1]), code[2], code[3].strip(), line)
                if current.insns and insn.offset <= current.insns[-1].offset:
                    raise PolicyError(
                        f'{current.key}: non-increasing bytecode offset {insn.offset} after '
                        f'{current.insns[-1].offset}; refusing to build a control-flow graph')
                current.insns.append(insn)
                if insn.op in ('tableswitch', 'lookupswitch'):
                    state = 'switch'
                    pending_switch = [[], None, insn.offset]
                continue
            if line.startswith(('LineNumberTable:', 'LocalVariableTable:', 'StackMapTable:')):
                state = None
                continue
            if line == '':
                continue
            # Any other trailing attribute ends the code array.
            state = None
        if line.startswith('descriptor:'):
            if member == 'method' and state == 'header' and not descriptor_seen:
                current.descriptor = line.split('descriptor:', 1)[1].strip()
                methods[f'{current.name}:{current.descriptor}'] = current
                descriptor_seen = True
                state = 'flags'
                continue
            if member == 'field' and not descriptor_seen and state is None:
                # A field's descriptor carries no certificate meaning; it must
                # never be silently bound to a method.
                descriptor_seen = True
                continue
            raise PolicyError(f'{owner}: descriptor for an unrecognised member: {line}')
        if current is not None and state == 'header':
            if line.startswith('flags:'):
                current.flags = set(re.findall(r'ACC_\w+', line))
                current.static = 'ACC_STATIC' in current.flags
                state = None
                continue
            if line.startswith(('Code:', 'Exceptions:')):
                state = None
        if line.startswith('flags:') and current is not None:
            current.flags = set(re.findall(r'ACC_\w+', line))
            current.static = 'ACC_STATIC' in current.flags
        if line == 'Code:':
            if member != 'method' or not descriptor_seen or code_seen or current is None:
                raise PolicyError(
                    f'{owner}: Code array without a recognised method declaration: {line}')
            code_seen = True
            state = 'code'
            continue
    return methods


def disassemble(javap: Path, classpath: Path, classname: str) -> dict[str, Method]:
    result = subprocess.run([str(javap), '-c', '-p', '-s', '-classpath', str(classpath), classname],
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise PolicyError(f'javap failed for {classname}: {result.stderr.strip()}')
    return parse(result.stdout, classname.replace('.', '/'))


# ---------- bytecode shape helpers ----------

TYPE_WIDTH = {'J': 2, 'D': 2}


def descriptor_types(descriptor: str):
    def one(at):
        start = at
        while descriptor[at] == '[':
            at += 1
        if descriptor[at] == 'L':
            at = descriptor.index(';', at) + 1
        else:
            at += 1
        return descriptor[start:at], at
    at = 1
    args = []
    while descriptor[at] != ')':
        value, at = one(at)
        args.append(value)
    result, _ = one(at + 1)
    return args, result


def width(t: str) -> int:
    return 2 if t in ('J', 'D') else 1


def method_ref(operand: str):
    """Return (owner|'', name, descriptor) for a javap invocation comment."""
    m = re.search(r'//\s+(?:Interface)?Method\s+("[^"]+"|[\w/$]+)\.("?[\w$<>]+"?):(\([^)]*\)\S+)', operand)
    if m:
        return m[1].strip('"'), m[2].strip('"'), m[3]
    m = re.search(r'//\s+(?:Interface)?Method\s+("[\w$<>]+"|[\w$<>]+):(\([^)]*\)\S+)', operand)
    if m:
        return '', m[1].strip('"'), m[2]
    return None


def field_ref(operand: str):
    """Return (owner|'', name, descriptor) for a javap field comment."""
    m = re.search(r'//\s+Field\s+([\w/$]+)\.([\w$]+):(\S+)', operand)
    if m:
        return m[1], m[2], m[3]
    m = re.search(r'//\s+Field\s+([\w$]+):(\S+)', operand)
    if m:
        return '', m[1], m[2]
    return None


# ---------- CFG ----------

COND_BRANCH = {
    'ifeq', 'ifne', 'iflt', 'ifge', 'ifgt', 'ifle', 'ifnull', 'ifnonnull',
    'if_icmpeq', 'if_icmpne', 'if_icmplt', 'if_icmpge', 'if_icmpgt', 'if_icmple',
    'if_acmpeq', 'if_acmpne',
}


def branch_target(insn: Insn) -> int | None:
    if insn.op in COND_BRANCH or insn.op in ('goto', 'goto_w'):
        m = re.match(r'(\d+)', insn.operand)
        return int(m[1]) if m else None
    return None


def cfg(method: Method) -> dict[int, list[int]]:
    offsets = [i.offset for i in method.insns]
    following = {off: (offsets[k + 1] if k + 1 < len(offsets) else None) for k, off in enumerate(offsets)}
    succ: dict[int, list[int]] = {}
    for insn in method.insns:
        if insn.op in COND_BRANCH:
            t = branch_target(insn)
            succ[insn.offset] = [t, following[insn.offset]] if t is not None and following[insn.offset] is not None else [t or following[insn.offset]]
        elif insn.op in ('goto', 'goto_w'):
            succ[insn.offset] = [branch_target(insn)]
        elif insn.op in ('ireturn', 'lreturn', 'areturn', 'freturn', 'dreturn', 'return', 'athrow'):
            succ[insn.offset] = []
        elif insn.op in ('tableswitch', 'lookupswitch'):
            if insn.offset not in method.switches:
                raise PolicyError(f'missing switch table in {method.key}@{insn.offset}')
            cases, default = method.switches[insn.offset]
            succ[insn.offset] = [t for _, t in cases] + [default]
        elif insn.op in ('ret', 'jsr', 'jsr_w'):
            raise PolicyError(f'unsupported control transfer {insn.op} in {method.key}')
        else:
            succ[insn.offset] = [following[insn.offset]] if following[insn.offset] is not None else []
    for off, targets in succ.items():
        for t in targets:
            if t not in succ:
                raise PolicyError(f'branch target {t} missing in {method.key}')
    return succ


def leaders(method: Method, succ: dict[int, list[int]]) -> list[int]:
    if not method.insns:
        raise PolicyError('empty method')
    starts = {method.insns[0].offset}
    for insn in method.insns:
        if insn.op in COND_BRANCH or insn.op in ('goto', 'goto_w'):
            starts.add(branch_target(insn))
            nxt = [i.offset for i in method.insns if i.offset > insn.offset]
            if insn.op in COND_BRANCH and nxt:
                starts.add(nxt[0])
        if insn.op in ('tableswitch', 'lookupswitch'):
            cases, default = method.switches[insn.offset]
            starts.update(t for _, t in cases)
            starts.add(default)
        if len(succ[insn.offset]) > 1:
            starts.add(succ[insn.offset][1])
    return sorted(starts)


def stack_depths(method: Method, succ: dict[int, list[int]]) -> dict[int, int]:
    """Verify the operand stack is empty at every basic-block boundary.

    Non-empty merge stacks are rejected rather than approximated: the reviewed
    methods do not use them, and a wrong stack mapping would be a bridge bug.
    """
    starts = set(leaders(method, succ))
    depth: dict[int, int] = {}
    work = [method.insns[0].offset]
    depth[method.insns[0].offset] = 0
    by_offset = {i.offset: i for i in method.insns}
    while work:
        pc = work.pop()
        d = depth[pc]
        insn = by_offset[pc]
        popped, pushed = stack_effect(insn)
        if d < popped:
            raise PolicyError(f'stack underflow at {method.key}@{pc}')
        nd = d - popped + pushed
        for target in succ[pc]:
            if target in depth:
                if depth[target] != nd:
                    raise PolicyError(f'inconsistent stack depth at {method.key}@{target}')
            else:
                depth[target] = nd
                work.append(target)
    for pc in starts:
        if pc not in depth:
            raise PolicyError(f'unreachable basic block leader {method.key}@{pc}')
    return depth


def stack_effect(insn: Insn) -> tuple[int, int]:
    """Operand-stack effect in *values* (every value counts one slot).

    Used only to require an empty operand stack at basic-block boundaries;
    run_block models the same value stack. Widths are irrelevant here.
    """
    op = insn.op
    if re.fullmatch(r'[ilfda]const_\w+', op) or op in ('bipush', 'sipush', 'ldc', 'ldc_w', 'ldc2_w', 'aconst_null'):
        return (0, 1)
    if re.fullmatch(r'[ailfd]load(?:_\d+)?', op):
        return (0, 1)
    if re.fullmatch(r'[ailfd]store(?:_\d+)?', op):
        return (1, 0)
    if op == 'dup': return (1, 2)
    if op == 'dup_x1': return (2, 3)
    if op == 'dup_x2': return (3, 4)
    if op == 'dup2': return (2, 4)
    if op == 'dup2_x1': return (3, 5)
    if op == 'dup2_x2': return (4, 6)
    if op == 'swap': return (2, 2)
    if op == 'pop': return (1, 0)
    if op == 'pop2': return (2, 0)
    if op in ('iadd','isub','imul','idiv','irem','iand','ior','ixor','ishl','ishr','iushr',
              'ladd','lsub','lmul','ldiv','lrem','land','lor','lxor','lshl','lshr','lushr',
              'fadd','fsub','fmul','fdiv','frem','dadd','dsub','dmul','ddiv','drem'):
        return (2, 1)
    if op in ('lcmp', 'fcmpl', 'fcmpg', 'dcmpl', 'dcmpg'):
        return (2, 1)
    if re.fullmatch(r'[ilfd]neg', op) or op in ('i2l', 'i2f', 'i2d', 'l2i', 'l2f', 'l2d',
              'f2i', 'f2l', 'f2d', 'd2i', 'd2l', 'd2f', 'i2b', 'i2c', 'i2s'):
        return (1, 1)
    if op == 'arraylength': return (1, 1)
    if op in ('getfield',): return (1, 1)
    if op in ('getstatic',): return (0, 1)
    if op == 'newarray': return (1, 1)
    if op == 'anewarray': return (1, 1)
    if op == 'multianewarray': raise PolicyError('multianewarray outside certificate')
    if op == 'new': return (0, 1)
    if op in ('checkcast', 'instanceof'): return (1, 1)
    if op in ('monitorenter', 'monitorexit'): return (1, 0)
    if op == 'athrow': return (1, 0)
    if re.fullmatch(r'[ilfdabcs]aload', op): return (2, 1)
    if re.fullmatch(r'[ilfdabcs]astore', op): return (3, 0)
    if op == 'putfield': return (2, 0)
    if op == 'putstatic': return (1, 0)
    if op in ('iinc', 'nop', 'goto', 'goto_w'): return (0, 0)
    if op in ('tableswitch', 'lookupswitch'): return (1, 0)
    if op == 'invokedynamic':
        m = re.search(r':\(([^)]*)\)', insn.operand)
        if not m:
            raise PolicyError('unparsed invokedynamic')
        return (len(descriptor_types('(' + m.group(1) + ')V')[0]), 1)
    if op in COND_BRANCH:
        if op in ('ifnull', 'ifnonnull'): return (1, 0)
        if op.startswith(('if_icmp', 'if_acmp')): return (2, 0)
        return (1, 0)
    if op in ('ireturn', 'lreturn', 'freturn', 'dreturn', 'areturn'): return (1, 0)
    if op == 'return': return (0, 0)
    if op.startswith('invoke'):
        m = method_ref(insn.operand)
        if not m:
            raise PolicyError(f'unparsed invocation: {insn.text}')
        _, _, desc = m
        args, result = descriptor_types(desc)
        return (len(args) + (0 if op == 'invokestatic' else 1), 0 if result == 'V' else 1)
    raise PolicyError(f'unsupported opcode {op}: {insn.text}')


# ---------- translation to a SecretTrace certificate ----------

BRANCH_KIND = {
    'ifeq': 'eq', 'ifne': 'ne', 'iflt': 'lt', 'ifge': 'ge', 'ifgt': 'gt', 'ifle': 'le',
    'if_icmpeq': 'eq', 'if_icmpne': 'ne', 'if_icmplt': 'lt', 'if_icmpge': 'ge',
    'if_icmpgt': 'gt', 'if_icmple': 'le', 'if_acmpeq': 'eq', 'if_acmpne': 'ne',
    'ifnull': 'eq', 'ifnonnull': 'ne',
}

ARITH_KIND = {
    'iadd': 'add', 'ladd': 'add', 'isub': 'sub', 'lsub': 'sub',
    'imul': 'mul', 'lmul': 'mul', 'iand': 'and', 'land': 'and',
    'ior': 'or', 'lor': 'or', 'ixor': 'xor', 'lxor': 'xor',
    'ishl': 'shl', 'lshl': 'shl', 'ishr': 'shr', 'lshr': 'shr',
    'iushr': 'ushr', 'lushr': 'ushr',
}

LOAD_OPS = {'iaload': 1, 'baload': 1, 'caload': 1, 'saload': 1, 'aaload': 1,
            'laload': 2, 'daload': 2}
STORE_OPS = {'iastore': 1, 'bastore': 1, 'castore': 1, 'sastore': 1, 'aastore': 1,
             'lastore': 2, 'dastore': 2}
UNARY_KIND = {'ineg': 'neg', 'lneg': 'neg', 'i2b': 'cast', 'i2c': 'cast', 'i2s': 'cast',
              'i2l': 'cast', 'l2i': 'cast', 'i2f': 'cast', 'f2i': 'cast', 'f2l': 'cast',
              'l2f': 'cast', 'f2l': 'cast', 'checkcast': 'cast'}
CMP_OPS = {'lcmp': 'cmp', 'fcmpl': 'cmp', 'fcmpg': 'cmp', 'dcmpl': 'cmp', 'dcmpg': 'cmp'}


def _int_literal(operand: str):
    m = re.search(r'//\s+(int|long)\s+(-?\d+)[lL]?\s*$', operand)
    if m:
        return int(m[2])
    raise PolicyError(f'non-integer constant: {operand}')


def _max_local(method: Method) -> int:
    top = 0
    for insn in method.insns:
        m = re.match(r'(?:([ailf])(?:load|store)_(\d+))$', insn.op)
        if m:
            top = max(top, int(m[2]) + (1 if m[1] in 'ilfa' else 2))
        elif re.fullmatch(r'[ailf](load|store)', insn.op):
            idx = int(insn.operand.split()[0])
            top = max(top, idx + (2 if insn.op.startswith(('l', 'd')) else 1))
        elif insn.op == 'iinc':
            top = max(top, int(insn.operand.split(',')[0]) + 1)
    return top


class Translator:
    """SSA translation of one method into a SecretTrace certificate.

    Every value is a fresh register (SSA); loop-carried locals get explicit phi
    registers written by edge-copy instructions. Taint is computed by a
    monotone fixpoint over that SSA graph, so a register's annotation is the
    union of all definitions that reach it (never narrower). Array roles are
    flow-sensitive metadata used only to pick the Load/Store role.
    """

    def __init__(self, method: Method, policy: dict, class_policy: dict):
        self.m = method
        self.policy = policy
        self.cp = class_policy
        # Both gates run before any CFG/stack analysis so that a rejected body is
        # diagnosed by its actual defect (table presence, merged offsets) rather
        # than by a downstream symptom of the corrupted instruction list.
        if method.exception_table or method.handlers:
            raise PolicyError(f'{method.key}: exception table is outside the accepted language')
        check_offsets(method)
        self.succ_offsets = cfg(method)
        self.depth = stack_depths(method, self.succ_offsets)
        self.leaders = leaders(method, self.succ_offsets)
        self.block_of = {lead: i for i, lead in enumerate(self.leaders)}
        self.by_offset = {i.offset: i for i in method.insns}
        self.nblocks = len(self.leaders)
        self.max_local = _max_local(method)
        self.roles: dict[str, str] = {}
        self.sites: list[dict] = []
        self.site_n = 0
        self.call_targets: dict[str, int] = {}
        self.next_reg = 0
        self.def_taints: dict[int, str] = {}
        self.result_ids: dict[int, int] = {}
        self.write_ids: dict[int, int] = {}
        self.phi_ids: dict[tuple[int, int], int] = {}
        self.entry_ids: dict[int, dict[int, int]] = {i: {} for i in range(self.nblocks)}
        self.entry_taints: dict[int, dict[int, str]] = {i: {} for i in range(self.nblocks)}
        self.out_ids: dict[int, dict[int, int]] = {}
        self.out_taints: dict[int, dict[int, str]] = {}
        self.entry_stack_ids: dict[int, dict[int, int]] = {i: {} for i in range(self.nblocks)}
        self.entry_stack_taints: dict[int, dict[int, str]] = {i: {} for i in range(self.nblocks)}
        self.out_stack_ids: dict[int, dict[int, int]] = {}
        self.out_stack_taints: dict[int, dict[int, str]] = {}
        self.stack_phi_ids: dict[tuple[int, int], int] = {}
        self.edge_copies: dict[tuple[int, int], list[tuple[int, int]]] = {}
        self.edge_block: dict[tuple[int, int], int] = {}
        self.role_entry: dict[int, dict[int, str | None]] = {}

    # -- allocation --
    def alloc(self, taint: str) -> int:
        reg = self.next_reg
        self.next_reg += 1
        self.def_taints[reg] = taint
        return reg

    def result_id(self, pc: int) -> int:
        if pc not in self.result_ids:
            self.result_ids[pc] = self.alloc('pub')
        return self.result_ids[pc]

    def write_id(self, pc: int) -> int:
        if pc not in self.write_ids:
            self.write_ids[pc] = self.alloc('pub')
        return self.write_ids[pc]

    def stack_phi(self, block: int, index: int) -> int:
        key = (block, index)
        if key not in self.stack_phi_ids:
            self.stack_phi_ids[key] = self.alloc('pub')
        return self.stack_phi_ids[key]

    def phi_id(self, block: int, slot: int) -> int:
        key = (block, slot)
        if key not in self.phi_ids:
            self.phi_ids[key] = self.alloc('pub')
        return self.phi_ids[key]

    def site(self, pc: int, what: str) -> int:
        n = self.site_n
        self.site_n += 1
        self.sites.append({'site': n, 'class': self.m.owner, 'method': self.m.name,
                           'descriptor': self.m.descriptor, 'offset': pc, 'what': what})
        return n

    def or_(self, *ts: str) -> str:
        return 'sec' if any(t == 'sec' for t in ts) else 'pub'

    def add_role(self, role: str, taint: str):
        self.roles[role] = self.or_(self.roles.get(role, 'pub'), taint)

    def taint_role(self, role: str) -> str:
        if role not in self.roles:
            self.roles[role] = 'sec'
            return 'sec'
        return self.roles[role]

    def dispatch_allowed(self, op: str, owner: str, name: str, desc: str) -> bool:
        if op == 'invokestatic' or op == 'invokespecial':
            return True
        if op in ('invokevirtual', 'invokeinterface'):
            externals = set(self.policy.get('external_dispatch', []))
            if owner in externals or owner.startswith('['):
                return True
            key = f'{owner}.{name}:{desc}'
            allowed = self.policy.get('virtual_allow', {})
            return allowed.get(key) == 'final-or-closed'
        return False

    def lambda_rule(self, operand: str):
        return any(pat in operand for pat in self.policy.get('lambdas', []))

    def call_rule(self, target: str):
        local = self.cp.get('methods', {}).get(f'{self.m.name}:{self.m.descriptor}', {}).get('calls', {})
        if target in local:
            return local[target]
        return self.policy.get('calls', {}).get(target)

    # -- inputs --
    def setup_params(self):
        args, _ = descriptor_types(self.m.descriptor)
        declared = self.cp.get('methods', {}).get(f'{self.m.name}:{self.m.descriptor}', {}).get('params')
        if declared is None:
            raise PolicyError(f'{self.m.key}: no parameter policy')
        if len(declared) != len(args):
            raise PolicyError(f'{self.m.key}: parameter policy length mismatch')
        self.param_reg = {}
        self.param_taint = {}
        self.param_role = {}
        self.param_order: list[int] = []
        zero = self.alloc('pub')
        if zero != 0:
            raise PolicyError('zero register must be 0')
        slot = 0
        if not self.m.static:
            self.param_reg[slot] = self.alloc('pub')
            self.param_taint[slot] = 'pub'
            self.param_role[slot] = None
            slot = 1
        for i, (t, value) in enumerate(zip(args, declared)):
            reg = self.alloc('pub' if value in ('pub', 'array_pub', 'array_sec', 'seq_pub', 'seq_sec') else 'sec')
            self.param_reg[slot] = reg
            self.param_order.append(reg)
            if value in ('pub', 'sec'):
                self.param_taint[slot] = value
                self.param_role[slot] = None
            elif value in ('array_pub', 'array_sec', 'seq_pub', 'seq_sec'):
                role = f'{self.m.owner}.{self.m.name}#p{i}'
                self.add_role(role, 'pub' if value.endswith('_pub') else 'sec')
                self.param_taint[slot] = 'pub'
                self.param_role[slot] = role
            else:
                raise PolicyError(f'{self.m.key}: bad parameter policy {value}')
            slot += width(t)
        self.param_slots = sorted(self.param_reg)
        self.inputs = self.next_reg
        self.written: set[int] = set()
        for insn in self.m.insns:
            mm = re.fullmatch(r'[ailf]store(?:_(\d+))?', insn.op)
            if mm:
                self.written.add(int(mm[1]) if mm[1] is not None else int(insn.operand.split()[0]))
            elif insn.op == 'iinc':
                self.written.add(int(insn.operand.split(',')[0]))
        for slot in self.written:
            if slot not in self.param_reg:
                self.param_reg[slot] = self.alloc('pub')
                self.param_taint[slot] = 'pub'
                self.param_role[slot] = None
        self.entry_ids[0] = dict(self.param_reg)
        self.entry_taints[0] = dict(self.param_taint)

    # -- role analysis (metadata only) --
    def block_insns(self, bi: int):
        lead = self.leaders[bi]
        end = self.leaders[bi + 1] if bi + 1 < len(self.leaders) else None
        return [i for i in self.m.insns if i.offset >= lead and (end is None or i.offset < end)]

    def role_merge(self, a, b):
        if a == b:
            return a
        if a == 'ambig' or b == 'ambig':
            return 'ambig'
        if a is None or b is None:
            return 'ambig'
        parts = set()
        for role in (a, b):
            if str(role).startswith('merge:'):
                parts.update(str(role)[6:].split('|'))
            else:
                parts.add(str(role))
        key = parts.pop() if len(parts) == 1 else 'merge:' + '|'.join(sorted(parts))
        self.add_role(key, self.or_(self.taint_role(a), self.taint_role(b)))
        return key

    def role_pass(self):
        entry = {bi: {} for bi in range(self.nblocks)}
        for slot, role in self.param_role.items():
            entry[0][slot] = role
        changed, rounds = True, 0
        while changed:
            changed = False
            rounds += 1
            if rounds > 64:
                raise PolicyError(f'{self.m.key}: array-role analysis did not converge')
            for bi in range(self.nblocks):
                state = dict(entry[bi])
                stack = [(None, 1)] * self.depth.get(self.leaders[bi], 0)
                for insn in self.block_insns(bi):
                    op, pc = insn.op, insn.offset
                    def push(r, w=1):
                        stack.append((r, w))
                    def pop():
                        if not stack:
                            raise PolicyError(f'{self.m.key}@{pc}: role stack underflow')
                        return stack.pop()
                    if re.fullmatch(r'[ilf]const_.*', op) or op in ('bipush', 'sipush', 'ldc', 'ldc_w', 'aconst_null'):
                        push(None)
                    elif op in ('lconst_0', 'lconst_1', 'ldc2_w'):
                        push(None, 2)
                    elif re.fullmatch(r'[ailf]load(?:_\d+)?', op):
                        mm = re.fullmatch(r'([ailf])load(?:_(\d+))?', op)
                        slot = int(mm[2]) if mm[2] is not None else int(insn.operand.split()[0])
                        push(state.get(slot), 2 if mm[1] in 'ld' else 1)
                    elif re.fullmatch(r'[ailf]store(?:_\d+)?', op):
                        mm = re.fullmatch(r'([ailf])store(?:_(\d+))?', op)
                        slot = int(mm[2]) if mm[2] is not None else int(insn.operand.split()[0])
                        state[slot] = pop()[0]
                    elif op == 'iinc':
                        state[int(insn.operand.split(',')[0])] = None
                    elif op == 'dup':
                        push(stack[-1][0], stack[-1][1])
                    elif op == 'pop':
                        pop()
                    elif op in ('pop2', 'dup2', 'dup2_x1', 'dup2_x2'):
                        raise PolicyError(f'{self.m.key}@{pc}: category-2 stack op outside certificate')
                    elif op == 'swap':
                        stack[-1], stack[-2] = stack[-2], stack[-1]
                    elif op in ARITH_KIND or op in CMP_OPS:
                        pop(); pop(); push(None)
                    elif op in UNARY_KIND:
                        a = pop()
                        if op == 'checkcast':
                            m = re.search(r'class\s+"?([^"]+)"?', insn.operand)
                            target_type = m.group(1) if m else ''
                            if target_type.startswith('[') and a[0]:
                                push(a[0])
                            elif target_type in self.policy.get('external_casts', []):
                                push(a[0])
                            else:
                                raise PolicyError(f'{self.m.key}@{pc}: runtime type test/cast outside certificate')
                        else:
                            push(None)
                    elif op in ('newarray', 'anewarray'):
                        pop()
                        role = f'{self.m.owner}.{self.m.name}@{pc}:new'
                        ap = self.cp.get('methods', {}).get(f'{self.m.name}:{self.m.descriptor}', {}).get('alloc_public', [])
                        self.add_role(role, 'pub' if (ap is True or pc in ap) else 'sec')
                        push(role)
                    elif op == 'arraylength':
                        pop(); push(None)
                    elif op in LOAD_OPS:
                        pop(); pop(); push(None)
                    elif op in STORE_OPS:
                        if op == 'aastore':
                            raise PolicyError(f'{self.m.key}@{pc}: aastore reference alias outside certificate')
                        pop(); pop(); pop()
                    elif op in ('getfield', 'putfield'):
                        f = field_ref(insn.operand)
                        f = (f[0] or self.m.owner, f[1], f[2])
                        key = f'{f[0]}.{f[1]}:{f[2]}'
                        rule = self.cp.get('fields', {}).get(key)
                        if rule is None:
                            raise PolicyError(f'{self.m.key}@{pc}: unlisted field {key}')
                        if op == 'getfield':
                            pop(); push(rule.get('seq_role') or rule.get('array_role'))
                        else:
                            pop(); pop()
                    elif op == 'getstatic':
                        push(None)
                    elif op == 'new':
                        raise PolicyError(f'{self.m.key}@{pc}: object identity/new outside certificate')
                    elif op == 'aconst_null':
                        raise PolicyError(f'{self.m.key}@{pc}: null identity outside certificate')
                    elif op == 'invokedynamic':
                        if not self.lambda_rule(insn.operand):
                            raise PolicyError(f'{self.m.key}@{pc}: unlisted invokedynamic')
                        desc = re.search(r'\)(.+)$', insn.operand.split('//')[-1].strip())
                        argdesc = re.search(r':\(([^)]*)\)', insn.operand)
                        if argdesc:
                            for t in descriptor_types('(' + argdesc.group(1) + ')' + (desc.group(1) if desc else 'V'))[0]:
                                pop()
                        push(None)
                    elif op == 'putstatic':
                        raise PolicyError(f'{self.m.key}@{pc}: putstatic outside certificate')
                    elif op in ('instanceof', 'checkcast'):
                        raise PolicyError(f'{self.m.key}@{pc}: runtime type test/cast outside certificate')
                    elif op.startswith('invoke'):
                        ref = method_ref(insn.operand)
                        if ref is None:
                            raise PolicyError(f'{self.m.key}@{pc}: unparsed invocation')
                        _, _, desc = ref
                        args, result = descriptor_types(desc)
                        arg_roles = [pop()[0] for _ in args][::-1]
                        if op != 'invokestatic':
                            pop()
                        rule = self.call_rule(f'{ref[0] or self.m.owner}.{ref[1]}:{desc}')
                        if rule is None:
                            raise PolicyError(f'{self.m.key}@{pc}: unlisted call')
                        kind = rule.get('kind', 'call')
                        if kind in ('identity', 'fill', 'requireNonNull'):
                            push(arg_roles[0] if arg_roles else None)
                        elif kind in ('length', 'seq_load', 'unbox'):
                            push(None)
                        elif kind == 'getfield':
                            sr = rule.get('seq_role') or rule.get('array_role')
                            if sr:
                                self.add_role(sr, rule.get('seq_taint', rule.get('array_taint', 'sec')))
                            push(sr)
                        elif kind == 'alloc':
                            role = f'{self.m.owner}.{self.m.name}@{pc}:alloc'
                            self.add_role(role, rule.get('role_taint', 'sec')); push(role)
                        elif kind == 'empty':
                            role = f'{self.m.owner}.{self.m.name}@{pc}:empty'
                            self.add_role(role, rule.get('role_taint', 'pub')); push(role)
                        elif kind in ('seq_of', 'seq_concat', 'seq_take'):
                            role = f'{self.m.owner}.{self.m.name}@{pc}:seq'
                            self.add_role(role, self.or_(*[self.taint_role(x) for x in arg_roles if x])); push(role)
                        elif kind in ('seq_to_array', 'clone'):
                            role = f'{self.m.owner}.{self.m.name}@{pc}:array'
                            self.add_role(role, self.taint_role(arg_roles[0]) if arg_roles and arg_roles[0] else 'sec'); push(role)
                        elif kind == 'new':
                            push(None)
                        elif result != 'V':
                            if result.startswith('['):
                                role=f'{self.m.owner}.{self.m.name}@{pc}:result'
                                self.add_role(role, rule.get('array_taint','sec')); push(role)
                            elif 'DafnySequence' in result:
                                role=f'{self.m.owner}.{self.m.name}@{pc}:seq_result'
                                self.add_role(role, rule.get('seq_taint','sec')); push(role)
                            else:
                                push(None)
                    elif op in ('tableswitch', 'lookupswitch'):
                        pop()
                        break
                    elif op == 'athrow':
                        pop()
                        break
                    elif op in COND_BRANCH or op in ('goto', 'goto_w'):
                        if op in COND_BRANCH:
                            if op in ('ifnull', 'ifnonnull'):
                                pop()
                            elif op.startswith(('if_icmp', 'if_acmp')):
                                pop(); pop()
                            else:
                                pop()
                        break
                    elif op in ('ireturn', 'lreturn', 'areturn', 'freturn', 'dreturn', 'return'):
                        break
                    elif op == 'nop':
                        pass
                    else:
                        raise PolicyError(f'{self.m.key}@{pc}: unlisted opcode {op}')
                for tb in self.block_succ(bi):
                    merged = {}
                    for slot in set(entry[tb]) | set(state):
                        a = entry[tb].get(slot, '__unset__')
                        b = state.get(slot, '__unset__')
                        value = b if a == '__unset__' else a if b == '__unset__' else self.role_merge(a, b)
                        if value != '__unset__':
                            merged[slot] = value
                    if merged != entry[tb]:
                        entry[tb] = merged
                        changed = True
        return entry

    def block_succ(self, bi: int) -> list[int]:
        last = self.block_insns(bi)[-1] if self.block_insns(bi) else None
        if last is None:
            return []
        if last.op in COND_BRANCH:
            nxt = [i.offset for i in self.m.insns if i.offset > last.offset]
            out = [self.block_of[branch_target(last)]]
            if nxt:
                out.append(self.block_of[nxt[0]])
            return out
        if last.op in ('goto', 'goto_w'):
            return [self.block_of[branch_target(last)]]
        if last.op in ('tableswitch', 'lookupswitch'):
            cases, default = self.m.switches[last.offset]
            return [self.block_of[t] for _, t in cases] + [self.block_of[default]]
        if last.op in ('ireturn', 'lreturn', 'areturn', 'freturn', 'dreturn', 'return', 'athrow'):
            return []
        nxt = [i.offset for i in self.m.insns if i.offset > last.offset]
        return [self.block_of[nxt[0]]] if nxt and nxt[0] in self.block_of else []

    # -- SSA + taint fixpoint --
    def ssa_pass(self):
        preds = {b: [] for b in range(self.nblocks)}
        for b in range(self.nblocks):
            for tb in self.block_succ(b):
                preds[tb].append(b)
        ready = {0}
        for rounds in range(256):
            changed = False
            for bi in sorted(ready):
                ids, taints, sids, stains = self.run_block(bi, False)
                self.out_ids[bi], self.out_taints[bi] = ids, taints
                self.out_stack_ids[bi], self.out_stack_taints[bi] = sids, stains
            for tb in range(self.nblocks):
                available = [p for p in preds[tb] if p in self.out_ids]
                if not available:
                    continue
                merged_ids, merged_taints = {}, {}
                slots = set()
                for p in available:
                    slots |= set(self.out_ids[p])
                for slot in slots:
                    incoming = [self.out_ids[p].get(slot) for p in available]
                    incoming_t = [self.out_taints[p].get(slot, 'sec') for p in available]
                    t = self.or_(*incoming_t)
                    present = [i for i in incoming if i is not None]
                    if len(present) == len(available) and len(set(present)) == 1:
                        merged_ids[slot] = present[0]
                    elif not present:
                        continue
                    else:
                        merged_ids[slot] = self.phi_id(tb, slot)
                    merged_taints[slot] = t
                # stack slots across a join become phi registers (edge copies)
                merged_sids, merged_stains = {}, {}
                stacks = [self.out_stack_ids[p] for p in available]
                for index in set().union(*[set(x) for x in stacks]):
                    incoming = [x.get(index) for x in stacks]
                    ts = [self.out_stack_taints[p].get(index, 'sec') for p in available]
                    present = [x for x in incoming if x is not None]
                    if len(present) == len(available) and len(set(present)) == 1:
                        merged_sids[index] = present[0]
                    elif present:
                        merged_sids[index] = self.stack_phi(tb, index)
                    if present:
                        merged_stains[index] = self.or_(*ts)
                if (merged_ids != self.entry_ids[tb] or merged_taints != self.entry_taints[tb]
                        or merged_sids != self.entry_stack_ids[tb]
                        or merged_stains != self.entry_stack_taints[tb]):
                    self.entry_ids[tb] = merged_ids
                    self.entry_taints[tb] = merged_taints
                    self.entry_stack_ids[tb] = merged_sids
                    self.entry_stack_taints[tb] = merged_stains
                    changed = True
                if tb not in ready:
                    ready.add(tb)
                    changed = True
            if not changed:
                break
        else:
            raise PolicyError(f'{self.m.key}: SSA/taint fixpoint did not converge')
        for (tb, slot), phi in self.phi_ids.items():
            if slot in self.entry_taints.get(tb, {}):
                self.def_taints[phi] = self.or_(self.def_taints.get(phi, 'pub'),
                                                self.entry_taints[tb][slot])
        for (tb, index), phi in self.stack_phi_ids.items():
            if index in self.entry_stack_taints.get(tb, {}):
                self.def_taints[phi] = self.or_(self.def_taints.get(phi, 'pub'),
                                                self.entry_stack_taints[tb][index])
        # edge copies: a phi register receives the predecessor's outgoing value
        for tb in range(self.nblocks):
            for p in preds[tb]:
                if p not in self.out_ids:
                    continue
                copies = []
                for slot, entry_id in self.entry_ids[tb].items():
                    if slot in self.out_ids.get(p, {}) and entry_id == self.phi_ids.get((tb, slot)):
                        incoming = self.out_ids[p][slot]
                        if incoming != entry_id:
                            copies.append((entry_id, incoming))
                for index, entry_id in self.entry_stack_ids[tb].items():
                    if index in self.out_stack_ids.get(p, {}) and entry_id == self.stack_phi_ids.get((tb, index)):
                        incoming = self.out_stack_ids[p][index]
                        if incoming != entry_id:
                            copies.append((entry_id, incoming))
                if copies:
                    self.edge_copies[(p, tb)] = copies

    # -- execution/emission of one block --
    def run_block(self, bi: int, emit: bool):
        lead = self.leaders[bi]
        current_ids = dict(self.entry_ids[bi])
        current_taints = dict(self.entry_taints[bi])
        self.current_role = dict(self.role_entry.get(bi, {}))
        stack: list[dict] = []
        for index in sorted(self.entry_stack_ids.get(bi, {})):
            stack.append({'id': self.entry_stack_ids[bi][index],
                          't': self.entry_stack_taints[bi].get(index, 'sec'),
                          'w': 1, 'role': None})
        steps: list[dict] = []

        def fresh(taint: str, pc: int) -> int:
            reg = self.result_id(pc)
            self.def_taints[reg] = self.or_(self.def_taints.get(reg, 'pub'), taint)
            return reg

        def push(entry):
            stack.append(entry)

        def pop():
            if not stack:
                raise PolicyError(f'{self.m.key}@{lead}: stack underflow in run_block')
            return stack.pop()

        def local(slot, pc):
            if slot not in current_ids:
                raise PolicyError(f'{self.m.key}@{pc}: read of uninitialized local {slot}')
            role = self.current_role.get(slot)
            if role == 'ambig':
                raise PolicyError(f'{self.m.key}@{pc}: ambiguous array role in local {slot}')
            return {'id': current_ids[slot], 't': current_taints.get(slot, 'sec'),
                    'w': 1, 'role': role}

        def step(pc, what, dst, kind, ann):
            if emit:
                steps.append({'type': 'step', 'site': self.site(pc, what), 'dst': dst,
                              'kind': kind, 'ann': ann})

        def write_local(pc, slot, value):
            current_ids[slot] = value['id']
            current_taints[slot] = self.or_(current_taints.get(slot, 'pub'), value['t'])
            self.current_role[slot] = value.get('role')

        def const(pc, value):
            reg = fresh('pub', pc)
            step(pc, 'const', reg, ('lit', value & ((1 << 64) - 1)), 'pub')
            return {'id': reg, 't': 'pub', 'w': 1, 'role': None}

        term = None
        insns = self.block_insns(bi)
        for insn in insns:
            op, pc = insn.op, insn.offset
            if re.fullmatch(r'iconst_(m1|\d)', op):
                push(const(pc, -1 if op == 'iconst_m1' else int(op.split('_')[1])))
            elif op in ('lconst_0', 'lconst_1'):
                e = const(pc, int(op.split('_')[1])); e['w'] = 2; push(e)
            elif op in ('bipush', 'sipush'):
                push(const(pc, int(insn.operand)))
            elif op in ('ldc', 'ldc_w', 'ldc2_w'):
                if '// String ' in insn.operand:
                    push(const(pc, 0))
                elif '// class ' in insn.operand or '// MethodHandle' in insn.operand:
                    raise PolicyError(f'{self.m.key}@{pc}: class/handle constant outside certificate')
                else:
                    push(const(pc, _int_literal(insn.operand)))
            elif op == 'aconst_null':
                raise PolicyError(f'{self.m.key}@{pc}: null identity outside certificate')
            elif re.fullmatch(r'[ailf]load(?:_\d+)?', op):
                mm = re.fullmatch(r'([ailf])load(?:_(\d+))?', op)
                slot = int(mm[2]) if mm[2] is not None else int(insn.operand.split()[0])
                push(local(slot, pc))
            elif re.fullmatch(r'[ailf]store(?:_\d+)?', op):
                mm = re.fullmatch(r'([ailf])store(?:_(\d+))?', op)
                slot = int(mm[2]) if mm[2] is not None else int(insn.operand.split()[0])
                value = pop()
                dst = self.write_id(pc)
                self.def_taints[dst] = self.or_(self.def_taints.get(dst, 'pub'), value['t'])
                step(pc, 'store-local', dst, ('op', 'copy', 0, value['id']), value['t'])
                value = dict(value)
                value['id'] = dst
                write_local(pc, slot, value)
            elif op == 'iinc':
                slot, amount = [int(x) for x in insn.operand.split(',')]
                one = const(pc, amount)
                cur = local(slot, pc)
                t = self.or_(cur['t'], 'pub')
                dst = self.write_id(pc)
                self.def_taints[dst] = self.or_(self.def_taints.get(dst, 'pub'), t)
                step(pc, 'iinc', dst, ('op', 'add', cur['id'], one['id']), t)
                write_local(pc, slot, {'id': dst, 't': t, 'w': 1, 'role': cur.get('role')})
            elif op == 'dup':
                push(dict(stack[-1]))
            elif op == 'pop':
                pop()
            elif op in ('pop2', 'dup2', 'dup2_x1', 'dup2_x2'):
                raise PolicyError(f'{self.m.key}@{pc}: category-2 stack op outside certificate')
            elif op == 'swap':
                stack[-1], stack[-2] = stack[-2], stack[-1]
            elif op in ('dup_x1', 'dup_x2', 'dup2_x1', 'dup2_x2'):
                raise PolicyError(f'{self.m.key}@{pc}: {op} outside reviewed stack shape')
            elif op in ARITH_KIND:
                b, a = pop(), pop()
                t = self.or_(a['t'], b['t'])
                reg = fresh(t, pc)
                step(pc, op, reg, ('op', ARITH_KIND[op], a['id'], b['id']), t)
                push({'id': reg, 't': t, 'w': 2 if op.startswith('l') else 1, 'role': None})
            elif op in CMP_OPS:
                b, a = pop(), pop()
                t = self.or_(a['t'], b['t'])
                reg = fresh(t, pc)
                step(pc, op, reg, ('op', 'cmp', a['id'], b['id']), t)
                push({'id': reg, 't': t, 'w': 1, 'role': None})
            elif op in UNARY_KIND:
                a = pop()
                if op == 'checkcast':
                    m = re.search(r'class\s+"?([^"]+)"?', insn.operand)
                    target_type = m.group(1) if m else ''
                    if target_type.startswith('[') and a.get('role'):
                        push(a)
                    elif target_type in self.policy.get('external_casts', []):
                        push(a)
                    else:
                        raise PolicyError(f'{self.m.key}@{pc}: runtime type test/cast outside certificate')
                else:
                    reg = fresh(a['t'], pc)
                    step(pc, op, reg, ('op', UNARY_KIND[op], a['id'], 0), a['t'])
                    push({'id': reg, 't': a['t'], 'w': 1, 'role': a.get('role')})
            elif op in ('newarray', 'anewarray'):
                size = pop()
                role = f'{self.m.owner}.{self.m.name}@{pc}:new'
                alloc_pub = self.cp.get('methods', {}).get(f'{self.m.name}:{self.m.descriptor}', {}).get('alloc_public', [])
                public = alloc_pub is True or pc in alloc_pub
                self.add_role(role, 'pub' if public else 'sec')
                reg = fresh('pub', pc)
                step(pc, op, reg, ('alloc', role, size['id']), 'pub')
                push({'id': reg, 't': 'pub', 'w': 1, 'role': role})
            elif op == 'arraylength':
                ref = pop(); role = self.require_role(ref, pc)
                reg = fresh('pub', pc)
                step(pc, op, reg, ('len', role), 'pub')
                push({'id': reg, 't': 'pub', 'w': 1, 'role': None})
            elif op in LOAD_OPS:
                idx, ref = pop(), pop()
                role = self.require_role(ref, pc)
                if op == 'aaload':
                    raise PolicyError(f'{self.m.key}@{pc}: aaload outside certificate')
                t = self.taint_role(role)
                reg = fresh(t, pc)
                step(pc, op, reg, ('load', role, idx['id']), t)
                push({'id': reg, 't': t, 'w': LOAD_OPS[op], 'role': None})
            elif op in STORE_OPS:
                if op == 'aastore':
                    raise PolicyError(f'{self.m.key}@{pc}: aastore reference alias outside certificate')
                val, idx, ref = pop(), pop(), pop()
                role = self.require_role(ref, pc)
                step(pc, op, 0, ('store', role, idx['id'], val['id']), 'pub')
            elif op in ('getfield', 'putfield'):
                f = field_ref(insn.operand)
                if f is None:
                    raise PolicyError(f'{self.m.key}@{pc}: unparsed field')
                f = (f[0] or self.m.owner, f[1], f[2])
                key = f'{f[0]}.{f[1]}:{f[2]}'
                rule = self.cp.get('fields', {}).get(key)
                if rule is None:
                    raise PolicyError(f'{self.m.key}@{pc}: unlisted field {key}')
                role = rule['role']
                self.add_role(role, rule['taint'])
                pop()
                if op == 'getfield':
                    if f[2].startswith('['):
                        array_role = rule.get('array_role')
                        if not array_role:
                            raise PolicyError(f'{self.m.key}@{pc}: array field {key} without array_role')
                        self.add_role(array_role, rule.get('array_taint', 'sec'))
                        reg = fresh('pub', pc)
                        step(pc, op, reg, ('load', role, 0), 'pub')
                        push({'id': reg, 't': 'pub', 'w': 1, 'role': array_role})
                    else:
                        t = rule['taint']
                        reg = fresh(t, pc)
                        step(pc, op, reg, ('load', role, 0), t)
                        push({'id': reg, 't': t, 'w': 2 if f[2] == 'J' else 1, 'role': None})
                else:
                    val = pop()
                    if rule.get('array_role') or rule.get('seq_role'):
                        raise PolicyError(f'{self.m.key}@{pc}: write to reference field {key} outside alias contract')
                    step(pc, op, 0, ('store', role, 0, val['id']), 'pub')
            elif op == 'getstatic':
                f = field_ref(insn.operand)
                if f is None:
                    raise PolicyError(f'{self.m.key}@{pc}: unparsed static')
                f = (f[0] or self.m.owner, f[1], f[2])
                key = f'{f[0]}.{f[1]}:{f[2]}'
                if key not in self.policy.get('statics', {}):
                    raise PolicyError(f'{self.m.key}@{pc}: unlisted static {key}')
                push(const(pc, 0))
            elif op == 'putstatic':
                raise PolicyError(f'{self.m.key}@{pc}: putstatic outside certificate')
            elif op == 'new':
                raise PolicyError(f'{self.m.key}@{pc}: object identity/new outside certificate')
            elif op in ('instanceof', 'checkcast'):
                raise PolicyError(f'{self.m.key}@{pc}: runtime type test/cast outside certificate')
            elif op in ('monitorenter', 'monitorexit'):
                raise PolicyError(f'{self.m.key}@{pc}: monitor operation outside certificate')
            elif op == 'invokedynamic':
                if not self.lambda_rule(insn.operand):
                    raise PolicyError(f'{self.m.key}@{pc}: unlisted invokedynamic')
                argdesc = re.search(r':\(([^)]*)\)', insn.operand)
                if argdesc:
                    desc = '(' + argdesc.group(1) + ')V'
                    for _ in descriptor_types(desc)[0]:
                        pop()
                push(const(pc, 0))
            elif op.startswith('invoke'):
                self.emit_call(bi, pc, insn, stack, step, fresh, push, pop)
            elif op in ('tableswitch', 'lookupswitch'):
                selector = pop()
                cases, default = self.m.switches[pc]
                term = ('switch', self.site(pc, op) if emit else None, selector['id'],
                        [(v & ((1 << 64) - 1), self.block_of[t]) for v, t in cases],
                        self.block_of[default])
                break
            elif op == 'athrow':
                if not self.cp.get('methods', {}).get(f'{self.m.name}:{self.m.descriptor}', {}).get('allow_raise'):
                    raise PolicyError(f'{self.m.key}@{pc}: explicit throw outside certificate')
                pop()
                term = ('raise', self.site(pc, 'athrow') if emit else None)
                break
            elif op in COND_BRANCH:
                kind = BRANCH_KIND[op]
                if op in ('ifnull', 'ifnonnull'):
                    a = pop(); b = {'id': 0, 't': 'pub', 'w': 1, 'role': None}
                elif op.startswith(('if_icmp', 'if_acmp')):
                    b, a = pop(), pop()
                else:
                    a = pop(); b = {'id': 0, 't': 'pub', 'w': 1, 'role': None}
                t = self.or_(a['t'], b['t'])
                reg = fresh(t, pc)
                step(pc, 'compare', reg, ('op', kind, a['id'], b['id']), t)
                term = ('branch', self.site(pc, op) if emit else None, reg,
                        self.block_of[branch_target(insn)], self.block_of[[i.offset for i in self.m.insns if i.offset > pc][0]])
                break
            elif op in ('goto', 'goto_w'):
                term = ('goto', None, None, self.block_of[branch_target(insn)], None)
                break
            elif op in ('ireturn', 'lreturn', 'areturn', 'freturn', 'dreturn'):
                term = ('stop', pop()['id'])
                break
            elif op == 'return':
                term = ('stop', None)
                break
            elif op == 'nop':
                pass
            elif op in ('tableswitch', 'lookupswitch'):
                raise PolicyError(f'{self.m.key}@{pc}: switch outside certificate')
            else:
                raise PolicyError(f'{self.m.key}@{pc}: unlisted opcode {op}')
        if term is None:
            last = insns[-1] if insns else None
            nxt = [i.offset for i in self.m.insns if last is not None and i.offset > last.offset]
            if nxt and nxt[0] in self.block_of:
                term = ('goto', self.block_of[nxt[0]])
            else:
                term = ('stop',)
        if emit:
            self.pending_steps = steps
            self.pending_term = term
        out_stack_ids = {i: e['id'] for i, e in enumerate(stack)}
        out_stack_taints = {i: e['t'] for i, e in enumerate(stack)}
        return dict(current_ids), dict(current_taints), out_stack_ids, out_stack_taints

    def require_role(self, entry: dict, pc: int) -> str:
        role = entry.get('role')
        if not role:
            raise PolicyError(f'{self.m.key}@{pc}: array operation on a value with no known role')
        return role

    def emit_op(self, step, pc, what, dst, kind, ann):
        step(pc, what, dst, kind, ann)

    def emit_call(self, bi, pc, insn, stack, step, fresh, push, pop):
        ref = method_ref(insn.operand)
        if ref is None:
            raise PolicyError(f'{self.m.key}@{pc}: unparsed invocation')
        owner, name, desc = ref
        owner = owner or self.m.owner
        target = f'{owner}.{name}:{desc}'
        args, result = descriptor_types(desc)
        values = [pop() for _ in args][::-1]
        if insn.op != 'invokestatic':
            receiver = pop(); values = [receiver] + values
        if not self.dispatch_allowed(insn.op, owner, name, desc):
            raise PolicyError(f'{self.m.key}@{pc}: unproven virtual dispatch {target}')
        rule = self.call_rule(target)
        if rule is None:
            raise PolicyError(f'{self.m.key}@{pc}: unlisted call {target}')
        arg_taints = [e['t'] for e in values]
        kind = rule.get('kind', 'call')
        if kind == 'call':
            heap_taints = [self.roles.get(e['role'], 'sec') for e in values if e.get('role')]
            problem = runtime_call_problem(target, arg_taints, heap_taints)
            if problem:
                raise PolicyError(f'{self.m.key}@{pc}: {problem}')
        elif kind not in MODELED_PRIMITIVE_KINDS:
            raise PolicyError(f'{self.m.key}@{pc}: unclassified external call kind {kind!r} for {target}')
        off = 0 if insn.op == 'invokestatic' else 1

        def alloc_role(role, taint, size_reg, what=target):
            self.add_role(role, taint)
            reg = fresh('pub', pc)
            step(pc, what, reg, ('alloc', role, size_reg), 'pub')
            return reg

        def len_reg(role):
            reg = fresh('pub', pc)
            step(pc, target, reg, ('len', role), 'pub')
            return reg

        if kind == 'identity' or kind == 'requireNonNull':
            push(values[off]); return
        if kind == 'length':
            role = self.require_role(values[0], pc)
            push({'id': len_reg(role), 't': 'pub', 'w': 1, 'role': None}); return
        if kind == 'getfield':
            role = rule['role']; self.add_role(role, rule['taint'])
            seq_role = rule.get('seq_role')
            array_role = rule.get('array_role')
            if seq_role:
                self.add_role(seq_role, rule.get('seq_taint', 'sec'))
                reg = fresh('pub', pc)
                step(pc, target, reg, ('load', role, 0), 'pub')
                push({'id': reg, 't': 'pub', 'w': 1, 'role': seq_role}); return
            if desc.startswith('[') or array_role:
                if not array_role:
                    raise PolicyError(f'{self.m.key}@{pc}: {target} needs array_role')
                self.add_role(array_role, rule.get('array_taint', 'sec'))
                reg = fresh('pub', pc)
                step(pc, target, reg, ('load', role, 0), 'pub')
                push({'id': reg, 't': 'pub', 'w': 1, 'role': array_role}); return
            t = rule['taint']; reg = fresh(t, pc)
            step(pc, target, reg, ('load', role, 0), t)
            push({'id': reg, 't': t, 'w': 2 if result == 'J' else 1, 'role': None}); return
        if kind == 'alloc':
            size_index = rule.get('size_arg', 0)
            role = f'{self.m.owner}.{self.m.name}@{pc}:alloc'
            reg = alloc_role(role, rule.get('role_taint', 'sec'), values[off + size_index]['id'])
            push({'id': reg, 't': 'pub', 'w': 1, 'role': role}); return
        if kind == 'empty':
            role = f'{self.m.owner}.{self.m.name}@{pc}:empty'
            reg = alloc_role(role, rule.get('role_taint', 'pub'), 0)
            push({'id': reg, 't': 'pub', 'w': 1, 'role': role}); return
        if kind == 'seq_of':
            array_role = self.require_role(values[0], pc)
            role = f'{self.m.owner}.{self.m.name}@{pc}:seq'
            reg = alloc_role(role, self.taint_role(array_role), len_reg(array_role))
            push({'id': reg, 't': 'pub', 'w': 1, 'role': role}); return
        if kind == 'seq_concat':
            r1 = self.require_role(values[0], pc)
            r2 = self.require_role(values[1], pc)
            role = f'{self.m.owner}.{self.m.name}@{pc}:seq'
            t = self.or_(self.taint_role(r1), self.taint_role(r2))
            l1 = len_reg(r1); l2 = len_reg(r2)
            total = fresh('pub', pc)
            step(pc, target, total, ('op', 'add', l1, l2), 'pub')
            reg = alloc_role(role, t, total)
            push({'id': reg, 't': 'pub', 'w': 1, 'role': role}); return
        if kind == 'seq_take':
            r1 = self.require_role(values[0], pc)
            role = f'{self.m.owner}.{self.m.name}@{pc}:seq'
            reg = alloc_role(role, self.taint_role(r1), values[1]['id'])
            push({'id': reg, 't': 'pub', 'w': 1, 'role': role}); return
        if kind in ('seq_to_array', 'clone'):
            r1 = self.require_role(values[0], pc)
            role = f'{self.m.owner}.{self.m.name}@{pc}:array'
            reg = alloc_role(role, self.taint_role(r1), len_reg(r1))
            push({'id': reg, 't': 'pub', 'w': 1, 'role': role}); return
        if kind == 'seq_load':
            role = self.require_role(values[0], pc)
            idx = values[1]
            t = self.taint_role(role)
            reg = fresh(t, pc)
            step(pc, target, reg, ('load', role, idx['id']), t)
            push({'id': reg, 't': t, 'w': 1, 'role': None}); return
        if kind == 'fill':
            role = self.require_role(values[off], pc)
            self.roles[role] = self.or_(self.roles[role], values[off + 1]['t'])
            push(values[off]); return
        if kind == 'new':
            push({'id': values[0]['id'] if values else 0, 't': 'pub', 'w': 1, 'role': None}); return
        heap_args = [e['role'] for e in values if e.get('role')]
        for role in heap_args:
            self.taint_role(role)
        arg_taint = self.or_(*(e['t'] for e in values))
        heap_taint = self.or_(*(self.taint_role(r) for r in heap_args))
        declared = rule.get('result', 'args')
        if declared == 'args':
            t = self.or_(arg_taint, heap_taint)
        elif declared in ('pub', 'sec'):
            t = declared
        else:
            raise PolicyError(f'{self.m.key}@{pc}: bad result policy {declared}')
        shape = bool(rule.get('shape', False))
        if shape:
            t = 'pub'
        target_code = self.call_targets.setdefault(target, len(self.call_targets) + 1)
        if result == 'V':
            dummy = self.alloc('sec')
            step(pc, target, dummy, ('call', target_code, [e['id'] for e in values], heap_args, False), 'sec')
            return
        reg = fresh(t, pc)
        step(pc, target, reg, ('call', target_code, [e['id'] for e in values], heap_args, shape), t)
        if result.startswith('[') or 'DafnySequence' in result:
            is_array = result.startswith('[')
            role = f'{self.m.owner}.{self.m.name}@{pc}:result' if is_array else f'{self.m.owner}.{self.m.name}@{pc}:seq_result'
            role_taint = rule.get('array_taint', 'sec') if is_array else rule.get('seq_taint', 'sec')
            self.add_role(role, role_taint)
            # Every call-result heap role needs an explicit public length
            # relation; otherwise reject instead of silently assuming length 0.
            if rule.get('length_zero'):
                size_reg = 0
            elif rule.get('length_arg') is not None:
                size_reg = values[off + rule['length_arg']]['id']
            elif rule.get('length_role') is not None:
                size_reg = len_reg(self.require_role(values[off + rule['length_role']], pc))
            else:
                raise PolicyError(f'{self.m.key}@{pc}: call-result role without length contract {target}')
            alloc_role(role, role_taint, size_reg)
            push({'id': reg, 't': t if is_array else 'pub', 'w': 1, 'role': role})
        else:
            push({'id': reg, 't': t, 'w': 2 if result in ('J', 'D') else 1, 'role': None})

    # -- emission and flattening --
    def emit(self):
        blocks: dict[int, list[dict]] = {}
        terms: dict[int, tuple] = {}
        emitted_succ: dict[int, set[int]] = {}
        for bi in range(self.nblocks):
            self.run_block(bi, True)
            blocks[bi] = self.pending_steps
            terms[bi] = self.pending_term
        # edge blocks
        for (p, tb), copies in self.edge_copies.items():
            eid = self.nblocks + len(self.edge_block)
            self.edge_block[(p, tb)] = eid
            blocks[eid] = []
            for phi, incoming in copies:
                blocks[eid].append({'type': 'step', 'site': self.site(-1, 'phi-copy'),
                                    'dst': phi, 'kind': ('op', 'copy', 0, incoming),
                                    'ann': self.def_taints.get(incoming, 'sec')})
            blocks[eid].append({'type': 'goto', 'target': tb})
        # terminators (recompute from run data stored per block)
        order = list(range(self.nblocks)) + [self.edge_block[k] for k in self.edge_block]
        code: list[dict] = []
        starts: dict[int, int] = {}
        for b in order:
            starts[b] = len(code)
            if b >= self.nblocks:
                code.extend(blocks[b])
                continue
            code.extend(blocks[b])
            term = terms[b]
            if term[0] == 'stop':
                code.append({'type': 'stop', 'ret': term[1] if len(term) > 1 else None})
                emitted_succ[b] = set()
            elif term[0] == 'goto':
                target_block = term[3] if len(term) > 3 else term[1]
                target = self.edge_block.get((b, target_block), target_block)
                code.append({'type': 'goto', 'target': target})
                emitted_succ[b] = {target_block}
            elif term[0] == 'branch':
                thn = self.edge_block.get((b, term[3]), term[3])
                els = self.edge_block.get((b, term[4]), term[4])
                code.append({'type': 'branch', 'site': term[1], 'cond': term[2],
                             'thn': thn, 'els': els})
                emitted_succ[b] = {term[3], term[4]}
            elif term[0] == 'switch':
                cases = [(v, self.edge_block.get((b, t), t)) for v, t in term[3]]
                dflt = self.edge_block.get((b, term[4]), term[4])
                code.append({'type': 'switch', 'site': term[1], 'cond': term[2],
                             'cases': cases, 'default': dflt})
                emitted_succ[b] = {t for _, t in term[3]} | {term[4]}
            elif term[0] == 'raise':
                code.append({'type': 'raise', 'site': term[1]})
                emitted_succ[b] = set()
        for b in range(self.nblocks):
            if emitted_succ.get(b, set()) != set(self.block_succ(b)):
                raise PolicyError(f'{self.m.key}: emitted CFG edge mismatch at block {b}')
        for inst in code:
            for key in ('target', 'thn', 'els', 'default'):
                if key in inst:
                    inst[key] = starts[inst[key]]
            if 'cases' in inst:
                inst['cases'] = [(v, starts[t]) for v, t in inst['cases']]
        # Reachability gate over emitted instructions: every instruction must be
        # reachable from entry, including blocks joined only by fall-through.
        succ_ir = {}
        for i, inst in enumerate(code):
            if inst['type'] in ('stop', 'raise'):
                succ_ir[i] = []
            elif inst['type'] == 'goto':
                succ_ir[i] = [inst['target']]
            elif inst['type'] == 'branch':
                succ_ir[i] = [inst['thn'], inst['els']]
            elif inst['type'] == 'switch':
                succ_ir[i] = [t for _, t in inst['cases']] + [inst['default']]
            else:
                succ_ir[i] = [i + 1]
        seen, work = set(), [0]
        while work:
            i = work.pop()
            if i in seen or not (0 <= i < len(code)):
                continue
            seen.add(i)
            work.extend(succ_ir[i])
        if len(seen) != len(code):
            raise PolicyError(f'{self.m.key}: {len(code) - len(seen)} unreachable certificate instructions')
        return {
            'registers': self.next_reg,
            'roles': self.roles,
            'reg_taints': self.def_taints,
            'code': code,
            'sites': self.sites,
            'call_targets': self.call_targets,
            'inputs': self.inputs,
            'instructions_reachable': len(seen),
            'cfg_edges_checked': True,
            'param_regs': list(self.param_order),
            'static': self.m.static,
        }


def translate(method: Method, policy: dict, class_policy: dict) -> dict:
    t = Translator(method, policy, class_policy)
    t.setup_params()
    t.role_entry = t.role_pass()
    t.ssa_pass()
    return t.emit()


def certificate_source(result: dict) -> dict:
    role_names = sorted(result['roles'])
    role_id = {name: i for i, name in enumerate(role_names)}
    code = result['code']
    instrs = []
    for inst in code:
        if inst['type'] == 'step':
            dst = inst['dst']; kind = inst['kind']
            if kind[0] == 'lit':
                instrs.append(f'IStep({inst["site"]}, {dst}, Lit({kind[1]}), __NEXT__)')
            elif kind[0] == 'op':
                instrs.append(f'IStep({inst["site"]}, {dst}, Op({KIND[kind[1]]}, {kind[2]}, {kind[3]}), __NEXT__)')
            elif kind[0] == 'len':
                instrs.append(f'IStep({inst["site"]}, {dst}, LenOf({role_id[kind[1]]}), __NEXT__)')
            elif kind[0] == 'load':
                instrs.append(f'IStep({inst["site"]}, {dst}, Load({role_id[kind[1]]}, {kind[2]}), __NEXT__)')
            elif kind[0] == 'store':
                instrs.append(f'IStep({inst["site"]}, {dst}, Store({role_id[kind[1]]}, {kind[2]}, {kind[3]}), __NEXT__)')
            elif kind[0] == 'alloc':
                instrs.append(f'IStep({inst["site"]}, {dst}, Alloc({role_id[kind[1]]}, {kind[2]}, 0), __NEXT__)')
            elif kind[0] == 'call':
                heap = ', '.join(str(role_id[r]) for r in kind[3])
                shape = 'true' if len(kind) > 4 and kind[4] else 'false'
                instrs.append(f'IStep({inst["site"]}, {dst}, Call({kind[1]}, [{", ".join(map(str, kind[2]))}], [{heap}], {shape}), __NEXT__)')
            else:
                raise PolicyError(f'bad certificate kind {kind}')
        elif inst['type'] == 'goto':
            instrs.append(f'IGoto({inst["target"]})')
        elif inst['type'] == 'branch':
            instrs.append(f'IBranch({inst["site"]}, {inst["cond"]}, {inst["thn"]}, {inst["els"]})')
        elif inst['type'] == 'stop':
            instrs.append('IStop()')
        elif inst['type'] == 'raise':
            instrs.append(f'IRaise({inst["site"]}, 0)')
        elif inst['type'] == 'switch':
            cases = ', '.join(f'({v}, {t})' for v, t in inst['cases'])
            instrs.append(f'ISwitch({inst["site"]}, {inst["cond"]}, [{cases}], {inst["default"]})')
        else:
            raise PolicyError(f'bad certificate term {inst["type"]}')
    body = [text.replace('__NEXT__', str(i + 1)) for i, text in enumerate(instrs)]
    taint_words = ['Pub' if result['reg_taints'].get(r, 'sec') == 'pub' else 'Sec'
                   for r in range(result['registers'])]
    annots_chunks = [taint_words[i:i + 32] for i in range(0, len(taint_words), 32)] or [['Pub']]
    annots = ', '.join('[' + ', '.join(c) + ']' for c in annots_chunks)
    heap_annots = ', '.join('Pub' if result['roles'][r] == 'pub' else 'Sec' for r in role_names)
    functions = '\n'.join(f'  function I{i}(): Instr {{ {text} }}' for i, text in enumerate(body))
    chunk_texts = []
    for start in range(0, len(body), 32):
        chunk_texts.append('[' + ', '.join(f'I{i}()' for i in range(start, min(start + 32, len(body)))) + ']')
    code_expr = '[' + ', '.join(chunk_texts) + ']'
    return {
        'role_names': role_names,
        'functions': functions,
        'dafny': ('Program('
                  f'registers := {result["registers"]}, '
                  f'roles := {len(role_names)}, '
                  f'inputs := {result["inputs"]}, '
                  f'annots := [{annots}], '
                  f'heapAnnots := [{heap_annots}], '
                  'chunks := ' + code_expr + ', '
                  f'instructions := {len(body)}'
                  ')'),
    }


def _leq(a: str, b: str) -> bool:
    return a == 'pub' or b == 'sec'


def audit_certificate(result: dict) -> list[dict]:
    roles = result['roles']
    role_names = sorted(roles)
    role_id = {name: i for i, name in enumerate(role_names)}
    heap = [roles[name] for name in role_names]
    reg = result['reg_taints']
    def rt(r):
        return reg.get(r, 'sec')
    def ht(r):
        return heap[r] if r < len(heap) else 'sec'
    def or_(*ts):
        return 'sec' if any(t == 'sec' for t in ts) else 'pub'
    failures = []
    for inst in result['code']:
        if inst['type'] == 'step':
            kind = inst['kind']; dst = inst['dst']
            problem = None
            site = inst.get('site')
            if dst >= result['registers']:
                problem = 'register out of range'
            elif kind[0] == 'lit':
                if not _leq('pub', rt(dst)): problem = 'lit annotation'
            elif kind[0] == 'op':
                rule = or_(rt(kind[2]), rt(kind[3]))
                if not _leq(rule, rt(dst)):
                    problem = f'op rule {rule} > annot {rt(dst)}'
            elif kind[0] == 'len':
                if not _leq('pub', rt(dst)): problem = 'len annotation'
            elif kind[0] == 'load':
                role, idx = role_id[kind[1]], kind[2]
                if rt(idx) != 'pub': problem = f'secret load index (taint {rt(idx)})'
                elif not _leq(ht(role), rt(dst)): problem = f'load {ht(role)} > {rt(dst)}'
            elif kind[0] == 'store':
                role, idx, val = role_id[kind[1]], kind[2], kind[3]
                if rt(idx) != 'pub': problem = f'secret store index (taint {rt(idx)})'
                elif heap[role] == 'pub' and rt(val) != 'pub': problem = 'secret write into public array'
            elif kind[0] == 'alloc':
                role, size = role_id[kind[1]], kind[2]
                if rt(size) != 'pub': problem = f'secret allocation size (taint {rt(size)})'
            elif kind[0] == 'call':
                args, heap_args = kind[2], kind[3]
                shape = len(kind) > 4 and kind[4]
                target = result.get('call_targets', {})
                names = sorted(name for name, ident in target.items() if ident == kind[1])
                if len(names) != 1:
                    # Fail closed: an unregistered or ambiguous call id cannot be
                    # classified, so it must never be treated as an owned call.
                    problem = ('unclassified call target id %s (%s)'
                               % (kind[1], 'missing' if not names else 'ambiguous: '
                                  + ', '.join(names)))
                    target_name = ''
                else:
                    target_name = names[0]
                runtime_problem = runtime_call_problem(
                    target_name, [rt(a) for a in args],
                    [ht(role_id[r]) for r in heap_args])
                if runtime_problem:
                    problem = runtime_problem
                rule = or_(*[rt(a) for a in args], *[ht(role_id[r]) for r in heap_args])
                if problem is None and shape:
                    if rt(dst) != 'pub': problem = 'shape call result not public'
                elif problem is None and not _leq(rule, rt(dst)):
                    problem = f'call rule {rule} > annot {rt(dst)}'
            if problem:
                failures.append({'site': site, 'offset': result['sites'][site]['offset'] if site is not None and site < len(result['sites']) else None,
                                 'method': result['sites'][site]['method'] if site is not None and site < len(result['sites']) else None,
                                 'problem': problem})
        elif inst['type'] in ('branch', 'switch'):
            if rt(inst['cond']) != 'pub':
                site = inst['site']
                failures.append({'site': site, 'offset': result['sites'][site]['offset'],
                                 'method': result['sites'][site]['method'],
                                 'problem': f'secret {inst["type"]} condition (taint {rt(inst["cond"])})'})
    return failures


def certificate_module(name: str, result: dict, check_only: bool = False,
                       witness: dict | None = None) -> str:
    """Emit a Dafny module proving Structure in chunks and applying TwoRun.

    A `witness` adds a concrete secret-pair application of the universal theorem.
    Two different obligations are kept apart:

      * hypothesis satisfiability: `WS() != WT()` and `Agree(P(), WS(), WT())`;
      * finite concrete execution: the witness run is executed by the bounded
        interpreter in `trace_exec.py` and only then is the emitted lemma allowed
        to claim a completed (`terminal == 'stop'`) run and concrete event/store
        facts. `Exec` returns `(s, [])` at fuel 0, so a truncated prefix would
        otherwise be indistinguishable from a completed run.

    The witness is a control over the *extracted program text*, not a new
    theorem; the universal statement remains `TwoRun`.
    """
    src = certificate_source(result)
    n = len(result['code'])
    chunk = 32
    chunks = [list(range(i, min(i + chunk, n))) for i in range(0, n, chunk)]
    lemmas, calls = [], []
    for ci, indices in enumerate(chunks):
        inner = '\n'.join('        } else if j == %d {' % i for i in range(1, len(indices)))
        lemmas.append('''  lemma Chunk%d()
    ensures forall j :: 0 <= j < |P().chunks[%d]| ==> InstrOK(P(), P().chunks[%d][j])
  {
    var p := P();
    assert |p.chunks| == %d;
    assert |p.chunks[%d]| == %d;
    forall j | 0 <= j < |p.chunks[%d]|
      ensures InstrOK(p, p.chunks[%d][j])
    {
      if j == 0 {
%s
      } else {
        assert false;
      }
    }
  }''' % (ci, ci, ci, len(chunks), ci, len(indices), ci, ci, inner))
        calls.append('    Chunk%d();' % ci)
    if len(chunks) == 1:
        split = '      if c == 0 { Chunk0(); } else { assert false; }'
    else:
        lines = ['      if c == 0 { Chunk0(); }']
        lines += ['      else if c == %d { Chunk%d(); }' % (i, i) for i in range(1, len(chunks))]
        lines += ['      else { assert false; }']
        split = '\n'.join(lines)
    two_run = '' if check_only else '''  // Universal two-run statement for the extracted actual-method certificate:
  // any two whole-machine states related by Agree produce equal observation
  // traces for every fuel. The bridge from bytecode to this program is the
  // trusted extractor; the statement itself is proved here.
  lemma TwoRun(s: State, t: State, fuel: nat)
    requires Agree(P(), s, t)
    ensures Exec(P(), 0, s, fuel).1 == Exec(P(), 0, t, fuel).1
  {
    var p := P();
    assert p.instructions == %d;
    WellFormed();
    ExecTwoRun(p, 0, s, t, fuel);
  }
''' % n
    witness_text = ''
    if witness is not None and not check_only:
        def seq(values):
            return '[' + ', '.join(str(v) for v in values) + ']'
        heap_s = '[' + ', '.join(seq(h) for h in witness['heap_s']) + ']'
        heap_t = '[' + ', '.join(seq(h) for h in witness['heap_t']) + ']'
        states = '''
  function WS(): State { State(%s, %s) }
  function WT(): State { State(%s, %s) }
''' % (seq(witness['regs_s']), heap_s, seq(witness['regs_t']), heap_t)
        execution = witness.get('execution')
        fuel = witness['fuel'] or (len(result['code']) + 8)
        if execution is None:
            # No finite execution was validated: only claim what is proved (the
            # hypothesis is satisfiable). Never call a truncated prefix complete.
            witness_text = states + '''
  // Hypothesis satisfiability only. The bounded interpreter did not reach a
  // terminal instruction within its step cap, so no concrete execution claim is
  // made here.
  lemma WitnessHypothesis()
    ensures WS() != WT()
  {
    assert Agree(P(), WS(), WT());
  }
'''
        else:
            # Concrete executed control flow (terminal instruction, stores) is
            # validated by the independent bounded interpreter in trace_exec.py
            # and reported as witness_execution. Dafny's verifier does not
            # symbolically evaluate a long concrete `Exec` (that is a resource
            # limit, not an error), so no concrete event-count assertion is
            # emitted here.
            witness_text = states + '''
  // Non-vacuity: the secret projection really differs and `Agree` holds. The
  // witness run's completion, executed stores and secret liveness are checked
  // by the bounded interpreter (trace_exec.py) on this exact program text and
  // recorded in the report as `witness_execution`.
  lemma Witness()
    ensures WS() != WT()
  {
    var p := P();
    assert Agree(p, WS(), WT());
    TwoRun(WS(), WT(), %d);
  }
''' % fuel
    return '''// Generated by formal/timing/bytecode_trace.py -- do not edit.
include "SecretTrace.dfy"
module Cert%s {
  import opened SecretTrace

%s

  function P(): Program {
    %s
  }

%s

  lemma WellFormed()
    ensures Structure(P())
  {
    var p := P();
    assert p.instructions == %d;
    assert |p.chunks| == %d;
%s
    forall c | 0 <= c < |p.chunks|
      ensures forall i :: 0 <= i < |p.chunks[c]| ==> InstrOK(p, p.chunks[c][i])
    {
%s
    }
    assert Structure(p);
  }

%s%s}
''' % (name, src['functions'], src['dafny'], '\n\n'.join(lemmas), n, len(chunks),
       '\n'.join(calls), split, two_run, witness_text)
