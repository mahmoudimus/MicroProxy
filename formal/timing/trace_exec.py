"""Finite interpreter for the pinned SecretTrace machine (F1/F5 control).

This module is an *independent* executable mirror of the observation semantics
frozen in `SecretTrace.dfy` (`Apply`, `DoStep`, `PublicArgs`, `ProviderResult`,
`Exec`). It does not prove anything; it exists so that

  * emitted certificates can be executed concretely and their *executed* control
    flow checked (e.g. that a modelled `Wipe` really reaches its stores),
  * the witness states emitted by `composition.witness` are validated by a
    finite run that must terminate, instead of silently comparing truncated
    prefixes (`Exec` returns `(s, [])` at fuel 0),
  * the numeric `Apply` table used by the translator (`KIND`, `Op(kind, a, b)`)
    is compared against the actual compiled Dafny function (see
    `ApplyProbe.dfy` and `run.py`).

The mirror is faithful to the *program text that is emitted*: role indices come
from `sorted(result['roles'])`, register taints come from `reg_taints` with the
`Sec` default for out-of-range registers, exactly like `certificate_source` /
`SecretTrace.RegTaint`, and `ProviderResult` returns the first *public* argument
value or the target id, like the model.

`Apply` is bit-exact 64-bit word arithmetic (`bv64`), so results are masked to
`2**64`; comparisons/equality follow Dafny's `bv64` comparisons on unsigned
values (the model's `Unsigned` is used only for addresses).
"""
from __future__ import annotations

MASK64 = (1 << 64) - 1

#: Apply kinds and their bytecode_trace.KIND names, mirroring the pinned model.
APPLY_NAMES = {
    0: 'xor', 1: 'cmp', 2: 'add', 3: 'and', 4: 'or', 5: 'sub', 6: 'mul',
    7: 'neg', 8: 'cast', 9: 'shl', 10: 'shr', 11: 'ushr', 12: 'copy',
    13: 'test', 14: 'eq', 15: 'ne', 16: 'gt', 17: 'ge', 18: 'lt', 19: 'le',
}
APPLY_IDS = {name: kind for kind, name in APPLY_NAMES.items()}


def apply(kind: int, a: int, b: int) -> int:
    """`SecretTrace.Apply(kind, a, b)` for bv64 `a`, `b`."""
    a &= MASK64
    b &= MASK64
    if kind == 0:
        return a ^ b
    if kind == 1:
        return 1 if a < b else 0
    if kind == 2:
        return (a + b) & MASK64
    if kind == 3:
        return a & b
    if kind == 4:
        return a | b
    if kind == 5:
        return (a - b) & MASK64
    if kind == 6:
        return (a * b) & MASK64
    if kind == 7:
        return (0 - a) & MASK64
    if kind == 8:
        return a
    if kind == 9:
        return (a << (b % 64)) & MASK64
    if kind in (10, 11):
        return a >> (b % 64)
    if kind == 12:
        return b
    if kind in (13, 14):
        return 1 if a == b else 0
    if kind == 15:
        return 1 if a != b else 0
    if kind == 16:
        return 1 if a > b else 0
    if kind == 17:
        return 1 if a >= b else 0
    if kind == 18:
        return 1 if a < b else 0
    if kind == 19:
        return 1 if a <= b else 0
    return b


class ProgramView:
    """The exact program shape used by `certificate_source` / `SecretTrace`."""

    def __init__(self, result: dict):
        self.role_names = sorted(result['roles'])
        self.role_id = {name: i for i, name in enumerate(self.role_names)}
        self.heap_taints = [result['roles'][name] for name in self.role_names]
        self.registers = result['registers']
        self.code = result['code']
        self.reg_taints = result['reg_taints']

    def reg_taint(self, r: int) -> str:
        # SecretTrace.RegTaint: Sec outside the emitted annotation table.
        if r >= self.registers:
            return 'sec'
        return 'pub' if self.reg_taints.get(r, 'sec') == 'pub' else 'sec'

    def heap_taint(self, role: int) -> str:
        return self.heap_taints[role] if role < len(self.heap_taints) else 'sec'

    def get(self, regs: list[int], r: int) -> int:
        return regs[r] if r < len(regs) else 0

    def public_args(self, regs: list[int], args: list[int]) -> list[tuple[str, int]]:
        out = []
        for a in args:
            if self.reg_taint(a) == 'pub':
                out.append(('pub', self.get(regs, a)))
        return out

    def provider_result(self, target: int, regs: list[int], args: list[int]) -> int:
        public = self.public_args(regs, args)
        return public[0][1] if public else target % (1 << 64)


def execute(view: ProgramView, regs: list[int], heap: list[list[int]],
            fuel: int) -> dict:
    """`SecretTrace.Exec` from pc 0 with explicit fuel.

    Returns a dict with the terminal kind (`stop`/`raise`/`fault`/`fuel`), the
    step count, the observation tape (as `(event, site, detail)` tuples) and
    counters for the interesting events.
    """
    regs = list(regs)
    heap = [list(a) for a in heap]
    code = view.code
    events: list[tuple] = []
    counts = {'store': 0, 'load': 0, 'alloc': 0, 'call': 0, 'guard': 0,
              'len': 0, 'raise': 0, 'fault': 0}
    steps = 0
    pc = 0
    terminal = 'fuel'
    while True:
        if fuel == 0:
            terminal = 'fuel'
            break
        if not (0 <= pc < len(code)):
            terminal = 'fault'
            events.append(('fault-ip', pc, 0))
            counts['fault'] += 1
            break
        inst = code[pc]
        t = inst['type']
        steps += 1
        if t == 'goto':
            pc = inst['target']
            fuel -= 1
            continue
        if t == 'stop':
            terminal = 'stop'
            break
        if t == 'raise':
            events.append(('raise', inst.get('site'), 0))
            counts['raise'] += 1
            terminal = 'raise'
            break
        if t == 'branch':
            cond = view.get(regs, inst['cond'])
            take = cond != 0
            events.append(('guard', inst.get('site'), 1 if take else 0))
            counts['guard'] += 1
            pc = inst['thn'] if take else inst['els']
            fuel -= 1
            continue
        if t == 'switch':
            v = view.get(regs, inst['cond'])
            index = 0
            target = inst['default']
            matched = False
            for i, (case, dest) in enumerate(inst['cases']):
                if (case & MASK64) == v and not matched:
                    index = i
                    target = dest
                    matched = True
            if not matched:
                index = len(inst['cases'])
            events.append(('switch', inst.get('site'), index))
            pc = target
            fuel -= 1
            continue
        if t != 'step':
            terminal = 'fault'
            events.append(('fault-instr', pc, 0))
            counts['fault'] += 1
            break
        kind = inst['kind']
        dst = inst['dst']
        site = inst.get('site')
        head = kind[0]
        if head == 'lit':
            regs[dst] = kind[1] & MASK64
            events.append(('op', site, 0))
        elif head == 'op':
            op = APPLY_IDS.get(kind[1])
            if op is None:
                terminal = 'fault'
                events.append(('fault-kind', site, 0))
                counts['fault'] += 1
                break
            regs[dst] = apply(op, view.get(regs, kind[2]), view.get(regs, kind[3]))
            events.append(('op', site, op))
        elif head == 'len':
            role = view.role_id[kind[1]]
            regs[dst] = len(heap[role]) % (1 << 64)
            events.append(('len', site, (role, len(heap[role]))))
            counts['len'] += 1
        elif head == 'load':
            role = view.role_id[kind[1]]
            idx = view.get(regs, kind[2])
            if idx < len(heap[role]):
                regs[dst] = heap[role][idx]
                events.append(('load', site, (role, idx)))
                counts['load'] += 1
            else:
                events.append(('fault', site, (role, idx)))
                counts['fault'] += 1
                terminal = 'fault'
                break
        elif head == 'store':
            role = view.role_id[kind[1]]
            idx = view.get(regs, kind[2])
            val = view.get(regs, kind[3])
            if idx < len(heap[role]):
                heap[role][idx] = val
                events.append(('store', site, (role, idx)))
                counts['store'] += 1
            else:
                events.append(('fault', site, (role, idx)))
                counts['fault'] += 1
                terminal = 'fault'
                break
        elif head == 'alloc':
            role = view.role_id[kind[1]]
            size = view.get(regs, kind[2])
            heap[role] = [0] * size
            regs[dst] = role % (1 << 64)
            events.append(('alloc', site, (role, size)))
            counts['alloc'] += 1
        elif head == 'call':
            # Both the observed public arguments and the provider result are
            # evaluated on the pre-step state (SecretTrace.DoStep).
            public = view.public_args(regs, kind[2])
            regs[dst] = view.provider_result(kind[1], regs, kind[2])
            events.append(('call', site, (kind[1], tuple(public))))
            counts['call'] += 1
        else:
            terminal = 'fault'
            events.append(('fault-kind', site, 0))
            counts['fault'] += 1
            break
        pc += 1
        fuel -= 1
    return {'terminal': terminal, 'steps': steps, 'events': events,
            'counts': counts, 'regs': regs, 'heap': heap, 'fuel_left': fuel}


def run_to_completion(view: ProgramView, regs: list[int],
                      heap: list[list[int]], start_fuel: int,
                      cap: int = 1 << 18) -> dict | None:
    """Execute with doubling fuel until a terminal state or `cap` steps.

    Returns the completed run (``terminal in {'stop','raise','fault'}``) or
    ``None`` when no finite execution was found within the cap. A truncated run
    is never reported as complete.
    """
    fuel = max(1, start_fuel)
    while fuel <= cap:
        run = execute(view, regs, heap, fuel)
        if run['terminal'] != 'fuel':
            run['fuel_used'] = fuel
            return run
        fuel *= 2
    return None


def differing_registers(view: ProgramView, regs_s: list[int],
                        regs_t: list[int]) -> list[int]:
    """Registers whose final words differ between the two witness runs."""
    out = []
    for r in range(view.registers):
        if view.get(regs_s, r) != view.get(regs_t, r):
            out.append(r)
    return out
