"""Checked inline expansion of certified owned callees into a caller certificate.

The base extractor (`bytecode_trace.py`) models an owned call as one atomic
`Call` step: an observed dispatch plus public arguments, an unconstrained
abstract result, and *no* heap effect. That is a deliberate opaque contract, not
a callee proof. This module removes that contract for an explicitly enumerated
set of exact static owned targets by splicing the callee's already-translated
bytecode body into the caller's flat certificate.

The result is a single `SecretTrace.Program` that is checked by the unchanged
`Structure` / `ExecTwoRun` gate. The spliced instructions are the callee's
translated body (its branches, array reads/writes and heap stores are present in
the emitted program), and the callee's result register is copied into the
caller's destination register. There is no new success flag: either the composed
program verifies or the replay fails.

Scope of the claim: this is a *source-to-IR* splice plus the trusted extractor,
not a JVM-semantics theorem. Locals and phi edges are emitted as
`Op(12, 0, src)` copies so that the frozen `Apply(12, a, b) == b` model really
copies `src`; concrete executed control flow (iteration counts, stores) is
checked separately by the bounded interpreter in `trace_exec.py`.

Trusted steps added by this module (documented in README/threat-model):
  * exact static target matching (class + name + descriptor) against the
    classified callee;
  * register renaming, site renumbering and role aliasing for the spliced body
    (parameter roles must be the exact plain parameter identity, never a merged
    or derived role);
  * entry copies for scalar parameters and a return copy from the callee's
    actual return register;
  * taint *instantiation* of the callee parameters from the caller's actual
    argument/role taints (the composed body is re-checked, never assumed).

The inline expansion does not emit the constant `invoke`/`return` dispatch
events. It observes the expanded body trace instead; the dispatch target and
return site are static per call site. JVM value refinement, implicit
exceptions and physical timing remain outside the model.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass

import bytecode_trace as bt
import trace_exec


class CompositionError(bt.PolicyError):
    pass


#: Recorded callee contracts must use one of these heap effects (F6). A void
#: callee records what it does to its heap arguments; a value-returning callee
#: records `none` (its heap effect is expressed by its contract roles).
CONTRACT_HEAP_EFFECTS = {'none', 'parameter-array-clear', 'parameter-array-write'}

#: Fail-closed expansion limits (F9): the enumerated policy expands at most a
#: handful of small bodies. These are refusal thresholds against unbounded or
#: recursive expansion, not success budgets.
MAX_INLINE_EVENTS = 32
MAX_INLINE_INSTRUCTIONS = 20000


@dataclass
class CalleeSpec:
    target: str
    owner: str
    name: str
    descriptor: str
    method: bt.Method
    class_policy: dict
    declared_params: list[str]

    @property
    def result_type(self) -> str:
        return bt.descriptor_types(self.descriptor)[1]

    @property
    def param_types(self) -> list[str]:
        return bt.descriptor_types(self.descriptor)[0]


def exact_target(owner: str, name: str, descriptor: str) -> str:
    return f'{owner}.{name}:{descriptor}'


def check_contract(entry: dict, policy: dict) -> None:
    """Reject a recorded callee contract that disagrees with the enforced policy.

    The certificate is built from `classes[owner].methods[key].params` and
    `calls[target]`; the `contract` block is what reviewers and the report read.
    A mismatch would let the report describe a different (e.g. private-input)
    contract than the one proved, so it is a hard failure (F6).
    """
    owner = entry['class'].replace('.', '/')
    target = exact_target(owner, entry['name'], entry['descriptor'])
    key = f"{entry['name']}:{entry['descriptor']}"
    method_policy = policy.get('classes', {}).get(owner, {}).get('methods', {}).get(key)
    if method_policy is None:
        raise CompositionError('callee has no declared parameter policy: ' + target)
    contract = entry.get('contract')
    if not isinstance(contract, dict):
        raise CompositionError('callee root has no recorded contract: ' + target)
    declared = list(method_policy.get('params') or [])
    if list(contract.get('params') or []) != declared:
        raise CompositionError(
            'contract params ' + repr(contract.get('params')) + ' do not match the '
            'enforced class policy ' + repr(declared) + ' for ' + target)
    roles = contract.get('roles') or {}
    role_values = [value for name, value in roles.items() if name != 'result']
    if role_values != declared:
        raise CompositionError(
            'contract roles ' + repr(role_values) + ' do not match the enforced '
            'class policy ' + repr(declared) + ' for ' + target)
    heap = contract.get('heap')
    if heap not in CONTRACT_HEAP_EFFECTS:
        raise CompositionError('contract heap effect ' + repr(heap) + ' is not reviewed for ' + target)
    result_type = bt.descriptor_types(entry['descriptor'])[1]
    recorded_result = contract.get('result', 'args')
    if result_type == 'V':
        if recorded_result != 'V':
            raise CompositionError('contract result ' + repr(recorded_result)
                                   + ' is not V for ' + target)
        if heap == 'none':
            raise CompositionError('void callee contract must record its heap effect: ' + target)
    else:
        rule = policy.get('calls', {}).get(target) or {}
        if recorded_result != rule.get('result', 'args'):
            raise CompositionError(
                'contract result ' + repr(recorded_result) + ' does not match call rule '
                + repr(rule.get('result', 'args')) + ' for ' + target)
        if heap != 'none':
            raise CompositionError('non-void callee contract must record heap=none: ' + target)


def _check_acyclic(policy: dict, specs: dict[str, CalleeSpec]) -> None:
    """Fail closed before expansion if the enumerated callees can recurse."""
    edges: dict[str, list[str]] = {}
    for target, spec in specs.items():
        try:
            proto = bt.translate(spec.method, policy, spec.class_policy)
        except bt.PolicyError as error:
            raise CompositionError(
                f'{target}: callee body is not translatable under its declared policy: {error}')
        edges[target] = sorted(t for t in proto['call_targets'] if t in specs)
    state: dict[str, int] = {}

    def visit(node: str, stack: list[str]) -> None:
        mark = state.get(node, 0)
        if mark == 2:
            return
        if mark == 1:
            cycle = stack[stack.index(node):] + [node]
            raise CompositionError('recursive owned-callee inline cycle: ' + ' -> '.join(cycle))
        state[node] = 1
        for nxt in edges.get(node, []):
            visit(nxt, stack + [node])
        state[node] = 2

    for node in edges:
        visit(node, [])


def load_callee_specs(policy: dict, javap, classpath, entries: list[dict]) -> dict[str, CalleeSpec]:
    """Load exactly the enumerated callee targets from actual bytecode."""
    specs: dict[str, CalleeSpec] = {}
    for entry in entries:
        owner = entry['class'].replace('.', '/')
        target = exact_target(owner, entry['name'], entry['descriptor'])
        if target in specs:
            raise CompositionError('duplicate callee target ' + target)
        methods = bt.disassemble(javap, classpath, entry['class'])
        key = f"{entry['name']}:{entry['descriptor']}"
        if key not in methods:
            raise CompositionError('missing callee method ' + target)
        method = methods[key]
        if not method.static:
            raise CompositionError('inline composition requires a static callee: ' + target)
        arg_types, result_type = bt.descriptor_types(entry['descriptor'])
        if result_type.startswith('[') or result_type.startswith('L'):
            raise CompositionError(
                'inline composition supports only scalar/void results: ' + target)
        if any(t.startswith('L') for t in arg_types):
            raise CompositionError(
                'inline composition supports only scalar or primitive-array parameters: ' + target)
        class_policy = policy['classes'][owner]
        declared = class_policy['methods'][key]['params']
        if len(declared) != len(bt.descriptor_types(entry['descriptor'])[0]):
            raise CompositionError('callee parameter policy length mismatch: ' + target)
        check_contract(entry, policy)
        specs[target] = CalleeSpec(target, owner, entry['name'], entry['descriptor'],
                                   method, copy.deepcopy(class_policy), list(declared))
    _check_acyclic(policy, specs)
    return specs


def _instance_policy(spec: CalleeSpec, arg_taints: list[str], arg_role_taints: list[str]) -> dict:
    """Re-check the callee under the caller's actual argument taints.

    A callee parameter takes the caller's *actual* argument taint, which is
    conservative in both directions: a public-declared parameter becomes secret
    if the caller passes a secret value (stronger obligation), and a
    secret-declared parameter becomes public only when the caller's argument is
    itself public by the taint discipline (weaker obligation, re-checked by the
    audit on the composed program). Array/sequence parameters are aliased to the
    caller's role taint.
    """
    key = f'{spec.name}:{spec.descriptor}'
    cp = copy.deepcopy(spec.class_policy)
    params = []
    for i, declared in enumerate(spec.declared_params):
        if declared.startswith('array') or declared.startswith('seq'):
            params.append('array_pub' if arg_role_taints[i] == 'pub' else 'array_sec')
        else:
            params.append(arg_taints[i])
    cp['methods'][key]['params'] = params
    return cp


def reachable(code: list[dict]) -> set[int]:
    succ: dict[int, list[int]] = {}
    for i, inst in enumerate(code):
        if inst['type'] in ('stop', 'raise'):
            succ[i] = []
        elif inst['type'] == 'goto':
            succ[i] = [inst['target']]
        elif inst['type'] == 'branch':
            succ[i] = [inst['thn'], inst['els']]
        elif inst['type'] == 'switch':
            succ[i] = [t for _, t in inst['cases']] + [inst['default']]
        else:
            succ[i] = [i + 1]
    seen, work = set(), [0]
    while work:
        i = work.pop()
        if i in seen or not (0 <= i < len(code)):
            continue
        seen.add(i)
        work.extend(succ[i])
    return seen


def _retarget(inst: dict, ci: int, delta: int):
    if inst['type'] == 'goto':
        inst['target'] = inst['target'] if inst['target'] <= ci else inst['target'] + delta
    elif inst['type'] == 'branch':
        inst['thn'] = inst['thn'] if inst['thn'] <= ci else inst['thn'] + delta
        inst['els'] = inst['els'] if inst['els'] <= ci else inst['els'] + delta
    elif inst['type'] == 'switch':
        inst['cases'] = [(v, t if t <= ci else t + delta) for v, t in inst['cases']]
        inst['default'] = inst['default'] if inst['default'] <= ci else inst['default'] + delta


def inline_one(result: dict, ci: int, spec: CalleeSpec, policy: dict) -> dict:
    """Splice one exact static call target with its translated body."""
    inst = result['code'][ci]
    if inst['type'] != 'step' or inst['kind'][0] != 'call':
        raise CompositionError('inline site is not a call step')
    kind = inst['kind']
    args = list(kind[2])
    heap_roles = list(kind[3])
    dst = inst['dst']
    if len(args) != len(spec.param_types):
        raise CompositionError(f'{spec.target}: argument count mismatch at site {ci}')
    arg_taints = [result['reg_taints'].get(a, 'sec') for a in args]
    arg_role_taints = [result['roles'].get(r, 'sec') for r in heap_roles]
    array_params = [i for i, t in enumerate(spec.param_types) if t.startswith('[') or t.startswith('L')]
    if len(heap_roles) != len(array_params):
        raise CompositionError(f'{spec.target}: heap argument/role count mismatch at site {ci}')
    # Compact heap roles to their parameter positions.
    role_taints_by_param = {p: 'sec' for p in range(len(spec.param_types))}
    for slot, p in enumerate(array_params):
        role_taints_by_param[p] = arg_role_taints[slot]
    arg_role_taints_full = [role_taints_by_param[i] for i in range(len(spec.param_types))]
    cp = _instance_policy(spec, arg_taints, arg_role_taints_full)
    callee = bt.translate(spec.method, policy, cp)
    failures = bt.audit_certificate(callee)
    if failures:
        raise CompositionError(
            f'{spec.target}: instantiated callee certificate rejected: {failures[0]["problem"]}')
    off = result['registers']

    # Sites: retain the callee's actual bytecode sites for provenance.
    site_map = {}
    site_offset = len(result['sites'])
    for s in callee['sites']:
        site_map[s['site']] = s['site'] + site_offset
        result['sites'].append(dict(s))

    def new_site(what: str) -> int:
        sid = len(result['sites'])
        result['sites'].append({'site': sid, 'class': spec.owner, 'method': spec.name,
                                'descriptor': spec.descriptor, 'offset': -1, 'what': what})
        return sid

    # Roles: a callee *parameter* role must be the exact plain identity emitted
    # by setup_params (`f'{owner}.{name}#p{i}'` for an array parameter `i`) and
    # aliases the caller's actual array role. Anything else that looks like a
    # parameter role (a merged/derived role such as `merge:...#p0|...`, a stale
    # index, or a role attached to a scalar parameter) is not a plain parameter
    # identity: reject it instead of silently aliasing it to a caller role (F2).
    param_roles = {f'{spec.owner}.{spec.name}#p{i}': i for i in array_params}
    role_map = {}
    for name in sorted(callee['roles']):
        if name.startswith('merge:'):
            raise CompositionError(
                f'{spec.target}: merged array role {name!r} cannot be aliased to a caller role')
        if '#p' in name:
            p = param_roles.get(name)
            if p is None:
                raise CompositionError(
                    f'{spec.target}: role {name!r} is not an exact plain parameter role')
            role_map[name] = heap_roles[array_params.index(p)]
        else:
            role_map[name] = f'{spec.target}@inline{ci}:{name}'

    # Call targets: reuse existing ids, otherwise allocate stable new ones.
    target_map = {}
    callee_id_to_target = {v: k for k, v in callee['call_targets'].items()}
    for cid, ctarget in callee_id_to_target.items():
        if ctarget in result['call_targets']:
            target_map[cid] = result['call_targets'][ctarget]
        else:
            new_id = max(result['call_targets'].values(), default=0) + 1
            result['call_targets'][ctarget] = new_id
            target_map[cid] = new_id

    def reg(r: int) -> int:
        return off + r

    inserted: list[dict] = []
    for i, t in enumerate(spec.param_types):
        if i in array_params:
            continue
        inserted.append({'type': 'step', 'site': new_site('inline-entry'),
                         'dst': reg(callee['param_regs'][i]),
                         'kind': ('op', 'cast', args[i], 0),
                         'ann': arg_taints[i]})

    # Positions shift by entry copies and by per-return result copies, so branch
    # targets must use the inserted position of each callee instruction.
    src = callee['code']
    pos = [None] * len(src)
    cur = len(inserted)
    for local, cinst in enumerate(src):
        pos[local] = cur
        if cinst['type'] != 'stop':
            cur += 1
        else:
            if cinst.get('ret') is not None and spec.result_type != 'V':
                cur += 1
            cur += 1
    pending_cont: list[dict] = []
    for local, cinst in enumerate(src):
        t = cinst['type']
        if t == 'step':
            k = cinst['kind']
            if k[0] == 'lit':
                nk = k
            elif k[0] == 'op':
                nk = ('op', k[1], reg(k[2]), reg(k[3]))
            elif k[0] == 'len':
                nk = ('len', role_map[k[1]])
            elif k[0] == 'load':
                nk = ('load', role_map[k[1]], reg(k[2]))
            elif k[0] == 'store':
                nk = ('store', role_map[k[1]], reg(k[2]), reg(k[3]))
            elif k[0] == 'alloc':
                nk = ('alloc', role_map[k[1]], reg(k[2]))
            elif k[0] == 'call':
                nk = ('call', target_map[k[1]], [reg(a) for a in k[2]],
                      [role_map[r] for r in k[3]], k[4] if len(k) > 4 else False)
            else:
                raise CompositionError(f'{spec.target}: unsupported callee step {k}')
            ndst = 0 if k[0] == 'store' else reg(cinst['dst'])
            inserted.append({'type': 'step', 'site': site_map[cinst['site']],
                             'dst': ndst, 'kind': nk, 'ann': cinst['ann']})
        elif t == 'goto':
            inserted.append({'type': 'goto', 'target': ci + pos[cinst['target']]})
        elif t == 'branch':
            inserted.append({'type': 'branch', 'site': site_map[cinst['site']],
                             'cond': reg(cinst['cond']),
                             'thn': ci + pos[cinst['thn']],
                             'els': ci + pos[cinst['els']]})
        elif t == 'switch':
            inserted.append({'type': 'switch', 'site': site_map[cinst['site']],
                             'cond': reg(cinst['cond']),
                             'cases': [(v, ci + pos[tt]) for v, tt in cinst['cases']],
                             'default': ci + pos[cinst['default']]})
        elif t == 'raise':
            inserted.append({'type': 'raise', 'site': site_map[cinst['site']]})
        elif t == 'stop':
            if cinst.get('ret') is not None and spec.result_type != 'V':
                ret_taint = callee['reg_taints'].get(cinst['ret'], 'sec')
                if ret_taint == 'sec' and result['reg_taints'].get(dst) != 'sec':
                    raise CompositionError(
                        f'{spec.target}: secret callee result cannot flow into public destination at site {ci}')
                inserted.append({'type': 'step', 'site': new_site('inline-return'),
                                 'dst': dst, 'kind': ('op', 'cast', reg(cinst['ret']), 0),
                                 'ann': result['reg_taints'].get(dst, 'sec')})
            g = {'type': 'goto', 'target': None}
            pending_cont.append(g)
            inserted.append(g)
        else:
            raise CompositionError(f'{spec.target}: unsupported callee terminator {t}')
    cont = ci + len(inserted)
    for g in pending_cont:
        g['target'] = cont

    # Registers and taints: fresh SSA block per call site, instantiated params.
    result['registers'] = off + callee['registers']
    for r, taint in callee['reg_taints'].items():
        result['reg_taints'][off + r] = taint
    for i, t in enumerate(spec.param_types):
        if i in array_params:
            continue
        result['reg_taints'][off + callee['param_regs'][i]] = arg_taints[i]
    # Roles: aliased parameter roles must have exactly the caller's taint.
    for name in sorted(callee['roles']):
        mapped = role_map[name]
        taint = callee['roles'][name]
        if mapped in result['roles']:
            if result['roles'][mapped] != taint:
                raise CompositionError(
                    f'{spec.target}: role {mapped} taint {taint} disagrees with caller '
                    f'{result["roles"][mapped]} at site {ci}')
        else:
            result['roles'][mapped] = taint

    delta = len(inserted) - 1
    prefix, suffix = result['code'][:ci], result['code'][ci + 1:]
    for x in prefix + suffix:
        _retarget(x, ci, delta)
    result['code'] = prefix + inserted + suffix
    seen = reachable(result['code'])
    if len(seen) != len(result['code']):
        raise CompositionError(
            f'{spec.target}: inline expansion left {len(result["code"]) - len(seen)} unreachable instructions')
    result['instructions_reachable'] = len(seen)
    sig = json.dumps(shape_signature(callee), sort_keys=True).encode()
    result.setdefault('inlined', []).append({
        'target': spec.target, 'site': ci, 'owner': spec.owner,
        'method': spec.name, 'descriptor': spec.descriptor,
        'callee_instructions': len(callee['code']),
        'callee_registers': callee['registers'],
        'callee_roles': sorted(callee['roles']),
        'callee_shape_sha256': hashlib.sha256(sig).hexdigest(),
    })
    return result


def inline_owned_callees(result: dict, specs: dict[str, CalleeSpec], policy: dict) -> dict:
    """Inline every call whose exact target is a certified owned callee."""
    while True:
        if (len(result.get('inlined', [])) >= MAX_INLINE_EVENTS
                or len(result['code']) > MAX_INLINE_INSTRUCTIONS):
            raise CompositionError(
                'inline expansion limit exceeded (possible unbounded or recursive callee): '
                + ', '.join(sorted(specs)))
        id_to_target = {v: k for k, v in result['call_targets'].items()}
        found = None
        for ci, inst in enumerate(result['code']):
            if inst['type'] == 'step' and inst['kind'][0] == 'call':
                target = id_to_target.get(inst['kind'][1])
                if target in specs:
                    found = (ci, specs[target])
                    break
        if found is None:
            break
        result = inline_one(result, found[0], found[1], policy)
    return result


def active_targets(result: dict) -> dict[str, int]:
    """Drop call-table entries no longer referenced by the composed code."""
    used = {inst['kind'][1] for inst in result['code']
            if inst['type'] == 'step' and inst['kind'][0] == 'call'}
    return {target: tid for target, tid in result['call_targets'].items() if tid in used}


def shape_signature(result: dict) -> tuple:
    """Instruction-shape signature used to bind an inlined body to its root.

    Taints, sites, role *names* and register numbers are excluded; the callee
    body's opcode/kind sequence and terminator shape must match the separately
    certified translation exactly.
    """
    id_to_target = {v: k for k, v in result.get('call_targets', {}).items()}
    sig = []
    for inst in result['code']:
        if inst['type'] == 'step':
            kind = inst['kind']
            if kind[0] == 'call':
                sig.append((inst['type'], kind[0], len(kind[2]), len(kind[3]),
                            id_to_target.get(kind[1], '')))
            else:
                sig.append((inst['type'], kind[0]))
        else:
            sig.append((inst['type'],))
    return tuple(sig)


WITNESS_LIMIT = 96
#: Fail-closed step cap for the witness execution control. A witness state that
#: does not reach a terminal instruction within this many steps is not called a
#: completed execution (F5).
WITNESS_STEP_CAP = 1 << 18


def has_secret(result: dict) -> bool:
    return (any(t == 'sec' for t in result['reg_taints'].values())
            or any(t == 'sec' for t in result['roles'].values()))


def witness(result: dict) -> dict | None:
    """A secret-pair witness, with a validated finite execution when possible.

    Public registers/roles agree exactly and every secret array role has equal
    length but different contents. Only *private inputs* differ initially: the
    private scalar parameter registers and the secret array contents. Every
    other secret register (i.e. every secret register that is not a declared
    scalar parameter) is initialised to the same word (zero) in both states, so
    a register that differs in the final state must have been made to differ by
    the executed program, not by its initial value (M2: no false liveness from
    unexecuted registers).

    Returns None when the program has no secret register or heap role
    (public-only), or when the concrete state is too large for a single
    solver-reducible `Agree` assertion (the composed Feed); the generic TwoRun
    theorem still covers it.

    The returned witness carries an `execution` block only when both witness
    runs reach a terminal instruction at the same validated fuel (executed by
    `trace_exec`, which mirrors the frozen model). If no finite execution is
    found, `execution` and `fuel` are None and the emitted lemma is restricted
    to hypothesis satisfiability: a fuel-truncated prefix is never reported as a
    completed run.

    The `execution` block records which registers differ at the end
    (`differing_registers`), which secret roles were zeroed
    (`zeroed_roles`), and how many stores each role received
    (`role_store_counts`, indexed like `sorted(result['roles'])`). `run.py`
    gates the private-scalar liveness and secret-parameter-array clearing
    obligations on those facts.
    """
    registers = result['registers']
    if registers > WITNESS_LIMIT or len(result['code']) > WITNESS_LIMIT * 2:
        return None
    role_names = sorted(result['roles'])
    param_regs = sorted(set(result.get('param_regs') or []))
    param_set = set(param_regs)
    # Small, non-collapsing public words: 1 keeps shift/mask computations live
    # (a larger public shift can annihilate a small secret witness) while array
    # lengths come from the witness heap, not from these registers. Secret
    # registers that are not scalar parameters start equal (zero) in both runs.
    def initial(secret_value: int) -> list[int]:
        out = []
        for r in range(registers):
            if result['reg_taints'].get(r, 'sec') == 'pub':
                out.append(1)
            elif r in param_set:
                out.append(secret_value)
            else:
                out.append(0)
        return out

    regs_s = initial(11)
    regs_t = initial(13)
    heap_s, heap_t = [], []
    secret = any(result['reg_taints'].get(r, 'sec') == 'sec' for r in range(registers))
    for name in role_names:
        if result['roles'][name] == 'pub':
            heap_s.append([1, 1, 1, 1])
            heap_t.append([1, 1, 1, 1])
        else:
            heap_s.append([1, 2, 3, 4])
            heap_t.append([5, 6, 7, 8])
            secret = True
    if not secret:
        return None
    view = trace_exec.ProgramView(result)
    start = max(32, len(result['code']) + 8)
    run_s = trace_exec.run_to_completion(view, regs_s, heap_s, start, WITNESS_STEP_CAP)
    execution = None
    fuel = None
    if run_s is not None:
        fuel = run_s['fuel_used']
        run_t = trace_exec.run_to_completion(view, regs_t, heap_t, fuel, fuel)
        if (run_t is not None and run_t['terminal'] == run_s['terminal']
                and len(run_t['events']) == len(run_s['events'])):
            differing = trace_exec.differing_registers(view, run_s['regs'], run_t['regs'])
            zeroed = []
            for index, name in enumerate(role_names):
                if result['roles'][name] != 'sec':
                    continue
                before = heap_s[index]
                after = run_s['heap'][index]
                if before and any(v != 0 for v in before) and after and all(v == 0 for v in after):
                    zeroed.append(index)
            store_counts = [0] * len(role_names)
            for event in run_s['events']:
                if event[0] == 'store':
                    store_counts[event[2][0]] += 1
            execution = {
                'terminal': run_s['terminal'],
                'steps': run_s['steps'],
                'events': len(run_s['events']),
                'counts': dict(run_s['counts']),
                'store_events': [i for i, event in enumerate(run_s['events'])
                                 if event[0] == 'store'],
                'store_roles': [event[2][0] for event in run_s['events']
                                if event[0] == 'store'],
                'role_store_counts': store_counts,
                'differing_registers': differing,
                'public_registers_agree': all(
                    view.reg_taint(r) != 'pub' for r in differing),
                'zeroed_roles': zeroed,
                'final_heap': [list(role) for role in run_s['heap']],
                'fuel': fuel,
            }
    return {'regs_s': regs_s, 'regs_t': regs_t, 'heap_s': heap_s, 'heap_t': heap_t,
            'fuel': fuel, 'execution': execution}
