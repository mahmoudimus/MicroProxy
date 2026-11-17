"""Finite, paired-state execution controls for the newly checked trace roots.

These are *execution controls*, not proofs: they take an already translated
`result` (the exact program text that the emitted Dafny certificate contains),
seed two concrete states that differ **only in the private inputs**, run both
through the frozen `trace_exec` mirror of `SecretTrace.DoStep`/`Exec`, and record
whether the observation tapes agree while the private flow is still live.

Seeding scheme (fixed, deliberately stricter than `composition.witness`):

  * public registers carry the same value in both runs;
  * private **parameter** registers carry distinct per-ordinal values
    (run S: ``11 + 3*i``, run T: ``13 + 5*i``) so that expressions such as
    ``a + Q - b`` cannot cancel when every parameter is seeded with one value;
  * every other private scalar register starts at ``0`` in **both** runs, so a
    register that differs at the end was written by the executed program, never
    by state initialisation;
  * secret **parameter** heap roles differ in contents but agree in length;
    every other role (internal/fresh, public) starts *equal* — internal roles
    zero-filled, public roles identical — because their initial contents are not
    inputs.

Limits (kept explicit so no reader upgrades the claim):

  * the frozen model fills every allocation with a constant, so a copy/alias
    relation between an input role and a produced role is **not expressible**;
    the historical `HkdfBridge.sequence` fixture exercises only its input
    private pair, with no private-output/copy liveness claim. That method is
    retired from current roots; the fixture is a regression only;
  * provider results are abstract (`ProviderResult` returns the first public
    argument value or the target id), so the shift in `NativeField` carries the
    public shift count as its *value*; value-level arithmetic refinement and
    JVM semantics are out of scope;
  * only the chosen finite pair per program is checked — no universal value
    liveness and no claim that every operand affects the result.

The module is imported by `run.py` (to record controls for the promoted roots)
and by `test_coverage.py` (which exercises the gate properties). It uses only
the frozen `trace_exec`/`bytecode_trace` APIs; no new interpreter and no change
to the model, extractor or composition semantics.
"""
from __future__ import annotations

import bytecode_trace as bt
import composition as comp
import trace_exec

#: Seed ordinals for the two states. Distinct primes keep the per-parameter
#: values distinct *within* and *across* runs for any realistic arity.
SEED_S = (11, 3)
SEED_T = (13, 5)

#: Step cap for the finite execution (the reviewed composition witness cap).
STEP_CAP = comp.WITNESS_STEP_CAP

#: Prefix of every owned class/method target in this repository.
OWNED_PREFIX = 'io/github/mahmoudimus/'

#: Methods whose result is checked for the public shift-count admission rule.
SHIFT_CALL = 'dafny/Helpers.bv64ShiftRight:(JB)J'


def parameter_ordinals(result: dict) -> dict[int, int]:
    """Map each *private* scalar parameter register to its parameter ordinal.

    Public parameter registers hold public metadata (a role word or a public
    scalar) and are seeded with the same value in both runs; only private
    parameters carry the S/T input values.
    """
    view = trace_exec.ProgramView(result)
    return {register: ordinal
            for ordinal, register in enumerate(result.get('param_regs') or [])
            if view.reg_taint(register) == 'sec'}


def role_kind(name: str) -> str:
    """'parameter' for `…<method>#p<i>` roles, else 'internal'."""
    return 'parameter' if '#p' in name else 'internal'


def build_states(result: dict, seeds: tuple[tuple[int, int], tuple[int, int]] = (SEED_S, SEED_T),
                 role_length: int = 4) -> dict:
    """Two states that differ only in the private *inputs*.

    Returns the states plus the invariant facts a caller can assert on directly
    (this is what `test_coverage.py` checks without running the interpreter).
    """
    view = trace_exec.ProgramView(result)
    ordinals = parameter_ordinals(result)
    (base_s, step_s), (base_t, step_t) = seeds

    def registers(base: int, step: int) -> list[int]:
        out = []
        for register in range(result['registers']):
            if view.reg_taint(register) == 'pub':
                out.append(1)
            elif register in ordinals:
                out.append(base + step * ordinals[register])
            else:
                out.append(0)
        return out

    secret_parameter_roles = [name for name in sorted(result['roles'])
                              if result['roles'][name] == 'sec' and role_kind(name) == 'parameter']
    role_names = sorted(result['roles'])
    heap_s, heap_t = [], []
    for name in role_names:
        taint = result['roles'][name]
        parameter = role_kind(name) == 'parameter'
        if taint == 'sec' and parameter:
            heap_s.append([1, 2, 3, 4])
            heap_t.append([5, 6, 7, 8])
        elif taint == 'sec':
            heap_s.append([0] * role_length)
            heap_t.append([0] * role_length)
        else:
            heap_s.append([1] * role_length)
            heap_t.append([1] * role_length)

    regs_s, regs_t = registers(base_s, step_s), registers(base_t, step_t)
    public = [r for r in range(result['registers']) if view.reg_taint(r) == 'pub']
    secret = [r for r in range(result['registers']) if view.reg_taint(r) == 'sec']
    non_parameter = [r for r in secret if r not in ordinals]
    invariants = {
        'public_registers_equal': all(regs_s[r] == regs_t[r] for r in public),
        'non_parameter_private_start_at_zero': all(
            regs_s[r] == 0 and regs_t[r] == 0 for r in non_parameter),
        'parameter_values_differ_across_runs': all(
            regs_s[r] != regs_t[r] for r in ordinals),
        'parameter_values_distinct_within_run': (
            len({regs_s[r] for r in ordinals}) == len(ordinals)
            and len({regs_t[r] for r in ordinals}) == len(ordinals)),
        'role_lengths_equal': all(len(a) == len(b) for a, b in zip(heap_s, heap_t)),
        'non_parameter_role_contents_equal': all(
            heap_s[i] == heap_t[i] for i, name in enumerate(role_names)
            if not (result['roles'][name] == 'sec' and role_kind(name) == 'parameter')),
        'parameter_secret_role_contents_differ': all(
            heap_s[i] != heap_t[i] for i, name in enumerate(role_names)
            if result['roles'][name] == 'sec' and role_kind(name) == 'parameter'),
    }
    invariants['differences_are_inputs_only'] = all((
        invariants['public_registers_equal'],
        invariants['non_parameter_private_start_at_zero'],
        invariants['role_lengths_equal'],
        invariants['non_parameter_role_contents_equal'],
    ))
    return {'regs_s': regs_s, 'regs_t': regs_t, 'heap_s': heap_s, 'heap_t': heap_t,
            'parameter_registers': sorted(ordinals), 'parameter_ordinals': ordinals,
            'public_registers': public,
            'private_scalar_parameters': sorted(ordinals),
            'secret_parameter_roles': secret_parameter_roles,
            'parameters_seeded': bool(ordinals) or bool(secret_parameter_roles),
            'role_names': role_names, 'invariants': invariants}


def terminal_stop(result: dict) -> dict:
    """The single terminal `stop` instruction of a translated root program.

    The translator emits exactly one `stop`; composition rewrites a spliced
    callee's `stop` into a return copy plus a goto, so a composed root still has
    exactly one. More than one is ambiguous for the return-register obligation,
    so we refuse instead of guessing.
    """
    stops = [index for index, inst in enumerate(result['code']) if inst['type'] == 'stop']
    if len(stops) != 1:
        raise bt.PolicyError('expected exactly one terminal stop, found %d' % len(stops))
    return {'index': stops[0], 'ret': result['code'][stops[0]].get('ret')}


def owned_call_targets(result: dict) -> list[str]:
    return sorted(target for target in result.get('call_targets', {})
                  if target.startswith(OWNED_PREFIX))


def _shift_counts_public(result: dict) -> dict:
    """Every `bv64ShiftRight` call must pass a public shift count (existing rule)."""
    id_to_target = {ident: target for target, ident in result.get('call_targets', {}).items()}
    calls = []
    for step in result['code']:
        if step['type'] != 'step' or step['kind'][0] != 'call':
            continue
        if id_to_target.get(step['kind'][1]) != SHIFT_CALL:
            continue
        count = step['kind'][2][1]
        calls.append({'count_register': count,
                      'count_taint': result['reg_taints'].get(count, 'sec'),
                      'word_taint': result['reg_taints'].get(step['kind'][2][0], 'sec')})
    return {'shift_calls': calls,
            'all_counts_public': all(call['count_taint'] == 'pub' for call in calls)}


def paired_control(result: dict, *, require_liveness: bool,
                   expect_return_register: int | None = None,
                   step_cap: int = STEP_CAP, require_no_owned_calls: bool = True,
                   seeds: tuple[tuple[int, int], tuple[int, int]] = (SEED_S, SEED_T)) -> dict:
    """Run the finite paired-state control for one translated program."""
    audit = bt.audit_certificate(result)
    shift = _shift_counts_public(result)
    owned = owned_call_targets(result)
    record: dict = {
        'kind': 'paired-state-execution-control',
        'model': 'trace_exec.py (frozen SecretTrace Apply/DoStep/Exec mirror)',
        'seeds': {'S': list(seeds[0]), 'T': list(seeds[1])},
        'require_liveness': bool(require_liveness),
        'audit_failures': audit,
        'owned_call_targets': owned,
        'shift_count_rule': shift,
    }
    states = build_states(result, seeds=seeds)
    record['state_invariants'] = states['invariants']
    record['parameter_registers'] = states['parameter_registers']
    record['private_scalar_parameters'] = states['private_scalar_parameters']
    record['secret_parameter_roles'] = states['secret_parameter_roles']
    record['public_registers'] = states['public_registers']
    if not states['parameters_seeded']:
        record['status'] = ('not-applicable: no private parameters or private parameter roles')
        return record
    try:
        stop = terminal_stop(result)
    except bt.PolicyError as error:
        record['status'] = 'FAILED'
        record['reason'] = 'terminal-stop: ' + str(error)
        return record
    record['return_register'] = stop['ret']
    if expect_return_register is not None and expect_return_register != stop['ret']:
        record['status'] = 'FAILED'
        record['reason'] = ('return-register-mismatch: expected %r, terminal stop returns %r'
                            % (expect_return_register, stop['ret']))
        return record
    view = trace_exec.ProgramView(result)
    start = max(32, len(result['code']) + 8)
    run_s = trace_exec.run_to_completion(view, states['regs_s'], states['heap_s'],
                                         start, step_cap)
    if run_s is None:
        record['status'] = 'FAILED'
        record['reason'] = 'no-finite-execution-within-step-cap (truncated prefix is not a run)'
        return record
    run_t = trace_exec.run_to_completion(view, states['regs_t'], states['heap_t'],
                                         run_s['fuel_used'], run_s['fuel_used'])
    if run_t is None:
        record['status'] = 'FAILED'
        record['reason'] = 'second run did not terminate at the validated fuel'
        return record
    differing = trace_exec.differing_registers(view, run_s['regs'], run_t['regs'])
    record.update({
        'terminal': {'s': run_s['terminal'], 't': run_t['terminal']},
        'fuel': run_s['fuel_used'],
        'steps': {'s': run_s['steps'], 't': run_t['steps']},
        'events': {'s': run_s['events'], 't': run_t['events']},
        'event_counts': {'s': run_s['counts'], 't': run_t['counts']},
        'trace_equal': run_s['events'] == run_t['events'],
        'public_registers_equal': all(run_s['regs'][r] == run_t['regs'][r]
                                      for r in states['public_registers']),
        'differing_registers': differing,
        'non_parameter_differing': [r for r in differing
                                    if r not in states['parameter_registers']],
        'return_differs': (stop['ret'] is not None
                           and run_s['regs'][stop['ret']] != run_t['regs'][stop['ret']]),
    })
    record['parameter_only_liveness'] = (bool(differing)
                                         and set(differing) <= set(states['parameter_registers']))
    checks = {
        'state_differences_are_inputs_only': states['invariants']['differences_are_inputs_only'],
        'both_terminal_stop': record['terminal'] == {'s': 'stop', 't': 'stop'},
        'trace_equal': record['trace_equal'],
        'public_registers_equal': record['public_registers_equal'],
        'no_parameter_only_liveness': not record['parameter_only_liveness'],
        'audit_clean': not audit,
        'shift_counts_public': shift['all_counts_public'],
    }
    if require_liveness:
        checks['non_parameter_private_flow'] = bool(record['non_parameter_differing'])
        checks['return_value_differs'] = record['return_differs']
    if require_no_owned_calls:
        checks['no_owned_calls_remaining'] = not owned
    record['checks'] = checks
    record['status'] = 'ok' if all(checks.values()) else 'FAILED'
    if record['status'] == 'FAILED':
        record['reason'] = 'failed: ' + ', '.join(name for name, ok in checks.items() if not ok)
    return record


def length_control(result: dict, lengths: tuple[int, ...] = (0, 1, 3, 5),
                   step_cap: int = STEP_CAP) -> dict:
    """Bounded loop-length control for an all-public program such as `labelUnits`.

    The provider model returns the first public argument value for
    `String.length`, so seeding the string parameter register with L makes the
    unit array length L and the loop iterate exactly L times. This is a property
    of the *emitted program under the provider model*, not of a real `String`.
    """
    params = list(result.get('param_regs') or [])
    if not params:
        return {'kind': 'length-execution-control',
                'status': 'not-applicable: no parameter register to seed'}
    view = trace_exec.ProgramView(result)
    runs = []
    for length in lengths:
        regs = [1] * result['registers']
        regs[params[0]] = length
        heap = [[1] * length for _ in range(len(result['roles']))]
        run = trace_exec.run_to_completion(view, regs, heap,
                                           max(32, len(result['code']) + 8), step_cap)
        if run is None:
            runs.append({'length': length, 'status': 'no-finite-execution'})
            continue
        runs.append({
            'length': length,
            'status': 'ok' if run['terminal'] == 'stop' else 'FAILED',
            'terminal': run['terminal'],
            'stores': run['counts']['store'],
            'guards': run['counts']['guard'],
            'allocs': [event[2][1] for event in run['events'] if event[0] == 'alloc'],
            'alloc_sizes_match': all(size == length for event in run['events']
                                     if event[0] == 'alloc' for size in [event[2][1]]),
            'store_count_matches': run['counts']['store'] == length,
        })
    ok = all(item.get('status') == 'ok' and item.get('alloc_sizes_match')
             and item.get('store_count_matches') for item in runs)
    return {'kind': 'length-execution-control', 'lengths': list(lengths),
            'seed_register': params[0], 'runs': runs,
            'status': 'ok' if ok else 'FAILED',
            'note': 'emitted-program property under ProviderResult(String.length); '
                    'not a claim about java.lang.String'}
