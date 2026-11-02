"""Optional certificate layout for large extracted programs.

The existing emitter and observer are unchanged. Chunk lemmas establish
Structure for the concrete Layout; a verified opaque function returns exactly
that Layout. Its proved postconditions let TwoRun apply the model theorem
without repeatedly unfolding hundreds of instructions. Opacity affects solver
unfolding, not the theorem's premises, fuel domain, or observation trace.

LayoutIdentity proves the connection to the concrete program. The bytecode
mapper remains trusted, as it is with the original emitter. This module does
not admit bytecodes, callees, receiver assumptions, or runtime contracts.
"""
if __package__:
    from . import bytecode_trace as bt
else:
    import bytecode_trace as bt


def certificate_module(name: str, result: dict) -> str:
    """Emit the same concrete IR with verified Structure and universal TwoRun.

    This emitter deliberately supplies no witness: callers must execute their
    finite controls separately and report their completion and liveness. Old
    certificate outputs continue to use bytecode_trace.certificate_module.
    """
    source = bt.certificate_module(name, result, check_only=True)
    if not source.endswith('\n}\n') or source.count('  function P(): Program {') != 1:
        raise ValueError('unexpected base certificate layout')
    source = source[:-3].replace('P()', 'Layout()')
    count = len(result['code'])
    return source + f'''

  opaque function P(): Program
    ensures Structure(P())
    ensures P().instructions == {count}
  {{
    WellFormed();
    Layout()
  }}

  lemma LayoutIdentity()
    ensures P() == Layout()
  {{
    reveal P();
  }}

  lemma TwoRun(s: State, t: State, fuel: nat)
    requires Agree(P(), s, t)
    ensures Exec(P(), 0, s, fuel).1 == Exec(P(), 0, t, fuel).1
  {{
    ExecTwoRun(P(), 0, s, t, fuel);
  }}
}}
'''
