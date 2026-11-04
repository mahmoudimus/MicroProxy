# HKDF traces over executable Dafny

The paired-execution harness calls the actual production `Extract`, `Expand`,
`LabelInfo` and `ExpandLabel` methods in
[`Hkdf.dfy`](../../dafny/hkdf/Hkdf.dfy). Their ghost trace outputs are erased when
that same verified source generates Java. There is no second HKDF algorithm.

For arbitrary private byte contents, equal public shapes produce equal source
observation traces and equal success/failure shapes. Hash choice, lengths and
TLS label units are public. The general functional input domain is preserved,
including invalid hash/length/key/label outcomes and accepted boundary cases.
The included proof has 248 verified checks; the paired/domain harness has 259.
These are universal obligations under the contracts, not sampled test inputs.

The actual event helpers prove retention of tags, widths, branch outcomes,
sequence addresses/lengths, call targets/arity and provider-call metadata. A
trusted C# adapter over Dafny's resolved AST separately checks coverage and
ordered updates of the exact ghost output: every accepted call has its own
output binding and one immediate append; roots and markers have exact resolved
identities; unsupported statements/expressions and by-method functions reject.
It rejects trace resets, missing/reordered observations, shadow declarations,
private datatype equality and incomplete loop observations. The paired proof
alone does not establish this coverage connection. The C# checker is reviewed
and tested, not formally proved correct.

The binding scan uses an exact positive statement-class grammar over every
resolved descendant, including ghost/proof blocks. Unsupported forms such as
assign-such-that (`:|`) and statement expressions reject. Ghost/lemma calls
with output bindings also reject, and no call may replace the actual trace
output. This restriction is on the supported instrumentation language; it
does not narrow the cryptographic methods' input domain.

Site IDs are bounded nonnegative integer literals unique per static marker in
each method. They are opaque method-local annotation labels, not physical
source positions or JVM program counters. A consistent fresh relabel is valid;
colliding/nonliteral labels reject. Semantic event arguments and order remain
checked. `Ops` records operation counts, not instruction order or cost.

From the repository root:

```sh
python3 -m unittest discover -s formal/source/hkdf -p 'test_*.py' -v
python3 formal/source/hkdf/run.py --output /fresh/hkdf-source-traces
```

The output must not exist. Every log, copied input, checker build and receipt
stays inside it. The runner freezes its complete reviewed input inventory
before importing tool helpers, discovers includes using the pinned official
Dafny parser, audits every included file, and uses Dafny 4.9.1/Z3 with the
30-second, 50-million-resource, case-split-zero policy. The existing external
`Mac` contract is the one allowed assumption. Parser errors, tool crashes,
resource exhaustion and timeouts do not qualify as proof-control failures.

The 72 control records include one accepted fresh relabel and 71
rejection/audit/proof records. Historical frozen fault sources are distinguished
from controls generated on the current source. Metadata defects must fail real
Dafny obligations in their exact affected encoder declarations; each filtered
encoder is also checked positively and the full baseline remains verified.
This avoids treating unrelated failures in intentionally broken programs as
semantic evidence. Faithfully observed private behavior must fail the paired
trace equality; omitted observations must fail the coverage adapter.
The assign-such-that regression also replays its complete body and paired
proofs (246 and 257 checks) and checks generated-Java identity: those gates
still pass for the forged observation, so the named coverage rejection is
essential.

Java checks use the actual repository generated package and three production
adapter/provider sources. All nine generated package files, the top-level
aggregator, twelve compiled classes and the four public method signatures must
match. These finite artifact checks support delivery under compiler trust;
they do not prove the compiler's semantics or Java adapter refinement.

Dafny/Boogie/Z3, the compiler and ghost erasure, .NET/build environment, the
coverage adapter, javac/DafnyRuntime/JVM and JCE HMAC remain trust assumptions.
This component does not establish HMAC security, physical constant-time JVM
execution, cryptographic hardness, whole TLS/QUIC security or external expert
review. Cross-component trace composition and the common typed codec remain
separate obligations. Existing bytecode evidence remains supplementary.
