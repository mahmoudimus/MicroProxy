# Checked secret-trace evidence

The checked snapshot is `PRODUCTION-EVIDENCE.json`, SHA-256
`85fcbfb445ac0ceaecd82fd19a51a935cbec24aa68474e5a547f67c72a077f47`.
It records the 2026-11-02 macOS arm64 replay at
`/Users/mahmoud/.cache/microproxy-formal/issue117-20261101/keccak-linux-hints-full-replay/report.json`
(workspace `replay-bnc6incm`) over the preserved JDK 21 library classes.
The central ledger pins the snapshot and independently requires its input,
root, fixture, execution-control and residual inventories. A future receipt
needs source review and an explicit checker-baseline renewal.

This is conditional trace evidence under the frozen `SecretTrace` observer.
It is not exact Java/JVM value refinement, physical timing, cryptographic
hardness, implicit-exception coverage or physical secret erasure.

## Replay and controls

- Dafny `4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2`; Z3 `4.12.1`.
- Homebrew JDK `21.0.12.1`; DafnyRuntime SHA-256
  `dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6`.
- 138 pinned inputs and 77 matching source-rebuilt class bindings.
- 197 unit tests by discovery, with two optional expensive replays skipped. The
  complete replay above executes both proof components; its API regression is
  also run separately. The trace module/direct script retains its 90 tests.
  The ledger/release suite separately checks receipt semantics, including
  corruption after snapshot-digest renewal; all 200 ledger/release tests pass.
- Unchanged `SecretTrace.dfy`: 57 verified declarations; unchanged
  `HkdfShape.dfy`: 17; compiled positive control executed.
- Compiled `ApplyProbe.dfy`: 138 rows and nine operand-sensitive expectations,
  compared with the bounded execution-control interpreter. This checks the
  interpreter against the model; it does not prove the interpreter correct.
- 27 fixtures: four accepted (`ConstantTime`, `PublicEuclidean`,
  `LongSlotPublic`, `HeapExternalPublic`), 23 normal policy rejections.
- Four Select certificate mutants and twelve callee mutants rejected with genuine
  proof-obligation failures. Parser, crash, timeout and resource failures never
  count as successful negative controls.

## Exception-table and member-boundary guards

An additional guard repair records the actual javap `Exception table:` header
independently of parsed rows, skips the table's column header and preserves its
protected ranges. Every method with a declared table is rejected; malformed
numeric rows cause a hard parse failure. Previously the column header ended
parsing early, leaving the handler list empty and allowing handler code to be
omitted. Real typed-catch, catch-all and finally controls reproduce that defect
and now reject; a no-table control is still accepted. Empty-table and malformed
row controls also reject.

The same review found that declarations ending in `throws` were not recognized:
a sibling's body could be merged with the preceding method and silently dropped
from its certificate. Such declarations are now recognized as distinct members;
each descriptor/Code array must bind to its own recognized declaration. Orphan or
repeated Code arrays, unbound descriptors, and non-increasing bytecode offsets
are rejected. Positive controls retain separate no-handler throws methods,
constructors/static initializers, fields and abstract/native members. The 15
additional tests are in the pinned input inventory. Member boundaries still
rely on javap's reviewed `-c -p -s` layout; these guards are not a parser proof.

All selected caller, helper and expanded Feed bodies lack exception tables.
Their certificate bodies are unchanged apart from the repository include path;
proof counts, solver limits, policies, execution controls and residual
inventories are unchanged. Of the four handler-bearing wrapper methods, only `JdkHmac.compute` is an
explicit opaque owned contract; the other three are outside the certified call
graph. Extract and Expand call `compute`, whose exceptions are not modeled.
This repair strengthens the trusted extractor's rejection boundary;
it does not verify exceptions or eliminate those owned assumptions.

## Checked certificates

| Caller | Instructions/reachable | Verified declarations | Budget |
|---|---:|---:|---|
| NativeMlKem.Select | 75/75 | 84 | 30 s / 50 M |
| NativeSampling.Feed | 167/167 | 179 | 120 s / 200 M |
| VerifiedHkdf.Extract | 30/30 | 34 | 30 s / 50 M |
| VerifiedHkdf.Expand | 103/103 | 111 | 120 s / 200 M |
| VerifiedHkdf.LabelInfo | 158/158 | 169 | 120 s / 200 M |

| Additional certificate | Instructions/reachable | Verified declarations | Scope |
|---|---:|---:|---|
| NativeCodec.Extract, including Pow2 | 87/87 | 97 | private accumulator; public shift/width |
| NativeCodec.Pow2 | 62/62 | 57 | public inputs only |
| NativeCodec.PublicMod | 2/2 | 7 | public dividend/divisor only |
| NativeCodec.Wipe | 19/19 | 25 | private array contents; public length |
| Composed NativeSampling.Feed | 369/369 | 393 | public seed/prefix; three helper bodies expanded |

Extract uses 120 s / 100 M; Pow2/PublicMod/Wipe use 30 s / 50 M; the composed
Feed uses 180 s / 400 M. Exact solver options, including omitted case-split
overrides, are retained in the snapshot. Budgets were not padded.

## Additional checked helper bodies

The two static adapter helpers are checked roots; exactly `sequence` and
`labelUnits` leave the open-root list (15 to 13). Nine NativeField roots support
seven fully expanded private arithmetic bodies and two public constant leaves.
All new certificates use 30 s / 50 M with the existing case-split option.

| Body | Instructions/reachable | Verified declarations |
|---|---:|---:|
| verifiedhkdf.sequence | 5/5 | 11 |
| verifiedhkdf.labelUnits | 23/23 | 28 |
| NativeField.ReduceOnce | 23/23 | 29 |
| NativeField.Reduce | 45/45 | 53 |
| NativeField.Add | 31/31 | 37 |
| NativeField.Sub | 35/35 | 43 |
| NativeField.Mul | 53/53 | 61 |
| NativeField.MulSub | 59/59 | 67 |
| NativeField.AddMul | 55/55 | 63 |
| NativeField.Q | 2/2 | 7 |
| NativeField.MaxReduce | 2/2 | 7 |

Every expanded private field body has zero opaque owned calls; the existing
`Helpers.bv64ShiftRight(secretWord, publicCount)` contract remains. Its public
count is enforced by the trusted audit gate, not by the SMT theorem alone. The
model's shift value is abstract; functional modular-arithmetic proofs are
separate. The `Witness` read is represented as a public literal and is overwritten
before use. The two public leaves are constants, not additional arithmetic proofs.

The new `execution_controls.py` uses the frozen interpreter with distinct
per-parameter cohorts, other private registers zero and fresh roles equal.
Seven field pairs terminate with equal observations/public state, non-parameter
private flow and a differing terminal return register. A required private control
must be `ok`; a public-only `not-applicable` cannot satisfy it. These are finite
controls, not universal return-liveness or JVM value-refinement proofs.

For `sequence`, the differing private input role is exercised; modeled
allocations are constant-filled. Neither copied content, alias ownership nor
private output-copy liveness is proved. `AliasNoClone` is trace-equivalent under
this observer. `labelUnits` is all-public, with `alloc_public` narrowed to pc 11;
model runs at lengths 0/1/3/5 execute that many stores. This is a property under
`ProviderResult(String.length)`, not a theorem about `java.lang.String`.

The original five callers, four codec helpers and separate Feed retain identical
mathematical certificate bodies (only repository include paths differ). The
19-caller contract union and 31 aggregate unchecked labels remain; the broader
field/NTT/codec/sampling label stays because its callers and other helpers are
unfinished. The receipt's TCB and partial-composition disclosures are validated
independently of an accepted snapshot-digest renewal.

## Expanded Keccak trace supplement

Seven actual generated Keccak methods are translated and composed into separate
certificates. All owned calls and both DafnyRuntime word-shift bodies in these
programs are expanded. The original five-caller assumption inventory is retained;
this supplement does not silently replace those caller certificates.

| Body | Instructions | Verified declarations |
|---|---:|---:|
| Rotate | 32 | 48 |
| Theta | 130 | 163 |
| RhoPi | 59 | 80 |
| Iota | 12 | 29 |
| Chi | 46 | 67 |
| Round | 249 | 294 |
| PermuteScratch | 407 | 472 |

`PublicProvider.dfy` has 16 checks, `PublicProviderPublic.dfy` nine, and
`WordArithmetic.dfy` 56. They preserve the frozen observer's events, faults and
fuel and extend calls with the same pure total public oracle in both executions.
Each concrete certificate proves that every remaining call has a known target,
exact argument count, public scalar arguments and no heap arguments. The total
fallback oracle is unreachable for these programs' call shapes. Provider purity,
JVM narrowing, BigInteger identity and primitive costs remain trusted boundaries.
All new proofs use 30 s / 50 M and the existing case-split option. The Linux solver
initially exhausted its budget on `Div5_16`; six intermediate assertions repair
that proof without changing its result, functions, assumptions or budget. The
original Linux binary reproduces the failure; the repaired three models and
seven certificates all verify with that binary at the same limits.

The actual pinned `Helpers.class` left/right bodies each have 12 checks with a
witness and 11 without. Their branch depends on the public byte count; private
count variants fail the named `Chunk0.InstrOK` branch obligation (nine checks,
two genuine errors each). A Java/model adapter compares 28 input rows, 56 results,
including counts 64 and 65. This is a bounded value check, not JVM refinement.

The completed `PermuteScratch` control executes all 24 rounds in each cohort:
54,340 steps with fuel 106,240, private lanes/scratch/parity and public offset/
source arrays of honest lengths 25/25/5/25/25. Both runs stop without a fault,
produce equal observations and public state, and retain live private input/output
differences. Compiled Dafny public arithmetic matches Python in 243 finite cases.
Secret-branch, secret-index and four public-call mutants fail their named proof
obligations; insufficient fuel, bounds faults and equal private cohorts cannot
count as completed private controls.

The receipt binds loaded checker modules, actual source/class bytes, runtime
entry and JDK/Dafny/solver identities before and after replay. The independent
static gate additionally pins the exact per-root provider IDs/counts, inline
sequence, actual callee body/class hashes, certificate/public-contract agreement
and named negative diagnostics. Certificate, oracle and proof-log identities
were checked against the actual preserved replay artifacts and independently
pinned; the proved file must match the claimed certificate/model. Recomputing a report-local hash or renewing the
accepted report digest alone cannot satisfy those identities. These checks are
trusted Python tooling, not a proof of the mapper or evidence checker itself.

`Permute`'s array-return factories, Sponge receiver/alias ownership and trace
composition, complete NTT/KEM/adapter traces, physical timing and external expert
review remain outside this supplement. The 13/19/31 residual inventories stay
unchanged. Functional SHAKE/ML-KEM source proofs remain a distinct claim.

## Execution witnesses and their limits

Only private inputs differ initially; other private registers start equally at
zero. The finite model-execution control checks termination, trace equality,
public-register agreement and the declared witness contract. Wipe completes
in 51 steps with four stores to its secret parameter role and a zeroed
four-element heap. Extract completes in 18 steps: parameter registers are
`[1,2,3]`, differing registers `[1,7]`, and register 7 is a live non-parameter
private value. The replay rejects parameter-only liveness or clearing the wrong
role. These are finite execution controls, not additional universal SMT proofs.

The Dafny witness lemma establishes differing states, `Agree` and an application
of `TwoRun` at the validated fuel. It does not assert a fully unrolled concrete
`Exec`: attempts to discharge that stronger assertion were inconclusive and are
not counted as proofs. Extract's atomic shift-helper model depends only on public
arguments, so the witness does not establish a private-dependent returned value.
The separate ExtractShape fixture tests private flow through explicit operations.
The large composed Feed has no concrete witness; its universal theorem remains
conditional on `Structure` and `Agree`.

## Runtime classification and composition

Ordinary calls in the reviewed Dafny/JDK namespaces (`dafny/`, `java/`,
`javax/`, `jdk/`, `sun/`, `com/sun/`) require public scalar and heap-content
arguments by default. Reviewed exceptions are the branch-free Byte unsigned
casts and both `Helpers.bv64ShiftLeft` and `Helpers.bv64ShiftRight` with a public shift
count. The expanded Keccak supplement separately checks their actual bodies. There are no
private-heap exceptions. Enumerated memory/shape primitives are distinct model
steps; their implementation semantics remain trusted. In particular, the pinned
Dafny Euclidean bodies branch on values: PublicMod is public-only. Policy/code
classification drift, unknown call IDs, merged parameter roles and recursion
are rejected. Arbitrary third-party namespaces are outside this classification
claim.

The original five caller certificates retain 19 opaque owned helper contracts.
The separate composed Feed expands Extract, PublicMod and Wipe, with Pow2 as a
supporting body, reducing Feed's opaque set from ten to seven. Replacing the
original Feed would reduce the five-caller union to 16; this snapshot keeps both
certificates and does not claim that replacement or whole-callee closure.
Thirteen roots and 31 aggregate unchecked labels remain open. Dispatch/object identity,
implicit exceptions, full arithmetic/value refinement and provider/runtime
internals remain outside the observer. Shape hashes check direct-translation
self-consistency; the splice and javap extractor are trusted, mutation-tested
bridges rather than proved JVM translations.

The reviewed target-to-model-kind mapping is pinned policy, without a second
independent target/kind inventory. Array-parameter references are connected by
role aliasing; the selected Wipe uses role-based length/stores. Extending to a
callee that reads a reference as a scalar needs an additional rule or entry copy.
Neither limitation affects the enumerated current callees.

## Superseded receipts

The earlier accepted snapshot `9782ef72...`, candidate `5f9faa87...`, and the
missing temporary `4db165b4...` candidate predate the copy correction. The
extractor put the source in operand a while model copy returns operand b, so
modeled local/loop values could be degenerate. All five caller certificate
hashes were replaced; the model itself was unchanged.

The preserved `helper-fixed-replay` receipt `9800c358...` includes the copy fix,
but predates the complete unit entry points and enforced witness contracts. It
is historical only. The preserved `helper-final-replay` receipt `245c1d77...` adds those controls.
The accepted helper snapshot `7161fb23...` retains those repairs and predates the
Keccak supplement. The current snapshot preserves the original 25 positive
certificate bodies, including fixtures, while adding the seven Keccak certificates
and their models/controls. The original budgets are unchanged. See `README.md`
for fresh replay commands.
