# V7 secret-trace threat model and declassification ledger

Status: **scoped conditional trace evidence for the checked roots listed in
`policy.json`**. It is not a whole-JVM constant-time theorem, not a
cryptographic security proof, and not a statement about physical latency.
`JVM timing is deferred` is separate from any source/bytecode trace result.

## 1. Observer and two-run statement

For each checked root, a certificate extracted from actual bytecode satisfies
`SecretTrace.Structure` and the universal self-composition theorem
`ExecTwoRun`: for every two states related by `Agree` (equal public registers,
equal public array contents, equal array lengths) and every fuel, the observation
traces are equal. The trace records operation kinds, branch/switch outcomes,
array read/write addresses, terminal out-of-bounds faults, lengths/allocations,
provider dispatch and public arguments, and raise sites. Values are not observed
unless they control one of these; outputs may differ.

Fall-through edges are emitted as `IGoto` and the replay fails unless every
emitted terminator matches the bytecode CFG and every emitted instruction is
reachable from entry. `Structure` still checks all instructions, but the theorem
is applied to the full emitted program, not a prefix.

The bridge from class files to certificates remains the trusted extractor
(`bytecode_trace.py`). It is mutation-tested, not formally verified. Its operand
mapping and policy classification are the residual trusted step. Arithmetic is
abstract/deterministic: the theorem is about control-dependency shape, not JVM
value refinement.

Methods with a declared javap exception table are rejected before certificate
translation, including empty tables. The parser records table presence separately
from its rows and rejects malformed numeric rows. Real typed-catch, catch-all and
finally bytecode regressions check this guard against independently read javap
output. This guard covers explicit protected ranges; ordinary implicit exceptions
of handler-free methods remain outside the observer. The current selected caller,
helper and composed bodies contain no exception tables. Among the four handler-bearing HMAC/hash wrapper methods found in the bound
class inventory, only `JdkHmac.compute` is a declared opaque owned assumption;
the other three are outside the certified call graph. `VerifiedHkdf.Extract` and
`Expand` call `compute`, which can throw. Its call is modeled atomically as
returning, so table-free translated bodies do not imply exception-free call
chains.

The parser recognizes method declarations with `throws` clauses and binds each
descriptor and Code array to its member declaration. Unbound descriptors and
orphan/repeated Code arrays are rejected; instruction offsets must strictly
increase before CFG construction. Member boundaries rely on the pinned javap
`-c -p -s` layout (two-space declaration indentation). Real sibling-method and
synthetic malformed-input regressions exercise these guards. They do not prove
method-boundary parsing or the extractor correct for all class files.

## 2. Public / secret classification

| Root | Public | Secret |
|---|---|---|
| `NativeMlKem.Select` | lengths/indices, array roles, constants | ciphertext, expected/candidate/fallback contents, mask, output |
| `NativeSampling.Feed` | public rho-derived bytes/counts/prefix, lengths | none in the public-matrix use (declared public deliberately) |
| `VerifiedHkdf.Extract` | hash length, sequence identities/lengths | salt, IKM, HMAC output bytes |
| `VerifiedHkdf.Expand` | hash length, output length, PRK length, sequence identities/lengths | PRK, info/context, block bytes, output bytes |
| `VerifiedHkdf.LabelInfo` | label units (ASCII public), label length, context length, output length | context contents, serialized bytes/result payload |

Public metadata is exactly: object/array identity (role), lengths, allocation
sizes, loop counters/indices, algorithm/label selection, and the declared
public matrix seed. HKDF result **tags** (`Success`/named failure) and success
**lengths** are treated as public shape only because `HkdfShape.dfy` proves,
against the unchanged kernel, that they depend only on public hash length,
output length, label length+ASCII and key length. Payload bytes remain secret;
PRK/salt/IKM/context are never reclassified public. Source shape is not a
compiler trace proof; the actual Java CFG certificate is separate.

## 3. Declassification and shape results

The observable trace compares branch outcomes, addresses, lengths, provider
dispatch/public args and raise sites. `shape` results (generated HKDF result
objects/tags) are public only under the `HkdfShape.dfy` invariant and are
marked with an explicit certificate flag. `BytesResult.dtor_bytes`,
`JdkHmac.compute` payloads and all sequence contents remain secret. No secret
value is used as a branch condition, index, allocation size or public call
result in checked roots. `Agree` includes shape registers, so actual runs must
satisfy the shape invariant; this is stated as a condition, not proved by the
bytecode certificate alone.

## 4. Heap roles, aliases and call results

Array/sequence identities are static roles (parameter, field reference,
allocation site, call result site). `Agree` pairs the same role across runs,
requires equal lengths for every role and equal contents for public roles.
Reference-field writes and `aastore` are rejected: a secret-content reference
cannot be stored into a public array field. Array field reads rely on the
documented constructor/ownership precondition; the constructors are not checked
roots. Every call-result array/sequence role must have an explicit public length
relation (`length_arg`, `length_role`, or `length_zero`); a missing contract
fails closed. This models allocation/length observation but does not prove that
a checked callee's returned bytes equal the actual JVM bytes.

## 4a. Inline composition of certified owned callees

An opaque `Call` step is atomic: it observes a static dispatch/public arguments,
returns an abstract word, and does **not** model callee instructions or heap
writes. That contract is unchanged for the five original caller certificates. A
separate, explicitly enumerated expansion removes it for
`NativeCodec.Extract:(JII)I`, `PublicMod:(II)I` and `Wipe:([I)V` in a
**separate** composed `NativeSampling.Feed` certificate:

- the exact static target (class + name + descriptor) selects the body; a
  same-named method on another owner or with another descriptor is an unlisted
  call and fails closed;
- the body is re-translated under the caller's actual argument taints and role
  taints, then re-checked by `Structure` (no callee annotation is trusted);
- scalar arguments are copied to the callee parameter registers, array
  parameters alias the caller's static role, and every return site copies the
  callee's actual return register into the caller destination; a secret result
  cannot flow into a public destination;
- array parameter roles must be the *exact plain* identity emitted for that
  parameter; a merged/derived role (for example a control-flow join of a
  parameter role with an allocation role) is a composition error rather than a
  silent alias to some caller role;
- `Wipe`'s stores are part of the composed program, so its heap effect is
  modelled rather than assumed away; array contents remain secret and no
  declassification or physical-erasure claim is made;
- each inlined body's shape hash is compared with the in-process direct
  translation of the same callee (nested callee-root inlines included), and the
  composed certificate must remove exactly the enumerated targets and add no
  owned target. This is direct-translation *self-consistency* plus the trusted
  splice: it detects a corrupted or substituted body; it is not a hash of the
  emitted certificate and not a theorem about the JVM;
- recursive or unbounded callee expansion is refused before it starts (a
  call-cycle check over the enumerated callees plus fail-closed expansion
  limits), and each callee's recorded contract must match the enforced class
  policy (`params`, role values, result and heap effect).

The expansion is a trusted bridge step (like the javap extractor): plain
parameter-role aliasing, register and role renaming, entry/return copies, and the
omission of the constant `invoke`/`return` dispatch events are mutation-tested
but not formally verified. Locals and phi edges are emitted as
`Op(12, 0, src)` copies so that the frozen `Apply(12, a, b) == b` model really
copies `src`; a copy with the source in operand `a` would silently read register
0 and make loop counters and local values dead. The observed trace is the
expanded body trace; JVM value refinement, implicit exceptions and physical
timing remain excluded.

`PublicMod` is admitted only with public `value`/`divisor`: the pinned
DafnyRuntime `DafnyEuclidean.EuclideanModulus/Division` bodies branch on the
dividend/divisor value, so the wrapper is a public-context certificate, not a
private-value constant-time theorem. A zero divisor would throw and is an
explicit residual of the enumerated DafnyRuntime contract.
`Extract` is itself composed with the separately certified public `Pow2` body so
the callee root has no remaining opaque owned call.

Secret-pair witnesses are emitted for the small `Extract`/`Wipe` callee roots.
The witness is a hypothesis-satisfiability control (`Agree` holds and the secret
projection differs) and the *executed* witness run is validated by the bounded
interpreter in `trace_exec.py`. Only private inputs differ initially: private
scalar parameter registers take different words and secret arrays take different
contents, while every other secret register is zero in both states, so a final
difference cannot come from initialisation. `run.check_witness_contract` enforces
from the certificate's actual `param_regs` and the validated run that
(a) a callee with a private scalar parameter keeps the secret live in a register
that is not a parameter register (a parameter-only difference is a rejected dead
input), and (b) a `parameter-array-clear` callee zeroes every secret *parameter
array role* and executes at least that role's witness length in stores to that
role, not merely a global store count. The execution block is reported as
`witness_execution` and the gate result as `witness_contract`. Because the
model's atomic `Call` result depends only on public arguments, no secret value in
`Extract`'s returned register is claimed. A run that exhausts the step cap is reported as
hypothesis-only and is never described as a completed execution: `Exec` returns
`(s, [])` at fuel 0, so a truncated prefix must not be counted as a run. The
interpreter's operand table is compared row-by-row with the compiled
`ApplyProbe.dfy` table, so it mirrors the frozen model rather than itself. The
369-instruction composed Feed uses the generic `TwoRun` theorem without a
concrete witness because a single solver-reducible `Agree` assertion over 286
registers is not practical.

Every admitted **ordinary external call** in the enumerated standard-runtime
namespaces `dafny/`, `java/`, `javax/`, `jdk/`, `sun/` and `com/sun/` is
public-scalar-and-public-heap-argument-only by default: secret array/sequence
contents are the same kind of value-dependent input as a secret scalar, and an
atomic `Call` step cannot see a runtime branch on those contents. The prefix list
is drift-checked against the code table. Targets under any other prefix are not
admitted by any checked certificate and are outside this claim (no blanket
third-party-library coverage). The reviewed
exceptions are the branch-free `Byte.toUnsignedLong/Int` casts (no heap
arguments) and `Helpers.bv64ShiftRight` (shift count public; value may be
private). No heap-content exception is granted for any checked root. Abstract
memory/shape operations (`Load`/`LenOf`/`Alloc`/fill and the enumerated
`modeled_primitive_kinds`) are not ordinary calls: the extractor replaces them
with model steps, so they are outside this gate. An unregistered or ambiguous
call id is an audit failure, and the recorded classification is compared with the
enforced code tables before the replay starts. This is a classification gate for
the trace model, not a runtime/compiler timing proof.

The original five caller certificates keep their 19-target union. The composed
Feed discharges only the three named targets and still assumes its other 7 owned
contracts; the five-certificate union would be 16 only if the composed
certificate replaced Feed, which this branch does not claim. This is not a
whole-callee closure.

## 5. Dispatch, types and object identity

`invokevirtual`/`invokeinterface` to owned classes is rejected unless a
final/closed-world dispatch contract is proved. This is why Sponge and Decaps
are open: `Sponge.rate()/lanes()` and `SecretKey`/`PublicKey` getters are public
non-final methods and a subclass could make their result secret-dependent
(reviewer counterexamples `/tmp/trace-probes/sponge`, `/tmp/trace-probes/dispatch`).
Only enumerated external contracts are allowed for virtual dispatch:
DafnyRuntime (`DafnySequence`, `DafnySet`, `TypeDescriptor`) and deterministic
JDK library calls (`BigInteger`, `String`, boxed values, `Objects`). Those are
trusted library contracts, not a JVM timing claim. `new`, `aconst_null`,
`instanceof`, and casts to owned non-final types are rejected; array casts (role
tracked) and a small enumerated final-JDK cast set are the only exceptions.
Owned generated result-object dispatch (e.g. `BytesResult.is_Success`) is open
until a checked closed-world/exact-type contract exists.

## 6. Provider and external contracts

Certified callers also assume the opaque owned helper/adapter contracts listed
in the report's `assumed_owned_callees`. This includes `JdkHmac.compute`, generated
result constructors, `ValidHash` and public-seed sampling helpers. Their actual
class bytes are bound to the pinned-source rebuild, but their traces are not
proved. The report requires each used owned contract to remain in the structured
unchecked inventory; a caller certificate cannot establish whole-callee closure.

Only JDK HMAC/SHA3 and DafnyRuntime (plus the enumerated deterministic JDK
library calls above) are external. `JdkHmac.compute`, `native_kem_hash.sha3_512`,
provider internals, exceptions and timing are trusted/outside. `HkdfBridge`/
`JdkHmac` byte conversion uses the reviewed `toRawArray()` primitive bulk-copy
path. `JdkHmac.compute` is our reviewed/trusted handwritten bridge to JDK HMAC;
the provider primitive contract does not prove that Java adapter, and complete
`HkdfBridge`/Java refinement remains open. The final canonical21 build exists;
adapter trace roots remain open because of owned object/dispatch/type/exception
and alias restrictions, not a missing build. The separate composed Feed
certificate discharges exactly `NativeCodec.Extract`, `PublicMod` and `Wipe`;
it does not turn any other owned helper into a provider contract. Owned
`Encrypt`/`Decrypt`/`ExpandMatrix`/`NativeShake.Xof`/`NativeKeccak` are **not**
provider assumptions; they are listed as unchecked owned callees and no V7
closure claim includes them. `Decaps` is a caller skeleton only.

## 7. Faults and residuals

- Out-of-bounds array access is a terminal `EFault` observation; execution does
  not continue after it.
- Provider calls are total deterministic functions of public arguments in the
  model. JDK/BigInteger/DafnyRuntime calls that can throw (e.g. division by a
  zero divisor) are not modelled as exceptions; checked call sites use public
  constants/invariants (HkdfShape) and this remains an explicit residual.
- Implicit JVM exceptions (null, class cast, monitor, allocation failure),
  physical erasure, GC and JIT/CPU/provider timing are excluded.
- Arithmetic/value semantics are abstract; the certificate does not prove the
  model's branch values equal JVM values, only that control depends on the same
  public projection.
- Source→class binding is checked by rebuilding pinned sources with
  `javac -g --release 21` and comparing bytes for checked roots against the
  selected `--classes` directory. The official Dafny archive/extracted
  assemblies and solver are checksum-validated; the exact Dafny build, Maven
  runtime SHA and shared helper/tool-manifest pins are enforced before proofs,
  and revalidated after replay. JDK java/javac/javap are recorded before/after.
  Compiler/javap correctness and the generator remain trusted.

## 7a. Additional static helper bodies

`HkdfBridge.sequence` and `labelUnits` are checked static roots under the same
observer. Clone/sequence construction is modeled through lengths/allocations;
its contents and copy/alias ownership remain trusted adapter semantics. A finite
private-input pair for `sequence` establishes equal observations, with no claim
that the modeled clone/sequence roles contain the original bytes. `labelUnits`
is entirely public; its allocation declassification is restricted to pc 11.

Seven private `NativeField` arithmetic bodies are checked with their owned calls
fully expanded; `Q` and `MaxReduce` are public supporting leaves. The checked
programs retain only the existing private-word/public-shift runtime contract.
The audit's runtime-admission rule is a trusted rejection gate. The shift's model
value is abstract and does not refine the JVM shift value. Finite private-input
pairs check termination, equal observations/public state, and live private result
registers in these seven programs. Their source-level functional correctness,
full NTT/KEM composition and physical timing are separate obligations.

## 7b. Keccak public-provider extension

The Keccak supplement imports the original observer through `PublicProvider.dfy`.
Its theorem uses the same pure public oracle in both runs and proves equivalence
with the original semantics for the default oracle. It does not model arbitrary
private provider outputs. For the seven concrete helper programs, a separate
`PublicOnly` proof checks every remaining call: its target is known, all scalar
arguments are public, it has no heap arguments, and its argument count matches
the generated arity map. The certificate proves this
property from the emitted instructions; it is not an assumed precondition.
Private helpers and both actual pinned runtime shift bodies are inlined.

The trusted bridges additionally include `keccak_traces.py`'s exact-target splice,
public-oracle mapping and finite execution adapter, and `runtime_primitives.py`'s
loaded-source, jar-entry and diagnostic binding. The original shape hash is not
a callee-body identity: the supplement records actual bytecode-body and class
hashes as well. Python source-file binding assumes a trusted interpreter/process
and does not attest bytecode caches or a compromised execution environment.

Completed finite controls require public-heap equality as well as public-register
and trace equality. A fault, truncated fuel prefix or unchanged private inputs
cannot stand in for a completed private-flow control. The concrete public word
arithmetic and its compiled controls do not refine all Java int narrowing,
BigInteger objects or exceptional/provider execution. `BigInteger.ZERO` is the
only handle used by the corresponding Iota call in the selected control.

The seven helper proofs leave the whole Sponge, `Permute` wrapper, polynomial/NTT,
KEM and adapter composition open. Prototype receiver/ownership analyses are not
accepted by this replay; no new exact-receiver assumption is introduced.

## 8. Explicit open items

`policy.json.open_roots` names every claimed-but-unchecked root: Sponge methods,
Decaps (caller skeleton), HKDF ExpandLabel, bridge extract/expand/labelInfo/
failure/hash and bridge bytes (semantic object/dispatch/type/exception
restrictions; final canonical21 build exists). The checked sequence/labelUnits
trace bodies remove exactly those two entries, leaving 13 open roots. `unchecked_owned_callees`
lists owned code not covered (Encrypt, Decrypt, ExpandMatrix, KeyGen, Encaps,
Xof, the Keccak aggregate label, field/NTT/codec/sampling). The Keccak helper
supplement does not close those consuming layers. The report includes both lists and
never reclassifies them as providers. `NativeSampling.Feed` is checked at
120 s/200 M with the explicit `O:smt.case_split=0` override omitted (explicitly recorded); a
timeout/resource failure is always a failure, never a counterexample/success.
