# Scoped secret-trace verification (V7)

This directory adds a two-run (self-composition) observation theorem and a
fail-closed extractor that applies it to actual bytecode of selected generated
cryptographic methods. It does **not** prove JVM timing, provider internals,
cryptographic hardness, exact Java value refinement, or a full-program result.
Read [threat-model.md](threat-model.md) for the observer, public/secret ledger,
declassifications, dispatch/type restrictions, and residuals.

## Files

| File | Role |
|---|---|
| `SecretTrace.dfy` | Taint-annotated word/array machine with chunked code/taint tables, switch terminator, shape-result calls, terminal array faults, two-run theorem, positive instance and model controls |
| `PositiveTraceCheck.dfy` | Compiled execution control (`dafny run`), not a proof |
| `HkdfShape.dfy` | Imports the unchanged `formal/dafny/hkdf/Hkdf.dfy` and proves source-level result-kind/length independence for equal public inputs; it does not prove compiler trace preservation |
| `bytecode_trace.py` | Trusted javap extractor: CFG + fall-through gate, SSA/phi edge copies (`Op(12, 0, src)` so the frozen `Apply(12,a,b)==b` really copies `src`), taint/role fixpoint, dispatch/field/type policy, certificate/module emitter, independent audit |
| `composition.py` | Fail-closed inline expansion of an enumerated set of exact static certified owned callees into a caller certificate (plain parameter-role identity, register renaming, argument instantiation, return copy, recursion/expansion guards, full reachability gate) |
| `trace_exec.py` | Bounded interpreter of the frozen machine (`Apply`/`DoStep`/`Exec`); executes witness states and emitted certificates for *executed* control-flow controls (terminal instruction, stores, secret liveness). Not a theorem |
| `ApplyProbe.dfy` | Compiled control (`dafny run`) that prints the frozen `Apply` operand table; `run.py` compares it row-by-row with `trace_exec.apply` |
| `policy.json` | Checked caller/callee/composed roots, open roots, parameter/field/allocation/call policy, enums of external contracts, fixtures, per-root solver budgets |
| `run.py` | Atomic replay: pins, model and HKDF-shape proofs, compiled control, source→class binding against a chosen class directory, actual-class certificates, fixtures, certificate mutants, structured open scope |
| `fixtures/` | Constant-time positive control plus branch/index/early-compare/exception/alloc/loop-bound/field-alias/virtual-dispatch/type-test/new-identity/call-length/category-2 mutants, exact-owned-target and call-result/heap composition mutants, public/private Euclidean-runtime controls, long-slot regressions, secret-heap external-call controls and unit-test-only merged-role/extract-shape/recursive composition controls |
| `test_trace.py` | 90 unit tests over parser, translation, audit, rejection, callee identity/scope, inline composition, frozen-`Apply`/executed-witness controls, contract-driven witness liveness/clearing gates, heap-argument classification (including `javax/`, `jdk/`, `sun/`, `com/sun/`), policy/contract/prefix drift, call-id and recursion fail-closed gates. One test re-runs the compiled `ApplyProbe.dfy` cross-check and is skipped when the pinned Dafny binary is absent (the replay always runs it) |
| `test_exception_table.py` | 15 additional unit tests using independently read real javap tables and member boundaries: typed catches, catch-all/finally and throws declarations; empty/malformed tables, orphan/repeated Code arrays, unbound descriptors and duplicate/backwards offsets; accepted no-handler controls |
| `EVIDENCE.md` | Recorded local replay and exact open items |
| `inputs.json` | SHA-256 pins for timing sources, fixtures, inspected production sources and the unchanged HKDF model |

`run.py` imports the reviewed process/report helpers from `formal/dafny/run.py`
and their toolchain module. The directory is therefore **not standalone**: it
requires that repository sibling. The shared runner, toolchain installer and tool
manifest are pinned alongside this component's sources. Replay validates the
official Dafny archive and extracted tools, the Maven runtime checksum and the
selected JDK tool identities before and after checking the certificates.

## What is checked

The universal theorem states: for every program satisfying `Structure`, every
two states related by `Agree` (equal public registers, equal public-array
contents, equal array lengths) and **every** fuel, the observation traces are
identical. Observed: operation kinds, branch/switch outcomes, array read/write
addresses, terminal bounds faults, lengths/allocations, provider dispatch and
public argument values, raise sites. Secret outputs may differ.

Checks enforced by `Structure` and the extractor include:

- fall-through edges are emitted as `IGoto`; the replay rejects a certificate
  unless every emitted block terminator matches the bytecode CFG and every
  emitted instruction is reachable from entry (F1);
- secret branch/switch conditions, secret array indices, secret allocation
  sizes and secret-derived public call results are rejected;
- `invokevirtual`/`invokeinterface` to owned classes is **rejected unless a
  final/closed-world dispatch contract is proved**; only enumerated external
  JDK/DafnyRuntime contracts are allowed (F2);
- writing a reference (array/sequence) field and `aastore` are rejected; array
  field reads rely on a documented construction/ownership precondition (F3);
- a call-result array/sequence role requires an explicit public length contract
  (`length_arg`, `length_role` or `length_zero`) (F4);
- `new`/`aconst_null`/`instanceof` and casts to non-final owned types are
  rejected; array casts and a small enumerated final-JDK cast set are allowed
  (F5);
- category-2 stack operations are rejected rather than approximated (F7);
- an out-of-bounds array access is a terminal observation event (F7).

## Checked roots

- `NativeMlKem.Select` — full fixed 1088-byte comparison and masked selection
  (static bytecode; full 75-instruction certificate reachable).
- `NativeSampling.Feed` — public-seed rejection loop (full 167-instruction
  certificate; 120 s / 200 M, the explicit O:smt.case_split=0 override omitted, explicitly justified).
- Generated HKDF `VerifiedHkdf.__default.{Extract,Expand,LabelInfo}` — the
  actual generated Java control flow, including the Expand feedback loop and
  LabelInfo ASCII loop. `Expand`/`LabelInfo` use 120 s / 200 M (explicitly
  recorded). `HkdfShape.dfy` proves the source-level public tag/length facts
  used to classify result objects as public shape while payload bytes stay
  secret.

### Owned-callee certificates and checked inline composition

The `NativeCodec.__default` primitives are certified from the same actual
canonical21 classes:

- `NativeCodec.Extract:(JII)I` — private accumulator `value`, public `shift` and
  `bits`; the certificate is composed with the separately certified `Pow2:(I)I`
  body (12 direct instructions, 87 composed, 120 s / 100 M).
- `NativeCodec.Pow2:(I)I` — public width power (62 instructions, 30 s / 50 M).
- `NativeCodec.PublicMod:(II)I` — **public** `value` and **public** `divisor`
  (2 instructions, 30 s / 50 M), admitted only in public contexts. The pinned
  DafnyRuntime `DafnyEuclidean.EuclideanModulus/Division` bodies branch on the
  dividend/divisor value (e.g. `EuclideanModulus(II)I` offsets 22/28/38/53/59/64/72/104/120), so
  a private-value contract for this wrapper would hide known runtime control
  flow. A zero divisor would throw and remains outside the trace model.
- `NativeCodec.Wipe:([I)V` — private array contents, public length/reference;
  the full 19-instruction loop-stores-0 body (30 s / 50 M).

Each callee root has a full emitted-CFG reachability gate and a recorded contract
that is checked against the enforced class policy (`params`, role values, result
and heap effect); `PublicMod` is public/public in both places. `Extract` and
`Wipe` carry a secret-pair witness (two states with equal public projection that
differ in a secret register or in secret-array contents) applied to `ExecTwoRun`,
and the *executed* witness is validated by the bounded interpreter in
`trace_exec.py`. Only private inputs differ initially (private scalar parameter
registers and secret array contents); every other secret register starts at zero
in both witness states, so a difference in the final state can only come from
execution. `run.check_witness_contract` then enforces, from the certificate's
actual `param_regs` and the validated execution:

- a callee with a private scalar parameter must have a **non-parameter** register
  differing at the end (a parameter-only difference is rejected as a dead private
  input);
- a callee whose contract records `parameter-array-clear` must zero every
  **secret parameter array role** and execute at least that role's witness length
  in stores to *that role* (not merely a global store count to any role).

`Callee_Extract` keeps the non-parameter difference in register 7; `Callee_Wipe`
executes its four stores and clears secret role 0. The record carries
`parameter_registers`, `witness_execution` and `witness_contract`; a run that
exhausts the step cap is recorded as hypothesis-only and is never called
complete. The model's atomic `Call` result (`ProviderResult`) depends only on
public arguments, so no secret-dependent *value* in `Callee_Extract`'s returned
register is claimed — that is the documented dependency-shape abstraction. `Pow2` and `PublicMod` are **public-only** certificates;
no private-value constant-time claim is made for `PublicMod`. Normal
Dafny proof mutants (`public-result-from-secret-arg`, `secret-runtime-arg`,
`secret-store-index`, `secret-branch-cond`) are rejected by the same strict
normal proof-failure gate as the `Select` mutants (single completed summary,
non-zero errors, obligation diagnostic, no resource/crash), never as
resource/crash results.

### External runtime classification

The extractor and the independent audit enforce a mandatory rule for every
admitted **ordinary external `Call`** in the enumerated standard-runtime
namespaces `dafny/`, `java/`, `javax/`, `jdk/`, `sun/` and `com/sun/`: public
scalar arguments **and** public heap (array/sequence) contents by default. The
prefix enumeration is recorded in `policy.json` (`external_runtime_prefixes`) and
drift-checked against the code table, so a policy edit cannot narrow the gate
silently. A target under any other prefix is not admitted by any checked
certificate and is outside this claim: arbitrary third-party library calls are
not covered, and no blanket "all libraries" claim is made. Secret array
contents are the same kind of value-dependent input as a secret scalar, and the
model's `Call` step is atomic, so it cannot see runtime branches on those
contents. The reviewed exceptions are the branch-free byte casts
(`Byte.toUnsignedLong`, `Byte.toUnsignedInt`, any scalar taint, no heap
arguments) and `Helpers.bv64ShiftRight`, where only the shift-count argument must
be public (the shifted long may be private). No heap-content exception is needed
or granted for any checked root (`public_heap_exceptions` is empty). Abstract
memory/shape steps (`Load`/`LenOf`/`Alloc`/fill and the enumerated
`modeled_primitive_kinds`) are not ordinary calls and are unaffected. The
recorded classification is compared with the enforced code tables before the
replay starts, so a policy edit cannot silently change what the report claims to
have enforced. In particular, every
`DafnyEuclidean.EuclideanDivision`/`EuclideanModulus` overload is
public-argument-only; that family branches on the dividend value in the pinned
runtime. `Helpers.toIntChecked` and `Integer.compareUnsigned`/`BigInteger.compareTo`
also branch on values and are therefore public-only under the default. This is a
classification gate in code, not an optional JSON flag; a private argument is a
normal policy rejection. It is not a compiler/runtime timing proof.

`NativeSampling.Feed` additionally has a **separate** composed certificate
(369 reachable instructions, 180 s / 400 M) in which the exact static bodies of
`Extract`, `PublicMod` and `Wipe` are inlined. The composed certificate:

- re-translates each body with the caller's actual argument/role taints and
  re-checks the full body under that instantiation;
- aliases array parameter roles to the caller's role, emits scalar entry copies,
  and copies the callee's actual return register into the caller destination;
- models `Wipe`'s heap stores instead of assuming a no-op call (the inlined
  body's stores are executed by the validated witness run of `Callee_Wipe`);
- aliases only an *exact plain* callee parameter role; merged/derived roles are
  rejected instead of being silently mapped to a caller role;
- shape-binds every inlined body (including nested callee-root inlines) to the
  in-process direct translation of the same callee, as direct-translation
  self-consistency plus the trusted splice — not a hash of the emitted
  certificate and not a JVM-semantics theorem;
- proves that exactly the three enumerated owned targets disappear from the
  opaque target set and no owned target is added (`removed == 3`, `added == 0`).

This removes exactly those three assumptions **for the composed certificate
only**. The original five caller certificates remain unchanged and still assume
their 19-target union; the composed Feed alone still assumes its other 7 owned
contracts. The five-certificate union would be 16 only if the composed
certificate replaced the original Feed certificate, which this branch does not
claim (§Open scope). There is no new JSON success flag and no whole-V7 closure
claim.
The inline expansion itself (plain parameter-role aliasing, register/role
renaming, entry/return copies and the omission of the constant `invoke`/`return`
dispatch events) is a trusted bridge step like the extractor; it is
mutation-tested but not formally verified. Recursive or unbounded callee
expansion is refused before it starts (policy-cycle detection plus expansion
limits).

## Open scope (reported, not green)

The five caller certificates assume 19 opaque owned helper/adapter contracts,
including `JdkHmac.compute`, `ValidHash`, result/failure constructors and the
public-seed sampler's helpers. `assumed_owned_callees` records each exact target
and policy contract; every one must also appear in `unchecked_owned_callees`.
These are explicit assumptions, not callee trace proofs. Source/class identity is
checked for all rebuilt crypto classes, including adapters and result variants;
matching bytes do not discharge a callee's trace obligation. The separate
composed Feed certificate discharges only `NativeCodec.Extract`, `PublicMod` and
`Wipe`; it still assumes its other 7 owned contracts (16 across the
five-certificate union only if it replaced Feed) and is not a whole-callee
closure.

- `NativeShake.Sponge.{Update,AbsorbOne,XorByte,Next,Start}` and
  `NativeMlKem.Decaps`: rejected by the dispatch gate because owned classes and
  getters are public non-final; no exact-receiver/closed-world proof is claimed.
  `Decaps` remains a **caller skeleton** only.
- HKDF `ExpandLabel`, bridge `extract/expand/labelInfo/failure/hash/bytes`:
  rejected by owned `BytesResult`/`FailureKind` virtual dispatch, `new`/type
  tests, object-identity/alias restrictions, or the reviewed adapter boundary.
  The final canonical21 build **exists**; these roots remain open for those
  semantic reasons, not a missing build. `JdkHmac.compute` is our reviewed
  handwritten bridge to JDK HMAC (a primitive contract does not prove its Java);
  complete `HkdfBridge`/Java refinement remains open.
- Owned callees `Encrypt`, `Decrypt`, `ExpandMatrix`, `KeyGen`, `Encaps`,
  `NativeShake.Xof`, `NativeKeccak.PermuteScratch`, field/NTT/codec/sampling
  helpers are listed as unchecked; they are not provider assumptions.
  Only JDK HMAC/SHA3 and DafnyRuntime (plus deterministic JDK
  BigInteger/String/boxed calls under enumerated policy) are external contracts.
- JVM/JIT/CPU/GC/provider timing, implicit exceptions/null checks, exact value
  refinement, dispatch/type identity theorems, cryptographic hardness and
  physical erasure are excluded.

## Reproduce

```sh
cd /path/to/microproxy
# The trace module and direct script each run 90 tests; discovery runs all 105,
# including 15 exception-table and member-boundary regressions. The module adds its own directory
# to sys.path and puts `unittest.main()` at end of file:
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  python3 -m unittest -v formal.timing.test_trace      # from the repo root
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  python3 -m unittest discover -s formal/timing -p 'test_*.py'  # all 105
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  python3 formal/timing/test_trace.py                  # direct script
# (add DAFNY=/path/to/pinned/dafny to also run the compiled ApplyProbe cross-check;
#  the full replay below always runs it)

python3 formal/timing/run.py \
  --output /fresh/output/dir \
  --classes quic/target/classes \
  --java-home /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  --dafny ~/.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny \
  --runtime ~/.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar
```

`--classes` selects the class directory to inspect. First build it with JDK 21
(`JAVA_HOME=/trusted/jdk21 mvn -pl quic -am -DskipTests package`), or select a
preserved JDK 21 class directory. The replay rebuilds the pinned sources with
`javac -g --release 21` and requires byte-identical class files for the checked
roots. Classes compiled with JDK 25 can carry different attributes and are not a
canonical JDK 21 input; this does not by itself indicate a product regression. The replay validates the official
checksum-pinned Dafny archive and every extracted assembly/solver, requires the
exact build `4.9.1+452c...`, derives the solver from that distribution, pins the
shared helper/tool manifest, validates the Maven DafnyRuntime SHA and records
JDK tool hashes before/after. Reports are published atomically; a failure leaves
`{"status":"failed"}` and never preserves older success. No `mvn clean` is run.
