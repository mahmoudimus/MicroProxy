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
| `bytecode_trace.py` | Trusted javap extractor: CFG + fall-through gate, SSA/phi edge copies, taint/role fixpoint, dispatch/field/type policy, certificate/module emitter, independent audit |
| `policy.json` | Checked roots, open roots, parameter/field/allocation/call policy, enums of external contracts, fixtures, per-root solver budgets |
| `run.py` | Atomic replay: pins, model and HKDF-shape proofs, compiled control, source→class binding against a chosen class directory, actual-class certificates, fixtures, certificate mutants, structured open scope |
| `fixtures/` | Constant-time positive control plus branch/index/early-compare/exception/alloc/loop-bound/field-alias/virtual-dispatch/type-test/new-identity/call-length/category-2 mutants |
| `test_trace.py` | 27 unit tests over parser, translation, audit, rejection, callee identity/scope and CFG/reachability gates |
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

## Open scope (reported, not green)

The five caller certificates assume 19 opaque owned helper/adapter contracts,
including `JdkHmac.compute`, `ValidHash`, result/failure constructors and the
public-seed sampler's helpers. `assumed_owned_callees` records each exact target
and policy contract; every one must also appear in `unchecked_owned_callees`.
These are explicit assumptions, not callee trace proofs. Source/class identity is
checked for all rebuilt crypto classes, including adapters and result variants;
matching bytes do not discharge a callee's trace obligation.

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
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  python3 -m unittest -v formal/timing/test_trace.py

python3 formal/timing/run.py \
  --output /fresh/output/dir \
  --classes /tmp/microproxy-117-20261101/actual-final21/classes \
  --java-home /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  --dafny ~/.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny \
  --runtime ~/.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar
```

`--classes` selects the immutable class directory to inspect; the replay rebuilds
the pinned sources with `javac -g --release 21` and requires byte-identical
class files for the checked roots. Use
`/tmp/microproxy-117-20261101/actual-final21/classes` (467 classes) for the final
canonical21 replay. The current `quic/target/classes` carries javac25 attributes
and is not treated as a product regression. The replay validates the official
checksum-pinned Dafny archive and every extracted assembly/solver, requires the
exact build `4.9.1+452c...`, derives the solver from that distribution, pins the
shared helper/tool manifest, validates the Maven DafnyRuntime SHA and records
JDK tool hashes before/after. Reports are published atomically; a failure leaves
`{"status":"failed"}` and never preserves older success. No `mvn clean` is run.
