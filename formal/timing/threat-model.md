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
and alias restrictions, not a missing build. Owned
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

## 8. Explicit open items

`policy.json.open_roots` names every claimed-but-unchecked root: Sponge methods,
Decaps (caller skeleton), HKDF ExpandLabel, bridge extract/expand/labelInfo/
failure/hash, and adapter conversion roots (semantic object/dispatch/type/
exception restrictions; final canonical21 build exists). `unchecked_owned_callees`
lists owned code not covered (Encrypt, Decrypt, ExpandMatrix, KeyGen, Encaps,
Xof, Keccak helpers, field/NTT/codec/sampling). The report includes both lists and
never reclassifies them as providers. `NativeSampling.Feed` is checked at
120 s/200 M with the explicit `O:smt.case_split=0` override omitted (explicitly recorded); a
timeout/resource failure is always a failure, never a counterexample/success.
