# Recorded local replay (V7 secret trace, post-review fixes)

- Dafny: `4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2`; Z3: `Z3 version 4.12.1 - 64 bit`
- JDK: `openjdk version "21.0.12.1" 2026-08-18`; DafnyRuntime `dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6`
- Inspected classes: `/tmp/microproxy-117-20261101/actual-final21/classes` (final canonical21, 467 classes); report `/tmp/microproxy-117-20261101/timing-evidence-release/report.json`
- `SecretTrace.dfy`: 57 verified declarations, 0 errors; `HkdfShape.dfy`: 17 verified declarations
- Compiled positive control: `positive-control-ok` (runtime evidence, not a proof)
- Official pinned Dafny archive/extracted assemblies/solver validated; exact build `4.9.1+452c...`; Maven runtime SHA `dc62...` and JDK tool identities checked before/after replay; shared `formal/dafny/{run.py,toolchain.py,tools.json}` pinned.

## Checked roots (full emitted CFG reachable)

| Root | Instructions | Reachable | Dafny verified declarations | Budget |
|---|---|---|---|---|
| `Select` | 75 | 75 | 84 | 30s / 50,000,000 |
| `Feed` | 167 | 167 | 179 | 120s / 200,000,000 |
| `Extract` | 30 | 30 | 34 | 30s / 50,000,000 |
| `Expand` | 103 | 103 | 111 | 120s / 200,000,000 |
| `LabelInfo` | 158 | 158 | 169 | 120s / 200,000,000 |

All roots pass the emitted-CFG-edge/reachability gate (`instructions == instructions_reachable`); `Select` is the full 75-instruction 1088-byte compare/mask, not an entry prefix. `Expand`/`LabelInfo`/`Feed` use the recorded larger budgets with the explicit O:smt.case_split=0 override omitted; no timeout/resource result is accepted as success.

## Source/class binding

The final replay binds all 77 rebuilt crypto classes, including the assumed callees. The replay rebuilds all pinned crypto sources with `javac -g --release 21` and checks the entire resulting crypto class inventory against the inspected build, including owned adapters and generated result variants. The five certified methods reside in these three classes:
- `io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/__default.class` `545a578cab08e318`
- `io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.class` `2cb86bea744d0f94`
- `io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.class` `c1df4e947257748b`

## Bytecode controls

- `ConstantTime`: accepted, certificate verified (61 declarations, reachable 54/54)
- `SecretBranch`: rejected normally: secret branch condition (taint sec)
- `SecretIndex`: rejected normally: secret load index (taint sec)
- `EarlyCompare`: rejected normally: secret branch condition (taint sec)
- `ExceptionOracle`: rejected normally: ExceptionOracle.run:([B)I@6: object identity/new outside certificate
- `SecretAlloc`: rejected normally: secret allocation size (taint sec)
- `SecretLoopBound`: rejected normally: secret branch condition (taint sec)
- `SecretDigestBranch`: rejected normally: secret branch condition (taint sec)
- `FieldAlias`: rejected normally: FieldAlias.run:([B)I@27: write to reference field FieldAlias.f:[I outside alias contract
- `VirtualDispatch`: rejected normally: VirtualDispatch.run:([BLVirtualDispatch$Base;)I@1: unproven virtual dispatch VirtualDispatch$Base.tag:()I
- `ClassOracle`: rejected normally: ClassOracle.run:([BLjava/lang/Object;)I@1: runtime type test/cast outside certificate
- `NewIdentity`: rejected normally: NewIdentity.run:([B)I@0: object identity/new outside certificate
- `ResultArrayCall`: rejected normally: ResultArrayCall.run:([B)I@1: call-result role without length contract ResultArrayCall.make:([B)[B
- `CategoryTwo`: rejected normally: CategoryTwo.run:(J)J@10: category-2 stack op outside certificate

## Certificate mutations (actual Select certificate)

The 13 rejected bytecode fixtures are **policy/extractor rejections**, not
counterexamples to the Dafny theorem. `ExceptionOracle` is rejected because
`new`/object construction is unsupported, not because a secret throw theorem was
proved. Only the four certificate mutations below are proof-obligation failures.

- `secret-guard`: proof-obligation-rejected (Error: possible violation of postcondition of forall statement)
- `secret-index`: proof-obligation-rejected (Error: possible violation of postcondition of forall statement)
- `early-compare-guard`: proof-obligation-rejected (Error: possible violation of postcondition of forall statement)
- `public-taint-launder`: proof-obligation-rejected (Error: possible violation of postcondition of forall statement)

## Structured open scope (not green)

- `open_roots`: 15 entries in `policy.json`; includes Sponge methods, Decaps caller skeleton, HKDF ExpandLabel, and bridge extract/expand/labelInfo/failure/hash/bytes/sequence/labelUnits (owned dispatch/type/object/exception/alias restrictions; final canonical21 build exists; adapter refinement open).
- `unchecked_owned_callees`: 31 entries (Encrypt, Decrypt, ExpandMatrix, KeyGen, Encaps, Xof, Keccak/field/NTT/codec/sampling helpers). These are owned code, not provider assumptions.
- HKDF checked roots are generated `Extract`, `Expand`, `LabelInfo`; `HkdfShape.dfy` justifies public result tags/lengths only. Bridge/adapters and `ExpandLabel` remain open.
- JVM/JIT/CPU/GC/provider timing, implicit exceptions/null, exact value refinement, dispatch/type identity and physical erasure are excluded.

## Review-finding disposition

- F1 fixed: fall-through edges emitted as goto; emitted CFG edge comparison and full reachability gates added. `Select` 75/75, `Feed` 167/167.
- F2 fixed: owned non-final virtual/interface dispatch rejected; external contracts enumerated. Sponge/Decaps/HKDF bridge/ExpandLabel are open, not hidden as JVM/provider.
- F3 fixed: reference-field writes and `aastore` rejected; `FieldAlias` regression rejected.
- F4 fixed: call-result array/sequence roles require explicit length contracts; `ResultArrayCall` regression rejected.
- F5 fixed: `new`/null/`instanceof`/owned casts rejected; `ClassOracle`/`NewIdentity` regressions rejected.
- F6 fixed: report carries `open_roots`, `unchecked_owned_callees`, caller-skeleton status; HKDF is no longer stale.
- F7 fixed/declared: EFault terminal, category-2 ops rejected (`CategoryTwo`), helper sibling dependency documented (not self-contained); provider-fault/divisor residuals explicit.

## Opaque owned callee contracts

The five caller certificates assume 19 explicitly recorded owned contracts.
The report lists each target and its policy in `assumed_owned_callees`, and
requires every target in the 31-entry `unchecked_owned_callees` inventory.
`JdkHmac.compute` is our reviewed Java bridge, not external provider code.
`ValidHash`, result/failure factories, type metadata and public-seed sampling
helpers are generated owned code whose class identity is checked; their traces
remain unproved. These conditional caller certificates do not close full V7.
The unused false `labelUnits` length-zero rule was removed, so that open adapter
path requires a real String-length contract before it can be admitted.
