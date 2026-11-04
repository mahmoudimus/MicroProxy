# Native polynomial source observations

This package proves paired source observations over the executable production
Dafny methods used to generate Java. It covers 13 native polynomial methods,
seven field dependencies and 19 executable pure helpers. Forward and inverse
NTT and multiplication are included. It does not establish whole-crypto trace
independence, compiler refinement, physical-memory semantics or JVM timing.

The paired harness calls the actual methods with independently varying permitted
secret coefficients. Original frames and within-call alias restrictions remain;
permitted shared-buffer cases have dedicated callers. The separately trusted C#
checker binds observations to resolved operations, callees and actual trace
outputs. It is reviewed and tested code, not a formally proved semantics.
Read/write observations identify method-local buffer roles and indices, rather
than physical Java heap addresses. Site labels are opaque annotation labels.

## Mandatory checks

| Target | Verified checks |
|---|---:|
| NativeField body | 86 |
| NativePolynomial body | 1,001 |
| Polynomial paired harness | 26 |
| Field trace compatibility | 14 |
| NativeMlKem included composition | 2,767 |
| Shared SourceTrace wrappers | 17 |
| Canonical ObservationVocabulary | 29 |
| Positive checker-control harness | 19 |

Every positive target requires zero errors. Eight audits require zero findings.
The replay retains all method/function/binding, canonical encoder, decoy-class,
omission, ordering and mutation controls. An observed private branch or index
must fail the paired equality; missing instrumentation must fail coverage.
Resource exhaustion, parser errors and tool crashes are not proof failures.
The 64 replay records include proofs, audits, controls and an actual malicious
scope-selection probe; they are not 64 security theorems.

The runner clears both `POLY_TRACE_ROOTS` and `POLY_TRACE_FUNCS` for canonical
checks and requires the exact 20 unique method identities. Counting 20 entries
alone would accept a selector repeating one root 20 times. Test selectors are
explicit and confined to controls. Default pure-helper coverage has 19 entries.

The `missing-false-prefix` negative is verified against the actual affected
`NativePolynomial.ZetasValue` function with `--filter-symbol`, not by a
whole-file sweep that can add an unrelated `NewZetas` timeout. A paired original
focused positive uses the same function, domain and policy and must be nonzero
with zero errors. A zero-match filter is rejected, and no timeout, resource or
parse output is accepted as a counterexample.

## Reproduce

Use a fresh output and baseline directory. The helper materializes exact Git
blobs at commit `5ce660a69a1dd496dda02705bf1e2b1aa7a2be1d`, with tree and manifest
checks; it never takes a comparison baseline from the mutable working tree.
The runner independently authenticates that baseline against Git or the exact
reviewed manifest digest. A shallow clone needs the pinned historical commit.

```sh
python3 scripts/security/prepare_poly_baseline.py --output /fresh/poly-baseline
python3 -m unittest discover -s formal/source/polynomial -p 'test_*.py' -v
python3 formal/source/polynomial/replay.py \
  --output /fresh/poly-evidence \
  --cache /path/to/toolchain-cache \
  --baseline /fresh/poly-baseline \
  --git-repo . \
  --javac21 /path/to/jdk21/bin/javac \
  --javac25 /path/to/jdk25/bin/javac \
  --runtime /path/to/DafnyRuntime-4.9.1.jar
```

The alternative baseline authentication argument is
`--baseline-manifest-sha256 77daf19d88d147086717d86f06cda280e9f16d0e7b2ef769472745a77f256ff0`.
The runtime must be the checksum-pinned Dafny toolchain runtime or the approved
Maven `org.dafny:DafnyRuntime:4.9.1` artifact (`dc62d345...`). Dafny 4.9.1 uses
30-second, 50-million-resource, two-core proofs, case split zero except the
included ML-KEM composition at three. Official Dafny parsing discovers includes.

All 44 reviewed inputs are frozen before verification; the guard additionally
pins `inputs.json`. Unrelated repository files and top-level handoff scaffolding
are outside the package inventory. Unsafe paths and source symlinks reject.
The checker builds in isolation with recorded source/project/SDK/assembly hashes
and disabled Directory.Build imports. Separate platform builds are attested;
there is no cross-SDK binary-reproducibility claim.

`SOURCE-EVIDENCE.json` is the full `evidence.json` produced by the accepted
replay. Its exact input maps, proofs, audits, checker build, complete control
inventory, baseline and JDK comparisons are validated by the obligation ledger.
The [tracked evidence bundle](../../crypto/evidence/2026-11-04-poly/MANIFEST.json)
records relative raw-receipt and log paths alongside their hashes. Producer
absolute paths are provenance, not paths required in another checkout.

## Delivery and trust

The same frozen Dafny generates Java. Erasure comparisons cover 65 generated and
native-provider class files on JDK 21 and 25; the full delivery stage separately
covers all 66 native/provider classes, including the reference provider. The
polynomial Java text gains parentheses at 20 expression sites. All 66 canonical
class bytes match the prior stage. No generated Java is hand-edited.

Existing native polynomial, codec/sampling, KEM, Maven, browser-profile and actual
JAR/bundle checks are separate acceptance gates. Historical v0.7.0 artifact
records remain unchanged. Neither a component proof nor its class comparison
establishes an arbitrary future artifact's identity.

Dafny/Boogie/Z3, ghost erasure, the resolved-AST checker, the .NET/build
environment, javac/JVM, DafnyRuntime and JDK providers remain trust boundaries.
Complete SHAKE/Keccak/KEM and Java-adapter/comparison trace composition,
failure-path declassification, physical timing and external expert review remain
open. The existing bytecode residual inventories are unchanged. This component
does not close issue #117 or prove cryptographic hardness or whole TLS/QUIC
security.
