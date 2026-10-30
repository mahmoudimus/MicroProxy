# Dafny toolchain soundness review

Reviewed 2026-10-29. This assesses three known upstream issues against the current
crypto graph. It does not establish general verifier soundness.

Final `NativeMlKem.dfy` SHA256:
`4dabda21e130be283ac2ab78e74414019a0f74dc04ea7ca92af361825898c2d8`.
Its include closure has 18 files. A subsequent EncodeTen split adds only five
pure integer radix lemmas, introducing none of the affected constructs.
The serialization change adds ghost captures, assertions and frame lemmas.
The final NoiseVector portability split captures its existing model sequence and
asserts the current row equation. It adds no opaque blocks, choice assignments or
allocation functions, and leaves all 66 generated Java sources byte-identical.
Executable statements and contracts are unchanged by these proof-only changes.

## Applicability

| Upstream issue | Affected construct | Current graph |
|---|---|---|
| [#6164](https://github.com/dafny-lang/dafny/issues/6164), [fix #6166](https://github.com/dafny-lang/dafny/pull/6166) | Allocation axioms for heapless functions returning references did not connect arguments to the quantified heap. Inspected 4.4.0/4.9.1/4.10.0 contain the encoding; 4.11.0 fixes it. Exact introduction was not established. | Exactly three allocation-consequence axioms occur: `PolyObjects`, `PublicKey.Repr`, `SecretKey.Repr`. Both function applications and their `#canCall` predicates carry the heap. No affected heapless axiom occurs. |
| [#6060](https://github.com/dafny-lang/dafny/issues/6060), [fix #6066](https://github.com/dafny-lang/dafny/pull/6066) | Opaque blocks exposing allocated references could make `old`/`fresh` inconsistent without a new heap. Introduced in 4.9.0, fixed in 4.11.0. | Zero opaque blocks in all 29 crypto/primitives Dafny files. Opaque functions are a different construct. Constructor freshness alone does not trigger this bug. |
| [#6024](https://github.com/dafny-lang/dafny/issues/6024), [fix #6026](https://github.com/dafny-lang/dafny/pull/6026) | Standalone assign-such-that ignored its `by` proof. Syntax arrived in 4.9.0; fixed in 4.10.0. The upstream example is erroneous rejection, not a false proof. | Zero `:|` assignments in the 29 scanned files. |

The #6166 fix adds argument-allocation conditions where needed; it does not simply
remove every heapless allocation axiom. Source inspection and actual emitted
Boogie establish this applicability result, rather than a successful proof alone.

## Evidence and limits

Official 4.11.0 macOS ARM64 archive SHA256:
`c90c75e7d5db9c6ccbb7127840dfe43f0ac938b039a7ebed146d8ead383a572f`.
Version `4.11.0+fcb2042d6d043a2634f0854338c08feeaaaf4ae2`, Z3 4.12.1.
It was installed in a separate external cache without changing production pins.

Upstream false-proof regressions were accepted by official 4.9.1 and rejected by
4.11.0. The assign-such-that example changed from erroneous rejection to acceptance.
Focused 4.11 checks passed constructors **6/0**, representations **3/0**, and
`PolyObjects` **1/0**, at 30-second/50-million-resource limits. Those constructor/
representation checks preceded the final proof-only serialization decomposition.
After the earlier 83500677 serialization freeze, both versions' emitted Boogie
were inspected again and
`PolyObjects` again passed **1/0** under each without warnings or source drift.

This is not a full 4.11 functional-proof or delivery replay. None of the three
issues has an affected construct in the inspected graph. Reassess after adding
heapless reference-returning functions, opaque blocks, assign-such-that proofs,
changing dependencies or changing tools. Other verifier defects and compiler/
runtime/provider correctness remain trust boundaries. Cleanup contracts cover
modeled returns; provider normal completion is assumed and unmodeled JVM failures
are excluded. JVM timing and physical/JIT erasure remain unproved.
