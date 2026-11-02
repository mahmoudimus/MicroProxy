# Checked secret-trace evidence

The checked snapshot is `PRODUCTION-EVIDENCE.json`, SHA-256
`b6ae6560ccf2e107597001afdec3d1abb197582328ad52d64f857419ec543ab6`.
It records the 2026-11-01 macOS arm64 replay at
`/Users/mahmoud/.cache/microproxy-formal/issue117-20261101/helper-final-doc-replay/report.json`
(workspace `replay-nvi3byhu`) over the preserved JDK 21 library classes.
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
- 126 pinned inputs and 77 matching source-rebuilt class bindings.
- 90 unit tests, all run by the root-module, discovery and direct-script entry
  points documented in `README.md`.
- Unchanged `SecretTrace.dfy`: 57 verified declarations; unchanged
  `HkdfShape.dfy`: 17; compiled positive control executed.
- Compiled `ApplyProbe.dfy`: 138 rows and nine operand-sensitive expectations,
  compared with the bounded execution-control interpreter. This checks the
  interpreter against the model; it does not prove the interpreter correct.
- 27 fixtures: four accepted (`ConstantTime`, `PublicEuclidean`,
  `LongSlotPublic`, `HeapExternalPublic`), 23 normal policy rejections.
- Four Select certificate mutants and five callee mutants rejected with genuine
  proof-obligation failures. Parser, crash, timeout and resource failures never
  count as successful negative controls.

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
casts and `Helpers.bv64ShiftRight` with a public shift count. There are no
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
Fifteen roots and 31 unchecked labels remain open. Dispatch/object identity,
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
The current snapshot repeats that replay after correcting three documentation
counts/offset/classification descriptions; its mathematical certificates differ
only in the absolute include path for the worktree. It retains the same budgets. See `README.md` for fresh replay commands.
