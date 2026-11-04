# Executable Dafny as the primary crypto proof boundary

This records the source-first direction approved for issue #117 on 2026-11-03.
The implementation being verified must be the executable Dafny implementation
used to generate production Java. Bytecode analysis remains supplementary.
This changes the route to the remaining obligations, not their required scope.

## Existing evidence

Production HKDF, SHAKE, ML-KEM and nonce construction already use generated Java
with functional proofs and explicit external primitive, compiler, runtime and
adapter assumptions. `NativeShake.Sponge` already has checked constructor
freshness, array bounds, several alias restrictions and method frames. Its
domain harness calls those actual methods over arbitrary permitted inputs.

The bytecode trace work remains useful evidence for its documented observer and
subset. Its original 13 open roots, 19 caller assumptions and 31 unchecked
labels remain open. Passing a theorem about an extracted model does not prove
that an incorrect extractor described the implementation faithfully.

## Approved approach

1. Establish ownership, freshness, disjointness and frame preservation directly
   in the actual Dafny classes and factory callers. Separate a stronger factory
   footprint from the accepted domain of arbitrary existing callers; do not
   silently narrow that domain to simplify a proof.
2. Specify observable source execution: runtime branches, iteration counts,
   accessed buffer roles and indices, allocations and public call metadata.
   State allowed output declassification and external primitive contracts.
3. Prove equal observations for executions whose public inputs agree while
   secret payloads vary. Bind the observations to the same executable bodies.
   A manually appended ghost trace is not sufficient unless its coverage and
   connection to the executed operations are checked and their remaining
   trusted machinery is identified.
4. Generate Java from those verified bodies. Check ghost erasure against the
   prior generated source and retain functional vectors, adapter, packaging and
   fingerprint checks. If executable code changes, measure compatibility and
   performance before production adoption.
5. Retain bytecode checks as independent diagnostics and release evidence.
   They are not prerequisites for a source theorem, nor may a source theorem
   be relabeled as a proof of the JVM's execution trace.

We considered continuing to expand the bytecode extractor, maintaining a second
handwritten trace implementation, and proving properties at the executable
Dafny boundary. The user selected the last approach. It reuses Dafny's actual
heap, call and frame verification instead of reconstructing ownership in a
separate instruction model. A second implementation would reintroduce an
equivalence obligation and cannot establish the source connection by identity
hashes or matching finite test outputs alone.

## Delivery and acceptance

- A direct ownership harness calls the production constructor and methods,
  proves freshness relative to preexisting external arrays, preserves frames
  through absorb/read/destroy, and exercises permitted external buffer aliases.
- Source trace roots name their observer, secret/public domains, real callee
  dependencies, declassifications and trusted instrumentation explicitly.
- Missing observations, secret-dependent conditions/indices, wrong alias facts,
  incorrect frame writes and dropped owned callees must be caught by genuine
  proof failures or a separately identified completeness check. A checker
  rejection is not a Dafny proof of that checker's correctness.
- Positive and negative results use pinned Dafny 4.9.1 and Z3, the existing
  30-second / 50,000,000-resource policy and `O:smt.case_split=0`. Parse/type
  failures, timeouts and resource exhaustion are not semantic negative controls.
- Regeneration and actual supplied-artifact validation connect the checked
  source to the delivered classes. Their finite checks support that connection
  under the compiler/runtime assumptions; they do not prove a compiler correct.

The implementation plan is in
[the source-assurance plan](2026-11-03-dafny-source-assurance-plan.md).

## Scoped implementation progress

HKDF now uses this route for its four executable methods, with 248 body checks
and 259 included paired/domain checks. A separate polynomial component covers
13 native polynomial methods, seven field dependencies and 19 executable pure
helpers. Its actual paired callers cover forward/inverse NTT and multiplication
without requiring equal secret coefficients. The polynomial body has 1,001
verified checks, the field body 86, the polynomial paired harness 26 and the
field compatibility harness 14. Original frames and permitted within-call
aliases remain part of the domain.

The resolved-AST coverage checkers remain trusted, reviewed code. They check
operation/observation order and actual resolved dependencies; the orchestration
must also enforce the exact reviewed scope. A negative control which erases
observations may still satisfy a paired Dafny theorem, so accepting only that
theorem would miss the fault. Separate coverage controls must reject it.
Likewise, a count of 20 roots does not establish coverage if an environment
variable selected the same root 20 times. The polynomial runner clears those
selectors and checks the exact unique identities.

These are scoped source-observation results. Complete SHAKE/Keccak, ML-KEM,
Java adapters/comparisons and failure-path declassification still require
composition work. The existing residual bytecode inventories remain open.

The separate `assurance/shake-api/` root now proves public API state/status
coupling by calling the unchanged executable Sponge methods over arbitrary valid
states. It preserves the native caller domains, makes cross-run separation
explicit and includes shared external outputs. Its replay verifies 1,558
included-body checks and 51 overlapping root-only checks, seven zero-finding
audits, five named false-assertion controls and an included-body axiom control.
This prerequisite does not prove internal operation traces: secret-dependent
branches could preserve the public state. Keccak child traces and API observation
faithfulness remain open. The independent root imports production source; no
existing root imports it, so the frozen Select inputs remain unchanged.

## Assurance boundaries

Functional correctness, source trace independence and artifact identity remain
separate claims. The proof infrastructure, compiler/runtime, reviewed Java
adapters, JDK primitives and their stated contracts remain trust boundaries.
Cryptographic hardness and complete TLS/QUIC security are not established by
these implementation proofs. Physical JVM/JIT/CPU/GC/provider timing remains
outstanding as an assurance boundary; universal constant-time execution is not
a promised Dafny deliverable. Deployment-specific measurements do not close that
universal claim. Independent external cryptographic/proof review remains open;
development-agent review does not discharge it. The
[review brief](2026-11-04-crypto-external-review-brief.md) prepares its scope and
reproduction requirements without claiming that the review has taken place.
