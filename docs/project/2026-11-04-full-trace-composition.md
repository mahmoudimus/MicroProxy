# Full source trace and adapter composition

This executes the approved source-first direction in issue
[#117](https://github.com/mahmoudimus/MicroProxy/issues/117). The implementation
choices below belong to this work; they are not additional security claims.

## Goal and completion boundary

Prove logical observation independence over the executable Dafny implementation,
then generate Java from that same verified source. Equal declared public inputs
and independently varying permitted secrets must produce equal declared
observations. Each composition boundary must state its ownership, frames,
public/private classification and any permitted output declassification.

The stages are:

1. Complete Keccak: eleven methods and four executable pure functions, including
   operation observations, child traces, allocations and cleanup.
2. Compose SHAKE/sponge, polynomial/NTT/ML-KEM and HKDF through their actual call
   paths, preserving the original accepted input and alias domains.
3. Close owned adapters: secret comparisons, conversions, validation, exceptions,
   errors and cleanup. State JDK/provider contracts explicitly.

This goal excludes physical JVM timing and independent external expert review.
Both remain outstanding obligations. Logical observations do not model physical
addresses, JIT decisions, garbage collection or CPU execution time. Cryptographic
hardness, Dafny/Boogie/Z3, compiler/runtime/provider behavior, and trusted
observation and evidence tooling remain explicit boundaries.

## First deliverable: complete Keccak observations

The exact method set is `NewOffsets`, `NewSources`, `SetLane`, `Iota`, `Theta`,
`RhoPi`, `Chi`, `Round`, `PermuteScratch`, `Permute` and `Wipe`. The exact pure
function set is `Rotate`, `Constant`, `Offset` and `Source`.

Use the existing canonical `SourceTrace` vocabulary. Observe ordered calls,
branch outcomes, method-local buffer roles and indices, allocations, loop bounds
and checks. The seven-field `Ops` event summarizes the declared arithmetic,
bitwise and shift operations in its supported executable region; it is not an
ordered JVM instruction trace. Implicit loop guards/iteration are represented by
the declared loop events. Every claimed operation family is mandatory, including
XORs in Theta and Chi. Unsupported syntax fails coverage rather than disappearing.

Scalar indices, array lengths and fixed tables are public under their actual
contracts. State words and standalone `Iota`/`Round` constants may vary as secrets.
The table equations justify public table values; their Java integer type does
not. No equality of private array contents is an implicit precondition. Retain
all existing functional contracts, ranges, freshness and alias restrictions.

`Round` must append each actual child trace. `PermuteScratch` must include each
round constant evaluation and round. `Permute` must include scratch/table
allocations, initializations, the permutation and both wipes. Factory results
receive explicit local roles; roles denote logical identities, not physical
addresses. New paired callers must prove that their first execution preserves
the inputs needed by the second, including all permitted shared-buffer cases.

## Pure-call snapshots without executable temporaries

The representation experiment found that executable tuple-capture locals change
Theta/RhoPi bytecode. A ghost capture followed by the original inline value
projection preserves every compiled class on the two qualified local JDKs:

```dafny
ghost var callWitness := Rotate(word, distance);
trace := trace + ST.Call(site, rotateTarget, 2) + callWitness.1;
var value := Rotate(word, distance).0;
```

The actual function returns `(value, ghost trace)`. Both components must be
connected to that function's checked body. Equality of the trace alone is
insufficient: Rotate's trace is independent of its private word, so a witness
with the wrong word could have the same trace.

The new resolved-AST rule must enforce all of the following:

- The capture is an explicitly ghost, fresh local with one defining assignment
  in the entire method, including ghost branches. It captures the full tuple.
- Capture and executable call resolve to the same admitted pure function and
  ordered argument expressions, using resolved declaration identity. Admitted
  functions have no heap reads, by-method body, external implementation or
  executable effects. Evaluate argument expressions at the same executable
  prestate; permit only reviewed ghost annotations between capture and call.
- Both occur in the same lexical block. Initially support one registered pure
  call in an executable statement. Unsupported multiple calls fail closed.
- Capture arguments cannot be replaced by aliases, constants, textual names or
  another call's arguments. No executable mutation or other effect may intervene.
- Structural argument equality preserves resolved node/result types and every
  conversion's destination type. It never strips conversion nodes: truncating
  and re-extending a private word can preserve its trace while changing its value.
- The actual runtime value is its inline `.0` projection. Exactly one child
  `.1` projection of this witness follows the actual Call event at the proper
  point in the surrounding expression's observation order. Reject missing,
  duplicated, reordered, reassigned or fabricated children.
- Observe executable argument reads and surrounding operations in their actual
  evaluation order. Ghost snapshot evaluation adds no runtime Call or Read event.
- Reject unknown callees, shadow declarations, unsupported tuple projections and
  pure functions whose value/trace relationship is outside the checked grammar.

The initial argument grammar admits resolved non-ghost variables, typed integer
and bitvector literals, one-dimensional array element reads, array lengths,
typed arithmetic/bitwise/shift expressions and explicitly reviewed native
conversions. Compare each node's resolved type, operator and declaration, not its
printed spelling. Reject statement expressions, conditionals, short-circuit
operators, comprehensions, function calls in arguments and unreviewed casts.
The enclosing runtime statement admits one inline pure call inside these same
strict expressions, a local assignment or one array-element assignment. A nested
effectful method-call argument, needed by `PermuteScratch`, requires a separate
reviewed extension after the initial binding controls pass.

Use one adjacent logical trace packet per supported executable statement. For
the initial pure-call grammar it follows the witness and precedes the executable
statement, with no executable effects between them. This records reads and
addresses before an assignment can change a variable used by those expressions.
The admitted function is total under its verified preconditions. Its
recursive expression traversal consumes argument Read events, then the exact
Call event and witness child, then subsequent surrounding events. For RhoPi the
packet orders `Read(a,j)`, `Read(offsets,j)`, `Call(Rotate)`, the child, and
`Write(b,i)`. Theta's left operand read precedes its Rotate argument read. A
fixed concatenation position for every child is insufficient. Packet placement
must not cross an executable effect or another statement's trace update.

A direct Dafny harness must establish full-result/value correspondence at the
supported array-read and local-variable sites, including writes to a separate
output array. A faithful intervening private mutation must break that theorem.
This complements the trusted AST rule; it is not a proof of that C# rule.

The complete Keccak instrumentation must also assert full-result equality in
the actual executable source, immediately after the pre-runtime packet and
before the inline call:

```dafny
assert callWitness == Rotate(actualWord, actualDistance);
```

This lets Dafny itself reject a stale captured value at the actual call site,
including a mutation hidden inside a parallel trace assignment. The observer
must bind the assertion to that call and still check all surrounding operations;
the assertion does not replace coverage. The initial binding-only regression
fixture deliberately retains its narrower four-statement grammar. Admission of
this five-statement production pattern is a reviewed extension in the complete
Keccak package, with its own body proofs and controls.

## Controls and evidence

Keep the frozen Select checker, fixtures and historical evidence unchanged.
Create a separate Keccak qualification package and explicit input manifest.
Controls must distinguish a real assertion counterexample from parsing,
resource exhaustion, a zero-match filter, tool failure or an unrelated failure.

Required controls include a private branch/address that is faithfully observed
but fails paired equality; missing Ops/Read/Write/Call/Alloc/loop observations;
dropped/reordered child traces; wrong branch outcomes; snapshot argument/callee
mismatch, shadowing, reassignment, a second unbound call, interposed mutation,
and fabricated tuples. Unchanged positive counterparts must pass under the same
proof policy. Exercise the actual proposed AST binding, not a text-only model.

Before adoption, freeze the complete input/tool graph, verify every included
owned body, audit it, run all controls and independently review the result.
Regenerate the complete production Java closure. Preserve literal source maps
and diffs. Following the polynomial component's precedent, explicitly reviewed
parentheses changes may be accepted only with exact complete class-set and byte
equality on the qualified JDK 21 and 25 profiles. This is a scoped compilation
result, not general compiler refinement. Recheck browser fingerprints and the
actual delivery boundary; no digest renewal substitutes for rerunning evidence.

Affected Select, polynomial, SHAKE API, functional and delivery consumers need a
new qualification against the changed source closure. Preserve dated historical
receipts; never relabel them as evidence for a new program.

## Execution and release coordination

Development starts from immutable commit
`d8d4a778afbdd63b39c3e5e09d203c278f0d5748` on the isolated
`diff/crypto-full-trace-composition` branch. The 0.8.1 publication chain has a
separate owner. Do not modify its script, branches, PRs, tags or merges. Adoption
and merge of this work require completed publication, a refreshed immutable
baseline, current qualification and eligible exact-head checks.

The erasure experiments are nonqualifying. Their two JDK class comparisons do
not close any trace proof, coverage-checker review or Linux qualification.
Keep #117 open until its stated engineering obligations are met; keep external
review and physical timing visible independently.

## Candidate checkpoint (2026-11-05 UTC)

Draft [#147](https://github.com/mahmoudimus/MicroProxy/pull/147) publishes the
complete Keccak source candidate and its checked replay. Production adoption
still requires the parent assurance and delivery gates below.

The source replay passes all 44 gates: nine full proof roots with 1,877
overlapping checks, nine clean audits, the independent-state paired harness,
and controls for secret-dependent addresses, branches and stale full-result
captures. The coverage replay checks all eleven methods and four pure functions,
with 61 method and 18 function controls. Both observers must accept the same
actual program. Their C# rules and the Python evidence tooling remain trusted.

The changed dependency graph also has fresh SHAKE functional, ownership/API
and Select consumer evidence. The original historical packages and receipts
remain unchanged. Replays reject altered source/dependency identities, forged
command/log bindings and ambiguous proof summaries. The published data bundles
retain raw logs and support checked relocation without private-cache fallback.

The fresh full canonical stage verifies every one of its 20 source roots. Its
66 source/provider files compile to the same complete 66-class map as the
released 0.8.1 baseline on the qualified compiler profile. The sole raw Java
change is five grouping-parenthesis pairs in one file. Four of those lines
appear in the literal runtime caller inventory, so the old delivery contract
correctly rejects the new digest. A separately selected successor retains the
193-site inventory, helper/boxing policy and reviews, adds current source pins,
and preserves the original configuration. It does not normalize arbitrary
source changes or accept both digests indiscriminately.

Parent integration uses three distinct authenticated views:

1. A complete released Baf project for historical ledger/package checks.
2. The current 85-source view and its separate paired proof program.
3. A full current delivery project using the selected successor at its canonical
   configuration path, with unchanged helper code.

The parent must require current replacement evidence for every affected claim.
Only unchanged complete polynomial theorem closures may inherit their old
proofs. Old ML-KEM composition and package-wide erasure claims cannot be relabeled.
The actual checkout's generated Java must match the canonical source; placing
canonical files only in a private project does not establish checkout identity.

The original artifact-only validator passed against the actual published 0.8.1
library and bundle using the candidate's freshly built checkout classes. All
468 library classes match. The bundle retains those classes, 84 crypto classes,
37 runtime classes and all three required notices. Nine handshake cases and
nine nonce cases pass on each of JDK 21 and 25, with checked class origins.
The complete project and actual checkout input maps remain unchanged afterward.
This establishes artifact compatibility; it does not substitute for the parent
prerequisite policy or complete its adoption gate.

Physical JVM timing and independent external
expert review remain outstanding. Full SHAKE/sponge, NTT/KEM, HKDF and owned
adapter trace composition are the later stages, not conclusions of this slice.
