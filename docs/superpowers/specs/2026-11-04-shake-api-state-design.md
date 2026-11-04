# SHAKE public API state coupling

The approved architecture for issue #117 proves properties over executable
Dafny, then generates Java from that source. The next bounded deliverable is
public API state/status coupling for the existing `NativeShake.Sponge`, before
full logical-trace composition. This design follows the maintainer's instruction
to continue while keeping physical JVM timing outstanding.

## Property and domain

Two valid sponges with equal public rate, position and squeezing phase may have
arbitrary, independently chosen lane/scratch contents. With equal public input
lengths, slice arguments and requested output lengths, corresponding calls must
return the same status and preserve equality of those public state fields.
Actual secret output contents are intentionally unconstrained. Cover constructor,
Update, Start, Next, Read and Destroy, with arbitrary permitted contents and both
rates. Prove closure across segmented calls and include empty input/output,
exact rate boundaries, invalid slices and phase-error precedence. Do not narrow
the production methods' accepted domains or hide an alias precondition.

The proof must call the actual methods, using their functional contracts, and
verify the included implementation bodies. Ghost lemmas may establish public
state relations for the existing SpongeSpec equations; they must not implement a
second executable sponge. Use fresh paired instances or explicit cross-run
write-footprint disjointness, and preserve within-call external buffer aliases.

## Component and dependencies

Add a standalone proof component at `assurance/shake-api/`. This independent root
includes the existing production `formal/crypto/NativeShake.dfy`; no old proof
root includes the new component. All existing production and Select package
inputs remain byte-identical. The component owns an exact parser-discovered
transitive-source inventory, including its harness, replay/tool inputs and source
audits. This avoids changing a frozen unrelated proof package for an additive
proof root. It does not permit changed or omitted dependencies.

The selected alternative was same-body full SHAKE observations. That stronger
milestone requires checked field/receiver observations and transitive Keccak
traces; observing an opaque Permute call would not close it. Continuing the
bytecode extractor is not the selected route.

## Acceptance and claim limits

Use checksum-pinned Dafny 4.9.1/Z3, the existing 30-second / 50,000,000-resource
policy and `O:smt.case_split=0`. Replay included bodies as well as the new root,
audit every included file and reject incorrect status/phase/position claims with
named genuine proof failures. Parser/type/resource/timeout failures cannot pass
negative controls. Pin inputs before and after replay; reject unsafe output paths
and source drift. Preserve raw commands/diagnostics and report incomplete/failure
honestly.

Require tests for manifest omissions, unsafe paths, drift, incorrect proof
counts, misleading verifier summaries and control diagnostics. Run current ledger,
release-claim and strict documentation gates; confirm unchanged existing source
and generated production Java. Independent development review is required.

This component proves public API state/status coupling under the existing
functional contracts. It does not prove operation trace independence, observation
completeness, Java/JVM refinement, physical timing/erasure, hardness or external
expert review. Do not add a supported whole-SHAKE trace claim. Document what
remains, including Keccak child traces, API observer faithfulness and adapter/error
composition. Physical JVM/JIT/CPU/GC/provider timing stays outstanding.
