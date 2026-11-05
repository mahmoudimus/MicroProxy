# Focused pure-snapshot binding gate

This package tests the proposed pure-call binding used before complete Keccak
source observations. It is **binding-only** and reports `qualification: false`.
It does not establish full operation coverage, noninterference, canonical
encoding semantics, Java delivery or physical timing.

The fixed roots are `SnapshotBindingControls.Local`, `ArrayRead` and `Around`.
They call the actual `NativeKeccak.Rotate`, materialized from Git commit
`d8d4a778afbdd63b39c3e5e09d203c278f0d5748` with the exact reviewed private
Rotate tuple/ghost patch. The canonical production source is never changed.
The runner contains the patch and its digest; it does not read producer caches.

Run with the qualified macOS arm64 Dafny 4.9.1 and .NET SDK 10.0.400 launchers:

```sh
python3 -B formal/source/keccak/test_snapshot_binding.py \
  --dafny /absolute/path/to/dafny \
  --dotnet /absolute/path/to/dotnet \
  --output /absolute/path/outside-git/new-output
```

The fixed Git commit must be available locally. The existing reviewed macOS
profile is mandatory and hash-bound; missing keys or different tools reject.
This is currently a macOS arm64 execution profile, without Linux qualification.
The resolver runs without a solver. Used launcher/Core/Boogie identities are
checked before and after execution. C# builds consume the frozen staged source,
with directory build imports disabled and output outside Git. Existing output
paths and symlink ancestors reject without writes. Raw commands, logs, source
maps, checker inputs/DLL hashes and typed outcomes remain under the output.
A consumer test poisons a simulated checkout after freezing and checks that an
actual second build still consumes the frozen source.

## Admitted binding

Each root has exactly an empty trace initialization, an explicitly ghost full
tuple capture, its adjacent pre-runtime packet, then one executable assignment.
Reset, capture and packet each have exactly one ghost destination and one
initializer/RHS; multiassignment cannot hide a call or heap write. No additional
prefix, ghost reassignment, executable gap or trailing statement is admitted. The witness has one definition across the whole resolved method.
The actual value call is inline `.0`; the packet consumes that witness's `.1`
exactly once after its exact `Call` event. Argument reads and surrounding
operations determine the packet order.

Snapshot and runtime arguments must have identical resolved declarations,
operators, intermediate types and conversion destinations. The narrow cast
policy admits `bv8`/`bv64` and native `I`/`int` conversions in either direction;
other conversions reject. The actual Rotate body also admits Dafny's inserted
native `I` to `bv7` shift-distance conversion. Unknown type and expression forms,
higher-order application, by-method/extern functions and heap-reading targets
reject. Array assignment indices are initially limited to a typed literal or a
non-ghost formal. Complex LHS evaluation needs a separate reviewed extension.

The wrapped-add control has a companion accepted wide-arithmetic packet. It
changes only the snapshot's intermediate addition from `bv64` to `bv8`, requiring
a typed-argument mismatch rather than an unsupported cast or missing Ops error.
The controls also cover ghost such-that prefixes, extra calls, child omission,
duplication/order, marker mismatches, aliases, unsupported syntax and target
closure. Every negative first resolves without the plugin, then must produce
its named checker diagnostic. Parse, type, tool and resource failures do not
count as successful controls.

## Trusted premises and separate proofs

The C# rule and Python orchestration remain trusted. Exact Git-pinned
`SourceTrace` and observation vocabulary definitions are premises of this
focused gate. The plugin checks marker identity and a finite pure-body grammar;
it does **not** validate their encoder bodies or prove value/trace observation
semantics. The later complete Keccak observer must check canonical marker
bodies, all operations and the full eleven-method/four-function closure.

`SnapshotValueBridge.dfy` is the separate direct Dafny value/full-result bridge,
including shared input/output arrays. Its faithful stale-word mutation is a
proof control, not an AST rejection control. Those root-owned proof receipts
are separate from this resolver-only runner. Historical Select checks are kept
unchanged: the runner reproduces their registered Keccak positive fixture and
two existing inline-projection/forged-child negatives. It makes no claim that an
unknown new root or an incompatible old signature proves protocol rejection.

The erasure spike found all 65 generated classes identical on the two qualified
local JDKs for the ghost-capture representation, with four literal Java
parenthesis bytes changed. That experiment is separate and nonqualifying; this
binding gate does not regenerate Java. Full closure qualification must repeat
the required source/class comparison after instrumentation. Physical JVM timing,
GC/JIT behavior, providers, cryptographic hardness and expert review remain
outside this result.
