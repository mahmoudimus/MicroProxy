# HKDF source observations and array input composition

The production Java bridge calls generated `ExtractArrays`, `ExpandArrays` and
`LabelInfoArray`. These copy Java-backed octet arrays through the actual compiled
`CopyInput` method, then compose the original `Extract`, `Expand`, `LabelInfo` and
`ExpandLabel` operations. The eight methods share the single implementation in
`formal/dafny/hkdf/Hkdf.dfy`; ghost outputs disappear during Java generation.
`Hkdf.java` and `JdkHmac.java` retain their public behavior and primitive boundary.

The functional input domains and error precedence are unchanged: invalid hash
first; Expand length before empty key; LabelInfo bounds before ASCII validation.
Empty labels, empty IKM and every nonempty PRK size remain accepted. Array inputs
may alias. CopyInput returns the entry-state sequence and preserves its array;
the array harness proves saved snapshots survive later writes, including aliased
inputs. The generated array route replaces the handwritten `HkdfBridge.sequence`
helper. Historical bytecode evidence for that removed helper is historical, not
current coverage of the new route.

Public observations include hash choice, lengths, label UTF-16 units, branch
outcomes, sequence operation metadata, calls and primitive-call shapes. Byte
contents and HMAC results remain private. The paired harnesses prove trace and
success/failure-shape equality under equal public shapes, without equating private
inputs or imposing array disjointness. These are source-level observations.

The finite C# checker binds exact resolved module/class/declaration/formal and
child-output identities. A callee trace is appended once immediately after its
actual call; trace resets, stale/reused child outputs, shadow declarations,
unsupported effects and unknown expressions fail closed. The four array roots
allow only identifier assignment/call-output LHS forms. CopyInput admits only the
rank-one bv8 array Length of its exact input formal, its explicit upper-bound
read, and its full slice; arbitrary array reads/stores are unsupported.

Bare returns require both absent authored RHS and absent resolved HiddenUpdate.
Short-circuit AND/OR operands emit `EvBranchIf(site,enabled,outcome)` with exact
resolved path conditions. Conditional nested reads/calls/allocations are rejected.
The only sequence constructor is Extract's canonical zero-byte initializer.
`ValidHash` is an explicit atomic public-only boundary with an exact checked
signature and `{32,48,64}` membership body. Coverage does not model the generated
DafnySet implementation, allocation internals, or general JVM execution order.
Site IDs are method-local labels; a consistent bijective relabel is valid.

The approved source has 257 kernel VC rows, 11 sequence NI rows and 13 array NI
rows. `EvBranchIf` contributes one actual well-formedness VC. Two mixed AND/OR
fixtures each require a full 257-row proof. Five functional/model/ownership
controls require actual correctness failure and passing well-formedness at their
named obligations. The only allowed assumption is the deterministic external
`Mac` contract; audits of the three own files admit exactly 1/0/0 findings.

The portable replay reconstructs the exact reviewed 115 coverage fixtures from
line-edit recipes with authenticated base and result hashes: 112 named negatives
and three valid positives. Each must ordinarily resolve before any coverage
classification. Real anchored plugin diagnostics are required; comments, source
excerpts, missing roots, parser failures and resource failures earn no credit.
Original checked-in reviewer fixtures and the v1 input manifest remain historical
inputs. Current recipes port all 81 prior named negatives to the eight-root
program and add the R2 fidelity cases. Existing metadata, observed-secret,
binding-erasure, duplicate-child and BOM/include-audit controls also remain in the
full replay. Observed-secret controls prove their actual changed Extract body and
reject its own-file NI harness; they do not claim the new array wrappers satisfy
secret-dependent mutant trace contracts.

Run data-only regressions from the repository root:

```sh
python3 -I -B -m unittest discover -s formal/source/hkdf -p 'test*.py' -v
```

Run the complete bounded unit using explicitly selected absolute tool paths and
an independently reviewed digest of `inputs-v2.json`:

```sh
python3 -I -B formal/source/hkdf/run.py \
  --manifest "$REPO/formal/source/hkdf/inputs-v2.json" \
  --expected-manifest "$HKDF_INPUTS_SHA256" \
  --profile macos-sdk10.0.400 \
  --dafny "$DAFNY" --dotnet "$DOTNET" \
  --targeting-packs "$OFFLINE_NET6_PACKS" --runtime "$DAFNY_RUNTIME_JAR" \
  --jdk21 "$JDK21" --jdk25 "$JDK25" --output "$FRESH_ABSOLUTE_OUTPUT"
```

The Linux profile is `linux-sdk10.0.400`. Both profiles are the repository's
reviewed Select tool profiles, authenticated byte-for-byte. They pin Dafny4.9.1,
Z3 4.12.1, SDK10.0.400 and the JDK/runtime inputs. The offline pack directory must
contain exactly the two archives from
`formal/source/keccak/encoder/net6-targeting-packs.json` (577 payloads). No SDK,
pack, tool tree or absolute private path is shipped here. The caller supplies
those authenticated external tools; no ambient NuGet restore is used.

`--phase preflight` performs ordinary resolution, the strict checker build,
coverage and actual Java/runtime checks, with **zero SMT proof credit**. The
full phase additionally executes every required proof/audit/control at the
original 30-second/50-million-resource/two-core/case-split-zero/seed-zero policy.
Output must be new, outside Git and all input roots. Inputs and complete tool
maps are authenticated before/after. JDK maps include every regular file, directory
and symbolic link as typed triples; symbolic directories are never followed and
external link targets reject. Output overlap is rejected in both directions
against all source, manifest, runtime, targeting-pack and tool roots before any
output directory is created. Every child gets a private HOME/temp/XDG
configuration and a minimal environment. Python helpers compile captured pinned
source bytes rather than loading .pyc. The reviewed owned-process supervisor
saves stdout and fsyncs the actual exit/argv/environment record before parsing or
classification; only confirmed process-group members can be signaled.

Nine generated package Java files, the aggregator and translation metadata must
match the reviewed R2 bytes literally. Three actual facade/bridge/provider sources
join both same-JDK compilations; committed and freshly generated output must have
identical inventories and all 12 actual class bytes on JDK21 and25. Reviewed
same-profile class maps are checked separately. Raw source differences are saved
without normalization. The real array/JCE harness executes 150 cases and346
assertions separately on each JDK. The original GeneratedHkdfTest suite also
executes 45 cases/2766 assertions on each JDK, with adapter discipline and its
select/cast/decoy controls. These suite counts stay separate. These finite checks
are not adapter refinement.

Dafny/Boogie/Z3, compiler ghost erasure, the reviewed but unproved C# checker,
.NET/SDK tooling, javac/DafnyRuntime/JVM/JIT/CPU/GC and JCE HMAC remain trusted.
No physical constant-time, cryptographic-hardness, global trace-ID identity,
whole-component composition, release/adoption or expert-security claim follows.
Every report retains `qualification:false`. Current external delivery/timing
inventories must explicitly adopt the changed source and removed helper; old
receipts are not refreshed by this replay.

A completed full run emits a new `SOURCE-EVIDENCE-v2.json` projection in its output
directory, with hashes of every raw command record and no private absolute paths.
It cannot export a preflight or relabel the old five-operand JDK scope as a full
tree snapshot. Staging that receipt is a separate reviewed action; it never
rewrites repository evidence or its own input manifest. Exactly the named output
receipt is excluded from package input hashing to avoid a hash cycle; it must be
independently pinned by the obligation ledger. Executable/control files in
`work`, `obj`, `bin` or `__pycache__` remain subject to admission. Never-loaded
Python bytecode cache files are ignored because raw-source loading bypasses them.
The old v1 input and source/production receipts remain historical.
