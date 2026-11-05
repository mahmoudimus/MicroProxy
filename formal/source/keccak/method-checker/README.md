# Complete Keccak coverage replay

This is a coverage-only component. Every receipt says `qualification: false`.
It does not prove source values, noninterference, Java identity, delivery, or
physical timing. The C# observers and Python runner remain trusted tooling.

Run both reviewed observers and all real controls with explicit inputs:

```sh
python3 -B formal/source/keccak/coverage_replay.py \
  --source-root /absolute/path/to/complete-source-stage \
  --dafny /absolute/path/to/dafny \
  --dotnet /absolute/path/to/dotnet \
  --profile macos-sdk10.0.400 \
  --targeting-packs /absolute/path/to/exact-two-nupkg-inputs \
  --output /absolute/path/outside-git/fresh-coverage-output
```

`--source-root` must contain the actual complete stage, including these fixed
combined entries:

- `formal/crypto/NativeMlKem.dfy`
- `formal/source/NativeKeccakTraceHarness.dfy`
- `formal/crypto/native_shake_domain.dfy`

The paired harness can be materialized by the full qualification owner from
its `.dfy.in` template. This runner has no author-cache or missing-file fallback.
It freezes the literal include closure and checks both plugins against that
same program. The actual event/operation analysis uses resolved Dafny ASTs;
the include scanner only freezes inputs. Escaped, nonliteral, absolute, or
out-of-root includes reject.

The required reviewed profile IDs are `macos-sdk10.0.400` and
`linux-sdk10.0.400`. Their exact existing Select profile JSON bytes are pinned,
and the host, SDK, launcher, Dafny/Core and Boogie identities must match.
Unsupported or missing profiles fail closed. The legacy Select DLL, JDK and
Maven-runtime profile fields are outside this resolver-only scope; no Java or
solver invocation occurs. All installed .NET and Dafny files are hashed before
and after execution. A supported profile is not itself a claim that this
component has been qualified on that platform.

The runner builds from frozen copies outside Git, pins SDK10.0.400 with
`rollForward: disable`, and disables ambient Directory.Build imports. Separate
projects use explicit compile items and share the unchanged canonical encoder
policy in `../encoder`. The old `../checker/PureSnapshotCoverage.csproj` is
untouched; these projects are siblings outside its default compile glob.

The replay requires the exact eleven method roots and all four actual pure
function bodies. It then executes the 61 method controls and 18 function
controls with separate per-gate counts. Every negative first resolves without
a plugin and then must produce its intended checker diagnostic. Parser,
resource, timeout, tool and zero-match failures cannot count as a passing
control. No production `.dfy` fixture is added; all mutant sources are generated
inside the fresh private output.

Output admission rejects existing paths, symlinks, Git ancestry, relative paths
and input-root output paths without overwriting them. Bounded admission controls
exercise those checks. A private mutable-input simulation is poisoned after
freezing; fresh builds and a combined resolve must still consume the unchanged
frozen inputs and reproduce identical DLLs. The real source and checkout are
never poisoned.

The method observer preserves the independently reviewed C# SHA256
`f106ea52f289062c2110c31981ad916017c0735c25f294c5dc925ea793e1fab3`.
It checks exact declarations/imports, ordered operations and accesses, native
conversions and intermediate widths, immutable trace prefixes, pure tuple
snapshots and last assertions, actual child traces, allocations and loop checks.
Complex array LHS expressions and unknown executable forms remain unsupported.
Faithfully observed private branches and read addresses are admitted; secrecy
belongs to separate paired source proofs.

The build also requires exactly the two official .NET6.0.36 targeting-pack
archives listed in `../encoder/net6-targeting-packs.json`. The manifest pins
NuGet.org catalog SHA512, package sizes, SHA256 and exact versioned URLs. The
runner authenticates and freezes the archives, rejects unsafe/duplicate ZIP
paths and symlinks, and installs all577 payload files into a private pack root.
No replay download or mutable user-package-cache fallback occurs.

Child processes use a minimal locale/PATH allowlist with owned HOME, config,
temporary, CLI/cache directories. MSBuildUserExtensionsPath is explicit, all six
Common/CSharp user-import hooks and directory build/package imports are disabled,
and automatic response files, compiler servers, workload resolution and ambient
editor/global-config discovery are disabled. The explicit private NuGet config
has no sources or fallback folders; targeting-pack downloads are disabled.
Actual restore metadata, compiler reference/analyzer/source/config items and
reported imports are checked and recorded. The reported MSBuildAllProjects list
is not itself a complete import inventory; the closure relies on the pinned SDK
tree plus explicit suppression of ambient hooks.

Default replay includes real poisoned-selector/user-target/ancestor response and
package-config controls, missing-private-pack rejection, private-config tampering,
and nine untrusted archive-admission controls. The initial portable run001 is
historical: it did not close ambient imports or the577 targeting-pack files.
