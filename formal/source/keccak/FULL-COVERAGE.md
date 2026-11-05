# Complete Keccak observation coverage

`coverage_replay.py` checks the resolved executable bodies of eleven
`NativeKeccak` methods and four pure functions. It checks the canonical trace
encoder, ordered observations and child traces, typed pure-call snapshots, and
the full-result assertions beside the actual inline calls. Unsupported syntax
fails coverage. The C# observers and Python orchestration remain trusted tooling.

This is a resolver-only component. Every result has `qualification:false`.
Coverage does not prove functional correctness, noninterference, generated Java
identity, physical timing or delivery. Those need separate proof and delivery
receipts for the same source graph. The earlier snapshot-binding experiment in
`README.md` retains its original, narrower scope and inputs.

Run from the checkout containing this component:

```sh
python3 -I -B formal/source/keccak/coverage_replay.py \
  --source-root /absolute/path/to/complete-keccak-stage \
  --dafny /absolute/path/to/dafny \
  --dotnet /absolute/path/to/dotnet \
  --profile macos-sdk10.0.400 \
  --targeting-packs /absolute/path/to/two-approved-archives \
  --output /absolute/fresh/output/outside-git
```

The stage must contain the complete parser-discovered source closure for
`NativeMlKem.dfy`, `native_shake_domain.dfy`, and the materialized paired
`formal/source/NativeKeccakTraceHarness.dfy`. The harness template is
`NativeKeccakTraceHarness.dfy.in`. Materialize it only in a separate replay stage;
the authenticated production source views deliberately keep it as a template.
See [source-view construction](../epochs/keccak-004/README.md).

The runner requires Dafny 4.9.1, .NET SDK 10.0.400, the selected reviewed tool
profile, and the two official .NET 6 reference-pack archives listed by exact
identity in `encoder/net6-targeting-packs.json`. It builds both observers from
captured source bytes, with private offline reference packs and controlled
MSBuild imports, compiler inputs and environment. Existing output, input aliases,
unexpected references, imports, analyzers and configuration inputs reject.

Acceptance requires all 61 method controls, 18 function controls, both observers
on one combined actual program, the frozen-input rebuild, and the build-boundary
and caller-admission controls. Each negative must resolve without the observer
first and then produce its intended diagnostic. Raw logs, evaluated compiler
inputs, complete file maps and before/after identities are retained.

The macOS arm64 execution has passed engineering review. A Linux profile is
implemented but has no completed execution qualification in this component's
current evidence. JDK/runtime fields retained in the legacy tool profiles are
not inputs to this resolver-only result. No solver or JVM is invoked.
