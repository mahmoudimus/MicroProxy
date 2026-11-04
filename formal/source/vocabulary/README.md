# Ghost observation vocabulary

This Dafny component proves that a typed source-observation vocabulary retains
its event kinds and payloads when encoded. It proves event and arbitrary-list
injectivity, prefix unambiguity and decoding of emitted encodings. Buffer roles,
addresses, branch outcomes, loop checks, calls and provider metadata remain
distinguishable. `Ops` records counts, not an ordered instruction trace.

The vocabulary does not prove that source instrumentation observes the actual
operations. Binding identities and covering executable source remain separate
obligations. Compiler/runtime/JDK behavior and physical timing remain outside
these proofs.

From the repository root:

```sh
python3 -m unittest discover -s formal/source/vocabulary -p 'test_*.py' -v
python3 formal/source/vocabulary/replay.py --output /fresh/vocabulary-replay
```

The runner freezes every input before loading shared Python tools, uses the
pinned Dafny parser (`formal/crypto/delivery.source_closure`) to discover the
complete include closure, installs the official checksum-pinned Dafny 4.9.1
distribution, audits all nine source files and verifies 29 kernel checks under
the existing 30-second / 50,000,000-resource / `case_split=0` policy. Six
defective encodings must fail their exact named assertions. The erasure clients
must pass their reviewed 2/3 checks and generate identical complete file
inventories at the same basename. The ghost-only vocabulary emits no Java
classes.

The owned-declaration policy uses a tiny trusted C# `--plugin` over Dafny's
actual resolved AST. It is not a source lexer or a second parser. The runner
builds `formal/source/vocabulary/checker/ObservationDeclarations.csproj` from
the frozen `.cs`/`.csproj` before invoking Dafny, using the portable
`DafnyHome` property to reference the pinned `DafnyCore.dll` and
`Boogie.Core.dll`. The build is development-only; it is not a production
runtime dependency. It requires a .NET SDK; CI installs SDK 10, and the receipt
records the actual SDK version, build command and resulting assembly hash. The
Release build disables debug metadata so the assembly hash is stable across
build paths; source, project, SDK and `DafnyHome` are the portable build
identity, and the actual assembly is re-hashed before and after policy calls.
The SDK version is queried in the build directory. A separate build-isolation
control plants stale sources and invalid MSBuild imports inside the fresh
output tree, then requires an identical clean build without changing the
fixture. The runner does not inspect or create neighboring build directories.

For every source file in every entry's official parser closure, the plugin
checks exact authored identities and rejects:

- `Function.Body == null` (functions and predicates);
- `Method.Body == null` (methods, lemmas and constructors);
- `ConstantField.Rhs == null` (consts without `:=`);
- abstract type declarations and `{:opaque}` type declarations;
- abstract modules, traits and unknown owned AST declaration forms.

Datatype constructor fields and class `var` fields are storage declarations,
not algorithm bodies. System/prelude declarations are filtered by source-file
origin and source-token metadata. An authored `{:auto_generated}` attribute
does not exempt a function, method or const from the body check; a real control
tests all three. The plugin also requires every file in
the complete parser closure to appear in its inventory, including include-only
and declaration-free/comment-only files. Quoted comments, strings, attributes,
inline formatting, contracts and
set/map literals are handled by the Dafny parser, so a contract set literal can
never be mistaken for a body. Diagnostics are named policy rejections such as
`owned declaration missing implementation: function M._default.F` or
`unsupported owned abstract type: M.T`.

Dafny's auditor remains enabled and independent; it catches axioms, `assume`
statements and `{:verify false}`. The verifier checks contracts. The plugin
only adds the no-unimplemented-owned-declarations policy, where the auditor
deliberately allows conservative ghost symbols. The Dafny front end, the C# plugin adapter
and the pinning/build machinery are an explicit trusted computing base; they
are not formally verified.

The finite erasure experiment is evidence about this pinned compiler invocation;
the compiler remains trusted. Source, manifest and complete tool-distribution
checks run again before the replay can succeed. Legitimate proof changes require
reviewing the new obligations before changing the expected counts.
