# Vendored Starlark interpreter

The Java Starlark interpreter from [Bazel](https://github.com/bazelbuild/bazel)
(`net.starlark.java`), as maintained with additions (bytes, field and index assignment,
expiration deadlines) in the `libstarlark` module of
[verygoodsecurity/starlarky](https://github.com/verygoodsecurity/starlarky) (commit `b0d93f7`).
Both are Apache License 2.0; the original copyright headers are kept on every file.

Changes from upstream:

- Packages renamed from `net.starlark.java` to `org.microproxy.thirdparty.starlark`.
- The command-line REPL (`cmd`) and the annotation processor (`annot/processor`) are omitted.
- `CpuProfiler` logs through `System.Logger` instead of Flogger.
- JetBrains nullness annotations are replaced by `javax.annotation` (JSR 305) ones.
- A builtin returning a `Structure` whose class has `getAssociatedTypeConstructor()` is typed with
  that type instead of an anonymous struct (`MethodDescriptor`, `CallUtils.getAssociatedStarlarkType`),
  so `response(...)` is a `Response` to the type checker.
- From starlarky's `larky` module (which keeps them in the interpreter's packages):
  `eval/StarlarkEvalWrapper`, `eval/StarlarkSequence`, `eval/StarlarkIterator` and
  `eval/NamedTuple`, for the Larky runtime in `org.microproxy.thirdparty.larky`.
- `StarlarkThread.current()` returns the thread running the innermost call on the current Java
  thread (kept by `push`/`pop`), so that Larky values shared between scripts run code in their
  caller's thread.
- `bytes.decode` receives the thread, and uses the decoder installed with
  `StarlarkBytes.setDecoder` (CPython's codecs, by the standard library) only under the semantics
  flag `StarlarkBytes.PYTHON_CODECS`; otherwise it uses Java's charsets as before, now reporting an
  unknown encoding as an `EvalException` rather than an unchecked Java exception.

The proxy-facing API lives in `org.microproxy.starlark`; nothing outside this module depends on
these classes.
