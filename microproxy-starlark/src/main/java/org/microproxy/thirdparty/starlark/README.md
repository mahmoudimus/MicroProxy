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
- Allocation accounting (`eval/Allocations`, new): a thread counts the approximate bytes of the
  values its calls create (`StarlarkThread.getAllocatedBytes`), against an optional budget
  (`setMaxAllocatedBytes`); past it, `allocate` throws an `EvalException` ("memory budget
  exceeded") and every later step fails too. It counts bytes created, not bytes reachable.
  Counted where values are made: lists (`MutableStarlarkList`, `RegularImmutableStarlarkList` and
  `ImmutableSingletonStarlarkList` constructors, and each growth of a list's array), tuples
  (`Tuple.wrap`), dicts (`MutableDict` constructor, and new entries in `putEntry`, `putEntries` and
  `setdefault`, counted when the size reaches a power of two), bytes (the `StarlarkBytes`
  constructor), strings made by `+`, `*`, `%`, slicing, `str`, `repr` and the string methods
  (`join`, `replace`, `split`, `upper`, `format`, ...), list comprehensions as they grow,
  `json.encode`/`decode`/`indent`, `bytes.decode` and `hex`. Strings, lists, tuples and bytes
  repeated with `*`, lists concatenated with `+`, and `list(range(n))` are checked before they
  are allocated (`checkAllocation`), so `"x" * 10**9` fails without allocating; `replace` and
  `json.encode` check as their output grows. Code that cannot throw counts with `allocateLater`,
  which makes the thread's next step fail instead. `allocateCurrent` counts against the thread of
  `current()`, for code that is not handed its thread.
- The deadline is a `System.nanoTime()` value (`setDeadlineNanos`, `hasDeadline`,
  `getDeadlineNanos`) instead of epoch milliseconds read from a `Clock` (`setClock`/`getClock` are
  gone; `setExpirationMs`/`getExpirationMs` convert), and `exceededBudget()` reports the bound a
  failed call ran out of: steps, memory, or time (also when a builtin such as a regular expression
  gave up at the deadline).
- From the `larky` runtime, struct (`SimpleStruct`) and object (`LarkyPyObject`) constructors and
  `codecs.decode` count what they make too.

The proxy-facing API lives in `org.microproxy.starlark`; nothing outside this module depends on
these classes.
