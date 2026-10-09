# Vendored Larky runtime

The Python-compatibility runtime of [starlarky](https://github.com/verygoodsecurity/starlarky)'s
`larky` module (commit `b0d93f7`), which the standard library in
`org/microproxy/starlark/{stdlib,vendor}` (see `org.microproxy.starlark.stdlib.Stdlib`) is built
on: Larky's globals (`_struct`, `_mutablestruct`, `_partial`, `_property`, ...), Python builtins
(`bytes`, `bytearray`, `int`, `iter`, `next`, `getattr`, ...), the class model (`object`, `type`,
`super`, `classmethod`, `staticmethod`), structs, codecs, and the native modules the `.star` files
load. Apache License 2.0; original copyright headers are kept where the files had them.

Copied (packages under `org.microproxy.thirdparty.larky`):

- `annot/` (`Library`, `StarlarkConstructor`), `LarkySemantics`, `parser/StarlarkUtil`.
- `modules/`: `BinasciiModule` (`jbinascii`), `C99MathModule` (`c99math`), `CodecsModule`
  (`codecs`), `CollectionsModule` (`jcollections`), `ResultModule` (`jresult`), `StructModule`
  (`jstruct`), `SysModule` (`sys`), `ZLibModule` (`jzlib`), `XMLModule` (`jxml`) with
  `xml/LarkyXMLNamespaceContext`; `codecs/`, `globals/`, `types/` (and `results/`, `structs/`),
  `testing/AssertionsModule` (`assertions`), and from `utils/` `ByteArrayUtil` and `StringCache`.
- `objects/` (Larky's Python object model).
- `re/PyRegexTranslator` (adapted, see below).
- Into the interpreter's packages (they need package access): `StarlarkEvalWrapper`,
  `StarlarkSequence`, `StarlarkIterator`, `NamedTuple` (from the `larky` module's
  `net/starlark/java/eval`).

Not copied: the evaluator, script engine, console and module supplier (MicroProxy's loader is
`org.microproxy.starlark.stdlib.Stdlib`), and every module that needs BouncyCastle, Tink,
protobuf, WSS4J, Gson or re2j, or is specific to one company: crypto (`CryptoModule` and
`modules/crypto`), `OpenSSLModule`, `ECDHModule`, `X509Module`, `ProtoBufModule`, the vault,
network-token and PII modules, `JsonModule` (replaced, see below), `RegexModule` (rewritten), and
the JUnit-based `UnittestModule` (the tests have their own).

Changes from upstream:

- Packages renamed to `org.microproxy.thirdparty.larky` (and, for the interpreter, from
  `net.starlark.java` to `org.microproxy.thirdparty.starlark`).
- Lombok removed: `Partial` and `Property` have hand-written constructors (and `Property` a
  builder); `@SneakyThrows` bodies catch and rethrow through `utils/Sneaky`.
- JetBrains annotations replaced by `javax.annotation` (JSR 305) ones, or dropped (`@Contract`).
- `TextUtil` no longer uses commons-text (`StringEscapeUtils.escapeJava`, `EntityArrays`,
  `CharSequenceTranslator.hex` are reimplemented); `ByteArrayUtil` no longer uses BouncyCastle's
  `Pack`; `AssertionsModule` and `LarkyXMLNamespaceContext` use `java.util.regex` instead of re2j,
  and the latter spells out the XML-DSig namespace instead of importing `XMLSignature`.
- `utils/Reporter` logs through `System.Logger` instead of writing to a Larky console.
- Regular expressions run on `java.util.regex` instead of RE2: `re/PyRegexTranslator` emits Java
  syntax (Unicode property classes for `\d \w \s`, look-around for `\b`, `^`, `$`, numbered
  backreferences; look-around, backreferences, atomic groups and possessive quantifiers are
  accepted; conditional groups are rejected); `re/PyRegex` and `re/RegexPattern` are rewritten for
  Java's matcher (regions with transparent, non-anchoring bounds; matching aborts at the calling
  thread's deadline), and `RegexModule` is the `jregex` module.
- Values that remember the thread that made them (structs, Python objects, properties, iterators,
  `super`) run their code in the caller's thread (`StarlarkThread.current()`, through
  `StarlarkUtil.callerOr`), since MicroProxy shares loaded modules between scripts and
  connections.
- Natives that were not copied are MicroProxy's own, in `org.microproxy.starlark.stdlib`:
  `@stdlib//json` (`JsonModule`) wraps the interpreter's `json` module (object keys sorted, as
  there) and adds `dumps`/`loads`; `jhashlib` (`HashlibModule`, the JDK's `MessageDigest` and
  `Mac`) replaces the `Crypto.Hash` modules `hashlib.star` loaded; `jrandom` (`RandomModule`,
  `SecureRandom`) replaces `jcrypto`'s `Random`.
- Unused classes were left out (`SimpleStructWithMethods`, `ReadWriteDataBuffer`, `ScopedProperty`,
  `FnvHash`, `NumOpsUtils`, `LarkyParserInputUtils`).
