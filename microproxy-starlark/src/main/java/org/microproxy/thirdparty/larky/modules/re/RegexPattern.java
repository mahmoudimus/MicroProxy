package org.microproxy.thirdparty.larky.modules.re;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.ParamType;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.NoneType;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;
import org.microproxy.thirdparty.starlark.eval.Tuple;

/**
 * A compiled Python {@code re} pattern: the {@code py_*} primitives that {@code re.star} builds
 * Python's {@code re} API on (the same primitives as starlarky's RE2-backed pattern, here on
 * {@link java.util.regex}).
 */
@StarlarkBuiltin(name = "Pattern", doc = "A compiled Python regular expression.")
public final class RegexPattern implements StarlarkValue {

  /** Matching without a thread deadline gives up after this long. */
  private static final long DEFAULT_BUDGET_MILLIS = 2_000;

  private static final int CACHE_LIMIT = 512;

  private record PyKey(String regex, int flags) {}

  // Translated patterns by source and flags: re.match(pattern_string, ...) and the other
  // module-level functions compile their pattern on every call. Patterns come from scripts.
  private static final Map<PyKey, RegexPattern> PY_COMPILED = new ConcurrentHashMap<>();

  private final PyRegex py;

  private RegexPattern(PyRegex py) {
    this.py = py;
  }

  /** Compiles (or finds cached) {@code regex} with re.star's {@code flags}. */
  public static RegexPattern compile(String regex, int flags) throws EvalException {
    PyKey key = new PyKey(regex, flags);
    RegexPattern compiled = PY_COMPILED.get(key);
    if (compiled == null) {
      compiled = new RegexPattern(new PyRegex(regex, flags));
      if (PY_COMPILED.size() >= CACHE_LIMIT) {
        PY_COMPILED.clear();
      }
      PY_COMPILED.put(key, compiled);
    }
    return compiled;
  }

  @Override
  public void repr(Printer printer, StarlarkSemantics semantics) {
    printer.append("<Pattern ").repr(py.source, semantics).append(">");
  }

  @Override
  public void str(Printer printer, StarlarkSemantics semantics) {
    printer.append(py.source);
  }

  @Override
  public boolean isImmutable() {
    return true;
  }

  @StarlarkMethod(name = "pattern", doc = "The pattern's (Python) source.")
  public String pattern() {
    return py.source;
  }

  @StarlarkMethod(name = "java_pattern", doc = "The java.util.regex pattern it was translated to.")
  public String javaPattern() throws EvalException {
    return py.javaSource();
  }

  @StarlarkMethod(name = "py_groups", doc = "Number of capturing groups.", structField = true)
  public StarlarkInt pyGroups() {
    return StarlarkInt.of(py.groups());
  }

  @StarlarkMethod(
      name = "py_groupindex",
      doc = "A new dict mapping group names to group numbers.",
      useStarlarkThread = true)
  public Dict<String, StarlarkInt> pyGroupIndexDict(StarlarkThread thread) throws EvalException {
    Dict<String, StarlarkInt> d = Dict.of(thread.mutability());
    for (Map.Entry<String, Integer> e : py.groupIndex().entrySet()) {
      d.putEntry(e.getKey(), StarlarkInt.of(e.getValue()));
    }
    return d;
  }

  @StarlarkMethod(
      name = "py_group_index",
      doc = "The group number for a group number or name; fails with IndexError if there is none.",
      parameters = {@Param(name = "group")})
  public StarlarkInt pyGroupIndex(Object group) throws EvalException {
    if (group instanceof StarlarkInt g) {
      int idx = g.signum() < 0 ? -1 : g.toInt("group");
      if (idx >= 0 && idx <= py.groups()) {
        return StarlarkInt.of(idx);
      }
    } else if (group instanceof String) {
      Integer idx = py.groupIndex().get(group);
      if (idx != null) {
        return StarlarkInt.of(idx);
      }
    }
    throw new EvalException("IndexError: no such group");
  }

  /** str input as is; bytes as Latin-1 text (one char per byte). */
  private static String pyInput(Object input) {
    if (input instanceof StarlarkBytes b) {
      return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
    }
    return (String) input;
  }

  private static long deadline(StarlarkThread thread) {
    long deadline = thread.getExpirationMs();
    return deadline == Long.MAX_VALUE ? System.currentTimeMillis() + DEFAULT_BUDGET_MILLIS : deadline;
  }

  private Object pyRun(Object input, StarlarkInt pos, Object endpos, int kind, boolean mustAdvance,
      StarlarkThread thread) throws EvalException {
    CharSequence text = pyInput(input);
    int len = text.length();
    // As CPython's state_init: clamp pos and endpos to [0, len].
    int start = Math.max(0, Math.min(pos.toInt("pos"), len));
    int end = len;
    if (endpos != Starlark.NONE) {
      end = Math.max(0, Math.min(((StarlarkInt) endpos).toInt("endpos"), len));
    }
    if (end < start) {
      return Starlark.NONE;
    }
    if (end < len) {
      text = text.subSequence(0, end);
    }
    int[] spans = py.run(text, start, kind, mustAdvance, input instanceof StarlarkBytes,
        deadline(thread));
    if (spans == null) {
      return Starlark.NONE;
    }
    return intTuple(spans);
  }

  private static Tuple intTuple(int[] values) {
    Object[] out = new Object[values.length];
    for (int i = 0; i < values.length; i++) {
      out[i] = StarlarkInt.of(values[i]);
    }
    return Tuple.of(out);
  }

  @StarlarkMethod(
      name = "py_search",
      doc = "Python's Pattern.search: None, or the flat tuple of group spans (-1 when unmatched)."
          + " must_advance rejects an empty match at pos (for iterating after an empty match).",
      parameters = {
          @Param(name = "string", allowedTypes = {
              @ParamType(type = String.class), @ParamType(type = StarlarkBytes.class)}),
          @Param(name = "pos", allowedTypes = {@ParamType(type = StarlarkInt.class)},
              defaultValue = "0"),
          @Param(name = "endpos", allowedTypes = {
              @ParamType(type = StarlarkInt.class), @ParamType(type = NoneType.class)},
              defaultValue = "None"),
          @Param(name = "must_advance", allowedTypes = {@ParamType(type = Boolean.class)},
              defaultValue = "False")
      },
      useStarlarkThread = true)
  public Object pySearch(Object string, StarlarkInt pos, Object endpos, Boolean mustAdvance,
      StarlarkThread thread) throws EvalException {
    return pyRun(string, pos, endpos, PyRegex.SEARCH, mustAdvance, thread);
  }

  @StarlarkMethod(
      name = "py_match",
      doc = "Python's Pattern.match (anchored at pos); returns spans as py_search.",
      parameters = {
          @Param(name = "string", allowedTypes = {
              @ParamType(type = String.class), @ParamType(type = StarlarkBytes.class)}),
          @Param(name = "pos", allowedTypes = {@ParamType(type = StarlarkInt.class)},
              defaultValue = "0"),
          @Param(name = "endpos", allowedTypes = {
              @ParamType(type = StarlarkInt.class), @ParamType(type = NoneType.class)},
              defaultValue = "None")
      },
      useStarlarkThread = true)
  public Object pyMatch(Object string, StarlarkInt pos, Object endpos, StarlarkThread thread)
      throws EvalException {
    return pyRun(string, pos, endpos, PyRegex.MATCH, false, thread);
  }

  @StarlarkMethod(
      name = "py_fullmatch",
      doc = "Python's Pattern.fullmatch; returns spans as py_search.",
      parameters = {
          @Param(name = "string", allowedTypes = {
              @ParamType(type = String.class), @ParamType(type = StarlarkBytes.class)}),
          @Param(name = "pos", allowedTypes = {@ParamType(type = StarlarkInt.class)},
              defaultValue = "0"),
          @Param(name = "endpos", allowedTypes = {
              @ParamType(type = StarlarkInt.class), @ParamType(type = NoneType.class)},
              defaultValue = "None")
      },
      useStarlarkThread = true)
  public Object pyFullmatch(Object string, StarlarkInt pos, Object endpos, StarlarkThread thread)
      throws EvalException {
    return pyRun(string, pos, endpos, PyRegex.FULLMATCH, false, thread);
  }

  @StarlarkMethod(
      name = "py_split",
      doc = "Python's Pattern.split, as a flat tuple of (start, end) spans of the pieces and"
          + " groups; (-1, -1) for a group that did not participate.",
      parameters = {
          @Param(name = "string", allowedTypes = {
              @ParamType(type = String.class), @ParamType(type = StarlarkBytes.class)}),
          @Param(name = "maxsplit", allowedTypes = {@ParamType(type = StarlarkInt.class)},
              defaultValue = "0")
      },
      useStarlarkThread = true)
  public Tuple pySplit(Object string, StarlarkInt maxsplit, StarlarkThread thread)
      throws EvalException {
    return intTuple(py.split(pyInput(string), maxsplit.toInt("maxsplit"),
        string instanceof StarlarkBytes, deadline(thread)));
  }

  @StarlarkMethod(
      name = "py_template",
      doc = "Parses a replacement template (as for re.sub) into a tuple of str literals and"
          + " group numbers. A bytes template is read as Latin-1.",
      parameters = {
          @Param(name = "repl", allowedTypes = {
              @ParamType(type = String.class), @ParamType(type = StarlarkBytes.class)})
      })
  public Tuple pyTemplate(Object repl) throws EvalException {
    List<Object> items = py.parseTemplate(pyInput(repl));
    Object[] out = new Object[items.size()];
    for (int i = 0; i < out.length; i++) {
      Object item = items.get(i);
      out[i] = item instanceof Integer ? StarlarkInt.of((Integer) item) : item;
    }
    return Tuple.of(out);
  }

  @StarlarkMethod(
      name = "py_text",
      doc = "The text matches are taken from: the string itself, or bytes read as Latin-1 (as"
          + " in starlarky, matches on bytes are str).",
      parameters = {
          @Param(name = "string", allowedTypes = {
              @ParamType(type = String.class), @ParamType(type = StarlarkBytes.class)})
      })
  public String pyText(Object string) {
    return pyInput(string);
  }
}
