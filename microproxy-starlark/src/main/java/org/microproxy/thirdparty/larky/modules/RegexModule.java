package org.microproxy.thirdparty.larky.modules;

import org.microproxy.thirdparty.larky.modules.re.RegexPattern;

import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.ParamType;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;

/**
 * The native half of {@code re.star}: Python patterns translated to {@link java.util.regex}.
 * (starlarky's {@code re2j} module, on Java's backtracking engine; matching is bounded by the
 * calling thread's deadline.)
 */
@StarlarkBuiltin(
    name = "jregex",
    category = "BUILTIN",
    doc = "Python regular expressions on java.util.regex (used by @stdlib//re).")
public class RegexModule implements StarlarkValue {

  public static final RegexModule INSTANCE = new RegexModule();

  /** The {@code Pattern} namespace: {@code Pattern.py_compile(regex, flags)}. */
  @StarlarkBuiltin(name = "PatternFactory", doc = "Compiles patterns.")
  public static final class PatternFactory implements StarlarkValue {
    @StarlarkMethod(
        name = "py_compile",
        doc = "Compiles a Python re pattern. flags are re.star's RegexFlags.",
        parameters = {
            @Param(name = "regex", allowedTypes = {@ParamType(type = String.class)}),
            @Param(name = "flags", allowedTypes = {@ParamType(type = StarlarkInt.class)},
                defaultValue = "0")
        })
    public RegexPattern pyCompile(String regex, StarlarkInt flags) throws EvalException {
      return RegexPattern.compile(regex, flags.toInt("flags"));
    }
  }

  private static final PatternFactory PATTERN = new PatternFactory();

  @StarlarkMethod(name = "Pattern", doc = "pattern", structField = true)
  public PatternFactory pattern() {
    return PATTERN;
  }
}
