package org.microproxy.thirdparty.larky.modules.types.results;

import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;

@StarlarkBuiltin(name="AttributeError")
public final class LarkyAttributeError extends Error implements StarlarkValue {

  private LarkyAttributeError(EvalException exc) {
    super(exc);
  }

  private static final EvalException ATTRIBUTE_ERROR = new EvalException("AttributeError");

  public static final LarkyAttributeError INSTANCE = new LarkyAttributeError(ATTRIBUTE_ERROR);

  public static LarkyAttributeError getInstance() {
    return INSTANCE;
  }

  @Override
  public boolean isImmutable() {
    return true;
  }

  @Override
  public Object getValue() {
    return this;
  }

  @Override
  public Error getError() {
    return this;
  }

  @Override
  public boolean isOk() {
    return false;
  }

  @Override
  public boolean isError() {
    return true;
  }

}
