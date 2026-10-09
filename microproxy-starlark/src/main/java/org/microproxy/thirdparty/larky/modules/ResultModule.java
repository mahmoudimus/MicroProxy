package org.microproxy.thirdparty.larky.modules;

import org.microproxy.thirdparty.larky.modules.types.results.Error;
import org.microproxy.thirdparty.larky.modules.types.results.Result;

import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkCallable;
import org.microproxy.thirdparty.starlark.eval.StarlarkEvalWrapper;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;
import org.microproxy.thirdparty.starlark.eval.Tuple;


@StarlarkBuiltin(
    name = "jresult",
    category = "BUILTIN",
    doc =
      "Given that Starlark does not support exceptions, there needs to be a way to map python" +
      "exception handling and control flow to Starlark. One of the more popular ways to " +
      "do this is to take inspiration from some of the functional programming constructs." +
      "" +
      "Taking a page out of Railway Oriented Programming and the Result type of the Rust" +
      " programming language, we can emulate a Result type that will contain utilities " +
      "that enable functional style programming in Java (which maps well to Starlark) with" +
      " under-the-hood error handling without having to define try-catch-blocks or" +
      " conditionals."
)
public class ResultModule implements StarlarkValue {

  public static final ResultModule INSTANCE = new ResultModule();

  @StarlarkMethod(name = "Error", parameters = {@Param(name = "error")}, useStarlarkThread = true)
  public static Result error(Object error, StarlarkThread thread) {
    // TODO: capture stack frame
    return Result.error(error, thread);
  }

  @StarlarkMethod(name = "Ok", parameters = {@Param(name = "value")})
  public static Result ok(Object value) {
    return Result.ok(value);
  }

  @StarlarkMethod(name = "of", parameters = {@Param(name = "o")}, useStarlarkThread = true)
  public static Result of(Object o, StarlarkThread thread) {
    return Result.of(o, thread);
  }

  @StarlarkMethod(name = "safe",
    parameters = {@Param(name = "func")},
    extraPositionals = @Param(name = "args"),
    extraKeywords = @Param(name = "kwargs", defaultValue = "{}"),
    useStarlarkThread = true
  )
  public static Result safe(StarlarkCallable func, Tuple args, Dict<String, Object> kwargs, StarlarkThread thread)
      throws InterruptedException {
    int stackSize = StarlarkEvalWrapper.callStackSize(thread);
    try {
      return ok(Starlark.call(thread, func, args, kwargs));
    } catch(Error e) {
      StarlarkEvalWrapper.unwindCallStack(thread, stackSize);
      return e;
    } catch (EvalException e) {
      StarlarkEvalWrapper.unwindCallStack(thread, stackSize);
      return Error.of(e); // for the stack trace.
    } catch (RuntimeException e) {
      StarlarkEvalWrapper.unwindCallStack(thread, stackSize);
      return error(new EvalException(e.getMessage(), e.getCause()), thread);
    }
    // InterruptedException propagates: an interrupted evaluation must stop.
  }


}
