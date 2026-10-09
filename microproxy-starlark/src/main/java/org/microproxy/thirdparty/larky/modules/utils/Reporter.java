package org.microproxy.thirdparty.larky.modules.utils;

import java.lang.System.Logger.Level;
import java.util.List;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;

/**
 * Reports assertion failures with the Starlark call stack. Upstream wrote to a Larky console;
 * this copy logs through {@link System.Logger} ({@code org.microproxy.starlark.stdlib}).
 */
public class Reporter {

  private static final System.Logger LOG = System.getLogger("org.microproxy.starlark.stdlib");

  /** The reporter for {@code thread}, or a logging one when the thread has none. */
  public static Reporter of(StarlarkThread thread) {
    Reporter r = thread.getThreadLocal(Reporter.class);
    return r != null ? r : new Reporter();
  }

  public void report(StarlarkThread thread, String msg) {
    LOG.log(Level.INFO, "{0}: {1}", thread.getCallerLocation(), msg);
  }

  /**
   * Should be called by an assertion method when the test encounters an unexpected evaluation. It
   * does not stop the program; multiple failures may be reported in a single run.
   */
  public void reportError(StarlarkThread thread, String message) {
    StringBuilder sb = new StringBuilder("Traceback (most recent call last):\n");
    List<StarlarkThread.CallStackEntry> stack = thread.getCallStack();
    stack = stack.subList(0, Math.max(0, stack.size() - 1)); // pop the built-in function
    for (StarlarkThread.CallStackEntry fr : stack) {
      sb.append(String.format("%s: called from %s%n", fr.location, fr.name));
    }
    sb.append("Error: ").append(message);
    LOG.log(Level.DEBUG, sb.toString());
  }
}
