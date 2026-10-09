package org.microproxy.thirdparty.larky.modules.utils;

/**
 * Rethrows a checked exception without declaring it, as Lombok's {@code @SneakyThrows} (which the
 * upstream sources used) does.
 */
public final class Sneaky {

  private Sneaky() {}

  public static RuntimeException sneakyThrow(Throwable t) {
    throw Sneaky.<RuntimeException>doThrow(t);
  }

  @SuppressWarnings("unchecked")
  private static <T extends Throwable> T doThrow(Throwable t) throws T {
    throw (T) t;
  }
}
