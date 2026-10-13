/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.match;

import java.util.Arrays;
import java.util.Locale;

/** Internal, experimental match comparison backends. Selected once per JVM. */
public final class ByteComparisons {
  public interface Ops {
    /** Number of equal leading bytes in two valid ranges of {@code length} bytes. */
    int commonPrefix(byte[] a, int aOffset, byte[] b, int bOffset, int length);

    String description();
  }

  private static final Ops SCALAR =
      new Ops() {
        public int commonPrefix(byte[] a, int ao, byte[] b, int bo, int length) {
          int i = 0;
          while (i < length && a[ao + i] == b[bo + i]) i++;
          return i;
        }

        public String description() {
          return "scalar";
        }
      };
  private static final Ops ARRAYS =
      new Ops() {
        public int commonPrefix(byte[] a, int ao, byte[] b, int bo, int length) {
          int mismatch = Arrays.mismatch(a, ao, ao + length, b, bo, bo + length);
          return mismatch < 0 ? length : mismatch;
        }

        public String description() {
          return "arrays";
        }
      };
  private static final Ops SELECTED = choose();

  private ByteComparisons() {}

  public static Ops selected() {
    return SELECTED;
  }

  public static Ops scalar() {
    return SCALAR;
  }

  public static Ops arrays() {
    return ARRAYS;
  }

  public static Ops vector() {
    if (ModuleLayer.boot().findModule("jdk.incubator.vector").isEmpty()) return null;
    try {
      return (Ops)
          Class.forName("org.microproxy.thirdparty.jaybrotli.internal.match.VectorComparisons")
              .getDeclaredConstructor()
              .newInstance();
    } catch (ReflectiveOperationException | LinkageError e) {
      System.getLogger(ByteComparisons.class.getName())
          .log(
              System.Logger.Level.WARNING,
              "Vector comparison backend unavailable; using scalar comparisons",
              e);
      return null;
    }
  }

  private static Ops choose() {
    String property = System.getProperty("jaybrotli.simd");
    if (property == null) {
      // MicroProxy: without jaybrotli.simd, follow MicroProxy's own choice (the microproxy.simd
      // property and whether the JVM has the Vector API module; see org.microproxy.simd.Simd).
      Ops vector = org.microproxy.simd.Simd.isVectorized() ? vector() : null;
      return vector != null ? vector : SCALAR;
    }
    String setting = property.strip().toLowerCase(Locale.ROOT);
    switch (setting) {
      case "false":
        return SCALAR;
      case "arrays":
        return ARRAYS;
      case "true":
        Ops vector = vector();
        if (vector != null) return vector;
        System.getLogger(ByteComparisons.class.getName())
            .log(
                System.Logger.Level.WARNING,
                "jaybrotli.simd=true requires --add-modules jdk.incubator.vector; using scalar"
                    + " comparisons");
        return SCALAR;
      default:
        throw new IllegalArgumentException("jaybrotli.simd must be false, arrays, or true");
    }
  }

  public static int matchLength(
      byte[] block,
      int pos,
      int blockLen,
      byte[] history,
      int histStart,
      int histUse,
      int candAbs,
      int maxMatch) {
    if (SELECTED == SCALAR) {
      return scalarMatchLength(block, pos, blockLen, history, histStart, histUse, candAbs, maxMatch);
    }
    return matchLength(
        SELECTED, block, pos, blockLen, history, histStart, histUse, candAbs, maxMatch);
  }

  public static int matchLength(
      Ops ops,
      byte[] block,
      int pos,
      int blockLen,
      byte[] history,
      int histStart,
      int histUse,
      int candAbs,
      int maxMatch) {
    int limit = Math.min(blockLen - pos, maxMatch);
    int matched = 0;
    if (candAbs < histUse) {
      int historyLength = Math.min(limit, histUse - candAbs);
      matched = ops.commonPrefix(block, pos, history, histStart + candAbs, historyLength);
      if (matched < historyLength || matched == limit) return matched;
    }
    int blockOffset = candAbs + matched - histUse;
    int remaining = Math.min(limit - matched, blockLen - blockOffset);
    if (remaining <= 0) return matched;
    return matched + ops.commonPrefix(block, pos + matched, block, blockOffset, remaining);
  }

  /** Scalar split comparison without {@link Ops} dispatch; mirrors the generic two-segment logic. */
  private static int scalarMatchLength(
      byte[] block,
      int pos,
      int blockLen,
      byte[] history,
      int histStart,
      int histUse,
      int candAbs,
      int maxMatch) {
    int limit = Math.min(blockLen - pos, maxMatch);
    int matched = 0;
    if (candAbs < histUse) {
      int historyLength = Math.min(limit, histUse - candAbs);
      matched = wordPrefix(block, pos, history, histStart + candAbs, historyLength);
      if (matched < historyLength || matched == limit) return matched;
    }
    int blockOffset = candAbs + matched - histUse;
    int remaining = Math.min(limit - matched, blockLen - blockOffset);
    if (remaining <= 0) return matched;
    return matched + wordPrefix(block, pos + matched, block, blockOffset, remaining);
  }

  private static final java.lang.invoke.VarHandle LONGS =
      java.lang.invoke.MethodHandles.byteArrayViewVarHandle(
          long[].class, java.nio.ByteOrder.LITTLE_ENDIAN);

  /**
   * Common prefix length, eight bytes at a time (plain scalar code, no vector API): the first
   * differing byte is the lowest set byte of the XOR of two little-endian words.
   */
  private static int wordPrefix(byte[] a, int ao, byte[] b, int bo, int length) {
    int i = 0;
    for (; i + 8 <= length; i += 8) {
      long diff = (long) LONGS.get(a, ao + i) ^ (long) LONGS.get(b, bo + i);
      if (diff != 0) {
        return i + (Long.numberOfTrailingZeros(diff) >>> 3);
      }
    }
    while (i < length && a[ao + i] == b[bo + i]) {
      i++;
    }
    return i;
  }
}
