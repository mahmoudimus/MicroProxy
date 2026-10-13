/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

/** Optional FFM backend is linked only when the ffm profile is built. */
public final class Histories {
  private Histories() {}

  public static History create(int windowBits, boolean offHeap) {
    if (!offHeap) return new RingHistory(windowBits);
    try {
      return (History)
          Class.forName("org.microproxy.thirdparty.jaybrotli.internal.history.SegmentHistory")
              .getConstructor(int.class)
              .newInstance(windowBits);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          "Off-heap history requires a build with -Pffm on JDK 22 or newer", e);
    }
  }
}
