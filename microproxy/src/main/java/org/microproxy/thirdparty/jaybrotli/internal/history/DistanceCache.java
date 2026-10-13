/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

public record DistanceCache(int last, int last2, int last3, int last4) {
  public static DistanceCache initial() {
    return new DistanceCache(4, 11, 15, 16);
  }

  public DistanceCache push(int distance) {
    if (distance < 1) throw new IllegalArgumentException("distance");
    return new DistanceCache(distance, last, last2, last3);
  }
}
