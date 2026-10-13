/*
 * DistanceRing.java
 *
 * SPDX-License-Identifier: Apache-2.0
 * Modified for jaybrotli: namespace and licensing.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.microproxy.thirdparty.jaybrotli.internal.history;

/**
 * Four-slot ring of recent distances (RFC 7932 §4).
 *
 * <p>Initialized to {@code [16, 15, 11, 4]} at stream start. Distance symbol 0 and
 * static-dictionary references do not push.
 */
public final class DistanceRing {

  /**
   * ring[0] is most recent (last distance). Equivalent to Google's {@code [16,15,11,4]} with index
   * pointing at the last slot.
   */
  private final int[] ring = new int[] {4, 11, 15, 16};

  public DistanceCache snapshot() {
    return new DistanceCache(ring[0], ring[1], ring[2], ring[3]);
  }

  public void restore(DistanceCache cache) {
    ring[0] = cache.last();
    ring[1] = cache.last2();
    ring[2] = cache.last3();
    ring[3] = cache.last4();
  }

  public void reset() {
    ring[0] = 4;
    ring[1] = 11;
    ring[2] = 15;
    ring[3] = 16;
  }

  public int get(int index) {
    return ring[index];
  }

  public void push(int distance) {
    ring[3] = ring[2];
    ring[2] = ring[1];
    ring[1] = ring[0];
    ring[0] = distance;
  }

  /**
   * Resolves a short distance code 0..15 to an actual distance, applying ±1..±3 adjustments for
   * codes 4..15 (RFC §4). Does not push.
   *
   * @return distance, or -1 if invalid
   */
  public int resolveShort(int dcode) {
    if (dcode < 0 || dcode > 15) {
      return -1;
    }
    int base;
    int delta;
    switch (dcode) {
      case 0:
        return ring[0];
      case 1:
        return ring[1];
      case 2:
        return ring[2];
      case 3:
        return ring[3];
      case 4:
        base = ring[0];
        delta = -1;
        break;
      case 5:
        base = ring[0];
        delta = 1;
        break;
      case 6:
        base = ring[0];
        delta = -2;
        break;
      case 7:
        base = ring[0];
        delta = 2;
        break;
      case 8:
        base = ring[0];
        delta = -3;
        break;
      case 9:
        base = ring[0];
        delta = 3;
        break;
      case 10:
        base = ring[1];
        delta = -1;
        break;
      case 11:
        base = ring[1];
        delta = 1;
        break;
      case 12:
        base = ring[1];
        delta = -2;
        break;
      case 13:
        base = ring[1];
        delta = 2;
        break;
      case 14:
        base = ring[1];
        delta = -3;
        break;
      case 15:
        base = ring[1];
        delta = 3;
        break;
      default:
        return -1;
    }
    int d = base + delta;
    if (d < 1) {
      return -1;
    }
    return d;
  }
}
