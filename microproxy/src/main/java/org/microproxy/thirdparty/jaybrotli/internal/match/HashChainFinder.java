/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.match;

import org.microproxy.thirdparty.jaybrotli.spi.Match;
import java.util.Arrays;

public final class HashChainFinder extends IndexedFinder {
  private int[] previous;

  public String name() {
    return "hash-chain";
  }

  private int hash(int p) {
    return (int) ((key(p, 4) * 0x1e35a7bd) >>> 17) & 32767;
  }

  protected void build() {
    int[] heads = new int[32768];
    Arrays.fill(heads, -1);
    previous = new int[bytes.length];
    Arrays.fill(previous, -1);
    for (int p = 0; p + 4 <= bytes.length; p++) {
      int h = hash(p);
      previous[p] = heads[h];
      heads[h] = p;
    }
  }

  public Match find(int pos) {
    if (pos < 0 || pos > length) throw new IndexOutOfBoundsException(pos);
    if (pos + 4 > length) return null;
    int absolute = history + pos, best = 3, distance = 0;
    for (int p = previous[absolute], n = 0; p >= 0 && n < 64; p = previous[p], n++) {
      int d = absolute - p;
      if (d > window) break;
      int len = length(pos, p);
      if (len > best) {
        best = len;
        distance = d;
      }
    }
    return distance == 0 ? null : new Match(distance, best);
  }
}
