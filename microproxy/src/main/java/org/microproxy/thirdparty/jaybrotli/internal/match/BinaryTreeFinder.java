/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.match;

import org.microproxy.thirdparty.jaybrotli.spi.Match;
import java.util.*;

/** Ordered prefix tree with binary-search predecessor lookup and bounded candidate comparison. */
public final class BinaryTreeFinder extends IndexedFinder {
  private final NavigableMap<Long, ArrayList<Integer>> positions = new TreeMap<>();

  public String name() {
    return "binary-tree";
  }

  protected void build() {
    positions.clear();
    for (int p = 0; p + 4 <= bytes.length; p++)
      positions.computeIfAbsent(key(p, 4), k -> new ArrayList<>()).add(p);
  }

  public Match find(int pos) {
    if (pos < 0 || pos > length) throw new IndexOutOfBoundsException(pos);
    if (pos + 4 > length) return null;
    int absolute = history + pos, best = 3, distance = 0;
    var list = positions.get(key(absolute, 4));
    int at = Collections.binarySearch(list, absolute);
    for (int i = at - 1, n = 0; i >= 0 && n < 64; i--, n++) {
      int candidate = list.get(i), d = absolute - candidate;
      if (d > window) break;
      int len = length(pos, candidate);
      if (len > best) {
        best = len;
        distance = d;
      }
    }
    return distance == 0 ? null : new Match(distance, best);
  }
}
