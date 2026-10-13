/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.match;

import org.microproxy.thirdparty.jaybrotli.spi.Match;
import java.util.*;

/** Suffix array ordered by at most 256 prefix bytes; bounded neighbor search. */
public final class SuffixFinder extends IndexedFinder {
  private Integer[] suffixes;
  private int[] ranks;

  public String name() {
    return "suffix";
  }

  protected void build() {
    suffixes = new Integer[bytes.length];
    for (int i = 0; i < bytes.length; i++) suffixes[i] = i;
    Arrays.sort(
        suffixes,
        (a, b) -> {
          int limit = Math.min(256, bytes.length - Math.max(a, b));
          for (int i = 0; i < limit; i++) {
            int d = (bytes[a + i] & 255) - (bytes[b + i] & 255);
            if (d != 0) return d;
          }
          return Integer.compare(a, b);
        });
    ranks = new int[bytes.length];
    for (int i = 0; i < suffixes.length; i++) ranks[suffixes[i]] = i;
  }

  public Match find(int pos) {
    if (pos < 0 || pos > length) throw new IndexOutOfBoundsException(pos);
    if (pos + 4 > length) return null;
    int absolute = history + pos, best = 3, distance = 0, rank = ranks[absolute];
    for (int step = 1; step <= 64; step++)
      for (int direction = -1; direction <= 1; direction += 2) {
        int at = rank + direction * step;
        if (at < 0 || at >= suffixes.length) continue;
        int p = suffixes[at], d = absolute - p;
        if (d < 1 || d > window) continue;
        int len = length(pos, p);
        if (len > best || (len == best && d < distance)) {
          best = len;
          distance = d;
        }
      }
    return distance == 0 ? null : new Match(distance, best);
  }
}
