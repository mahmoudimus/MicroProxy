/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

import java.util.Arrays;

/** Adjacent normalized L1 histogram merging; an alternative to entropy cost. */
public final class HistogramSplitter implements BlockSplitStrategy {
  public int[] split(int[][] input, int[] lengths, int chunks, int alphabet, int maxTypes) {
    if (maxTypes < 1) throw new IllegalArgumentException("max types");
    int[][] h = new int[chunks][];
    int[] lens = new int[chunks];
    int count = 0;
    for (int i = 0; i < chunks; i++)
      if (lengths[i] > 0) {
        h[count] = Arrays.copyOf(input[i], alphabet);
        lens[count++] = lengths[i];
      }
    if (count == 0) return new int[] {1};
    while (count > maxTypes) {
      int selected = 0;
      double best = Double.POSITIVE_INFINITY;
      for (int i = 0; i < count - 1; i++) {
        double distance = 0;
        for (int s = 0; s < alphabet; s++)
          distance += Math.abs((double) h[i][s] / lens[i] - (double) h[i + 1][s] / lens[i + 1]);
        if (distance < best) {
          best = distance;
          selected = i;
        }
      }
      for (int s = 0; s < alphabet; s++) h[selected][s] += h[selected + 1][s];
      lens[selected] += lens[selected + 1];
      System.arraycopy(h, selected + 2, h, selected + 1, count - selected - 2);
      System.arraycopy(lens, selected + 2, lens, selected + 1, count - selected - 2);
      count--;
    }
    return Arrays.copyOf(lens, count);
  }
}
