/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

public interface DictionaryIndex {
  int tryFind(
      byte[] data,
      int offset,
      int available,
      boolean transforms,
      int[] wire,
      int[] covered,
      int[] transform,
      int[] index);

  default Match find(byte[] data, int offset, int available, int maxDistance) {
    int[] w = {0}, c = {0}, t = {0}, i = {0};
    int n = tryFind(data, offset, available, true, w, c, t, i);
    return n == 0
        ? null
        : new Match(maxDistance + 1 + i[0] + (t[0] << Dictionary.ndbits(w[0])), w[0], c[0]);
  }

  record Match(int distance, int wordLength, int length) {}
}
