/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

/** Consumes chunk histograms; returns positive run lengths whose sum is preserved. */
public interface BlockSplitStrategy {
  int[] split(int[][] histograms, int[] lengths, int chunks, int alphabet, int maxTypes);
}
