/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

/** Original bounded Shannon-cost merge strategy; mutates its scratch histograms. */
public final class EntropySplitter implements BlockSplitStrategy {
  public int[] split(int[][] h, int[] lengths, int chunks, int alphabet, int maxTypes) {
    return BlockSplitter.mergeChunks(h, lengths, chunks, alphabet, maxTypes);
  }
}
