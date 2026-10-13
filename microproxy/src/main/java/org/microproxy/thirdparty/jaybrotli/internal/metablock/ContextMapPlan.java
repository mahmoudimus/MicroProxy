/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.CodeBook;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.HuffmanEncoder;
import org.microproxy.thirdparty.jaybrotli.internal.ir.ContextMap;

/** Context-map coding decisions with fixed RLEMAX=0 and IMTF=0. */
public record ContextMapPlan(ContextMap contexts, int treeCount, CodeBook codeBook) {
  public ContextMapPlan {
    java.util.Objects.requireNonNull(contexts);
    if (treeCount < 1 || treeCount > 256) throw new IllegalArgumentException("Tree count");
    if (treeCount > 1) java.util.Objects.requireNonNull(codeBook);
  }

  public static ContextMapPlan create(int[] map, int trees) throws BrotliException {
    if (trees < 1 || trees > 256) throw new IllegalArgumentException("Tree count");
    var owned = new ContextMap(map);
    int[] histogram = new int[trees];
    for (int tree : owned.trees()) {
      if (tree < 0 || tree >= trees)
        throw new BrotliException("Context map tree index out of range");
      histogram[tree]++;
    }
    if (trees == 1) return new ContextMapPlan(owned, trees, null);
    int used = 0, sole = 0;
    for (int i = 0; i < trees; i++)
      if (histogram[i] > 0) {
        used++;
        sole = i;
      }
    CodeBook book;
    if (used <= 1) book = CodeBook.singleSymbol(sole, trees);
    else {
      int[] lengths = new int[trees];
      HuffmanEncoder.assignLengths(histogram, lengths, 15);
      book = CodeBook.fromLengths(lengths);
    }
    return new ContextMapPlan(owned, trees, book);
  }
}
