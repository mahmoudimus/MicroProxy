/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.huffman;

import org.microproxy.thirdparty.jaybrotli.BrotliException;

public final class HuffmanBuilder {
  private final org.microproxy.thirdparty.jaybrotli.spi.LengthLimiter limiter;

  public HuffmanBuilder() {
    this(null);
  }

  public HuffmanBuilder(org.microproxy.thirdparty.jaybrotli.spi.LengthLimiter limiter) {
    this.limiter = limiter;
  }

  public CodeBook build(int[] histogram, int maxBits) throws BrotliException {
    if (maxBits < 1 || maxBits > 15) throw new IllegalArgumentException("maxBits");
    int[] lengths = new int[histogram.length];
    HuffmanEncoder.assignLengths(histogram, lengths, maxBits);
    if (limiter != null) {
      byte[] result = limiter.limit(lengths.clone(), maxBits);
      if (result.length != lengths.length) throw new IllegalArgumentException("limiter alphabet");
      for (int i = 0; i < lengths.length; i++) lengths[i] = result[i] & 255;
    }
    int used = 0, only = 0;
    for (int i = 0; i < histogram.length; i++)
      if (histogram[i] > 0) {
        used++;
        only = i;
      }
    if (used == 1) return CodeBook.singleSymbol(only, histogram.length);
    for (int length : lengths)
      if (length > maxBits) throw new IllegalArgumentException("limiter exceeds maxBits");
    HuffmanTable.fromLengths(lengths);
    return CodeBook.fromLengths(lengths);
  }
}
