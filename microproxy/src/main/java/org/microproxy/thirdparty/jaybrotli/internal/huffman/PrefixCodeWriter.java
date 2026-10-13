/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.huffman;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSink;

public final class PrefixCodeWriter {
  public void write(BitSink output, CodeBook book) throws BrotliException {
    byte[] b = book.lengths();
    int[] lengths = new int[b.length];
    for (int i = 0; i < b.length; i++) lengths[i] = b[i] & 255;
    if (book.singleSymbol() >= 0) {
      PrefixCode.writeSimple(output, new int[] {book.singleSymbol()}, lengths.length);
      return;
    } else if (!java.util.Arrays.equals(book.codes(), CodeBook.fromLengths(lengths).codes()))
      throw new IllegalArgumentException("Brotli prefix serialization requires canonical codes");
    HuffmanEncoder.writePrefixCodeFromLengths(output, lengths);
  }
}
