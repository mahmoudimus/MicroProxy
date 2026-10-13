/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.huffman;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSource;

public final class HuffmanDecoder {
  private final HuffmanTable table;

  public HuffmanDecoder(CodeBook book) throws BrotliException {
    table = HuffmanTable.fromCodeBook(book);
  }

  public int decode(BitSource input) throws BrotliException {
    return table.decode(input);
  }
}
