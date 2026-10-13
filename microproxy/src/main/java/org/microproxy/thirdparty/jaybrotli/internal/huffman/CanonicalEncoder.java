/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.huffman;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSink;
import org.microproxy.thirdparty.jaybrotli.internal.bits.LsbBitOrder;

public final class CanonicalEncoder {
  private final int[] codes;
  private final byte[] lengths;
  private final int single;

  public CanonicalEncoder(CodeBook book) {
    codes = book.codesRaw();
    lengths = book.lengthsRaw();
    single = book.singleSymbol();
  }

  public static void writeCode(BitSink out, int code, int length) throws BrotliException {
    if (length > 0) out.writeBits(LsbBitOrder.INSTANCE.reverse(code, length), length);
  }

  public void encode(int symbol, BitSink out) throws BrotliException {
    if (symbol < 0
        || symbol >= codes.length
        || (single >= 0 ? symbol != single : lengths[symbol] == 0))
      throw new IllegalArgumentException("Unused symbol");
    if (single < 0)
      out.writeBits(LsbBitOrder.INSTANCE.reverse(codes[symbol], lengths[symbol]), lengths[symbol]);
  }
}
