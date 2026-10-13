/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.huffman;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSource;

public final class PrefixCodeReader {
  public CodeBook read(BitSource input, int alphabetSize) throws BrotliException {
    var table = PrefixCode.tryRead(input, alphabetSize);
    if (table == null) throw new BrotliException("Truncated prefix code");
    var b = table.codeBook();
    return b.singleSymbol() >= 0 ? CodeBook.singleSymbol(b.singleSymbol(), alphabetSize) : b;
  }
}
