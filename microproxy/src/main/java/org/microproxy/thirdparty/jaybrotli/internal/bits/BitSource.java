/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.bits;

import org.microproxy.thirdparty.jaybrotli.BrotliException;

public interface BitSource {
  int readBits(int n) throws BrotliException;

  boolean tryReadBits(int n, int[] out);

  boolean ensureBits(int n);

  int peekBits(int n);

  void dropBits(int n);

  int availableBits();

  long byteOffset();

  int bitOffset();

  void alignToByte(boolean requireZeroPadding) throws BrotliException;

  BitCursor mark();

  void resetTo(BitCursor cursor);
}
