/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.bits;

import org.microproxy.thirdparty.jaybrotli.BrotliException;

/** Array/ByteBuffer implementation; cursor marks are valid within one input generation. */
public class ArrayBitSource extends BitReader implements BitSource {
  public ArrayBitSource() {
    super();
  }

  public ArrayBitSource(java.nio.ByteBuffer input) {
    super(input);
  }

  public long byteOffset() {
    return consumedBits() >>> 3;
  }

  public int bitOffset() {
    return (int) (consumedBits() & 7);
  }

  public void alignToByte(boolean zero) throws BrotliException {
    jumpToByteBoundary(zero);
  }

  @Override
  public boolean tryReadBits(int n, int[] out) {
    if (n < 0 || n > 32) throw new IllegalArgumentException("bit width must be 0..32");
    if (!ensureBits(n) || availableBits() < n) return false;
    return super.tryReadBits(n, out);
  }
}
