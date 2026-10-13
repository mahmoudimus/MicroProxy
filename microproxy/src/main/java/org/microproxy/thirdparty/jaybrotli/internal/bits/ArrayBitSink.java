/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.bits;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.BrotliSink;

public final class ArrayBitSink extends BitWriter implements BitSink {
  public ArrayBitSink(BrotliSink sink, boolean direct) {
    super(sink, direct);
  }

  public void alignToByte() throws BrotliException {
    jumpToByteBoundary();
  }

  public void flush() throws BrotliException {
    flushBuffer();
  }
}
