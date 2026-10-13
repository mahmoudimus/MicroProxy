/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.bits;

import org.microproxy.thirdparty.jaybrotli.BrotliException;

public interface BitSink {
  void writeBits(int value, int n) throws BrotliException;

  void alignToByte() throws BrotliException;

  void flush() throws BrotliException;
}
