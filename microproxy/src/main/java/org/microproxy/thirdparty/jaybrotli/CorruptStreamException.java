/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

/** CorruptStream failure with an optional consumed-input location. */
public final class CorruptStreamException extends BrotliException {
  private static final long serialVersionUID = 1L;

  public CorruptStreamException(String message) {
    this(message, -1, -1);
  }

  public CorruptStreamException(String message, long byteOffset, int bitOffset) {
    super(message, null, byteOffset, bitOffset);
  }
}
