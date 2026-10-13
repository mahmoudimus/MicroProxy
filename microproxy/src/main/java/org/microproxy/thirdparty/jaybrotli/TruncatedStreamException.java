/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

/** TruncatedStream failure with an optional consumed-input location. */
public final class TruncatedStreamException extends BrotliException {
  private static final long serialVersionUID = 1L;

  public TruncatedStreamException(String message) {
    this(message, -1, -1);
  }

  public TruncatedStreamException(String message, long byteOffset, int bitOffset) {
    super(message, null, byteOffset, bitOffset);
  }
}
