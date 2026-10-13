/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

/** LimitExceeded failure with an optional consumed-input location. */
public final class LimitExceededException extends BrotliException {
  private static final long serialVersionUID = 1L;

  public LimitExceededException(String message) {
    this(message, -1, -1);
  }

  public LimitExceededException(String message, long byteOffset, int bitOffset) {
    super(message, null, byteOffset, bitOffset);
  }
}
