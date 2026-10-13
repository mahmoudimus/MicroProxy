/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

/**
 * Checked codec or callback failure. Offsets are -1 when the operation has no bitstream location.
 */
public sealed class BrotliException extends Exception
    permits CorruptStreamException, LimitExceededException, TruncatedStreamException {
  private static final long serialVersionUID = 1L;
  private final long byteOffset;
  private final int bitOffset;

  public BrotliException(String message) {
    this(message, null, -1, -1);
  }

  public BrotliException(String message, Throwable cause) {
    this(message, cause, -1, -1);
  }

  protected BrotliException(String message, Throwable cause, long byteOffset, int bitOffset) {
    super(message, cause);
    this.byteOffset = byteOffset;
    this.bitOffset = bitOffset;
  }

  public long byteOffset() {
    return byteOffset;
  }

  public int bitOffset() {
    return bitOffset;
  }
}
