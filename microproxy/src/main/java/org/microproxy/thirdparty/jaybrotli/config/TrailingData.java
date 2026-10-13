/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.config;

/**
 * What a decoder does with input that follows the end of the Brotli stream.
 *
 * <p>A Brotli stream ends with its last meta-block, padded with zero bits to a byte boundary (RFC
 * 7932 section 9.2). Non-zero padding bits are always a format error. Bytes after that boundary are
 * not part of the stream; this policy decides whether they are an error.
 *
 * @since 1.2
 */
public enum TrailingData {
  /**
   * Any byte after the end of the stream is a {@link
   * org.microproxy.thirdparty.jaybrotli.CorruptStreamException}, whether it arrives in the same input buffer as
   * the end of the stream or in a later one. This matches the reference decoder and is the default.
   * End-of-stream is not reported when trailing bytes are already present in the buffer that
   * completes the stream.
   */
  REJECT,

  /**
   * Decoding stops at the end of the stream and later bytes are left alone: the input buffer that
   * completes the stream is positioned at the first byte after it (when that byte belongs to this
   * buffer), and later input is neither consumed nor checked. Use it to find where an embedded or
   * concatenated stream ends; {@code Decoder.streamLength()} reports the exact length.
   */
  ALLOW
}
