/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

import java.nio.ByteBuffer;

/** Lambda-friendly callback for decoded content. */
@FunctionalInterface
public interface BrotliContentHandler {
  /**
   * Consumes decoded bytes synchronously. The buffer is valid only during this call.
   *
   * @param data decoded bytes in read mode; copy before retaining
   * @param end true for the last slice of the current output write, not stream EOF
   * @throws BrotliException if decoding should abort
   */
  void content(ByteBuffer data, boolean end) throws BrotliException;
}
