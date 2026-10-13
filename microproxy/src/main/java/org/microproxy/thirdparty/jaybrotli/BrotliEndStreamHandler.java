/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

/** Lambda-friendly callback for successful completion of a Brotli stream. */
@FunctionalInterface
public interface BrotliEndStreamHandler {
  /**
   * Runs synchronously when decoding completes or final encoded output is delivered.
   *
   * @throws BrotliException if the callback aborts
   */
  void endStream() throws BrotliException;
}
