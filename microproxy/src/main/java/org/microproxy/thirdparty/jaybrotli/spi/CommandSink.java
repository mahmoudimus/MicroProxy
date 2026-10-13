/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.spi;

/** Semantic output; all input bytes must be covered exactly once, in order. */
public interface CommandSink {
  void insert(int offset, int length);

  void copy(int distance, int length);

  void dictionary(int distance, int wordLength, int length);
}
