/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.BrotliHandler;

/** Bounded reconstructed output, including overlapping-copy and borrowed-slice emission. */
public interface History extends AutoCloseable {
  default void close() {}

  void append(byte[] source, int offset, int length);

  byte at(int distance);

  int size();

  void reset();

  long getPos();

  long getTotalWritten();

  int getSize();

  byte getByte(long absolute);

  byte writeByte(byte value);

  void copyBackward(int distance, int length);

  void writeBytes(byte[] source, int offset, int length);

  void emitContent(BrotliHandler handler, int length) throws BrotliException;

  byte recent(int distance);
}
