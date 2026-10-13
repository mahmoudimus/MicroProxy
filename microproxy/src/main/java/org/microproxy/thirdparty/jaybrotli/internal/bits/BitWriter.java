/*
 * BitWriter.java
 *
 * SPDX-License-Identifier: Apache-2.0
 * Modified for jaybrotli: namespace and licensing.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.microproxy.thirdparty.jaybrotli.internal.bits;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.BrotliSink;
import java.nio.ByteBuffer;

/**
 * Bit writer for Brotli bitstreams (RFC 7932 §1.5.1).
 *
 * <p>Integers are written LSB-first. Prefix-code symbols are written by emitting their canonical
 * bit pattern MSB-first (stored LSB-first in the byte stream after bit-reversal of the codeword).
 */
public class BitWriter implements BitSink {

  private static final int DEFAULT_CAPACITY = 8192;
  private static final int FLUSH_THRESHOLD_NUM = 3;
  private static final int FLUSH_THRESHOLD_DEN = 4;

  private final BrotliSink sink;
  private final boolean direct;

  private ByteBuffer buffer;
  private long accumulator;
  private int bitCount;

  public BitWriter(BrotliSink sink, boolean direct) {
    if (sink == null) {
      throw new NullPointerException("sink");
    }
    this.sink = sink;
    this.direct = direct;
    this.buffer = allocate(DEFAULT_CAPACITY);
    this.accumulator = 0L;
    this.bitCount = 0;
  }

  private ByteBuffer allocate(int capacity) {
    if (direct) {
      return ByteBuffer.allocateDirect(capacity);
    }
    return ByteBuffer.allocate(capacity);
  }

  public void reset() {
    accumulator = 0L;
    bitCount = 0;
    buffer.clear();
  }

  /** Writes {@code n} bits of {@code value} LSB-first. */
  public void writeBits(int value, int n) throws BrotliException {
    if (n == 0) {
      return;
    }
    long v = ((long) value) & ((1L << n) - 1L);
    accumulator |= v << bitCount;
    bitCount += n;
    while (bitCount >= 8) {
      emitByte((int) (accumulator & 0xff));
      accumulator >>>= 8;
      bitCount -= 8;
    }
  }

  /** Pads with zero bits to the next byte boundary. */
  public void jumpToByteBoundary() throws BrotliException {
    int rem = bitCount & 7;
    if (rem != 0) {
      writeBits(0, 8 - rem);
    }
  }

  /** Writes raw bytes that must start on a byte boundary. */
  public void writeBytesAligned(byte[] data, int offset, int length) throws BrotliException {
    jumpToByteBoundary();
    for (int i = 0; i < length; i++) {
      writeBits(data[offset + i] & 0xff, 8);
    }
  }

  private void emitByte(int b) throws BrotliException {
    if (!buffer.hasRemaining()) {
      flushBuffer();
    }
    buffer.put((byte) b);
    int used = buffer.position();
    int cap = buffer.capacity();
    if (used * FLUSH_THRESHOLD_DEN >= cap * FLUSH_THRESHOLD_NUM) {
      flushBuffer();
    }
  }

  public void flushBuffer() throws BrotliException {
    if (buffer.position() == 0) {
      return;
    }
    buffer.flip();
    try {
      sink.compressed(buffer);
    } finally {
      buffer.clear();
    }
  }

  /** Flushes all pending bits (padding the last byte with zeros) and buffer. */
  public void alignToByte() throws BrotliException {
    jumpToByteBoundary();
  }

  public void flush() throws BrotliException {
    flushBuffer();
  }

  public void finish() throws BrotliException {
    if (bitCount > 0) {
      emitByte((int) (accumulator & 0xff));
      accumulator = 0L;
      bitCount = 0;
    }
    flushBuffer();
  }

  public int getBitCount() {
    return bitCount;
  }
}
