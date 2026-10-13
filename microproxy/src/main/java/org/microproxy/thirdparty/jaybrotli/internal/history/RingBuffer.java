/*
 * RingBuffer.java
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

package org.microproxy.thirdparty.jaybrotli.internal.history;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.BrotliHandler;
import java.nio.ByteBuffer;

/**
 * Sliding-window ring buffer for reconstructed Brotli output.
 *
 * <p>Grows in powers of two up to {@code 1 << wbits}, so indexing can mask. That is 16 bytes larger
 * than the RFC window {@code (1 << wbits) - 16}.
 */
public class RingBuffer {

  private byte[] data;
  private final int maxSize;
  private int mask;
  private ByteBuffer view;
  private long pos;
  private long totalWritten;

  public RingBuffer(int wbits, boolean directIgnored) {
    // directIgnored reserved for future direct ByteBuffer ring; heap for now
    this.maxSize = 1 << wbits;
    int size = Math.min(maxSize, 8192);
    this.data = new byte[size];
    this.mask = size - 1;
    this.view = ByteBuffer.wrap(data);
    this.pos = 0L;
    this.totalWritten = 0L;
  }

  private void ensureCapacity(int additionalBytes) {
    int needed = (int) Math.min(maxSize, pos + additionalBytes);
    if (needed <= data.length) {
      return;
    }
    int capacity = data.length;
    while (capacity < needed) {
      capacity <<= 1;
    }
    // Growth happens before the first wrap; absolute indices are preserved.
    data = java.util.Arrays.copyOf(data, capacity);
    mask = capacity - 1;
    view = ByteBuffer.wrap(data);
  }

  public void reset() {
    pos = 0;
    totalWritten = 0;
  }

  public long getPos() {
    return pos;
  }

  public long getTotalWritten() {
    return totalWritten;
  }

  public int getSize() {
    return data.length;
  }

  public byte getByte(long absolutePos) {
    return data[(int) (absolutePos & mask)];
  }

  /** Writes one byte and returns it (for context tracking). */
  public byte writeByte(byte b) {
    ensureCapacity(1);
    data[(int) (pos & mask)] = b;
    pos++;
    totalWritten++;
    return b;
  }

  /**
   * Copies {@code length} bytes from {@code distance} back (1-based distance as in Brotli). Handles
   * overlapping copies byte-by-byte.
   */
  public void copyBackward(int distance, int length) {
    if (length <= 0) {
      return;
    }
    ensureCapacity(length);
    long src = pos - distance;
    if (distance >= length) {
      int copied = 0;
      while (copied < length) {
        int srcIdx = (int) ((src + copied) & mask);
        int dstIdx = (int) ((pos + copied) & mask);
        int run = length - copied;
        int toSrcEnd = data.length - srcIdx;
        int toDstEnd = data.length - dstIdx;
        if (run > toSrcEnd) {
          run = toSrcEnd;
        }
        if (run > toDstEnd) {
          run = toDstEnd;
        }
        System.arraycopy(data, srcIdx, data, dstIdx, run);
        copied += run;
      }
      pos += length;
      totalWritten += length;
      return;
    }
    for (int i = 0; i < length; i++) {
      byte b = data[(int) ((src + i) & mask)];
      data[(int) (pos & mask)] = b;
      pos++;
    }
    totalWritten += length;
  }

  /** Writes a contiguous run of bytes (e.g. dictionary transform output). */
  public void writeBytes(byte[] src, int offset, int length) {
    ensureCapacity(length);
    int copied = 0;
    while (copied < length) {
      int dstIdx = (int) ((pos + copied) & mask);
      int run = length - copied;
      int toEnd = data.length - dstIdx;
      if (run > toEnd) {
        run = toEnd;
      }
      System.arraycopy(src, offset + copied, data, dstIdx, run);
      copied += run;
    }
    pos += length;
    totalWritten += length;
  }

  /**
   * Emits the most recently written {@code length} bytes to the handler as one or two {@code
   * content} slices (ring wrap).
   */
  public void emitContent(BrotliHandler handler, int length) throws BrotliException {
    if (length <= 0) {
      return;
    }
    long start = pos - length;
    int startIdx = (int) (start & mask);
    int endIdx = (int) ((pos - 1) & mask);

    if (startIdx <= endIdx && (pos & mask) != 0) {
      // Contiguous, unless we wrapped exactly to 0
      if ((int) (pos & mask) >= startIdx || length <= data.length - startIdx) {
        // Check wrap: if startIdx + length > size, wraps
        if (startIdx + length <= data.length) {
          view.clear();
          view.position(startIdx);
          view.limit(startIdx + length);
          handler.content(view.slice(), true);
          return;
        }
      }
    }

    // Possibly wrapped
    if (startIdx + length <= data.length) {
      view.clear();
      view.position(startIdx);
      view.limit(startIdx + length);
      handler.content(view.slice(), true);
    } else {
      int first = data.length - startIdx;
      view.clear();
      view.position(startIdx);
      view.limit(data.length);
      handler.content(view.slice(), false);
      view.clear();
      view.position(0);
      view.limit(length - first);
      handler.content(view.slice(), true);
    }
  }

  /**
   * Returns the byte at relative distance 1 (most recent) or 2. Distance 1 = p1, distance 2 = p2
   * for literal context.
   */
  public byte recent(int distance) {
    if (totalWritten < distance) {
      return 0;
    }
    return data[(int) ((pos - distance) & mask)];
  }
}
