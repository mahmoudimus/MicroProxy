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
  private static final java.lang.invoke.VarHandle LONGS =
      java.lang.invoke.MethodHandles.byteArrayViewVarHandle(
          long[].class, java.nio.ByteOrder.LITTLE_ENDIAN);

  private byte[] data;
  private final int maxSize;
  private int mask;
  private ByteBuffer view;
  private long pos;
  private long totalWritten;

  public RingBuffer(int wbits, boolean directIgnored) {
    // directIgnored reserved for future direct ByteBuffer ring; heap for now
    this.maxSize = 1 << wbits;
    // Small to begin with: the decoder reserves each meta-block's length up front, so the ring
    // grows to what the stream needs in one step.
    int size = Math.min(maxSize, 1024);
    this.data = new byte[size];
    this.mask = size - 1;
    this.view = ByteBuffer.wrap(data);
    this.pos = 0L;
    this.totalWritten = 0L;
  }

  /**
   * Makes room for {@code additionalBytes} more bytes, growing the array (before its first wrap)
   * up to the window size. The array may be replaced; fetch {@link #array()} afterwards.
   *
   * @param additionalBytes bytes about to be written
   */
  public final void reserve(int additionalBytes) {
    ensureCapacity(additionalBytes);
  }

  /** Returns whether the array is still smaller than the window and may be replaced. */
  public final boolean canGrow() {
    return data.length < maxSize;
  }

  /** Backing array; positions map to {@code pos & (array().length - 1)}. Callers write directly. */
  public final byte[] array() {
    return data;
  }

  /**
   * Accounts for {@code length} bytes a caller wrote directly into {@link #array()} at the current
   * position, after {@link #reserve}.
   *
   * @param length bytes written
   */
  public final void advance(int length) {
    pos += length;
    totalWritten += length;
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
   * Copies {@code length} bytes from {@code distance} back (1-based distance as in Brotli).
   * Overlapping copies (distance &lt; length) repeat the last {@code distance} bytes.
   */
  public void copyBackward(int distance, int length) {
    if (length <= 0) {
      return;
    }
    ensureCapacity(length);
    copyWithin(data, mask, pos, distance, length);
    pos += length;
    totalWritten += length;
  }

  /**
   * Copies {@code length} bytes to ring position {@code dst} from {@code distance} bytes back, in
   * a power-of-two ring {@code ring} (index mask {@code mask}). Contiguous stretches use bulk
   * copies; an overlapping copy replicates its period by doubling, so no copy is byte-at-a-time
   * except short ones and those that cross the end of the ring.
   */
  public static void copyWithin(byte[] ring, int mask, long dst, int distance, int length) {
    int d = (int) (dst & mask);
    int s = (int) ((dst - distance) & mask);
    if (d + length > ring.length || s + length > ring.length || s > d && distance < length) {
      // Crosses the end of the ring (or a source that wraps behind the destination).
      for (int i = 0; i < length; i++) {
        ring[(d + i) & mask] = ring[(s + i) & mask];
      }
      return;
    }
    if (length <= 16) {
      if (distance >= 8 && d + 16 <= ring.length && s + 16 <= ring.length) {
        // Two 8-byte moves. Writing up to 16 - length bytes past the copy is harmless: those ring
        // positions are either unwritten or more than the window (ring size - 16) behind.
        LONGS.set(ring, d, (long) LONGS.get(ring, s));
        LONGS.set(ring, d + 8, (long) LONGS.get(ring, s + 8));
        return;
      }
      for (int i = 0; i < length; i++) {
        ring[d + i] = ring[s + i];
      }
      return;
    }
    if (distance >= length) {
      System.arraycopy(ring, s, ring, d, length);
      return;
    }
    if (distance == 1) {
      java.util.Arrays.fill(ring, d, d + length, ring[s]);
      return;
    }
    // [s, d) holds one period; each step copies everything written so far, doubling it.
    int copied = 0;
    while (copied < length) {
      int chunk = Math.min(distance + copied, length - copied);
      System.arraycopy(ring, s, ring, d + copied, chunk);
      copied += chunk;
    }
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
