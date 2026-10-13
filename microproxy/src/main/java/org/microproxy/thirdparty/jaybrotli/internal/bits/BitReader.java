/*
 * BitReader.java
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
import org.microproxy.thirdparty.jaybrotli.CorruptStreamException;
import org.microproxy.thirdparty.jaybrotli.TruncatedStreamException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Resumable LSB-first bit reader over pushed input chunks.
 *
 * <p>Input is read from a byte array: the caller's own array for writable heap buffers, otherwise
 * a staging copy (direct and read-only buffers, or input merged with bytes carried over from the
 * previous chunk). After {@link #savePending()} the caller's buffer is fully consumed; unread bytes
 * are carried into the next {@link #setInput}.
 *
 * <p>Besides the checked {@code try*} reads, the {@code fast*} accessors let a decoder loop keep
 * the accumulator in local variables while enough input is buffered, then {@link #fastCommit} the
 * state back.
 */
public class BitReader implements BitSource {
  public long byteOffset() {
    return consumedBits() >>> 3;
  }

  public int bitOffset() {
    return (int) (consumedBits() & 7);
  }

  public void alignToByte(boolean zero) throws BrotliException {
    jumpToByteBoundary(zero);
  }

  private static final VarHandle LONG_LE =
      MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

  private static final VarHandle INT_LE =
      MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

  /** Accumulator holding up to 64 bits, least-significant bits first. */
  private long accumulator;

  /** Number of valid bits in the accumulator (0–64). */
  private int bitCount;

  /** Bytes pulled from the compressed stream into the accumulator. */
  private long bytesPulled;

  /** Current input bytes are {@code buf[pos..end)}; null when no input is attached. */
  private byte[] buf;

  private int pos;
  private int end;

  /** The caller's buffer when {@link #buf} is its backing array; its position is set on save. */
  private ByteBuffer input;

  /** Staging array for copied or merged input. */
  private byte[] stage;

  /** Unconsumed bytes carried across {@code receive()} calls. */
  private byte[] carry;

  private int carryLen;

  /** True after {@link #markEof()}. */
  private boolean eof;

  /** Checkpoint generation for resumable multi-field reads (e.g. prefix codes). */
  private long generation;

  public BitReader() {
    clear();
  }

  /** Creates a reader over {@code input}, as {@link #setInput} would supply it. */
  protected BitReader(ByteBuffer input) {
    clear();
    attachInput(input);
  }

  public void reset() {
    clear();
  }

  private void clear() {
    generation++;
    accumulator = 0L;
    bitCount = 0;
    bytesPulled = 0L;
    buf = null;
    pos = 0;
    end = 0;
    input = null;
    eof = false;
    carryLen = 0;
    carry = null;
    stage = null;
  }

  /** Saves bit-reader position so a multi-step read can rewind on underflow. */
  public BitCursor mark() {
    return new BitCursor(
        this, generation, accumulator, bitCount, bytesPulled, buf != null ? pos : -1);
  }

  /** Returns the number of bits consumed from the stream. */
  public long consumedBits() {
    return bytesPulled * 8 - bitCount;
  }

  /** Restores the position saved by {@link #mark()}. */
  public void resetTo(BitCursor cursor) {
    if (cursor.owner() != this || cursor.generation() != generation)
      throw new IllegalArgumentException("Cursor belongs to another source or input generation");
    accumulator = cursor.accumulator();
    bitCount = cursor.bitCount();
    bytesPulled = cursor.bytesPulled();
    if (buf != null && cursor.inputPosition() >= 0) pos = cursor.inputPosition();
  }

  /**
   * Supplies the next chunk. Prepends any bytes carried over from a prior underflow; then, as for
   * direct or read-only buffers, the chunk is copied and the caller's buffer is consumed at once.
   */
  public final void setInput(ByteBuffer data) {
    attachInput(data);
  }

  private void attachInput(ByteBuffer data) {
    generation++;
    int n = data.remaining();
    if (carryLen > 0) {
      byte[] target = stage(carryLen + n);
      System.arraycopy(carry, 0, target, 0, carryLen);
      data.get(target, carryLen, n);
      attach(target, 0, carryLen + n, null);
      carryLen = 0;
    } else if (data.hasArray()) {
      int offset = data.arrayOffset();
      attach(data.array(), offset + data.position(), offset + data.limit(), data);
    } else {
      byte[] target = stage(n);
      data.get(target, 0, n);
      attach(target, 0, n, null);
    }
  }

  private void attach(byte[] array, int from, int to, ByteBuffer owner) {
    buf = array;
    pos = from;
    end = to;
    input = owner;
  }

  private byte[] stage(int size) {
    if (stage == null || stage.length < size) {
      int capacity = stage == null ? 64 : stage.length;
      while (capacity < size) capacity = Math.max(capacity * 2, size);
      stage = new byte[capacity];
    }
    return stage;
  }

  /** Carries unconsumed input bytes over to the next chunk and releases the current one. */
  public void savePending() {
    if (buf == null) {
      return;
    }
    int rem = end - pos;
    if (rem > 0) {
      if (carry == null || carry.length < rem) {
        carry = new byte[Math.max(rem, 64)];
      }
      System.arraycopy(buf, pos, carry, 0, rem);
      carryLen = rem;
    }
    if (input != null) {
      input.position(input.limit());
    }
    buf = null;
    input = null;
    pos = 0;
    end = 0;
  }

  public void markEof() {
    // A rolled-back read can leave the final bytes carried over rather than in
    // the accumulator. They must be consumed before EOF lookahead padding.
    if (carryLen > 0) {
      setInput(ByteBuffer.allocate(0));
    }
    eof = true;
  }

  public boolean isEof() {
    return eof;
  }

  public long getByteOffset() {
    return byteOffset();
  }

  public int getBitOffset() {
    return bitOffset();
  }

  public int availableBits() {
    return bitCount;
  }

  /**
   * Ensures at least {@code n} bits are available. Returns false on underflow when not at EOF. At
   * EOF, zero-pads so Huffman peeks never run dry.
   */
  public boolean ensureBits(int n) {
    while (bitCount < n) {
      if (!refillSafe()) {
        return eof;
      }
    }
    return true;
  }

  /** Adds whole bytes into the accumulator without exceeding 64 bits. */
  private boolean refillSafe() {
    if (buf == null || pos >= end) {
      return false;
    }
    int freeBits = 64 - bitCount;
    if (freeBits < 8) {
      return true;
    }
    int avail = end - pos;
    if (bitCount == 0 && avail >= 8) {
      accumulator = (long) LONG_LE.get(buf, pos);
      pos += 8;
      bitCount = 64;
      bytesPulled += 8;
      return true;
    }
    int take = Math.min(freeBits >> 3, avail);
    for (int i = 0; i < take; i++) {
      accumulator |= ((long) (buf[pos++] & 0xff)) << bitCount;
      bitCount += 8;
    }
    bytesPulled += take;
    return true;
  }

  public int peekBits(int n) {
    if (n == 0) {
      return 0;
    }
    return (int) (accumulator & ((1L << n) - 1L));
  }

  public void dropBits(int n) {
    accumulator >>>= n;
    bitCount -= n;
  }

  /**
   * Tries to read {@code n} bits LSB-first into {@code out[0]}.
   *
   * @return false on underflow
   */
  public boolean tryReadBits(int n, int[] out) {
    if (n == 0) {
      out[0] = 0;
      return true;
    }
    if (!ensureBits(n)) {
      return false;
    }
    long mask = (1L << n) - 1L;
    out[0] = (int) (accumulator & mask);
    accumulator >>>= n;
    bitCount -= n;
    if (bitCount < 0) {
      bitCount = 0;
      accumulator = 0L;
    }
    return true;
  }

  public int readBits(int n) throws BrotliException {
    int[] out = new int[1];
    if (!tryReadBits(n, out)) {
      throw new TruncatedStreamException("Unexpected end of bitstream");
    }
    return out[0];
  }

  /**
   * Jumps to the next byte boundary. If {@code requireZeroPadding} is true, unused bits in the
   * current byte must be zero.
   */
  public void jumpToByteBoundary(boolean requireZeroPadding) throws BrotliException {
    int rem = bitCount & 7;
    if (rem != 0) {
      int pad = (int) (accumulator & ((1L << rem) - 1L));
      if (requireZeroPadding && pad != 0) {
        throw new CorruptStreamException("Non-zero padding bits before byte boundary");
      }
      accumulator >>>= rem;
      bitCount -= rem;
    }
  }

  /**
   * Returns whether whole bytes remain beyond the current position: prefetched into the
   * accumulator, left in the current input, or carried over from an earlier input.
   */
  public boolean hasUnconsumedInput() {
    return bitCount >= 8 || (buf != null && pos < end) || carryLen > 0;
  }

  /** After the last metablock, verify remaining bits in the accumulator are zero. */
  public void verifyTrailingBitsZero() throws BrotliException {
    if (bitCount > 0) {
      long mask = (1L << bitCount) - 1L;
      if ((accumulator & mask) != 0L) {
        throw new CorruptStreamException("Non-zero trailing bits at end of stream");
      }
    }
  }

  /**
   * Reads byte-aligned bytes into dest. Must be (or jumps to) a byte boundary. Returns the number
   * of bytes copied; less than {@code length} means underflow.
   */
  public int tryReadBytesAligned(byte[] dest, int destPos, int length) throws BrotliException {
    jumpToByteBoundary(true);
    int copied = 0;
    while (copied < length && bitCount >= 8) {
      dest[destPos + copied] = (byte) (accumulator & 0xff);
      accumulator >>>= 8;
      bitCount -= 8;
      copied++;
    }
    if (buf != null && copied < length) {
      int take = Math.min(length - copied, end - pos);
      if (take > 0) {
        System.arraycopy(buf, pos, dest, destPos + copied, take);
        pos += take;
        bytesPulled += take;
        copied += take;
      }
    }
    return copied;
  }

  // ---- Unchecked access for decoder hot loops ----

  /** Current input array, or null; valid until the next {@link #setInput} or save. */
  public final byte[] fastBuffer() {
    return buf;
  }

  /** Index of the next unread input byte in {@link #fastBuffer()}. */
  public final int fastPosition() {
    return pos;
  }

  /** End (exclusive) of the input in {@link #fastBuffer()}. */
  public final int fastLimit() {
    return buf == null ? 0 : end;
  }

  public final long fastAccumulator() {
    return accumulator;
  }

  public final int fastBitCount() {
    return bitCount;
  }

  /**
   * Stores state advanced by a hot loop: the loop consumed input up to {@code position} and holds
   * {@code bits} valid bits in {@code acc}.
   */
  public final void fastCommit(long acc, int bits, int position) {
    bytesPulled += position - pos;
    // A hot loop may hold the next stream bits above the counted ones; drop them, since the
    // bytes they came from are still unconsumed.
    accumulator = bits >= 64 ? acc : acc & ((1L << bits) - 1);
    bitCount = bits;
    pos = position;
  }

  /** Reads eight input bytes as a little-endian long; the caller guarantees they exist. */
  public static long longAt(byte[] array, int index) {
    return (long) LONG_LE.get(array, index);
  }

  /** Reads four input bytes as a little-endian int; the caller guarantees they exist. */
  public static int intAt(byte[] array, int index) {
    return (int) INT_LE.get(array, index);
  }
}
