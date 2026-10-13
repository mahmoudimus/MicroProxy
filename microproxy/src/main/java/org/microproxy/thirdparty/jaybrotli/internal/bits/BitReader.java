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
 * Incremental bit reader for Brotli bitstreams (RFC 7932 §1.5.1).
 *
 * <p>Integers and extra bits are read LSB-first. Prefix-code bits are obtained by reading LSB-first
 * then reversing (MSB-first interpretation). On underflow try-methods return {@code false} so the
 * decoder can pause and resume.
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
      MethodHandles.byteBufferViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

  /** Accumulator holding up to 64 bits, least-significant bits first. */
  private long accumulator;

  /** Number of valid bits in the accumulator (0–64). */
  private int bitCount;

  /** Bytes pulled from the compressed stream into the accumulator. */
  private long bytesPulled;

  /** Current input chunk (read mode). */
  private ByteBuffer input;

  /** True after {@link #markEof()}. */
  private boolean eof;

  /**
   * Unconsumed input bytes carried across {@code receive()} when the caller passes a fresh,
   * non-overlapping buffer.
   */
  private ByteBuffer pending;

  /** Reused when {@link #pending} and a new chunk must be merged. */
  private ByteBuffer mergeBuf;

  /** Checkpoint for resumable multi-field reads (e.g. prefix codes). */
  private long generation;

  public BitReader() {
    reset();
  }

  public void reset() {
    generation++;
    accumulator = 0L;
    bitCount = 0;
    bytesPulled = 0L;
    input = null;
    eof = false;
    pending = null;
    mergeBuf = null;
  }

  /** Saves bit-reader position so a multi-step read can rewind on underflow. */
  public BitCursor mark() {

    return new BitCursor(
        this,
        generation,
        accumulator,
        bitCount,
        bytesPulled,
        input != null ? input.position() : -1);
  }

  /** Restores the position saved by {@link #mark()}. */
  public long consumedBits() {
    return bytesPulled * 8 - bitCount;
  }

  public void resetTo(BitCursor cursor) {
    if (cursor.owner() != this || cursor.generation() != generation)
      throw new IllegalArgumentException("Cursor belongs to another source or input generation");
    accumulator = cursor.accumulator();
    bitCount = cursor.bitCount();
    bytesPulled = cursor.bytesPulled();
    if (input != null && cursor.inputPosition() >= 0) input.position(cursor.inputPosition());
  }

  /**
   * Supplies the next chunk. Prepends any pending leftover from a prior underflow. When pending is
   * used, the caller's buffer is fully consumed.
   */
  public void setInput(ByteBuffer data) {
    generation++;
    if (pending != null && pending.hasRemaining()) {
      int need = pending.remaining() + data.remaining();
      if (mergeBuf == null || mergeBuf.capacity() < need) {
        int cap = mergeBuf != null ? mergeBuf.capacity() * 2 : 64;
        while (cap < need) {
          cap *= 2;
        }
        mergeBuf = ByteBuffer.allocate(cap);
      }
      mergeBuf.clear();
      mergeBuf.put(pending);
      mergeBuf.put(data);
      mergeBuf.flip();
      data.position(data.limit());
      input = mergeBuf;
      pending = null;
    } else {
      input = data;
    }
  }

  /** Stashes unconsumed input bytes into pending after an underflow return. */
  public void savePending() {
    if (input == null) {
      return;
    }
    if (input.hasRemaining()) {
      int rem = input.remaining();
      if (pending == null || pending.capacity() < rem) {
        pending = ByteBuffer.allocate(Math.max(rem, 64));
      } else {
        pending.clear();
      }
      pending.put(input);
      pending.flip();
    }
    input = null;
  }

  public void markEof() {
    // A rolled-back read can leave the final bytes in pending rather than
    // the accumulator. They must be consumed before EOF lookahead padding.
    if (pending != null && pending.hasRemaining()) {
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
        if (eof) {
          return true;
        }
        return false;
      }
    }
    return true;
  }

  /** Adds whole bytes into the accumulator without exceeding 64 bits. */
  private boolean refillSafe() {
    if (input == null || !input.hasRemaining()) {
      return false;
    }
    int freeBits = 64 - bitCount;
    if (freeBits < 8) {
      return true;
    }
    int freeBytes = freeBits >> 3;
    int avail = input.remaining();

    if (bitCount == 0 && avail >= 8) {
      long word = (long) LONG_LE.get(input, input.position());
      input.position(input.position() + 8);
      accumulator = word;
      bitCount = 64;
      bytesPulled += 8;
      return true;
    }

    int take = freeBytes < avail ? freeBytes : avail;
    for (int i = 0; i < take; i++) {
      int b = input.get() & 0xff;
      accumulator |= ((long) b) << bitCount;
      bitCount += 8;
      bytesPulled++;
    }
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
    if (input != null && copied < length) {
      int need = length - copied;
      int avail = input.remaining();
      int take = need < avail ? need : avail;
      if (take > 0) {
        input.get(dest, destPos + copied, take);
        bytesPulled += take;
        copied += take;
      }
    }
    return copied;
  }
}
