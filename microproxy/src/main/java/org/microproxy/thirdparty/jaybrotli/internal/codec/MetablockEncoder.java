/*
 * MetablockEncoder.java
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

package org.microproxy.thirdparty.jaybrotli.internal.codec;

import org.microproxy.thirdparty.jaybrotli.BrotliEndStreamHandler;
import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.BrotliSink;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSink;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitWriter;
import org.microproxy.thirdparty.jaybrotli.internal.history.DistanceRing;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.HuffmanEncoder;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.HuffmanTable;
import org.microproxy.thirdparty.jaybrotli.internal.ir.CommandBuffer;
import org.microproxy.thirdparty.jaybrotli.internal.metablock.MetablockPlan;
import org.microproxy.thirdparty.jaybrotli.internal.metablock.MetablockPlanner;
import org.microproxy.thirdparty.jaybrotli.internal.metablock.MetablockWriter;
import org.microproxy.thirdparty.jaybrotli.internal.parse.Lz77Encoder;
import org.microproxy.thirdparty.jaybrotli.internal.parse.StrategyRegistry;
import org.microproxy.thirdparty.jaybrotli.internal.parse.ZopfliParser;
import java.nio.ByteBuffer;

/**
 * Push-model Brotli encoder.
 *
 * <p>All qualities use LZ77 with Huffman coding; quality 0 probes one hash candidate per position
 * and skips ahead through literal runs. Quality 2+ uses the static dictionary; 3+ deepens LZ search; 4+ matches transformed dictionary words; 5+
 * uses literal context maps; 6 adds a literal block split and distance context trees; 7 tunes
 * NPOSTFIX/NDIRECT; 8 uses up to four literal trees and an insert-and-copy block split; 9 uses
 * larger metablocks and a distance block split; 10 uses Zopfli command selection with bounded block
 * splits and context clustering; 11 adds a second Zopfli pass with refined costs and shorter length
 * samples.
 */
public abstract class MetablockEncoder {
  // Created on first use: handing out `this` from a field initializer would let the planner see a
  // partly constructed encoder.
  private MetablockPlanner planner;
  private final MetablockWriter writer = new MetablockWriter();

  public static final int MAX_METABLOCK = 1 << 24;
  public static final int DEFAULT_BLOCK = 1 << 16;
  public static final int QUALITY9_BLOCK = 1 << 18;
  public org.microproxy.thirdparty.jaybrotli.spi.LengthLimiter lengthLimiter;

  public void assignLengths(int[] histogram, int[] lengths, int maxBits) throws BrotliException {
    HuffmanEncoder.assignLengths(histogram, lengths, maxBits);
    if (lengthLimiter == null) return;
    int used = 0;
    for (int count : histogram) if (count > 0) used++;
    if (used <= 1) return;
    byte[] limited = lengthLimiter.limit(lengths.clone(), maxBits);
    if (limited.length != lengths.length)
      throw new IllegalArgumentException("Length limiter alphabet mismatch");
    for (int i = 0; i < lengths.length; i++) {
      int n = limited[i] & 255;
      if (n > maxBits || (histogram[i] > 0 && n == 0))
        throw new IllegalArgumentException("Invalid limited length");
      lengths[i] = n;
    }
    HuffmanTable.fromLengths(lengths);
  }

  public BitWriter bw;
  public BrotliSink sink;
  public BrotliEndStreamHandler endStreamCallback;
  public int quality = 0;
  public String finderName = "standard", parserName = "standard";
  public int explicitMetablockSize;
  public int windowBits = 22;
  public boolean largeWindow;
  public boolean headerWritten;
  public boolean finished;
  public final byte[] copyBuf = new byte[8192];

  /** Pending uncompressed bytes for qualities 1+. */
  public byte[] pending = new byte[DEFAULT_BLOCK];

  public int pendingLen;

  /** Sliding window of previously encoded uncompressed bytes. */
  public byte[] history = new byte[1];

  public int historyLen;

  public final DistanceRing distRing = new DistanceRing();

  /** Hash chains of the standard LZ77 parser, kept across this stream's meta-blocks. */
  public final Lz77Encoder.Index lz77Index = new Lz77Encoder.Index();

  public void ensureHeader() throws BrotliException {
    if (sink == null) {
      throw new IllegalStateException("Register onCompressed before encoding");
    }
    if (headerWritten) {
      return;
    }
    writeWindowBits(windowBits);
    headerWritten = true;
  }

  public void writeWindowBits(int wbits) throws BrotliException {
    if (largeWindow) {
      bw.writeBits(0x11, 8);
      bw.writeBits(wbits, 6);
      return;
    }
    if (wbits == 16) {
      bw.writeBits(0, 1);
      return;
    }
    bw.writeBits(1, 1);
    if (wbits >= 18) {
      bw.writeBits(wbits - 17, 3);
      return;
    }
    bw.writeBits(0, 3);
    if (wbits == 17) {
      bw.writeBits(0, 3);
    } else {
      bw.writeBits(wbits - 8, 3);
    }
  }

  public void writeUncompressedMetablock(ByteBuffer data, int length, boolean last)
      throws BrotliException {
    bw.writeBits(last ? 1 : 0, 1);
    if (last) {
      bw.writeBits(0, 1);
    }
    writeMlen(length);
    if (!last) {
      bw.writeBits(1, 1);
    } else {
      throw new BrotliException("Internal: last uncompressed not supported");
    }
    bw.jumpToByteBoundary();
    int remaining = length;
    while (remaining > 0) {
      int n = remaining < copyBuf.length ? remaining : copyBuf.length;
      data.get(copyBuf, 0, n);
      bw.writeBytesAligned(copyBuf, 0, n);
      remaining -= n;
    }
  }

  public void writeMlen(int length) throws BrotliException {
    if (length <= 0 || length > MAX_METABLOCK) {
      throw new BrotliException("Invalid metablock length " + length);
    }
    int ml = length - 1;
    int mnibbles;
    if (ml < (1 << 16)) {
      mnibbles = 4;
    } else if (ml < (1 << 20)) {
      mnibbles = 5;
    } else {
      mnibbles = 6;
    }
    bw.writeBits(mnibbles - 4, 2);
    bw.writeBits(ml, mnibbles * 4);
  }

  public void ensurePendingCapacity(int needed) {
    if (needed <= pending.length) {
      return;
    }
    int cap = pending.length;
    while (cap < needed) {
      cap *= 2;
    }
    byte[] grown = new byte[cap];
    System.arraycopy(pending, 0, grown, 0, pendingLen);
    pending = grown;
  }

  public void flushCompressedMetablock(int length, boolean last) throws BrotliException {
    int windowSize = (1 << windowBits) - 16;
    Lz77Encoder.MatchMode mode = Lz77Encoder.MatchMode.forQuality(quality);

    CommandBuffer.Entry[][] box = new CommandBuffer.Entry[1][];
    if (!parserName.equals("standard")) {
      var context =
          new org.microproxy.thirdparty.jaybrotli.spi.ParseContext(
              java.nio.ByteBuffer.wrap(pending, 0, length),
              java.nio.ByteBuffer.wrap(history == null ? new byte[0] : history, 0, historyLen),
              windowBits,
              quality);
      CommandBuffer buffer = new CommandBuffer();
      StrategyRegistry.parser(parserName)
          .parse(context, StrategyRegistry.finder(finderName), buffer);
      box[0] = buffer.entries();
    } else if (mode.zopfli) {
      ZopfliParser.encode(pending, length, history, historyLen, windowSize, distRing, quality, box);
    } else {
      Lz77Encoder.encode(
          pending, length, history, historyLen, windowSize, mode, box, lz77Index);
    }
    CommandBuffer commandBuffer = CommandBuffer.fromEntries(box[0]);
    if (planner == null) planner = new MetablockPlanner(this);
    var ringBefore = distRing.snapshot();
    var plan = planner.plan(commandBuffer.snapshot(), pending, length);
    if (quality == 0
        && mostlyLiterals(box[0], length)
        && packedBits(plan, last) > 8L * length + 40) {
      // Quality 0 never expands incompressible input by more than a header: store the block.
      distRing.restore(ringBefore);
      writeUncompressedMetablock(ByteBuffer.wrap(pending, 0, length), length, false);
      if (last) {
        bw.writeBits(1, 1); // ISLAST
        bw.writeBits(1, 1); // ISLASTEMPTY
      }
    } else {
      writer.write(plan, bw, last);
    }

    // Append encoded bytes to history
    appendHistory(pending, length, windowSize);

    // Shift pending
    int remain = pendingLen - length;
    if (remain > 0) {
      System.arraycopy(pending, length, pending, 0, remain);
    }
    pendingLen = remain;
  }

  /**
   * Whether at least 90% of the block is literals: only then can packing fail to shrink it, so
   * only then is the packed size measured (which costs a second packing pass).
   */
  private static boolean mostlyLiterals(CommandBuffer.Entry[] commands, int length) {
    long literals = 0;
    for (CommandBuffer.Entry command : commands) literals += command.insertLen;
    return literals * 10 >= 9L * length;
  }

  /** Size of a packed plan in bits, without writing it. */
  private long packedBits(MetablockPlan plan, boolean last) throws BrotliException {
    long[] bits = {0};
    writer.write(
        plan,
        new BitSink() {
          public void writeBits(int value, int n) {
            bits[0] += n;
          }

          public void alignToByte() {
            bits[0] = (bits[0] + 7) & ~7L;
          }

          public void flush() {}
        },
        last);
    return bits[0];
  }

  public int historyByte(int distance) {
    return historyLen >= distance ? history[historyLen - distance] & 0xff : 0;
  }

  public void appendHistory(byte[] data, int length, int windowSize) {
    int needed = Math.min(windowSize, historyLen + length);
    if (history.length < needed) {
      int capacity = history.length;
      while (capacity < needed) {
        capacity = (int) Math.min(windowSize, 2L * capacity);
      }
      history = java.util.Arrays.copyOf(history, capacity);
    }
    if (length >= windowSize) {
      System.arraycopy(data, length - windowSize, history, 0, windowSize);
      historyLen = windowSize;
      return;
    }
    if (historyLen + length <= windowSize) {
      System.arraycopy(data, 0, history, historyLen, length);
      historyLen += length;
      return;
    }
    int keep = windowSize - length;
    System.arraycopy(history, historyLen - keep, history, 0, keep);
    System.arraycopy(data, 0, history, keep, length);
    historyLen = windowSize;
  }
}
