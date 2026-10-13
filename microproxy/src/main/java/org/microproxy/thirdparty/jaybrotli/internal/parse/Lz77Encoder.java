/*
 * Lz77Encoder.java
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

package org.microproxy.thirdparty.jaybrotli.internal.parse;

import org.microproxy.thirdparty.jaybrotli.internal.history.Dictionary;
import org.microproxy.thirdparty.jaybrotli.internal.history.StaticDictionary;
import org.microproxy.thirdparty.jaybrotli.internal.ir.CommandBuffer;
import org.microproxy.thirdparty.jaybrotli.internal.match.ByteComparisons;

/**
 * LZ77 matcher producing insert/copy commands for qualities 1–9 (greedy) and qualities 10–11
 * (Zopfli via {@link ZopfliParser}).
 *
 * <p>Qualities 1–2 use a single hash bucket (greedy). Qualities 3–4 walk a short hash chain and
 * apply one-step lazy matching. Quality 4 also searches transformed dictionary words. Qualities 5–9
 * reuse the quality-4 matcher.
 */
public final class Lz77Encoder {

  private static final int HASH_BITS = 15;
  private static final int HASH_SIZE = 1 << HASH_BITS;
  private static final int MIN_MATCH = 4;
  private static final int MAX_MATCH = 16777215;
  private static final int LAZY_MIN_LEN = 6;

  /** Match search configuration for a quality level. */
  public static final class MatchMode {
    public final int chainDepth;
    public final boolean lazy;
    public final boolean useDictionary;
    public final boolean dictionaryTransforms;
    public final boolean zopfli;

    /**
     * Quality 0: after a run of literals, probe positions progressively further apart (and leave
     * them out of the hash table), so incompressible stretches cost little time.
     */
    public final boolean skipLiteralRuns;

    public MatchMode(
        int chainDepth,
        boolean lazy,
        boolean useDictionary,
        boolean dictionaryTransforms,
        boolean zopfli) {
      this.chainDepth = chainDepth;
      this.lazy = lazy;
      this.useDictionary = useDictionary;
      this.dictionaryTransforms = dictionaryTransforms;
      this.zopfli = zopfli;
      this.skipLiteralRuns = false;
    }

    private MatchMode(int chainDepth, boolean skipLiteralRuns) {
      this.chainDepth = chainDepth;
      this.lazy = false;
      this.useDictionary = false;
      this.dictionaryTransforms = false;
      this.zopfli = false;
      this.skipLiteralRuns = skipLiteralRuns;
    }

    public static MatchMode forQuality(int quality) {
      switch (quality) {
        case 0:
          return new MatchMode(1, true);
        case 1:
          return new MatchMode(1, false, false, false, false);
        case 2:
          return new MatchMode(1, false, true, false, false);
        case 3:
          return new MatchMode(4, true, true, false, false);
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
          return new MatchMode(16, true, true, true, false);
        case 10:
        case 11:
          return new MatchMode(64, false, true, true, true);
        default:
          throw new IllegalArgumentException("LZ77 quality " + quality);
      }
    }
  }

  /**
   * Hash chains kept across the meta-blocks of one stream, so that each block indexes only its own
   * positions instead of re-indexing the whole window. Chain values are stream positions relative
   * to {@link #base}, newest first. Until the data outgrows the window, {@code next} is indexed by
   * value directly and grows with the data; after that it becomes a power-of-two ring larger than
   * the window. A chain is never followed past the window or the history, so a ring slot reused by
   * a newer position is never read.
   */
  public static final class Index {
    private final int[] head = new int[HASH_SIZE];
    private int[] next = new int[0];

    /** -1 while {@code next} is indexed directly; ring size - 1 afterwards. */
    private int mask = -1;

    /** Stream position that chain value 0 stands for. */
    private long base;

    /** Stream position of the next block. */
    private long end;

    /** First position (at most three before {@link #end}) the last block could not index. */
    private long pendingFrom;

    public Index() {
      reset();
    }

    /** Forgets all positions, for a new stream. */
    public void reset() {
      java.util.Arrays.fill(head, -1);
      next = new int[0];
      mask = -1;
      base = 0;
      end = 0;
      pendingFrom = 0;
    }

    /** Makes room for positions below {@code limit} and keeps chain values in int range. */
    void prepare(long limit, int windowSize) {
      long span = limit - base;
      if (mask == -1) {
        if (span <= next.length) {
          return;
        }
        if (span <= (long) windowSize + 1) {
          // Grow by half again (bounded by the window), not to a power of two: large windows
          // would otherwise double the memory the data needs.
          long capacity = Math.min(Math.max(span, next.length * 3L / 2), (long) windowSize + 1);
          int old = next.length;
          next = java.util.Arrays.copyOf(next, (int) capacity);
          java.util.Arrays.fill(next, old, next.length, -1);
          return;
        }
        // The data now outgrows the window: move the newest values into a ring.
        int capacity = Integer.highestOneBit(windowSize) << 1;
        int[] ring = new int[capacity];
        java.util.Arrays.fill(ring, -1);
        int top = (int) (end - base);
        for (int v = Math.max(0, top - capacity); v < top; v++) {
          ring[v & (capacity - 1)] = next[v];
        }
        next = ring;
        mask = capacity - 1;
      }
      if (span > (1L << 30)) {
        // Rebase by a multiple of the ring size; values that fall below zero are out of window.
        long shift = ((end - base - next.length) / next.length) * next.length;
        if (shift > 0) {
          int delta = (int) shift;
          for (int i = 0; i < head.length; i++) head[i] = head[i] >= delta ? head[i] - delta : -1;
          for (int i = 0; i < next.length; i++) next[i] = next[i] >= delta ? next[i] - delta : -1;
          base += shift;
        }
      }
    }

    void insert(int value, int hash) {
      next[value & mask] = head[hash];
      head[hash] = value;
    }
  }

  /** One insert+copy command. */
  private Lz77Encoder() {}

  /**
   * Parses {@code block[0..blockLen)} using optional history for cross-metablock matches.
   *
   * @param block current metablock bytes
   * @param blockLen length of block
   * @param history prior uncompressed bytes (may be null)
   * @param historyLen valid length of history
   * @param windowSize {@code (1<<wbits)-16}
   * @param mode match configuration
   * @param outCommands {@code outCommands[0]} receives the command array
   * @param index hash chains of this stream's earlier blocks, updated with this block's positions
   * @return number of commands
   */
  public static int encode(
      byte[] block,
      int blockLen,
      byte[] history,
      int historyLen,
      int windowSize,
      MatchMode mode,
      CommandBuffer.Entry[][] outCommands,
      Index index) {
    if (blockLen <= 0) {
      outCommands[0] = new CommandBuffer.Entry[0];
      return 0;
    }

    int histUse = historyLen;
    if (histUse > windowSize) {
      histUse = windowSize;
    }
    int histStart = historyLen - histUse;

    long blockStart = index.end;
    index.prepare(blockStart + blockLen, windowSize);
    // Chain values for block position p are blockBase + p; a chain value v is history-relative
    // position v - blockBase + histUse (negative: older than the history).
    int blockBase = (int) (blockStart - index.base);
    // The previous block's last positions needed bytes from this block to be hashed.
    for (long p = Math.max(index.pendingFrom, blockStart - histUse); p < blockStart; p++) {
      int rel = (int) (p - blockStart) + histUse;
      if (rel + 3 > histUse + blockLen) {
        break;
      }
      index.insert(
          (int) (p - index.base),
          hash3(byteAt(block, history, histStart, histUse, rel),
              byteAt(block, history, histStart, histUse, rel + 1),
              byteAt(block, history, histStart, histUse, rel + 2)));
    }

    CommandBuffer.Entry[] cmds = new CommandBuffer.Entry[16];
    int cmdCount = 0;
    int litStart = 0;
    int pos = 0;

    int[] dictLenOut = new int[1];
    int[] dictCoveredOut = new int[1];
    int[] dictTransformOut = new int[1];
    int[] dictIndexOut = new int[1];

    int[] best = new int[4]; // covered, wireLen, dist, dictFlag
    int[] lazyBest = new int[4];

    boolean known = false;
    while (pos < blockLen) {
      if (known) {
        // The lazy probe already searched this position with the same chains (no position has
        // been indexed since): reuse its result.
        System.arraycopy(lazyBest, 0, best, 0, best.length);
        known = false;
      } else {
        findBestMatch(
            block,
            pos,
            blockLen,
            history,
            histStart,
            histUse,
            windowSize,
            mode,
            index,
            blockBase,
            dictLenOut,
            dictCoveredOut,
            dictTransformOut,
            dictIndexOut,
            best);
      }

      if (best[0] >= MIN_MATCH && mode.lazy && best[0] < LAZY_MIN_LEN && pos + 1 < blockLen) {
        // Insert current position into the hash before looking ahead
        if (pos + MIN_MATCH <= blockLen) {
          insertHash(block, pos, index, blockBase);
        }
        findBestMatch(
            block,
            pos + 1,
            blockLen,
            history,
            histStart,
            histUse,
            windowSize,
            mode,
            index,
            blockBase,
            dictLenOut,
            dictCoveredOut,
            dictTransformOut,
            dictIndexOut,
            lazyBest);
        if (lazyBest[0] > best[0]) {
          pos++;
          known = true;
          continue;
        }
      } else if (pos + MIN_MATCH <= blockLen) {
        insertHash(block, pos, index, blockBase);
      }

      if (best[0] >= MIN_MATCH) {
        int covered = best[0];
        int remaining = blockLen - pos;
        if (covered > remaining) {
          covered = remaining;
        }
        CommandBuffer.Entry c = new CommandBuffer.Entry();
        c.insertOffset = litStart;
        c.insertLen = pos - litStart;
        c.copyLen = best[1];
        c.copyCovered = covered;
        c.distance = best[2];
        c.dictionary = best[3] != 0;
        cmds = append(cmds, cmdCount, c);
        cmdCount++;

        int end = pos + covered;
        pos++;
        while (pos < end) {
          if (pos + MIN_MATCH <= blockLen) {
            insertHash(block, pos, index, blockBase);
          }
          pos++;
        }
        litStart = pos;
      } else if (mode.skipLiteralRuns) {
        // One extra position skipped per 32 literals since the last match.
        pos += 1 + ((pos - litStart) >> 5);
      } else {
        pos++;
      }
    }

    if (litStart < blockLen || cmdCount == 0) {
      CommandBuffer.Entry c = new CommandBuffer.Entry();
      c.insertOffset = litStart;
      c.insertLen = blockLen - litStart;
      c.copyLen = 2;
      c.copyCovered = 0;
      c.distance = 0;
      c.dictionary = false;
      cmds = append(cmds, cmdCount, c);
      cmdCount++;
    }

    index.end = blockStart + blockLen;
    if (blockLen >= MIN_MATCH) {
      index.pendingFrom = blockStart + blockLen - (MIN_MATCH - 1);
    }

    CommandBuffer.Entry[] result = new CommandBuffer.Entry[cmdCount];
    System.arraycopy(cmds, 0, result, 0, cmdCount);
    outCommands[0] = result;
    return cmdCount;
  }

  /** Fills {@code out} with covered, wireLen, distance, dictFlag (0/1). */
  private static void findBestMatch(
      byte[] block,
      int pos,
      int blockLen,
      byte[] history,
      int histStart,
      int histUse,
      int windowSize,
      MatchMode mode,
      Index index,
      int blockBase,
      int[] dictLenOut,
      int[] dictCoveredOut,
      int[] dictTransformOut,
      int[] dictIndexOut,
      int[] out) {
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;

    int absPos = histUse + pos;
    int maxDist = absPos;
    if (maxDist > windowSize) {
      maxDist = windowSize;
    }

    if (pos + MIN_MATCH <= blockLen && maxDist >= 1) {
      int h = hash3(block, pos);
      int[] next = index.next;
      int mask = index.mask;
      int value = index.head[h];
      // History-relative candidate position; negative once the chain leaves the history.
      int candAbs = value < 0 ? -1 : value - blockBase + histUse;
      int depth = 0;
      while (candAbs >= 0 && depth < mode.chainDepth) {
        int distance = absPos - candAbs;
        if (distance > maxDist) {
          // Chains run newest first: everything further along is out of the window too (and its
          // ring slot may already hold a newer position).
          break;
        }
        if (distance >= 1) {
          int matchLen = matchLength(block, pos, blockLen, history, histStart, histUse, candAbs);
          if (matchLen >= MIN_MATCH && matchLen > out[0]) {
            out[0] = matchLen;
            out[1] = matchLen;
            out[2] = distance;
            out[3] = 0;
          }
        }
        value = next[value & mask];
        candAbs = value < 0 ? -1 : value - blockBase + histUse;
        depth++;
      }
    }

    // A dictionary word only replaces a longer match, and none covers more than
    // MAX_TRANSFORMED_WORD_LENGTH bytes, so the search is bounded below by what hashing found.
    if (mode.useDictionary
        && pos + 4 <= blockLen
        && out[0] < Dictionary.MAX_TRANSFORMED_WORD_LENGTH) {
      int avail = blockLen - pos;
      if (avail > Dictionary.MAX_TRANSFORMED_WORD_LENGTH) {
        avail = Dictionary.MAX_TRANSFORMED_WORD_LENGTH;
      }
      int covered =
          StaticDictionary.index()
              .tryFind(
                  block,
                  pos,
                  avail,
                  mode.dictionaryTransforms,
                  out[0],
                  dictLenOut,
                  dictCoveredOut,
                  dictTransformOut,
                  dictIndexOut);
      if (covered > out[0]) {
        int wireLen = dictLenOut[0];
        int wordId = (dictTransformOut[0] << Dictionary.ndbits(wireLen)) + dictIndexOut[0];
        out[0] = covered;
        out[1] = wireLen;
        out[2] = maxDist + 1 + wordId;
        out[3] = 1;
      }
    }
  }

  private static void insertHash(byte[] block, int pos, Index index, int blockBase) {
    index.insert(blockBase + pos, hash3(block, pos));
  }

  private static int byteAt(byte[] block, byte[] history, int histStart, int histUse, int rel) {
    return rel < histUse ? history[histStart + rel] & 0xff : block[rel - histUse] & 0xff;
  }

  private static CommandBuffer.Entry[] append(
      CommandBuffer.Entry[] cmds, int count, CommandBuffer.Entry c) {
    if (count == cmds.length) {
      CommandBuffer.Entry[] grown = new CommandBuffer.Entry[cmds.length * 2];
      System.arraycopy(cmds, 0, grown, 0, cmds.length);
      cmds = grown;
    }
    cmds[count] = c;
    return cmds;
  }

  private static int hash3(byte[] data, int offset) {
    return hash3(data[offset] & 0xff, data[offset + 1] & 0xff, data[offset + 2] & 0xff);
  }

  private static int hash3(int b0, int b1, int b2) {
    int v = b0 | (b1 << 8) | (b2 << 16);
    return (v * 0x1e35a7bd) >>> (32 - HASH_BITS);
  }

  private static int matchLength(
      byte[] block,
      int pos,
      int blockLen,
      byte[] history,
      int histStart,
      int histUse,
      int candAbs) {
    return ByteComparisons.matchLength(
        block, pos, blockLen, history, histStart, histUse, candAbs, MAX_MATCH);
  }
}
