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
    }

    public static MatchMode forQuality(int quality) {
      switch (quality) {
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
   * @return number of commands
   */
  public static int encode(
      byte[] block,
      int blockLen,
      byte[] history,
      int historyLen,
      int windowSize,
      MatchMode mode,
      CommandBuffer.Entry[][] outCommands) {
    if (blockLen <= 0) {
      outCommands[0] = new CommandBuffer.Entry[0];
      return 0;
    }

    int histUse = historyLen;
    if (histUse > windowSize) {
      histUse = windowSize;
    }
    int histStart = historyLen - histUse;

    int[] hashHead = new int[HASH_SIZE];
    for (int i = 0; i < HASH_SIZE; i++) {
      hashHead[i] = -1;
    }
    // Chain: next absolute position with same hash; size covers history+block
    int[] hashNext = new int[histUse + blockLen];
    for (int i = 0; i < hashNext.length; i++) {
      hashNext[i] = -1;
    }

    if (history != null && histUse >= MIN_MATCH) {
      for (int i = 0; i <= histUse - MIN_MATCH; i++) {
        int h = hash3(history, histStart + i);
        hashNext[i] = hashHead[h];
        hashHead[h] = i;
      }
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

    while (pos < blockLen) {
      findBestMatch(
          block,
          pos,
          blockLen,
          history,
          histStart,
          histUse,
          windowSize,
          mode,
          hashHead,
          hashNext,
          dictLenOut,
          dictCoveredOut,
          dictTransformOut,
          dictIndexOut,
          best);

      if (best[0] >= MIN_MATCH && mode.lazy && best[0] < LAZY_MIN_LEN && pos + 1 < blockLen) {
        // Insert current position into the hash before looking ahead
        if (pos + MIN_MATCH <= blockLen) {
          insertHash(block, pos, histUse, hashHead, hashNext);
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
            hashHead,
            hashNext,
            dictLenOut,
            dictCoveredOut,
            dictTransformOut,
            dictIndexOut,
            lazyBest);
        if (lazyBest[0] > best[0]) {
          pos++;
          continue;
        }
      } else if (pos + MIN_MATCH <= blockLen) {
        insertHash(block, pos, histUse, hashHead, hashNext);
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
            insertHash(block, pos, histUse, hashHead, hashNext);
          }
          pos++;
        }
        litStart = pos;
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
      int[] hashHead,
      int[] hashNext,
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
      int candAbs = hashHead[h];
      int depth = 0;
      while (candAbs >= 0 && depth < mode.chainDepth) {
        int distance = absPos - candAbs;
        if (distance >= 1 && distance <= maxDist) {
          int matchLen = matchLength(block, pos, blockLen, history, histStart, histUse, candAbs);
          if (matchLen >= MIN_MATCH && matchLen > out[0]) {
            out[0] = matchLen;
            out[1] = matchLen;
            out[2] = distance;
            out[3] = 0;
          }
        }
        if (candAbs >= hashNext.length) {
          break;
        }
        candAbs = hashNext[candAbs];
        depth++;
      }
    }

    if (mode.useDictionary && pos + 4 <= blockLen) {
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

  private static void insertHash(
      byte[] block, int pos, int histUse, int[] hashHead, int[] hashNext) {
    int absPos = histUse + pos;
    int h = hash3(block, pos);
    hashNext[absPos] = hashHead[h];
    hashHead[h] = absPos;
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
    int v =
        (data[offset] & 0xff)
            | ((data[offset + 1] & 0xff) << 8)
            | ((data[offset + 2] & 0xff) << 16);
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
