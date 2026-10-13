/*
 * Dictionary.java
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

/** RFC 7932 static dictionary and 121 word transforms (§8, Appendices A/B). */
public final class Dictionary {

  public static final int DICT_SIZE = 122784;
  public static final int NUM_TRANSFORMS = 121;
  public static final int MAX_TRANSFORMED_WORD_LENGTH = 38;

  /** NDBITS[L] for word length L (RFC Appendix A). */
  private static final int[] NDBITS = {
    0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5
  };

  private static final int[] DOFFSET = new int[25];

  private static final int DICT_HASH_BITS = 12;
  private static final int DICT_HASH_SIZE = 1 << DICT_HASH_BITS;
  private static final int[][] DICT_HASH_HEAD = new int[25][];
  private static final int[][] DICT_HASH_CHAIN = new int[25][];

  /**
   * Hash of transformed dictionary outputs for encoder quality 4. Indexed transforms: identity
   * (with affixes), omit-last-1, uppercase-first, uppercase-all. Pure identity (empty affixes)
   * stays on {@link #DICT_HASH_HEAD}.
   */
  private static final int XFORM_HASH_BITS = 14;

  private static final int XFORM_HASH_SIZE = 1 << XFORM_HASH_BITS;
  private static final int[] XFORM_PREFIX_LENGTHS = {4, 8, 12};
  private static int[][] XFORM_HEAD;
  private static int[] XFORM_NEXT;
  // Five low bits hold word length; upper bits hold the hash bits absent
  // from the bucket index. This filters collisions without another array.
  private static int[] XFORM_WORD_META;
  private static int[] XFORM_WORD_INDEX;
  private static int[] XFORM_TRANSFORM_ID;
  private static int[] XFORM_OUT_LEN;

  // Transform types (Google / wire numbering used in transforms table)
  private static final int IDENTITY = 0;
  private static final int OMIT_LAST_1 = 1;
  private static final int OMIT_LAST_9 = 9;
  private static final int UPPERCASE_FIRST = 10;
  private static final int UPPERCASE_ALL = 11;
  private static final int OMIT_FIRST_1 = 12;
  private static final int OMIT_FIRST_9 = 20;

  /** Transform types included in the quality-4 index. */
  private static final int[] INDEXED_TRANSFORM_TYPES = {
    IDENTITY, OMIT_LAST_1, UPPERCASE_FIRST, UPPERCASE_ALL
  };

  /**
   * Prefix/suffix blob: each entry is length-prefixed string. From RFC Appendix B / Google
   * kPrefixSuffix.
   */
  private static final byte[] PREFIX_SUFFIX = buildPrefixSuffix();

  private static final int[] PREFIX_SUFFIX_MAP = {
    0x00, 0x02, 0x05, 0x0E, 0x13, 0x16, 0x18, 0x1E, 0x23, 0x25,
    0x2A, 0x2D, 0x2F, 0x32, 0x34, 0x3A, 0x3E, 0x45, 0x47, 0x4E,
    0x55, 0x5A, 0x5C, 0x63, 0x68, 0x6D, 0x72, 0x77, 0x7A, 0x7C,
    0x80, 0x83, 0x88, 0x8C, 0x8E, 0x91, 0x97, 0x9F, 0xA5, 0xA9,
    0xAD, 0xB2, 0xB7, 0xBD, 0xC2, 0xC7, 0xCA, 0xCF, 0xD5, 0xD8
  };

  /** Triplets: prefix_id, transform_type, suffix_id for each of 121 transforms. */
  private static final byte[] TRANSFORMS = buildTransforms();

  private static final Transform[] TRANSFORM_RECORDS = transformRecords();

  private static Transform[] transformRecords() {
    Transform[] records = new Transform[NUM_TRANSFORMS];
    for (int i = 0; i < records.length; i++)
      records[i] =
          new Transform(
              TRANSFORMS[i * 3] & 255, TRANSFORMS[i * 3 + 1] & 255, TRANSFORMS[i * 3 + 2] & 255);
    return records;
  }

  private static final byte[] DICT = DictionaryData.BYTES;

  static {
    if (DICT.length != DICT_SIZE) {
      throw new ExceptionInInitializerError("Dictionary size " + DICT.length + " != " + DICT_SIZE);
    }
    int offset = 0;
    for (int len = 0; len < 25; len++) {
      DOFFSET[len] = offset;
      int nwords = NDBITS[len] == 0 ? 0 : (1 << NDBITS[len]);
      offset += nwords * len;
    }
    buildDictionaryHashIndex();
    buildTransformHashIndex();
  }

  private static void buildDictionaryHashIndex() {
    for (int len = 4; len <= 24; len++) {
      int nw = nwords(len);
      if (nw == 0) {
        continue;
      }
      int[] head = new int[DICT_HASH_SIZE];
      for (int i = 0; i < DICT_HASH_SIZE; i++) {
        head[i] = -1;
      }
      int[] chain = new int[nw];
      int base = DOFFSET[len];
      for (int idx = 0; idx < nw; idx++) {
        int woff = base + idx * len;
        int h = dictHash4(DICT, woff) & (DICT_HASH_SIZE - 1);
        chain[idx] = head[h];
        head[h] = idx;
      }
      DICT_HASH_HEAD[len] = head;
      DICT_HASH_CHAIN[len] = chain;
    }
  }

  private static boolean isIndexedTransformType(int type) {
    for (int i = 0; i < INDEXED_TRANSFORM_TYPES.length; i++) {
      if (INDEXED_TRANSFORM_TYPES[i] == type) {
        return true;
      }
    }
    return false;
  }

  private static int prefixSuffixLen(int mapId) {
    return PREFIX_SUFFIX[PREFIX_SUFFIX_MAP[mapId]] & 0xff;
  }

  private static void buildTransformHashIndex() {
    // Count entries first
    int count = 0;
    byte[] tmp = new byte[MAX_TRANSFORMED_WORD_LENGTH];
    for (int tid = 0; tid < NUM_TRANSFORMS; tid++) {
      int type = TRANSFORM_RECORDS[tid].type();
      if (!isIndexedTransformType(type)) {
        continue;
      }
      int prefixId = TRANSFORM_RECORDS[tid].prefixId();
      int suffixId = TRANSFORM_RECORDS[tid].suffixId();
      // Pure identity (empty affixes) is covered by DICT_HASH_HEAD
      if (type == IDENTITY && prefixSuffixLen(prefixId) == 0 && prefixSuffixLen(suffixId) == 0) {
        continue;
      }
      for (int len = 4; len <= 24; len++) {
        int nw = nwords(len);
        int base = DOFFSET[len];
        for (int idx = 0; idx < nw; idx++) {
          int outLen = transform(DICT, base + idx * len, len, tid, tmp);
          if (outLen >= 4) {
            count++;
          }
        }
      }
    }

    XFORM_HEAD = new int[XFORM_PREFIX_LENGTHS.length][XFORM_HASH_SIZE];
    for (int[] heads : XFORM_HEAD) {
      java.util.Arrays.fill(heads, -1);
    }
    XFORM_NEXT = new int[count];
    XFORM_WORD_META = new int[count];
    XFORM_WORD_INDEX = new int[count];
    XFORM_TRANSFORM_ID = new int[count];
    XFORM_OUT_LEN = new int[count];

    int slot = 0;
    for (int tid = 0; tid < NUM_TRANSFORMS; tid++) {
      int type = TRANSFORM_RECORDS[tid].type();
      if (!isIndexedTransformType(type)) {
        continue;
      }
      int prefixId = TRANSFORM_RECORDS[tid].prefixId();
      int suffixId = TRANSFORM_RECORDS[tid].suffixId();
      if (type == IDENTITY && prefixSuffixLen(prefixId) == 0 && prefixSuffixLen(suffixId) == 0) {
        continue;
      }
      for (int len = 4; len <= 24; len++) {
        int nw = nwords(len);
        int base = DOFFSET[len];
        for (int idx = 0; idx < nw; idx++) {
          int outLen = transform(DICT, base + idx * len, len, tid, tmp);
          if (outLen < 4) {
            continue;
          }
          int tier = outLen >= 12 ? 2 : outLen >= 8 ? 1 : 0;
          int hash = transformedHash(tmp, 0, XFORM_PREFIX_LENGTHS[tier]);
          int h = hash & (XFORM_HASH_SIZE - 1);
          XFORM_NEXT[slot] = XFORM_HEAD[tier][h];
          XFORM_HEAD[tier][h] = slot;
          XFORM_WORD_META[slot] = len | ((hash >>> XFORM_HASH_BITS) << 5);
          XFORM_WORD_INDEX[slot] = idx;
          XFORM_TRANSFORM_ID[slot] = tid;
          XFORM_OUT_LEN[slot] = outLen;
          slot++;
        }
      }
    }
  }

  private static int dictHash4(byte[] data, int offset) {
    // Both indexes mask low bits. Mix all four bytes before that mask;
    // masking the packed word directly ignores bytes three and four.
    return mixHash(readWord4(data, offset));
  }

  private static int readWord4(byte[] data, int offset) {
    return (data[offset] & 0xff)
        | ((data[offset + 1] & 0xff) << 8)
        | ((data[offset + 2] & 0xff) << 16)
        | ((data[offset + 3] & 0xff) << 24);
  }

  private static int mixHash(int word) {
    word ^= word >>> 16;
    word *= 0x7feb352d;
    word ^= word >>> 15;
    word *= 0x846ca68b;
    return word ^ (word >>> 16);
  }

  private static int transformedHash(byte[] data, int offset, int prefixLength) {
    int hash = dictHash4(data, offset);
    for (int i = 4; i < prefixLength; i += 4) {
      hash = mixHash(hash ^ readWord4(data, offset + i));
    }
    return hash;
  }

  private Dictionary() {}

  public static int nwords(int length) {
    if (length < 4 || length > 24) {
      return 0;
    }
    return 1 << NDBITS[length];
  }

  public static int ndbits(int length) {
    return NDBITS[length];
  }

  /**
   * Applies a dictionary reference: distance beyond the window selects word index and transform.
   *
   * @param copyLength copy length L
   * @param distance decoded distance
   * @param maxDistance max allowed backward distance
   * @param out buffer for transformed output (at least MAX_TRANSFORMED_WORD_LENGTH)
   * @return output length, or -1 if invalid
   */
  public static int lookup(int copyLength, int distance, int maxDistance, byte[] out)
      throws BrotliException {
    if (copyLength < 4 || copyLength > 24) {
      throw new BrotliException("Dictionary copy length out of range: " + copyLength);
    }
    long wordId = (long) distance - ((long) maxDistance + 1L);
    int nw = nwords(copyLength);
    if (nw == 0) {
      throw new BrotliException("No dictionary words of length " + copyLength);
    }
    int index = (int) (wordId % nw);
    int transformId = (int) (wordId >> NDBITS[copyLength]);
    if (transformId < 0 || transformId >= NUM_TRANSFORMS) {
      throw new BrotliException("Invalid transform id " + transformId);
    }
    int wordOffset = DOFFSET[copyLength] + index * copyLength;
    return transform(DICT, wordOffset, copyLength, transformId, out);
  }

  public static int transform(
      byte[] dict, int wordOffset, int wordLen, int transformId, byte[] dst) {
    int prefixId = TRANSFORM_RECORDS[transformId].prefixId();
    int type = TRANSFORM_RECORDS[transformId].type();
    int suffixId = TRANSFORM_RECORDS[transformId].suffixId();

    int idx = 0;
    idx += copyPrefixed(PREFIX_SUFFIX, PREFIX_SUFFIX_MAP[prefixId], dst, idx);

    int srcOff = wordOffset;
    int len = wordLen;
    if (type >= OMIT_LAST_1 && type <= OMIT_LAST_9) {
      len -= type; // OMIT_LAST_n where n == type
    } else if (type >= OMIT_FIRST_1 && type <= OMIT_FIRST_9) {
      int skip = type - (OMIT_FIRST_1 - 1);
      srcOff += skip;
      len -= skip;
    }
    if (len < 0) {
      len = 0;
    }

    int wordStart = idx;
    for (int i = 0; i < len; i++) {
      dst[idx++] = dict[srcOff + i];
    }

    if (type == UPPERCASE_FIRST) {
      toUpperCase(dst, wordStart);
    } else if (type == UPPERCASE_ALL) {
      int remaining = len;
      int p = wordStart;
      while (remaining > 0) {
        int step = toUpperCase(dst, p);
        p += step;
        remaining -= step;
      }
    }

    idx += copyPrefixed(PREFIX_SUFFIX, PREFIX_SUFFIX_MAP[suffixId], dst, idx);
    return idx;
  }

  private static int copyPrefixed(byte[] blob, int mapOffset, byte[] dst, int dstOff) {
    int len = blob[mapOffset] & 0xff;
    for (int i = 0; i < len; i++) {
      dst[dstOff + i] = blob[mapOffset + 1 + i];
    }
    return len;
  }

  /** Ferment / uppercase one UTF-8 codepoint; returns bytes consumed. */
  private static int toUpperCase(byte[] p, int offset) {
    int b0 = p[offset] & 0xff;
    if (b0 < 0xC0) {
      if (b0 >= 'a' && b0 <= 'z') {
        p[offset] = (byte) (b0 ^ 32);
      }
      return 1;
    }
    if (b0 < 0xE0) {
      p[offset + 1] = (byte) (p[offset + 1] ^ 32);
      return 2;
    }
    p[offset + 2] = (byte) (p[offset + 2] ^ 5);
    return 3;
  }

  private static byte[] buildPrefixSuffix() {
    // Exact bytes from Google kPrefixSuffix / RFC Appendix B
    String s =
        "\u0001 \u0002, \u0008 of the \u0004 of \u0002s \u0001.\u0005 and \u0004 "
            + "in \u0001\"\u0004 to \u0002\">\u0001\n\u0002. \u0001]\u0005 for \u0003 a \u0006 "
            + "that \u0001'\u0006 with \u0006 from \u0004 by \u0001(\u0006. T"
            + "he \u0004 on \u0004 as \u0004 is \u0004ing \u0002\n\t\u0001:\u0003ed "
            + "\u0002=\"\u0004 at \u0003ly \u0001,\u0002='\u0005.com/\u0007. This \u0005"
            + " not \u0003er \u0003al \u0004ful \u0004ive \u0005less \u0004es"
            + "t \u0004ize \u0002\u00c2\u00a0\u0004ous \u0005 the \u0002e ";
    byte[] bytes = new byte[s.length() + 1];
    for (int i = 0; i < s.length(); i++) {
      bytes[i] = (byte) s.charAt(i);
    }
    bytes[s.length()] = 0;
    return bytes;
  }

  private static byte[] buildTransforms() {
    // 121 triplets from Google kTransformsData
    int[] raw = {
      49, 0, 49, 49, 0, 0, 0, 0, 0, 49, 12, 49, 49, 10, 0, 49, 0, 47,
      0, 0, 49, 4, 0, 0, 49, 0, 3, 49, 10, 49, 49, 0, 6, 49, 13, 49,
      49, 1, 49, 1, 0, 0, 49, 0, 1, 0, 10, 0, 49, 0, 7, 49, 0, 9,
      48, 0, 0, 49, 0, 8, 49, 0, 5, 49, 0, 10, 49, 0, 11, 49, 3, 49,
      49, 0, 13, 49, 0, 14, 49, 14, 49, 49, 2, 49, 49, 0, 15, 49, 0, 16,
      0, 10, 49, 49, 0, 12, 5, 0, 49, 0, 0, 1, 49, 15, 49, 49, 0, 18,
      49, 0, 17, 49, 0, 19, 49, 0, 20, 49, 16, 49, 49, 17, 49, 47, 0, 49,
      49, 4, 49, 49, 0, 22, 49, 11, 49, 49, 0, 23, 49, 0, 24, 49, 0, 25,
      49, 7, 49, 49, 1, 26, 49, 0, 27, 49, 0, 28, 0, 0, 12, 49, 0, 29,
      49, 20, 49, 49, 18, 49, 49, 6, 49, 49, 0, 21, 49, 10, 1, 49, 8, 49,
      49, 0, 31, 49, 0, 32, 47, 0, 3, 49, 5, 49, 49, 9, 49, 0, 10, 1,
      49, 10, 8, 5, 0, 21, 49, 11, 0, 49, 10, 10, 49, 0, 30, 0, 0, 5,
      35, 0, 49, 47, 0, 2, 49, 10, 17, 49, 0, 36, 49, 0, 33, 5, 0, 0,
      49, 10, 21, 49, 10, 5, 49, 0, 37, 0, 0, 30, 49, 0, 38, 0, 11, 0,
      49, 0, 39, 0, 11, 49, 49, 0, 34, 49, 11, 8, 49, 10, 12, 0, 0, 21,
      49, 0, 40, 0, 10, 12, 49, 0, 41, 49, 0, 42, 49, 11, 17, 49, 0, 43,
      0, 10, 5, 49, 11, 10, 0, 0, 34, 49, 10, 33, 49, 0, 44, 49, 11, 5,
      45, 0, 49, 0, 0, 33, 49, 10, 30, 49, 11, 30, 49, 0, 46, 49, 11, 1,
      49, 10, 34, 0, 10, 33, 0, 11, 30, 0, 11, 1, 49, 11, 33, 49, 11, 21,
      49, 11, 12, 0, 11, 5, 49, 11, 34, 0, 11, 12, 0, 10, 30, 0, 11, 34,
      0, 10, 34
    };
    byte[] t = new byte[raw.length];
    for (int i = 0; i < raw.length; i++) {
      t[i] = (byte) raw[i];
    }
    return t;
  }

  /**
   * Finds a dictionary word match for the encoder (greedy).
   *
   * @param useTransforms if true, also search uppercase / omit-last / affixed identity
   * @param outLength wire copy length L (4..24)
   * @param outCovered plaintext bytes covered (transformed output length)
   * @param outTransformId transform id
   * @param outWordIndex dictionary word index
   * @return covered length on success, or -1
   */
  public static int findMatch(
      byte[] data,
      int offset,
      int available,
      boolean useTransforms,
      int[] outLength,
      int[] outCovered,
      int[] outTransformId,
      int[] outWordIndex) {
    int bestCovered = 0;
    int bestWireLen = 0;
    int bestTransform = 0;
    int bestIndex = 0;
    if (available < 4) {
      return -1;
    }
    int key = dictHash4(data, offset);

    for (int len = 24; len >= 4; len--) {
      if (len > available) {
        continue;
      }
      int[] head = DICT_HASH_HEAD[len];
      if (head == null) {
        continue;
      }
      int h = key & (DICT_HASH_SIZE - 1);
      int base = DOFFSET[len];
      int[] chain = DICT_HASH_CHAIN[len];
      for (int idx = head[h]; idx != -1; idx = chain[idx]) {
        int woff = base + idx * len;
        boolean match = true;
        for (int i = 0; i < len; i++) {
          if (DICT[woff + i] != data[offset + i]) {
            match = false;
            break;
          }
        }
        if (match && len > bestCovered) {
          bestCovered = len;
          bestWireLen = len;
          bestTransform = 0;
          bestIndex = idx;
          if (bestCovered >= 24) {
            outLength[0] = bestWireLen;
            outCovered[0] = bestCovered;
            outTransformId[0] = bestTransform;
            outWordIndex[0] = bestIndex;
            return bestCovered;
          }
        }
      }
      if (bestCovered >= len) {
        break;
      }
    }

    if (useTransforms) {
      byte[] tmp = new byte[MAX_TRANSFORMED_WORD_LENGTH];
      // Long affixes make even an exact four-byte key highly ambiguous.
      // Separate length ranges let longer words use more prefix bytes
      // without losing shorter matches near the end of the input.
      // Equal-length candidates stay in one tier and retain insertion order.
      for (int tier = 0; tier < XFORM_PREFIX_LENGTHS.length; tier++) {
        int prefixLength = XFORM_PREFIX_LENGTHS[tier];
        if (available < prefixLength) {
          continue;
        }
        int hash = transformedHash(data, offset, prefixLength);
        int h = hash & (XFORM_HASH_SIZE - 1);
        for (int slot = XFORM_HEAD[tier][h]; slot != -1; slot = XFORM_NEXT[slot]) {
          int outLen = XFORM_OUT_LEN[slot];
          if (outLen > available || outLen <= bestCovered) {
            continue;
          }
          int wordMeta = XFORM_WORD_META[slot];
          if ((wordMeta >>> 5) != (hash >>> XFORM_HASH_BITS)) {
            continue;
          }
          int wordLen = wordMeta & 31;
          int wordIndex = XFORM_WORD_INDEX[slot];
          int tid = XFORM_TRANSFORM_ID[slot];
          int produced = transform(DICT, DOFFSET[wordLen] + wordIndex * wordLen, wordLen, tid, tmp);
          if (produced != outLen) {
            continue;
          }
          boolean match = true;
          for (int i = 0; i < outLen; i++) {
            if (tmp[i] != data[offset + i]) {
              match = false;
              break;
            }
          }
          if (match) {
            bestCovered = outLen;
            bestWireLen = wordLen;
            bestTransform = tid;
            bestIndex = wordIndex;
            if (bestCovered >= MAX_TRANSFORMED_WORD_LENGTH) {
              break;
            }
          }
        }
      }
    }

    if (bestCovered >= 4) {
      outLength[0] = bestWireLen;
      outCovered[0] = bestCovered;
      outTransformId[0] = bestTransform;
      outWordIndex[0] = bestIndex;
      return bestCovered;
    }
    return -1;
  }
}
