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
import org.microproxy.thirdparty.jaybrotli.CorruptStreamException;

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

  /*
   * Encoder indexes. Both are bucketed hash tables stored as flat arrays (compressed sparse rows):
   * bucket b's entries are [START[b], START[b + 1]), each with its full 32-bit hash in HASH and a
   * packed description in ENTRY. A lookup reads one short contiguous run instead of chasing a chain
   * through several large arrays, and filters on the full hash before touching dictionary bytes.
   * Within a bucket, entries keep the order in which earlier versions of the index visited them,
   * so matches (and therefore compressed output) are unchanged.
   */

  /** Identity words, keyed by the hash of their first four bytes. */
  private static final int ID_BUCKET_BITS = 14;

  private static int[] ID_START;
  private static int[] ID_HASH;

  /** Word length &lt;&lt; 16 | word index; longest words first, then highest index first. */
  private static int[] ID_ENTRY;

  /** A bit per identity hash ({@code hash >>> 15}): skips the table for most positions. */
  private static final long[] ID_FILTER = new long[1 << 11];

  /**
   * Transformed words for encoder quality 4 and up. Indexed transforms: identity (with affixes),
   * omit-last-1, uppercase-first, uppercase-all. Pure identity (empty affixes) is in the identity
   * index. Three tiers by output length (4-7, 8-11, 12+) hash 4, 8 and 12 leading bytes.
   */

  private static final int XFORM_BUCKET_BITS = 16;

  private static final int[] XFORM_PREFIX_LENGTHS = {4, 8, 12};

  /** Longest output in each tier. */
  private static final int[] XFORM_TIER_MAX = {7, 11, MAX_TRANSFORMED_WORD_LENGTH};
  private static int[][] XFORM_START;
  /**
   * One long per entry, so a lookup reads one contiguous run: bits 0-28 the entry (output length
   * | word length &lt;&lt; 6 | word index &lt;&lt; 11 | transform id &lt;&lt; 22), bits 29-36 the
   * output's last byte (a cheap test before the output is built), bits 37-52 the high half of the
   * hash, offset to be unsigned (the bucket fixes the low half). Within a bucket, entries are
   * ordered by hash and, within a hash group, by output length (longest first) and then by the
   * order earlier versions visited them (transform id, word length and index descending), so the
   * first match in a group is the one those versions chose.
   */
  private static long[][] XFORM_ENTRY;

  /**
   * Per tier, a bit for every hash present ({@code hash >>> (32 - XFORM_FILTER_BITS)}). Most
   * positions match no transformed word; this fits in cache, unlike the tables, so a miss costs
   * one probe instead of two cache misses per tier.
   */
  private static final int XFORM_FILTER_BITS = 21;

  private static long[][] XFORM_FILTER;

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
    int count = 0;
    for (int len = 4; len <= 24; len++) count += nwords(len);
    int[] hashes = new int[count];
    int[] entries = new int[count];
    int n = 0;
    for (int len = 24; len >= 4; len--) {
      int base = DOFFSET[len];
      for (int idx = nwords(len) - 1; idx >= 0; idx--) {
        hashes[n] = dictHash4(DICT, base + idx * len);
        entries[n] = len << 16 | idx;
        n++;
      }
    }
    for (int i = 0; i < n; i++) ID_FILTER[hashes[i] >>> 21] |= 1L << (hashes[i] >>> 15);
    int[][] table = bucketize(hashes, entries, n, ID_BUCKET_BITS);
    ID_START = table[0];
    ID_HASH = table[1];
    ID_ENTRY = table[2];
  }

  /**
   * Stable counting sort of {@code n} (hash, entry) pairs into {@code 1 << bits} buckets by the low
   * hash bits. Returns {start, hashes, entries}.
   */
  private static int[][] bucketize(int[] hashes, int[] entries, int n, int bits) {
    int mask = (1 << bits) - 1;
    int[] start = new int[(1 << bits) + 1];
    for (int i = 0; i < n; i++) start[(hashes[i] & mask) + 1]++;
    for (int b = 0; b < 1 << bits; b++) start[b + 1] += start[b];
    int[] fill = java.util.Arrays.copyOf(start, 1 << bits);
    int[] sortedHashes = new int[n];
    int[] sortedEntries = new int[n];
    for (int i = 0; i < n; i++) {
      int at = fill[hashes[i] & mask]++;
      sortedHashes[at] = hashes[i];
      sortedEntries[at] = entries[i];
    }
    return new int[][] {start, sortedHashes, sortedEntries};
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
    int tiers = XFORM_PREFIX_LENGTHS.length;
    int[] counts = new int[tiers];
    int[][] hashes = new int[tiers][];
    int[][] entries = new int[tiers][];
    byte[][] lasts = new byte[tiers][];
    byte[] tmp = new byte[MAX_TRANSFORMED_WORD_LENGTH];
    for (int pass = 0; pass < 2; pass++) {
      if (pass == 1) {
        for (int t = 0; t < tiers; t++) {
          hashes[t] = new int[counts[t]];
          entries[t] = new int[counts[t]];
          lasts[t] = new byte[counts[t]];
          counts[t] = 0;
        }
      }
      // Reverse insertion order: the order in which lookups visit candidates.
      for (int tid = NUM_TRANSFORMS - 1; tid >= 0; tid--) {
        int type = TRANSFORM_RECORDS[tid].type();
        if (!isIndexedTransformType(type)) {
          continue;
        }
        int prefixId = TRANSFORM_RECORDS[tid].prefixId();
        int suffixId = TRANSFORM_RECORDS[tid].suffixId();
        // Pure identity (empty affixes) is in the identity index.
        if (type == IDENTITY && prefixSuffixLen(prefixId) == 0 && prefixSuffixLen(suffixId) == 0) {
          continue;
        }
        for (int len = 24; len >= 4; len--) {
          int base = DOFFSET[len];
          for (int idx = nwords(len) - 1; idx >= 0; idx--) {
            int outLen = transform(DICT, base + idx * len, len, tid, tmp);
            if (outLen < 4) {
              continue;
            }
            int tier = outLen >= 12 ? 2 : outLen >= 8 ? 1 : 0;
            int at = counts[tier]++;
            if (pass == 1) {
              hashes[tier][at] = transformedHash(tmp, 0, XFORM_PREFIX_LENGTHS[tier]);
              entries[tier][at] = outLen | len << 6 | idx << 11 | tid << 22;
              lasts[tier][at] = tmp[outLen - 1];
            }
          }
        }
      }
    }
    XFORM_START = new int[tiers][];
    XFORM_ENTRY = new long[tiers][];
    XFORM_FILTER = new long[tiers][1 << (XFORM_FILTER_BITS - 6)];
    for (int t = 0; t < tiers; t++) {
      for (int i = 0; i < counts[t]; i++) {
        int bit = hashes[t][i] >>> (32 - XFORM_FILTER_BITS);
        XFORM_FILTER[t][bit >>> 6] |= 1L << bit;
      }
      // Carry the last byte through the bucket sort inside the entry's spare high bits.
      int n = counts[t];
      long[] packed = new long[n];
      for (int i = 0; i < n; i++) packed[i] = (long) (lasts[t][i] & 0xff) << 32 | entries[t][i];
      int[] order = new int[n];
      for (int i = 0; i < n; i++) order[i] = i;
      int[][] table = bucketize(hashes[t], order, n, XFORM_BUCKET_BITS);
      int[] start = table[0], hash = table[1], index = table[2];
      // Within each bucket: by hash, then longest output first; insertion sort keeps it stable.
      for (int b = 0; b + 1 < start.length; b++) {
        for (int i = start[b] + 1; i < start[b + 1]; i++) {
          int h = hash[i], x = index[i];
          int len = (int) packed[x] & 63;
          int j = i - 1;
          while (j >= start[b]
              && (hash[j] > h || hash[j] == h && ((int) packed[index[j]] & 63) < len)) {
            hash[j + 1] = hash[j];
            index[j + 1] = index[j];
            j--;
          }
          hash[j + 1] = h;
          index[j + 1] = x;
        }
      }
      long[] sorted = new long[n];
      for (int i = 0; i < n; i++) {
        long v = packed[index[i]];
        sorted[i] = (long) ((hash[i] >> 16) + 32768) << 37 | (v >>> 32) << 29 | (v & 0x1fffffffL);
      }
      XFORM_START[t] = start;
      XFORM_ENTRY[t] = sorted;
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
      throw new CorruptStreamException("Dictionary copy length out of range: " + copyLength);
    }
    long wordId = (long) distance - ((long) maxDistance + 1L);
    int nw = nwords(copyLength);
    if (nw == 0) {
      throw new CorruptStreamException("No dictionary words of length " + copyLength);
    }
    int index = (int) (wordId & (nw - 1)); // nw is a power of two
    int transformId = (int) (wordId >> NDBITS[copyLength]);
    if (transformId < 0 || transformId >= NUM_TRANSFORMS) {
      throw new CorruptStreamException("Invalid transform id " + transformId);
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
    System.arraycopy(dict, srcOff, dst, idx, len);
    idx += len;

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
    System.arraycopy(blob, mapOffset + 1, dst, dstOff, len);
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
    return findMatch(
        data, offset, available, useTransforms, 0, outLength, outCovered, outTransformId,
        outWordIndex);
  }

  /**
   * Like {@link #findMatch(byte[], int, int, boolean, int[], int[], int[], int[])}, but only
   * reports matches covering more than {@code floor} bytes; a caller that already has a match of
   * {@code floor} bytes skips candidates that could not replace it. Whenever the best match covers
   * more than {@code floor}, the result is the same as without a floor.
   *
   * @param floor covered length a match must exceed, at least 0
   * @return covered length on success, or -1
   */
  public static int findMatch(
      byte[] data,
      int offset,
      int available,
      boolean useTransforms,
      int floor,
      int[] outLength,
      int[] outCovered,
      int[] outTransformId,
      int[] outWordIndex) {
    if (available < 4 || floor >= MAX_TRANSFORMED_WORD_LENGTH) {
      return -1;
    }
    int bestCovered = floor;
    int bestWireLen = 0;
    int bestTransform = 0;
    int bestIndex = 0;
    int key = dictHash4(data, offset);

    // Identity words, longest first: the first one that matches is the longest.
    int bucket = key & ((1 << ID_BUCKET_BITS) - 1);
    boolean identity = (ID_FILTER[key >>> 21] & 1L << (key >>> 15)) != 0;
    for (int i = identity ? ID_START[bucket] : 0, last = identity ? ID_START[bucket + 1] : 0;
        i < last;
        i++) {
      if (ID_HASH[i] != key) {
        continue;
      }
      int entry = ID_ENTRY[i];
      int len = entry >>> 16;
      if (len <= bestCovered && len < 24) {
        break;
      }
      if (len > available) {
        continue;
      }
      int idx = entry & 0xffff;
      int woff = DOFFSET[len] + idx * len;
      if (java.util.Arrays.equals(DICT, woff, woff + len, data, offset, offset + len)) {
        if (len <= floor) {
          return -1; // A 24-byte identity word ends the search, even below the floor.
        }
        bestCovered = len;
        bestWireLen = len;
        bestTransform = 0;
        bestIndex = idx;
        if (bestCovered >= 24) {
          // A 24-byte identity word ends the search, as it always has.
          outLength[0] = bestWireLen;
          outCovered[0] = bestCovered;
          outTransformId[0] = bestTransform;
          outWordIndex[0] = bestIndex;
          return bestCovered;
        }
        break;
      }
    }

    if (useTransforms && bestCovered < MAX_TRANSFORMED_WORD_LENGTH) {
      // Long affixes make even an exact four-byte key highly ambiguous.
      // Separate length ranges let longer words use more prefix bytes
      // without losing shorter matches near the end of the input.
      // Tiers hold disjoint output lengths, so the longest tier with a match decides: search
      // from the longest down and stop at the first match.
      int tiers = 1;
      int[] tierHash = new int[XFORM_PREFIX_LENGTHS.length];
      tierHash[0] = key;
      while (tiers < XFORM_PREFIX_LENGTHS.length && available >= XFORM_PREFIX_LENGTHS[tiers]) {
        int prefixLength = XFORM_PREFIX_LENGTHS[tiers];
        tierHash[tiers] = mixHash(tierHash[tiers - 1] ^ readWord4(data, offset + prefixLength - 4));
        tiers++;
      }
      byte[] tmp = null;
      search:
      for (int tier = tiers - 1; tier >= 0; tier--) {
        if (XFORM_TIER_MAX[tier] <= bestCovered) {
          break; // This and shorter tiers cannot beat what is already found.
        }
        int hash = tierHash[tier];
        int bit = hash >>> (32 - XFORM_FILTER_BITS);
        if ((XFORM_FILTER[tier][bit >>> 6] & 1L << bit) == 0) {
          continue;
        }
        int[] start = XFORM_START[tier];
        long[] entries = XFORM_ENTRY[tier];
        int high = (hash >> 16) + 32768;
        int b = hash & (start.length - 2); // start has 2^bits + 1 entries
        for (int i = start[b], last = start[b + 1]; i < last; i++) {
          long packed = entries[i];
          int h = (int) (packed >>> 37);
          if (h != high) {
            if (h > high) {
              break; // Sorted by hash: this hash's group is behind us or absent.
            }
            continue;
          }
          int entry = (int) packed & 0x1fffffff;
          int outLen = entry & 63;
          if (outLen <= bestCovered) {
            break; // Longest first: nothing further in this group can be better.
          }
          if (outLen > available || (byte) (packed >>> 29) != data[offset + outLen - 1]) {
            continue;
          }
          int wordLen = (entry >>> 6) & 31;
          int wordIndex = (entry >>> 11) & 2047;
          int tid = entry >>> 22;
          if (tmp == null) {
            tmp = new byte[MAX_TRANSFORMED_WORD_LENGTH];
          }
          int produced = transform(DICT, DOFFSET[wordLen] + wordIndex * wordLen, wordLen, tid, tmp);
          if (produced == outLen
              && java.util.Arrays.equals(tmp, 0, outLen, data, offset, offset + outLen)) {
            bestCovered = outLen;
            bestWireLen = wordLen;
            bestTransform = tid;
            bestIndex = wordIndex;
            break search;
          }
        }
      }
    }

    if (bestCovered > floor && bestCovered >= 4) {
      outLength[0] = bestWireLen;
      outCovered[0] = bestCovered;
      outTransformId[0] = bestTransform;
      outWordIndex[0] = bestIndex;
      return bestCovered;
    }
    return -1;
  }
}
