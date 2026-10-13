/*
 * LengthCoder.java
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

/** Insert and copy length tables and insert-and-copy code unpacking (RFC 7932 §5). */
public final class LengthCoder {

  /** Extra bits for insert length codes 0..23. */
  public static final int[] INSERT_EXTRA_BITS = {
    0, 0, 0, 0, 0, 0, 1, 1,
    2, 2, 3, 3, 4, 4, 5, 5,
    6, 7, 8, 9, 10, 12, 14, 24
  };

  /** Base insert lengths for codes 0..23. */
  public static final int[] INSERT_BASE = {
    0, 1, 2, 3, 4, 5, 6, 8,
    10, 14, 18, 26, 34, 50, 66, 98,
    130, 194, 322, 578, 1090, 2114, 6210, 22594
  };

  /** Extra bits for copy length codes 0..23. */
  public static final int[] COPY_EXTRA_BITS = {
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 2, 2, 3, 3, 4, 4,
    5, 5, 6, 7, 8, 9, 10, 24
  };

  /** Base copy lengths for codes 0..23. */
  public static final int[] COPY_BASE = {
    2, 3, 4, 5, 6, 7, 8, 9,
    10, 12, 14, 18, 22, 30, 38, 54,
    70, 102, 134, 198, 326, 582, 1094, 2118
  };

  /** Extra bits for block-count codes 0..25 (RFC §6). */
  public static final int[] BLOCK_LEN_EXTRA_BITS = {
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24
  };

  /** Base block counts for codes 0..25. */
  public static final int[] BLOCK_LEN_BASE = {
    1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265,
    2289, 4337, 8433, 16625
  };

  private LengthCoder() {}

  /**
   * Packs insert and copy lengths into an insert-and-copy symbol.
   *
   * @param insertLen insert length (&gt;= 0)
   * @param copyLen copy length (&gt;= 2)
   * @param implicitDist0 true to prefer codes 0..127 (last distance)
   * @param out {@code out[0]} = IaC code, {@code out[1]} = insert extra, {@code out[2]} = copy
   *     extra, {@code out[3]} = insert extra bits, {@code out[4]} = copy extra bits
   */
  public static void pack(int insertLen, int copyLen, boolean implicitDist0, int[] out) {
    int insertCode = insertLengthCode(insertLen);
    int copyCode = copyLengthCode(copyLen);
    out[1] = insertLen - INSERT_BASE[insertCode];
    out[2] = copyLen - COPY_BASE[copyCode];
    out[3] = INSERT_EXTRA_BITS[insertCode];
    out[4] = COPY_EXTRA_BITS[copyCode];
    out[0] = combineLengthCodes(insertCode, copyCode, implicitDist0);
  }

  public static int insertLengthCode(int insertLen) {
    if (insertLen < 6) {
      return insertLen;
    }
    if (insertLen < 130) {
      int nbits = log2Floor(insertLen - 2) - 1;
      return (nbits << 1) + ((insertLen - 2) >> nbits) + 2;
    }
    if (insertLen < 2114) {
      return log2Floor(insertLen - 66) + 10;
    }
    if (insertLen < 6210) {
      return 21;
    }
    if (insertLen < 22594) {
      return 22;
    }
    return 23;
  }

  public static int copyLengthCode(int copyLen) {
    if (copyLen < 10) {
      return copyLen - 2;
    }
    if (copyLen < 134) {
      int nbits = log2Floor(copyLen - 6) - 1;
      return (nbits << 1) + ((copyLen - 6) >> nbits) + 4;
    }
    if (copyLen < 2118) {
      return log2Floor(copyLen - 70) + 12;
    }
    return 23;
  }

  /** Combines insert/copy length codes into an IaC symbol (Google CombineLengthCodes). */
  public static int combineLengthCodes(int inscode, int copycode, boolean useLastDistance) {
    int bits64 = (copycode & 7) | ((inscode & 7) << 3);
    if (useLastDistance && inscode < 8 && copycode < 16) {
      return (copycode < 8) ? bits64 : (bits64 | 64);
    }
    int offset = 2 * ((copycode >> 3) + 3 * (inscode >> 3));
    offset = (offset << 5) + 0x40 + ((0x520D40 >> offset) & 0xC0);
    return offset | bits64;
  }

  private static int log2Floor(int n) {
    if (n <= 0) {
      return -1;
    }
    return 31 - Integer.numberOfLeadingZeros(n);
  }

  /**
   * Unpacks an insert-and-copy length symbol (0..703).
   *
   * @param code insert-and-copy symbol
   * @param out {@code out[0]} = insert length code, {@code out[1]} = copy length code, {@code
   *     out[2]} = 1 if distance symbol is implicit 0
   */
  public static void unpack(int code, int[] out) {
    int insertRange;
    int copyRange;
    int c = code;
    int dist0;
    if (c < 128) {
      dist0 = 1;
      if (c < 64) {
        insertRange = 0;
        copyRange = 0;
      } else {
        c -= 64;
        insertRange = 0;
        copyRange = 8;
      }
    } else {
      dist0 = 0;
      c -= 128;
      if (c < 64) {
        insertRange = 0;
        copyRange = 0;
      } else if (c < 128) {
        c -= 64;
        insertRange = 0;
        copyRange = 8;
      } else if (c < 192) {
        c -= 128;
        insertRange = 8;
        copyRange = 0;
      } else if (c < 256) {
        c -= 192;
        insertRange = 8;
        copyRange = 8;
      } else if (c < 320) {
        c -= 256;
        insertRange = 0;
        copyRange = 16;
      } else if (c < 384) {
        c -= 320;
        insertRange = 16;
        copyRange = 0;
      } else if (c < 448) {
        c -= 384;
        insertRange = 8;
        copyRange = 16;
      } else if (c < 512) {
        c -= 448;
        insertRange = 16;
        copyRange = 8;
      } else {
        c -= 512;
        insertRange = 16;
        copyRange = 16;
      }
    }
    out[0] = insertRange + ((c >> 3) & 7);
    out[1] = copyRange + (c & 7);
    out[2] = dist0;
  }
}
