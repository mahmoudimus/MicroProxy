/*
 * HuffmanTable.java
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

package org.microproxy.thirdparty.jaybrotli.internal.huffman;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.CorruptStreamException;
import org.microproxy.thirdparty.jaybrotli.TruncatedStreamException;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSource;

/**
 * Huffman decode table for Brotli prefix codes (RFC 7932 §3).
 *
 * <p>The lookup table is indexed directly by stream bits, least-significant (first read) bit first,
 * so decoding needs no bit reversal. It has two levels: a {@value #ROOT_BITS}-bit root table and,
 * for codes longer than that, second-level tables appended after it. Entries are packed ints:
 *
 * <ul>
 *   <li>symbol entry: {@code symbol << 16 | length}, length 0..15 (0 only for a single-symbol code,
 *       which consumes no bits);
 *   <li>link entry (root only): {@code offset << 16 | LINK | subBits}; the next {@code subBits}
 *       bits after the root bits index the second-level table at {@code offset};
 *   <li>{@link #INVALID} for bit patterns no code covers (only for incomplete explicit books).
 * </ul>
 *
 * <p>Hot decoder loops read {@link #lut()} directly; other callers use {@link #tryDecode}. The
 * {@link CodeBook} is derived on demand.
 */
public final class HuffmanTable {

  public static final int MAX_CODE_LENGTH = 15;

  /** Bits resolved by the root table. */
  public static final int ROOT_BITS = 8;

  /** Root-table size; a root index is {@code bits & ROOT_MASK}. */
  public static final int ROOT_MASK = (1 << ROOT_BITS) - 1;

  /** Flag marking a root entry that links to a second-level table. */
  public static final int LINK = 0x100;

  /** Entry for bit patterns that are not a code. */
  public static final int INVALID = 0xff;

  private final int[] lut;
  private final int maxLength;
  private final int singleSymbol;
  private final int[] codes;
  private final int[] lengths;
  private CodeBook book;

  private HuffmanTable(int[] codes, int[] lengths, int maxLength, int singleSymbol, CodeBook book) {
    this.codes = codes;
    this.lengths = lengths;
    this.maxLength = maxLength;
    this.singleSymbol = singleSymbol;
    this.book = book;
    this.lut = singleSymbol >= 0 ? singleLut(singleSymbol) : buildLut(codes, lengths);
  }

  /** A complete canonical code: {@code codes} is null and the codes follow from the lengths. */
  private HuffmanTable(int[] lengths, int maxLength, int[] lut) {
    this.codes = null;
    this.lengths = lengths;
    this.maxLength = maxLength;
    this.singleSymbol = -1;
    this.book = null;
    this.lut = lut;
  }

  private static int[] singleLut(int symbol) {
    int[] lut = new int[1 << ROOT_BITS];
    java.util.Arrays.fill(lut, symbol << 16);
    return lut;
  }

  /**
   * Builds the two-level table. {@code codes[s]} holds symbol s's code as an integer whose most
   * significant of {@code lengths[s]} bits is read first.
   */
  private static int[] buildLut(int[] codes, int[] lengths) {
    int rootSize = 1 << ROOT_BITS;
    int[] subBits = new int[rootSize];
    int[] reversed = new int[lengths.length];
    for (int s = 0; s < lengths.length; s++) {
      int len = lengths[s];
      if (len == 0) continue;
      int rev = Integer.reverse(codes[s]) >>> (32 - len);
      reversed[s] = rev;
      if (len > ROOT_BITS) {
        int root = rev & ROOT_MASK;
        subBits[root] = Math.max(subBits[root], len - ROOT_BITS);
      }
    }
    int size = rootSize;
    int[] offsets = new int[rootSize];
    for (int root = 0; root < rootSize; root++) {
      if (subBits[root] > 0) {
        offsets[root] = size;
        size += 1 << subBits[root];
      }
    }
    int[] lut = new int[size];
    java.util.Arrays.fill(lut, INVALID);
    for (int root = 0; root < rootSize; root++) {
      if (subBits[root] > 0) lut[root] = offsets[root] << 16 | LINK | subBits[root];
    }
    for (int s = 0; s < lengths.length; s++) {
      int len = lengths[s];
      if (len == 0) continue;
      int rev = reversed[s];
      int entry = s << 16 | len;
      if (len <= ROOT_BITS) {
        for (int i = rev; i < rootSize; i += 1 << len) lut[i] = entry;
      } else {
        int root = rev & ROOT_MASK;
        int base = offsets[root];
        int width = 1 << subBits[root];
        int subLen = len - ROOT_BITS;
        for (int i = rev >>> ROOT_BITS; i < width; i += 1 << subLen) lut[base + i] = entry;
      }
    }
    return lut;
  }

  /**
   * The packed lookup table; see the class documentation. Callers must not modify it.
   *
   * @return the lookup table
   */
  public int[] lut() {
    return lut;
  }

  public CodeBook codeBook() {
    CodeBook b = book;
    if (b == null) {
      if (singleSymbol >= 0) {
        b = CodeBook.singleSymbol(singleSymbol, singleSymbol + 1);
      } else {
        byte[] lens = new byte[lengths.length];
        for (int i = 0; i < lens.length; i++) lens[i] = (byte) lengths[i];
        b = codes == null ? CodeBook.fromLengths(lengths) : new CodeBook(codes, lens, maxLength);
      }
      book = b;
    }
    return b;
  }

  public static HuffmanTable fromCodeBook(CodeBook book) {
    if (book.singleSymbol() >= 0) return singleSymbol(book.singleSymbol());
    byte[] raw = book.lengthsRaw();
    int[] lengths = new int[raw.length];
    for (int i = 0; i < raw.length; i++) lengths[i] = raw[i] & 255;
    return new HuffmanTable(book.codesRaw().clone(), lengths, book.maxLength(), -1, book);
  }

  public int getMaxLength() {
    return maxLength;
  }

  /**
   * Tries to decode one symbol. Needs only the bits of the symbol's own code, not {@link
   * #getMaxLength()} bits of lookahead, so a stream can complete in the buffer that ends it.
   *
   * @return symbol &gt;= 0 on success; -2 on underflow; -1 on invalid code
   */
  public int tryDecode(BitSource br) {
    if (maxLength == 0) {
      return singleSymbol;
    }
    br.ensureBits(maxLength);
    int available = br.availableBits();
    // Bits beyond those available read as zero; a prefix code ignores bits past its own length.
    int entry = lut[br.peekBits(ROOT_BITS)];
    if ((entry & LINK) != 0) {
      int sub = entry & 0xff;
      entry = lut[(entry >>> 16) + (br.peekBits(ROOT_BITS + sub) >>> ROOT_BITS)];
    }
    if (entry == INVALID) {
      // Only incomplete (explicit) codes have gaps; missing bits might still complete a code.
      return available < maxLength ? -2 : -1;
    }
    int len = entry & 0xff;
    if (len > available) return -2;
    br.dropBits(len);
    return entry >>> 16;
  }

  public int decode(BitSource br) throws BrotliException {
    int s = tryDecode(br);
    if (s == -2) {
      throw new TruncatedStreamException(
          "Unexpected end of bitstream in Huffman decode", br.byteOffset(), br.bitOffset());
    }
    if (s == -1) {
      throw new CorruptStreamException("Invalid Huffman code");
    }
    return s;
  }

  /** Single-symbol code that consumes zero bits (simple prefix code NSYM=1). */
  public static HuffmanTable singleSymbol(int symbol) {
    return new HuffmanTable(null, null, 0, symbol, null);
  }

  /**
   * Builds a decode table from symbol bit lengths (0 = unused symbol). Validates the 15-bit Kraft
   * sum: the code must be complete.
   */
  public static HuffmanTable fromLengths(int[] lengths) throws BrotliException {
    int alphabetSize = lengths.length;
    int maxLength = 0;
    int used = 0;
    int onlySym = -1;
    int kraft = 0;
    int[] blCount = new int[MAX_CODE_LENGTH + 1];

    for (int i = 0; i < alphabetSize; i++) {
      int len = lengths[i];
      if (len < 0 || len > MAX_CODE_LENGTH) {
        throw new CorruptStreamException("Invalid code length " + len);
      }
      if (len > 0) {
        used++;
        onlySym = i;
        blCount[len]++;
        kraft += 1 << (MAX_CODE_LENGTH - len);
        if (len > maxLength) {
          maxLength = len;
        }
      }
    }

    if (used == 0) {
      throw new CorruptStreamException("Empty Huffman alphabet");
    }

    if (used == 1 && maxLength == 0) {
      return singleSymbol(onlySym);
    }

    // Kraft: sum (1 << (15 - len)) must equal 1 << 15
    if (kraft != (1 << MAX_CODE_LENGTH)) {
      throw new CorruptStreamException("Invalid Huffman code lengths (Kraft sum=" + kraft + ")");
    }

    return new HuffmanTable(lengths.clone(), maxLength, canonicalLut(lengths, blCount, maxLength));
  }

  /**
   * Builds the lookup table of a complete canonical code, after RFC 7932 section 3.2 and the
   * reference decoder: symbols are visited by increasing code length, so each length's codes are
   * consecutive and second-level tables are created in order, sized from the remaining counts.
   * Every slot is written, so no invalid-entry fill is needed.
   */
  private static int[] canonicalLut(int[] lengths, int[] counts, int maxLength) {
    // Symbols sorted by code length, then by symbol (counting sort).
    int[] offset = new int[MAX_CODE_LENGTH + 2];
    for (int len = 1; len <= MAX_CODE_LENGTH; len++) offset[len + 1] = offset[len] + counts[len];
    int[] sorted = new int[offset[MAX_CODE_LENGTH + 1]];
    for (int symbol = 0; symbol < lengths.length; symbol++) {
      int len = lengths[symbol];
      if (len != 0) sorted[offset[len]++] = symbol;
    }
    int rootSize = 1 << ROOT_BITS;
    // Pass 1 sizes the second-level tables; pass 2 fills everything.
    int total = rootSize;
    int[] remaining = counts.clone();
    if (maxLength > ROOT_BITS) {
      int code = 0;
      for (int len = 1; len <= ROOT_BITS; len++) code = (code + remaining[len]) << 1;
      int low = -1;
      for (int len = ROOT_BITS + 1; len <= maxLength; len++) {
        for (; remaining[len] > 0; remaining[len]--) {
          int root = Integer.reverse(code >>> (len - ROOT_BITS)) >>> (32 - ROOT_BITS);
          if (root != low) {
            total += 1 << subTableBits(remaining, len);
            low = root;
          }
          code++;
        }
        code <<= 1;
      }
    }
    int[] lut = new int[total];
    int code = 0;
    int next = 0;
    for (int len = 1; len <= Math.min(maxLength, ROOT_BITS); len++) {
      for (int n = counts[len]; n > 0; n--) {
        int entry = sorted[next++] << 16 | len;
        int rev = Integer.reverse(code++) >>> (32 - len);
        for (int i = rev; i < rootSize; i += 1 << len) lut[i] = entry;
      }
      code <<= 1;
    }
    if (maxLength > ROOT_BITS) {
      System.arraycopy(counts, 0, remaining, 0, counts.length);
      int low = -1;
      int base = rootSize;
      int width = 0;
      int sub = 0;
      for (int len = ROOT_BITS + 1; len <= maxLength; len++) {
        for (; remaining[len] > 0; remaining[len]--) {
          int rev = Integer.reverse(code++) >>> (32 - len);
          int root = rev & ROOT_MASK;
          if (root != low) {
            if (low >= 0) base += width;
            sub = subTableBits(remaining, len);
            width = 1 << sub;
            lut[root] = base << 16 | LINK | sub;
            low = root;
          }
          int entry = sorted[next++] << 16 | len;
          for (int i = rev >>> ROOT_BITS; i < width; i += 1 << (len - ROOT_BITS)) {
            lut[base + i] = entry;
          }
        }
        code <<= 1;
      }
    }
    return lut;
  }

  /** Bits of the second-level table that starts with a code of {@code len} bits. */
  private static int subTableBits(int[] remaining, int len) {
    int left = 1 << (len - ROOT_BITS);
    while (len < MAX_CODE_LENGTH) {
      left -= remaining[len];
      if (left <= 0) break;
      len++;
      left <<= 1;
    }
    return len - ROOT_BITS;
  }

  /**
   * Builds encode lengths → codes for the writer. {@code codes[sym]} and {@code lengths[sym]} for
   * each used symbol.
   */
  public static void buildEncodeTables(int[] lengths, int[] codesOut) throws BrotliException {
    int alphabetSize = lengths.length;
    int[] blCount = new int[MAX_CODE_LENGTH + 1];
    for (int i = 0; i < alphabetSize; i++) {
      int len = lengths[i];
      if (len > 0) {
        blCount[len]++;
      }
    }
    int[] nextCode = new int[MAX_CODE_LENGTH + 1];
    int code = 0;
    blCount[0] = 0;
    for (int bits = 1; bits <= MAX_CODE_LENGTH; bits++) {
      code = (code + blCount[bits - 1]) << 1;
      nextCode[bits] = code;
    }
    for (int sym = 0; sym < alphabetSize; sym++) {
      int len = lengths[sym];
      if (len > 0) {
        codesOut[sym] = nextCode[len];
        nextCode[len]++;
      } else {
        codesOut[sym] = 0;
      }
    }
  }
}
