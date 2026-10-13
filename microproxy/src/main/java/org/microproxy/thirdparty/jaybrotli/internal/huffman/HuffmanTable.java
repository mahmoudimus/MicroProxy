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
import org.microproxy.thirdparty.jaybrotli.internal.bits.LsbBitOrder;

/**
 * Flat Huffman decode table for Brotli prefix codes (RFC 7932 §3).
 *
 * <p>Built from per-symbol bit lengths. Lookup uses MSB-first prefix bits after {@link LsbBitOrder}
 * converts the wire bit order.
 */
public final class HuffmanTable {

  public static final int MAX_CODE_LENGTH = 15;

  /** Each entry: high 16 bits = symbol, low 16 bits = code length (0 = invalid). */
  private final int[] table;

  private final int[][] secondary;
  private final CodeBook book;

  public CodeBook codeBook() {
    return book;
  }

  private final int maxLength;
  private final int singleSymbol;

  private HuffmanTable(int[] full, int maxLength, int singleSymbol, CodeBook book) {
    this.book = book;
    if (maxLength <= 8) {
      this.table = full;
      this.secondary = null;
    } else {
      this.table = new int[256];
      this.secondary = new int[256][];
      int stride = 1 << (maxLength - 8);
      for (int i = 0; i < 256; i++) {
        int entry = full[i * stride];
        if ((entry & 0xffff) <= 8) table[i] = entry;
        else secondary[i] = java.util.Arrays.copyOfRange(full, i * stride, (i + 1) * stride);
      }
    }
    this.maxLength = maxLength;
    this.singleSymbol = singleSymbol;
  }

  public static HuffmanTable fromCodeBook(CodeBook book) {
    if (book.singleSymbol() >= 0) return singleSymbol(book.singleSymbol());
    int width = book.maxLength();
    int[] full = new int[1 << width], codes = book.codesRaw();
    byte[] lengths = book.lengthsRaw();
    for (int symbol = 0; symbol < lengths.length; symbol++) {
      int length = lengths[symbol] & 255;
      if (length == 0) continue;
      int start = codes[symbol] << (width - length), end = start + (1 << (width - length));
      java.util.Arrays.fill(full, start, end, (symbol << 16) | length);
    }
    return new HuffmanTable(full, width, -1, book);
  }

  public int getMaxLength() {
    return maxLength;
  }

  /**
   * Tries to decode one symbol.
   *
   * @return symbol &gt;= 0 on success; -2 on underflow; -1 on invalid code
   */
  public int tryDecode(BitSource br) {
    if (maxLength == 0) {
      return singleSymbol;
    }
    if (!br.ensureBits(maxLength)) {
      return -2;
    }
    int width = Math.min(8, maxLength);
    int peek = LsbBitOrder.INSTANCE.reverse(br.peekBits(width), width);
    int entry = table[peek];
    if (entry == 0 && secondary != null && secondary[peek] != null) {
      int full = LsbBitOrder.INSTANCE.reverse(br.peekBits(maxLength), maxLength);
      entry = secondary[peek][full & ((1 << (maxLength - 8)) - 1)];
    }
    int len = entry & 0xffff;
    if (len == 0) {
      return -1;
    }
    if (len > br.availableBits()) return -2;
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
    return new HuffmanTable(new int[1], 0, symbol, CodeBook.singleSymbol(symbol, symbol + 1));
  }

  /**
   * Builds a decode table from symbol bit lengths (0 = unused symbol). Validates the 15-bit Kraft
   * sum.
   */
  public static HuffmanTable fromLengths(int[] lengths) throws BrotliException {
    int alphabetSize = lengths.length;
    int maxLength = 0;
    int used = 0;
    int onlySym = -1;

    for (int i = 0; i < alphabetSize; i++) {
      int len = lengths[i];
      if (len < 0 || len > MAX_CODE_LENGTH) {
        throw new CorruptStreamException("Invalid code length " + len);
      }
      if (len > 0) {
        used++;
        onlySym = i;
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

    // If exactly one symbol, Brotli may still use length > 0, or NSYM=1 with 0.
    // Kraft: sum (1 << (15 - len)) must equal 1 << 15
    int kraft = 0;
    for (int i = 0; i < alphabetSize; i++) {
      int len = lengths[i];
      if (len > 0) {
        kraft += 1 << (MAX_CODE_LENGTH - len);
      }
    }
    if (kraft != (1 << MAX_CODE_LENGTH)) {
      throw new CorruptStreamException("Invalid Huffman code lengths (Kraft sum=" + kraft + ")");
    }

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

    int tableSize = 1 << maxLength;
    int[] table = new int[tableSize];

    for (int sym = 0; sym < alphabetSize; sym++) {
      int len = lengths[sym];
      if (len > 0) {
        int symbolCode = nextCode[len];
        nextCode[len]++;
        int step = 1 << (maxLength - len);
        int start = symbolCode << (maxLength - len);
        int entry = (sym << 16) | len;
        for (int i = 0; i < step; i++) {
          table[start + i] = entry;
        }
      }
    }

    return new HuffmanTable(table, maxLength, -1, CodeBook.fromLengths(lengths));
  }

  /** Wraps a prebuilt flat table (used for short code-length alphabets). */
  public static HuffmanTable fromPrebuilt(int[] table, int maxLength) {
    int alphabet = 0;
    for (int entry : table) alphabet = Math.max(alphabet, (entry >>> 16) + 1);
    int[] codes = new int[alphabet];
    byte[] lengths = new byte[alphabet];
    for (int i = 0; i < table.length; i++) {
      int symbol = table[i] >>> 16, length = table[i] & 0xffff;
      if (length > 0) {
        lengths[symbol] = (byte) length;
        codes[symbol] = i >>> (maxLength - length);
      }
    }
    return new HuffmanTable(table, maxLength, -1, new CodeBook(codes, lengths, maxLength));
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
