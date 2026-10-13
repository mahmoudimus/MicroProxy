/*
 * PrefixCode.java
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
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitCursor;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSink;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSource;
import org.microproxy.thirdparty.jaybrotli.internal.bits.LsbBitOrder;

/** Parses and writes Brotli prefix codes from/to the bitstream (RFC 7932 §3.4–3.5). */
public final class PrefixCode {

  private PrefixCode() {}

  /** Fixed 5-bit codes for code-length alphabet (RFC §3.5). */
  private static final int[] CODE_LENGTH_CODE_ORDER = {
    1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15
  };

  /**
   * Static prefix decode for code-length-of-code-lengths (RFC §3.5). Indexed by 4 LSB-first peek
   * bits → value 0..5; length from companion table.
   */
  private static final int[] CL_PREFIX_LENGTH = {2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4};

  private static final int[] CL_PREFIX_VALUE = {0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5};

  /** Static prefix encode for code-length-of-code-lengths values 0..5. */
  private static final int[] CL_ENC_BITS = {0, 7, 3, 2, 1, 15};

  private static final int[] CL_ENC_LEN = {2, 4, 3, 2, 2, 4};

  /**
   * Reads a prefix code for an alphabet of {@code alphabetSize} symbols.
   *
   * @return decode table, or null on underflow
   */
  public static HuffmanTable tryRead(BitSource br, int alphabetSize) throws BrotliException {
    return tryRead(br, alphabetSize, alphabetSize);
  }

  /** The wire alphabet determines simple-symbol width; the limit bounds trees. */
  public static HuffmanTable tryRead(BitSource br, int alphabetSize, int symbolLimit)
      throws BrotliException {
    BitCursor cursor = br.mark();
    HuffmanTable table = tryReadInner(br, alphabetSize, symbolLimit);
    if (table == null) {
      br.resetTo(cursor);
      return null;
    }

    return table;
  }

  private static HuffmanTable tryReadInner(BitSource br, int alphabetSize, int symbolLimit)
      throws BrotliException {
    int[] twoBits = new int[1];
    if (!br.tryReadBits(2, twoBits)) {
      return null;
    }
    if (twoBits[0] == 1) {
      return tryReadSimple(br, alphabetSize, symbolLimit);
    }
    return tryReadComplex(br, symbolLimit, twoBits[0]);
  }

  private static HuffmanTable tryReadSimple(BitSource br, int alphabetSize, int symbolLimit)
      throws BrotliException {
    int[] tmp = new int[1];
    if (!br.tryReadBits(2, tmp)) {
      return null;
    }
    int nsym = tmp[0] + 1;
    int bitsPerSymbol = log2Ceil(alphabetSize);

    int[] symbols = new int[4];
    for (int i = 0; i < nsym; i++) {
      if (!br.tryReadBits(bitsPerSymbol, tmp)) {
        return null;
      }
      symbols[i] = tmp[0];
      if (symbols[i] >= symbolLimit) {
        throw new CorruptStreamException("Simple prefix symbol out of range");
      }
      for (int j = 0; j < i; j++) {
        if (symbols[j] == symbols[i]) {
          throw new CorruptStreamException("Duplicate simple prefix symbol");
        }
      }
    }

    if (nsym == 4) {
      if (!br.tryReadBits(1, tmp)) {
        return null;
      }
      if (tmp[0] != 0) {
        int[] lengths = new int[symbolLimit];
        lengths[symbols[0]] = 1;
        lengths[symbols[1]] = 2;
        lengths[symbols[2]] = 3;
        lengths[symbols[3]] = 3;
        return HuffmanTable.fromLengths(lengths);
      }
      int[] lengths = new int[symbolLimit];
      lengths[symbols[0]] = 2;
      lengths[symbols[1]] = 2;
      lengths[symbols[2]] = 2;
      lengths[symbols[3]] = 2;
      return HuffmanTable.fromLengths(lengths);
    }

    if (nsym == 1) {
      return HuffmanTable.singleSymbol(symbols[0]);
    }
    if (nsym == 2) {
      int[] lengths = new int[symbolLimit];
      lengths[symbols[0]] = 1;
      lengths[symbols[1]] = 1;
      return HuffmanTable.fromLengths(lengths);
    }
    int[] lengths = new int[symbolLimit];
    lengths[symbols[0]] = 1;
    lengths[symbols[1]] = 2;
    lengths[symbols[2]] = 2;
    return HuffmanTable.fromLengths(lengths);
  }

  private static HuffmanTable tryReadComplex(BitSource br, int alphabetSize, int hskip)
      throws BrotliException {
    int[] tmp = new int[1];
    int[] clLengths = new int[18];
    int space = 32;
    int numCodes = 0;

    for (int i = hskip; i < 18; i++) {
      if (!br.ensureBits(4)) {
        return null;
      }
      int ix = br.peekBits(4);
      int len = CL_PREFIX_LENGTH[ix];
      int v = CL_PREFIX_VALUE[ix];
      br.dropBits(len);
      int sym = CODE_LENGTH_CODE_ORDER[i];
      clLengths[sym] = v;
      if (v != 0) {
        space -= 32 >> v;
        numCodes++;
        if (space <= 0) {
          break;
        }
      }
    }
    for (int i = 0; i < hskip; i++) {
      clLengths[CODE_LENGTH_CODE_ORDER[i]] = 0;
    }

    if (numCodes != 1 && space != 0) {
      throw new CorruptStreamException(
          "Invalid code-length Huffman lengths (Kraft space="
              + space
              + ", numCodes="
              + numCodes
              + ")");
    }

    HuffmanTable clTable;
    if (numCodes == 1) {
      int only = -1;
      for (int i = 0; i < 18; i++) {
        if (clLengths[i] != 0) {
          only = i;
          break;
        }
      }
      clTable = HuffmanTable.singleSymbol(only);
    } else {
      clTable = fromShortLengths(clLengths, 5);
    }

    int[] lengths = new int[alphabetSize];
    int prevNonZero = 8;
    int repeat = 0;
    int repeatCodeLen = 0;
    space = 32768;
    int i = 0;
    while (i < alphabetSize && space > 0) {
      int sym = clTable.tryDecode(br);
      if (sym == -2) {
        return null;
      }
      if (sym == -1) {
        throw new CorruptStreamException("Invalid code length code");
      }
      if (sym < 16) {
        lengths[i] = sym;
        i++;
        repeat = 0;
        if (sym != 0) {
          prevNonZero = sym;
          space -= 32768 >> sym;
        }
      } else {
        int extraBits = (sym == 16) ? 2 : 3;
        if (!br.tryReadBits(extraBits, tmp)) {
          return null;
        }
        int newLen = (sym == 16) ? prevNonZero : 0;
        if (repeatCodeLen != newLen) {
          repeat = 0;
          repeatCodeLen = newLen;
        }
        int oldRepeat = repeat;
        if (repeat > 0) {
          repeat = (repeat - 2) << extraBits;
        }
        repeat += tmp[0] + 3;
        int repeatDelta = repeat - oldRepeat;
        if (i + repeatDelta > alphabetSize) {
          throw new CorruptStreamException("Code length repeat overflow");
        }
        if (newLen != 0) {
          for (int r = 0; r < repeatDelta; r++) {
            lengths[i++] = newLen;
            space -= 32768 >> newLen;
          }
        } else {
          for (int r = 0; r < repeatDelta; r++) {
            lengths[i++] = 0;
          }
        }
      }
    }
    if (space != 0) {
      throw new CorruptStreamException(
          "Incomplete Huffman code lengths (Kraft space=" + space + ")");
    }

    return HuffmanTable.fromLengths(lengths);
  }

  private static HuffmanTable fromShortLengths(int[] lengths, int maxBits) throws BrotliException {
    int kraft = 0;
    int used = 0;
    int only = -1;
    for (int i = 0; i < lengths.length; i++) {
      int len = lengths[i];
      if (len > 0) {
        kraft += 1 << (maxBits - len);
        used++;
        only = i;
      }
    }
    if (used == 0) {
      throw new CorruptStreamException("Empty code-length alphabet");
    }
    if (used == 1) {
      return HuffmanTable.singleSymbol(only);
    }
    if (kraft != (1 << maxBits)) {
      throw new CorruptStreamException("Invalid code-length Huffman lengths (Kraft=" + kraft + ")");
    }

    // A complete canonical code: the same table the symbol-length codes use.
    return HuffmanTable.fromLengths(lengths);
  }

  public static int log2Ceil(int n) {
    if (n <= 1) {
      return 0;
    }
    return 32 - Integer.numberOfLeadingZeros(n - 1);
  }

  /** Writes a simple prefix code for the given symbols (encoder helper). */
  public static void writeSimple(BitSink bw, int[] symbols, int alphabetSize)
      throws BrotliException {
    int nsym = symbols.length;
    bw.writeBits(1, 2); // simple
    bw.writeBits(nsym - 1, 2);
    int bits = log2Ceil(alphabetSize);
    for (int i = 0; i < nsym; i++) {
      bw.writeBits(symbols[i], bits);
    }
    if (nsym == 4) {
      bw.writeBits(0, 1); // tree-select: all length 2
    }
  }

  /** Writes a simple prefix code with tree-select=1 (lengths 1,2,3,3). */
  public static void writeSimpleTreeSelect(BitSink bw, int[] symbols, int alphabetSize)
      throws BrotliException {
    bw.writeBits(1, 2);
    bw.writeBits(3, 2);
    int bits = log2Ceil(alphabetSize);
    for (int i = 0; i < 4; i++) {
      bw.writeBits(symbols[i], bits);
    }
    bw.writeBits(1, 1);
  }

  /**
   * Writes a prefix code for {@code lengths}. Prefer {@link HuffmanEncoder#writePrefixCode} which
   * handles NSYM=1 via histogram. At least one length must be &gt; 0, unless {@code soleSymbol}
   * &gt;= 0.
   *
   * @param soleSymbol if &gt;= 0 and no positive lengths, write NSYM=1 for it
   */
  public static void writeFromLengths(BitSink bw, int[] lengths, int soleSymbol)
      throws BrotliException {
    int alphabetSize = lengths.length;
    int[] usedSyms = new int[4];
    int nUsed = 0;
    for (int i = 0; i < alphabetSize; i++) {
      if (lengths[i] > 0) {
        if (nUsed < 4) {
          usedSyms[nUsed] = i;
        }
        nUsed++;
      }
    }
    if (nUsed == 0) {
      int sym = soleSymbol >= 0 ? soleSymbol : 0;
      writeSimple(bw, new int[] {sym}, alphabetSize);
      return;
    }
    if (nUsed == 1 && lengths[usedSyms[0]] == 0) {
      writeSimple(bw, new int[] {usedSyms[0]}, alphabetSize);
      return;
    }

    if (nUsed >= 2 && nUsed <= 4 && fitsSimple(lengths, nUsed)) {
      int[] syms = new int[nUsed];
      collectUsed(lengths, syms);
      orderSimpleSymbols(lengths, syms);
      if (nUsed == 4 && lengths[syms[0]] == 1) {
        writeSimpleTreeSelect(bw, syms, alphabetSize);
      } else {
        writeSimple(bw, syms, alphabetSize);
      }
      return;
    }

    writeComplex(bw, lengths);
  }

  /** Writes from lengths when at least one length is positive (or all-zero → symbol 0). */
  public static void writeFromLengths(BitSink bw, int[] lengths) throws BrotliException {
    writeFromLengths(bw, lengths, 0);
  }

  private static void collectUsed(int[] lengths, int[] out) {
    int j = 0;
    for (int i = 0; i < lengths.length && j < out.length; i++) {
      if (lengths[i] > 0) {
        out[j++] = i;
      }
    }
  }

  private static boolean fitsSimple(int[] lengths, int nUsed) {
    int c1 = 0;
    int c2 = 0;
    int c3 = 0;
    for (int i = 0; i < lengths.length; i++) {
      int L = lengths[i];
      if (L == 0) {
        continue;
      }
      if (L == 1) {
        c1++;
      } else if (L == 2) {
        c2++;
      } else if (L == 3) {
        c3++;
      } else {
        return false;
      }
    }
    if (nUsed == 2) {
      return c1 == 2;
    }
    if (nUsed == 3) {
      return c1 == 1 && c2 == 2;
    }
    if (nUsed == 4) {
      return (c2 == 4) || (c1 == 1 && c2 == 1 && c3 == 2);
    }
    return false;
  }

  private static void orderSimpleSymbols(int[] lengths, int[] syms) {
    int n = syms.length;
    if (n == 3) {
      // length-1 first
      for (int i = 0; i < 3; i++) {
        if (lengths[syms[i]] == 1) {
          int t = syms[0];
          syms[0] = syms[i];
          syms[i] = t;
          break;
        }
      }
      return;
    }
    if (n == 4 && (lengths[syms[0]] != 2 || lengths[syms[1]] != 2)) {
      // 1,2,3,3 pattern (as opposed to 2,2,2,2): the symbols must be
      // listed by ascending length, whatever their sorted position
      int s1 = -1;
      int s2 = -1;
      int s3a = -1;
      int s3b = -1;
      for (int i = 0; i < 4; i++) {
        int L = lengths[syms[i]];
        if (L == 1) {
          s1 = syms[i];
        } else if (L == 2) {
          s2 = syms[i];
        } else if (s3a < 0) {
          s3a = syms[i];
        } else {
          s3b = syms[i];
        }
      }
      if (s1 >= 0) {
        syms[0] = s1;
        syms[1] = s2;
        syms[2] = s3a;
        syms[3] = s3b;
      }
    }
  }

  private static void writeComplex(BitSink bw, int[] lengths) throws BrotliException {
    // Emit each code length directly (no RLE 16/17) for reliable kraft.
    boolean[] usedCl = new boolean[18];
    int kraftProbe = 32768;
    for (int i = 0; i < lengths.length && kraftProbe > 0; i++) {
      int len = lengths[i];
      if (len < 0 || len > 15) {
        throw new CorruptStreamException("Invalid code length " + len);
      }
      usedCl[len] = true;
      if (len != 0) {
        kraftProbe -= 32768 >> len;
      }
    }

    int[] clLengths = new int[18];
    assignCodeLengthCodeLengths(clLengths, usedCl);

    int[] order = CODE_LENGTH_CODE_ORDER;
    int hskip = 0;
    while (hskip < 3 && clLengths[order[hskip]] == 0) {
      hskip++;
    }
    if (hskip == 1) {
      hskip = 0;
    }

    bw.writeBits(hskip, 2);
    int space = 32;
    for (int oi = hskip; oi < 18 && space > 0; oi++) {
      int v = clLengths[order[oi]];
      bw.writeBits(CL_ENC_BITS[v], CL_ENC_LEN[v]);
      if (v != 0) {
        space -= 32 >> v;
      }
    }

    int[] clCodes = new int[18];
    HuffmanTable.buildEncodeTables(clLengths, clCodes);

    int kraft = 32768;
    for (int i = 0; i < lengths.length && kraft > 0; i++) {
      int len = lengths[i];
      writeClSymbol(bw, clLengths, clCodes, len);
      if (len != 0) {
        kraft -= 32768 >> len;
      }
    }
    if (kraft != 0) {
      throw new CorruptStreamException("Incomplete Huffman length encoding (Kraft=" + kraft + ")");
    }
  }

  private static void assignCodeLengthCodeLengths(int[] clLengths, boolean[] usedCl)
      throws BrotliException {
    for (int i = 0; i < 18; i++) {
      clLengths[i] = 0;
    }
    int[] usedSyms = new int[18];
    int n = 0;
    for (int i = 0; i < 18; i++) {
      if (usedCl[i]) {
        usedSyms[n++] = i;
      }
    }
    if (n == 0) {
      clLengths[0] = 1;
      clLengths[1] = 1;
      return;
    }
    if (n == 1) {
      clLengths[usedSyms[0]] = 1;
      int other = usedSyms[0] == 0 ? 1 : 0;
      clLengths[other] = 1;
      return;
    }
    if (n == 2) {
      clLengths[usedSyms[0]] = 1;
      clLengths[usedSyms[1]] = 1;
      return;
    }
    if (n == 3) {
      clLengths[usedSyms[0]] = 1;
      clLengths[usedSyms[1]] = 2;
      clLengths[usedSyms[2]] = 2;
      return;
    }
    if (n == 4) {
      for (int i = 0; i < 4; i++) {
        clLengths[usedSyms[i]] = 2;
      }
      return;
    }
    // Balanced complete code over the n used symbols: with L = ceil(log2 n),
    // 2^L - n symbols get length L - 1 and the rest get length L, so the
    // Kraft sum is exactly 32 for any n (L is at most 4 for n <= 16).
    int len = 3;
    while ((1 << len) < n) {
      len++;
    }
    int shorter = (1 << len) - n;
    for (int i = 0; i < n; i++) {
      clLengths[usedSyms[i]] = (i < shorter) ? len - 1 : len;
    }
  }

  private static void writeClSymbol(BitSink bw, int[] clLengths, int[] clCodes, int sym)
      throws BrotliException {
    int len = clLengths[sym];
    if (len == 0) {
      throw new CorruptStreamException("Writing unused code-length symbol " + sym);
    }
    bw.writeBits(LsbBitOrder.INSTANCE.reverse(clCodes[sym], len), len);
  }
}
