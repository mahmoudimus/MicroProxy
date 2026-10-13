/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.huffman;

import java.util.Arrays;

public record CodeBook(int[] codes, byte[] lengths, int maxLength, int singleSymbol) {
  public CodeBook {
    codes = codes.clone();
    lengths = lengths.clone();
    if (codes.length == 0 || codes.length != lengths.length || maxLength < 0 || maxLength > 15)
      throw new IllegalArgumentException("Invalid code book");
    int maximum = 0, used = 0;
    int[] lookup = new int[1 << maxLength];
    for (int symbol = 0; symbol < lengths.length; symbol++) {
      int length = lengths[symbol] & 255;
      if (length > maxLength) throw new IllegalArgumentException("Code length exceeds maximum");
      if (length == 0) continue;
      used++;
      maximum = Math.max(maximum, length);
      if (codes[symbol] < 0 || codes[symbol] >= (1 << length))
        throw new IllegalArgumentException("Code outside bit width");
      int start = codes[symbol] << (maxLength - length), end = start + (1 << (maxLength - length));
      for (int i = start; i < end; i++) {
        if (lookup[i] != 0) throw new IllegalArgumentException("Overlapping prefix codes");
        lookup[i] = symbol + 1;
      }
    }
    if (singleSymbol >= 0) {
      if (singleSymbol >= lengths.length || used != 0 || maxLength != 0)
        throw new IllegalArgumentException("Invalid single-symbol book");
    } else {
      if (used == 0 || maximum != maxLength)
        throw new IllegalArgumentException("Invalid maximum code length");
      for (int value : lookup)
        if (value == 0) throw new IllegalArgumentException("Incomplete prefix code");
    }
  }

  public CodeBook(int[] codes, byte[] lengths, int maxLength) {
    this(codes, lengths, maxLength, -1);
  }

  @Override
  public int[] codes() {
    return codes.clone();
  }

  @Override
  public byte[] lengths() {
    return lengths.clone();
  }

  /** Internal raw view for same-package consumers; callers must not mutate. */
  int[] codesRaw() {
    return codes;
  }

  /** Internal raw view for same-package consumers; callers must not mutate. */
  byte[] lengthsRaw() {
    return lengths;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof CodeBook b
        && maxLength == b.maxLength
        && singleSymbol == b.singleSymbol
        && Arrays.equals(codes, b.codes)
        && Arrays.equals(lengths, b.lengths);
  }

  @Override
  public int hashCode() {
    return 31 * (31 * Arrays.hashCode(codes) + Arrays.hashCode(lengths)) + maxLength + singleSymbol;
  }

  public static CodeBook singleSymbol(int symbol, int alphabet) {
    if (symbol < 0 || symbol >= alphabet) throw new IllegalArgumentException("symbol");
    return new CodeBook(new int[alphabet], new byte[alphabet], 0, symbol);
  }

  public static CodeBook fromLengths(int[] lengths) {
    int[] counts = new int[16], next = new int[16], codes = new int[lengths.length];
    byte[] lens = new byte[lengths.length];
    int max = 0;
    for (int i = 0; i < lengths.length; i++) {
      int n = lengths[i];
      if (n < 0 || n > 15) throw new IllegalArgumentException("length");
      lens[i] = (byte) n;
      if (n > 0) {
        counts[n]++;
        max = Math.max(max, n);
      }
    }
    int code = 0;
    for (int i = 1; i <= 15; i++) {
      code = (code + counts[i - 1]) << 1;
      next[i] = code;
    }
    for (int i = 0; i < lengths.length; i++) if (lengths[i] > 0) codes[i] = next[lengths[i]]++;
    return new CodeBook(codes, lens, max);
  }
}
