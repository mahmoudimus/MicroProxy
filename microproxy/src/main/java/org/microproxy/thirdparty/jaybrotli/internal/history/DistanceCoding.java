/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

import org.microproxy.thirdparty.jaybrotli.BrotliException;

/** Distance-alphabet rules from RFC 7932 and RFC 9841 section 6. */
public final class DistanceCoding {
  public static final int MAX_SUPPORTED_DISTANCE = 0x7ffffffc;

  private DistanceCoding() {}

  public static int alphabetSize(boolean largeWindow, int postfixBits, int directCodes) {
    return 16 + directCodes + ((largeWindow ? 124 : 48) << postfixBits);
  }

  /** Keep complete postfix groups whose largest distance fits a signed int. */
  public static int supportedAlphabetSize(int postfixBits, int directCodes) {
    int size = 16 + directCodes;
    int groupSize = 1 << postfixBits;
    for (int extraBits = 1; extraBits <= 30; extraBits++) {
      for (int half = 0; half < 2; half++) {
        long offset = ((2L + half) << extraBits) - 4;
        long maxExtra = (1L << extraBits) - 1;
        long maxDistance = ((offset + maxExtra) << postfixBits) + groupSize - 1L + directCodes + 1;
        if (maxDistance > MAX_SUPPORTED_DISTANCE) {
          return size;
        }
        size += groupSize;
      }
    }
    return size;
  }

  /**
   * Encodes a backward or dictionary distance with NPOSTFIX=0, NDIRECT=0.
   *
   * @param out {@code out[0]}=code, {@code out[1]}=extra, {@code out[2]}=extraBits
   */
  public static void encodeDistance(int distance, DistanceRing ring, int[] out)
      throws BrotliException {
    encodeDistance(distance, 0, 0, ring, out);
  }

  /**
   * Encodes a backward or dictionary distance.
   *
   * @param out {@code out[0]}=code, {@code out[1]}=extra, {@code out[2]}=extraBits
   */
  public static void encodeDistance(
      int distance, int npostfix, int ndirect, DistanceRing ring, int[] out)
      throws BrotliException {
    if (distance <= 0) {
      throw new BrotliException("Invalid distance " + distance);
    }
    for (int c = 0; c < 16; c++) {
      if (ring.resolveShort(c) == distance) {
        out[0] = c;
        out[1] = 0;
        out[2] = 0;
        return;
      }
    }
    if (ndirect > 0 && distance <= ndirect) {
      out[0] = 15 + distance;
      out[1] = 0;
      out[2] = 0;
      return;
    }
    int rem = distance - ndirect - 1;
    if (rem < 0) {
      throw new BrotliException("Invalid distance rem " + distance);
    }
    int postfixMask = (1 << npostfix) - 1;
    int lcode = rem & postfixMask;
    int prefixBody = rem >> npostfix;
    int dist = prefixBody + 4;
    int bucket = log2Floor(dist) - 1;
    if (bucket < 1) {
      bucket = 1;
    }
    int bit = (dist >> bucket) & 1;
    int offset = (2 + bit) << bucket;
    int nbits = bucket;
    int hcode = 2 * (nbits - 1) + bit;
    int code = 16 + ndirect + (hcode << npostfix) + lcode;
    int extra = dist - offset;
    out[0] = code;
    out[1] = extra;
    out[2] = nbits;
  }

  private static int log2Floor(int n) {
    return 31 - Integer.numberOfLeadingZeros(n);
  }
}
