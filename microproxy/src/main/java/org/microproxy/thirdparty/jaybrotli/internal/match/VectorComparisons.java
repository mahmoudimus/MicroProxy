/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.match;

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.VectorSpecies;

/** Loaded only on explicit opt-in with the incubator module resolved. */
public final class VectorComparisons implements ByteComparisons.Ops {
  public VectorComparisons() {}

  private static final VectorSpecies<Byte> SPECIES = ByteVector.SPECIES_PREFERRED;

  public int commonPrefix(byte[] a, int ao, byte[] b, int bo, int length) {
    // Most candidate matches are short. Reject an early mismatch before vector setup.
    int initial = Math.min(length, 8);
    for (int i = 0; i < initial; i++) if (a[ao + i] != b[bo + i]) return i;
    int i = initial;
    int bound = i + SPECIES.loopBound(length - i);
    for (; i < bound; i += SPECIES.length()) {
      var differences =
          ByteVector.fromArray(SPECIES, a, ao + i)
              .eq(ByteVector.fromArray(SPECIES, b, bo + i))
              .not();
      if (differences.anyTrue()) return i + differences.firstTrue();
    }
    for (; i < length; i++) if (a[ao + i] != b[bo + i]) return i;
    return length;
  }

  public String description() {
    return "vector " + SPECIES.vectorBitSize() + "-bit";
  }
}
