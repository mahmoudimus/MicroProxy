/*
 * ContextMapWriter.java
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

package org.microproxy.thirdparty.jaybrotli.internal.metablock;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSink;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.CanonicalEncoder;

/** Writes NTREES / NBLTYPES varints and context maps for the encoder. */
public final class ContextMapWriter {

  private ContextMapWriter() {}

  /**
   * Writes a DecodeVarLenUint8+1 value (NBLTYPES / NTREES).
   *
   * @param value value in 1..256
   */
  public static void writeVarLenUint8PlusOne(BitSink bw, int value) throws BrotliException {
    if (value < 1 || value > 256) {
      throw new BrotliException("Invalid varlenuint8+1 value " + value);
    }
    if (value == 1) {
      bw.writeBits(0, 1);
      return;
    }
    bw.writeBits(1, 1);
    if (value == 2) {
      bw.writeBits(0, 3);
      return;
    }
    int n = 0;
    int v = value - 1;
    while ((1 << n) <= v - (1 << n)) {
      n++;
    }
    // Find smallest n such that 1 + (1<<n) + ((1<<n)-1) >= value
    // i.e. value - 1 - (1<<n) fits in n bits and is >= 0
    for (n = 1; n <= 7; n++) {
      int base = 1 << n;
      int extra = value - 1 - base;
      if (extra >= 0 && extra < (1 << n)) {
        bw.writeBits(n, 3);
        bw.writeBits(extra, n);
        return;
      }
    }
    throw new BrotliException("Cannot encode varlenuint8+1 value " + value);
  }

  /** Writes the selected context-map book and symbols without entropy decisions. */
  public static void write(BitSink out, ContextMapPlan plan) throws BrotliException {
    if (plan.treeCount() == 1) {
      out.writeBits(0, 1);
      return;
    }
    writeVarLenUint8PlusOne(out, plan.treeCount());
    out.writeBits(0, 1); // RLEMAX = 0
    MetablockWriter.writePrefix(plan.codeBook(), out);
    var encoder = new CanonicalEncoder(plan.codeBook());
    for (int tree : plan.contexts().trees()) encoder.encode(tree, out);
    out.writeBits(0, 1); // IMTF = 0
  }
}
