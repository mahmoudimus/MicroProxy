/*
 * BlockLengthEncoder.java
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
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitWriter;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.CanonicalEncoder;
import org.microproxy.thirdparty.jaybrotli.internal.parse.LengthCoder;

/** Encodes Brotli block-count symbols (RFC 7932 §6). */
public final class BlockLengthEncoder {

  private BlockLengthEncoder() {}

  /**
   * Finds the block-length symbol and extra bits for {@code length}.
   *
   * @param length block length (&gt;= 1)
   * @param out {@code out[0]}=symbol, {@code out[1]}=extra, {@code out[2]}=extraBits
   */
  public static void pack(int length, int[] out) throws BrotliException {
    if (length < 1) {
      throw new BrotliException("Invalid block length " + length);
    }
    for (int sym = 0; sym <= 25; sym++) {
      int nbits = LengthCoder.BLOCK_LEN_EXTRA_BITS[sym];
      int base = LengthCoder.BLOCK_LEN_BASE[sym];
      int max = base + (1 << nbits) - 1;
      if (length >= base && length <= max) {
        out[0] = sym;
        out[1] = length - base;
        out[2] = nbits;
        return;
      }
    }
    throw new BrotliException("Block length out of range: " + length);
  }

  /** Writes a block-length code using a prebuilt Huffman table. */
  public static void write(BitWriter bw, int length, int[] lengths, int[] codes)
      throws BrotliException {
    int[] pack = new int[3];
    pack(length, pack);
    int sym = pack[0];
    int len = lengths[sym];
    if (len > 0) {
      CanonicalEncoder.writeCode(bw, codes[sym], len);
    }
    bw.writeBits(pack[1], pack[2]);
  }
}
