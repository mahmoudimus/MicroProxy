/*
 * HuffmanEncoder.java
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
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSink;

/** Huffman code-length assignment for the encoder. */
public final class HuffmanEncoder {

  private HuffmanEncoder() {}

  /**
   * Assigns bit lengths for symbols with positive histogram counts. Unused symbols get length 0. A
   * single used symbol gets length 0 (simple NSYM=1). Lengths satisfy the 15-bit Kraft inequality
   * when more than one symbol is used.
   *
   * @param histogram symbol frequencies (may be zero)
   * @param lengthsOut output lengths (same size as histogram)
   * @param maxBits maximum code length (typically 15)
   */
  public static void assignLengths(int[] histogram, int[] lengthsOut, int maxBits)
      throws BrotliException {
    if (maxBits < 1 || maxBits > HuffmanTable.MAX_CODE_LENGTH) {
      throw new BrotliException("Invalid maxBits " + maxBits);
    }
    int n = histogram.length;
    for (int i = 0; i < n; i++) {
      lengthsOut[i] = 0;
    }

    int used = 0;
    int only = -1;
    for (int i = 0; i < n; i++) {
      if (histogram[i] > 0) {
        used++;
        only = i;
      }
    }
    if (used == 0) {
      // Valid trivial tree: symbol 0 with zero bits.
      lengthsOut[0] = 0;
      return;
    }
    if (used == 1) {
      lengthsOut[only] = 0;
      return;
    }

    // Collect leaves: [symbol, frequency]
    int[] symbols = new int[used];
    int[] freqs = new int[used];
    int k = 0;
    for (int i = 0; i < n; i++) {
      if (histogram[i] > 0) {
        symbols[k] = i;
        freqs[k] = histogram[i];
        k++;
      }
    }

    // Huffman tree with 2*used-1 nodes. Leaves 0..used-1, internal used..
    int maxNodes = 2 * used - 1;
    int[] nodeFreq = new int[maxNodes];
    int[] left = new int[maxNodes];
    int[] right = new int[maxNodes];
    int[] parent = new int[maxNodes];
    for (int i = 0; i < maxNodes; i++) {
      left[i] = -1;
      right[i] = -1;
      parent[i] = -1;
    }
    for (int i = 0; i < used; i++) {
      nodeFreq[i] = freqs[i];
    }

    int nextNode = used;
    while (nextNode < maxNodes) {
      int a = -1;
      int b = -1;
      for (int i = 0; i < nextNode; i++) {
        if (parent[i] != -1) {
          continue;
        }
        if (a < 0 || nodeFreq[i] < nodeFreq[a]) {
          b = a;
          a = i;
        } else if (b < 0 || nodeFreq[i] < nodeFreq[b]) {
          b = i;
        }
      }
      if (a < 0 || b < 0) {
        throw new BrotliException("Huffman tree construction failed");
      }
      left[nextNode] = a;
      right[nextNode] = b;
      nodeFreq[nextNode] = nodeFreq[a] + nodeFreq[b];
      parent[a] = nextNode;
      parent[b] = nextNode;
      nextNode++;
    }

    int root = maxNodes - 1;
    int[] depth = new int[maxNodes];
    depth[root] = 0;
    // Iterative DFS via explicit stack
    int[] stack = new int[maxNodes];
    int sp = 0;
    stack[sp++] = root;
    while (sp > 0) {
      int node = stack[--sp];
      int d = depth[node];
      if (left[node] >= 0) {
        depth[left[node]] = d + 1;
        depth[right[node]] = d + 1;
        stack[sp++] = left[node];
        stack[sp++] = right[node];
      }
    }

    for (int i = 0; i < used; i++) {
      int d = depth[i];
      if (d < 1) {
        d = 1;
      }
      if (d > maxBits) {
        d = maxBits;
      }
      lengthsOut[symbols[i]] = d;
    }

    fixKraft(lengthsOut, maxBits);
  }

  /** Adjusts lengths so sum(2^(maxBits-len)) == 2^maxBits for used symbols. */
  private static void fixKraft(int[] lengths, int maxBits) throws BrotliException {
    int target = 1 << maxBits;
    int kraft = 0;
    int used = 0;
    for (int i = 0; i < lengths.length; i++) {
      int len = lengths[i];
      if (len > 0) {
        kraft += 1 << (maxBits - len);
        used++;
      }
    }
    if (used < 2) {
      return;
    }

    // Too large: lengthen codes
    while (kraft > target) {
      int best = -1;
      for (int i = 0; i < lengths.length; i++) {
        if (lengths[i] > 0 && lengths[i] < maxBits) {
          if (best < 0 || lengths[i] < lengths[best]) {
            best = i;
          }
        }
      }
      if (best < 0) {
        throw new BrotliException("Cannot fix Huffman Kraft (too large)");
      }
      kraft -= 1 << (maxBits - lengths[best]);
      lengths[best]++;
      kraft += 1 << (maxBits - lengths[best]);
    }

    // Too small: shorten codes
    while (kraft < target) {
      int best = -1;
      for (int i = 0; i < lengths.length; i++) {
        if (lengths[i] > 1) {
          if (kraft + (1 << (maxBits - lengths[i])) <= target) {
            if (best < 0 || lengths[i] > lengths[best]) {
              best = i;
            }
          }
        }
      }
      if (best < 0) {
        // Add a filler by shortening any length>1 even if overshoots, then lengthen others
        for (int i = 0; i < lengths.length; i++) {
          if (lengths[i] > 1) {
            best = i;
            break;
          }
        }
      }
      if (best < 0) {
        throw new BrotliException("Cannot fix Huffman Kraft (too small)");
      }
      kraft -= 1 << (maxBits - lengths[best]);
      lengths[best]--;
      kraft += 1 << (maxBits - lengths[best]);
    }

    if (kraft != target) {
      // Final pass: lengthen until exact
      while (kraft > target) {
        int best = -1;
        for (int i = 0; i < lengths.length; i++) {
          if (lengths[i] > 0 && lengths[i] < maxBits) {
            best = i;
            break;
          }
        }
        if (best < 0) {
          throw new BrotliException("Huffman Kraft mismatch " + kraft);
        }
        kraft -= 1 << (maxBits - lengths[best]);
        lengths[best]++;
        kraft += 1 << (maxBits - lengths[best]);
      }
    }
    if (kraft != target) {
      throw new BrotliException("Huffman Kraft mismatch " + kraft);
    }
  }

  /** Assigns lengths from histogram and writes the prefix code. */
  public static void writePrefixCode(BitSink bw, int[] histogram) throws BrotliException {
    int n = histogram.length;
    int used = 0;
    int only = 0;
    for (int i = 0; i < n; i++) {
      if (histogram[i] > 0) {
        used++;
        only = i;
      }
    }
    if (used <= 1) {
      PrefixCode.writeSimple(bw, new int[] {only}, n);
      return;
    }
    int[] lengths = new int[n];
    assignLengths(histogram, lengths, HuffmanTable.MAX_CODE_LENGTH);
    PrefixCode.writeFromLengths(bw, lengths, only);
  }

  /** Writes a prefix code for the given lengths (simple when possible). */
  public static void writePrefixCodeFromLengths(BitSink bw, int[] lengths) throws BrotliException {
    PrefixCode.writeFromLengths(bw, lengths);
  }
}
