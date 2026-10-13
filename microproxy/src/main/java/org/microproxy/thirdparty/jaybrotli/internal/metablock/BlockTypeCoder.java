/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSink;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.CanonicalEncoder;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.CodeBook;

/** Serializes a planned block group; tree selection belongs to the planner. */
public final class BlockTypeCoder {
  private BlockTypeCoder() {}

  public record Group(int[] lengths, CodeBook types, CodeBook counts) {
    public Group {
      lengths = lengths.clone();
      if (lengths.length == 0) throw new IllegalArgumentException("Block lengths");
      for (int n : lengths) if (n < 1) throw new IllegalArgumentException("Block lengths");
      if (lengths.length > 1) {
        java.util.Objects.requireNonNull(types);
        java.util.Objects.requireNonNull(counts);
      }
    }

    /** Number of block types in this group. */
    public int size() {
      return lengths.length;
    }

    /** Length of the block type at {@code index}. */
    public int length(int index) {
      return lengths[index];
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof Group g
          && java.util.Arrays.equals(lengths, g.lengths)
          && java.util.Objects.equals(types, g.types)
          && java.util.Objects.equals(counts, g.counts);
    }

    @Override
    public int hashCode() {
      return java.util.Objects.hash(
          java.util.Arrays.hashCode(lengths), types, counts);
    }
  }

  static void writeHeader(Group group, BitSink out) throws BrotliException {
    if (group.size() == 1) {
      out.writeBits(0, 1);
      return;
    }
    ContextMapWriter.writeVarLenUint8PlusOne(out, group.size());
    MetablockWriter.writePrefix(group.types(), out);
    MetablockWriter.writePrefix(group.counts(), out);
    writeLength(group.length(0), new CanonicalEncoder(group.counts()), out);
  }

  static void writeLength(int length, CanonicalEncoder counts, BitSink out) throws BrotliException {
    int[] packed = new int[3];
    BlockLengthEncoder.pack(length, packed);
    counts.encode(packed[0], out);
    out.writeBits(packed[1], packed[2]);
  }
}
