/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitSink;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.CanonicalEncoder;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.CodeBook;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.PrefixCode;
import java.nio.ByteBuffer;
import java.util.List;

/** Stateless serialization of completed plans. No histogram, split, or codec-state access. */
public final class MetablockWriter {
  public void write(MetablockPlan plan, BitSink out, boolean last) throws BrotliException {
    ByteBuffer data = plan.data();
    writeHeader(plan, data.remaining(), out, last);
    writeTrees(plan.literalTrees(), out);
    writeTrees(plan.commandTrees(), out);
    writeTrees(plan.distanceTrees(), out);
    writeCommands(plan, data, out);
  }

  private void writeHeader(MetablockPlan plan, int length, BitSink out, boolean last)
      throws BrotliException {
    out.writeBits(last ? 1 : 0, 1);
    if (last) out.writeBits(0, 1);
    int ml = length - 1;
    int nibbles = ml < (1 << 16) ? 4 : ml < (1 << 20) ? 5 : 6;
    out.writeBits(nibbles - 4, 2);
    out.writeBits(ml, nibbles * 4);
    if (!last) out.writeBits(0, 1);
    BlockTypeCoder.writeHeader(plan.literals(), out);
    BlockTypeCoder.writeHeader(plan.commands(), out);
    BlockTypeCoder.writeHeader(plan.distances(), out);
    out.writeBits(plan.npostfix(), 2);
    out.writeBits(plan.ndirect() >> plan.npostfix(), 4);
    for (int i = 0; i < plan.literals().size(); i++) out.writeBits(plan.contextMode(), 2);
    ContextMapWriter.write(out, plan.literalContexts());
    ContextMapWriter.write(out, plan.distanceContexts());
  }

  static void writePrefix(CodeBook book, BitSink out) throws BrotliException {
    byte[] bytes = book.lengths();
    int[] lengths = new int[bytes.length];
    for (int i = 0; i < bytes.length; i++) lengths[i] = bytes[i] & 255;
    PrefixCode.writeFromLengths(out, lengths, book.singleSymbol());
  }

  private void writeTrees(List<CodeBook> trees, BitSink out) throws BrotliException {
    for (CodeBook tree : trees) writePrefix(tree, out);
  }

  private CanonicalEncoder[] encoders(List<CodeBook> books) {
    return books.stream().map(CanonicalEncoder::new).toArray(CanonicalEncoder[]::new);
  }

  private void writeCommands(MetablockPlan plan, ByteBuffer data, BitSink out)
      throws BrotliException {
    var literalBlocks = new BlockCursor(plan.literals());
    var commandBlocks = new BlockCursor(plan.commands());
    var distanceBlocks = new BlockCursor(plan.distances());
    var literals = encoders(plan.literalTrees());
    var commands = encoders(plan.commandTrees());
    var distances = encoders(plan.distanceTrees());
    int[] literalMap = plan.literalContexts().contexts().trees();
    int[] distanceMap = plan.distanceContexts().contexts().trees();
    var semantic = plan.sequence().entries();
    int p1 = plan.previous1(), p2 = plan.previous2(), pos = 0;
    for (int ci = 0; ci < semantic.size(); ci++) {
      var cmd = semantic.get(ci);
      var packed = plan.packedCommands().get(ci);
      int commandTree = commandBlocks.next(out);
      commands[commandTree].encode(packed.code(), out);
      out.writeBits(packed.insertExtra(), packed.insertBits());
      out.writeBits(packed.copyExtra(), packed.copyBits());
      for (int j = 0; j < cmd.insertLen(); j++) {
        int block = literalBlocks.next(out);
        int literal = data.get(cmd.insertOffset() + j) & 255;
        int context = Context.literalContextId(plan.contextMode(), p1, p2);
        literals[literalMap[64 * block + context]].encode(literal, out);
        p2 = p1;
        p1 = literal;
        pos++;
      }
      if (packed.writeDistance()) {
        int block = distanceBlocks.next(out);
        distances[distanceMap[4 * block + packed.distanceContext()]].encode(
            packed.distanceCode(), out);
        out.writeBits(packed.distanceExtra(), packed.distanceBits());
      }
      for (int j = 0; j < cmd.copyCovered(); j++) {
        p2 = p1;
        p1 = data.get(pos++) & 255;
      }
    }
  }

  /** Packing cursor only tracks already planned boundaries; it makes no split decisions. */
  private static final class BlockCursor {
    private final BlockTypeCoder.Group group;
    private final CanonicalEncoder types, counts;
    private int block, used;

    BlockCursor(BlockTypeCoder.Group group) {
      this.group = group;
      types = group.types() == null ? null : new CanonicalEncoder(group.types());
      counts = group.counts() == null ? null : new CanonicalEncoder(group.counts());
    }

    int next(BitSink out) throws BrotliException {
      if (block < group.size() - 1 && used == group.length(block)) {
        types.encode(1, out);
        BlockTypeCoder.writeLength(group.length(++block), counts, out);
        used = 0;
      }
      used++;
      return block;
    }
  }
}
