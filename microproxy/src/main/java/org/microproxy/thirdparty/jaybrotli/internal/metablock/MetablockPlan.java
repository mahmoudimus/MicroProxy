/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

import org.microproxy.thirdparty.jaybrotli.internal.huffman.CodeBook;
import org.microproxy.thirdparty.jaybrotli.internal.ir.CommandSequence;
import java.nio.ByteBuffer;
import java.util.List;

/** Completed encoding decisions, independent of parser inputs and reusable planning scratch. */
public record MetablockPlan(
    CommandSequence sequence,
    MetablockData content,
    int contextMode,
    int previous1,
    int previous2,
    int npostfix,
    int ndirect,
    BlockTypeCoder.Group literals,
    BlockTypeCoder.Group commands,
    BlockTypeCoder.Group distances,
    ContextMapPlan literalContexts,
    ContextMapPlan distanceContexts,
    List<CodeBook> literalTrees,
    List<CodeBook> commandTrees,
    List<CodeBook> distanceTrees,
    List<PackedCommand> packedCommands) {
  public MetablockPlan {
    java.util.Objects.requireNonNull(sequence);
    java.util.Objects.requireNonNull(content);
    java.util.Objects.requireNonNull(literals);
    java.util.Objects.requireNonNull(commands);
    java.util.Objects.requireNonNull(distances);
    java.util.Objects.requireNonNull(literalContexts);
    java.util.Objects.requireNonNull(distanceContexts);
    literalTrees = List.copyOf(literalTrees);
    commandTrees = List.copyOf(commandTrees);
    distanceTrees = List.copyOf(distanceTrees);
    packedCommands = List.copyOf(packedCommands);
    if (packedCommands.size() != sequence.entries().size())
      throw new IllegalArgumentException("Command count mismatch");
  }

  /** Returns a read-only view with an independent cursor, without copying payload bytes. */
  public ByteBuffer data() {
    return content.view();
  }

  public record PackedCommand(
      int code,
      int insertExtra,
      int insertBits,
      int copyExtra,
      int copyBits,
      boolean writeDistance,
      int distanceCode,
      int distanceExtra,
      int distanceBits,
      int distanceContext) {}
}
