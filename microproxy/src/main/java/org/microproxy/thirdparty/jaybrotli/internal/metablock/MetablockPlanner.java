/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.internal.codec.MetablockEncoder;
import org.microproxy.thirdparty.jaybrotli.internal.history.DistanceCoding;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.CodeBook;
import org.microproxy.thirdparty.jaybrotli.internal.ir.*;
import org.microproxy.thirdparty.jaybrotli.internal.metablock.MetablockPlan.PackedCommand;
import org.microproxy.thirdparty.jaybrotli.internal.parse.LengthCoder;
import java.util.*;

/** Selects commands, splits, contexts and entropy books before serialization starts. */
public final class MetablockPlanner {
  private static final int MAX_CONTEXT_SLOTS = 64 * 16;
  private static final int[][] POSTFIX_CANDIDATES = {{0, 0}, {0, 4}, {1, 0}, {2, 0}};
  private final MetablockEncoder state;
  private final BlockSplitStrategy splitter = new EntropySplitter();
  private final ContextModeller contexts = ContextModeller.standard();
  private final int[] packOut = new int[5], distOut = new int[3], distScratch = new int[4096];
  private int[][] contextHistograms;

  public MetablockPlanner(MetablockEncoder state) {
    this.state = state;
  }

  public MetablockPlan plan(CommandSequence commands, byte[] data, int length)
      throws BrotliException {
    if (length < 1 || length > MetablockEncoder.MAX_METABLOCK || length > data.length)
      throw new IllegalArgumentException("Metablock length");
    MetablockData owned = MetablockData.copyOf(data, length);
    var initial = state.distRing.snapshot();
    try {
      int[] distanceParams = state.quality >= 7 ? choosePostfixPair(commands, length) : new int[2];
      int alphabet =
          DistanceCoding.alphabetSize(state.largeWindow, distanceParams[0], distanceParams[1]);
      List<PackedCommand> packed =
          packCommands(commands, length, distanceParams[0], distanceParams[1], alphabet);
      return state.quality >= 10
          ? planHq(commands, owned, packed, distanceParams, alphabet)
          : state.quality >= 5
              ? planContext(commands, owned, packed, distanceParams, alphabet)
              : planSimple(commands, owned, packed, distanceParams, alphabet);
    } catch (BrotliException | RuntimeException failure) {
      state.distRing.restore(initial);
      throw failure;
    }
  }

  private List<PackedCommand> packCommands(
      CommandSequence commands, int length, int postfix, int direct, int alphabet)
      throws BrotliException {
    List<PackedCommand> result = new ArrayList<>(commands.entries().size());
    int emitted = 0;
    for (var cmd : commands.entries()) {
      emitted += cmd.insertLen();
      boolean copy = emitted < length && cmd.distance() != 0;
      boolean implicit = !copy || (!cmd.dictionary() && cmd.distance() == state.distRing.get(0));
      int copyLength = Math.max(2, cmd.copyLen());
      LengthCoder.pack(cmd.insertLen(), copyLength, implicit, packOut);
      boolean explicit = copy && packOut[0] >= 128;
      int code = 0, extra = 0, bits = 0;
      if (explicit) {
        DistanceCoding.encodeDistance(cmd.distance(), postfix, direct, state.distRing, distOut);
        code = distOut[0];
        extra = distOut[1];
        bits = distOut[2];
        if (code >= alphabet) throw new BrotliException("Distance code out of alphabet");
        if (!cmd.dictionary() && code != 0) state.distRing.push(cmd.distance());
      }
      result.add(
          new PackedCommand(
              packOut[0],
              packOut[1],
              packOut[3],
              packOut[2],
              packOut[4],
              explicit,
              code,
              extra,
              bits,
              contexts.distanceContext(copyLength)));
      if (copy) emitted = Math.min(length, emitted + cmd.copyCovered());
    }
    return List.copyOf(result);
  }

  private MetablockPlan planSimple(
      CommandSequence commands,
      MetablockData data,
      List<PackedCommand> packed,
      int[] params,
      int alphabet)
      throws BrotliException {
    int[][] literals = new int[1][256], distances = new int[1][alphabet];
    for (var cmd : commands.entries())
      for (int j = 0; j < cmd.insertLen(); j++)
        literals[0][data.get(cmd.insertOffset() + j) & 255]++;
    for (var cmd : packed) if (cmd.writeDistance()) distances[0][cmd.distanceCode()]++;
    int[] literalLengths = {Math.max(1, totalLiterals(commands))};
    int[] commandLengths = {Math.max(1, packed.size())};
    int[] distanceLengths = {Math.max(1, explicitDistances(packed))};
    return finish(
        commands,
        data,
        packed,
        params,
        Context.LSB6,
        literalLengths,
        commandLengths,
        distanceLengths,
        new int[64],
        new int[4],
        literals,
        commandHistograms(packed, commandLengths),
        distances);
  }

  private MetablockPlan planContext(
      CommandSequence commands,
      MetablockData data,
      List<PackedCommand> packed,
      int[] params,
      int alphabet)
      throws BrotliException {
    int[] literalLengths = halfSplit(totalLiterals(commands), state.quality >= 6, 64);
    int[] commandLengths = halfSplit(packed.size(), state.quality >= 8, 32);
    int[] distanceLengths = halfSplit(explicitDistances(packed), state.quality >= 9, 32);
    boolean four = state.quality >= 8;
    int[][] literalBuckets = new int[four ? 4 : 2][256];
    visitLiterals(
        commands,
        data,
        literalLengths,
        (block, context, literal) ->
            literalBuckets[four ? context >> 4 : context < 32 ? 0 : 1][literal]++);
    var literals = compact(literalBuckets);
    int[] literalMap = new int[64 * literalLengths.length];
    for (int i = 0; i < literalMap.length; i++) {
      int context = i % 64;
      literalMap[i] = literals.map()[four ? context >> 4 : context < 32 ? 0 : 1];
    }
    boolean distanceContexts = state.quality >= 6;
    var distances = distanceTrees(packed, distanceLengths, alphabet, distanceContexts);
    return finish(
        commands,
        data,
        packed,
        params,
        Context.UTF8,
        literalLengths,
        commandLengths,
        distanceLengths,
        literalMap,
        distances.map(),
        literals.histograms(),
        commandHistograms(packed, commandLengths),
        distances.histograms());
  }

  private MetablockPlan planHq(
      CommandSequence commands,
      MetablockData data,
      List<PackedCommand> packed,
      int[] params,
      int alphabet)
      throws BrotliException {
    boolean finest = state.quality >= 11;
    int[] literalLengths = splitLiterals(commands, data, finest ? 512 : 1024, finest ? 16 : 8);
    int[] commandLengths = splitCommands(commands, finest ? 16 : 32, finest ? 8 : 4);
    int[] distanceLengths = splitDistances(packed, finest ? 16 : 32, finest ? 8 : 4);
    var literals = clusteredLiterals(commands, data, literalLengths, finest ? 16 : 8);
    var distances = distanceTrees(packed, distanceLengths, alphabet, true);
    return finish(
        commands,
        data,
        packed,
        params,
        Context.UTF8,
        literalLengths,
        commandLengths,
        distanceLengths,
        literals.map(),
        distances.map(),
        literals.histograms(),
        commandHistograms(packed, commandLengths),
        distances.histograms());
  }

  private MetablockPlan finish(
      CommandSequence commands,
      MetablockData data,
      List<PackedCommand> packed,
      int[] params,
      int mode,
      int[] literalLengths,
      int[] commandLengths,
      int[] distanceLengths,
      int[] literalMap,
      int[] distanceMap,
      int[][] literalHistograms,
      int[][] commandHistograms,
      int[][] distanceHistograms)
      throws BrotliException {
    return new MetablockPlan(
        commands,
        data,
        mode,
        state.historyByte(1),
        state.historyByte(2),
        params[0],
        params[1],
        group(literalLengths),
        group(commandLengths),
        group(distanceLengths),
        ContextMapPlan.create(literalMap, literalHistograms.length),
        ContextMapPlan.create(distanceMap, distanceHistograms.length),
        books(literalHistograms),
        books(commandHistograms),
        books(distanceHistograms),
        packed);
  }

  private BlockTypeCoder.Group group(int[] lengths) throws BrotliException {
    if (lengths.length == 1) return new BlockTypeCoder.Group(lengths, null, null);
    int[] types = new int[lengths.length + 2], counts = new int[26], packed = new int[3];
    types[1] = 1;
    for (int length : lengths) {
      BlockLengthEncoder.pack(length, packed);
      counts[packed[0]]++;
    }
    return new BlockTypeCoder.Group(lengths, book(types), book(counts));
  }

  private List<CodeBook> books(int[][] histograms) throws BrotliException {
    List<CodeBook> result = new ArrayList<>(histograms.length);
    for (int[] histogram : histograms) result.add(book(histogram));
    return List.copyOf(result);
  }

  private CodeBook book(int[] histogram) throws BrotliException {
    if (sum(histogram) == 0) histogram[0] = 1;
    int[] lengths = new int[histogram.length];
    state.assignLengths(histogram, lengths, 15);
    int maximum = 0, sole = 0;
    for (int i = 0; i < histogram.length; i++) {
      maximum = Math.max(maximum, lengths[i]);
      if (histogram[i] > 0) sole = i;
    }
    return maximum == 0
        ? CodeBook.singleSymbol(sole, histogram.length)
        : CodeBook.fromLengths(lengths);
  }

  private int[][] commandHistograms(List<PackedCommand> commands, int[] lengths) {
    int[][] histograms = new int[lengths.length][704];
    int at = 0;
    for (int block = 0; block < lengths.length; block++)
      for (int j = 0; j < lengths[block] && at < commands.size(); j++)
        histograms[block][commands.get(at++).code()]++;
    return histograms;
  }

  private record Trees(int[][] histograms, int[] map) {}

  private Trees distanceTrees(
      List<PackedCommand> commands, int[] lengths, int alphabet, boolean useContexts) {
    int buckets = useContexts ? 2 : 1;
    int[][] histograms = new int[lengths.length * buckets][alphabet];
    int block = 0, used = 0;
    for (var cmd : commands) {
      if (!cmd.writeDistance()) continue;
      if (block < lengths.length - 1 && used == lengths[block]) {
        block++;
        used = 0;
      }
      int context = useContexts && cmd.distanceContext() > 0 ? 1 : 0;
      histograms[block * buckets + context][cmd.distanceCode()]++;
      used++;
    }
    var compacted = compact(histograms);
    int[] map = new int[4 * lengths.length];
    for (int bt = 0; bt < lengths.length; bt++)
      for (int context = 0; context < 4; context++)
        map[4 * bt + context] =
            compacted.map()[bt * buckets + (useContexts && context > 0 ? 1 : 0)];
    return new Trees(compacted.histograms(), map);
  }

  private Trees compact(int[][] histograms) {
    List<int[]> used = new ArrayList<>();
    int[] map = new int[histograms.length];
    for (int i = 0; i < histograms.length; i++)
      if (sum(histograms[i]) > 0) {
        map[i] = used.size();
        used.add(histograms[i]);
      }
    if (used.isEmpty()) used.add(new int[histograms[0].length]);
    return new Trees(used.toArray(int[][]::new), map);
  }

  @FunctionalInterface
  private interface LiteralVisitor {
    void accept(int block, int context, int literal);
  }

  private void visitLiterals(
      CommandSequence commands, MetablockData data, int[] lengths, LiteralVisitor visitor) {
    int p1 = state.historyByte(1), p2 = state.historyByte(2), pos = 0, block = 0, used = 0;
    for (var cmd : commands.entries()) {
      for (int j = 0; j < cmd.insertLen(); j++) {
        if (block < lengths.length - 1 && used == lengths[block]) {
          block++;
          used = 0;
        }
        int literal = data.get(cmd.insertOffset() + j) & 255;
        visitor.accept(block, contexts.literalContext(Context.UTF8, p1, p2), literal);
        p2 = p1;
        p1 = literal;
        used++;
        pos++;
      }
      for (int j = 0; j < cmd.copyCovered(); j++) {
        p2 = p1;
        p1 = data.get(pos++) & 255;
      }
    }
  }

  private Trees clusteredLiterals(
      CommandSequence commands, MetablockData data, int[] lengths, int cap) {
    int slots = lengths.length * 64;
    if (contextHistograms == null) contextHistograms = new int[MAX_CONTEXT_SLOTS][256];
    for (int i = 0; i < slots; i++) Arrays.fill(contextHistograms[i], 0);
    visitLiterals(
        commands,
        data,
        lengths,
        (block, context, literal) -> contextHistograms[64 * block + context][literal]++);
    int[] map = new int[slots];
    int trees = BlockSplitter.clusterContexts(contextHistograms, slots, cap, map);
    return new Trees(Arrays.copyOf(contextHistograms, trees), map);
  }

  private int[] splitLiterals(CommandSequence commands, MetablockData data, int chunk, int cap) {
    int count = totalLiterals(commands);
    if (count == 0) return new int[] {1};
    int chunks = (count + chunk - 1) / chunk;
    int[][] histograms = new int[chunks][256];
    int[] lengths = new int[chunks];
    int at = 0;
    for (var cmd : commands.entries())
      for (int j = 0; j < cmd.insertLen(); j++) {
        int block = at++ / chunk;
        histograms[block][data.get(cmd.insertOffset() + j) & 255]++;
        lengths[block]++;
      }
    return splitter.split(histograms, lengths, chunks, 256, cap);
  }

  private int[] splitCommands(CommandSequence commands, int chunk, int cap) {
    int count = commands.entries().size();
    if (count < 32) return new int[] {Math.max(1, count)};
    int chunks = (count + chunk - 1) / chunk;
    int[][] histograms = new int[chunks][24];
    int[] lengths = new int[chunks];
    for (int i = 0; i < count; i++) {
      int symbol =
          Math.clamp(LengthCoder.insertLengthCode(commands.entries().get(i).insertLen()), 0, 23);
      histograms[i / chunk][symbol]++;
      lengths[i / chunk]++;
    }
    return splitter.split(histograms, lengths, chunks, 24, cap);
  }

  private int[] splitDistances(List<PackedCommand> commands, int chunk, int cap) {
    int count = explicitDistances(commands);
    if (count < 32) return new int[] {Math.max(1, count)};
    int chunks = (count + chunk - 1) / chunk;
    int[][] histograms = new int[chunks][16];
    int[] lengths = new int[chunks];
    int at = 0;
    for (var cmd : commands)
      if (cmd.writeDistance()) {
        int block = at++ / chunk;
        histograms[block][cmd.distanceCode() & 15]++;
        lengths[block]++;
      }
    return splitter.split(histograms, lengths, chunks, 16, cap);
  }

  private int[] choosePostfixPair(CommandSequence commands, int length) throws BrotliException {
    int count = 0, emitted = 0;
    for (var cmd : commands.entries()) {
      emitted += cmd.insertLen();
      boolean copy = emitted < length && cmd.distance() != 0;
      boolean implicit = !copy || (!cmd.dictionary() && cmd.distance() == state.distRing.get(0));
      LengthCoder.pack(cmd.insertLen(), Math.max(2, cmd.copyLen()), implicit, packOut);
      if (copy && packOut[0] >= 128 && count < distScratch.length)
        distScratch[count++] = cmd.distance();
      if (copy) emitted = Math.min(length, emitted + cmd.copyCovered());
    }
    int[] best = {0, 0};
    int bestCost = Integer.MAX_VALUE;
    for (int[] candidate : POSTFIX_CANDIDATES) {
      int cost = 0;
      for (int i = 0; i < count; i++) {
        DistanceCoding.encodeDistance(
            distScratch[i], candidate[0], candidate[1], state.distRing, distOut);
        cost += distOut[2];
      }
      if (cost < bestCost) {
        bestCost = cost;
        best = candidate;
      }
    }
    return best.clone();
  }

  private int[] halfSplit(int count, boolean enabled, int minimum) {
    return enabled && count >= minimum
        ? new int[] {count / 2, count - count / 2}
        : new int[] {Math.max(1, count)};
  }

  private int totalLiterals(CommandSequence commands) {
    return commands.entries().stream().mapToInt(CommandSequence.Entry::insertLen).sum();
  }

  private int explicitDistances(List<PackedCommand> commands) {
    return (int) commands.stream().filter(PackedCommand::writeDistance).count();
  }

  private static int sum(int[] histogram) {
    return Arrays.stream(histogram).sum();
  }
}
