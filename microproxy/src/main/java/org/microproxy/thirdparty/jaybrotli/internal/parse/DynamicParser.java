/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.parse;

import org.microproxy.thirdparty.jaybrotli.spi.CommandSink;
import org.microproxy.thirdparty.jaybrotli.spi.Match;
import org.microproxy.thirdparty.jaybrotli.spi.MatchFinder;
import org.microproxy.thirdparty.jaybrotli.spi.ParseContext;
import org.microproxy.thirdparty.jaybrotli.spi.ParseStrategy;
import java.util.*;

abstract class DynamicParser implements ParseStrategy {
  private final int width;

  DynamicParser(int width) {
    this.width = width;
  }

  private record State(
      long cost, int position, State previous, int distance, int length, int lastDistance) {}

  public void parse(ParseContext context, MatchFinder finder, CommandSink out) {
    finder.reset(context);
    int length = context.data().remaining();
    State[][] states = new State[length + 1][width];
    states[0][0] = new State(0, 0, null, 0, 0, 0);
    for (int pos = 0; pos < length; pos++) {
      Match match = finder.find(pos);
      for (State s : states[pos]) {
        if (s == null) continue;
        offer(states[pos + 1], new State(s.cost + 8, pos + 1, s, 0, 1, s.lastDistance));
        if (match != null) {
          int[] lengths =
              width == 1
                  ? new int[] {match.length()}
                  : new int[] {match.length(), Math.max(4, match.length() / 2), 4};
          for (int n : lengths) {
            long cost =
                4
                    + 2L * (31 - Integer.numberOfLeadingZeros(n))
                    + (match.distance() == s.lastDistance
                        ? 1
                        : 2L * (31 - Integer.numberOfLeadingZeros(match.distance())) + 2);
            offer(
                states[pos + n],
                new State(s.cost + cost, pos + n, s, match.distance(), n, match.distance()));
          }
        }
      }
      finder.advance(pos);
    }
    State best = states[length][0];
    List<State> path = new ArrayList<>();
    for (State s = best; s.previous != null; s = s.previous) path.add(s);
    Collections.reverse(path);
    int literal = -1, literalLength = 0;
    for (State s : path) {
      if (s.distance == 0) {
        if (literal < 0) literal = s.position - 1;
        literalLength++;
      } else {
        if (literalLength > 0) out.insert(literal, literalLength);
        literal = -1;
        literalLength = 0;
        out.copy(s.distance, s.length);
      }
    }
    if (literalLength > 0) out.insert(literal, literalLength);
  }

  private void offer(State[] beam, State next) {
    for (int i = 0; i < beam.length; i++) {
      State old = beam[i];
      if (old != null && old.lastDistance == next.lastDistance) {
        if (old.cost <= next.cost) return;
        beam[i] = next;
        Arrays.sort(beam, Comparator.nullsLast(Comparator.comparingLong(State::cost)));
        return;
      }
    }
    for (int i = 0; i < beam.length; i++)
      if (beam[i] == null || beam[i].cost > next.cost) {
        for (int j = beam.length - 1; j > i; j--) beam[j] = beam[j - 1];
        beam[i] = next;
        return;
      }
  }
}
