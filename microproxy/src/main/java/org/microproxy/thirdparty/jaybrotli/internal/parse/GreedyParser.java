/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.parse;

import org.microproxy.thirdparty.jaybrotli.spi.CommandSink;
import org.microproxy.thirdparty.jaybrotli.spi.Match;
import org.microproxy.thirdparty.jaybrotli.spi.MatchFinder;
import org.microproxy.thirdparty.jaybrotli.spi.ParseContext;
import org.microproxy.thirdparty.jaybrotli.spi.ParseStrategy;

public class GreedyParser implements ParseStrategy {
  public String name() {
    return "greedy";
  }

  protected boolean lazy() {
    return false;
  }

  public void parse(ParseContext context, MatchFinder finder, CommandSink out) {
    finder.reset(context);
    int length = context.data().remaining(), literal = 0, pos = 0;
    while (pos < length) {
      Match m = finder.find(pos);
      if (m != null && lazy() && pos + 1 < length) {
        Match next = finder.find(pos + 1);
        if (next != null && next.length() > m.length() + 1) m = null;
      }
      if (m == null) {
        finder.advance(pos++);
        continue;
      }
      if (pos > literal) out.insert(literal, pos - literal);
      out.copy(m.distance(), m.length());
      int end = pos + m.length();
      while (pos < end) finder.advance(pos++);
      literal = pos;
    }
    if (pos > literal) out.insert(literal, pos - literal);
  }
}
