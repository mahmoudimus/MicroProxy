/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.match;

import org.microproxy.thirdparty.jaybrotli.spi.MatchFinder;
import org.microproxy.thirdparty.jaybrotli.spi.ParseContext;
import java.util.*;

abstract class IndexedFinder implements MatchFinder {
  protected byte[] bytes;
  protected int history, window, length;

  public void reset(ParseContext context) {
    var h = context.history();
    var d = context.data();
    history = h.remaining();
    length = d.remaining();
    window = (1 << context.windowBits()) - 16;
    bytes = new byte[history + length];
    h.get(bytes, 0, history);
    d.get(bytes, history, length);
    build();
  }

  protected abstract void build();

  protected int length(int position, int candidate) {
    return ByteComparisons.selected()
        .commonPrefix(bytes, history + position, bytes, candidate, length - position);
  }

  protected long key(int p, int width) {
    long key = 0;
    for (int i = 0; i < width; i++) key = (key << 8) | (bytes[p + i] & 255);
    return key;
  }

  public void advance(int position) {} // Immutable pre-indexed previous-position structures.
}
