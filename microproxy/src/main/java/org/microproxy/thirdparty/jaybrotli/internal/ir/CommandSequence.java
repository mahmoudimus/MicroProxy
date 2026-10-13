/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.ir;

import java.util.ArrayList;
import java.util.List;

/** Immutable command ownership boundary; parser entries never escape into a completed block. */
public record CommandSequence(List<Entry> entries) {
  public record Entry(
      int insertOffset,
      int insertLen,
      int copyLen,
      int copyCovered,
      int distance,
      boolean dictionary) {}

  public CommandSequence {
    entries = List.copyOf(entries);
  }

  public List<Command> commands() {
    List<Command> out = new ArrayList<>();
    for (Entry e : entries) {
      if (e.insertLen() > 0) out.add(new Command.Insert(e.insertOffset(), e.insertLen()));
      if (e.copyCovered() > 0)
        out.add(
            e.dictionary()
                ? new Command.DictionaryCopy(e.distance(), e.copyLen(), e.copyCovered())
                : new Command.Copy(e.distance(), e.copyCovered()));
    }
    return List.copyOf(out);
  }
}
