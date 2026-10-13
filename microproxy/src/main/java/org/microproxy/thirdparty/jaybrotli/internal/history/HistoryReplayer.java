/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

import org.microproxy.thirdparty.jaybrotli.internal.ir.Command;

/** Replays validated semantic copies incrementally, without retaining an entire decoded block. */
public final class HistoryReplayer {
  private HistoryReplayer() {}

  public static void copy(History history, Command.Copy copy, int chunkLength) {
    if (chunkLength < 1 || chunkLength > copy.length())
      throw new IllegalArgumentException("copy chunk");
    history.copyBackward(copy.distance(), chunkLength);
  }

  public static void dictionary(History history, Command.DictionaryCopy copy, byte[] transformed) {
    history.writeBytes(transformed, 0, copy.length());
  }
}
