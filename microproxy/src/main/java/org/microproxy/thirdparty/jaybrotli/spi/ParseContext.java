/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.spi;

import java.nio.ByteBuffer;

/** Borrowed input is read-only for the synchronous duration of parse. */
public record ParseContext(ByteBuffer data, ByteBuffer history, int windowBits, int quality) {
  public ParseContext {
    data = data.asReadOnlyBuffer();
    history = history.asReadOnlyBuffer();
    if (windowBits < 10 || windowBits > 30 || quality < 0 || quality > 11)
      throw new IllegalArgumentException("parse configuration");
  }

  @Override
  public ByteBuffer data() {
    return data.duplicate();
  }

  @Override
  public ByteBuffer history() {
    return history.duplicate();
  }
}
