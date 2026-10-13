/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** A single owned payload copy shared by planning and packing through immutable access. */
public final class MetablockData {
  private final ByteBuffer bytes;

  private MetablockData(byte[] owned) {
    bytes = ByteBuffer.wrap(owned).asReadOnlyBuffer();
  }

  static MetablockData copyOf(byte[] input, int length) {
    if (length < 1 || length > input.length) throw new IllegalArgumentException("Metablock length");
    return new MetablockData(Arrays.copyOf(input, length));
  }

  int length() {
    return bytes.capacity();
  }

  byte get(int index) {
    return bytes.get(index);
  }

  ByteBuffer view() {
    return bytes.duplicate();
  }
}
