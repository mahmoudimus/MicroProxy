/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

public final class RingHistory extends RingBuffer implements History {
  public RingHistory(int windowBits) {
    super(windowBits, false);
  }

  public RingHistory(int windowBits, boolean direct) {
    super(windowBits, direct);
  }

  public void append(byte[] source, int offset, int length) {
    writeBytes(source, offset, length);
  }

  public byte at(int distance) {
    if (distance < 1 || distance > size()) throw new IllegalArgumentException("distance");
    return recent(distance);
  }

  public int size() {
    return (int) Math.min(getTotalWritten(), getSize());
  }
}
